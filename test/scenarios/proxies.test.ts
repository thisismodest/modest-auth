// Scenarios 65 to 71 of docs/scenarios.md: proxies and X-Forwarded-For.
// Which address a request counts as is seen from outside by the 5 links one address may ask for in
// 15 minutes: use up an address's 5, then a request that counts as it sends no email.

import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { after, before, test } from "node:test";
import { createAuth, createHandler } from "../../src/index.ts";
import { freshEmail, freshIp, type Harness, LINK_PAGE, rawRequest, rawStatus, startHarness, wait } from "./harness.ts";

let h: Harness;
before(async () => {
  h = await startHarness();
});
after(() => h.close());

/** Asks for a sign-in link to a fresh inbox, with these X-Forwarded-For lines (and any other headers): the status, and whether it was emailed. */
async function linkWith(harness: Harness, forwarded: string[], extra: string[] = []): Promise<{ status: number; emailed: boolean }> {
  const to = freshEmail();
  const body = JSON.stringify({ email: to });
  const head = [
    "POST /auth/send-sign-in-link HTTP/1.1",
    "Host: example.org",
    "Origin: https://example.org",
    "Content-Type: application/json",
    `Content-Length: ${body.length}`,
    ...forwarded.map((line) => `X-Forwarded-For: ${line}`),
    ...extra,
    "Connection: close",
    "",
    "",
  ].join("\r\n");
  const status = rawStatus(await rawRequest(harness, head + body));
  return { status, emailed: (await harness.countEmailsAfter((m) => m.to === to, 150)) > 0 };
}

/** An address with its 5 links used up. */
async function usedUp(harness: Harness, address = freshIp()): Promise<string> {
  for (let i = 0; i < 5; i++) assert.equal((await linkWith(harness, [address])).emailed, true);
  assert.equal((await linkWith(harness, [address])).emailed, false);
  return address;
}

test("with loopback trusted, the rightmost address counts, and whatever is written to its left never changes it (65)", async () => {
  const client = await usedUp(h);
  for (const forwarded of [`1.1.1.1, ${client}`, `${freshIp()}, ${freshIp()}, ${client}`, `${client}, ${client}`]) {
    assert.equal((await linkWith(h, [forwarded])).emailed, false, forwarded);
  }
  assert.equal((await linkWith(h, [`${client}, ${freshIp()}`])).emailed, true, "the rightmost is the client");
});

test("nothing a client writes in X-Forwarded-For escapes its own limits, and an address that can't be read gets 400 (66)", async (t) => {
  const client = await usedUp(h);
  const thousand = Array.from({ length: 1000 }, () => freshIp()).join(", ");
  for (const written of ["127.0.0.1", "127.0.0.1, ::1", "", " ", "unknown", "garbage!", "999.1.1.1", "::ffff:127.0.0.1", thousand]) {
    const sent = await linkWith(h, [`${written}, ${client}`]);
    assert.equal(sent.emailed, false, `"${written.slice(0, 40)}" to the left`);
    const asLine = await linkWith(h, [written, client]);
    assert.equal(asLine.emailed, false, `"${written.slice(0, 40)}" as its own header line`);
  }
  // A proxy on this machine in front of the trusted one passes it on, still the client's.
  assert.equal((await linkWith(h, [`${client}, 127.0.0.1`])).emailed, false);
  assert.equal((await linkWith(h, [`${client}, ::1`])).emailed, false);

  const unreadable = [];
  for (const forwarded of ["unknown", "garbage!", `${client}, unknown`, "999.1.1.1", "1.2.3"]) {
    const sent = await linkWith(h, [forwarded]);
    unreadable.push(`${forwarded}: ${sent.status}`);
    assert.equal(sent.status, 400, `${forwarded} answered ${sent.status}`);
  }
  const loopbackOnly = await linkWith(h, ["127.0.0.1"]);
  const empty = await linkWith(h, [""]);
  t.diagnostic(`only loopback written: ${loopbackOnly.status}; an empty header: ${empty.status}`);
});

test("with no proxies named, X-Forwarded-For is ignored, and said in the log a few times at most (67)", async () => {
  const direct = await startHarness({ trustedProxies: null });
  try {
    for (let i = 0; i < 5; i++) assert.equal((await linkWith(direct, [freshIp()])).emailed, true);
    for (let i = 0; i < 15; i++) assert.equal((await linkWith(direct, [freshIp()])).emailed, false, "every one counts as the connection's address");
    await wait(50);
    const notes = direct.logs.filter((line) => /forwarded|proxies|proxy/i.test(line));
    assert.ok(notes.length >= 1, "the log says what to set");
    assert.ok(notes.length <= 5, `${notes.length} notes`);
  } finally {
    await direct.close();
  }
});

test("a port after an address is dropped (68)", async () => {
  const v4 = freshIp();
  for (let i = 0; i < 5; i++) await linkWith(h, [`${v4}:${1000 + i}`]);
  assert.equal((await linkWith(h, [v4])).emailed, false);
  const v6 = "2001:db8:68::1";
  for (let i = 0; i < 5; i++) await linkWith(h, [`[${v6}]:${80 + i}`]);
  assert.equal((await linkWith(h, [v6])).emailed, false);
});

test("trusting ranges that are much of the internet is refused when the handler is made (69)", async (t) => {
  const auth = createAuth(new DatabaseSync(":memory:"));
  const make = (trustedProxies: string[]) => () =>
    createHandler(auth, { origin: "https://example.org", linkPage: LINK_PAGE, sendEmail: () => {}, trustedProxies });
  for (const range of ["0.0.0.0/0", "::/0", "::/1", "0.0.0.0/1", "128.0.0.0/1"]) assert.throws(make([range]), range);
  const borderline = [];
  for (const range of ["0.0.0.0/8", "10.0.0.0/8", "2000::/3"]) {
    try {
      make([range])();
      borderline.push(`${range} taken`);
    } catch {
      borderline.push(`${range} refused`);
    }
  }
  t.diagnostic(borderline.join(", "));
  assert.doesNotThrow(make(["173.245.48.0/20", "private", "loopback"]));
});

test("Forwarded and X-Real-IP are ignored (70)", async () => {
  const client = await usedUp(h);
  const other = freshIp();
  assert.equal((await linkWith(h, [client], [`Forwarded: for=${other}`, `X-Real-IP: ${other}`])).emailed, false);
  // Nor do they stand in for X-Forwarded-For: these count as the loopback connection itself, again and again.
  const statuses = [];
  for (let i = 0; i < 7; i++) statuses.push((await linkWith(h, [], [`Forwarded: for=${freshIp()}`, `X-Real-IP: ${freshIp()}`])).emailed);
  assert.ok(statuses.filter(Boolean).length <= 5, `${statuses.filter(Boolean).length} emailed`);
});

test("six sources behind an unnamed proxy give at most 5 log notes (71)", async () => {
  const fresh = await startHarness();
  try {
    for (let source = 1; source <= 6; source++) {
      for (let i = 0; i < 3; i++) await linkWith(fresh, [`${freshIp()}, 10.0.71.${source}`]);
    }
    await wait(50);
    const notes = fresh.logs.filter((line) => /forwarded|proxies|proxy/i.test(line));
    assert.ok(notes.length >= 1, "the log says what to set");
    assert.ok(notes.length <= 5, `${notes.length} notes`);
  } finally {
    await fresh.close();
  }
});
