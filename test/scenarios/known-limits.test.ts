// Scenarios 79 to 84 of docs/scenarios.md: what the known limits imply.

import assert from "node:assert/strict";
import { test } from "node:test";
import { askForLink, freshEmail, freshIp, type Harness, signUp, startHarness, wait, whoIs } from "./harness.ts";

/** Link requests from fresh addresses (5 each, the most one may ask for) to fresh inboxes. */
async function flood(h: Harness, count: number) {
  let ip = freshIp();
  for (let sent = 0; sent < count; sent += 50) {
    await Promise.all(
      Array.from({ length: Math.min(50, count - sent) }, (_, i) => {
        if ((sent + i) % 5 === 0) ip = freshIp();
        return h.visitor(ip).post("/auth/send-sign-in-link", { email: freshEmail("flood") });
      }),
    );
  }
}

test("a flood of dropped emails is said in the log a few times, not once each, so it can't fill the log (79)", async () => {
  let release = () => {};
  const held = new Promise<void>((resolve) => {
    release = resolve;
  });
  const h = await startHarness({ sendEmail: () => held });
  try {
    await flood(h, 1110);
    await wait(200);
    const said = h.logs.filter((line) => /email/i.test(line));
    assert.ok(said.length >= 1, "the dropping is said");
    assert.ok(said.length <= 6, `${said.length} lines for about 100 dropped emails`);
  } finally {
    release();
    await h.close();
  }
});

test("past 10 sending and 1,000 waiting, further emails are dropped and logged, and requests stay quick (79)", async (t) => {
  let release = () => {};
  const held = new Promise<void>((resolve) => {
    release = resolve;
  });
  const h = await startHarness({ sendEmail: () => held });
  try {
    const account = await signUp(h).catch(() => null);
    await flood(h, 1030);
    await wait(100);
    assert.equal(h.emails.length, 10, "10 at once");
    const quick = await h.visitor().get("/auth/session");
    assert.ok(quick.ms < 250, `${quick.ms} ms`);
    const logged = h.logs.join("\n");
    release();
    for (let settled = -1; settled !== h.emails.length; ) {
      settled = h.emails.length;
      await wait(200);
    }
    t.diagnostic(`emails sent: ${h.emails.length} of 1,031 asked for; log lines: ${h.logs.length}`);
    assert.ok(h.emails.length <= 1010, `${h.emails.length} sent`);
    assert.ok(h.emails.length >= 1000);
    assert.ok(/too many waiting|dropped|queue|full/i.test(logged), "the dropping is logged");
    if (account) assert.equal(await whoIs(account.visitor), account.email);
  } finally {
    release();
    await h.close();
  }
  t.diagnostic("a link run out while it waited isn't sent: not tested, as it needs 15 minutes to pass");
});

test("a sendEmail that never settles is aborted after 30 seconds, and the sends waiting behind it then go (80)", { timeout: 60_000 }, async () => {
  const signals: AbortSignal[] = [];
  const h = await startHarness({
    sendEmail: (_to, _subject, _text, { signal }) => {
      signals.push(signal);
      if (signals.length <= 10) return new Promise<void>(() => {});
    },
  });
  try {
    const started = Date.now();
    await flood(h, 10);
    await wait(100);
    assert.equal(signals.length, 10);
    const waiting = freshEmail("waiting");
    await h.visitor().post("/auth/send-sign-in-link", { email: waiting });
    await wait(500);
    assert.equal(h.emails.filter((m) => m.to === waiting).length, 0, "behind the 10 stuck sends");
    const aborted = await new Promise<number>((resolve) => (signals[0] as AbortSignal).addEventListener("abort", () => resolve(Date.now() - started)));
    assert.ok(aborted > 29_000 && aborted < 33_000, `aborted after ${aborted} ms`);
    await h.takeEmail((m) => m.to === waiting, 3000);
    await askForLink(h, "password", freshEmail("later"));
  } finally {
    await h.close();
  }
});

test("accounts differing by a Cyrillic letter are separate, and /auth/link gives the address as kept (81)", async () => {
  const h = await startHarness();
  try {
    const local = `ann${Date.now()}`;
    const latin = await signUp(h, `${local}@example.net`);
    const cyrillicEmail = `а${local.slice(1)}@example.net`;
    const cyrillic = await signUp(h, cyrillicEmail);
    assert.notEqual(latin.userId, cyrillic.userId);
    assert.equal(await whoIs(latin.visitor), latin.email);
    assert.equal(await whoIs(cyrillic.visitor), cyrillicEmail);
    const token = await askForLink(h, "sign-in", cyrillicEmail);
    const shown = await h.visitor().post("/auth/link", { token });
    assert.deepEqual(shown.json, { kind: "sign-in", email: cyrillicEmail });
    assert.equal(shown.json.email.codePointAt(0), 0x430);
  } finally {
    await h.close();
  }
});

test("after 100 tries in an hour, the owner signs in by link from another /48 (82)", (t) => {
  t.skip("tested with 25, in limits-account.test.ts, which spends the 100 tries once for both");
});

test("a raised scrypt cost replaces an old hash at the next sign-in, and a stored cost above the current one is refused quickly (83)", (t) => {
  t.skip("the public API has no way to raise the cost, nor to write a hash at another cost, without the library's internals");
});

test("emails of accounts sent a link, old limit rows, and expired sessions are gone from the file and WAL in time (84)", (t) => {
  t.skip("needs the clock moved on, and README documents no way to control time");
});
