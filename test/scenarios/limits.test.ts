// Scenarios 23, 24, 26, and 28 to 32 of docs/scenarios.md: limits and pausing.
// (25 and 27, which need a hundred tries or more, have files of their own, so they run alongside.)

import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { type Answer, freshEmail, freshIp, freshPassword, type Harness, signUp, startHarness, unlessBusy, type Visitor, wait } from "./harness.ts";

let h: Harness;
before(async () => {
  h = await startHarness();
});
after(() => h.close());

const wrong = () => freshPassword();

/** Asks for a link to a fresh inbox, as the address in `ip`: whether an email went. */
async function linkFrom(harness: Harness, ip: string, kind: "password" | "sign-in" = "sign-in", to = freshEmail()): Promise<{ answer: Answer; to: string }> {
  const answer = await harness.visitor(ip).post(kind === "password" ? "/auth/send-password-link" : "/auth/send-sign-in-link", { email: to });
  return { answer, to };
}
const emailedTo = async (harness: Harness, to: string, waitMs = 300) => (await harness.countEmailsAfter((m) => m.to === to, waitMs)) > 0;

/** Wrong passwords by `visitor`, at `email`, one after another (asking again when busy), until paused: how many were checked. */
async function checkedUntilPaused(visitor: Visitor, email: string, most = 25): Promise<number> {
  for (let checked = 0; checked <= most; checked++) {
    const answer = await unlessBusy(() => visitor.post("/auth/sign-in", { email, password: wrong() }));
    if (answer.status === 429) {
      assert.ok(answer.headers.get("retry-after"), "a pause says when to try again");
      return checked;
    }
    assert.equal(answer.status, 401);
  }
  return Number.POSITIVE_INFINITY;
}

test("30 wrong passwords at once from one address check at most 10, and the rest are paused (23)", async (t) => {
  const account = await signUp(h);
  const visitor = h.visitor();
  const before = h.events.length;
  const answers = await Promise.all(Array.from({ length: 30 }, () => visitor.post("/auth/sign-in", { email: account.email, password: wrong() })));
  const counts = (status: number) => answers.filter((a) => a.status === status).length;
  t.diagnostic(`401: ${counts(401)}, 429: ${counts(429)}, 503: ${counts(503)}`);
  assert.ok(counts(401) <= 10, `${counts(401)} checked`);
  for (const answer of answers.filter((a) => a.status !== 401)) {
    assert.ok([429, 503].includes(answer.status), `answered ${answer.status}`);
    assert.ok(answer.headers.get("retry-after"));
  }
  const more = await checkedUntilPaused(visitor, account.email);
  assert.equal(counts(401) + more, 10, "exactly 10 checked, busy ones not counted");
  await wait(100);
  const failed = h.events.slice(before).filter((e) => e.type === "sign-in-failed" && e.userId === account.userId).length;
  assert.equal(failed, 10);
});

test("an address paused at an account is refused even the right password, while another address signs in (24)", async () => {
  const account = await signUp(h);
  const paused = h.visitor();
  assert.equal(await checkedUntilPaused(paused, account.email), 10);
  const right = await paused.post("/auth/sign-in", { email: account.email, password: account.password });
  assert.equal(right.status, 429);
  assert.deepEqual(right.setCookies, []);
  const elsewhere = await unlessBusy(() => h.visitor().post("/auth/sign-in", { email: account.email, password: account.password }));
  assert.equal(elsewhere.status, 200);
});

test("20 tries at different accounts from one address pause it for every account (26)", async () => {
  const account = await signUp(h);
  const visitor = h.visitor();
  for (let i = 0; i < 20; i += 2) {
    const pair = await Promise.all([0, 1].map(() => unlessBusy(() => visitor.post("/auth/sign-in", { email: freshEmail(), password: wrong() }))));
    for (const answer of pair) assert.equal(answer.status, 401);
  }
  const right = await visitor.post("/auth/sign-in", { email: account.email, password: account.password });
  assert.equal(right.status, 429);
  assert.ok(right.headers.get("retry-after"));
});

test("one IPv6 /64 however it's written counts as one address, and an IPv4 address carried in IPv6 as itself (28)", async (t) => {
  const spellings = [
    "2001:db8:28:1::5",
    "2001:0db8:0028:0001:0000:0000:0000:0005",
    "2001:DB8:28:1::5",
    "2001:db8:28:1:0:0:0:5",
    "2001:db8:28:1::5%eth0",
    "[2001:db8:28:1::5]:443",
    "2001:db8:28:1::abcd",
    "2001:db8:28:1:ffff:ffff:ffff:ffff",
    "2001:0DB8:028:01::0005",
  ];
  const v4 = [
    "203.0.113.28",
    "::ffff:203.0.113.28",
    "64:ff9b::203.0.113.28",
    "::ffff:cb00:711c",
    "64:ff9b::cb00:711c",
    "0:0:0:0:0:ffff:203.0.113.28",
    "203.0.113.28",
  ];
  for (const [label, forms] of [
    ["IPv6", spellings],
    ["IPv4 in IPv6", v4],
  ] as const) {
    const sent: { form: string; status: number; to: string }[] = [];
    for (const form of forms) {
      const { answer, to } = await linkFrom(h, form);
      sent.push({ form, status: answer.status, to });
    }
    await wait(300);
    const emailed = sent.filter((s) => h.emails.some((m) => m.to === s.to));
    t.diagnostic(`${label}: ${sent.map((s) => `${s.form} ${s.status}${emailed.includes(s) ? " emailed" : ""}`).join(", ")}`);
    for (const s of sent) assert.ok([202, 400, 429].includes(s.status), `${s.form} answered ${s.status}`);
    assert.ok(emailed.length <= 5, `${emailed.length} emails from one address: ${emailed.map((s) => s.form).join(", ")}`);
  }
  assert.ok(await emailedTo(h, (await linkFrom(h, "2001:db8:28:2::5")).to), "another /64 still gets one");
});

test("an address's sixth link of either kind in 15 minutes sends no email, and a /48's 21st (29)", async (t) => {
  const ip = freshIp();
  const kinds = ["password", "sign-in", "password", "sign-in", "password", "sign-in"] as const;
  const sent = [];
  for (const kind of kinds) sent.push(await linkFrom(h, ip, kind));
  await wait(300);
  const emailed = sent.map((s) => h.emails.some((m) => m.to === s.to));
  t.diagnostic(`one address, 6 links: ${sent.map((s, i) => `${s.answer.status} ${s.answer.text}${emailed[i] ? " emailed" : ""}`).join(", ")}`);
  assert.deepEqual(emailed, [true, true, true, true, true, false]);

  const block = [];
  for (let i = 1; i <= 21; i++) block.push(await linkFrom(h, `2001:db8:29:${i.toString(16)}::1`));
  await wait(300);
  const blockEmailed = block.map((s) => h.emails.some((m) => m.to === s.to));
  t.diagnostic(`one /48, 21 links: the 21st answered ${block[20]?.answer.status} ${block[20]?.answer.text}`);
  assert.deepEqual(blockEmailed, [...Array(20).fill(true), false]);
  assert.ok(await emailedTo(h, (await linkFrom(h, "2001:db8:2a:1::1")).to), "another /48 still gets one");
});

test("four sign-in links asked for one inbox send exactly three, all usable, and a password link still goes (30)", async () => {
  const account = await signUp(h);
  for (let i = 0; i < 4; i++) assert.equal((await linkFrom(h, freshIp(), "sign-in", account.email)).answer.status, 202);
  await wait(300);
  const signInLinks = h.emails.filter((m) => m.to === account.email && m.link?.kind === "sign-in");
  assert.equal(signInLinks.length, 3);
  for (const email of signInLinks) assert.equal((await h.visitor().post("/auth/link", { token: email.link?.token })).status, 200);
  await linkFrom(h, freshIp(), "password", account.email);
  await h.takeEmail((m) => m.to === account.email && m.link?.kind === "password");
});

test("counts and pauses outlive a restart (31)", async () => {
  const account = await signUp(h);
  const guesser = h.visitor();
  assert.equal(await checkedUntilPaused(guesser, account.email), 10);
  const asker = freshIp();
  for (let i = 0; i < 5; i++) await linkFrom(h, asker);
  await h.restart();
  const right = await guesser.post("/auth/sign-in", { email: account.email, password: account.password });
  assert.equal(right.status, 429, "still paused");
  assert.equal(await emailedTo(h, (await linkFrom(h, asker)).to), false, "still out of links");
  assert.equal(await emailedTo(h, (await linkFrom(h, freshIp())).to), true, "and it answers others");
});

test("ten wrong current passwords from a session pause its password checks, but not signing out everywhere (32)", async () => {
  const account = await signUp(h);
  for (let i = 0; i < 10; i++) {
    const answer = await unlessBusy(() => account.visitor.post("/auth/password", { current: wrong(), next: freshPassword() }));
    assert.ok(answer.status >= 400 && answer.status < 500 && answer.status !== 429, `try ${i + 1} answered ${answer.status}`);
  }
  const right = await account.visitor.post("/auth/password", { current: account.password, next: freshPassword() });
  assert.equal(right.status, 429);
  assert.ok(right.headers.get("retry-after"));
  assert.equal((await account.visitor.post("/auth/sign-out-everywhere")).status, 200);
  assert.deepEqual((await account.visitor.get("/auth/session")).json, { user: null });
});
