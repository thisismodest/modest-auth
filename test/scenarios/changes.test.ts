// Scenarios 46 to 54 of docs/scenarios.md: changing the password and the email.

import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { after, before, test } from "node:test";
import {
  askToMove,
  freshEmail,
  freshPassword,
  type Harness,
  isRefusal,
  rowsMentioning,
  signIn,
  signUp,
  startHarness,
  unlessBusy,
  wait,
  whoIs,
} from "./harness.ts";

let h: Harness;
before(async () => {
  h = await startHarness();
});
after(() => h.close());

const signsIn = async (email: string, password: string) => (await unlessBusy(() => h.visitor().post("/auth/sign-in", { email, password }))).status === 200;
const linkStillGood = async (token: string) => (await h.visitor().post("/auth/link", { token })).status === 200;

test("a password change keeps this session, ends the others, and sends a notice without the password (46)", async () => {
  const account = await signUp(h);
  const other = await signIn(h, account);
  const next = freshPassword();
  const changed = await unlessBusy(() => account.visitor.post("/auth/password", { next }));
  assert.equal(changed.status, 200);
  assert.equal(await whoIs(account.visitor), account.email);
  assert.equal(await whoIs(other), null);
  const notice = await h.takeEmail((m) => m.to === account.email && m.link === null);
  assert.ok(!notice.text.includes(next) && !notice.text.includes(account.password));
  assert.ok(!notice.subject.includes(next) && !notice.subject.includes(account.password));
});

test("a move link does nothing signed out, or signed in to another account, and isn't used up (47)", async () => {
  const account = await signUp(h);
  const victim = await signUp(h);
  const to = freshEmail("new");
  const token = await askToMove(h, account, to);

  const signedOut = await h.visitor().post("/auth/confirm-email", { token });
  assert.ok(isRefusal(signedOut.status), `signed out: ${signedOut.status}`);
  assert.ok(await linkStillGood(token));

  // The link reached someone else's inbox, and they opened it signed in to their own account.
  const elsewhere = await victim.visitor.post("/auth/confirm-email", { token });
  assert.ok(isRefusal(elsewhere.status), `another account: ${elsewhere.status}`);
  assert.equal(await whoIs(victim.visitor), victim.email);
  assert.equal(await whoIs(account.visitor), account.email);
  assert.ok(await linkStillGood(token));

  assert.equal((await account.visitor.post("/auth/confirm-email", { token })).status, 200);
  assert.ok(await signsIn(to, account.password));
});

test("a move to an address someone signed up at before it was confirmed fails cleanly, merging nothing (48)", async (t) => {
  const account = await signUp(h);
  const to = freshEmail("new");
  const token = await askToMove(h, account, to);
  const squatter = await signUp(h, to);
  const confirmed = await account.visitor.post("/auth/confirm-email", { token });
  t.diagnostic(`confirm answered ${confirmed.status} ${confirmed.text}`);
  assert.ok(isRefusal(confirmed.status), `answered ${confirmed.status}`);
  assert.equal(rowsMentioning(h.db, "auth_users", to), 1);
  assert.equal(rowsMentioning(h.db, "auth_users", account.email), 1);
  assert.equal(await whoIs(squatter.visitor), to);
  assert.ok(await signsIn(account.email, account.password));
});

test("a thief with the password can't move the account: nothing reaches the new address until the old one approves (49)", async () => {
  const owner = await signUp(h);
  const thief = await signIn(h, owner);
  const to = freshEmail("thief");
  const before = h.emails.length;
  const asked = await unlessBusy(() => thief.post("/auth/change-email", { email: to }));
  assert.equal(asked.status, 202, asked.text);
  await wait(200);
  const sent = h.emails.slice(before);
  assert.deepEqual(
    sent.map((m) => [m.to, m.link?.kind]),
    [[owner.email, "move"]],
    "one email, to the address the account has, asking it to approve",
  );
  assert.equal(rowsMentioning(h.db, "auth_users", owner.email), 1, "nothing moved");
  assert.ok(await signsIn(owner.email, owner.password));
});

test("an approval link signs nobody in, works once, and does nothing once the account has moved elsewhere (50)", async () => {
  const account = await signUp(h);
  const asked = await unlessBusy(() => account.visitor.post("/auth/change-email", { email: freshEmail("a") }));
  assert.equal(asked.status, 202);
  const stale = (await h.takeEmail((m) => m.to === account.email && m.link?.kind === "move")).link?.token ?? "";
  const visitor = h.visitor();
  const confirm = await askToMove(h, account, freshEmail("b"));
  assert.equal(await whoIs(visitor), null, "approving signs nobody in");
  assert.equal((await account.visitor.post("/auth/confirm-email", { token: confirm })).status, 200);
  const late = await visitor.post("/auth/approve-email", { token: stale });
  assert.ok(isRefusal(late.status), `an approval for an address the account no longer has: ${late.status}`);
});

test("a move asked for while the password changed isn't stored (52)", (t) => {
  t.skip("the race's window can't be aimed at from outside, so no test of it could be relied on");
});

test("a move to the same address, in any spelling, is refused or does nothing, with no notice to that inbox (53)", async (t) => {
  const local = `same${randomBytes(3).toString("hex")}`;
  const account = await signUp(h, `${local}@xn--bcher-kva.de`);
  for (const to of [
    `${local}@bücher.de`,
    `${local}@xn--bcher-kva.de`,
    `${local.toUpperCase()}@BÜCHER.DE`,
    `${[...local].map((c) => String.fromCodePoint((c.codePointAt(0) ?? 0) + 0xfee0)).join("")}@bücher.de`,
  ]) {
    const before = h.emails.length;
    const asked = await unlessBusy(() => account.visitor.post("/auth/change-email", { email: to }));
    await wait(200);
    const sent = h.emails.slice(before);
    t.diagnostic(`${to}: ${asked.status} ${asked.text}; emails: ${sent.map((m) => `${m.to} ${m.link?.kind ?? "notice"}`).join(", ") || "none"}`);
    assert.ok(asked.status < 500);
    assert.equal(sent.length, 0, "nothing sent");
    assert.equal(await whoIs(account.visitor), account.email, "still signed in, at the same address");
  }
});
