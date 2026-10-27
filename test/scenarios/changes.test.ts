// Scenarios 46 to 54 of docs/scenarios.md: changing the password and the email, and the undo link.

import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { after, before, test } from "node:test";
import {
  type Account,
  askForLink,
  freshEmail,
  freshPassword,
  type Harness,
  moveAccount,
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

const isRefusal = (status: number) => status >= 400 && status < 500;
const signsIn = async (email: string, password: string) => (await unlessBusy(() => h.visitor().post("/auth/sign-in", { email, password }))).status === 200;
const linkStillGood = async (token: string) => (await h.visitor().post("/auth/link", { token })).status === 200;

/** Asks to move `account` to `to`: the token of the link emailed there. */
async function askToMove(account: Account, to: string): Promise<string> {
  const asked = await unlessBusy(() => account.visitor.post("/auth/change-email", { password: account.password, email: to }));
  assert.equal(asked.status, 202, asked.text);
  return (await h.takeEmail((m) => m.to === to && m.link?.kind === "email")).link?.token ?? "";
}

test("a password change keeps this session, ends the others, and sends a notice without the password (46)", async () => {
  const account = await signUp(h);
  const other = await signIn(h, account);
  const next = freshPassword();
  const changed = await unlessBusy(() => account.visitor.post("/auth/password", { current: account.password, next }));
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
  const token = await askToMove(account, to);

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
  const token = await askToMove(account, to);
  const squatter = await signUp(h, to);
  const confirmed = await account.visitor.post("/auth/confirm-email", { token });
  t.diagnostic(`confirm answered ${confirmed.status} ${confirmed.text}`);
  assert.ok(isRefusal(confirmed.status), `answered ${confirmed.status}`);
  assert.equal(rowsMentioning(h.db, "auth_users", to), 1);
  assert.equal(rowsMentioning(h.db, "auth_users", account.email), 1);
  assert.equal(await whoIs(squatter.visitor), to);
  assert.ok(await signsIn(account.email, account.password));
});

test("undoing a move when the old address has an account again leaves no two accounts sharing it (49)", async (t) => {
  // Another account moves to the old address before the undo.
  const ann = freshEmail("ann");
  const first = await signUp(h, ann);
  const { undo } = await moveAccount(h, first, freshEmail("a2"));
  const other = await signUp(h);
  await moveAccount(h, other, ann);
  const undone = await h.visitor().post("/auth/undo-email", { token: undo });
  t.diagnostic(`undo, with another account now at the old address: ${undone.status} ${undone.text}`);
  assert.ok(undone.status < 500);
  assert.ok(rowsMentioning(h.db, "auth_users", ann) <= 1, "one account at most at the old address");

  // A password link at the old address first (which restores the account), then the undo.
  const bea = freshEmail("bea");
  const second = await signUp(h, bea);
  const moved = await moveAccount(h, second, freshEmail("b2"));
  const reset = await askForLink(h, "password", bea);
  assert.equal((await unlessBusy(() => h.visitor().post("/auth/set-password", { token: reset, password: freshPassword() }))).status, 200);
  const late = await h.visitor().post("/auth/undo-email", { token: moved.undo });
  t.diagnostic(`undo after a password link restored the account: ${late.status} ${late.text}`);
  assert.ok(late.status < 500);
  assert.ok(rowsMentioning(h.db, "auth_users", bea) <= 1, "one account at most at the old address");
});

test("the owner's undo outlasts a thief's two moves and new password, and gives the owner a way back in (50)", async () => {
  const owner = await signUp(h);
  const home = owner.email;
  const ownerPassword = owner.password;
  // The thief has the password and a session.
  const thief: Account = { ...owner, visitor: await signIn(h, owner) };
  const { undo } = await moveAccount(h, thief, freshEmail("t1"));
  await signIn(h, thief, thief.visitor);
  await moveAccount(h, thief, freshEmail("t2"));
  await signIn(h, thief, thief.visitor);
  const thiefPassword = freshPassword();
  assert.equal((await unlessBusy(() => thief.visitor.post("/auth/password", { current: thief.password, next: thiefPassword }))).status, 200);
  // The home address's password links are used up meanwhile.
  for (let i = 0; i < 3; i++) await h.visitor().post("/auth/send-password-link", { email: home });
  await wait(200);
  const before = h.emails.filter((m) => m.to === home && m.link?.kind === "password").length;

  const undone = await h.visitor().post("/auth/undo-email", { token: undo });
  assert.equal(undone.status, 200, undone.text);
  assert.equal(await whoIs(thief.visitor), null);
  assert.equal(await signsIn(home, ownerPassword), false, "the old password is useless");
  assert.equal(await signsIn(home, thiefPassword), false, "and the thief's");
  await wait(200);
  const links = h.emails.filter((m) => m.to === home && m.link?.kind === "password");
  assert.equal(links.length, before + 1, "a password link even past the limit");
  const visitor = h.visitor();
  assert.equal(
    (await unlessBusy(() => visitor.post("/auth/set-password", { token: links[links.length - 1]?.link?.token, password: freshPassword() }))).status,
    200,
  );
  assert.equal(await whoIs(visitor), home);
});

test("a thief undoing their own second move doesn't cancel the owner's undo of the first (51)", async () => {
  const owner = await signUp(h);
  const home = owner.email;
  const thief: Account = { ...owner, visitor: await signIn(h, owner) };
  const first = await moveAccount(h, thief, freshEmail("t1"));
  await signIn(h, thief, thief.visitor);
  const second = await moveAccount(h, thief, freshEmail("t2"));
  assert.equal((await h.visitor().post("/auth/undo-email", { token: second.undo })).status, 200);
  const undone = await h.visitor().post("/auth/undo-email", { token: first.undo });
  assert.equal(undone.status, 200, undone.text);
  assert.equal(rowsMentioning(h.db, "auth_users", home), 1);
  await h.takeEmail((m) => m.to === home && m.link?.kind === "password");
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
    const asked = await unlessBusy(() => account.visitor.post("/auth/change-email", { password: account.password, email: to }));
    await wait(200);
    const sent = h.emails.slice(before);
    t.diagnostic(`${to}: ${asked.status} ${asked.text}; emails: ${sent.map((m) => `${m.to} ${m.link?.kind ?? "notice"}`).join(", ") || "none"}`);
    assert.ok(asked.status < 500);
    const link = sent.find((m) => m.link?.kind === "email");
    if (link) {
      const confirmed = await account.visitor.post("/auth/confirm-email", { token: link.link?.token });
      t.diagnostic(`its link: ${confirmed.status}`);
      await wait(200);
    }
    assert.equal(h.emails.slice(before).filter((m) => m.link?.kind === "undo").length, 0, "no old-address notice to the same inbox");
    assert.equal(await whoIs(account.visitor), account.email, "still signed in, at the same address");
  }
});

test("an undo link at 7 days and a minute is refused (54)", (t) => {
  t.skip("needs the clock moved on, and README documents no way to control time");
});
