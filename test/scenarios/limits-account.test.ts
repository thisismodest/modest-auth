// Scenarios 25, 34, and 82 of docs/scenarios.md: the hundred tries an hour at one account,
// for a real account and an unknown email alike. A file of its own, as it hashes a few hundred passwords.

import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { freshEmail, freshPassword, type Harness, signUp, startHarness, unlessBusy, whoIs } from "./harness.ts";

let h: Harness;
before(async () => {
  h = await startHarness();
});
after(() => h.close());

/** `tries` wrong passwords at `email`, 10 from each of several addresses, two at a time: their statuses. */
async function spread(email: string, tries: number): Promise<number[]> {
  const statuses: number[] = [];
  let visitor = h.visitor();
  for (let i = 0; i < tries; i += 2) {
    if (i % 10 === 0) visitor = h.visitor();
    const pair = await Promise.all([0, 1].map(() => unlessBusy(() => visitor.post("/auth/sign-in", { email, password: freshPassword() }))));
    statuses.push(...pair.map((a) => a.status));
  }
  return statuses;
}

let realAfterHundred: number[] = [];

test("100 tries at one account pause signing in to it from anywhere, but not its owner's link or session (25, 82)", async () => {
  const account = await signUp(h);
  const statuses = await spread(account.email, 100);
  assert.deepEqual(new Set(statuses), new Set([401]), "all 100 checked");
  const fresh = await h.visitor().post("/auth/sign-in", { email: account.email, password: account.password });
  assert.equal(fresh.status, 429, "a twelfth address is paused, even with the right password");
  assert.ok(fresh.headers.get("retry-after"));
  realAfterHundred = [...statuses, fresh.status];

  // A sign-in link from another network still works (82).
  const owner = h.visitor("2001:db8:82::1");
  assert.equal((await owner.post("/auth/send-sign-in-link", { email: account.email })).status, 202);
  const link = await h.takeEmail((m) => m.to === account.email && m.link?.kind === "sign-in");
  assert.equal((await owner.post("/auth/sign-in-with-link", { token: link.link?.token })).status, 200);
  assert.equal(await whoIs(owner), account.email);

  // The signed-in owner can still change the password, and delete the account.
  const next = freshPassword();
  assert.equal((await unlessBusy(() => account.visitor.post("/auth/password", { current: account.password, next }))).status, 200);
  assert.equal((await unlessBusy(() => account.visitor.post("/auth/delete-account", { password: next }))).status, 200);
});

test("an unknown email pauses after the same tries as a real one, from one address and from many (34)", async () => {
  const real = await signUp(h);
  const unknown = freshEmail("nobody");
  const fromOne = async (email: string) => {
    const visitor = h.visitor();
    const statuses = [];
    for (let i = 0; i < 11; i++) statuses.push((await unlessBusy(() => visitor.post("/auth/sign-in", { email, password: freshPassword() }))).status);
    return statuses;
  };
  const realOne = await fromOne(real.email);
  const unknownOne = await fromOne(unknown);
  assert.deepEqual(realOne, [...Array(10).fill(401), 429]);
  assert.deepEqual(unknownOne, realOne);

  const other = freshEmail("nobody");
  const statuses = await spread(other, 100);
  const fresh = await h.visitor().post("/auth/sign-in", { email: other, password: freshPassword() });
  assert.deepEqual([...statuses, fresh.status], realAfterHundred.length ? realAfterHundred : [...Array(100).fill(401), 429]);
});
