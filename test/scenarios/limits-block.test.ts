// Scenario 27 of docs/scenarios.md: 200 tries from one IPv6 /48 pause it, whichever /64s they came from.
// A file of its own, as it hashes 200 passwords.

import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { freshEmail, freshPassword, type Harness, startHarness, unlessBusy } from "./harness.ts";

let h: Harness;
before(async () => {
  h = await startHarness();
});
after(() => h.close());

test("200 tries across the /64s of one /48 pause the whole /48, and only it (27)", async () => {
  for (let block = 1; block <= 20; block++) {
    const visitor = h.visitor(`2001:db8:27:${block.toString(16)}::1`);
    const email = freshEmail();
    for (let i = 0; i < 10; i += 2) {
      const pair = await Promise.all([0, 1].map(() => unlessBusy(() => visitor.post("/auth/sign-in", { email, password: freshPassword() }))));
      for (const answer of pair) assert.equal(answer.status, 401, `/64 number ${block}`);
    }
  }
  const sameBlock = await h.visitor("2001:db8:27:ff::1").post("/auth/sign-in", { email: freshEmail(), password: freshPassword() });
  assert.equal(sameBlock.status, 429);
  assert.ok(sameBlock.headers.get("retry-after"));
  const otherBlock = await unlessBusy(() => h.visitor("2001:db8:28:ff::1").post("/auth/sign-in", { email: freshEmail(), password: freshPassword() }));
  assert.equal(otherBlock.status, 401);
});
