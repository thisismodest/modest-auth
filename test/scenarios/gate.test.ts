// Scenarios 72 to 74, and 88 and 89, of docs/scenarios.md: the concurrency gate on password hashing.

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { after, before, test } from "node:test";
import { HASHING } from "../../src/index.ts";
import { type Answer, askForLink, freshEmail, freshPassword, type Harness, signUp, startHarness, unlessBusy, wait } from "./harness.ts";

let h: Harness;
before(async () => {
  h = await startHarness();
});
after(() => h.close());

test("a flood of sign-ins is refused as busy, counting only those checked, the same for known and unknown emails, while sessions answer fast (72, 73)", async (t) => {
  const account = await signUp(h);
  const before = h.events.length;
  const sends: Promise<Answer & { known: boolean }>[] = [];
  for (let i = 0; i < 60; i++) {
    const known = i % 2 === 0;
    const email = known ? account.email : freshEmail("nobody");
    sends.push(
      h
        .visitor()
        .post("/auth/sign-in", { email, password: freshPassword() })
        .then((a) => ({ ...a, known })),
    );
  }
  await wait(30);
  const session = await account.visitor.get("/auth/session");
  const answers = await Promise.all(sends);
  const busy = answers.filter((a) => a.status === 503);
  const busyKnown = busy.filter((a) => a.known).length;
  const busyUnknown = busy.length - busyKnown;
  const checkedKnown = answers.filter((a) => a.known && a.status === 401).length;
  t.diagnostic(
    `busy: ${busyKnown} known, ${busyUnknown} unknown; checked: ${answers.filter((a) => a.status === 401).length}; session answered in ${session.ms.toFixed(1)} ms`,
  );
  assert.ok(busy.length > 0, "some refused as busy");
  for (const answer of busy) {
    assert.ok(answer.headers.get("retry-after"));
    assert.equal(answer.json?.error?.code, "busy");
  }
  for (const answer of answers) assert.ok([401, 503].includes(answer.status), `answered ${answer.status}`);
  assert.ok(Math.abs(busyKnown - busyUnknown) <= 6, "busy as often for either");
  assert.equal(session.json?.user?.email, account.email);
  assert.ok(session.ms < 250, `the session took ${session.ms} ms`);
  await wait(100);
  const failed = h.events.slice(before).filter((e) => e.type === "sign-in-failed" && e.userId === account.userId).length;
  assert.equal(failed, checkedKnown, "only those checked are counted");
});

test("set-password, password, and delete-account wait at the same gate, and busy refusals there don't count towards the 10 an hour (74)", async (t) => {
  const account = await signUp(h);
  const token = await askForLink(h, "password", freshEmail());
  // Fill the gate with sign-ins, then try each of the others while it's full.
  const flood = Array.from({ length: 70 }, () => h.visitor().post("/auth/sign-in", { email: freshEmail("nobody"), password: freshPassword() }));
  await wait(200);
  const during = await Promise.all([
    account.visitor.post("/auth/password", { current: freshPassword(), next: freshPassword() }),
    account.visitor.post("/auth/delete-account", { password: freshPassword() }),
    account.visitor.post("/auth/password", { current: freshPassword(), next: freshPassword() }),
    h.visitor().post("/auth/set-password", { token, password: freshPassword() }),
  ]);
  await Promise.all(flood);
  t.diagnostic(
    `while full: password ${during[0]?.status}, delete-account ${during[1]?.status}, password ${during[2]?.status}, set-password ${during[3]?.status}`,
  );
  for (const answer of during) assert.ok([401, 503].includes(answer.status) || answer.json?.error?.code === "invalid-link", `answered ${answer.status}`);
  assert.ok(during.some((a) => a.status === 503));
  const accountChecks = during.slice(0, 3).filter((a) => a.status === 401).length;
  let checked = accountChecks;
  for (; checked < 12; checked++) {
    const answer = await unlessBusy(() => account.visitor.post("/auth/password", { current: freshPassword(), next: freshPassword() }));
    if (answer.status === 429) break;
  }
  assert.equal(checked, 10, "the busy refusals cost the account none of its 10");
});

/** Sign-ins sent all at once, by `count` visitors, each to an email with no account. */
const flood = (count: number) =>
  Array.from({ length: count }, () => h.visitor().post("/auth/sign-in", { email: freshEmail("nobody"), password: freshPassword() }));

test("HASHING says how many hash at once and how many may wait, and that's what a flood meets (88)", async (t) => {
  t.diagnostic(`on this machine: ${HASHING.atOnce} at once, ${HASHING.waiting} waiting`);
  assert.ok(HASHING.atOnce >= 1 && HASHING.atOnce <= 16);
  assert.equal(HASHING.waiting, 25 * HASHING.atOnce);
  const within = await Promise.all(flood(HASHING.atOnce + HASHING.waiting));
  assert.deepEqual(
    within.filter((a) => a.status === 503).map((a) => a.status),
    [],
    "as many as may hash or wait: none refused",
  );
  const beyond = await Promise.all(flood(HASHING.atOnce + HASHING.waiting + 30));
  assert.ok(
    beyond.some((a) => a.status === 503 && a.json?.error?.code === "busy"),
    "beyond both: some refused as busy",
  );
});

test("while hashing is as busy as it gets, reading a file still takes moments (89)", async (t) => {
  const sends = flood(HASHING.atOnce + HASHING.waiting);
  await wait(30);
  const took: number[] = [];
  for (let i = 0; i < 10; i++) {
    const started = performance.now();
    await readFile(new URL(import.meta.url));
    took.push(performance.now() - started);
  }
  await Promise.all(sends);
  const middle = [...took].sort((a, b) => a - b)[5] ?? 0;
  t.diagnostic(`file reads during the flood: ${took.map((ms) => ms.toFixed(1)).join(", ")} ms`);
  assert.ok(middle < 25, `a file read took ${middle.toFixed(1)} ms in the middle, waiting behind the hashing`);
});
