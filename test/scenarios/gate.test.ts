// Scenarios 72 to 74, and 88 and 89, of docs/scenarios.md: the concurrency gate on password hashing.

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { after, before, test } from "node:test";
import { HASHING } from "../../src/index.ts";
import { type Answer, askForLink, freshEmail, freshPassword, type Harness, hashTime, signUp, startHarness, unlessBusy, wait } from "./harness.ts";

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
  // Queued behind the flood, it would wait for dozens of hashes; a few hashes' time is noise on a busy machine.
  const hashMs = await hashTime();
  assert.ok(session.ms < Math.max(250, 5 * hashMs), `the session took ${session.ms.toFixed(1)} ms (a hash here: ${hashMs.toFixed(1)} ms)`);
  await wait(100);
  const failed = h.events.slice(before).filter((e) => e.type === "sign-in-failed" && e.userId === account.userId).length;
  assert.equal(failed, checkedKnown, "only those checked are counted");
});

test("set-password and password wait at the same gate as sign-in, and a busy refusal changes nothing (74)", async (t) => {
  const account = await signUp(h);
  const token = await askForLink(h, "password", freshEmail());
  // Fill the gate with sign-ins (more than may hash or wait, on this machine), then try each of the others while it's full.
  const flood = Array.from({ length: HASHING.atOnce + HASHING.waiting + 40 }, () =>
    h.visitor().post("/auth/sign-in", { email: freshEmail("nobody"), password: freshPassword() }),
  );
  await wait(30);
  const next = freshPassword();
  const during = await Promise.all([
    account.visitor.post("/auth/password", { next }),
    h.visitor().post("/auth/set-password", { token, password: freshPassword() }),
  ]);
  await Promise.all(flood);
  t.diagnostic(`while full: password ${during[0]?.status}, set-password ${during[1]?.status}`);
  for (const answer of during) assert.ok([200, 503].includes(answer.status), `answered ${answer.status}`);
  assert.ok(during.some((a) => a.status === 503));
  // Refused as busy: nothing changed, so the same requests go through once the gate is free.
  if (during[0]?.status === 503) assert.equal((await unlessBusy(() => account.visitor.post("/auth/password", { next }))).status, 200);
  if (during[1]?.status === 503)
    assert.equal((await unlessBusy(() => h.visitor().post("/auth/set-password", { token, password: freshPassword() }))).status, 200);
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
  // A read waiting behind the hashing would take at least one hash: half of one, on this machine, is the bar.
  const hash = await hashTime();
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
  assert.ok(middle < hash / 2, `a file read took ${middle.toFixed(1)} ms in the middle (a hash takes ${hash.toFixed(1)}), waiting behind the hashing`);
});
