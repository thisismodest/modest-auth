// Scenarios 33 and 35 to 39 of docs/scenarios.md: not telling who has an account.
// Timing is compared by medians, with a generous tolerance: a skipped hash (about 100 to 200 ms)
// stands far outside it, and ordinary noise doesn't.

import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { type Answer, freshEmail, freshPassword, type Harness, median, signUp, startHarness, steadyHeaders, unlessBusy, wait } from "./harness.ts";

let h: Harness;
before(async () => {
  h = await startHarness();
});
after(() => h.close());

const same = (a: Answer, b: Answer) => {
  assert.equal(a.status, b.status);
  assert.equal(a.text, b.text);
  assert.deepEqual(steadyHeaders(a), steadyHeaders(b));
};
/** Two medians the same within noise: 40% of the larger, or `floor` ms, whichever is more. */
const sameTime = (a: number[], b: number[], floor: number) => {
  const [ma, mb] = [median(a), median(b)];
  assert.ok(Math.abs(ma - mb) <= Math.max(floor, 0.4 * Math.max(ma, mb)), `medians ${ma.toFixed(1)} ms and ${mb.toFixed(1)} ms`);
  return `${ma.toFixed(1)} ms and ${mb.toFixed(1)} ms`;
};

test("an unknown email and a wrong password get the same answer, in the same time (33)", async (t) => {
  const account = await signUp(h);
  const known: Answer[] = [];
  const unknown: Answer[] = [];
  for (let i = 0; i < 30; i++) {
    // A fresh address for each, so no limit is reached; the account's own hourly 100 is far off.
    unknown.push(await unlessBusy(() => h.visitor().post("/auth/sign-in", { email: freshEmail(), password: freshPassword() })));
    known.push(await unlessBusy(() => h.visitor().post("/auth/sign-in", { email: account.email, password: freshPassword() })));
  }
  for (let i = 0; i < known.length; i++) same(known[i] as Answer, unknown[i] as Answer);
  assert.equal(known[0]?.status, 401);
  t.diagnostic(
    `medians: ${sameTime(
      known.map((a) => a.ms),
      unknown.map((a) => a.ms),
      30,
    )}`,
  );
});

test("asking for either kind of link gives 202 {} the same, in the same time, and an email either way (35)", async (t) => {
  const accounts = [await signUp(h), await signUp(h)];
  for (const route of ["/auth/send-password-link", "/auth/send-sign-in-link"]) {
    const start = h.emails.length;
    const known: Answer[] = [];
    const unknown: Answer[] = [];
    const unknownInboxes: string[] = [];
    // Two links each to the accounts, so their inboxes' 3 aren't reached (the sign-up used one password link).
    for (let i = 0; i < 2; i++) {
      for (const account of accounts) {
        const inbox = freshEmail("nobody");
        unknownInboxes.push(inbox);
        unknown.push(await h.visitor().post(route, { email: inbox }));
        known.push(await h.visitor().post(route, { email: account.email }));
      }
    }
    for (const answer of [...known, ...unknown]) {
      assert.equal(answer.status, 202);
      assert.equal(answer.text, "{}");
      same(answer, known[0] as Answer);
    }
    t.diagnostic(
      `${route} medians: ${sameTime(
        known.map((a) => a.ms),
        unknown.map((a) => a.ms),
        15,
      )}`,
    );
    await wait(300);
    for (const inbox of unknownInboxes) {
      const emails = h.emails.filter((m) => m.to === inbox);
      assert.equal(emails.length, 1, "an email to an address with no account");
      if (route === "/auth/send-sign-in-link") {
        assert.equal(emails[0]?.link, null, "with no link in it");
        assert.ok(!/#|token/i.test(emails[0]?.text ?? ""));
      }
    }
    for (const account of accounts) assert.equal(h.emails.slice(start).filter((m) => m.to === account.email && m.link).length, 2);
  }
});

test("a slow email service doesn't make the next request's time show whether the address has an account (36)", async (t) => {
  const slow = await startHarness({
    sendEmail: async () => {
      await wait(2000);
    },
  });
  try {
    const account = await signUp(slow);
    const known: number[] = [];
    const unknown: number[] = [];
    const asking: number[] = [];
    for (let i = 0; i < 2; i++) {
      for (const [email, into] of [
        [freshEmail("nobody"), unknown],
        [account.email, known],
      ] as const) {
        const asked = await slow.visitor().post("/auth/send-sign-in-link", { email });
        asking.push(asked.ms);
        into.push((await slow.visitor().get("/auth/session")).ms);
      }
    }
    assert.ok(Math.max(...asking) < 1000, "the answer doesn't wait for the email");
    t.diagnostic(`next request medians: ${sameTime(known, unknown, 15)}`);
  } finally {
    await slow.close();
  }
});

test("asking to move to an address with an account or without gives the same answer, in the same time, and an email to each (37)", async (t) => {
  const mover = await signUp(h);
  const taken = await signUp(h);
  const toTaken: Answer[] = [];
  const toFree: Answer[] = [];
  const freeInboxes: string[] = [];
  // Two of each: with the sign-up's link, that's the 5 links one address may ask for in 15 minutes.
  for (let i = 0; i < 2; i++) {
    const free = freshEmail("free");
    freeInboxes.push(free);
    toFree.push(await unlessBusy(() => mover.visitor.post("/auth/change-email", { password: mover.password, email: free })));
    toTaken.push(await unlessBusy(() => mover.visitor.post("/auth/change-email", { password: mover.password, email: taken.email })));
  }
  for (let i = 0; i < 2; i++) same(toTaken[i] as Answer, toFree[i] as Answer);
  t.diagnostic(
    `answered ${toFree[0]?.status} ${toFree[0]?.text}; medians ${sameTime(
      toTaken.map((a) => a.ms),
      toFree.map((a) => a.ms),
      30,
    )}`,
  );
  await wait(300);
  for (const inbox of freeInboxes) assert.equal(h.emails.filter((m) => m.to === inbox && m.link?.kind === "email").length, 1);
  const toTakenInbox = h.emails.filter((m) => m.to === taken.email && m.link?.kind !== "password");
  assert.equal(toTakenInbox.length, 2, "an email to the address with an account each time");
  for (const email of toTakenInbox) assert.equal(email.link, null);
});

test("a fourth password link to one inbox looks the same whether or not it has an account (38)", async () => {
  const account = await signUp(h);
  const nobody = freshEmail("nobody");
  // The sign-up used one of the account's three.
  for (let i = 0; i < 2; i++) await h.visitor().post("/auth/send-password-link", { email: account.email });
  for (let i = 0; i < 3; i++) await h.visitor().post("/auth/send-password-link", { email: nobody });
  await wait(200);
  const beforeKnown = h.emails.filter((m) => m.to === account.email).length;
  const beforeNobody = h.emails.filter((m) => m.to === nobody).length;
  assert.equal(beforeNobody, 3);
  const known = await h.visitor().post("/auth/send-password-link", { email: account.email });
  const unknown = await h.visitor().post("/auth/send-password-link", { email: nobody });
  same(known, unknown);
  await wait(300);
  assert.equal(h.emails.filter((m) => m.to === account.email).length, beforeKnown, "no fourth email");
  assert.equal(h.emails.filter((m) => m.to === nobody).length, beforeNobody, "no fourth email");
});

test("a malformed email and an unknown one each get a fixed answer, whatever accounts exist (39)", async (t) => {
  const fresh = await startHarness();
  try {
    const tries = ["not-an-email", "a@b@example.net", "<x>@example.net", "x@example.net\n", "\u200bx@example.net"];
    const ask = async () => {
      const answers: Answer[] = [];
      for (const email of tries) answers.push(await unlessBusy(() => fresh.visitor().post("/auth/sign-in", { email, password: freshPassword() })));
      return answers;
    };
    const before = await ask();
    t.diagnostic(`sign-in with a malformed email: ${[...new Set(before.map((a) => a.json?.error?.code))].join(", ")}`);
    for (const answer of before) {
      assert.ok(answer.status >= 400 && answer.status < 500);
      same(answer, before[0] as Answer);
    }
    const linkAnswer = await fresh.visitor().post("/auth/send-password-link", { email: "not-an-email" });
    t.diagnostic(`send-password-link with a malformed email: ${linkAnswer.status} ${linkAnswer.text}`);
    const accounts = [await signUp(fresh, "x@example.net"), await signUp(fresh)];
    const after = await ask();
    for (let i = 0; i < tries.length; i++) same(before[i] as Answer, after[i] as Answer);
    const unknown = await unlessBusy(() => fresh.visitor().post("/auth/sign-in", { email: freshEmail(), password: freshPassword() }));
    assert.equal(unknown.json?.error?.code, "wrong-credentials");
    const malformedLink = await fresh.visitor().post("/auth/send-password-link", { email: "not-an-email" });
    same(malformedLink, linkAnswer);
    assert.equal(accounts.length, 2);
  } finally {
    await fresh.close();
  }
});
