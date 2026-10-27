// Scenarios 75 to 78 of docs/scenarios.md: events and the log.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { askForLink, freshEmail, freshIp, freshPassword, type Harness, moveAccount, signIn, signUp, startHarness, unlessBusy, wait } from "./harness.ts";

const hashesOf = (secret: string) => {
  const digest = createHash("sha256").update(secret).digest();
  return [digest.toString("hex"), digest.toString("base64url"), digest.toString("base64")];
};

/** A run through every route, by a few visitors: everything secret it handled. */
async function fullRun(h: Harness): Promise<string[]> {
  const secrets: string[] = [];
  const account = await signUp(h, freshEmail("loggable"));
  const first = account.email;
  const other = await signIn(h, account, h.visitor(`${freshIp()}, ${freshIp()}`));
  const wrong = freshPassword();
  await unlessBusy(() => h.visitor().post("/auth/sign-in", { email: account.email, password: wrong }));
  const unknown = freshEmail("unknown");
  await unlessBusy(() => h.visitor().post("/auth/sign-in", { email: unknown, password: wrong }));
  const signInToken = await askForLink(h, "sign-in", account.email);
  const linked = h.visitor();
  await linked.post("/auth/link", { token: signInToken });
  await linked.post("/auth/sign-in-with-link", { token: signInToken });
  await h.visitor().post("/auth/send-sign-in-link", { email: unknown });
  await other.get("/auth/sessions");
  await other.get("/auth/my-data");
  const next = freshPassword();
  await unlessBusy(() => account.visitor.post("/auth/password", { current: account.password, next }));
  secrets.push(account.password);
  account.password = next;
  await unlessBusy(() => account.visitor.post("/auth/password", { current: freshPassword(), next: freshPassword() }));
  const moved = freshEmail("moved");
  const { undo } = await moveAccount(h, account, moved);
  await h.visitor().post("/auth/undo-email", { token: undo });
  const reset = await h.takeEmail((m) => m.to === first && m.link?.kind === "password");
  const finalPassword = freshPassword();
  const last = h.visitor();
  await unlessBusy(() => last.post("/auth/set-password", { token: reset.link?.token, password: finalPassword }));
  await last.post("/auth/sign-out");
  await signIn(h, { email: first, password: finalPassword }, last);
  await last.post("/auth/sign-out-everywhere");
  await signIn(h, { email: first, password: finalPassword }, last);
  await unlessBusy(() => last.post("/auth/delete-account", { password: finalPassword }));
  await wait(200);

  secrets.push(next, wrong, finalPassword, first, moved, unknown, first.toUpperCase());
  for (const email of h.emails) if (email.link) secrets.push(email.link.token, ...hashesOf(email.link.token));
  for (const visitor of [account.visitor, other, linked, last]) for (const value of visitor.cookies.values()) secrets.push(value, ...hashesOf(value));
  return secrets;
}

test("nothing secret reaches the log, the console, or the events: no password, token, cookie, email, or token's hash (75)", async () => {
  const h = await startHarness();
  try {
    const stdoutBefore = h.stdout.length;
    const secrets = await fullRun(h);
    const seen = [h.logs.join("\n"), h.stdout.slice(stdoutBefore).join("\n"), JSON.stringify(h.events)].join("\n");
    for (const secret of secrets) assert.ok(!seen.includes(secret), "a secret was written out");
    // Not stdout: it carries the test runner's own reports, as bytes in which "@" can turn up.
    assert.ok(![...h.logs, JSON.stringify(h.events)].join("\n").includes("@"), "no email at all");
  } finally {
    await h.close();
  }
});

test("every event has its account's id and the address worked out, never the raw header, and an unknown email's has no email (78)", async () => {
  const h = await startHarness();
  try {
    await fullRun(h);
    const missing: string[] = [];
    for (const event of h.events) {
      if (typeof event.from !== "string") missing.push(`${event.type} has no from`);
      assert.ok(!event.from?.includes(","), `${event.type} from ${event.from}`);
      if (event.type !== "sign-in-failed" && typeof event.userId !== "string") missing.push(`${event.type} has no account id`);
    }
    const failedUnknown = h.events.filter((e) => e.type === "sign-in-failed" && !e.userId);
    assert.equal(failedUnknown.length, 1, "the unknown email's sign-in is an event with no account");
    assert.ok(!JSON.stringify(h.events).includes("@"));
    assert.deepEqual(missing, [], "README: events come with the account's id and where it came from");
  } finally {
    await h.close();
  }
});

test("an email service's error holding the link is logged without it (76)", async () => {
  const h = await startHarness({
    sendEmail: (to, _subject, text) => {
      throw new Error(`could not send to ${to}: ${text}`);
    },
  });
  try {
    await h.visitor().post("/auth/send-password-link", { email: freshEmail() });
    await wait(200);
    const email = h.emails[0];
    assert.ok(email?.link);
    const log = h.logs.join("\n");
    assert.ok(log.length > 0, "the failure is logged");
    assert.ok(!log.includes(email.link.token), "without the link");
    assert.ok(!log.includes(email.to), "or the address");
  } finally {
    await h.close();
  }
});

test("an onEvent that throws changes no answer, and is logged (77)", async () => {
  const h = await startHarness({
    onEvent: () => {
      throw new Error("the app's own bug");
    },
  });
  try {
    const account = await signUp(h);
    const visitor = await signIn(h, account);
    assert.equal((await visitor.get("/auth/session")).json?.user?.email, account.email);
    await wait(50);
    assert.ok(
      h.logs.some((line) => /onEvent|the app's own bug/.test(line)),
      "the failure is logged",
    );
  } finally {
    await h.close();
  }
});
