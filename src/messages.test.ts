import assert from "node:assert/strict";
import { test } from "node:test";
import { emailFor, type Message, messageFor } from "./messages.ts";
import { DAY, MINUTE } from "./time.ts";

const ORIGIN = "https://app.example.org";
const to = { email: "ann@example.org" };
const link = `${ORIGIN}/account/link#sign-in=${"a".repeat(43)}`;
const soon = () => Date.now() + 15 * MINUTE;

const EVERY: Message[] = [
  { kind: "sign-up", to, link, expires: soon() },
  { kind: "sign-in", to, link, expires: soon() },
  { kind: "new-password", to, link, expires: soon() },
  { kind: "no-account", to },
  { kind: "confirm-email", to, link, expires: soon() },
  { kind: "email-in-use", to },
  { kind: "password-changed", to },
  { kind: "account-deleted", to },
  { kind: "email-changed", to, email: "ann@new.example", link, expires: Date.now() + 7 * DAY },
];

test("emailFor writes every kind: the link exactly once where there is one, and none where there isn't", () => {
  for (const message of EVERY) {
    const { subject, text } = emailFor(message, { origin: ORIGIN });
    assert.match(subject, / app\.example\.org$/, `${message.kind}: the subject names the site`);
    assert.equal(text.split(link).length - 1, "link" in message ? 1 : 0, message.kind);
    assert.doesNotMatch(subject, /[\r\n]/, `${message.kind}: one line`);
  }
});

test("emailFor says how long a link lasts: in minutes, or in days for an undo", () => {
  assert.match(emailFor({ kind: "sign-in", to, link, expires: Date.now() + 15 * MINUTE }, { origin: ORIGIN }).text, /within 15 minutes/);
  assert.match(emailFor(EVERY[8] as Message, { origin: ORIGIN }).text, /within 7 days/);
});

test("emailFor names the site with its host, which a copycat can't borrow", () => {
  const { subject, text } = emailFor({ kind: "sign-in", to, link, expires: soon() }, { origin: ORIGIN, name: "Example Club" });
  assert.equal(subject, "Sign in to Example Club");
  assert.match(text, /Example Club \(app\.example\.org\)/);
});

test("messageFor: each link becomes the message that fits it, and an undo link isn't one on its own", () => {
  const link = (kind: "password" | "sign-in" | "email" | "undo", token: string | null, account: boolean) => ({
    kind,
    to: "ann@example.org",
    token,
    account,
    expires: soon(),
  });
  const url = `${ORIGIN}/account/link#x`;
  assert.equal(messageFor(link("password", "t", false), url).kind, "sign-up");
  assert.equal(messageFor(link("password", "t", true), url).kind, "new-password");
  assert.equal(messageFor(link("sign-in", "t", false), url).kind, "sign-up");
  assert.equal(messageFor(link("sign-in", "t", true), url).kind, "sign-in");
  assert.deepEqual(messageFor(link("sign-in", null, false), url), { kind: "no-account", to });
  assert.equal(messageFor(link("email", "t", false), url).kind, "confirm-email");
  assert.deepEqual(messageFor(link("email", null, true), url), { kind: "email-in-use", to });
  assert.throws(() => messageFor(link("undo", "t", true), url), /email-changed/);
});
