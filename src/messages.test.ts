import assert from "node:assert/strict";
import { test } from "node:test";
import { emailFor, type Message, messageFor } from "./messages.ts";
import { MINUTE } from "./time.ts";

const ORIGIN = "https://app.example.org";
const to = { email: "ann@example.org" };
const link = `${ORIGIN}/account/link#sign-in=${"a".repeat(43)}`;
const soon = () => Date.now() + 15 * MINUTE;

const EVERY: Message[] = [
  { kind: "sign-up", to, link, expires: soon() },
  { kind: "sign-in", to, link, expires: soon() },
  { kind: "new-password", to, link, expires: soon() },
  { kind: "no-account", to },
  { kind: "passkey-only", to },
  { kind: "confirm-email", to, link, expires: soon() },
  { kind: "email-in-use", to },
  { kind: "password-changed", to },
  { kind: "account-deleted", to },
  { kind: "approve-email", to, email: "ann@new.example", link, expires: soon() },
];

test("emailFor writes every kind: the link exactly once where there is one, and none where there isn't", () => {
  for (const message of EVERY) {
    const { subject, text } = emailFor(message, { origin: ORIGIN });
    assert.match(subject, / app\.example\.org$/, `${message.kind}: the subject names the site`);
    assert.equal(text.split(link).length - 1, "link" in message ? 1 : 0, message.kind);
    assert.doesNotMatch(subject, /[\r\n]/, `${message.kind}: one line`);
  }
});

test("emailFor says how long a link lasts", () => {
  assert.match(emailFor({ kind: "sign-in", to, link, expires: Date.now() + 15 * MINUTE }, { origin: ORIGIN }).text, /within 15 minutes/);
});

test("emailFor names the site with its host, which a copycat can't borrow", () => {
  const { subject, text } = emailFor({ kind: "sign-in", to, link, expires: soon() }, { origin: ORIGIN, name: "Example Club" });
  assert.equal(subject, "Sign in to Example Club");
  assert.match(text, /Example Club \(app\.example\.org\)/);
});

test("messageFor: each link becomes the message that fits it, and a refused one by the reason it was refused", () => {
  const url = `${ORIGIN}/account/link#x`;
  const open = (kind: "password" | "sign-in" | "email", account: boolean) => ({ kind, to: "ann@example.org", token: "t", account, expires: soon() });
  const refused = (kind: "sign-in" | "email", why: "no-account" | "email-in-use" | "passkey-only", account: boolean) =>
    ({ kind, to: "ann@example.org", token: null, refused: why, account, expires: soon() }) as const;
  assert.equal(messageFor(open("password", false), url).kind, "sign-up");
  assert.equal(messageFor(open("password", true), url).kind, "new-password");
  assert.equal(messageFor(open("sign-in", false), url).kind, "sign-up");
  assert.equal(messageFor(open("sign-in", true), url).kind, "sign-in");
  assert.equal(messageFor(open("email", false), url).kind, "confirm-email");
  for (const [kind, why, account] of [
    ["sign-in", "no-account", false],
    ["email", "email-in-use", true],
    ["sign-in", "passkey-only", true],
  ] as const) {
    assert.deepEqual(messageFor(refused(kind, why, account), url), { kind: why, to });
  }
  const move = { kind: "move", to: "ann@example.org", newEmail: "ann@new.example", token: "t", account: true, expires: soon() } as const;
  assert.deepEqual(messageFor(move, url), { kind: "approve-email", to, email: "ann@new.example", link: url, expires: move.expires });
});
