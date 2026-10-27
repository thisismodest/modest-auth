// Scenarios 40 to 45 of docs/scenarios.md: the rules for new passwords, and the breached-password check.

import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { after, before, test } from "node:test";
import { askForLink, freshEmail, freshPassword, type Harness, signUp, startHarness, unlessBusy, wait, whoIs } from "./harness.ts";

let h: Harness;
const prefixes: string[] = [];
let breachMode: "answer" | "hang" = "answer";
let breached = "";
const sha1 = (text: string) => createHash("sha1").update(text, "utf8").digest("hex").toUpperCase();

before(async () => {
  h = await startHarness({
    breachedRange: (prefix) => {
      prefixes.push(prefix);
      if (breachMode === "hang") return new Promise<string>(() => {});
      const hash = sha1(breached);
      return hash.startsWith(prefix) ? `${hash.slice(5)}:12\r\n0000000000000000000000000000000000A:1` : "0000000000000000000000000000000000A:1";
    },
  });
});
after(() => h.close());

const isRefusal = (status: number) => status >= 400 && status < 500;
/** Characters chosen at random out of `alphabet`, as code points. */
const randomFrom = (alphabet: string[], length: number) => Array.from({ length }, () => alphabet[(randomBytes(1)[0] as number) % alphabet.length]).join("");
const ascii = [..."abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789-_"];
const emoji = Array.from({ length: 80 }, (_, i) => String.fromCodePoint(0x1f600 + i));

/** Tries a password at a password link: the answer (a refusal leaves the link usable). */
const tryAt = (token: string, password: string, raw?: string) =>
  unlessBusy(() => h.visitor().post("/auth/set-password", { token, password }, raw === undefined ? {} : { raw }));

test("new passwords are 15 to 200 characters, counted as characters (40)", async () => {
  const token = await askForLink(h, "password", freshEmail());
  for (const [password, code] of [
    [randomFrom(ascii, 14), "short-password"],
    [randomFrom(ascii, 201), "long-password"],
    [emoji.slice(0, 14).join(""), "short-password"],
  ] as const) {
    const answer = await tryAt(token, password);
    assert.ok(isRefusal(answer.status), `${[...password].length} characters answered ${answer.status}`);
    assert.equal(answer.json?.error?.code, code);
  }
  for (const password of [randomFrom(ascii, 15), randomFrom(ascii, 200), emoji.slice(0, 15).join(""), randomFrom(emoji, 200)]) {
    const fresh = await askForLink(h, "password", freshEmail());
    const answer = await tryAt(fresh, password);
    assert.equal(answer.status, 200, `${[...password].length} characters (${password.length} UTF-16 units) answered ${answer.status} ${answer.text}`);
  }
  assert.equal((await tryAt(token, freshPassword())).status, 200, "the refusals left the link usable");
});

test("the longest passwords allowed fit the body limit, as a browser's JSON sends them (41)", async (t) => {
  const account = await signUp(h, freshEmail(), randomFrom(emoji, 200));
  const next = randomFrom(emoji, 200);
  const body = JSON.stringify({ current: account.password, next });
  t.diagnostic(`as JSON.stringify sends it: ${Buffer.byteLength(body)} bytes`);
  const changed = await unlessBusy(() => account.visitor.post("/auth/password", { current: account.password, next }));
  assert.equal(changed.status, 200, changed.text);

  // The same, with every character escaped (😀): valid JSON, but no browser sends it so.
  const escaped = JSON.stringify({ current: next, next: randomFrom(emoji, 200) }).replace(/[\u{10000}-\u{10ffff}]/gu, (c) =>
    [...c.split("")].map((unit) => `\\u${unit.charCodeAt(0).toString(16).padStart(4, "0")}`).join(""),
  );
  const answer = await unlessBusy(() => account.visitor.post("/auth/password", undefined, { raw: escaped }));
  t.diagnostic(`escaped: ${Buffer.byteLength(escaped)} bytes, answered ${answer.status} ${answer.text}`);
  assert.ok(answer.status < 500);
});

test("a password with a lone surrogate is refused, and changes nothing (42)", async () => {
  const email = freshEmail();
  const token = await askForLink(h, "password", email);
  const lone = `{"token":"${token}","password":"abcdefghijklmnop\\ud800qrstu"}`;
  const answer = await tryAt(token, "", lone);
  assert.ok(isRefusal(answer.status), `answered ${answer.status}`);
  assert.equal(answer.json?.error?.code, "invalid-password");
  assert.deepEqual(answer.setCookies, []);
  const password = freshPassword();
  assert.equal((await tryAt(token, password)).status, 200, "the link is still usable");

  const visitor = h.visitor();
  await unlessBusy(() => visitor.post("/auth/sign-in", { email, password }));
  const change = await unlessBusy(() =>
    visitor.post("/auth/password", undefined, { raw: `{"current":${JSON.stringify(password)},"next":"abcdefghijklmnop\\udc00qrstu"}` }),
  );
  assert.equal(change.json?.error?.code, "invalid-password");
  assert.equal(await whoIs(visitor), email);
  assert.equal((await unlessBusy(() => h.visitor().post("/auth/sign-in", { email, password }))).status, 200, "the old password still works");
});

test("common passwords with characters added, the email, and repeats are refused (43)", async (t) => {
  const email = `annabelle.smithson${randomBytes(2).toString("hex")}@example.net`;
  let token = await askForLink(h, "password", email);
  const accepted: string[] = [];
  /** Whether a password is refused as too easy; one accepted is noted, and a new link asked for. */
  const refusedAsCommon = async (password: string) => {
    const answer = await tryAt(token, password);
    if (answer.status === 200) {
      accepted.push(password);
      token = await askForLink(h, "password", freshEmail());
    }
    return answer.json?.error?.code === "common-password";
  };
  // Those made from the email first, while the link is still the one for that email.
  const local = email.slice(0, email.indexOf("@"));
  for (const password of [email, `${local}${local}`, local.toUpperCase(), "abcabcabcabcabc", "aaaaaaaaaaaaaaaaaaaa", "abababababababababab"]) {
    await refusedAsCommon(password);
  }
  const candidates = ["passwordpassword", "123456789012345", "1234567890123456", "qwertyuiopasdfgh", "iloveyouiloveyou", "1q2w3e4r5t6y7u8i9o0p"];
  const common: string[] = [];
  for (const candidate of candidates) if (await refusedAsCommon(candidate)) common.push(candidate);
  t.diagnostic(`refused as common: ${common.join(", ")}`);
  assert.ok(common.length > 0, "some well-known long password is on the list");
  for (const base of common) {
    for (const variant of [
      `${base}!!`,
      `${base}2024`,
      `${base[0]?.toUpperCase()}${base.slice(1)}`,
      base.toUpperCase(),
      `${base}   `,
      `${base}?!.`,
      `${base}!2024`,
    ]) {
      await refusedAsCommon(variant);
    }
  }
  assert.deepEqual(accepted, [], "every one of these is refused");
});

test("a password with NUL, a newline, and right-to-left marks is accepted, and signs in as typed (44)", async (t) => {
  const email = freshEmail();
  const token = await askForLink(h, "password", email);
  const typed = `Ab\u0000cd\nef\u200fgh\u202eｗｉｄｅ${randomBytes(4).toString("hex")}`;
  const normal = typed.normalize("NFKC");
  assert.notEqual(typed, normal);
  const made = await tryAt(token, typed);
  assert.equal(made.status, 200, made.text);
  const asTyped = await unlessBusy(() => h.visitor().post("/auth/sign-in", { email, password: typed }));
  const asNormal = await unlessBusy(() => h.visitor().post("/auth/sign-in", { email, password: normal }));
  t.diagnostic(`signing in as typed: ${asTyped.status}; in its NFKC form: ${asNormal.status}`);
  assert.equal(asTyped.status, 200);
});

test("the breached-password check gets only 5 hex characters, refuses what it finds, and lets a password through when it hangs (45)", async (t) => {
  breached = freshPassword();
  const start = prefixes.length;
  const token = await askForLink(h, "password", freshEmail());
  const refused = await tryAt(token, breached);
  assert.equal(refused.json?.error?.code, "breached-password");
  const plain = freshPassword();
  assert.equal((await tryAt(token, plain)).status, 200);
  for (const prefix of prefixes.slice(start)) assert.match(prefix, /^[0-9A-F]{5}$/);
  assert.deepEqual(prefixes.slice(start), [sha1(breached).slice(0, 5), sha1(plain).slice(0, 5)], "once for each password");

  const twoForms = `ｗｉｄｅ-${freshPassword()}`;
  const before = prefixes.length;
  assert.equal((await tryAt(await askForLink(h, "password", freshEmail()), twoForms)).status, 200);
  assert.deepEqual(
    new Set(prefixes.slice(before)),
    new Set([sha1(twoForms.normalize("NFKC")).slice(0, 5), sha1(twoForms).slice(0, 5)]),
    "its normal form and as typed",
  );

  breachMode = "hang";
  const hung = freshPassword();
  const logged = h.logs.length;
  const answer = await tryAt(await askForLink(h, "password", freshEmail()), hung);
  breachMode = "answer";
  t.diagnostic(`with the check hanging: ${answer.status} after ${answer.ms.toFixed(0)} ms`);
  assert.equal(answer.status, 200);
  assert.ok(answer.ms > 4500 && answer.ms < 8000, `${answer.ms} ms`);
  await wait(50);
  const log = h.logs.slice(logged).join("\n");
  assert.ok(log.length > 0, "the failed check is logged");
  assert.ok(!log.includes(hung), "without the password");
});
