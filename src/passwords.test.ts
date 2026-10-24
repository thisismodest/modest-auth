import assert from "node:assert/strict";
import { test } from "node:test";
import { code, must, oldHash } from "../test/helpers.ts";
import { checkNewPassword, checkPassword, hashPassword } from "./passwords.ts";

test("a password is kept only as a salted scrypt hash, which records its cost", async () => {
  const stored = await hashPassword("correct horse battery");
  assert.match(stored, /^\$scrypt\$ln=17,r=8,p=1\$[\w-]{22}\$[\w-]{43}$/);
  assert.ok(!stored.includes("correct horse"));
  assert.notEqual(stored, await hashPassword("correct horse battery"), "salted: the same password hashes differently each time");
});

test("a password is checked against its hash, and nothing else matches", async () => {
  const stored = await hashPassword("correct horse battery");
  assert.deepEqual(await checkPassword("correct horse battery", stored), { ok: true, outdated: false });
  assert.equal((await checkPassword("correct horse batterY", stored)).ok, false);
  for (const bad of ["", "not-a-hash", "scrypt$x$y", `$bcrypt$ln=17,r=8,p=1$aaaaaaaaaaaaaaaaaaaaaa$${"a".repeat(43)}`])
    assert.equal((await checkPassword("correct horse battery", bad)).ok, false);
});

test("a hash at an older, cheaper cost still checks, and says it's outdated", async () => {
  const old = oldHash("correct horse battery", 14);
  assert.deepEqual(await checkPassword("correct horse battery", old), { ok: true, outdated: true });
  assert.deepEqual(
    await checkPassword("wrong password", old),
    { ok: false, outdated: false },
    "never outdated when wrong: nothing is rehashed for a wrong guess",
  );
});

test("a stored hash can't make the server do more work than the current cost", async () => {
  const salt = "a".repeat(22);
  const hash = "a".repeat(43);
  for (const cost of ["ln=22,r=8,p=1", "ln=17,r=64,p=1", "ln=17,r=8,p=99", "ln=17,r=8,p=2", "ln=16,r=8,p=4", "ln=4,r=8,p=1"]) {
    assert.deepEqual(await checkPassword("anything at all", `$scrypt$${cost}$${salt}$${hash}`), { ok: false, outdated: false });
  }
});

test("the same password typed in different Unicode forms matches", async () => {
  // "é" as one character, and as "e" plus a combining accent.
  const stored = await hashPassword("café au lait please");
  assert.equal((await checkPassword("café au lait please", stored)).ok, true);
});

test("a new password: 15 characters or more, counted as characters, any characters at all", () => {
  const ok = (p: string) => checkNewPassword(p, "ann@example.org");
  assert.doesNotThrow(() => ok("correct horse battery"));
  assert.doesNotThrow(() => ok("ünïcödé päsŝwörd ✓"), "any characters");
  assert.throws(() => ok("fourteen chars"), code("short-password"));
  assert.throws(() => ok("😀😀😀😀😀😀😀😀"), code("short-password"), "8 emoji are 8 characters, not 16");
  assert.throws(() => ok("x".repeat(201)), code("long-password"));
});

test("a new password that's too easy to guess is refused", () => {
  const ok = (p: string, email = "ann.smith@example.org") => checkNewPassword(p, email);
  for (const common of ["1q2w3e4r5t6y7u8i", "123456789987654321", "1Q2W3E4R5T6Y7U8I"]) assert.throws(() => ok(common), code("common-password"), common);
  assert.throws(() => ok("aaaaaaaaaaaaaaaaaaaa"), code("common-password"), "one character over and over");
  assert.throws(() => ok("abababababababababab"), code("common-password"), "two characters over and over");
  assert.throws(() => ok("my name is ann.smith ok"), code("common-password"), "made from the email");
  assert.throws(() => ok("ann.smith@example.org"), code("common-password"), "the email itself");
});

test("a new password with broken Unicode is refused, rather than stored as something else", () => {
  assert.throws(() => checkNewPassword("\ud800 a long enough password", "ann@example.org"), code("invalid-password"));
});

test("a wrong password takes the current cost's work even against an older, cheaper hash", async () => {
  const old = oldHash("correct horse battery", 12);
  const current = await hashPassword("correct horse battery");
  const time = async (stored: string) => {
    const started = performance.now();
    await checkPassword("wrong password", stored);
    return performance.now() - started;
  };
  // The middle of five each, so a busy machine doesn't decide it.
  const median = async (stored: string) => {
    const times = [];
    for (let i = 0; i < 5; i++) times.push(await time(stored));
    return must(times.sort((a, b) => a - b)[2]);
  };
  const [againstOld, againstCurrent] = [await median(old), await median(current)];
  assert.ok(againstOld >= againstCurrent * 0.6, `old ${Math.round(againstOld)}ms, current ${Math.round(againstCurrent)}ms`);
});

test("a common password isn't made acceptable by spaces, punctuation, capitals, or numbers on the end", () => {
  for (const variant of [" 1q2w3e4r5t6y7u8i", "1q2w3e4r5t6y7u8i!", "1Q2W3E4R5T6Y7U8I 2026", "1q2w-3e4r-5t6y-7u8i"]) {
    assert.throws(() => checkNewPassword(variant, "ann@example.org"), code("common-password"), variant);
  }
});

test("made from the email: caught in other forms, but short addresses don't block ordinary words", () => {
  for (const p of ["adalovelace12345", "Ada Lovelace 1815!", "my login is ada.lovelace"]) {
    assert.throws(() => checkNewPassword(p, "ada.lovelace@example.org"), code("common-password"), p);
  }
  assert.doesNotThrow(() => checkNewPassword("information superhighway", "info@example.org"));
  assert.doesNotThrow(() => checkNewPassword("glove compartment rain", "love@example.org"));
});

test("a password that would be too long to sign in with is refused at sign-up too", () => {
  // Hangul typed as separate letters: 450 units as typed, 150 characters once joined.
  const decomposed = "각".repeat(150);
  assert.throws(() => checkNewPassword(decomposed, "ann@example.org"), code("long-password"));
});

test("strong passwords without letters are fine: digits, symbols, or emoji", () => {
  for (const p of ["83920174659283746510", "#%&*+=?@^~|!$<>[]", "🌲🦊🌙🍄🪵🐝🌊🔥🍂🦉🌾🪨🌻🐌🌿"])
    assert.doesNotThrow(() => checkNewPassword(p, "ann@example.org"), p);
});
