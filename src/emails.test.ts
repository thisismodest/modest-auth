import assert from "node:assert/strict";
import { test } from "node:test";
import { cleanEmail } from "./emails.ts";

test("an address is kept trimmed, normalised, and lowercase", () => {
  assert.equal(cleanEmail("  Ann.Smith+news@Example.ORG "), "ann.smith+news@example.org");
  assert.equal(cleanEmail("ａｎｎ@example.org"), "ann@example.org", "lookalike full-width letters are the same address");
  assert.equal(cleanEmail("józef@example.org"), "józef@example.org");
  assert.equal(cleanEmail("ann@BÜCHER.de"), "ann@xn--bcher-kva.de", "a domain in its ASCII form");
  assert.equal(cleanEmail("ann@xn--bcher-kva.de"), cleanEmail("ann@bücher.de"), "one mailbox, one account, however its domain is written");
});

test("anything that isn't plainly an address is refused", () => {
  for (const bad of [
    "user@example.com/path",
    "user@example.com?q=1",
    "user@/example.com",
    "user@example.com#x",
    "user@ex%61mple.com",
    "user@0x7f.1",
    "user@2130706433",
    "user@127.1",
    "user@127.0.0.1",
    "",
    "ann",
    "@example.org",
    "ann@",
    "ann@example",
    "ann@@example.org",
    "a@b@example.org",
    "ann@.example.org",
    "ann@example..org",
    "ann@-example.org",
    ".ann@example.org",
    "an..n@example.org",
    "ann smith@example.org",
  ]) {
    assert.equal(cleanEmail(bad), null, bad);
  }
});

test("nothing that could display as another address, or as markup, gets through", () => {
  for (const bad of [
    "ann\ufe0f@example.org",
    "ann\u034f@example.org",
    "ann\u3164@example.org",
    "ann\u115f@example.org",
    "ann\u180b@example.org",
    "ann\u2800@example.org",
    "ann\u202e@example.org",
    "ann\u200b@example.org",
    "ann\u0000@example.org",
    "ann\n@example.org",
    '"ann"@example.org',
    "<ann>@example.org",
    "ann@exam<b>ple.org",
    "ann'@example.org",
    "ann@example.org\r\nBcc: x@y.z",
  ]) {
    assert.equal(cleanEmail(bad), null, JSON.stringify(bad));
  }
});

test("too long is refused, by RFC 5321's limits", () => {
  assert.equal(cleanEmail(`${"a".repeat(65)}@example.org`), null);
  assert.equal(cleanEmail(`a@${"b".repeat(250)}.org`), null);
  assert.ok(cleanEmail(`${"a".repeat(64)}@example.org`));
});

test("a crafted address can't make it slow", () => {
  const started = performance.now();
  for (const input of [`a@${".".repeat(1_000_000)}x`, `${"a".repeat(1_000_000)}@`, `a@${"a.".repeat(500_000)}`, "@".repeat(1_000_000)])
    assert.equal(cleanEmail(input), null);
  assert.ok(performance.now() - started < 200, `took ${Math.round(performance.now() - started)}ms`);
});

test("fuzzed: it never throws, and anything it keeps it keeps unchanged when given again", () => {
  const alphabet = "aZ09@.-_+ \t\n\"<>()[]\\,;:`'é\u202e\u200bａ\u0000";
  let seed = 7;
  const random = () => {
    seed = (seed * 1103515245 + 12345) % 2 ** 31;
    return seed / 2 ** 31;
  };
  for (let i = 0; i < 20_000; i++) {
    const input = Array.from({ length: Math.floor(random() * 40) }, () => alphabet[Math.floor(random() * alphabet.length)]).join("");
    const kept = cleanEmail(input);
    if (kept !== null) assert.equal(cleanEmail(kept), kept, JSON.stringify(input));
  }
});

test("an address a mail program would read as an option or a pipe is refused", () => {
  for (const email of ["-X/var/www/s.php@example.org", "-oQ/tmp@example.org", "|cmd@example.org"]) assert.equal(cleanEmail(email), null, email);
  assert.equal(cleanEmail("ann-smith@example.org"), "ann-smith@example.org", "a hyphen elsewhere is fine");
});
