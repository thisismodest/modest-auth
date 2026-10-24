import assert from "node:assert/strict";
import { test } from "node:test";
import { clearedCookie, readSessionCookie, sessionCookie } from "./cookies.ts";

const SITE = "https://example.org";
const DEV = "http://localhost:3000";

const TOKEN = "abcDEF123_-xyz";

test("over HTTPS the cookie is __Host-, Secure, HttpOnly, SameSite=Lax, for the whole site", () => {
  assert.equal(sessionCookie(TOKEN, SITE), `__Host-session=${TOKEN}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000; Secure`);
  assert.doesNotMatch(sessionCookie(TOKEN, SITE), /Domain=/i, "__Host- cookies may not name a domain");
});

test("over plain HTTP (development) it's the same, without Secure and the prefix", () => {
  assert.equal(sessionCookie(TOKEN, DEV), `modest-auth-dev-session=${TOKEN}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000`);
});

test("signing out clears it", () => {
  assert.equal(clearedCookie(SITE), "__Host-session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; Secure");
});

test("the token is read from among other cookies, and only a well-formed one", () => {
  assert.equal(readSessionCookie(`theme=dark; __Host-session=${TOKEN}; other=1`, SITE), TOKEN);
  assert.equal(
    readSessionCookie(`session=${TOKEN}; modest-auth-dev-session=${TOKEN}`, SITE),
    null,
    "over HTTPS, an unprefixed cookie (which any subdomain could set) isn't read",
  );
  assert.equal(readSessionCookie(`modest-auth-dev-session=${TOKEN}`, DEV), TOKEN);
  assert.equal(readSessionCookie(`__Host-session=${TOKEN}; __Host-session=other`, SITE), null, "two of them: neither is believed");
  assert.equal(readSessionCookie(`__Host-session="${TOKEN}"`, SITE), null, "quoted");
  assert.equal(readSessionCookie("__Host-session=a%20b", SITE), null);
  assert.equal(readSessionCookie(undefined, SITE), null);
});

test("nothing but a token can be written into the cookie", () => {
  assert.throws(() => sessionCookie("x; Domain=evil.example", SITE));
  assert.throws(() => sessionCookie("", SITE));
});

test("a cookie whose name only looks like ours, with an odd character round it, isn't read", () => {
  assert.equal(readSessionCookie(` __Host-session=${TOKEN}`, SITE), null);
  assert.equal(readSessionCookie(`__Host-session\ufeff=${TOKEN}`, SITE), null);
  assert.equal(readSessionCookie(` \t__Host-session=${TOKEN}`, SITE), TOKEN, "ordinary spaces are fine");
});

test("the cookie can't be made less safe by mistake: the site's origin decides, and plain HTTP is for this machine only", () => {
  assert.throws(() => sessionCookie(TOKEN, "http://example.org"));
  assert.throws(() => readSessionCookie(`session=${TOKEN}`, "http://example.org"));
  assert.throws(() => sessionCookie(TOKEN, "https://example.org/app"));
  assert.match(sessionCookie(TOKEN, "http://127.0.0.1:8080"), /^modest-auth-dev-session=/);
});
