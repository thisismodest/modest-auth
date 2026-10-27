// Scenarios 13 to 22 of docs/scenarios.md: sign-in, sessions, and the cookie.

import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { after, before, test } from "node:test";
import { createAuth, createHandler } from "../../src/index.ts";
import {
  type Account,
  freshEmail,
  freshPassword,
  type Harness,
  isRefusal,
  LINK_PAGE,
  moveAccount,
  rawRequest,
  rawStatus,
  signIn,
  signUp,
  startHarness,
  unlessBusy,
  type Visitor,
  whoIs,
} from "./harness.ts";

let h: Harness;
before(async () => {
  h = await startHarness();
});
after(() => h.close());

const tokenOf = (visitor: Visitor) => visitor.cookies.get(h.cookieName ?? "") ?? "";
const withCookie = (cookie: string) => {
  const visitor = h.visitor();
  visitor.cookies.set(h.cookieName ?? "", cookie);
  return visitor;
};
const sessionAs = (cookieHeader: string) =>
  rawRequest(h, `GET /auth/session HTTP/1.1\r\nHost: example.org\r\nX-Forwarded-For: 203.0.113.9\r\nCookie: ${cookieHeader}\r\nConnection: close\r\n\r\n`);

test("signing in with a planted cookie gives a new token, and the planted one signs nobody in (13)", async () => {
  const account = await signUp(h);
  const planted = randomBytes(32).toString("base64url");
  const victim = withCookie(planted);
  await signIn(h, account, victim);
  assert.notEqual(tokenOf(victim), planted);
  assert.equal(await whoIs(withCookie(planted)), null);

  // A real session of the attacker's, planted in the victim's browser: signing in ends it.
  const attacker = await signIn(h, account);
  const attackerToken = tokenOf(attacker);
  const second = withCookie(attackerToken);
  await signIn(h, account, second);
  assert.notEqual(tokenOf(second), attackerToken);
  assert.equal(await whoIs(attacker), null);
  assert.equal(await whoIs(second), account.email);
});

test("a request carrying two session cookies is signed out (14)", async () => {
  const one = await signUp(h);
  const two = await signUp(h);
  const name = h.cookieName ?? "";
  for (const header of [
    `${name}=${tokenOf(one.visitor)}; ${name}=${tokenOf(two.visitor)}`,
    `${name}=${tokenOf(one.visitor)}; ${name}=${tokenOf(one.visitor)}`,
    `${name}=${tokenOf(one.visitor)}; other=1; ${name}=${randomBytes(32).toString("base64url")}`,
  ]) {
    const answer = await h.visitor().get("/auth/session", { headers: { cookie: header } });
    assert.deepEqual(answer.json, { user: null });
  }
});

test("a session's id signs nobody in, and another account can't end it, with an answer like a missing id's (15)", async () => {
  const a = await signUp(h);
  const b = await signUp(h);
  const listed = (await b.visitor.get("/auth/sessions")).json.sessions;
  assert.equal(listed.length, 1);
  const id = listed[0].id;
  assert.equal(await whoIs(withCookie(id)), null);
  const ended = await a.visitor.post("/auth/end-session", { id });
  const missing = await a.visitor.post("/auth/end-session", { id: randomBytes(16).toString("base64url").slice(0, id.length) });
  assert.equal(ended.status, missing.status);
  assert.equal(ended.text, missing.text);
  assert.equal(await whoIs(b.visitor), b.email);
  assert.equal(await whoIs(a.visitor), a.email);
});

test("no sign-in that checked the old password survives a password change it raced (16)", async (t) => {
  for (let round = 0; round < 2; round++) {
    const account = await signUp(h);
    const next = freshPassword();
    const signIns: Promise<Visitor & { status?: number }>[] = [];
    const race = async () => {
      const visitor = h.visitor();
      const answer = await visitor.post("/auth/sign-in", { email: account.email, password: account.password });
      return Object.assign(visitor, { status: answer.status });
    };
    for (let i = 0; i < 5; i++) signIns.push(race());
    const change = account.visitor.post("/auth/password", { current: account.password, next });
    for (let i = 0; i < 5; i++) signIns.push(race());
    const [changed, visitors] = await Promise.all([change, Promise.all(signIns)]);
    t.diagnostic(`password change ${changed.status}; sign-ins: ${visitors.map((v) => v.status).join(" ")}`);
    if (changed.status === 503) continue;
    assert.equal(changed.status, 200);
    for (const visitor of visitors.filter((v) => v.status === 200)) assert.equal(await whoIs(visitor), null);
    assert.equal(await whoIs(account.visitor), account.email);
  }
});

test("an account keeps at most 50 sessions, ending the oldest (17)", async () => {
  const account = await signUp(h);
  const visitors: Visitor[] = [account.visitor];
  for (let i = 0; i < 50; i += 2) {
    const [one, two] = await Promise.all([signIn(h, account), signIn(h, account)]);
    visitors.push(one, two);
  }
  assert.equal(visitors.length, 51);
  assert.equal(await whoIs(account.visitor), null, "the first session ended");
  const listed = (await (visitors[50] as Visitor).get("/auth/sessions")).json.sessions;
  assert.equal(listed.length, 50);
  let signedIn = 0;
  for (const visitor of visitors.slice(1)) if ((await whoIs(visitor)) === account.email) signedIn += 1;
  assert.equal(signedIn, 50);
});

async function twoSessions(): Promise<{ account: Account; other: Visitor }> {
  const account = await signUp(h);
  return { account, other: await signIn(h, account) };
}

test("signing out everywhere ends every session (18)", async () => {
  const { account, other } = await twoSessions();
  assert.equal((await account.visitor.post("/auth/sign-out-everywhere")).status, 200);
  assert.equal(await whoIs(other), null);
  assert.equal(await whoIs(account.visitor), null);
});

test("changing the password ends every other session and keeps this one (18)", async () => {
  const { account, other } = await twoSessions();
  const changed = await unlessBusy(() => account.visitor.post("/auth/password", { current: account.password, next: freshPassword() }));
  assert.equal(changed.status, 200);
  assert.equal(await whoIs(other), null);
  assert.equal(await whoIs(account.visitor), account.email);
});

test("confirming a move ends every session, and undoing it does too (18)", async () => {
  const { account, other } = await twoSessions();
  const first = account.email;
  const kept = tokenOf(account.visitor);
  const { undo } = await moveAccount(h, account, freshEmail("moved"));
  assert.equal(await whoIs(other), null);
  assert.equal(await whoIs(withCookie(kept)), null);
  const after = await signIn(h, account);
  const undone = await h.visitor().post("/auth/undo-email", { token: undo });
  assert.equal(undone.status, 200);
  assert.equal(await whoIs(after), null);
  await h.takeEmail((m) => m.to === first && m.link?.kind === "password");
});

test("deleting the account ends every session (18)", async () => {
  const { account, other } = await twoSessions();
  assert.equal((await unlessBusy(() => account.visitor.post("/auth/delete-account", { password: account.password }))).status, 200);
  assert.equal(await whoIs(other), null);
  assert.equal(await whoIs(account.visitor), null);
});

test("a session unused for 7 days has ended, and one used daily ends at 30 (19)", (t) => {
  t.skip("needs the clock moved on, and README documents no way to control time");
});

function cookieParts(line: string) {
  const [pair = "", ...attributes] = line.split(";").map((part) => part.trim());
  return { name: pair.slice(0, pair.indexOf("=")), attributes: attributes.map((a) => a.toLowerCase()) };
}

test("over HTTPS the cookie is __Host-, Secure, HttpOnly, SameSite=Lax, Path=/, with no Domain (20)", async () => {
  const account = await signUp(h);
  const answer = await unlessBusy(() => h.visitor().post("/auth/sign-in", { email: account.email, password: account.password }));
  assert.equal(answer.setCookies.length, 1);
  const { name, attributes } = cookieParts(answer.setCookies[0] ?? "");
  assert.ok(name.startsWith("__Host-"), name);
  for (const wanted of ["secure", "httponly", "samesite=lax", "path=/"]) assert.ok(attributes.includes(wanted), `${wanted} in ${attributes}`);
  assert.ok(!attributes.some((a) => a.startsWith("domain")), "no Domain");
});

test("on localhost the cookie has no Secure and no prefix, and a plain-HTTP origin elsewhere is refused (20)", async () => {
  const local = await startHarness({ origin: "http://localhost:3000" });
  try {
    const account = await signUp(local);
    const answer = await unlessBusy(() => local.visitor().post("/auth/sign-in", { email: account.email, password: account.password }));
    const { name, attributes } = cookieParts(answer.setCookies[0] ?? "");
    assert.ok(!name.startsWith("__Host-") && !name.startsWith("__Secure-"), name);
    assert.ok(!attributes.includes("secure"));
    assert.ok(attributes.includes("httponly") && attributes.includes("samesite=lax"));
  } finally {
    await local.close();
  }
  const auth = createAuth(new DatabaseSync(":memory:"));
  for (const origin of ["http://example.org", "http://192.0.2.1", "http://example.org:8080"]) {
    assert.throws(() => createHandler(auth, { origin, linkPage: LINK_PAGE, sendEmail: () => {} }), `${origin} refused`);
  }
});

test("over HTTPS a valid token under any name but the exact prefixed one isn't read (21)", async () => {
  const account = await signUp(h);
  const token = tokenOf(account.visitor);
  const name = h.cookieName ?? "";
  const plain = name.replace(/^__Host-/, "");
  const check = await sessionAs(`${name}=${token}`);
  assert.match(check, /"email"/, "the exact name is read");
  const zeroWidth = Buffer.from("\u200b", "utf8").toString("latin1");
  const nbsp = Buffer.from(" ", "utf8").toString("latin1");
  for (const header of [
    `${plain}=${token}`,
    `${zeroWidth}${name}=${token}`,
    `${name}${zeroWidth}=${token}`,
    `${nbsp}${name}=${token}`,
    `${name.toLowerCase()}=${token}`,
    `${name.toUpperCase()}=${token}`,
    `__Secure-${plain}=${token}`,
  ]) {
    const answer = await sessionAs(header);
    assert.equal(rawStatus(answer), 200, header);
    assert.match(answer, /\{"user":null\}/, `${JSON.stringify(header)} isn't read`);
  }
});

test("odd cookie values sign nobody in, crash nothing, and aren't reflected (22)", async () => {
  const account = await signUp(h);
  const token = tokenOf(account.visitor);
  const name = h.cookieName ?? "";
  const marker = "Zq9Marker";
  for (const header of [
    `${name}=${marker};${token}`,
    `${name}="${token}"`,
    `${name}="${marker}`,
    `${name}=${marker}${"A".repeat(10_240)}`,
    `${name}=${marker}\r ${token}`,
  ]) {
    const answer = await sessionAs(header);
    const status = rawStatus(answer);
    assert.ok(status === 200 || isRefusal(status), `answered ${status}`);
    if (status === 200) assert.match(answer, /\{"user":null\}/);
    assert.ok(!answer.includes(marker), "nothing reflected");
  }
  assert.equal(await whoIs(account.visitor), account.email, "the server still answers");
});
