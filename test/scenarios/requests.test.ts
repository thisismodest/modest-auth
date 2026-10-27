// Scenarios 58 to 64 of docs/scenarios.md: the Origin check and the shapes of requests.

import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { gzipSync } from "node:zlib";
import { askForLink, freshEmail, freshIp, freshPassword, type Harness, rawRequest, rawStatus, signUp, startHarness, wait, whoIs } from "./harness.ts";

let h: Harness;
before(async () => {
  h = await startHarness();
});
after(() => h.close());

const isRefusal = (status: number) => status >= 400 && status < 500;
const POSTS = [
  "send-password-link",
  "send-sign-in-link",
  "link",
  "set-password",
  "sign-in-with-link",
  "sign-in",
  "sign-out",
  "sign-out-everywhere",
  "end-session",
  "password",
  "change-email",
  "confirm-email",
  "undo-email",
  "delete-account",
];

/** A raw POST, with exactly the headers given. */
const post = (path: string, headers: string[], body: string | Buffer) => {
  const head = [`POST ${path} HTTP/1.1`, "Host: example.org", `X-Forwarded-For: ${freshIp()}`, ...headers, "Connection: close", "", ""].join("\r\n");
  return rawRequest(h, Buffer.concat([Buffer.from(head, "latin1"), typeof body === "string" ? Buffer.from(body) : body]));
};

test("every POST is refused without the site's own Origin, or when the browser says it's cross-site (58)", async (t) => {
  const account = await signUp(h);
  const token = await askForLink(h, "password", freshEmail());
  const body = { email: freshEmail(), password: account.password, token, current: account.password, next: freshPassword(), id: "x" };
  const emails = h.emails.length;
  const events = h.events.length;
  const bad: { origin?: string | null; site?: string }[] = [
    { origin: null },
    { origin: "null" },
    { origin: "https://example.org/" },
    { origin: "https://example.org:8443" },
    { origin: "http://example.org" },
    { origin: "https://EXAMPLE.org" },
    { origin: "https://sub.example.org" },
    { origin: "https://example.org.evil.example" },
    { origin: "https://evil.example" },
    { origin: "https://example.org", site: "cross-site" },
    { origin: "https://example.org", site: "same-site" },
  ];
  for (const route of POSTS) {
    for (const { origin, site } of bad) {
      const answer = await account.visitor.post(`/auth/${route}`, body, { origin: origin ?? null, headers: site ? { "sec-fetch-site": site } : {} });
      assert.ok(isRefusal(answer.status), `${route} with Origin ${origin} and Sec-Fetch-Site ${site} answered ${answer.status}`);
      assert.deepEqual(answer.setCookies, []);
    }
  }
  await wait(300);
  assert.equal(h.emails.length, emails, "no email sent");
  assert.deepEqual(h.events.slice(events), [], "nothing happened");
  assert.equal(await whoIs(account.visitor), account.email);
  const none = await h.visitor().post("/auth/send-sign-in-link", { email: freshEmail() }, { headers: { "sec-fetch-site": "none" } });
  t.diagnostic(`Sec-Fetch-Site: none with the right Origin: ${none.status}`);
  const fine = await h.visitor().post("/auth/send-sign-in-link", { email: freshEmail() }, { headers: { "sec-fetch-site": "same-origin" } });
  assert.equal(fine.status, 202, "the site's own pages get through");
});

test("only Content-Type application/json is taken (59)", async () => {
  const body = JSON.stringify({ email: freshEmail() });
  const taken: string[] = [];
  for (const types of [
    ["text/plain"],
    ["application/jsonx"],
    ["application/json, text/html"],
    ["text/plain", "application/json"],
    ["application/json", "text/plain"],
    ["multipart/form-data"],
    [],
  ]) {
    const answer = await post(
      "/auth/send-sign-in-link",
      ["Origin: https://example.org", `Content-Length: ${Buffer.byteLength(body)}`, ...types.map((type) => `Content-Type: ${type}`)],
      body,
    );
    if (!isRefusal(rawStatus(answer))) taken.push(`${JSON.stringify(types)} answered ${rawStatus(answer)}`);
  }
  const signOut = await post("/auth/sign-out", ["Origin: https://example.org", "Content-Length: 0"], "");
  if (!isRefusal(rawStatus(signOut))) taken.push(`no Content-Type and no body answered ${rawStatus(signOut)}`);
  const charset = await post(
    "/auth/send-sign-in-link",
    ["Origin: https://example.org", "Content-Type: application/json; charset=utf-8", `Content-Length: ${Buffer.byteLength(body)}`],
    body,
  );
  assert.equal(rawStatus(charset), 202);
  assert.deepEqual(taken, [], "every other Content-Type refused");
});

test("oversized, cut-short, stalled, and compressed bodies get a 4xx, with nothing hashed and nothing crashed (60)", async (t) => {
  const account = await signUp(h);
  const json = JSON.stringify({ email: account.email, password: freshPassword() });
  const events = h.events.length;
  const headers = ["Origin: https://example.org", "Content-Type: application/json"];

  const big = json + " ".repeat(4097 - Buffer.byteLength(json));
  const tooBig = await post("/auth/sign-in", [...headers, `Content-Length: ${Buffer.byteLength(big)}`], big);
  assert.ok(isRefusal(rawStatus(tooBig)), `4,097 bytes answered ${rawStatus(tooBig)}`);

  const chunked = `${json}${" ".repeat(5000)}`;
  const chunks = `${(2000).toString(16)}\r\n${chunked.slice(0, 2000)}\r\n${(chunked.length - 2000).toString(16)}\r\n${chunked.slice(2000)}\r\n0\r\n\r\n`;
  const overChunked = await post("/auth/sign-in", [...headers, "Transfer-Encoding: chunked"], chunks);
  assert.ok(isRefusal(rawStatus(overChunked)), `chunked over 4KB answered ${rawStatus(overChunked)}`);

  const short = await post("/auth/sign-in", [...headers, "Content-Length: 10"], json);
  assert.ok(isRefusal(rawStatus(short)), `a short Content-Length answered ${rawStatus(short)}`);

  const zipped = gzipSync(json);
  const gzip = await post("/auth/sign-in", [...headers, "Content-Encoding: gzip", `Content-Length: ${zipped.length}`], zipped);
  assert.ok(isRefusal(rawStatus(gzip)), `gzip answered ${rawStatus(gzip)}`);

  // A body that stops halfway: the server answers others meanwhile, and this one in time.
  const started = Date.now();
  const stalled = rawRequest(
    h,
    `POST /auth/sign-in HTTP/1.1\r\nHost: example.org\r\nX-Forwarded-For: ${freshIp()}\r\nOrigin: https://example.org\r\nContent-Type: application/json\r\nContent-Length: ${json.length}\r\n\r\n${json.slice(0, 10)}`,
    3_000,
  );
  await wait(100);
  assert.equal(await whoIs(account.visitor), account.email, "others are answered meanwhile");
  const stalledAnswer = await stalled;
  t.diagnostic(`stalled body: ${rawStatus(stalledAnswer) || "closed with no answer"} after ${Date.now() - started} ms`);
  // Node's requestTimeout is checked every 30 seconds, so the socket may outlast this test: only no success matters here.
  assert.ok(rawStatus(stalledAnswer) === 0 || isRefusal(rawStatus(stalledAnswer)));

  assert.deepEqual(
    h.events.slice(events).filter((e) => e.type === "sign-in-failed"),
    [],
    "no password checked",
  );
  assert.equal(await whoIs(account.visitor), account.email);
});

test("odd JSON shapes get a clean 4xx, and duplicate keys never act on one email and show another (61)", async (t) => {
  const emailed = (to: string) => h.emails.some((m) => m.to === to);
  const [a, b, p, c, arr] = [freshEmail("a"), freshEmail("b"), freshEmail("p"), freshEmail("c"), freshEmail("arr")];
  const send = (raw: string) => h.visitor().post("/auth/send-password-link", undefined, { raw });
  const duplicate = await send(`{"email":"${a}","email":"${b}"}`);
  t.diagnostic(`duplicate email keys: ${duplicate.status} ${duplicate.text}`);
  for (const raw of [
    `{"__proto__":{"email":"${p}"}}`,
    `{"constructor":{"email":"${c}"}}`,
    `[{"email":"${arr}"}]`,
    `{"email":12345}`,
    `{"email":["${arr}"]}`,
    "null",
    '"x"',
    "{",
  ]) {
    const answer = await send(raw);
    assert.ok(isRefusal(answer.status), `${raw} answered ${answer.status}`);
  }
  await wait(300);
  assert.ok(!emailed(p) && !emailed(c) && !emailed(arr), "nothing sent from a shape that isn't { email }");
  assert.ok(!(emailed(a) && emailed(b)), "never both");
  if (duplicate.status === 202) t.diagnostic(`the duplicate's email went to the ${emailed(b) ? "last" : emailed(a) ? "first" : "neither"}`);
  assert.ok(duplicate.status < 500);
  // With duplicate keys at /auth/link: what's shown is what's acted on.
  const token = await askForLink(h, "password", freshEmail());
  const other = await askForLink(h, "password", freshEmail());
  const shown = await h.visitor().post("/auth/link", undefined, { raw: `{"token":"${other}","token":"${token}"}` });
  if (shown.status === 200) {
    const visitor = h.visitor();
    await visitor.post("/auth/set-password", undefined, { raw: `{"token":"${other}","token":"${token}","password":"${freshPassword()}"}` });
    assert.equal(await whoIs(visitor), shown.json.email);
  }
});

test("any method on any route gets an answer, and none has CORS headers (62)", async () => {
  const tries = [
    "GET /auth/sign-in",
    "POST /auth/session",
    "HEAD /auth/session",
    "OPTIONS /auth/sign-in",
    "PROPFIND /auth/session",
    "DELETE /auth/sessions",
    "PUT /auth/sign-out",
    "FOO /auth/session",
    "G@T /auth/session",
  ];
  for (const line of tries) {
    const answer = await rawRequest(
      h,
      `${line} HTTP/1.1\r\nHost: example.org\r\nX-Forwarded-For: ${freshIp()}\r\nOrigin: https://evil.example\r\nAccess-Control-Request-Method: POST\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}`,
    );
    assert.ok(rawStatus(answer) >= 200, `${line}: no answer`);
    assert.ok(rawStatus(answer) < 500, `${line}: ${rawStatus(answer)}`);
    assert.ok(!/^access-control-/im.test(answer), `${line}: CORS headers`);
  }
});

test("odd paths reach the right route or none, never the route by a back way, and other paths reach the app untouched (63)", async (t) => {
  const account = await signUp(h);
  const cookie = account.visitor.cookieHeader() ?? "";
  const get = async (target: string) => {
    const answer = await rawRequest(
      h,
      `GET ${target} HTTP/1.1\r\nHost: example.org\r\nX-Forwarded-For: ${freshIp()}\r\nCookie: ${cookie}\r\nConnection: close\r\n\r\n`,
    );
    const body = answer.slice(answer.indexOf("\r\n\r\n") + 4);
    return body.includes(`"email":"${account.email}"`) ? "route" : body.startsWith("app ") ? `app: ${body.trim()}` : `refused ${rawStatus(answer)}`;
  };
  assert.equal(await get("/auth/session"), "route");
  assert.equal(await get("/auth/session?x=1"), "route");
  const odd = [
    "/auth/session/",
    "/AUTH/session",
    "/auth/Session",
    "/auth//session",
    "//auth/session",
    "/auth/%73ession",
    "/%61uth/session",
    "/auth/./session",
    "/auth/../auth/session",
    "/x/../auth/session",
    "/auth/%2e%2e/auth/session",
    "/auth\\session",
    "/auth/session%00",
    "/auth/session;x",
    "http://evil/auth/session",
    "http://example.org/auth/session",
  ];
  const seen: string[] = [];
  for (const target of odd) {
    const first = await get(target);
    assert.equal(await get(target), first, `${target} answered the same twice`);
    seen.push(`${target} ${first}`);
    assert.notEqual(first, "route", `${target} reached the route`);
    if (first.startsWith("app")) assert.equal(first, `app: app GET ${target}`, "untouched");
  }
  t.diagnostic(seen.join("; "));
  for (const target of ["/authx", "/authx/session", "/x/auth/session", "/", "/account/link"]) assert.equal(await get(target), `app: app GET ${target}`);
  const appPost = await post("/app/save", ["Content-Type: text/plain", "Content-Length: 5"], "hello");
  assert.match(appPost, /app POST \/app\/save hello/);
});

test("after a malformed URL, a cut-off body, or a dropped socket, the server answers the next request (64)", async () => {
  const account = await signUp(h);
  await rawRequest(h, "GET /auth/%zz HTTP/1.1\r\nHost: example.org\r\nConnection: close\r\n\r\n");
  await rawRequest(h, "GET /auth/session\x00 HTTP/1.1\r\nHost: example.org\r\n\r\n");
  await rawRequest(h, "GARBAGE\r\n\r\n");
  await rawRequest(
    h,
    'POST /auth/sign-in HTTP/1.1\r\nHost: example.org\r\nOrigin: https://example.org\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{"email"',
    50,
  );
  await rawRequest(h, "GET /auth/sess", 20);
  assert.equal(await whoIs(account.visitor), account.email);
});
