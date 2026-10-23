import assert from "node:assert/strict";
import { createServer } from "node:http";
import { DatabaseSync } from "node:sqlite";
import { test } from "node:test";
import { createAuth } from "./auth.ts";
import { createHandler } from "./handler.ts";
import { handleNode, toRequest } from "./node.ts";

const ORIGIN = "https://app.example.org";
const PASSWORD = "a long enough password";

const setup = () => {
  const auth = createAuth(new DatabaseSync(":memory:"));
  const handler = createHandler(auth, { origin: ORIGIN });
  let cookie = "";
  /** A request from the site's own page, as a browser sends it (carrying the cookie it was given). */
  const send = async (path: string, body?: unknown, headers: Record<string, string> = {}) => {
    const request = new Request(`${ORIGIN}${path}`, {
      method: body === undefined ? "GET" : "POST",
      headers: { origin: ORIGIN, "sec-fetch-site": "same-origin", "content-type": "application/json", ...(cookie ? { cookie } : {}), ...headers },
      ...(body === undefined ? {} : { body: typeof body === "string" ? body : JSON.stringify(body) }),
    });
    const response = await handler.handle(request, "203.0.113.9");
    assert.ok(response, `${path} is one of the routes`);
    const set = response.headers.get("set-cookie");
    if (set) cookie = set.split(";")[0]!;
    return { status: response.status, json: (await response.json()) as Record<string, any>, set, headers: response.headers };
  };
  return { auth, handler, send, cookie: () => cookie, forget: () => (cookie = "") };
};

test("sign up, see who's signed in, sign out", async () => {
  const { send } = setup();
  assert.deepEqual((await send("/auth/session")).json, { user: null });
  const up = await send("/auth/sign-up", { email: "ann@example.org", password: PASSWORD });
  assert.equal(up.status, 201);
  assert.match(up.set!, /^__Host-session=[\w-]{43}; Path=\/; HttpOnly; SameSite=Lax; Max-Age=\d+; Secure$/);
  assert.equal(up.headers.get("cache-control"), "no-store");
  assert.deepEqual((await send("/auth/session")).json, { user: { email: "ann@example.org" } });
  assert.match((await send("/auth/sign-out", {})).set!, /Max-Age=0/);
  assert.deepEqual((await send("/auth/session")).json, { user: null });
});

test("another site can't sign anyone in or out, nor can a request that won't say where it's from", async () => {
  const { send } = setup();
  await send("/auth/sign-up", { email: "ann@example.org", password: PASSWORD });
  for (const headers of [{ origin: "https://evil.example" }, { origin: "" }, { origin: "https://app.example.org.evil.example" }, { "sec-fetch-site": "cross-site" }, { "sec-fetch-site": "same-site" }]) {
    const res = await send("/auth/sign-out", {}, headers);
    assert.equal(res.status, 403, JSON.stringify(headers));
  }
  assert.deepEqual((await send("/auth/session")).json, { user: { email: "ann@example.org" } }, "still signed in");
});

test("only small JSON objects are read", async () => {
  const { send } = setup();
  assert.equal((await send("/auth/sign-in", "email=ann@example.org", { "content-type": "application/x-www-form-urlencoded" })).status, 415, "a form, which any site can send, isn't accepted");
  assert.equal((await send("/auth/sign-in", "not json")).status, 400);
  assert.equal((await send("/auth/sign-in", "[1, 2]")).status, 400);
  assert.equal((await send("/auth/sign-in", { email: "a".repeat(5000) })).status, 413);
  assert.equal((await send("/auth/sign-in", { email: ["ann@example.org"], password: { x: 1 } })).json.error.code, "wrong-credentials", "anything but a string is ignored");
});

test("each sign-in starts a fresh session and ends the one the browser had", async () => {
  const { auth, send, cookie } = setup();
  await send("/auth/sign-up", { email: "ann@example.org", password: PASSWORD });
  const first = cookie().split("=")[1]!;
  await send("/auth/sign-in", { email: "ann@example.org", password: PASSWORD });
  const second = cookie().split("=")[1]!;
  assert.notEqual(first, second);
  assert.equal(auth.userOf(first), null, "the old session is over");
  assert.ok(auth.userOf(second));
});

test("changing the password signs out everywhere else, and keeps this browser signed in", async () => {
  const { auth, send } = setup();
  await send("/auth/sign-up", { email: "ann@example.org", password: PASSWORD });
  const elsewhere = auth.startSession(await auth.signIn("ann@example.org", PASSWORD, "192.0.2.50"));
  assert.equal((await send("/auth/password", { current: "wrong password!", next: "a brand new password" })).status, 401);
  assert.equal((await send("/auth/password", { current: PASSWORD, next: "a brand new password" })).status, 200);
  assert.equal(auth.userOf(elsewhere), null);
  assert.deepEqual((await send("/auth/session")).json, { user: { email: "ann@example.org" } });
});

test("signing out everywhere, and deleting the account, need a signed-in browser", async () => {
  const { send, forget } = setup();
  await send("/auth/sign-up", { email: "ann@example.org", password: PASSWORD });
  assert.equal((await send("/auth/delete-account", { password: "wrong password!" })).status, 401);
  assert.equal((await send("/auth/delete-account", { password: PASSWORD })).status, 200);
  assert.equal((await send("/auth/sign-in", { email: "ann@example.org", password: PASSWORD })).status, 401, "the account is gone");
  forget();
  assert.equal((await send("/auth/password", { current: PASSWORD, next: "a brand new password" })).status, 401);
});

test("wrong methods and unknown routes are refused; other paths are left to the app", async () => {
  const { handler, send } = setup();
  assert.equal((await send("/auth/sign-in")).status, 405);
  assert.equal((await send("/auth/nothing", {})).status, 404);
  assert.equal((await send("/auth/constructor", {})).status, 404);
  assert.equal(await handler.handle(new Request(`${ORIGIN}/authority`), undefined), null);
  assert.equal(await handler.handle(new Request(`${ORIGIN}/`), undefined), null);
});

test("it won't run on plain HTTP, except on this machine, nor with an origin that's more than an origin", () => {
  const auth = createAuth(new DatabaseSync(":memory:"));
  assert.throws(() => createHandler(auth, { origin: "http://example.org" }));
  assert.throws(() => createHandler(auth, { origin: "https://example.org/app" }));
  assert.throws(() => createHandler(auth, { origin: "https://example.org", proxies: -1 }));
  assert.doesNotThrow(() => createHandler(auth, { origin: "http://localhost:3000" }));
});

test("with Node's own http server: the same routes, and the app's own requests left alone", async () => {
  const auth = createAuth(new DatabaseSync(":memory:"));
  const handler = createHandler(auth, { origin: "http://localhost:3000" });
  const server = createServer(async (req, res) => {
    if (await handleNode(handler, req, res)) return;
    const user = handler.userOf(toRequest(req));
    res.end(user ? `hello ${user.email}` : "hello stranger");
  });
  await new Promise<void>((ready) => server.listen(0, "127.0.0.1", ready));
  const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  try {
    const up = await fetch(`${base}/auth/sign-up`, {
      method: "POST",
      headers: { origin: "http://localhost:3000", "content-type": "application/json" },
      body: JSON.stringify({ email: "ann@example.org", password: PASSWORD }),
    });
    assert.equal(up.status, 201);
    const cookie = up.headers.getSetCookie()[0]!.split(";")[0]!;
    assert.equal(await (await fetch(`${base}/page`, { headers: { cookie } })).text(), "hello ann@example.org");
    assert.equal(await (await fetch(`${base}/page`)).text(), "hello stranger");
    const big = await fetch(`${base}/auth/sign-in`, { method: "POST", headers: { origin: "http://localhost:3000", "content-type": "application/json" }, body: "x".repeat(100_000) });
    assert.equal(big.status, 413);
  } finally {
    server.close();
  }
});

test("a request with no Origin header at all is refused, and fromSite says so for the app's own routes", async () => {
  const { handler } = setup();
  const bare = new Request(`${ORIGIN}/auth/sign-out`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
  assert.equal((await handler.handle(bare, "203.0.113.9"))!.status, 403);
  assert.equal(handler.fromSite(bare), false);
  assert.equal(handler.fromSite(new Request(`${ORIGIN}/my/route`, { method: "POST", headers: { origin: ORIGIN } })), true);
  assert.equal(handler.fromSite(new Request(`${ORIGIN}/my/route`, { method: "POST", headers: { origin: ORIGIN, "sec-fetch-site": "same-site" } })), false);
});

test("routes that take nothing accept an empty JSON body", async () => {
  const { send } = setup();
  await send("/auth/sign-up", { email: "ann@example.org", password: PASSWORD });
  assert.equal((await send("/auth/sign-out", "")).status, 200);
});

test("signing up ends any session the browser had", async () => {
  const { auth, send, cookie } = setup();
  await send("/auth/sign-up", { email: "ann@example.org", password: PASSWORD });
  const ann = cookie().split("=")[1]!;
  await send("/auth/sign-up", { email: "bob@example.org", password: PASSWORD });
  assert.equal(auth.userOf(ann), null);
});

test("without knowing where a request came from, it's refused rather than sharing everyone's allowance", async () => {
  const auth = createAuth(new DatabaseSync(":memory:"));
  const handler = createHandler(auth, { origin: ORIGIN });
  const request = new Request(`${ORIGIN}/auth/sign-in`, { method: "POST", headers: { origin: ORIGIN, "content-type": "application/json" }, body: "{}" });
  assert.equal((await handler.handle(request, undefined))!.status, 400);
});

test("base must be a plain path", () => {
  const auth = createAuth(new DatabaseSync(":memory:"));
  for (const base of ["/", "auth", "/auth/", "/Auth", "/a/../b", ""]) assert.throws(() => createHandler(auth, { origin: ORIGIN, base }), Error, base);
  assert.doesNotThrow(() => createHandler(auth, { origin: ORIGIN, base: "/api/auth" }));
});

test("with Node's own http server, nothing a client sends can crash the app", async () => {
  const { connect } = await import("node:net");
  const auth = createAuth(new DatabaseSync(":memory:"));
  const handler = createHandler(auth, { origin: "http://localhost:3000" });
  // As the README's quick start: no try/catch of its own.
  const server = createServer(async (req, res) => {
    if (await handleNode(handler, req, res)) return;
    res.end("app");
  });
  await new Promise<void>((ready) => server.listen(0, "127.0.0.1", ready));
  const port = (server.address() as { port: number }).port;
  const raw = (text: string, hangUp = false) =>
    new Promise<string>((done) => {
      // A server that has fallen over never answers: give up after a moment, so the test fails rather than hangs.
      const timer = setTimeout(() => (socket.destroy(), done("no answer")), 2000);
      const socket = connect(port, "127.0.0.1", () => {
        socket.write(text);
        if (hangUp) setTimeout(() => (socket.destroy(), done("")), 50);
      });
      let got = "";
      socket.on("data", (d) => (got += d));
      socket.on("end", () => (clearTimeout(timer), done(got)));
      socket.on("error", () => (clearTimeout(timer), done(got)));
    });
  const crashed: unknown[] = [];
  const onRejection = (e: unknown) => crashed.push(e);
  process.on("unhandledRejection", onRejection);
  try {
    await raw("TRACE /auth/sign-out HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    await raw("GET http://a:99999/ HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    await raw("GET http://[ HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    await raw('POST /auth/sign-in HTTP/1.1\r\nHost: x\r\nOrigin: http://localhost:3000\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{"em', true);
    await new Promise((r) => setTimeout(r, 100));
    assert.deepEqual(crashed, []);
    assert.match(await raw("GET /page HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"), /\r\n\r\napp$/, "still answering");
  } finally {
    process.off("unhandledRejection", onRejection);
    server.close();
  }
});

test("with Node's own http server, the app's own requests are left exactly as they came, large bodies and all", async () => {
  const auth = createAuth(new DatabaseSync(":memory:"));
  const handler = createHandler(auth, { origin: "http://localhost:3000" });
  const server = createServer(async (req, res) => {
    if (await handleNode(handler, req, res)) return;
    handler.userOf(toRequest(req));
    let size = 0;
    for await (const chunk of req) size += chunk.length;
    res.end(String(size));
  });
  await new Promise<void>((ready) => server.listen(0, "127.0.0.1", ready));
  const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  try {
    for (const size of [10, 70_000, 1_000_000]) {
      const res = await fetch(`${base}/upload`, { method: "POST", body: "x".repeat(size), signal: AbortSignal.timeout(5000) });
      assert.equal(await res.text(), String(size));
    }
  } finally {
    server.close();
  }
});

test("odd forms of a path never reach the routes, so a rule in front of the app can't be stepped round", async () => {
  const { connect } = await import("node:net");
  const auth = createAuth(new DatabaseSync(":memory:"));
  const handler = createHandler(auth, { origin: "http://localhost:3000" });
  const server = createServer(async (req, res) => {
    if (await handleNode(handler, req, res)) return;
    res.end("app");
  });
  await new Promise<void>((ready) => server.listen(0, "127.0.0.1", ready));
  const port = (server.address() as { port: number }).port;
  const ask = (target: string) =>
    new Promise<string>((done) => {
      const socket = connect(port, "127.0.0.1", () => socket.write(`GET ${target} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n`));
      let got = "";
      socket.on("data", (d) => (got += d));
      socket.on("end", () => done(got));
    });
  try {
    assert.match(await ask("/auth/session"), /"user":null/);
    assert.match(await ask("/auth/session?next=%2Fhome"), /"user":null/, "an encoded slash in the query is the query's business");
    for (const target of ["/auth\\session", "/zzz/%2e%2e/auth/session", "/x/../auth/session", "/./auth/session", "/auth/./session", "//evil/auth/session", "http://evil.example/auth/session", "/auth%2fsession"]) {
      assert.match(await ask(target), /\r\n\r\napp$/, target);
    }
  } finally {
    server.close();
  }
});

test("signing out everywhere, from the route, ends every session of the account and only theirs", async () => {
  const { auth, send } = setup();
  await send("/auth/sign-up", { email: "ann@example.org", password: PASSWORD });
  const phone = auth.startSession(await auth.signIn("ann@example.org", PASSWORD, "192.0.2.60"));
  await auth.signUp("bob@example.org", PASSWORD, "192.0.2.61");
  const bobs = auth.startSession(await auth.signIn("bob@example.org", PASSWORD, "192.0.2.61"));
  assert.equal((await send("/auth/sign-out-everywhere", "")).status, 200);
  assert.equal(auth.userOf(phone), null);
  assert.ok(auth.userOf(bobs));
  assert.deepEqual((await send("/auth/session")).json, { user: null });
});

test("answers carry no CORS headers, so another site's page can't read them; pauses say when to try again", async () => {
  const { send } = setup();
  const answer = await send("/auth/session", undefined, { origin: "https://evil.example" });
  for (const name of ["access-control-allow-origin", "access-control-allow-credentials"]) assert.equal(answer.headers.get(name), null);
  for (let i = 0; i < 10; i++) await send("/auth/sign-in", { email: "ann@example.org", password: "a wrong password here" });
  const paused = await send("/auth/sign-in", { email: "ann@example.org", password: "a wrong password here" });
  assert.equal(paused.status, 429);
  const wait = Number(paused.headers.get("retry-after"));
  assert.ok(wait > 890 && wait <= 900, `until this pause (15 minutes) lifts: ${wait}s`);
});

test("a forwarded address with no proxies declared is warned about once, naming the setting", async () => {
  const { send } = setup();
  const warnings: string[] = [];
  const realWarn = console.warn;
  console.warn = (message: string) => void warnings.push(message);
  try {
    await send("/auth/sign-out", "", { "x-forwarded-for": "203.0.113.50" });
    await send("/auth/sign-out", "", { "x-forwarded-for": "203.0.113.51" });
  } finally {
    console.warn = realWarn;
  }
  assert.equal(warnings.length, 1);
  assert.match(warnings[0]!, /proxies/);
});
