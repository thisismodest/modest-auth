import assert from "node:assert/strict";
import { createServer } from "node:http";
import { DatabaseSync } from "node:sqlite";
import { test } from "node:test";
import { createAuth } from "./auth.ts";
import { createHandler } from "./handler.ts";
import { handleNode, toRequest } from "./node.ts";

const ORIGIN = "https://app.example.org";
const PASSWORD = "a long enough password";
/** What every handler needs besides its origin: where links go, and how to send an email (here, nowhere). */
const EMAIL = { linkPage: "/account/link", sendEmail: () => {} };
/** After the answer: emails go once it's sent. */
const afterwards = () => new Promise((done) => setImmediate(() => setImmediate(done)));

const setup = () => {
  const auth = createAuth(new DatabaseSync(":memory:"));
  const emails: { to: string; subject: string; text: string }[] = [];
  const handler = createHandler(auth, { origin: ORIGIN, linkPage: "/account/link", sendEmail: (to, subject, text) => void emails.push({ to, subject, text }) });
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
  /** The token in the last link emailed to `to`. */
  const linkTo = async (to: string, kind: "password" | "sign-in" | "email" | "undo") => {
    await afterwards();
    const text = emails.findLast((email) => email.to === to)?.text ?? "";
    const token = new RegExp(`^${ORIGIN}/account/link#${kind}=([\\w-]{43})$`, "m").exec(text)?.[1];
    assert.ok(token, `a ${kind} link was emailed to ${to}`);
    return token;
  };
  /** Signing up as a person does: asking for a password link, then choosing a password at it. */
  const signUp = async (email: string, password = PASSWORD) => {
    await send("/auth/send-password-link", { email });
    return send("/auth/set-password", { token: await linkTo(email, "password"), password });
  };
  return { auth, handler, send, emails, linkTo, signUp, cookie: () => cookie, forget: () => (cookie = "") };
};

test("sign up, see who's signed in, sign out", async () => {
  const { send, signUp } = setup();
  assert.deepEqual((await send("/auth/session")).json, { user: null });
  const up = await signUp("ann@example.org");
  assert.equal(up.status, 200);
  assert.match(up.set!, /^__Host-session=[\w-]{43}; Path=\/; HttpOnly; SameSite=Lax; Max-Age=\d+; Secure$/);
  assert.equal(up.headers.get("cache-control"), "no-store");
  assert.deepEqual((await send("/auth/session")).json, { user: { email: "ann@example.org" } });
  assert.match((await send("/auth/sign-out", {})).set!, /Max-Age=0/);
  assert.deepEqual((await send("/auth/session")).json, { user: null });
});

test("another site can't sign anyone in or out, nor can a request that won't say where it's from", async () => {
  const { send, signUp } = setup();
  await signUp("ann@example.org");
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
  const { auth, send, cookie, signUp } = setup();
  await signUp("ann@example.org");
  const first = cookie().split("=")[1]!;
  await send("/auth/sign-in", { email: "ann@example.org", password: PASSWORD });
  const second = cookie().split("=")[1]!;
  assert.notEqual(first, second);
  assert.equal(auth.userOf(first), null, "the old session is over");
  assert.ok(auth.userOf(second));
});

test("changing the password signs out everywhere else, and keeps this browser signed in", async () => {
  const { auth, send, signUp } = setup();
  await signUp("ann@example.org");
  const elsewhere = auth.startSession(await auth.signIn("ann@example.org", PASSWORD, "192.0.2.50"));
  assert.equal((await send("/auth/password", { current: "wrong password!", next: "a brand new password" })).status, 401);
  assert.equal((await send("/auth/password", { current: PASSWORD, next: "a brand new password" })).status, 200);
  assert.equal(auth.userOf(elsewhere), null);
  assert.deepEqual((await send("/auth/session")).json, { user: { email: "ann@example.org" } });
});

test("signing out everywhere, and deleting the account, need a signed-in browser", async () => {
  const { send, forget, signUp } = setup();
  await signUp("ann@example.org");
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
  assert.throws(() => createHandler(auth, { origin: "http://example.org", ...EMAIL }));
  assert.throws(() => createHandler(auth, { origin: "https://example.org/app", ...EMAIL }));
  assert.throws(() => createHandler(auth, { origin: "https://example.org", proxies: -1, ...EMAIL }));
  assert.doesNotThrow(() => createHandler(auth, { origin: "http://localhost:3000", ...EMAIL }));
});

test("with Node's own http server: the same routes, and the app's own requests left alone", async () => {
  const auth = createAuth(new DatabaseSync(":memory:"));
  let mail = "";
  const handler = createHandler(auth, { origin: "http://localhost:3000", linkPage: "/link", sendEmail: (_to, _subject, text) => void (mail = text) });
  const server = createServer(async (req, res) => {
    if (await handleNode(handler, req, res)) return;
    const user = handler.userOf(toRequest(req));
    res.end(user ? `hello ${user.email}` : "hello stranger");
  });
  await new Promise<void>((ready) => server.listen(0, "127.0.0.1", ready));
  const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  const post = (route: string, body: unknown) =>
    fetch(`${base}/auth/${route}`, { method: "POST", headers: { origin: "http://localhost:3000", "content-type": "application/json" }, body: JSON.stringify(body) });
  try {
    assert.equal((await post("send-password-link", { email: "ann@example.org" })).status, 202);
    await afterwards();
    const up = await post("set-password", { token: /#password=([\w-]{43})/.exec(mail)![1], password: PASSWORD });
    assert.equal(up.status, 200);
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
  const { send, signUp } = setup();
  await signUp("ann@example.org");
  assert.equal((await send("/auth/sign-out", "")).status, 200);
});

test("signing up ends any session the browser had", async () => {
  const { auth, cookie, signUp } = setup();
  await signUp("ann@example.org");
  const ann = cookie().split("=")[1]!;
  await signUp("bob@example.org");
  assert.equal(auth.userOf(ann), null);
});

test("without knowing where a request came from, it's refused rather than sharing everyone's allowance", async () => {
  const auth = createAuth(new DatabaseSync(":memory:"));
  const handler = createHandler(auth, { origin: ORIGIN, ...EMAIL });
  const request = new Request(`${ORIGIN}/auth/sign-in`, { method: "POST", headers: { origin: ORIGIN, "content-type": "application/json" }, body: "{}" });
  assert.equal((await handler.handle(request, undefined))!.status, 400);
});

test("base must be a plain path", () => {
  const auth = createAuth(new DatabaseSync(":memory:"));
  for (const base of ["/", "auth", "/auth/", "/Auth", "/a/../b", ""]) assert.throws(() => createHandler(auth, { origin: ORIGIN, base, ...EMAIL }), Error, base);
  assert.doesNotThrow(() => createHandler(auth, { origin: ORIGIN, base: "/api/auth", ...EMAIL }));
});

test("with Node's own http server, nothing a client sends can crash the app", async () => {
  const { connect } = await import("node:net");
  const auth = createAuth(new DatabaseSync(":memory:"));
  const handler = createHandler(auth, { origin: "http://localhost:3000", ...EMAIL });
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
  const handler = createHandler(auth, { origin: "http://localhost:3000", ...EMAIL });
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
  const handler = createHandler(auth, { origin: "http://localhost:3000", ...EMAIL });
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
  const { auth, send, signUp } = setup();
  await signUp("ann@example.org");
  const phone = auth.startSession(await auth.signIn("ann@example.org", PASSWORD, "192.0.2.60"));
  await auth.usePasswordLink(auth.requestLink("password", "bob@example.org", "192.0.2.61")!.token!, PASSWORD, "192.0.2.61");
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

test("asking for a link gets the same answer whether or not there's an account, and the email goes only after the answer", async () => {
  const { handler, emails, signUp } = setup();
  await signUp("ann@example.org");
  emails.length = 0;
  const answers = [];
  const ask = (route: string, email: string, address: string) =>
    handler.handle(new Request(`${ORIGIN}/auth/${route}`, { method: "POST", headers: { origin: ORIGIN, "content-type": "application/json" }, body: JSON.stringify({ email }) }), address);
  for (const [route, email] of [["send-sign-in-link", "ann@example.org"], ["send-sign-in-link", "nobody@example.org"], ["send-password-link", "ann@example.org"], ["send-password-link", "nobody@example.org"]] as const) {
    const sentBefore = emails.length;
    const answer = (await ask(route, email, "198.51.100.60"))!;
    assert.equal(emails.length, sentBefore, "nothing sent before the answer");
    answers.push([answer.status, await answer.text(), answer.headers.get("set-cookie")]);
    await afterwards();
  }
  assert.deepEqual(new Set(answers.map((a) => JSON.stringify(a))).size, 1, "every answer the same");
  assert.deepEqual(emails.map((e) => [e.to, e.subject]), [
    ["ann@example.org", "Sign in to app.example.org"],
    ["nobody@example.org", "Sign in to app.example.org"],
    ["ann@example.org", "Choose a new password for app.example.org"],
    ["nobody@example.org", "Finish signing up to app.example.org"],
  ], "an email every time, so the work after the answer is the same too");
  assert.doesNotMatch(emails[1]!.text, /#/, "with no link where there's no account");
  assert.match(emails[1]!.text, /no account/);
  for (const i of [1, 2]) await ask("send-sign-in-link", "ann@example.org", `198.51.100.${60 + i}`);
  const capped = (await ask("send-sign-in-link", "ann@example.org", "198.51.100.70"))!;
  assert.deepEqual([capped.status, await capped.text(), capped.headers.get("set-cookie")], answers[0], "past the limit for that inbox, still the same answer");
});

test("a link's token is after the #, which browsers never send to a server, on the page the app chose", async () => {
  const { send, emails } = setup();
  await send("/auth/send-password-link", { email: "ann@example.org" });
  await afterwards();
  assert.match(emails[0]!.text, /^https:\/\/app\.example\.org\/account\/link#password=[\w-]{43}$/m);
  assert.doesNotMatch(emails[0]!.text, /\?/, "nothing in a query string, which servers log and pages pass on");
});

test("a sign-in link signs this browser in with a fresh session, ending the one it had", async () => {
  const { auth, send, cookie, linkTo, signUp } = setup();
  await signUp("ann@example.org");
  const before = cookie().split("=")[1]!;
  await send("/auth/send-sign-in-link", { email: "ann@example.org" });
  const token = await linkTo("ann@example.org", "sign-in");
  const answer = await send("/auth/sign-in-with-link", { token });
  assert.equal(answer.status, 200);
  assert.deepEqual(answer.json, { user: { email: "ann@example.org" } });
  assert.equal(auth.userOf(before), null, "the session the browser had is over");
  const again = await send("/auth/sign-in-with-link", { token });
  assert.deepEqual([again.status, again.json.error.code], [400, "invalid-link"]);
});

test("choosing a password at a link signs this browser in, and every other session out", async () => {
  const { auth, send, linkTo, signUp } = setup();
  await signUp("ann@example.org");
  const elsewhere = auth.startSession(await auth.signIn("ann@example.org", PASSWORD, "192.0.2.70"));
  await send("/auth/send-password-link", { email: "ann@example.org" });
  const answer = await send("/auth/set-password", { token: await linkTo("ann@example.org", "password"), password: "a brand new long password" });
  assert.equal(answer.status, 200);
  assert.equal(auth.userOf(elsewhere), null);
  assert.deepEqual((await send("/auth/session")).json, { user: { email: "ann@example.org" } });
});

test("an email that can't be sent is logged without its text, and changes nothing for the person asking", async () => {
  const auth = createAuth(new DatabaseSync(":memory:"));
  const handler = createHandler(auth, { origin: ORIGIN, linkPage: "/account/link", sendEmail: () => Promise.reject(new Error("refused: https://app.example.org/account/link#password=secret")) });
  const logged: unknown[][] = [];
  const realError = console.error;
  console.error = (...parts: unknown[]) => void logged.push(parts);
  try {
    const request = new Request(`${ORIGIN}/auth/send-password-link`, { method: "POST", headers: { origin: ORIGIN, "content-type": "application/json" }, body: JSON.stringify({ email: "ann@example.org" }) });
    assert.equal((await handler.handle(request, "203.0.113.9"))!.status, 202);
    await afterwards();
    await afterwards();
  } finally {
    console.error = realError;
  }
  assert.equal(logged.length, 1);
  assert.doesNotMatch(JSON.stringify(logged), /secret|#password|ann@example/);
});

test("it needs a page for links and a way to send email", () => {
  const auth = createAuth(new DatabaseSync(":memory:"));
  for (const linkPage of ["", "account", "https://evil.example/x", "//evil.example", "/a b", "/a#b", "/a?b"]) {
    assert.throws(() => createHandler(auth, { origin: ORIGIN, linkPage, sendEmail: () => {} }), Error, linkPage);
  }
  assert.throws(() => createHandler(auth, { origin: ORIGIN, linkPage: "/link" } as never));
  assert.doesNotThrow(() => createHandler(auth, { origin: ORIGIN, linkPage: "/account/link", sendEmail: () => {} }));
});

test("the link page can ask which email a link is for, so nobody is signed in to someone else's account unawares", async () => {
  const { send, linkTo } = setup();
  await send("/auth/send-password-link", { email: "mallory@evil.example" });
  const token = await linkTo("mallory@evil.example", "password");
  const answer = await send("/auth/link", { token });
  assert.deepEqual([answer.status, answer.json], [200, { kind: "password", email: "mallory@evil.example" }]);
  assert.equal(answer.set, null, "it signs nobody in");
  assert.equal((await send("/auth/link", { token: "nonsense" })).json.error.code, "invalid-link");
});

test("a stuck email service can't pile up sends without end", async () => {
  let started = 0;
  const stuck = createHandler(createAuth(new DatabaseSync(":memory:")), { origin: ORIGIN, linkPage: "/l", sendEmail: () => ((started++, new Promise(() => {})) as Promise<void>) });
  const logged: unknown[][] = [];
  const realError = console.error;
  console.error = (...parts: unknown[]) => void logged.push(parts);
  try {
    for (let i = 0; i < 1015; i++) {
      const address = `10.${i >> 8}.${i & 255}.1`;
      await stuck.handle(new Request(`${ORIGIN}/auth/send-password-link`, { method: "POST", headers: { origin: ORIGIN, "content-type": "application/json" }, body: JSON.stringify({ email: `p${i}@example.org` }) }), address);
    }
    await afterwards();
    await afterwards();
  } finally {
    console.error = realError;
  }
  assert.equal(started, 10, "10 at once");
  assert.equal(logged.length, 5, "1,000 waiting, and the rest dropped, each logged");
  assert.match(String(logged[0]), /too many waiting/);
});

test("an email whose link runs out while it waits to be sent isn't sent", async () => {
  const sent: string[] = [];
  let release!: () => void;
  const blocked = new Promise<void>((done) => (release = done));
  let calls = 0;
  const handler = createHandler(createAuth(new DatabaseSync(":memory:")), {
    origin: ORIGIN,
    linkPage: "/l",
    sendEmail: async (to) => {
      if (calls++ < 10) await blocked;
      sent.push(to);
    },
  });
  const ask = (email: string, i: number) =>
    handler.handle(new Request(`${ORIGIN}/auth/send-password-link`, { method: "POST", headers: { origin: ORIGIN, "content-type": "application/json" }, body: JSON.stringify({ email }) }), `10.9.${i}.1`);
  for (let i = 0; i < 11; i++) await ask(`p${i}@example.org`, i);
  await afterwards();
  const realNow = Date.now;
  const logged: unknown[][] = [];
  const realError = console.error;
  Date.now = () => realNow() + 61 * 60_000;
  console.error = (...parts: unknown[]) => void logged.push(parts);
  try {
    release();
    await afterwards();
    await afterwards();
  } finally {
    Date.now = realNow;
    console.error = realError;
  }
  assert.equal(sent.length, 10, "the 10 already sending finish");
  assert.ok(!sent.includes("p10@example.org"), "the one that waited past its link's life isn't sent");
  assert.match(String(logged[0]), /ran out/);
});

test("changing the email: a link to the new address, the same answer either way, and a notice to the old one", async () => {
  const { send, emails, linkTo, signUp, forget } = setup();
  await signUp("ann@example.org");
  assert.equal((await send("/auth/change-email", { password: "a wrong password here", email: "ann@new.example" })).status, 401);
  const free = await send("/auth/change-email", { password: PASSWORD, email: "ann@new.example" });
  const token = await linkTo("ann@new.example", "email");
  const answer = await send("/auth/confirm-email", { token });
  assert.deepEqual([answer.status, answer.json], [200, { email: "ann@new.example" }]);
  assert.match(answer.set!, /Max-Age=0/, "signs nobody in: every session ended, this one too");
  assert.deepEqual((await send("/auth/session")).json, { user: null });
  await afterwards();
  const notice = emails.findLast((e) => e.to === "ann@example.org")!;
  assert.match(notice.subject, /email address was changed/);
  assert.match(notice.text, /ann@new\.example/);
  forget();
  await signUp("bob@example.org");
  const taken = await send("/auth/change-email", { password: PASSWORD, email: "ann@new.example" });
  assert.deepEqual([taken.status, taken.json], [free.status, free.json], "the same answer when the address has an account");
  await afterwards();
  assert.match(emails.findLast((e) => e.to === "ann@new.example")!.text, /has an account of its own already/);
  forget();
  assert.equal((await send("/auth/change-email", { password: PASSWORD, email: "x@example.org" })).status, 401, "signed out");
});

test("a changed password is told to the account's email, by either route, but signing up isn't", async () => {
  const { send, emails, linkTo, signUp } = setup();
  await signUp("ann@example.org");
  await afterwards();
  assert.ok(!emails.some((e) => /password was changed/.test(e.subject)), "a new account gets no notice");
  await send("/auth/password", { current: PASSWORD, next: "a brand new long password" });
  await afterwards();
  assert.equal(emails.filter((e) => e.to === "ann@example.org" && /password was changed/.test(e.subject)).length, 1);
  await send("/auth/send-password-link", { email: "ann@example.org" });
  await send("/auth/set-password", { token: await linkTo("ann@example.org", "password"), password: "a third long password here" });
  await afterwards();
  assert.equal(emails.filter((e) => e.to === "ann@example.org" && /password was changed/.test(e.subject)).length, 2);
});

test("confirming a move needs the account signed in; the notice to the old address can undo it, and a password link follows", async () => {
  const { send, emails, linkTo, signUp, forget } = setup();
  await signUp("ann@example.org");
  await send("/auth/change-email", { password: PASSWORD, email: "ann@new.example" });
  const token = await linkTo("ann@new.example", "email");
  forget();
  assert.equal((await send("/auth/confirm-email", { token })).status, 401, "signed out: nothing happens");
  await send("/auth/sign-in", { email: "ann@example.org", password: PASSWORD });
  assert.equal((await send("/auth/confirm-email", { token })).status, 200, "the link wasn't used up");
  const undo = await linkTo("ann@example.org", "undo");
  forget();
  const back = await send("/auth/undo-email", { token: undo });
  assert.deepEqual([back.status, back.json], [200, { email: "ann@example.org" }]);
  assert.equal(back.set, null, "it signs nobody in");
  await linkTo("ann@example.org", "password");
  assert.match(emails.at(-1)!.subject, /Choose a new password/);
});

test("the sessions route lists the account's sessions, and ending this one signs this browser out", async () => {
  const { auth, send, signUp, forget } = setup();
  await signUp("ann@example.org");
  const phone = auth.startSession(await auth.signIn("ann@example.org", PASSWORD, "192.0.2.170"));
  const listed = await send("/auth/sessions");
  assert.equal(listed.status, 200);
  assert.equal(listed.json.sessions.length, 2);
  const other = listed.json.sessions.find((s: { current: boolean }) => !s.current);
  const ended = await send("/auth/end-session", { id: other.id });
  assert.deepEqual([ended.status, ended.set], [200, null], "another session ended: this browser stays signed in");
  assert.equal(auth.userOf(phone), null);
  const mine = (await send("/auth/sessions")).json.sessions[0];
  assert.match((await send("/auth/end-session", { id: mine.id })).set!, /Max-Age=0/);
  assert.equal((await send("/auth/end-session", { id: mine.id })).status, 401, "signed out now");
  forget();
  assert.equal((await send("/auth/sessions")).status, 401);
  assert.equal((await send("/auth/sessions", undefined, { origin: "https://evil.example" })).headers.get("access-control-allow-origin"), null, "no other site can read it");
});

test("my data comes as a file to save, only to the account itself", async () => {
  const { send, signUp, forget } = setup();
  await signUp("ann@example.org");
  const copy = await send("/auth/my-data");
  assert.equal(copy.status, 200);
  assert.equal(copy.json.email, "ann@example.org");
  assert.match(copy.headers.get("content-disposition")!, /attachment; filename="my-data.json"/);
  assert.equal(copy.headers.get("cache-control"), "no-store");
  forget();
  assert.equal((await send("/auth/my-data")).status, 401);
});
