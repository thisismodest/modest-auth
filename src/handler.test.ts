import assert from "node:assert/strict";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { connect } from "node:net";
import { test } from "node:test";
import {
  afterwards,
  captureErrors,
  captureWarnings,
  count,
  fresh,
  HERE,
  must,
  openSession,
  PASSWORD,
  sendsSettle,
  wait,
  watchCrashes,
  withClock,
} from "../test/helpers.ts";
import { createHandler, type Handler } from "./handler.ts";
import { handleNode, toRequest } from "./node.ts";
import { MINUTE } from "./time.ts";

const ORIGIN = "https://app.example.org";
const DEV = "http://localhost:3000";
/** What every handler needs besides its origin: where links go, and how to send an email (here, nowhere). */
const EMAIL = { linkPage: "/account/link", sendEmail: () => {} };

/** A JSON POST to one of the routes from the site's origin; `address` is the client's. */
const post = (handler: Handler, route: string, body: unknown, address: string | undefined) =>
  handler.handle(
    new Request(`${ORIGIN}/auth/${route}`, { method: "POST", headers: { origin: ORIGIN, "content-type": "application/json" }, body: JSON.stringify(body) }),
    address,
  );

/** Node's own http server on a free port, the handler in front of the app, closed once `run` is done. */
const withServer = async (
  handler: Handler,
  app: (req: IncomingMessage, res: ServerResponse) => unknown,
  run: (base: string, port: number) => Promise<void>,
) => {
  const server = createServer(async (req, res) => {
    if (await handleNode(handler, req, res)) return;
    await app(req, res);
  });
  await new Promise<void>((ready) => server.listen(0, "127.0.0.1", ready));
  const port = (server.address() as { port: number }).port;
  try {
    await run(`http://127.0.0.1:${port}`, port);
  } finally {
    server.close();
  }
};

/** An app that answers "app" to whatever the handler leaves to it. */
const plainApp = (_req: IncomingMessage, res: ServerResponse) => res.end("app");

/** What the routes answer, as the tests read it. */
type Json = {
  error: { code: string; message: string };
  user: { email: string } | null;
  email: string;
  kind: string;
  sessions: { id: string; current: boolean; started: number; lastUsed: number }[];
  [key: string]: unknown;
};

const setup = () => {
  const { auth } = fresh();
  const emails: { to: string; subject: string; text: string }[] = [];
  const handler = createHandler(auth, { ...EMAIL, origin: ORIGIN, sendEmail: (to, subject, text) => void emails.push({ to, subject, text }) });
  let cookie = "";
  /** A request from the site's own page, as a browser sends it (carrying the cookie it was given). */
  const send = async (path: string, body?: unknown, headers: Record<string, string> = {}) => {
    const request = new Request(`${ORIGIN}${path}`, {
      method: body === undefined ? "GET" : "POST",
      headers: { origin: ORIGIN, "sec-fetch-site": "same-origin", "content-type": "application/json", ...(cookie ? { cookie } : {}), ...headers },
      ...(body === undefined ? {} : { body: typeof body === "string" ? body : JSON.stringify(body) }),
    });
    const response = await handler.handle(request, HERE);
    assert.ok(response, `${path} is one of the routes`);
    const set = response.headers.get("set-cookie");
    if (set) cookie = must(set.split(";")[0]);
    return { status: response.status, json: (await response.json()) as Json, set, headers: response.headers };
  };
  /** The token in the last link emailed to `to`. */
  const linkTo = async (to: string, kind: "password" | "sign-in" | "email" | "undo") => {
    await afterwards();
    const text = emails.findLast((email) => email.to === to)?.text ?? "";
    const token = new RegExp(`^${ORIGIN}${EMAIL.linkPage}#${kind}=([\\w-]{43})$`, "m").exec(text)?.[1];
    assert.ok(token, `a ${kind} link was emailed to ${to}`);
    return token;
  };
  /** Signing up as a person does: asking for a password link, then choosing a password at it. */
  const signUp = async (email: string, password = PASSWORD) => {
    await send("/auth/send-password-link", { email });
    return send("/auth/set-password", { token: await linkTo(email, "password"), password });
  };
  return { auth, handler, send, emails, linkTo, signUp, token: () => must(cookie.split("=")[1]), forget: () => (cookie = "") };
};

test("sign up, see who's signed in, sign out", async () => {
  const { send, signUp } = setup();
  assert.deepEqual((await send("/auth/session")).json, { user: null });
  const up = await signUp("ann@example.org");
  assert.equal(up.status, 200);
  assert.match(must(up.set), /^__Host-session=[\w-]{43}; Path=\/; HttpOnly; SameSite=Lax; Max-Age=\d+; Secure$/);
  assert.equal(up.headers.get("cache-control"), "no-store");
  assert.deepEqual((await send("/auth/session")).json, { user: { email: "ann@example.org" } });
  assert.match(must((await send("/auth/sign-out", {})).set), /Max-Age=0/);
  assert.deepEqual((await send("/auth/session")).json, { user: null });
});

test("another site can't sign anyone in or out, nor can a request that won't say where it's from", async () => {
  const { send, signUp } = setup();
  await signUp("ann@example.org");
  for (const headers of [
    { origin: "https://evil.example" },
    { origin: "" },
    { origin: "https://app.example.org.evil.example" },
    { "sec-fetch-site": "cross-site" },
    { "sec-fetch-site": "same-site" },
  ]) {
    const res = await send("/auth/sign-out", {}, headers);
    assert.equal(res.status, 403, JSON.stringify(headers));
  }
  assert.deepEqual((await send("/auth/session")).json, { user: { email: "ann@example.org" } }, "still signed in");
});

test("only small JSON objects are read", async () => {
  const { send } = setup();
  assert.equal(
    (await send("/auth/sign-in", "email=ann@example.org", { "content-type": "application/x-www-form-urlencoded" })).status,
    415,
    "a form, which any site can send, isn't accepted",
  );
  assert.equal((await send("/auth/sign-in", "not json")).status, 400);
  assert.equal((await send("/auth/sign-in", "[1, 2]")).status, 400);
  assert.equal((await send("/auth/sign-in", { email: "a".repeat(5000) })).status, 413);
  assert.equal(
    (await send("/auth/sign-in", { email: ["ann@example.org"], password: { x: 1 } })).json.error.code,
    "wrong-credentials",
    "anything but a string is ignored",
  );
});

test("each sign-in starts a fresh session and ends the one the browser had", async () => {
  const { auth, send, token, signUp } = setup();
  await signUp("ann@example.org");
  const first = token();
  await send("/auth/sign-in", { email: "ann@example.org", password: PASSWORD });
  const second = token();
  assert.notEqual(first, second);
  assert.equal(auth.userOf(first), null, "the old session is over");
  assert.ok(auth.userOf(second));
});

test("changing the password signs out everywhere else, and keeps this browser signed in", async () => {
  const { auth, send, signUp } = setup();
  await signUp("ann@example.org");
  const elsewhere = await openSession(auth, "ann@example.org", "192.0.2.50");
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
  const { auth } = fresh();
  assert.throws(() => createHandler(auth, { origin: "http://example.org", ...EMAIL }));
  assert.throws(() => createHandler(auth, { origin: "https://example.org/app", ...EMAIL }));
  assert.throws(
    () => createHandler(auth, { origin: "https://example.org", proxies: 1, ...EMAIL } as never),
    /trustedProxies/,
    "the old setting says what replaced it",
  );
  assert.throws(() => createHandler(auth, { origin: "https://example.org", trustedProxies: ["not a range"], ...EMAIL }), /trustedProxies/);
  assert.doesNotThrow(() => createHandler(auth, { origin: DEV, ...EMAIL }));
});

test("with Node's own http server: the same routes, and the app's own requests left alone", async () => {
  let mail = "";
  const handler = createHandler(fresh().auth, {
    origin: DEV,
    linkPage: "/link",
    sendEmail: (_to, _subject, text) => {
      mail = text;
    },
  });
  const app = (req: IncomingMessage, res: ServerResponse) => {
    const user = handler.userOf(toRequest(req));
    res.end(user ? `hello ${user.email}` : "hello stranger");
  };
  await withServer(handler, app, async (base) => {
    const send = (route: string, body: string) =>
      fetch(`${base}/auth/${route}`, { method: "POST", headers: { origin: DEV, "content-type": "application/json" }, body });
    assert.equal((await send("send-password-link", JSON.stringify({ email: "ann@example.org" }))).status, 202);
    await afterwards();
    const up = await send("set-password", JSON.stringify({ token: must(/#password=([\w-]{43})/.exec(mail))[1], password: PASSWORD }));
    assert.equal(up.status, 200);
    const cookie = must(must(up.headers.getSetCookie()[0]).split(";")[0]);
    assert.equal(await (await fetch(`${base}/page`, { headers: { cookie } })).text(), "hello ann@example.org");
    assert.equal(await (await fetch(`${base}/page`)).text(), "hello stranger");
    const big = await send("sign-in", "x".repeat(100_000));
    assert.equal(big.status, 413);
  });
});

test("a request with no Origin header at all is refused, and fromSite says so for the app's own routes", async () => {
  const { handler } = setup();
  const bare = new Request(`${ORIGIN}/auth/sign-out`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
  assert.equal(must(await handler.handle(bare, HERE)).status, 403);
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
  const { auth, token, signUp } = setup();
  await signUp("ann@example.org");
  const ann = token();
  await signUp("bob@example.org");
  assert.equal(auth.userOf(ann), null);
});

test("without knowing where a request came from, it's refused rather than sharing everyone's allowance", async () => {
  const handler = createHandler(fresh().auth, { origin: ORIGIN, ...EMAIL });
  assert.equal(must(await post(handler, "sign-in", {}, undefined)).status, 400);
});

test("base must be a plain path", () => {
  const { auth } = fresh();
  for (const base of ["/", "auth", "/auth/", "/Auth", "/a/../b", ""]) assert.throws(() => createHandler(auth, { origin: ORIGIN, base, ...EMAIL }), Error, base);
  assert.doesNotThrow(() => createHandler(auth, { origin: ORIGIN, base: "/api/auth", ...EMAIL }));
});

test("with Node's own http server, nothing a client sends can crash the app", async () => {
  const handler = createHandler(fresh().auth, { origin: DEV, ...EMAIL });
  // As the README's quick start: no try/catch of its own.
  await withServer(handler, plainApp, async (_base, port) => {
    const raw = (text: string, hangUp = false) =>
      new Promise<string>((done) => {
        // A server that has fallen over never answers: give up after a moment, so the test fails rather than hangs.
        const timer = setTimeout(() => {
          socket.destroy();
          done("no answer");
        }, 2000);
        const socket = connect(port, "127.0.0.1", () => {
          socket.write(text);
          if (hangUp)
            setTimeout(() => {
              socket.destroy();
              done("");
            }, 50);
        });
        let got = "";
        socket.on("data", (d) => (got += d));
        socket.on("end", () => {
          clearTimeout(timer);
          done(got);
        });
        socket.on("error", () => {
          clearTimeout(timer);
          done(got);
        });
      });
    await watchCrashes(async (crashed) => {
      await raw("TRACE /auth/sign-out HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
      await raw("GET http://a:99999/ HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
      await raw("GET http://[ HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
      await raw(
        'POST /auth/sign-in HTTP/1.1\r\nHost: x\r\nOrigin: http://localhost:3000\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{"em',
        true,
      );
      await wait(100);
      assert.deepEqual(crashed, []);
      assert.match(await raw("GET /page HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"), /\r\n\r\napp$/, "still answering");
    });
  });
});

test("with Node's own http server, the app's own requests are left exactly as they came, large bodies and all", async () => {
  const handler = createHandler(fresh().auth, { origin: DEV, ...EMAIL });
  const app = async (req: IncomingMessage, res: ServerResponse) => {
    handler.userOf(toRequest(req));
    let size = 0;
    for await (const chunk of req) size += chunk.length;
    res.end(String(size));
  };
  await withServer(handler, app, async (base) => {
    for (const size of [10, 70_000, 1_000_000]) {
      const res = await fetch(`${base}/upload`, { method: "POST", body: "x".repeat(size), signal: AbortSignal.timeout(5000) });
      assert.equal(await res.text(), String(size));
    }
  });
});

test("odd forms of a path never reach the routes, so a rule in front of the app can't be stepped round", async () => {
  const handler = createHandler(fresh().auth, { origin: DEV, ...EMAIL });
  await withServer(handler, plainApp, async (_base, port) => {
    const ask = (target: string) =>
      new Promise<string>((done) => {
        const socket = connect(port, "127.0.0.1", () => socket.write(`GET ${target} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n`));
        let got = "";
        socket.on("data", (d) => (got += d));
        socket.on("end", () => done(got));
      });
    assert.match(await ask("/auth/session"), /"user":null/);
    assert.match(await ask("/auth/session?next=%2Fhome"), /"user":null/, "an encoded slash in the query is the query's business");
    for (const target of [
      "/auth\\session",
      "/zzz/%2e%2e/auth/session",
      "/x/../auth/session",
      "/./auth/session",
      "/auth/./session",
      "//evil/auth/session",
      "http://evil.example/auth/session",
      "/auth%2fsession",
    ]) {
      assert.match(await ask(target), /\r\n\r\napp$/, target);
    }
  });
});

test("signing out everywhere, from the route, ends every session of the account and only theirs", async () => {
  const { auth, send, signUp } = setup();
  await signUp("ann@example.org");
  const phone = await openSession(auth, "ann@example.org", "192.0.2.60");
  await auth.usePasswordLink(must(must(auth.requestLink("password", "bob@example.org", "192.0.2.61")).token), PASSWORD, "192.0.2.61");
  const bobs = await openSession(auth, "bob@example.org", "192.0.2.61");
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
  const seconds = Number(paused.headers.get("retry-after"));
  assert.ok(seconds > 890 && seconds <= 900, `until this pause (15 minutes) lifts: ${seconds}s`);
});

test("a proxy passing X-Forwarded-For but not trusted is said once, naming what to set", async () => {
  const { send } = setup();
  const sign = (address: string, forwardedFor: string, trustedProxies?: string[]) =>
    createHandler(fresh().auth, { ...EMAIL, origin: ORIGIN, ...(trustedProxies ? { trustedProxies } : {}) }).handle(
      new Request(`${ORIGIN}/auth/sign-out`, {
        method: "POST",
        headers: { origin: ORIGIN, "content-type": "application/json", "x-forwarded-for": forwardedFor },
      }),
      address,
    );
  const fromCdn = await captureWarnings(async () => {
    await send("/auth/sign-out", "", { "x-forwarded-for": "203.0.113.50" });
    await send("/auth/sign-out", "", { "x-forwarded-for": "203.0.113.51" });
  });
  assert.equal(fromCdn.length, 1, "once for that address");
  assert.match(String(fromCdn), /add its address ranges to trustedProxies/);
  assert.match(String(await captureWarnings(() => sign("127.0.0.1", "203.0.113.9"))), /trustedProxies: \["loopback"\]/);
  assert.match(String(await captureWarnings(() => sign("10.0.0.1", "203.0.113.9"))), /trustedProxies: \["private"\]/);
  assert.deepEqual(await captureWarnings(() => sign("10.0.0.1", "203.0.113.9", ["private"])), [], "named: nothing to say");
  // Behind a private load balancer, a CDN that isn't named is found where the trail stops.
  assert.match(String(await captureWarnings(() => sign("10.0.0.1", "203.0.113.9, 173.245.48.5", ["private"]))), /173\.245\.48\.5.*trustedProxies/);
});

test("a proxy in front that passes no address on is said once, with what to add, on a real (HTTPS) site", async () => {
  const sign = (origin: string) =>
    createHandler(fresh().auth, { ...EMAIL, origin }).handle(
      new Request(`${origin}/auth/sign-out`, { method: "POST", headers: { origin, "content-type": "application/json" } }),
      "127.0.0.1",
    );
  assert.match(String(await captureWarnings(() => sign(ORIGIN))), /no X-Forwarded-For.*proxy_set_header X-Forwarded-For/);
  assert.deepEqual(await captureWarnings(() => sign(DEV)), [], "in development, a request from this machine is just that");
});

test("a page whose origin isn't the one set is said once, naming both; another site's request isn't", async () => {
  const handler = createHandler(fresh().auth, { ...EMAIL, origin: ORIGIN });
  const from = (origin: string, site: string) =>
    handler.handle(
      new Request(`${ORIGIN}/auth/sign-out`, { method: "POST", headers: { origin, "sec-fetch-site": site, "content-type": "application/json" } }),
      HERE,
    );
  const said = await captureWarnings(async () => {
    assert.equal((await from("https://www.app.example.org", "same-origin"))?.status, 403);
  });
  assert.match(String(said), /www\.app\.example\.org.*origin is https:\/\/app\.example\.org/);
  assert.deepEqual(await captureWarnings(() => from("https://evil.example", "cross-site")), [], "another site's: refused, and nothing to say");
});

test("a handler given no address says how to give it", async () => {
  const handler = createHandler(fresh().auth, { ...EMAIL, origin: ORIGIN });
  const said = await captureWarnings(async () => {
    const request = new Request(`${ORIGIN}/auth/sign-out`, { method: "POST", headers: { origin: ORIGIN, "content-type": "application/json" } });
    assert.equal((await handler.handle(request, undefined))?.status, 400);
  });
  assert.match(String(said), /given no address.*Bun.*Deno.*Hono/);
});

test("a sendEmail that ignores its signal is let go when it's up, and said why, so email doesn't stop", async () => {
  const realTimeout = AbortSignal.timeout;
  // The 30 seconds, up at once.
  AbortSignal.timeout = () => {
    const stop = new AbortController();
    setImmediate(() => stop.abort());
    return stop.signal;
  };
  let started = 0;
  try {
    const handler = createHandler(fresh().auth, {
      ...EMAIL,
      origin: ORIGIN,
      sendEmail: () => {
        started++;
        return new Promise<void>(() => {});
      },
    });
    const logged = await captureErrors(async () => {
      for (let i = 0; i < 12; i++) await post(handler, "send-password-link", { email: `p${i}@example.org` }, `10.6.0.${i}`);
      // A second's grace after each signal, for a send that passed it on to stop by itself: the last two
      // sends start once the first ten are let go, so two seconds and a bit for all of them.
      await wait(2300);
      for (let i = 0; i < 6; i++) await afterwards();
    });
    assert.equal(started, 12, "every send started: none held a place for good");
    assert.match(String(logged), /didn't finish in 30 seconds: pass its signal on/);
  } finally {
    AbortSignal.timeout = realTimeout;
  }
});

test("asking for a link gets the same answer whether or not there's an account, and the email goes only after the answer", async () => {
  const { handler, emails, signUp } = setup();
  await signUp("ann@example.org");
  emails.length = 0;
  const answers = [];
  const ask = (route: string, email: string, address: string) => post(handler, route, { email }, address);
  for (const [route, email] of [
    ["send-sign-in-link", "ann@example.org"],
    ["send-sign-in-link", "nobody@example.org"],
    ["send-password-link", "ann@example.org"],
    ["send-password-link", "nobody@example.org"],
  ] as const) {
    const sentBefore = emails.length;
    const answer = must(await ask(route, email, "198.51.100.60"));
    assert.equal(emails.length, sentBefore, "nothing sent before the answer");
    answers.push([answer.status, await answer.text(), answer.headers.get("set-cookie")]);
    await afterwards();
  }
  assert.deepEqual(new Set(answers.map((a) => JSON.stringify(a))).size, 1, "every answer the same");
  assert.deepEqual(
    emails.map((e) => [e.to, e.subject]),
    [
      ["ann@example.org", "Sign in to app.example.org"],
      ["nobody@example.org", "Sign in to app.example.org"],
      ["ann@example.org", "Choose a new password for app.example.org"],
      ["nobody@example.org", "Finish signing up to app.example.org"],
    ],
    "an email every time, so the work after the answer is the same too",
  );
  assert.doesNotMatch(must(emails[1]).text, /#/, "with no link where there's no account");
  assert.match(must(emails[1]).text, /no account/);
  for (const i of [1, 2]) await ask("send-sign-in-link", "ann@example.org", `198.51.100.${60 + i}`);
  const capped = must(await ask("send-sign-in-link", "ann@example.org", "198.51.100.70"));
  assert.deepEqual([capped.status, await capped.text(), capped.headers.get("set-cookie")], answers[0], "past the limit for that inbox, still the same answer");
});

test("a link's token is after the #, which browsers never send to a server, on the page the app chose", async () => {
  const { send, emails } = setup();
  await send("/auth/send-password-link", { email: "ann@example.org" });
  await afterwards();
  assert.match(must(emails[0]).text, /^https:\/\/app\.example\.org\/account\/link#password=[\w-]{43}$/m);
  assert.doesNotMatch(must(emails[0]).text, /\?/, "nothing in a query string, which servers log and pages pass on");
});

test("a sign-in link signs this browser in with a fresh session, ending the one it had", async () => {
  const { auth, send, token: session, linkTo, signUp } = setup();
  await signUp("ann@example.org");
  const before = session();
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
  const elsewhere = await openSession(auth, "ann@example.org", "192.0.2.70");
  await send("/auth/send-password-link", { email: "ann@example.org" });
  const answer = await send("/auth/set-password", { token: await linkTo("ann@example.org", "password"), password: "a brand new long password" });
  assert.equal(answer.status, 200);
  assert.equal(auth.userOf(elsewhere), null);
  assert.deepEqual((await send("/auth/session")).json, { user: { email: "ann@example.org" } });
});

test("an email that can't be sent is logged without its text, and changes nothing for the person asking", async () => {
  const handler = createHandler(fresh().auth, {
    origin: ORIGIN,
    linkPage: "/account/link",
    sendEmail: () => Promise.reject(new Error("refused: https://app.example.org/account/link#password=secret")),
  });
  const logged = await captureErrors(async () => {
    assert.equal(must(await post(handler, "send-password-link", { email: "ann@example.org" }, HERE)).status, 202);
    await sendsSettle();
  });
  assert.equal(logged.length, 1);
  assert.doesNotMatch(JSON.stringify(logged), /secret|#password|ann@example/);
});

test("it needs a page for links and a way to send email", () => {
  const { auth } = fresh();
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
  const stuck = createHandler(fresh().auth, {
    origin: ORIGIN,
    linkPage: "/l",
    sendEmail: () => {
      started++;
      return new Promise<void>(() => {});
    },
  });
  const logged = await captureErrors(async () => {
    for (let i = 0; i < 1015; i++) await post(stuck, "send-password-link", { email: `p${i}@example.org` }, `10.${i >> 8}.${i & 255}.1`);
    await sendsSettle();
  });
  assert.equal(started, 10, "10 at once");
  assert.equal(logged.length, 5, "1,000 waiting, and the rest dropped, each logged");
  assert.match(String(logged[0]), /too many waiting/);
});

test("an email whose link runs out while it waits to be sent isn't sent", async () => {
  const sent: string[] = [];
  let release = () => {};
  const blocked = new Promise<void>((done) => {
    release = done;
  });
  let calls = 0;
  const handler = createHandler(fresh().auth, {
    origin: ORIGIN,
    linkPage: "/l",
    sendEmail: async (to) => {
      if (calls++ < 10) await blocked;
      sent.push(to);
    },
  });
  for (let i = 0; i < 11; i++) await post(handler, "send-password-link", { email: `p${i}@example.org` }, `10.9.${i}.1`);
  await afterwards();
  let logged: unknown[][] = [];
  await withClock(async (ahead) => {
    ahead(61 * MINUTE);
    logged = await captureErrors(async () => {
      release();
      await sendsSettle();
    });
  });
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
  assert.match(must(answer.set), /Max-Age=0/, "signs nobody in: every session ended, this one too");
  assert.deepEqual((await send("/auth/session")).json, { user: null });
  await afterwards();
  const notice = must(emails.findLast((e) => e.to === "ann@example.org"));
  assert.match(notice.subject, /email address was changed/);
  assert.match(notice.text, /ann@new\.example/);
  forget();
  await signUp("bob@example.org");
  const taken = await send("/auth/change-email", { password: PASSWORD, email: "ann@new.example" });
  assert.deepEqual([taken.status, taken.json], [free.status, free.json], "the same answer when the address has an account");
  await afterwards();
  assert.match(must(emails.findLast((e) => e.to === "ann@new.example")).text, /has an account of its own already/);
  forget();
  assert.equal((await send("/auth/change-email", { password: PASSWORD, email: "x@example.org" })).status, 401, "signed out");
});

test("a changed password is told to the account's email, by either route, but signing up isn't", async () => {
  const { send, emails, linkTo, signUp } = setup();
  await signUp("ann@example.org");
  await afterwards();
  assert.ok(!emails.some((e) => /password was changed/.test(e.subject)), "a new account gets no notice");
  await send("/auth/password", { current: PASSWORD, next: "a brand new long password" });
  const notices = () => emails.filter((e) => e.to === "ann@example.org" && /password was changed/.test(e.subject)).length;
  await afterwards();
  assert.equal(notices(), 1);
  await send("/auth/send-password-link", { email: "ann@example.org" });
  await send("/auth/set-password", { token: await linkTo("ann@example.org", "password"), password: "a third long password here" });
  await afterwards();
  assert.equal(notices(), 2);
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
  assert.match(must(emails.at(-1)).subject, /Choose a new password/);
});

test("the sessions route lists the account's sessions, and ending this one signs this browser out", async () => {
  const { auth, send, signUp, forget } = setup();
  await signUp("ann@example.org");
  const phone = await openSession(auth, "ann@example.org", "192.0.2.170");
  const listed = await send("/auth/sessions");
  assert.equal(listed.status, 200);
  assert.equal(listed.json.sessions.length, 2);
  const other = must(
    listed.json.sessions.find((s) => !s.current),
    "another session",
  );
  const ended = await send("/auth/end-session", { id: other.id });
  assert.deepEqual([ended.status, ended.set], [200, null], "another session ended: this browser stays signed in");
  assert.equal(auth.userOf(phone), null);
  const mine = must((await send("/auth/sessions")).json.sessions[0], "this session");
  assert.match(must((await send("/auth/end-session", { id: mine.id })).set), /Max-Age=0/);
  assert.equal((await send("/auth/end-session", { id: mine.id })).status, 401, "signed out now");
  forget();
  assert.equal((await send("/auth/sessions")).status, 401);
  assert.equal(
    (await send("/auth/sessions", undefined, { origin: "https://evil.example" })).headers.get("access-control-allow-origin"),
    null,
    "no other site can read it",
  );
});

test("my data comes as a file to save, only to the account itself", async () => {
  const { send, signUp, forget } = setup();
  await signUp("ann@example.org");
  const copy = await send("/auth/my-data");
  assert.equal(copy.status, 200);
  assert.equal(copy.json.email, "ann@example.org");
  assert.match(must(copy.headers.get("content-disposition")), /attachment; filename="my-data.json"/);
  assert.equal(copy.headers.get("cache-control"), "no-store");
  forget();
  assert.equal((await send("/auth/my-data")).status, 401);
});

test("a body read before the handler (a body parser mounted in front) is said plainly, not taken as empty", async () => {
  const request = new Request(`${ORIGIN}/auth/sign-in`, { method: "POST", headers: { origin: ORIGIN, "content-type": "application/json" }, body: "{}" });
  await request.text();
  await assert.rejects(setup().handler.handle(request, HERE), /before any body parser/);
  const handler = createHandler(fresh().auth, { origin: DEV, ...EMAIL });
  // A body parser in front of the handler, as express.json() would be: the body read, and put on the request.
  const server = createServer(async (req, res) => {
    let text = "";
    for await (const chunk of req) text += chunk;
    Object.assign(req, { body: JSON.parse(text || "{}"), _body: true });
    if (!(await handleNode(handler, req, res))) res.end("app");
  });
  await new Promise<void>((ready) => server.listen(0, "127.0.0.1", ready));
  try {
    const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
    const errors = await captureErrors(async () => {
      const res = await fetch(`${base}/auth/sign-in`, {
        method: "POST",
        headers: { origin: DEV, "content-type": "application/json" },
        body: JSON.stringify({ email: "a@example.org", password: PASSWORD }),
      });
      assert.equal(res.status, 500);
    });
    assert.match(String(errors), /before any body parser/);
  } finally {
    server.close();
  }
});

test("sendEmail is given a signal that aborts after 30 seconds, so a stuck service can be let go", async () => {
  let signal: AbortSignal | undefined;
  const handler = createHandler(fresh().auth, {
    ...EMAIL,
    origin: ORIGIN,
    sendEmail: (_to, _subject, _text, options) => {
      signal = options.signal;
    },
  });
  await post(handler, "send-password-link", { email: "ann@example.org" }, HERE);
  await afterwards();
  assert.ok(signal instanceof AbortSignal && !signal.aborted);
});

test("a parser that only set req.body, without reading this request, isn't taken for one that read it", async () => {
  const handler = createHandler(fresh().auth, { origin: DEV, ...EMAIL });
  const server = createServer(async (req, res) => {
    // As express.urlencoded() does for a JSON request: req.body set, nothing read.
    Object.assign(req, { body: {} });
    if (!(await handleNode(handler, req, res))) res.end("app");
  });
  await new Promise<void>((ready) => server.listen(0, "127.0.0.1", ready));
  try {
    const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
    const res = await fetch(`${base}/auth/sign-in`, {
      method: "POST",
      headers: { origin: DEV, "content-type": "application/json" },
      body: JSON.stringify({ email: "a@example.org", password: PASSWORD }),
    });
    assert.equal(res.status, 401, "read and answered as usual");
  } finally {
    server.close();
  }
});

test("a send whose email service times out is said to have timed out, not to have ignored its signal", async () => {
  const realTimeout = AbortSignal.timeout;
  AbortSignal.timeout = () => {
    const stop = new AbortController();
    setImmediate(() => stop.abort(new DOMException("timed out", "TimeoutError")));
    return stop.signal;
  };
  try {
    const handler = createHandler(fresh().auth, {
      ...EMAIL,
      origin: ORIGIN,
      sendEmail: (_to, _subject, _text, { signal }) =>
        new Promise<void>((_, fail) => signal.addEventListener("abort", () => fail(signal.reason), { once: true })),
    });
    const logged = await captureErrors(async () => {
      await post(handler, "send-password-link", { email: "ann@example.org" }, HERE);
      for (let i = 0; i < 6; i++) await afterwards();
    });
    assert.match(String(logged), /didn't answer in 30 seconds/);
    assert.doesNotMatch(String(logged), /pass its signal on/);
  } finally {
    AbortSignal.timeout = realTimeout;
  }
});

test("setup messages can't be used up: this site's origin only, a few of each kind, public and internal proxies apart, IPv6 by /48", async () => {
  const handler = createHandler(fresh().auth, { ...EMAIL, origin: ORIGIN });
  const ask = (headers: Record<string, string>, address: string) =>
    handler.handle(new Request(`${ORIGIN}/auth/sign-out`, { method: "POST", headers: { "content-type": "application/json", ...headers } }), address);
  const said = await captureWarnings(async () => {
    // Other sites' origins, however many, and this site's at other ports: nothing new to say past the first.
    for (let i = 0; i < 20; i++) await ask({ origin: `https://site${i}.example`, "sec-fetch-site": "same-origin" }, HERE);
    for (let port = 1; port < 20; port++) await ask({ origin: `https://app.example.org:${port}`, "sec-fetch-site": "same-origin" }, HERE);
    // Other spellings of the same: capitals, a path, other schemes.
    for (const origin of [
      "https://APP.example.org",
      "https://aPP.example.org:9",
      "https://app.example.org/x",
      "ftp://app.example.org",
      "javascript://app.example.org",
    ]) {
      await ask({ origin, "sec-fetch-site": "same-origin" }, HERE);
    }
    await ask({ origin: "https://www.app.example.org", "sec-fetch-site": "same-origin" }, HERE);
    // Many addresses across one IPv6 /48 passing X-Forwarded-For: one message.
    for (let i = 1; i < 20; i++) await ask({ origin: ORIGIN, "x-forwarded-for": "203.0.113.9" }, `2001:db8:1:${i}::${i}`);
    // Public senders, past the few allowed: they don't stop an internal proxy being said.
    for (let i = 1; i < 20; i++) await ask({ origin: ORIGIN, "x-forwarded-for": "203.0.113.9" }, `198.51.100.${i}`);
    await ask({ origin: ORIGIN, "x-forwarded-for": "203.0.113.9" }, "127.0.0.1");
  });
  const lines = said.map((parts) => String(parts[0]));
  assert.equal(lines.filter((line) => /was refused, as origin is/.test(line)).length, 2, "app.example.org (any port), and www.");
  assert.ok(!lines.some((line) => /site\d+\.example/.test(line)), "other sites' origins never said");
  assert.equal(lines.filter((line) => /2001:db8:1:/.test(line)).length, 1);
  assert.ok(lines.filter((line) => /passed X-Forwarded-For on/.test(line)).length <= 5, "a few public ones at most");
  assert.ok(
    lines.some((line) => /proxy at 127\.0\.0\.1.*\["loopback"\]/.test(line)),
    "the internal proxy still said",
  );
});

test("an address that isn't one is said, like a missing one", async () => {
  const handler = createHandler(fresh().auth, { ...EMAIL, origin: ORIGIN });
  const request = new Request(`${ORIGIN}/auth/sign-out`, { method: "POST", headers: { origin: ORIGIN, "content-type": "application/json" } });
  const said = await captureWarnings(async () => {
    assert.equal((await handler.handle(request, "81.2.69.160, 10.0.0.1"))?.status, 400);
  });
  assert.match(String(said), /something that isn't one.*not a header/);
});

test("on a Unix socket, the Node adapter counts the connection as this machine's, so a proxy named as loopback is read past", async () => {
  const { mkdtempSync, rmSync } = await import("node:fs");
  const { join } = await import("node:path");
  const { tmpdir } = await import("node:os");
  const { request: send } = await import("node:http");
  const dir = mkdtempSync(join(tmpdir(), "modest-auth-"));
  const socketPath = join(dir, "app.sock");
  const { db, auth } = fresh();
  const handler = createHandler(auth, { ...EMAIL, origin: ORIGIN, trustedProxies: ["loopback"] });
  const server = createServer(async (req, res) => {
    if (!(await handleNode(handler, req, res))) res.end("app");
  });
  await new Promise<void>((ready) => server.listen(socketPath, ready));
  try {
    const status = await new Promise<number>((done) => {
      const body = JSON.stringify({ email: "a@example.org", password: PASSWORD });
      const req = send(
        {
          socketPath,
          path: "/auth/sign-in",
          method: "POST",
          headers: { origin: ORIGIN, "content-type": "application/json", "x-forwarded-for": "203.0.113.9" },
        },
        (res) => {
          res.resume();
          done(res.statusCode ?? 0);
        },
      );
      req.end(body);
    });
    assert.equal(status, 401, "answered, not refused for want of an address");
    assert.ok(count(db, "auth_limits") > 0, "and counted (as the visitor the proxy named)");
  } finally {
    server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a connection reset as its request arrives is never taken for this machine's (nor counted as whoever it named)", async () => {
  const { connect: open } = await import("node:net");
  const { db, auth } = fresh();
  const handler = createHandler(auth, { ...EMAIL, origin: DEV, trustedProxies: ["loopback"] });
  const warned = await captureWarnings(() =>
    withServer(
      handler,
      (_req, res) => res.end("app"),
      async (_base, port) => {
        for (let i = 0; i < 10; i++) {
          await new Promise<void>((done) => {
            const socket = open(port, "127.0.0.1", () => {
              const body = JSON.stringify({ email: "a@example.org", password: PASSWORD });
              socket.write(
                `POST /auth/send-sign-in-link HTTP/1.1\r\nhost: localhost\r\norigin: ${DEV}\r\ncontent-type: application/json\r\nx-forwarded-for: 6.6.6.${i}\r\ncontent-length: ${body.length}\r\n\r\n${body}`,
              );
              socket.resetAndDestroy();
              setTimeout(done, 20);
            });
            socket.on("error", () => {});
          });
        }
        await wait(50);
        const keys = (db.prepare("SELECT key FROM auth_limits").all() as { key: string }[]).length;
        assert.ok(keys <= 3, `forged addresses aren't counted as different visitors (${keys} keys)`);
      },
    ),
  );
  // Nor taken for a setup mistake: a visitor going away isn't the server being given no address.
  assert.ok(!warned.flat().join(" ").includes("no address"), "no false alarm in the log");
});
