// The routes, ready to mount: Web-standard Request in, Response out (Node, Bun,
// Deno, and most frameworks speak these). They do what an app could otherwise
// forget: every change must come from the site's own pages; bodies are small
// JSON (which another site's page can't send without the browser asking first);
// each sign-in starts a fresh session; and the caller's address is worked out
// the same way every time.
//
//   GET  /auth/session               who's signed in: { user: { email } | null }
//   POST /auth/link                  { token }: which email a link is for, and its kind
//   POST /auth/sign-out               (no fields: an empty body, or {})
//   POST /auth/sign-out-everywhere    (no fields)
//   GET  /auth/sessions              the account's sessions: { sessions: [{ id, started, lastUsed, current }] }
//   POST /auth/end-session           { id }: ends one of them
//   GET  /auth/my-data               everything kept about the account, as a file to save
//   POST /auth/change-email          { email }: a link to the new address (signed in recently)
//   POST /auth/confirm-email         { token }: from that link, signed in; every session ends
//   POST /auth/undo-email            { token }: from the notice to the old address
//   POST /auth/delete-account         (no fields; signed in recently)
//
// Where sign-in links are sent (a site that signs in by link, or has no passwords, so links make accounts and
// get people back in):
//
//   POST /auth/send-sign-in-link     { email }: to sign in (or sign up, or get back in)
//   POST /auth/sign-in-with-link     { token, reset }: from a sign-in link (reset "true": every session, link, and passkey ended)
//
// And only on a site with passwords:
//
//   POST /auth/send-password-link    { email }: to sign up, or to choose a new password
//   POST /auth/set-password          { token, password }: from a password link
//   POST /auth/sign-in               { email, password }
//   POST /auth/password              { next }: a new password (signed in recently); every other session ends
//
// And only on a site with passkeys (each passkey part a base64url string, as the browser gives it):
//
//   POST /auth/sign-in-options        (no fields): options for navigator.credentials.get
//   POST /auth/sign-in-with-passkey  { id, clientDataJSON, authenticatorData, signature, userHandle }
//   POST /auth/passkey-options        (no fields; signed in recently): options for navigator.credentials.create
//   POST /auth/add-passkey           { clientDataJSON, attestationObject, name }: signed in recently
//   GET  /auth/passkeys              the account's passkeys: { passkeys: [{ id, name, created, lastUsed }] }
//   POST /auth/remove-passkey        { id }: signed in recently
//
// Changing the email or password, or deleting the account, needs a session started in the last
// RECENT_MINUTES: an older one is told "sign-in-again", and signing in again (by any way the site has)
// starts a fresh one.

import type { Auth, Link, User } from "./auth.ts";
import { clearedCookie, readSessionCookie, sessionCookie, siteOrigin } from "./cookies.ts";
import { AuthError } from "./errors.ts";
import { atMost, blockOf, traceClient, trusting } from "./limits.ts";
import { type Message, messageFor } from "./messages.ts";
import { readAtMost } from "./streams.ts";
import { DAY } from "./time.ts";

export type HandlerOptions = {
  /** The site's origin, such as "https://example.org". Over HTTPS, except on this machine. */
  origin: string;
  /**
   * The proxies in front of the server, whose X-Forwarded-For is believed: "loopback" (nginx or Caddy on
   * this machine), "private" (a hosting platform's load balancer, or another container), or a
   * proxy's own addresses. Never a CDN's ranges: its other customers send from them too; put a proxy you
   * run behind it, and name that. None by default, which is always safe (visitors behind a proxy share its
   * address for limits); the log says what to set. A named proxy must add the visitor's address, not pass
   * theirs on (nginx: proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;).
   */
  trustedProxies?: readonly string[];
  /** Where the routes live. */
  base?: string;
  /**
   * The app's page that links open, such as "/account/link". The token
   * follows "#" ("#password=…" or "#sign-in=…"), which browsers never send to a
   * server. The page reads it (before any other script can), asks /auth/link which
   * email it's for and shows that, then asks for a password or shows a sign-in
   * button, and sends it to set-password or sign-in-with-link. It never acts by
   * itself: someone could send a person their own link, to sign them in to the
   * wrong account.
   */
  linkPage: string;
  /**
   * Sends a message to `message.to`: the app's own way (any email service; emailFor writes
   * modest-auth's own words for one). Called after the answer has gone, and for every request
   * whether or not there's an account, so neither the answer nor the work after it shows which.
   * At most 10 at once (each until it finishes) and 1,000 waiting; beyond that, or once its link
   * has run out, a message is dropped. `signal` aborts after 30 seconds: pass it on
   * (fetch(url, { signal })), so a stuck service can't hold a place. Failures are logged, without
   * the message.
   */
  deliver(message: Message, options: { signal: AbortSignal }): Promise<void> | void;
};

export type Handler = {
  /** Where its routes live, such as "/auth". */
  readonly base: string;
  /** The answer to a request for one of the routes, or null if it isn't one. `address`: the connection's own. */
  handle(request: Request, address: string | undefined): Promise<Response | null>;
  /** Who's signed in, for the app's own routes. */
  userOf(request: Request): User | null;
  /**
   * Whether a request came from the site's own pages. Check it on every one of
   * the app's own routes that changes anything, as the handler does on its own.
   */
  fromSite(request: Request): boolean;
};

export const BODY_READ =
  "The request's body was read before modest-auth's handler saw it: mount the handler before any body parser (express.json() and the like).";

/** How nginx adds the client's address, which it doesn't by default. */
const NGINX = "nginx: proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;";
/**
 * A web page's origin, read: its host without "www." or a port (what two addresses of one site have in
 * common), a key without the port, and the origin as the URL standard writes it. Null unless http or https.
 */
const pageOf = (origin: string | null) => {
  try {
    const url = new URL(origin ?? "");
    if (url.protocol !== "http:" && url.protocol !== "https:") return null;
    return { host: url.hostname.replace(/^www\./, ""), key: `${url.protocol}//${url.hostname}`, origin: url.origin };
  } catch {
    return null;
  }
};
const TOO_SLOW = "deliver didn't finish in 30 seconds: pass its signal on to the service it uses";

/** The largest body a route reads. */
const BODY_LIMIT = 4096;

/** Every answer's headers: JSON, never kept, and never read as anything else (the Node adapter's own failures use them too). */
export const HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
  "x-content-type-options": "nosniff",
  // Read only by the site's own pages, not by another site's, even a sibling subdomain's.
  "cross-origin-resource-policy": "same-origin",
};

function reply(status: number, body: unknown, cookie?: string, retryAfter?: number): Response {
  const headers = new Headers(HEADERS);
  if (cookie) headers.append("set-cookie", cookie);
  // Paused or busy: when it's worth trying again (seconds), from the limit itself.
  if (retryAfter !== undefined) headers.set("retry-after", String(Math.max(1, retryAfter)));
  return new Response(JSON.stringify(body), { status, headers });
}
const refuse = (status: number, code: string, message: string, retryAfter?: number) => reply(status, { error: { code, message } }, undefined, retryAfter);

/** A small JSON object of strings (an empty body counts as {}), or why not. */
async function readBody(request: Request): Promise<Record<string, string> | Response> {
  // Read already, by a body parser in front: a mistake in how the handler is mounted, said plainly (or every route would see no fields).
  if (request.bodyUsed) throw new Error(BODY_READ);
  // Exactly JSON, with nothing but a charset after it: not "application/jsonx", nor two types run together
  const type = (request.headers.get("content-type") ?? "").toLowerCase();
  if (!/^application\/json\s*(;\s*charset=[\w-]+\s*)?$/.test(type)) return refuse(415, "json-only", "Send JSON.");
  if (Number(request.headers.get("content-length") ?? 0) > BODY_LIMIT) return refuse(413, "too-large", "That's too large.");
  let bytes: Buffer | "too-large";
  try {
    bytes = await readAtMost(request.body, BODY_LIMIT);
  } catch {
    // The client went away mid-body.
    return refuse(400, "incomplete", "The request didn't arrive whole.");
  }
  if (bytes === "too-large") return refuse(413, "too-large", "That's too large.");
  if (bytes.length === 0) return {};
  try {
    const body: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    if (!body || typeof body !== "object" || Array.isArray(body)) throw new Error();
    const strings: Record<string, string> = {};
    for (const [key, value] of Object.entries(body)) if (typeof value === "string") strings[key] = value;
    return strings;
  } catch {
    return refuse(400, "bad-json", "That isn't a JSON object.");
  }
}

export function createHandler(auth: Auth, options: HandlerOptions): Handler {
  const { origin, secure } = siteOrigin(options.origin);
  const { linkPage, deliver } = options;
  if (typeof linkPage !== "string" || !/^(\/[A-Za-z0-9._~-]+)+\/?$|^\/$/.test(linkPage))
    throw new Error('linkPage must be a path on the site, such as "/account/link".');
  if ("sendEmail" in options || "name" in options) {
    throw new Error(
      "sendEmail and name have gone: give deliver(message) instead, and use emailFor(message, { origin, name }) in it for modest-auth's own emails.",
    );
  }
  if (typeof deliver !== "function") throw new Error("deliver must be a function that sends a message: (message, { signal }).");
  const passwords = auth.signInWith.includes("password");
  const passkeys = auth.signInWith.includes("passkey");
  // A slow or stuck service can't pile up sends without end: 10 at once (each until it finishes), 1,000 waiting.
  const sending = atMost(10, 1000);
  // Why, but never the message (it holds the link) nor the service's own error message (which may repeat it).
  const why = (error: unknown) =>
    error instanceof AuthError
      ? "too many waiting"
      : !(error instanceof Error)
        ? typeof error
        : error.message === TOO_SLOW
          ? TOO_SLOW
          : error.name === "TimeoutError" || error.name === "AbortError"
            ? "it didn't finish in 30 seconds"
            : error.name;
  // Messages not sent, said at most 5 times a minute, with a count of the rest: a flood can't fill the log, and a
  // service that's down still shows.
  let notesSaid = 0;
  let notesUnsaid = 0;
  let notesMinute = 0;
  const notSent = (reason: string) => {
    const now = Math.floor(Date.now() / 60_000);
    if (now !== notesMinute) {
      if (notesUnsaid) console.error(`modest-auth: ${notesUnsaid} more messages weren't sent in the minute before (not each said)`);
      [notesMinute, notesSaid, notesUnsaid] = [now, 0, 0];
    }
    if (notesSaid++ < 5) console.error(`modest-auth: ${reason}`);
    else notesUnsaid++;
  };
  /** Sent after the answer, so a slow service doesn't hold it up; not at all if it's no use by then (a day, for a notice). */
  const queue = (message: Message) =>
    setImmediate(() => {
      const until = "expires" in message ? message.expires : Date.now() + DAY;
      sending(async () => {
        if (Date.now() >= until) return notSent("a message wasn't sent: its link ran out while it waited");
        // Waited for until it ends, or a second after its signal aborts at 30 seconds (time for a send that passed the
        // signal on to stop): one that ignores the signal can't hold a place.
        const signal = AbortSignal.timeout(30_000);
        const late = new Promise<never>((_, fail) =>
          signal.addEventListener("abort", () => setTimeout(() => fail(new Error(TOO_SLOW)), 1000).unref(), { once: true }),
        );
        await Promise.race([Promise.resolve().then(() => deliver(message, { signal })), late]);
      }).catch((error: unknown) => notSent(`a message couldn't be sent: ${why(error)}`));
    });
  /** The page a link of `kind` opens, with its token after "#". */
  const linkTo = (kind: string, token: string) => `${origin}${linkPage}#${kind}=${token}`;
  const send = (link: Link | null) => {
    if (link) queue(messageFor(link, linkTo(link.kind, link.token ?? "")));
  };
  /** A notice to an account's email that its password changed: so its owner hears of a change they didn't make. */
  const passwordChanged = (email: string) => queue({ kind: "password-changed", to: { email } });
  const base = options.base ?? "/auth";
  if (!/^(\/[a-z0-9-]+)+$/.test(base)) throw new Error('base must be a path such as "/auth", in lowercase letters, numbers, and hyphens.');
  if ("proxies" in options) {
    throw new Error(
      'proxies has gone: name the proxies in front in trustedProxies instead, such as ["loopback"] for one on this machine, ["private"] for a hosting platform\'s, or a proxy\'s own address.',
    );
  }
  const trusted = trusting(options.trustedProxies);
  /** This site's own pages, to tell a setting that's off from an attack. */
  const ownPage = pageOf(origin);

  // Setup mistakes, said once each in the log: a few of each kind at most, so nobody can flood it or use them up.
  const said = new Map<string, Set<string>>();
  const sayOnce = (kind: string, key: string, message: string) => {
    const seen = said.get(kind) ?? new Set<string>();
    said.set(kind, seen);
    if (seen.has(key) || seen.size >= 5) return;
    seen.add(key);
    console.warn(`modest-auth: ${message}`);
  };
  /** What the proxies in front look like, from one request: anything that doesn't add up, said plainly. */
  const checkProxies = (trace: ReturnType<typeof traceClient>, address: string | undefined) => {
    const proxy = trace.untrustedProxy;
    if (proxy?.where === "public") {
      // Counted by its /48 for IPv6 (what one home or site can be given), so one network can't use these
      // up to hide another.
      sayOnce(
        "public proxy",
        blockOf(trace.key) ?? trace.key,
        `a request from ${proxy.address} passed X-Forwarded-For on. If that's a proxy you run in front of this server, add its address to trustedProxies, or its visitors share its sign-in limits (for a CDN, put a proxy you run behind it and name that); if it's a visitor's own proxy, ignore this.`,
      );
    } else if (proxy) {
      const setting = proxy.where === "loopback" ? "loopback" : "private";
      sayOnce(
        "internal proxy",
        proxy.address,
        `a proxy at ${proxy.address} passes X-Forwarded-For on but isn't trusted, so every visitor counts as it. Add trustedProxies: ["${setting}"], and check it adds the client's address rather than passing on the visitor's (${NGINX}).`,
      );
    }
    if (trace.quietProxy && secure) {
      sayOnce(
        "quiet",
        String(address),
        `requests reach the handler from ${address} with no X-Forwarded-For. If a proxy is in front, have it add the client's address (${NGINX}) and name it in trustedProxies, or every visitor shares one allowance.`,
      );
    }
  };

  const tokenOf = (request: Request) => readSessionCookie(request.headers.get("cookie"), origin);
  /** The session a request carries, and whose it is; null if none. */
  const signedInAs = (request: Request) => {
    const token = tokenOf(request);
    const user = token ? auth.userOf(token) : null;
    return token && user ? { token, user } : null;
  };
  const userOf = (request: Request) => signedInAs(request)?.user ?? null;
  const signedIn = (user: User, old: string | null, from: string) => {
    // A fresh session at each sign-in, and the one the browser had ended: nobody can plant a session and wait.
    if (old) auth.endSession(old, from);
    return reply(200, { user: { email: user.email } }, sessionCookie(auth.startSession(user), origin));
  };
  /** Signed out: the session cookie cleared. */
  const signedOut = (body: object = {}) => reply(200, body, clearedCookie(origin));
  /** Sends the message (after the answer), and answers the same whatever happened. */
  const sent = (link: Link | null) => {
    send(link);
    return reply(202, {});
  };

  // Only the site's own pages may change anything (browsers always send Origin on a POST).
  const fromSite = (request: Request) => {
    const site = request.headers.get("sec-fetch-site");
    return request.headers.get("origin") === origin && (site === null || site === "same-origin");
  };

  type Me = { token: string; user: User };
  /** A route only for a signed-in browser, given who it is; "signed-out" otherwise. */
  const own =
    <A extends unknown[]>(route: (me: Me, ...rest: A) => Promise<Response> | Response, ask = "Please sign in.") =>
    (request: Request, ...rest: A) => {
      const me = signedInAs(request);
      return me ? route(me, ...rest) : refuse(401, "signed-out", ask);
    };

  type Body = Record<string, string>;
  type Route = (request: Request, body: Body, from: string) => Promise<Response> | Response;
  /** A notice to an account's email that a passkey was added or removed, naming it. */
  const passkeyNotice = (kind: "passkey-added" | "passkey-removed", email: string, name: string) => queue({ kind, to: { email }, name });
  /** The routes for sign-in links: where they're sent (to sign in, or, without passwords, to make accounts and get back in). */
  const linkRoutes: Record<string, Route> = {
    "send-sign-in-link": (_r, b, from) => sent(auth.requestLink("sign-in", b.email ?? "", from)),
    // `reset: "true"`: a fresh start, every session, link, and passkey of the account ended (always, where links
    // aren't a sign-in method, as they're only the way back in there).
    "sign-in-with-link": (r, b, from) => signedIn(auth.useSignInLink(b.token ?? "", from, { reset: b.reset === "true" }), tokenOf(r), from),
  };
  /** The routes for passwords: only on a site that uses them. */
  const passwordRoutes: Record<string, Route> = {
    "send-password-link": (_r, b, from) => sent(auth.requestLink("password", b.email ?? "", from)),
    "set-password": async (r, b, from) => {
      const user = await auth.usePasswordLink(b.token ?? "", b.password ?? "", from);
      const answer = signedIn(user, tokenOf(r), from);
      if (!user.made) passwordChanged(user.email);
      return answer;
    },
    "sign-in": async (r, b, from) => signedIn(await auth.signIn(b.email ?? "", b.password ?? "", from), tokenOf(r), from),
    password: own(async ({ token }, b: Body, from: string) => {
      const changed = await auth.changePassword(token, b.next ?? "", from);
      // The session that asked ended with every other: a fresh one for it.
      const answer = signedIn(changed, null, from);
      passwordChanged(changed.email);
      return answer;
    }),
  };
  /** The routes for passkeys: only on a site that uses them. Each passkey part is a base64url string, as the browser gives it. */
  const passkeyRoutes: Record<string, Route> = {
    "passkey-options": own(({ token }, _b: Body, from: string) => reply(200, auth.passkeyOptions(token, origin, from))),
    "add-passkey": own(({ token, user }, b: Body, from: string) => {
      const made = { clientDataJSON: b.clientDataJSON ?? "", attestationObject: b.attestationObject ?? "" };
      const passkey = auth.addPasskey(token, made, b.name, origin, from);
      passkeyNotice("passkey-added", user.email, passkey.name);
      return reply(200, { passkey });
    }),
    "sign-in-options": (_r, _b, from) => reply(200, auth.signInOptions(origin, from)),
    "sign-in-with-passkey": (r, b, from) => {
      const { id = "", clientDataJSON = "", authenticatorData = "", signature = "", userHandle } = b;
      const assertion = { id, clientDataJSON, authenticatorData, signature, ...(userHandle === undefined ? {} : { userHandle }) };
      return signedIn(auth.signInWithPasskey(assertion, origin, from), tokenOf(r), from);
    },
    "remove-passkey": own(({ token, user }, b: Body, from: string) => {
      const removed = auth.removePasskey(token, b.id ?? "", from);
      if (!removed) return refuse(404, "not-found", "There's no such passkey.");
      passkeyNotice("passkey-removed", user.email, removed.name);
      return reply(200, {});
    }),
  };
  const routes: Record<string, Route> = {
    link: (_r, b, from) => reply(200, auth.lookUpLink(b.token ?? "", from)),
    "sign-out": (r, _b, from) => {
      const token = tokenOf(r);
      if (token) auth.endSession(token, from);
      return signedOut();
    },
    "sign-out-everywhere": (r, _b, from) => {
      const user = userOf(r);
      if (user) auth.endAllSessions(user.id, from);
      return signedOut();
    },
    "end-session": own(({ token, user }, b: Body, from: string) => {
      const current = auth.sessionsOf(user.id, token).find((session) => session.current)?.id === b.id;
      if (!auth.endSessionOf(user.id, b.id ?? "", from)) return refuse(404, "not-found", "There's no such session.");
      return reply(200, {}, current ? clearedCookie(origin) : undefined);
    }),
    "change-email": own(({ token }, b: Body, from: string) => sent(auth.requestEmailChange(token, b.email ?? "", from))),
    // Only by the account it moves, signed in here: someone could send a person their own link.
    "confirm-email": own(({ user }, b: Body, from: string) => {
      const moved = auth.useEmailLink(b.token ?? "", user.id, from);
      const { undo } = moved;
      queue({ kind: "email-changed", to: { email: undo.to }, email: moved.email, link: linkTo("undo", undo.token ?? ""), expires: undo.expires });
      // Every session ended, this one too.
      return signedOut({ email: moved.email });
    }, "Please sign in, then open the link again."),
    "undo-email": (_r, b, from) => {
      const back = auth.useUndoLink(b.token ?? "", from);
      // Its password no longer works: a link to get back in, to the address it's back at.
      send(back.reset);
      return reply(200, { email: back.email });
    },
    "delete-account": own(({ token, user }, _b: Body, from: string) => {
      auth.deleteAccount(token, from);
      // It can't be undone: the address is told, so a deletion its owner didn't make is at least known.
      queue({ kind: "account-deleted", to: { email: user.email } });
      return signedOut();
    }),
    ...(auth.signInLinks ? linkRoutes : {}),
    ...(passwords ? passwordRoutes : {}),
    ...(passkeys ? passkeyRoutes : {}),
  };

  /** The routes that only read: GET, and nothing in a body. */
  const reads: Record<string, (request: Request) => Promise<Response> | Response> = {
    session: (r) => {
      const user = userOf(r);
      return reply(200, { user: user ? { email: user.email } : null });
    },
    sessions: own(({ token, user }) => reply(200, { sessions: auth.sessionsOf(user.id, token) })),
    ...(passkeys ? { passkeys: own(({ user }) => reply(200, { passkeys: auth.passkeysOf(user.id) })) } : {}),
    "my-data": own(({ user }) => {
      const answer = reply(200, auth.dataOf(user.id));
      answer.headers.set("content-disposition", 'attachment; filename="my-data.json"');
      return answer;
    }),
  };

  return {
    base,
    userOf,
    fromSite,
    async handle(request, address) {
      const path = new URL(request.url).pathname;
      if (path !== base && !path.startsWith(`${base}/`)) return null;
      const which = path.slice(base.length + 1);
      const read = Object.hasOwn(reads, which) ? reads[which] : undefined;
      if (read && request.method === "GET") return read(request);
      const route = Object.hasOwn(routes, which) ? routes[which] : undefined;
      if (!route) return refuse(404, "not-found", "Not found.");
      if (request.method !== "POST") return refuse(405, "post-only", "Use POST.");
      if (!fromSite(request)) {
        // This site's own pages at another address (www., or a port) than the one set: the setting, not an attack.
        // Only this site's host is said, so nobody can fill the log, or use the message up, with others.
        const page = pageOf(request.headers.get("origin"));
        if (page && page.host === ownPage?.host) {
          const came = page.origin;
          // Keyed by scheme and host, without the port: at most four (http or https, with or without www.), all this site's.
          sayOnce(
            "origin",
            page.key,
            `a request from a page at ${came} was refused, as origin is ${origin}. If that's this site (www., or a port), set origin to the address its pages are served from.`,
          );
        }
        return refuse(403, "cross-site", "Cross-site request refused.");
      }
      // Who's asking, for the limits: without it, everyone would share one allowance.
      const trace = traceClient({ remoteAddress: address, forwardedFor: request.headers.get("x-forwarded-for") }, trusted);
      if (!trace.connection) {
        sayOnce(
          "address",
          "",
          `handle(request, address) was given ${address === undefined ? "no address" : "something that isn't one"}: pass the connection's own (Node: req.socket.remoteAddress; Bun: server.requestIP(req)?.address; Deno: info.remoteAddr.hostname; Hono: getConnInfo(c).remote.address), not a header; on a Unix socket, name the proxy with trustedProxies: ["loopback"]. Until then every request is refused.`,
        );
      }
      checkProxies(trace, address);
      const from = trace.key;
      if (from === "unknown") return refuse(400, "no-address", "Where the request came from isn't known.");
      const body = await readBody(request);
      if (body instanceof Response) return body;
      try {
        return await route(request, body, from);
      } catch (error) {
        if (error instanceof AuthError) return refuse(error.status, error.code, error.message, error.retryAfter);
        throw error;
      }
    },
  };
}
