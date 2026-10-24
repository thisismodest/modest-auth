// The routes, ready to mount: Web-standard Request in, Response out (Node, Bun,
// Deno, and most frameworks speak these). They do what an app could otherwise
// forget: every change must come from the site's own pages; bodies are small
// JSON (which another site's page can't send without the browser asking first);
// each sign-in starts a fresh session; and the caller's address is worked out
// the same way every time.
//
//   GET  /auth/session               who's signed in: { user: { email } | null }
//   POST /auth/send-password-link    { email }: to sign up, or to choose a new password
//   POST /auth/send-sign-in-link     { email }
//   POST /auth/link                  { token }: which email a link is for, and its kind
//   POST /auth/set-password          { token, password }: from a password link
//   POST /auth/sign-in-with-link     { token }: from a sign-in link
//   POST /auth/sign-in               { email, password }
//   POST /auth/sign-out               (no fields: an empty body, or {})
//   POST /auth/sign-out-everywhere    (no fields)
//   GET  /auth/sessions              the account's sessions: { sessions: [{ id, started, lastUsed, current }] }
//   POST /auth/end-session           { id }: ends one of them
//   GET  /auth/my-data               everything kept about the account, as a file to save
//   POST /auth/password              { current, next }: every other session ends
//   POST /auth/change-email          { password, email }: a link to the new address
//   POST /auth/confirm-email         { token }: from that link, signed in; every session ends
//   POST /auth/undo-email            { token }: from the notice to the old address
//   POST /auth/delete-account        { password }

import { type Auth, EMAIL_LINK_MINUTES, type Link, PASSWORD_LINK_MINUTES, SIGN_IN_LINK_MINUTES, UNDO_DAYS, type User } from "./auth.ts";
import { clearedCookie, readSessionCookie, sessionCookie, siteOrigin } from "./cookies.ts";
import { AuthError } from "./errors.ts";
import { atMost, traceClient, trusting } from "./limits.ts";
import { readAtMost } from "./streams.ts";
import { DAY } from "./time.ts";

export type HandlerOptions = {
  /** The site's origin, such as "https://example.org". Over HTTPS, except on this machine. */
  origin: string;
  /**
   * Address ranges of proxies in front of the server that connect from public addresses, such as a CDN's
   * (["173.245.48.0/20", …] for Cloudflare). Proxies on this machine or a private network (nginx, Caddy, a
   * hosting platform's load balancer) are trusted without it. Leave it out unless a CDN is in front.
   */
  trustedProxies?: readonly string[];
  /** Where the routes live. */
  base?: string;
  /**
   * The app's page that emailed links open, such as "/account/link". The token
   * follows "#" ("#password=…" or "#sign-in=…"), which browsers never send to a
   * server. The page reads it (before any other script can), asks /auth/link which
   * email it's for and shows that, then asks for a password or shows a sign-in
   * button, and sends it to set-password or sign-in-with-link. It never acts by
   * itself: someone could send a person their own link, to sign them in to the
   * wrong account.
   */
  linkPage: string;
  /**
   * Sends an email: the app's own way (any email service). Called after the answer
   * has gone, and for every request whether or not there's an account, so neither
   * the answer nor the work after it shows which. At most 10 at once (each until it
   * finishes) and 1,000 waiting; beyond that, or once its link has run out, an email
   * is dropped. `signal` aborts after 30 seconds: pass it on (fetch(url, { signal })),
   * so a stuck email service can't hold a place. Failures are logged, without the
   * email's text.
   */
  sendEmail(to: string, subject: string, text: string, options: { signal: AbortSignal }): Promise<void> | void;
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
const TOO_SLOW = "sendEmail didn't finish in 30 seconds: pass its signal on to your email service";

/** The largest body a route reads. */
const BODY_LIMIT = 4096;

const HEADERS = { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff" };

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
  if (!(request.headers.get("content-type") ?? "").toLowerCase().startsWith("application/json")) return refuse(415, "json-only", "Send JSON.");
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

/** The email for a link, in plain text. */
function linkEmail(link: Link, site: string, url: string, origin: string): { subject: string; text: string } {
  /** The link, and how long it lasts. */
  const within = (minutes: number, where = "") => `within ${minutes} minutes${where}:\n\n${url}\n\n`;
  const notYou = "If it wasn't you, you can ignore this email.\n";
  if (link.kind === "email" && link.token === null) {
    return {
      subject: `Your email address on ${site}`,
      text: `Someone asked to use this email address for an account on ${site}, but it has an account of its own already, so nothing has changed.\n\n${notYou}`,
    };
  }
  if (link.kind === "email") {
    return {
      subject: `Confirm your new email address on ${site}`,
      text: `To use this email address for your account on ${site}, open this link ${within(EMAIL_LINK_MINUTES, ", in a browser where you're signed in to that account")}Using it signs you out everywhere. If you didn't ask, you can ignore this email: nothing changes without it.\n`,
    };
  }
  if (link.token === null) {
    return {
      subject: `Sign in to ${site}`,
      text: `Someone asked to sign in to ${site} with this email address, but there's no account for it. To make one, sign up at ${origin}\n\n${notYou}`,
    };
  }
  if (link.kind === "sign-in") {
    return {
      subject: `Sign in to ${site}`,
      text: `To sign in to ${site}, open this link ${within(SIGN_IN_LINK_MINUTES)}If you didn't ask to sign in, you can ignore this email.\n`,
    };
  }
  if (link.account) {
    return {
      subject: `Choose a new password for ${site}`,
      text: `To choose a new password for your account on ${site}, open this link ${within(PASSWORD_LINK_MINUTES)}Choosing one signs you out everywhere else. If you didn't ask, you can ignore this email: your password stays as it is.\n`,
    };
  }
  return {
    subject: `Finish signing up to ${site}`,
    text: `To finish signing up to ${site}, choose a password at this link ${within(PASSWORD_LINK_MINUTES)}If you didn't ask to sign up, you can ignore this email: no account is made without it.\n`,
  };
}

export function createHandler(auth: Auth, options: HandlerOptions): Handler {
  const { origin } = siteOrigin(options.origin);
  const { linkPage, sendEmail } = options;
  if (typeof linkPage !== "string" || !/^(\/[A-Za-z0-9._~-]+)+\/?$|^\/$/.test(linkPage))
    throw new Error('linkPage must be a path on the site, such as "/account/link".');
  if (typeof sendEmail !== "function") throw new Error("sendEmail must be a function that sends an email: (to, subject, text).");
  const site = new URL(origin).host;
  // A slow or stuck email service can't pile up sends without end: 10 at once (each until it finishes), 1,000 waiting.
  const sending = atMost(10, 1000);
  // Why, but never the email's text (it holds the link) nor the service's own message (which may repeat it).
  const why = (error: unknown) =>
    error instanceof AuthError ? "too many waiting" : error instanceof Error ? (error.message === TOO_SLOW ? TOO_SLOW : error.name) : typeof error;
  /** Sent after the answer, so a slow email service doesn't hold it up; not at all if it's no use by then. */
  const queue = (to: string, subject: string, text: string, until: number) =>
    setImmediate(() => {
      sending(async () => {
        if (Date.now() >= until) return console.error("modest-auth: an email wasn't sent: its link ran out while it waited");
        // Waited for until it ends or 30 seconds pass, whichever is first: one that ignores the signal can't hold a place.
        const signal = AbortSignal.timeout(30_000);
        const late = new Promise<never>((_, fail) => signal.addEventListener("abort", () => fail(new Error(TOO_SLOW)), { once: true }));
        await Promise.race([Promise.resolve().then(() => sendEmail(to, subject, text, { signal })), late]);
      }).catch((error: unknown) => console.error("modest-auth: an email couldn't be sent:", why(error)));
    });
  const send = (link: Link | null) => {
    if (!link) return;
    const { subject, text } = linkEmail(link, site, `${origin}${linkPage}#${link.kind}=${link.token}`, origin);
    queue(link.to, subject, text, link.expires);
  };
  /** A notice of a change to an account, to its email: so its owner hears of a change they didn't make. */
  const notify = (to: string, subject: string, text: string) => queue(to, `${subject} on ${site}`, `${text}\n`, Date.now() + DAY);
  const passwordChanged = (to: string) =>
    notify(
      to,
      "Your password was changed",
      `The password for your account on ${site} was just changed, and every other session ended.\n\nIf it wasn't you, choose a new one now at ${origin} ("forgotten your password"), which also signs out whoever changed it.`,
    );
  const base = options.base ?? "/auth";
  if (!/^(\/[a-z0-9-]+)+$/.test(base)) throw new Error('base must be a path such as "/auth", in lowercase letters, numbers, and hyphens.');
  if ("proxies" in options) {
    throw new Error(
      'proxies has gone: name the proxies in front in trustedProxies instead, such as ["loopback"] for one on this machine, ["private"] for a hosting platform\'s, or a CDN\'s address ranges.',
    );
  }
  const trusted = trusting(options.trustedProxies);
  const secure = origin.startsWith("https://");

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
      sayOnce(
        "proxy",
        proxy.address,
        `a request from ${proxy.address} passed X-Forwarded-For on. If that's a CDN or proxy in front of this server, add its address ranges to trustedProxies, or its visitors share its sign-in limits; if it's a visitor's own proxy, ignore this.`,
      );
    } else if (proxy) {
      const name = proxy.where === "loopback" ? "loopback" : "private";
      sayOnce(
        "proxy",
        proxy.address,
        `a proxy at ${proxy.address} passes X-Forwarded-For on but isn't trusted, so every visitor counts as it. Add trustedProxies: ["${name}"], and check it adds the client's address rather than passing on the visitor's (${NGINX}).`,
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
  const signedIn = (user: User, old: string | null) => {
    // A fresh session at each sign-in, and the one the browser had ended: nobody can plant a session and wait.
    if (old) auth.endSession(old);
    return reply(200, { user: { email: user.email } }, sessionCookie(auth.startSession(user), origin));
  };
  /** Signed out: the session cookie cleared. */
  const signedOut = (body: object = {}) => reply(200, body, clearedCookie(origin));
  /** Sends the email (after the answer), and answers the same whatever happened. */
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
  const routes: Record<string, (request: Request, body: Body, from: string) => Promise<Response> | Response> = {
    "send-password-link": (_r, b, from) => sent(auth.requestLink("password", b.email ?? "", from)),
    "send-sign-in-link": (_r, b, from) => sent(auth.requestLink("sign-in", b.email ?? "", from)),
    link: (_r, b, from) => reply(200, auth.lookUpLink(b.token ?? "", from)),
    "set-password": async (r, b, from) => {
      const user = await auth.usePasswordLink(b.token ?? "", b.password ?? "", from);
      const answer = signedIn(user, tokenOf(r));
      if (!user.made) passwordChanged(user.email);
      return answer;
    },
    "sign-in-with-link": (r, b, from) => signedIn(auth.useSignInLink(b.token ?? "", from), tokenOf(r)),
    "sign-in": async (r, b, from) => signedIn(await auth.signIn(b.email ?? "", b.password ?? "", from), tokenOf(r)),
    "sign-out": (r) => {
      const token = tokenOf(r);
      if (token) auth.endSession(token);
      return signedOut();
    },
    "sign-out-everywhere": (r) => {
      const user = userOf(r);
      if (user) auth.endAllSessions(user.id);
      return signedOut();
    },
    "end-session": own(({ token, user }, b: Body) => {
      const current = auth.sessionsOf(user.id, token).find((session) => session.current)?.id === b.id;
      if (!auth.endSessionOf(user.id, b.id ?? "")) return refuse(404, "not-found", "There's no such session.");
      return reply(200, {}, current ? clearedCookie(origin) : undefined);
    }),
    password: own(async ({ user }, b: Body, from: string) => {
      const changed = await auth.changePassword(user.id, b.current ?? "", b.next ?? "", from);
      const answer = signedIn(changed, null);
      passwordChanged(changed.email);
      return answer;
    }),
    "change-email": own(async ({ user }, b: Body, from: string) => sent(await auth.requestEmailChange(user.id, b.password ?? "", b.email ?? "", from))),
    // Only by the account it moves, signed in here: someone could send a person their own link.
    "confirm-email": own(({ user }, b: Body, from: string) => {
      const moved = auth.useEmailLink(b.token ?? "", user.id, from);
      notify(
        moved.previous,
        "Your email address was changed",
        `The email address for your account on ${site} was just changed from this one to ${moved.email}, and every session ended.\n\nIf it wasn't you, undo it within ${UNDO_DAYS} days at this link, which moves the account back to this address, signs everyone out, and sends you a link to choose a new password:\n\n${origin}${linkPage}#undo=${moved.undo}`,
      );
      // Every session ended, this one too.
      return signedOut({ email: moved.email });
    }, "Please sign in, then open the link again."),
    "undo-email": (_r, b, from) => {
      const back = auth.useUndoLink(b.token ?? "", from);
      // Its password no longer works: a link to choose a new one, to the address it's back at.
      send(back.reset);
      return reply(200, { email: back.email });
    },
    "delete-account": own(async ({ user }, b: Body, from: string) => {
      await auth.deleteAccount(user.id, b.password ?? "", from);
      return signedOut();
    }),
  };

  /** The routes that only read: GET, and nothing in a body. */
  const reads: Record<string, (request: Request) => Promise<Response> | Response> = {
    session: (r) => {
      const user = userOf(r);
      return reply(200, { user: user ? { email: user.email } : null });
    },
    sessions: own(({ token, user }) => reply(200, { sessions: auth.sessionsOf(user.id, token) })),
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
      const name = path.slice(base.length + 1);
      const read = Object.hasOwn(reads, name) ? reads[name] : undefined;
      if (read && request.method === "GET") return read(request);
      const route = Object.hasOwn(routes, name) ? routes[name] : undefined;
      if (!route) return refuse(404, "not-found", "Not found.");
      if (request.method !== "POST") return refuse(405, "post-only", "Use POST.");
      if (!fromSite(request)) {
        // From the site's own page, as the browser says, but not the origin set: the setting, not an attack.
        const came = request.headers.get("origin");
        if (came && request.headers.get("sec-fetch-site") !== "cross-site") {
          sayOnce(
            "origin",
            came.slice(0, 200),
            `a request from a page at ${came.slice(0, 200)} was refused, as origin is ${origin}. If that's this site (www., a port, http), set origin to the address its pages are served from.`,
          );
        }
        return refuse(403, "cross-site", "Cross-site request refused.");
      }
      if (address === undefined) {
        sayOnce(
          "address",
          "",
          "handle(request, address) was given no address: pass the connection's (Bun: server.requestIP(req)?.address; Deno: info.remoteAddr.hostname; Hono: getConnInfo(c).remote.address), or every request is refused.",
        );
      }
      // Who's asking, for the limits: without it, everyone would share one allowance.
      const trace = traceClient({ remoteAddress: address, forwardedFor: request.headers.get("x-forwarded-for") }, trusted);
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
