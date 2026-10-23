// The routes, ready to mount: Web-standard Request in, Response out (Node, Bun,
// Deno, and most frameworks speak these). They do what an app could otherwise
// forget: every change must come from the site's own pages; bodies are small
// JSON (which another site's page can't send without the browser asking first);
// each sign-in starts a fresh session; and the caller's address is worked out
// the same way every time.
//
//   GET  /auth/session               who's signed in: { user: { email } | null }
//   POST /auth/sign-up               { email, password }
//   POST /auth/sign-in               { email, password }
//   POST /auth/sign-out               (no fields: an empty body, or {})
//   POST /auth/sign-out-everywhere    (no fields)
//   POST /auth/password              { current, next }: every other session ends
//   POST /auth/delete-account        { password }

import type { Auth, User } from "./auth.ts";
import { clearedCookie, readSessionCookie, sessionCookie, siteOrigin } from "./cookies.ts";
import { AuthError } from "./errors.ts";
import { addressKey } from "./limits.ts";

export type HandlerOptions = {
  /** The site's origin, such as "https://example.org". Over HTTPS, except on this machine. */
  origin: string;
  /** How many reverse proxies are in front of the server (see addressKey). */
  proxies?: number;
  /** Where the routes live. */
  base?: string;
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
  if (!(request.headers.get("content-type") ?? "").toLowerCase().startsWith("application/json")) return refuse(415, "json-only", "Send JSON.");
  if (Number(request.headers.get("content-length") ?? 0) > BODY_LIMIT) return refuse(413, "too-large", "That's too large.");
  const chunks: Uint8Array[] = [];
  let size = 0;
  const reader = request.body?.getReader();
  try {
    for (let part = await reader?.read(); part && !part.done; part = await reader!.read()) {
      size += part.value.byteLength;
      if (size > BODY_LIMIT) {
        await reader!.cancel().catch(() => {});
        return refuse(413, "too-large", "That's too large.");
      }
      chunks.push(part.value);
    }
  } catch {
    // The client went away mid-body.
    return refuse(400, "incomplete", "The request didn't arrive whole.");
  }
  if (size === 0) return {};
  try {
    const body: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks)));
    if (!body || typeof body !== "object" || Array.isArray(body)) throw new Error();
    const strings: Record<string, string> = {};
    for (const [key, value] of Object.entries(body)) if (typeof value === "string") strings[key] = value;
    return strings;
  } catch {
    return refuse(400, "bad-json", "That isn't a JSON object.");
  }
}

export function createHandler(auth: Auth, options: HandlerOptions): Handler {
  const { origin } = siteOrigin(options.origin);
  const base = options.base ?? "/auth";
  if (!/^(\/[a-z0-9-]+)+$/.test(base)) throw new Error('base must be a path such as "/auth", in lowercase letters, numbers, and hyphens.');
  const proxies = options.proxies ?? 0;
  if (!Number.isInteger(proxies) || proxies < 0) throw new Error("proxies must be a whole number, 0 or more.");
  // A proxy is passing addresses on, but none was declared: everyone looks like the proxy, and shares one allowance.
  let warned = false;
  const checkProxies = (request: Request) => {
    if (warned || proxies > 0 || !request.headers.has("x-forwarded-for")) return;
    warned = true;
    console.warn("modest-auth: requests carry X-Forwarded-For, but proxies is 0: if a reverse proxy is in front, set proxies, or every visitor shares its sign-in limits.");
  };

  const tokenOf = (request: Request) => readSessionCookie(request.headers.get("cookie"), origin);
  const userOf = (request: Request) => {
    const token = tokenOf(request);
    return token ? auth.userOf(token) : null;
  };
  const signedIn = (user: User, old: string | null, status = 200) => {
    // A fresh session at each sign-in, and the one the browser had ended: nobody can plant a session and wait.
    if (old) auth.endSession(old);
    return reply(status, { user: { email: user.email } }, sessionCookie(auth.startSession(user), origin));
  };

  // Only the site's own pages may change anything (browsers always send Origin on a POST).
  const fromSite = (request: Request) => {
    const site = request.headers.get("sec-fetch-site");
    return request.headers.get("origin") === origin && (site === null || site === "same-origin");
  };

  const routes: Record<string, (body: Record<string, string>, request: Request, from: string) => Promise<Response> | Response> = {
    "sign-up": async (b, r, from) => signedIn(await auth.signUp(b.email ?? "", b.password ?? "", from), tokenOf(r), 201),
    "sign-in": async (b, r, from) => signedIn(await auth.signIn(b.email ?? "", b.password ?? "", from), tokenOf(r)),
    "sign-out": (_b, r) => {
      const token = tokenOf(r);
      if (token) auth.endSession(token);
      return reply(200, {}, clearedCookie(origin));
    },
    "sign-out-everywhere": (_b, r) => {
      const user = userOf(r);
      if (user) auth.endAllSessions(user.id);
      return reply(200, {}, clearedCookie(origin));
    },
    password: async (b, r, from) => {
      const user = userOf(r);
      if (!user) return refuse(401, "signed-out", "Please sign in.");
      return signedIn(await auth.changePassword(user.id, b.current ?? "", b.next ?? "", from), null);
    },
    "delete-account": async (b, r, from) => {
      const user = userOf(r);
      if (!user) return refuse(401, "signed-out", "Please sign in.");
      await auth.deleteAccount(user.id, b.password ?? "", from);
      return reply(200, {}, clearedCookie(origin));
    },
  };

  return {
    base,
    userOf,
    fromSite,
    async handle(request, address) {
      const path = new URL(request.url).pathname;
      if (path !== base && !path.startsWith(`${base}/`)) return null;
      const name = path.slice(base.length + 1);
      if (request.method === "GET" && name === "session") {
        const user = userOf(request);
        return reply(200, { user: user ? { email: user.email } : null });
      }
      const route = Object.hasOwn(routes, name) ? routes[name] : undefined;
      if (!route) return refuse(404, "not-found", "Not found.");
      if (request.method !== "POST") return refuse(405, "post-only", "Use POST.");
      if (!fromSite(request)) return refuse(403, "cross-site", "Cross-site request refused.");
      checkProxies(request);
      // Who's asking, for the limits: without it, everyone would share one allowance.
      const from = addressKey({ remoteAddress: address, forwardedFor: request.headers.get("x-forwarded-for") }, proxies);
      if (from === "unknown") return refuse(400, "no-address", "Where the request came from isn't known.");
      const body = await readBody(request);
      if (body instanceof Response) return body;
      try {
        return await route(body, request, from);
      } catch (error) {
        if (error instanceof AuthError) return refuse(error.status, error.code, error.message, error.retryAfter);
        throw error;
      }
    },
  };
}
