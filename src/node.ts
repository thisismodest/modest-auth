// For Node's own http server (and frameworks built on it): its requests and
// responses, turned into the Web-standard ones the handler speaks, and back.
// handleNode never throws, and never touches a request that isn't for its own
// routes: whatever a client sends, the app keeps running, and its own requests
// (bodies and all) are left exactly as they came.

import type { IncomingMessage, ServerResponse } from "node:http";
import { Readable } from "node:stream";
import type { Handler } from "./handler.ts";

/**
 * The request's path, if it's a plain one ("/auth/sign-in", not "http://host/...",
 * "//x", "/a\b", or "/x/%2e%2e/auth"): odd forms are nobody's route here, so a rule
 * in front of the app (a proxy blocking a path, say) can't be stepped round.
 */
function plainPath(url: string | undefined): string | null {
  // The path alone: what follows "?" (a query, which may well hold "%2F") is the app's business.
  const path = url?.split(/[?#]/)[0] ?? "";
  // Nor whitespace or control characters, which the URL standard drops (Node's own parser refuses them, unless set to be lenient).
  if (!path.startsWith("/") || path.startsWith("//") || path.includes("\\") || /%2e|%2f|%5c/i.test(path) || /[\s\p{Cc}]/u.test(path)) return null;
  // No "." or ".." segments: a path is taken as written, not worked out.
  if (path.split("/").some((segment) => segment === "." || segment === "..")) return null;
  try {
    return new URL(path, "http://localhost").pathname;
  } catch {
    return null;
  }
}

/**
 * A Web-standard Request for a Node one, for handler.userOf and handler.fromSite:
 * its headers only, so the app's own reading of the body is undisturbed. Only the
 * path is taken from the URL; the Host header isn't trusted.
 */
export const toRequest = (req: IncomingMessage): Request => webRequest(req, false);

/** The same, with its body (only ever for the handler's own routes). */
function webRequest(req: IncomingMessage, withBody: boolean): Request {
  const headers = new Headers();
  for (const [name, value] of Object.entries(req.headers)) {
    if (value === undefined) continue;
    for (const one of Array.isArray(value) ? value : [value]) headers.append(name, one);
  }
  // Methods a Web-standard Request can't carry (TRACE and the like) are treated as GET.
  const method = req.method === "POST" || req.method === "HEAD" ? req.method : "GET";
  const body = withBody && method === "POST" ? { body: Readable.toWeb(req) as ReadableStream<Uint8Array>, duplex: "half" } : {};
  return new Request(`http://localhost${plainPath(req.url) ?? "/"}`, { method, headers, ...body } as RequestInit);
}

/** Answers the request if it's for one of the handler's routes; false if it isn't (for the app to answer). */
export async function handleNode(handler: Handler, req: IncomingMessage, res: ServerResponse): Promise<boolean> {
  const path = plainPath(req.url);
  if (!path || (path !== handler.base && !path.startsWith(`${handler.base}/`))) return false;
  try {
    const response = await handler.handle(webRequest(req, true), req.socket.remoteAddress);
    if (!response) return false;
    const headers: Record<string, string | string[]> = {};
    response.headers.forEach((value, name) => {
      if (name !== "set-cookie") headers[name] = value;
    });
    const cookies = response.headers.getSetCookie();
    if (cookies.length) headers["set-cookie"] = cookies;
    res.writeHead(response.status, headers);
    res.end(Buffer.from(await response.arrayBuffer()));
  } catch (error) {
    console.error("modest-auth:", error instanceof Error ? error.message : error);
    if (res.headersSent) res.destroy();
    else
      res
        .writeHead(500, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" })
        .end('{"error":{"code":"failed","message":"Something went wrong."}}');
  }
  return true;
}
