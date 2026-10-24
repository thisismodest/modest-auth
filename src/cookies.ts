// The session cookie: one way to write it, one way to read it, worked out from
// the site's origin, so it can't be set up less safely by mistake.
//
// - HttpOnly: the page's scripts can't read it, so an injected script can't steal it.
// - SameSite=Lax: other sites' requests don't carry it, except when someone follows
//   a link to this site (a top-level GET, which changes nothing here).
// - Over HTTPS, the __Host- prefix: browsers only accept it Secure, for Path=/,
//   with no Domain, so it can't be set by, or sent to, any other host.
// Over plain HTTP (allowed only on this machine, for development) it has the same
// flags but no Secure or prefix, and a name of its own with the port in it, so other
// apps on localhost (which share cookies across ports), this one's too, don't overwrite it.

import { LONGEST_TOKEN, SESSION_DAYS } from "./auth.ts";
import { DAY } from "./time.ts";

/** The site's origin, checked: just a scheme, host, and port; HTTPS, or plain HTTP on this machine. Whether it's HTTPS, and the cookie's name. */
export function siteOrigin(given: string): { origin: string; secure: boolean; cookie: string } {
  let url: URL;
  try {
    url = new URL(given);
  } catch {
    throw new Error(`origin must be the site's address, such as "https://example.org" (got ${JSON.stringify(given)}).`);
  }
  const { origin } = url;
  if (origin !== given) throw new Error(`origin must be just the scheme, host, and port, such as "${origin}".`);
  const secure = origin.startsWith("https://");
  if (!secure && !/^http:\/\/(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$/.test(origin)) throw new Error("origin must be HTTPS (plain HTTP only on this machine).");
  return { origin, secure, cookie: secure ? "__Host-session" : `modest-auth-dev-session-${url.port || "80"}` };
}

const TOKEN = new RegExp(`^[A-Za-z0-9_-]{1,${LONGEST_TOKEN}}$`);
const trimmed = (text: string) => text.replace(/^[ \t]+|[ \t]+$/g, "");

/** The Set-Cookie header for the site at `origin`: `value` for `seconds`. */
function cookie(origin: string, value: string, seconds: number): string {
  const { secure, cookie: name } = siteOrigin(origin);
  return `${name}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${seconds}${secure ? "; Secure" : ""}`;
}

/** The Set-Cookie header that starts a session, for the site at `origin`. */
export function sessionCookie(token: string, origin: string): string {
  if (!TOKEN.test(token)) throw new Error("That isn't a session token.");
  return cookie(origin, token, (SESSION_DAYS * DAY) / 1000);
}

/** The Set-Cookie header that ends one (on signing out). */
export const clearedCookie = (origin: string): string => cookie(origin, "", 0);

/**
 * The session token from a request's Cookie header, or null. If the header holds
 * more than one cookie of the name, none is believed: a browser keeps one, so a
 * second was planted by someone trying to swap their session in. Only spaces and
 * tabs are trimmed round a name: one with any other character round it isn't ours.
 */
export function readSessionCookie(header: string | undefined | null, origin: string): string | null {
  const wanted = siteOrigin(origin).cookie;
  const found: string[] = [];
  for (const part of (header ?? "").split(";")) {
    const at = part.indexOf("=");
    if (at >= 0 && trimmed(part.slice(0, at)) === wanted) found.push(trimmed(part.slice(at + 1)));
  }
  const [only] = found;
  return found.length === 1 && only !== undefined && TOKEN.test(only) ? only : null;
}
