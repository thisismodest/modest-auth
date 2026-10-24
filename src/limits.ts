// Limits that slow guessing down and keep the server from being swamped.
//
// Rate limits are kept in the database (auth_limits): they survive a restart,
// every process sharing the database shares them, and none can be pushed out by
// flooding the table with other keys. Each key is stored as a hash, not as the
// email or address itself; a copy of the database could still test a guess
// against one, so rows go once their window has passed (an hour at most).

import { createHash } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import { AuthError } from "./errors.ts";

const LIMITS_SCHEMA = `
  CREATE TABLE IF NOT EXISTS auth_limits (
    key TEXT PRIMARY KEY,
    count INTEGER NOT NULL,
    resets INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS auth_limits_resets ON auth_limits (resets);
`;

/**
 * Runs a setting-up step, trying again for up to two seconds while another process
 * holds the file. SQLite usually waits by itself (busy_timeout), but not always:
 * when several processes open a new file at once and switch it to WAL, it refuses
 * some at once rather than risk them waiting on each other. Only at start-up, so
 * the short pauses between tries can block.
 */
export function settingUp(step: () => void): void {
  const until = Date.now() + 2000;
  for (;;) {
    try {
      step();
      return;
    } catch (error) {
      if (!/locked|busy/i.test(String(error)) || Date.now() > until) throw error;
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 10 + Math.random() * 40);
    }
  }
}

/** A rate limit: counts a try for `key`, and throws "too-many-tries" past the limit. */
export type Limit = (key: string) => void;

/** Rate limits kept in `db`: `limit(name, max, windowMs)` makes one. */
export function databaseLimits(db: DatabaseSync): (name: string, max: number, windowMs: number) => Limit {
  settingUp(() => db.exec(LIMITS_SCHEMA));
  // One statement: counted and read at once, so tries sent together are each counted.
  const count = db.prepare(
    `INSERT INTO auth_limits (key, count, resets) VALUES (?, 1, ?)
     ON CONFLICT (key) DO UPDATE SET
       count = CASE WHEN resets <= ? THEN 1 ELSE count + 1 END,
       resets = CASE WHEN resets <= ? THEN excluded.resets ELSE resets END
     RETURNING count, resets`,
  );
  // Clearing passed windows a batch at a time, so a large clear-out can't hold the server up.
  const sweep = db.prepare("DELETE FROM auth_limits WHERE rowid IN (SELECT rowid FROM auth_limits WHERE resets <= ? LIMIT 2000)");
  let swept = 0;
  return (name, max, windowMs) => (key) => {
    const now = Date.now();
    if (now - swept > 10_000) {
      swept = now;
      sweep.run(now);
    }
    const hashed = createHash("sha256").update(`${name}\0${key}`).digest("base64url");
    const row = count.get(hashed, now + windowMs, now, now) as { count: number; resets: number };
    if (row.count > max) throw new AuthError("too-many-tries", "Too many tries. Please wait a while, then try again.", Math.ceil((row.resets - now) / 1000));
  };
}

/**
 * At most `atOnce` of a heavy job running, a short queue behind them, and beyond
 * that "busy", so a flood of them can't use up the server's memory or threads.
 * (Per process: it guards this process's resources.)
 */
export function atMost(atOnce: number, queue: number): (<T>(work: () => Promise<T>) => Promise<T>) & { check(): void } {
  let running = 0;
  const waiting: (() => void)[] = [];
  const check = () => {
    if (running >= atOnce && waiting.length >= queue) throw new AuthError("busy", "Too much at once. Please try again in a minute.", 60);
  };
  const run = async <T>(work: () => Promise<T>): Promise<T> => {
    check();
    if (running >= atOnce) await new Promise<void>((go) => waiting.push(go));
    running++;
    try {
      return await work();
    } finally {
      running--;
      waiting.shift()?.();
    }
  };
  return Object.assign(run, { check });
}

/** Where a request came from: its connection's address, and its X-Forwarded-For header if any. */
export type ClientAddress = { remoteAddress: string | undefined; forwardedFor?: string | string[] | null | undefined };

/** An IPv4 address's four numbers, or null. */
function ipv4(text: string): number[] | null {
  const parts = text.split(".");
  if (parts.length !== 4 || !parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255)) return null;
  return parts.map(Number);
}

/** An IPv6 address's eight numbers, or null. */
function ipv6(text: string): number[] | null {
  const halves = text.split("::");
  if (halves.length > 2) return null;
  const groups = (half: string | undefined) => (half ? half.split(":") : []);
  const [left, right] = [groups(halves[0]), groups(halves[1])];
  // An IPv4 address at the end stands for the last two groups.
  const last = (halves.length === 2 ? right : left).at(-1);
  const embedded = last?.includes(".") ? ipv4(last) : null;
  if (last?.includes(".") && !embedded) return null;
  if (embedded) {
    const [a = 0, b = 0, c = 0, d = 0] = embedded;
    (halves.length === 2 ? right : left).splice(-1, 1, ((a << 8) | b).toString(16), ((c << 8) | d).toString(16));
  }
  const missing = 8 - left.length - right.length;
  if (halves.length === 2 ? missing < 1 : missing !== 0) return null;
  const all = [...left, ...Array<string>(halves.length === 2 ? missing : 0).fill("0"), ...right];
  return all.every((group) => /^[0-9a-f]{1,4}$/i.test(group)) ? all.map((group) => parseInt(group, 16)) : null;
}

/** An address, read: IPv4 as four numbers, IPv6 as eight. */
export type Address = { v4: number[] } | { v6: number[] };

/**
 * An address as written by a connection or a proxy, or null if it isn't one. A port and brackets
 * ("[2001:db8::1]:443", "203.0.113.9:51234") and a zone ("%eth0") are dropped, and an IPv4 address
 * carried in IPv6 is that IPv4 address, or every IPv4 visitor would share one /64: mapped
 * (::ffff:a.b.c.d), compatible (::a.b.c.d), and through NAT64 (64:ff9b::a.b.c.d, RFC 6052, and the
 * local-use 64:ff9b:1::/48, RFC 8215, with the usual /96 prefix).
 */
function readAddress(written: string): Address | null {
  let address = written.trim().toLowerCase();
  const bracketed = /^\[([^\]]+)\](?::\d+)?$/.exec(address);
  if (bracketed) address = bracketed[1] ?? "";
  else if (/^[\d.]+:\d+$/.test(address)) address = address.slice(0, address.indexOf(":"));
  address = address.split("%")[0] ?? "";
  const v4 = ipv4(address);
  if (v4) return { v4 };
  const v6 = address.includes(":") ? ipv6(address) : null;
  if (!v6) return null;
  const zeros = (from: number, to: number) => v6.slice(from, to).every((n) => n === 0);
  // The last two groups: where an IPv4 address is carried.
  const [g6 = 0, g7 = 0] = v6.slice(6);
  const carriesIpv4 =
    (zeros(0, 5) && v6[5] === 0xffff) ||
    (zeros(0, 6) && (g6 > 0 || g7 > 1)) ||
    (v6[0] === 0x64 && v6[1] === 0xff9b && (v6[2] === 0 || v6[2] === 1) && zeros(3, 6));
  return carriesIpv4 ? { v4: [g6 >> 8, g6 & 255, g7 >> 8, g7 & 255] } : { v6 };
}

/** An address's bits, from the left: 8 to a number for IPv4, 16 for IPv6. */
const bits = (address: Address) => ("v4" in address ? { of: address.v4, size: 8 } : { of: address.v6, size: 16 });

/** Whether `address` is in `range` (an address and a prefix length). */
function inRange(address: Address, range: { at: Address; prefix: number }): boolean {
  const [a, r] = [bits(address), bits(range.at)];
  if (a.size !== r.size) return false;
  for (let left = range.prefix, i = 0; left > 0; left -= a.size, i++) {
    const take = Math.min(left, a.size);
    const mask = ((1 << take) - 1) << (a.size - take);
    if (((a.of[i] ?? 0) & mask) !== ((r.of[i] ?? 0) & mask)) return false;
  }
  return true;
}

/** A range as written ("10.0.0.0/8", "2400:cb00::/32", or one address), or why not. `own`: one of the named sets', not checked for width. */
function readRange(written: string, own = false): { at: Address; prefix: number } {
  const text = String(written);
  const [address = "", prefix, ...more] = text.split("/");
  // Just an address and a length: a port, a zone, or brackets mean it was copied from somewhere else.
  const plain = !/[[\]%\s]/.test(address) && !/^\d+\.\d+\.\d+\.\d+:/.test(address);
  const at = plain ? readAddress(address) : null;
  const most = at && "v4" in at ? 32 : 128;
  const length = prefix === undefined ? most : /^\d{1,3}$/.test(prefix) ? Number(prefix) : Number.NaN;
  if (!at || more.length || !(length >= 0 && length <= most))
    throw new Error(`trustedProxies: "${text}" isn't an address or a range such as "203.0.113.0/24".`);
  // IPv4 written as IPv6 (::ffff:a.b.c.d/96 and the like) is read as IPv4, so its length would mean something else.
  if ("v4" in at && address.includes(":")) throw new Error(`trustedProxies: write "${text}" as an IPv4 address or range.`);
  // Wider than any one network's proxies: it would trust much of the internet to say who it is.
  if (!own && length < ("v4" in at ? 8 : 16)) throw new Error(`trustedProxies: "${text}" is too wide to be a network's proxies.`);
  return { at, prefix: length };
}

const LOOPBACK = ["127.0.0.0/8", "::1"];
/** Private networks: where a hosting platform's load balancer, or your own, connects from. */
const PRIVATE = [...LOOPBACK, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10", "fc00::/7", "fe80::/10"];
/** Names for the usual cases: "loopback" (a proxy on this machine), "private" (one on a private network). */
const NAMED: Record<string, string[]> = { loopback: LOOPBACK, private: PRIVATE };

/** Whether an address is a proxy you trust: in one of `trustedProxies`' ranges ("loopback", "private", or a CDN's, say). */
export function trusting(trustedProxies: readonly string[] = []): (address: Address) => boolean {
  if (!Array.isArray(trustedProxies)) throw new Error('trustedProxies must be a list, such as ["loopback"] or ["173.245.48.0/20"].');
  const ranges = trustedProxies.flatMap((entry) =>
    Object.hasOwn(NAMED, entry) ? (NAMED[entry] ?? []).map((range) => readRange(range, true)) : [readRange(entry)],
  );
  return (address) => ranges.some((range) => inRange(address, range));
}
const isPrivate = trusting(["private"]);
const isLoopback = trusting(["loopback"]);

/** The address a limit counts: IPv4 as it is, IPv6 by its /64 (the block one household or server is given). */
const keyOf = (address: Address) =>
  "v4" in address
    ? address.v4.join(".")
    : `${address.v6
        .slice(0, 4)
        .map((n) => n.toString(16))
        .join(":")}::/64`;

/** The whole address, as it's written in a message. */
const written = (address: Address) => ("v4" in address ? address.v4.join(".") : address.v6.map((n) => n.toString(16)).join(":"));

/**
 * Who a request came from, for limits, and any sign that the proxies in front aren't set up as they
 * should be. Starting from the connection, each address that's a proxy you trust passes on the next one
 * along X-Forwarded-For, from the right (each proxy adds the address it saw); the first that isn't a
 * trusted proxy is the client. So any number of trusted proxies, on any path, is read rightly, and a
 * connection from anyone else has its header ignored, whatever it says.
 *
 * - `untrustedProxy`: the client found still passed addresses on, so it may be a proxy of yours that
 *   isn't in trustedProxies (or a visitor's own, which is harmless): its address, and whether it's on
 *   this machine or a private network.
 * - `connection`: whether the connection's own address was one at all.
 * - `quietProxy`: the request came from this machine or a private network with no X-Forwarded-For at
 *   all, so a proxy in front may not be passing the client's address on.
 */
export function traceClient(
  { remoteAddress, forwardedFor }: ClientAddress,
  trusted: (address: Address) => boolean,
): { key: string; connection: boolean; untrustedProxy: { address: string; where: "loopback" | "private" | "public" } | null; quietProxy: boolean } {
  const header = Array.isArray(forwardedFor) ? forwardedFor.join(",") : (forwardedFor ?? "");
  const hops = header
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean);
  // No address at all is a Unix socket (or a mistake): this machine, if a proxy on it is named.
  const local: Address = { v4: [127, 0, 0, 1] };
  const connection = remoteAddress === undefined && trusted(local) ? local : readAddress(remoteAddress ?? "");
  const quietProxy = !!connection && hops.length === 0 && isPrivate(connection);
  let client = connection;
  while (client && trusted(client) && hops.length) client = readAddress(hops.pop() ?? "");
  if (!client) return { key: "unknown", connection: !!connection, untrustedProxy: null, quietProxy };
  const where = isLoopback(client) ? "loopback" : isPrivate(client) ? "private" : "public";
  return {
    key: keyOf(client),
    connection: !!connection,
    untrustedProxy: hops.length && !trusted(client) ? { address: written(client), where } : null,
    quietProxy,
  };
}

/** Who a request came from, for limits (see traceClient), trusting the proxies in `trustedProxies` and no others. */
export const addressKey = (client: ClientAddress, trustedProxies: readonly string[] = []): string => traceClient(client, trusting(trustedProxies)).key;
