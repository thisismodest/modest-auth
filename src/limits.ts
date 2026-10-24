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

/**
 * Who a request came from, for limits. Behind `proxies` proxies you trust, the
 * address the first of them saw: counted from the right of X-Forwarded-For, as
 * each proxy adds the address it saw (anything further left is the client's to
 * make up). With no proxies, the header is ignored. A port, if a proxy adds one,
 * is dropped. An IPv6 address counts by its /64, the block one household or
 * server is given, so changing the rest of it doesn't get round a limit; and
 * anything that isn't an address counts as "unknown".
 */
export function addressKey({ remoteAddress, forwardedFor }: ClientAddress, proxies = 0): string {
  const header = Array.isArray(forwardedFor) ? forwardedFor.join(",") : (forwardedFor ?? "");
  // Read from the right however long it is: padding it out can't make anyone share the proxy's own address.
  const forwarded = header
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean);
  let address = ((proxies > 0 ? forwarded[forwarded.length - proxies] : undefined) ?? remoteAddress ?? "").trim().toLowerCase();
  // "[2001:db8::1]:443" and "203.0.113.9:51234": the address without its port.
  const bracketed = /^\[([^\]]+)\](?::\d+)?$/.exec(address);
  if (bracketed) address = bracketed[1] ?? "";
  else if (/^[\d.]+:\d+$/.test(address)) address = address.slice(0, address.indexOf(":"));
  address = address.split("%")[0] ?? "";
  const v4 = ipv4(address);
  if (v4) return v4.join(".");
  const v6 = address.includes(":") ? ipv6(address) : null;
  if (!v6) return "unknown";
  // An IPv4 address carried in IPv6 is that IPv4 address, or every IPv4 visitor would share one /64:
  // mapped (::ffff:a.b.c.d), compatible (::a.b.c.d), and through NAT64 (64:ff9b::a.b.c.d, RFC 6052,
  // and the local-use 64:ff9b:1::/48, RFC 8215, with the usual /96 prefix).
  const zeros = (from: number, to: number) => v6.slice(from, to).every((n) => n === 0);
  // The last two groups: where an IPv4 address is carried.
  const [g6 = 0, g7 = 0] = v6.slice(6);
  const carriesIpv4 =
    (zeros(0, 5) && v6[5] === 0xffff) ||
    (zeros(0, 6) && (g6 > 0 || g7 > 1)) ||
    (v6[0] === 0x64 && v6[1] === 0xff9b && (v6[2] === 0 || v6[2] === 1) && zeros(3, 6));
  if (carriesIpv4) return [g6 >> 8, g6 & 255, g7 >> 8, g7 & 255].join(".");
  return `${v6
    .slice(0, 4)
    .map((n) => n.toString(16))
    .join(":")}::/64`;
}
