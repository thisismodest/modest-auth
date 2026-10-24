// Passwords are never stored: only a slow, salted hash of each (scrypt, built
// into Node), so a copy of the database doesn't give anyone's password away.
//
// A hash records the cost it was made with ("$scrypt$ln=17,r=8,p=1$salt$hash"),
// so the cost can be raised later: a password hashed at an older cost still
// checks, and is hashed again at the new one when its owner next signs in.
//
// A new password follows NIST SP 800-63B: at least 15 characters (it's the only
// thing proving who someone is), any characters at all, no rules about mixing
// them, but not a common password (nor one with only spaces, punctuation, or
// trailing numbers added), not made from the email, and not with fewer than four
// different characters.

import { randomBytes, scrypt, timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import { AuthError } from "./errors.ts";
import { atMost } from "./limits.ts";

/** OWASP's suggested scrypt cost: N=2^17 (ln=17), r=8, p=1. About 128MB and 50ms a guess. */
const CURRENT = { ln: 17, r: 8, p: 1 };
const SALT_BYTES = 16;
const HASH_BYTES = 32;

/** In characters (Unicode code points, after normalising), not bytes or UTF-16 units. */
export const SHORTEST_PASSWORD = 15;
/** Longer is refused before hashing: a huge password would tie the server up. */
export const LONGEST_PASSWORD = 200;
/** The same limit as typed, before normalising (which can shorten it): sign-in refuses beyond this, so sign-up does too. */
export const LONGEST_TYPED = LONGEST_PASSWORD * 2;

type Cost = typeof CURRENT;

// Each hash takes about 128MB and one of Node's few worker threads (which file
// reads share): two at once, so a flood of sign-ins can't stall the server.
const twoAtOnce = atMost(2, 50);

/** Throws "busy" if hashing is too far behind to take another. Checked before a try is counted, so refusals cost nobody a try. */
export const checkHashingFree = () => twoAtOnce.check();

const derive = (password: string, salt: Buffer, { ln, r, p }: Cost) =>
  twoAtOnce(
    () =>
      new Promise<Buffer>((done, fail) =>
        scrypt(password.normalize("NFKC"), salt, HASH_BYTES, { N: 2 ** ln, r, p, maxmem: 256 * 1024 * 1024 }, (error, key) => (error ? fail(error) : done(key))),
      ),
  );

const characters = (text: string) => [...text].length;

/** Letters and digits only, lowercase: so "Password 123!" and "password123" are the same guess. */
const reduce = (text: string) => text.toLowerCase().replace(/[^\p{L}\p{N}]/gu, "");

let common: Set<string> | null = null;
/** The common passwords (common-passwords.txt), reduced, read the first time they're needed. */
function commonPasswords(): Set<string> {
  common ??= new Set(
    readFileSync(new URL("./common-passwords.txt", import.meta.url), "utf8")
      .split("\n")
      .filter((line) => line && !line.startsWith("#"))
      .map(reduce)
      // An entry that's all punctuation reduces to nothing, and would match every password without letters or digits.
      .filter(Boolean),
  );
  return common;
}

/** Throws if `password` won't do as a new password for the account with `email`. */
export function checkNewPassword(password: string, email: string): void {
  if (typeof password !== "string" || !password.isWellFormed()) throw new AuthError("invalid-password", "That password has characters that can't be kept. Please choose another.");
  const normal = password.normalize("NFKC");
  const length = characters(normal);
  if (length < SHORTEST_PASSWORD) throw new AuthError("short-password", `Please choose a password of ${SHORTEST_PASSWORD} characters or more: a few words together works well.`);
  if (length > LONGEST_PASSWORD || password.length > LONGEST_TYPED) throw new AuthError("long-password", `Please choose a password of ${LONGEST_PASSWORD} characters or fewer.`);
  const reduced = reduce(normal);
  const local = reduce(email.slice(0, email.indexOf("@")));
  const fromEmail = characters(local) >= 6 && reduced.includes(local);
  const list = commonPasswords();
  const common = list.has(reduced) || list.has(reduced.replace(/\p{N}+$/u, ""));
  if (new Set(normal.toLowerCase()).size < 4 || fromEmail || common) {
    throw new AuthError("common-password", "That password is too easy to guess. Please choose another: a few unrelated words together works well.");
  }
}

/** A hash as it's stored: its cost, salt, and hash. */
const stored = ({ ln, r, p }: Cost, salt: Buffer, hash: Buffer) => `$scrypt$ln=${ln},r=${r},p=${p}$${salt.toString("base64url")}$${hash.toString("base64url")}`;

/** A hash of the current form and cost that no password matches (random bytes, so nothing is hashed to make it). */
export const unmatchableHash = () => stored(CURRENT, randomBytes(SALT_BYTES), randomBytes(HASH_BYTES));

/** The hash to store. */
export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(SALT_BYTES);
  return stored(CURRENT, salt, await derive(password, salt, CURRENT));
}

const work = ({ ln, r, p }: Cost) => 2 ** ln * r * p;
const memory = ({ ln, r }: Cost) => 2 ** ln * r;

/** A stored hash's parts, if it's one of ours, at a cost no greater than the current one in work or memory. */
function parse(stored: string): { cost: Cost; salt: Buffer; hash: Buffer } | null {
  const match = /^\$scrypt\$ln=(\d{1,2}),r=(\d{1,2}),p=(\d{1,2})\$([A-Za-z0-9_-]{16,64})\$([A-Za-z0-9_-]{43})$/.exec(stored);
  if (!match) return null;
  const cost = { ln: Number(match[1]), r: Number(match[2]), p: Number(match[3]) };
  if (cost.ln < 10 || cost.r < 1 || cost.p < 1 || work(cost) > work(CURRENT) || memory(cost) > memory(CURRENT)) return null;
  return { cost, salt: Buffer.from(match[4]!, "base64url"), hash: Buffer.from(match[5]!, "base64url") };
}

const isCurrent = ({ ln, r, p }: Cost) => ln === CURRENT.ln && r === CURRENT.r && p === CURRENT.p;

/**
 * Whether a password matches a stored hash (compared in constant time), and
 * whether the hash should be made again at the current cost. A wrong password
 * always takes the work of the current cost, whatever the stored hash, so the
 * time taken doesn't tell anyone which accounts have older hashes.
 */
export async function checkPassword(password: string, stored: string): Promise<{ ok: boolean; outdated: boolean }> {
  const parsed = parse(stored);
  const given = parsed ? await derive(password, parsed.salt, parsed.cost) : null;
  const ok = !!parsed && !!given && timingSafeEqual(given, parsed.hash);
  if (!ok && (!parsed || !isCurrent(parsed.cost))) await derive(password, randomBytes(SALT_BYTES), CURRENT);
  return { ok, outdated: ok && !isCurrent(parsed!.cost) };
}
