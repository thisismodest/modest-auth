// Accounts and sessions. An account is an email and a password; signing in
// starts a session, whose token goes in a cookie (cookies.ts). The database
// keeps a hash of each token, never the token itself, and a slow hash of each
// password, never the password.
//
// It keeps its tables (auth_users, auth_sessions, auth_limits) in a node:sqlite
// database you give it, which may be your app's own, and may be shared by
// several processes.

import { createHash, randomBytes, randomUUID } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import { cleanEmail } from "./emails.ts";
import { AuthError } from "./errors.ts";
import { databaseLimits, settingUp } from "./limits.ts";
import { checkHashingFree, checkNewPassword, checkPassword, hashPassword, LONGEST_TYPED } from "./passwords.ts";

export type User = { id: string; email: string };

/** A session lasts this long from signing in, however much it's used. */
export const SESSION_DAYS = 30;
/** And ends sooner if it isn't used for this long. */
export const IDLE_DAYS = 7;
const DAY_MS = 86_400_000;
/** How often a session's last use is written down (not on every request). */
const SEEN_EVERY_MS = 60 * 60 * 1000;
/** Sessions one account can have at once: beyond this, the oldest ends. */
const MOST_SESSIONS = 50;

export type Auth = {
  /** A new account. `from` is who's asking (addressKey in limits.ts). */
  signUp(email: string, password: string, from: string): Promise<User>;
  /** The account, if the password is right. A wrong email and a wrong password get the same answer. */
  signIn(email: string, password: string, from: string): Promise<User>;
  /**
   * A new session for a user just returned by signIn, signUp, or changePassword: the
   * token to put in their cookie. One session for each time the password was checked,
   * and only while it's still the account's password (and the account still there).
   */
  startSession(user: User): string;
  /** Who a session's token belongs to, while it lasts. */
  userOf(token: string): User | null;
  /** Signing out: the session ends. */
  endSession(token: string): void;
  /** Signing out everywhere: every session of the user ends. */
  endAllSessions(userId: string): void;
  /** A new password, given the current one. Every session of the user ends. */
  changePassword(userId: string, current: string, next: string, from: string): Promise<User>;
  /** The account and its sessions, gone, given its password. */
  deleteAccount(userId: string, password: string, from: string): Promise<void>;
};

const SCHEMA = `
  CREATE TABLE IF NOT EXISTS auth_users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    created INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS auth_sessions (
    token TEXT PRIMARY KEY,
    user TEXT NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    expires INTEGER NOT NULL,
    seen INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS auth_sessions_user ON auth_sessions (user);
  CREATE INDEX IF NOT EXISTS auth_sessions_expires ON auth_sessions (expires);
  CREATE INDEX IF NOT EXISTS auth_sessions_seen ON auth_sessions (seen);
`;

const tokenHash = (token: string) => createHash("sha256").update(token).digest("base64url");
/** What addressKey gives for a real address: IPv4, or an IPv6 /64. */
const ADDRESS = /^(?:\d{1,3}\.){3}\d{1,3}$|^[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){3}::\/64$/;
const WRONG = () => new AuthError("wrong-credentials", "That email and password don't match.");
const TAKEN = () => new AuthError("email-taken", "There's already an account for that email: sign in instead.");

/** Accounts and sessions, kept in `db` (its tables are made if they aren't there). */
export function createAuth(db: DatabaseSync): Auth {
  // Several processes can share the file: they wait up to two seconds for another
  // that's writing (set first, so even switching to WAL waits), and WAL lets them
  // read while one writes. Foreign keys take sessions with their account. Deleted
  // rows are overwritten in the file (and the WAL is emptied after a deletion).
  db.exec("PRAGMA busy_timeout = 2000;");
  settingUp(() => db.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA secure_delete = ON;"));
  settingUp(() => db.exec(SCHEMA));
  const limit = databaseLimits(db);

  // Each counted before a password is hashed, so tries sent all at once count too.
  // 20 sign-ins, sign-ups, or password checks from one address in 15 minutes.
  const perAddress = limit("address", 20, 15 * 60 * 1000);
  // 10 tries at one account from one address in 15 minutes: a stranger elsewhere can't lock its owner out.
  const perAccountAndAddress = limit("account+address", 10, 15 * 60 * 1000);
  // 100 tries at one account an hour, from anywhere: guesses spread over many addresses are slowed too.
  const perAccount = limit("account", 100, 60 * 60 * 1000);
  // 200 from one IPv6 /48 in 15 minutes: the block a single site or customer is often given, so its 65,536 /64s count together.
  const perBlock = limit("block", 200, 15 * 60 * 1000);
  // 10 password checks an hour by the account's own signed-in sessions (changing the password, deleting the
  // account): strangers can't use these up, and a stolen session can't guess the password.
  const perOwner = limit("owner", 10, 60 * 60 * 1000);
  const fromWhere = (from: string) => {
    // Without an address, everyone would share one allowance: that's a mistake in the calling code.
    if (typeof from !== "string" || !ADDRESS.test(from)) throw new Error("from must be where the request came from, as addressKey gives it.");
    perAddress(from);
    if (from.endsWith("::/64")) perBlock(`${from.split(":").slice(0, 3).join(":")}::/48`);
  };

  // Checked against when there's no such account, so a wrong email takes as long as a wrong password:
  // a hash of the current form and cost that nothing matches (made from random bytes, so no hashing at start-up).
  const nobody = `$scrypt$ln=17,r=8,p=1$${randomBytes(16).toString("base64url")}$${randomBytes(32).toString("base64url")}`;

  // The password hash each signed-in user was checked against: a session starts only while it's still theirs.
  const checked = new WeakMap<User, string>();

  const userRow = (where: "email" | "id", value: string) =>
    db.prepare(`SELECT id, email, password FROM auth_users WHERE ${where} = ?`).get(value) as { id: string; email: string; password: string } | undefined;

  /**
   * The account's hash after checking its password (made again if at an older cost), limited as a
   * sign-in is. `owner`: the account's own signed-in session is asking, so the per-account pause,
   * which strangers can trigger, doesn't apply.
   */
  async function verify(row: { id: string; password: string } | undefined, key: string, password: string, from: string, owner = false): Promise<string> {
    const stored = row?.password ?? nobody;
    // Busy first (and nothing awaited after it until the hash): a try refused for being busy isn't counted.
    checkHashingFree();
    fromWhere(from);
    perAccountAndAddress(`${key}\0${from}`);
    if (owner) perOwner(row?.id ?? key);
    else perAccount(key);
    if (typeof password !== "string" || password.length > LONGEST_TYPED || !password.isWellFormed()) throw WRONG();
    const { ok, outdated } = await checkPassword(password, stored);
    if (!row || !ok) throw WRONG();
    if (!outdated) return row.password;
    const fresh = await hashPassword(password);
    // Only if nothing changed it meanwhile: a password changed while this was hashing stays changed.
    if (db.prepare("UPDATE auth_users SET password = ? WHERE id = ? AND password = ?").run(fresh, row.id, row.password).changes) return fresh;
    // Changed meanwhile: by another sign-in upgrading it too, or by a new password. Check against what's there now.
    const now = userRow("id", row.id);
    if (now && (await checkPassword(password, now.password)).ok) return now.password;
    throw WRONG();
  }

  const endAllSessions = (userId: string) => void db.prepare("DELETE FROM auth_sessions WHERE user = ?").run(userId);
  // After a deletion or a new password: empty the WAL into the file, so old rows don't linger beside it.
  const flush = () => db.exec("PRAGMA wal_checkpoint(TRUNCATE);");

  let swept = 0;
  /** Expired and idle sessions, cleared a batch at a time, at most every ten seconds. */
  const sweep = (now: number) => {
    if (now - swept < 10_000) return;
    swept = now;
    db.prepare(
      "DELETE FROM auth_sessions WHERE token IN (SELECT token FROM auth_sessions WHERE expires <= ? UNION SELECT token FROM auth_sessions WHERE seen <= ? LIMIT 2000)",
    ).run(now, now - IDLE_DAYS * DAY_MS);
  };

  return {
    async signUp(given, password, from) {
      checkHashingFree();
      fromWhere(from);
      const email = cleanEmail(given);
      if (!email) throw new AuthError("invalid-email", "Please give your email address.");
      checkNewPassword(password, email);
      if (userRow("email", email)) throw TAKEN();
      const user = { id: randomUUID(), email };
      const hashed = await hashPassword(password);
      try {
        db.prepare("INSERT INTO auth_users (id, email, password, created) VALUES (?, ?, ?, ?)").run(user.id, email, hashed, Date.now());
      } catch (error) {
        // Two sign-ups for one email at once: the second finds it taken. Anything else is a real failure.
        if (userRow("email", email)) throw TAKEN();
        throw error;
      }
      checked.set(user, hashed);
      return user;
    },

    async signIn(given, password, from) {
      const email = cleanEmail(given) ?? "";
      const row = email ? userRow("email", email) : undefined;
      const hash = await verify(row, email || "invalid", password, from);
      const user = { id: row!.id, email: row!.email };
      checked.set(user, hash);
      return user;
    },

    startSession(user) {
      const token = randomBytes(32).toString("base64url");
      const now = Date.now();
      sweep(now);
      const hash = checked.get(user);
      if (hash === undefined) throw new Error("startSession needs a user just returned by signIn, signUp, or changePassword, and starts one session for it.");
      checked.delete(user);
      // Only while the account exists and still has the password that was checked.
      const started = db
        .prepare("INSERT INTO auth_sessions (token, user, expires, seen) SELECT ?, id, ?, ? FROM auth_users WHERE id = ? AND password = ?")
        .run(tokenHash(token), now + SESSION_DAYS * DAY_MS, now, user.id, hash);
      if (started.changes === 0) throw WRONG();
      db.prepare(
        `DELETE FROM auth_sessions WHERE user = ? AND token NOT IN (SELECT token FROM auth_sessions WHERE user = ? ORDER BY expires DESC LIMIT ${MOST_SESSIONS})`,
      ).run(user.id, user.id);
      return token;
    },

    userOf(token) {
      if (typeof token !== "string" || !token || token.length > 100) return null;
      const now = Date.now();
      sweep(now);
      const hashed = tokenHash(token);
      const row = db
        .prepare("SELECT u.id AS id, u.email AS email, s.seen AS seen FROM auth_sessions s JOIN auth_users u ON u.id = s.user WHERE s.token = ? AND s.expires > ? AND s.seen > ?")
        .get(hashed, now, now - IDLE_DAYS * DAY_MS) as (User & { seen: number }) | undefined;
      if (!row) return null;
      if (now - row.seen > SEEN_EVERY_MS) db.prepare("UPDATE auth_sessions SET seen = ? WHERE token = ?").run(now, hashed);
      return { id: row.id, email: row.email };
    },

    endSession(token) {
      if (typeof token === "string" && token) db.prepare("DELETE FROM auth_sessions WHERE token = ?").run(tokenHash(token));
    },

    endAllSessions,

    async changePassword(userId, current, next, from) {
      const row = userRow("id", userId);
      if (!row) throw WRONG();
      const hash = await verify(row, row.email, current, from, true);
      checkNewPassword(next, row.email);
      const fresh = await hashPassword(next);
      const done = db.prepare("UPDATE auth_users SET password = ? WHERE id = ? AND password = ?").run(fresh, userId, hash);
      if (done.changes === 0) throw WRONG();
      endAllSessions(userId);
      flush();
      const user = { id: row.id, email: row.email };
      checked.set(user, fresh);
      return user;
    },

    async deleteAccount(userId, password, from) {
      const row = userRow("id", userId);
      if (!row) throw WRONG();
      const hash = await verify(row, row.email, password, from, true);
      const done = db.prepare("DELETE FROM auth_users WHERE id = ? AND password = ?").run(userId, hash);
      if (done.changes === 0) throw WRONG();
      flush();
    },
  };
}
