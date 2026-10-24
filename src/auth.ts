// Accounts and sessions. An account is an email and a password; signing in
// starts a session, whose token goes in a cookie (cookies.ts). The database
// keeps a hash of each token, never the token itself, and a slow hash of each
// password, never the password.
//
// An account is made by a link sent to its email: whoever opens it chooses the
// password, so only the person who reads that inbox can. The same link, sent to
// an email that has an account, chooses a new password; and a sign-in link
// signs in without one. Links are single-use and short-lived, and kept only as
// hashes.
//
// It keeps its tables (auth_users, auth_sessions, auth_links, auth_limits) in a
// node:sqlite database you give it, which may be your app's own, and may be
// shared by several processes.

import { createHash, randomBytes, randomUUID } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import { cleanEmail } from "./emails.ts";
import { AuthError } from "./errors.ts";
import { databaseLimits, type Limit, settingUp } from "./limits.ts";
import { checkHashingFree, checkNewPassword, checkPassword, hashPassword, LONGEST_TYPED, unmatchableHash } from "./passwords.ts";
import { readAtMost } from "./streams.ts";
import { DAY, HOUR, MINUTE } from "./time.ts";

export type User = { id: string; email: string };

/** Something that happened to an account, for the app to keep: never a password, token, or email. `from` is addressKey's. */
export type AuthEvent = {
  type:
    | "signed-in"
    | "sign-in-failed"
    | "password-check-failed"
    | "paused"
    | "account-made"
    | "password-changed"
    | "email-changed"
    | "email-change-undone"
    | "signed-out"
    | "signed-out-everywhere"
    | "session-ended"
    | "account-deleted";
  at: number;
  userId?: string;
  from?: string;
  /** For "signed-in" (a session started): after the password was checked, or an emailed link used. */
  by?: "password" | "link";
};
// "sign-in-failed": a wrong email or password; "password-check-failed": a wrong password from the account's own
// session (changing the password or deleting the account); "paused": a try refused by a limit, on the account or
// on where it came from.

export type AuthOptions = {
  /**
   * Told of each event, after the answer has gone (so how long it takes shows nothing, and a failure is
   * logged, not passed on). For a record of who did what, and when.
   */
  onEvent?(event: AuthEvent): void;
  /**
   * Checks new passwords against a breached-password set, without ever seeing them: given the first 5
   * characters of a password's SHA-1 (uppercase hex), gives what Have I Been Pwned's range API does for them
   * (lines of "SUFFIX:COUNT"), as text or as the fetch Response itself, such as
   * `(prefix, { signal }) => fetch(\`https://api.pwnedpasswords.com/range/${prefix}\`, { signal })`.
   * `signal` aborts after 5 seconds. A password found there is refused; if the check fails (an error, an
   * answer that isn't OK, or no answer in 5 seconds), the password is allowed and that's logged, so a
   * service that's down can't stop anyone choosing one.
   */
  breachedRange?(prefix: string, options: { signal: AbortSignal }): Promise<string | Response> | string | Response;
};

/** One of an account's sessions, as its owner sees it: `id` names it (it can't be used to sign in), and `current` is the one asking. */
export type Session = { id: string; started: number; lastUsed: number; current: boolean };

/** Everything kept about an account, for its owner (as UK GDPR asks): nothing in it can be used to sign in. */
export type AccountData = {
  email: string;
  created: number;
  /** Kept only as a slow hash, which isn't given. */
  password: "set";
  sessions: { started: number; lastUsed: number }[];
  /** Emailed links not yet used: what each does, where it went, and when it runs out. */
  links: { kind: LinkKind; email: string; expires: number }[];
};

/** A session lasts this long from signing in, however much it's used. */
export const SESSION_DAYS = 30;
/** And ends sooner if it isn't used for this long. */
export const IDLE_DAYS = 7;
/** How often a session's last use is written down (not on every request). */
const SEEN_EVERY_MS = HOUR;
/** Sessions one account can have at once: beyond this, the oldest ends. */
const MOST_SESSIONS = 50;
/** How long a link to choose a password lasts. */
export const PASSWORD_LINK_MINUTES = 60;
/** How long a sign-in link lasts. */
export const SIGN_IN_LINK_MINUTES = 15;

/**
 * What an emailed link does: choose a password (making the account, if there isn't one), sign in, move an
 * account to a new email, or undo a move (sent to the address it moved from).
 */
export type LinkKind = "password" | "sign-in" | "email" | "undo";
/** How long the address an account moved from can undo the move. */
export const UNDO_DAYS = 7;
/** How long a link to move an account to a new email lasts. */
export const EMAIL_LINK_MINUTES = 60;

/**
 * An email to send. `token` goes in the link, and only `to` should get it; for a
 * sign-in link to an email with no account there's none, and the email says so
 * instead, so an email goes either way. `account` chooses the email's words, and
 * must never change what the person asking is told. Not worth sending after `expires`.
 */
export type Link = { kind: LinkKind; to: string; token: string | null; account: boolean; expires: number };

export type Auth = {
  /**
   * An email to send to `email`, or null if none should be: at most 3 of each kind
   * to one address in 15 minutes, and the rest quietly aren't sent, so nobody can
   * flood an inbox; every link sent in those 15 minutes still works, so nobody can
   * stop its owner getting one either. An email goes whether or not there's an
   * account (for a sign-in link to an email with none, one saying so), so neither
   * the answer nor the work after it shows which. At most 5 asked for from one
   * address in 15 minutes, and 20 from one IPv6 /48. `from` is who's asking
   * (addressKey in limits.ts).
   */
  requestLink(kind: "password" | "sign-in", email: string, from: string): Link | null;
  /** Which email a link is for, and its kind, without using it: for the page it opens to show, so nobody is signed in to someone else's account unawares. */
  lookUpLink(token: string, from: string): { kind: LinkKind; email: string };
  /** The account, given a password link's token and the password chosen: made (`made`), or its password replaced (every session ending). */
  usePasswordLink(token: string, password: string, from: string): Promise<User & { made: boolean }>;
  /** The account a sign-in link's token is for. */
  useSignInLink(token: string, from: string): User;
  /**
   * A link to email to `email`, to move the signed-in user's account to it, given the
   * account's password; or null if none should be sent (3 to one address in 15
   * minutes, as for other links). If the address already has an account, the email
   * says so instead (`token` null): the same answer and work either way.
   */
  requestEmailChange(userId: string, password: string, email: string, from: string): Promise<Link | null>;
  /**
   * Moves the account to the email an email link was sent to, ending every session: only for `userId`, the
   * account signed in where the link is opened (the one it moves), so a link sent to someone else does nothing.
   * `previous` is the email it had; `undo`, a token for a link to it that undoes the move, for UNDO_DAYS.
   */
  useEmailLink(token: string, userId: string, from: string): User & { previous: string; undo: string };
  /**
   * Undoes a move, from the address it moved from: the account has that email again, every session ends, and
   * its password stops working (whoever moved it may know it). `reset` is a password link to send there, made
   * here so no limit can stop it. Every later move's undo link ends; an earlier one stays, so a thief's own
   * undo can't cancel the owner's.
   */
  useUndoLink(token: string, from: string): User & { reset: Link };
  /** The account, if the password is right. A wrong email and a wrong password get the same answer. */
  signIn(email: string, password: string, from: string): Promise<User>;
  /**
   * A new session for a user just returned by signIn, a link, or changePassword: the
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
  /**
   * The user's sessions, the most recently used first (`lastUsed` is written down at most hourly). `token`: the
   * session asking, marked `current`.
   */
  sessionsOf(userId: string, token: string): Session[];
  /** Ends one of the user's sessions, by its `id`; false if it has none of that id. */
  endSessionOf(userId: string, id: string): boolean;
  /** Everything kept about the user's account, or null if there's no such account. */
  dataOf(userId: string): AccountData | null;
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
  CREATE TABLE IF NOT EXISTS auth_links (
    token TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    email TEXT NOT NULL,
    expires INTEGER NOT NULL,
    user TEXT REFERENCES auth_users(id) ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS auth_links_email ON auth_links (email);
  CREATE INDEX IF NOT EXISTS auth_links_user ON auth_links (user);
  CREATE INDEX IF NOT EXISTS auth_links_expires ON auth_links (expires);
`;

/** A new token: 256 random bits, base64url (43 characters). */
const newToken = () => randomBytes(32).toString("base64url");
const tokenHash = (token: string) => createHash("sha256").update(token).digest("base64url");
/** An IPv6 /64 (as addressKey gives it)'s /48: the block a single site or customer is often given. */
const blockOf = (from: string) => (from.endsWith("::/64") ? `${from.split(":").slice(0, 3).join(":")}::/48` : null);
/** When a session started, from when it runs out. */
const startedAt = (expires: number) => expires - SESSION_DAYS * DAY;
/** A session's name for its owner: a hash of its stored hash, so it can't be used to sign in. */
/** The longest token a cookie can carry: longer is no token of ours (they're 43 characters). */
export const LONGEST_TOKEN = 100;
const SESSION_ID_LENGTH = 22;
const sessionId = (stored: string) => createHash("sha256").update(`session\0${stored}`).digest("base64url").slice(0, SESSION_ID_LENGTH);
/** A session that hasn't run out or gone unused, as SQL over auth_sessions, with `live(now)` for its two values. */
const LIVE = "expires > ? AND seen > ?";
const live = (now: number) => [now, now - IDLE_DAYS * DAY] as const;
/** What addressKey gives for a real address: IPv4, or an IPv6 /64. */
const ADDRESS = /^(?:\d{1,3}\.){3}\d{1,3}$|^[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){3}::\/64$/;
const WRONG = () => new AuthError("wrong-credentials", "That email and password don't match.");
const EXPIRED = () => new AuthError("invalid-link", "That link has expired or been used. Please ask for a new one.");
/** A link token as newToken makes it. */
const LINK_TOKEN = /^[A-Za-z0-9_-]{43}$/;
/** The address as it's kept, or "invalid-email". */
const emailOrRefuse = (given: string) => {
  const email = cleanEmail(given);
  if (!email) throw new AuthError("invalid-email", "Please give your email address.");
  return email;
};
/** When a new link of `kind` runs out. */
const LIFETIME: Record<LinkKind, number> = {
  password: PASSWORD_LINK_MINUTES * MINUTE,
  "sign-in": SIGN_IN_LINK_MINUTES * MINUTE,
  email: EMAIL_LINK_MINUTES * MINUTE,
  undo: UNDO_DAYS * DAY,
};
const linkExpires = (kind: LinkKind) => Date.now() + LIFETIME[kind];

/** Accounts and sessions, kept in `db` (its tables are made if they aren't there). */
export function createAuth(db: DatabaseSync, options: AuthOptions = {}): Auth {
  const { onEvent, breachedRange } = options;
  if (onEvent !== undefined && typeof onEvent !== "function") throw new Error("onEvent must be a function.");
  if (breachedRange !== undefined && typeof breachedRange !== "function") throw new Error("breachedRange must be a function.");
  /** An event, told after the answer has gone: the same whatever it is, so it can't show anything by its timing. */
  const emit = (type: AuthEvent["type"], details: Omit<AuthEvent, "type" | "at"> = {}) => {
    if (!onEvent) return;
    const event: AuthEvent = { type, at: Date.now(), ...details };
    setImmediate(() => {
      // Whether it throws or (being async) rejects: logged, never passed on.
      Promise.resolve()
        .then(() => onEvent(event))
        .catch((error: unknown) => console.error("modest-auth: onEvent failed:", error instanceof Error ? error.name : typeof error));
    });
  };
  /**
   * Refuses a new password found in the breached-password set, if the app gave one to check against: as it's
   * kept (normalised, NFKC), and as typed if that differs, so a breached password typed in another Unicode form
   * isn't let through.
   */
  const checkBreached = async (password: string) => {
    if (!breachedRange) return;
    for (const form of new Set([password.normalize("NFKC"), password])) await checkBreachedForm(form, breachedRange);
  };
  const checkBreachedForm = async (password: string, breachedRange: NonNullable<AuthOptions["breachedRange"]>) => {
    const sha1 = createHash("sha1").update(password).digest("hex").toUpperCase();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const stop = new AbortController();
    try {
      const late = new Promise<never>((_, fail) => {
        timer = setTimeout(() => {
          stop.abort();
          fail(new Error("took over 5 seconds"));
        }, 5000);
      });
      /**
       * The range as text: given as text, or read from a Response (one that isn't OK is a failure), at most 1MB
       * (a padded range is about 40KB), and let go of when 5 seconds pass, so it can't keep sending.
       */
      const fetchRange = async () => {
        const given = await breachedRange(sha1.slice(0, 5), { signal: stop.signal });
        if (typeof given === "string") return given;
        if (!(given instanceof Response)) throw new Error("breachedRange gave neither text nor a Response: give the fetch Response itself, or its text");
        if (!given.ok) {
          await given.body?.cancel().catch(() => {});
          throw new Error(`the range answered ${given.status}`);
        }
        const bytes = await readAtMost(given.body, 1_000_000, stop.signal);
        if (bytes === "too-large") throw new Error("the range was over 1MB");
        return bytes.toString("utf8");
      };
      const range = await Promise.race([fetchRange(), late]);
      for (const line of range.split("\n")) {
        const [suffix, count] = line.trim().split(":");
        // Padding (which the API can add) has a count of 0.
        if (suffix?.toUpperCase() === sha1.slice(5) && Number(count) > 0) {
          throw new AuthError("breached-password", "That password has appeared in a data breach, so it's easy to guess. Please choose another.");
        }
      }
    } catch (error) {
      if (error instanceof AuthError) throw error;
      console.error("modest-auth: the breached-password check failed, so the password was allowed:", error instanceof Error ? error.message : typeof error);
    } finally {
      clearTimeout(timer);
    }
  };
  // Several processes can share the file: they wait up to two seconds for another
  // that's writing (set first, so even switching to WAL waits), and WAL lets them
  // read while one writes. Foreign keys take sessions with their account. Deleted
  // rows are overwritten in the file (and the WAL is emptied after a deletion).
  db.exec("PRAGMA busy_timeout = 2000;");
  settingUp(() => db.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA secure_delete = ON;"));
  settingUp(() => db.exec(SCHEMA));
  const limit = databaseLimits(db);

  // Each counted before a password is hashed, so tries sent all at once count too.
  // 20 sign-ins, links, or password checks from one address in 15 minutes.
  const perAddress = limit("address", 20, 15 * MINUTE);
  // 10 tries at one account from one address in 15 minutes: a stranger elsewhere can't lock its owner out.
  const perAccountAndAddress = limit("account+address", 10, 15 * MINUTE);
  // 100 tries at one account an hour, from anywhere: guesses spread over many addresses are slowed too.
  const perAccount = limit("account", 100, HOUR);
  // 200 from one IPv6 /48 in 15 minutes: the block a single site or customer is often given, so its 65,536 /64s count together.
  const perBlock = limit("block", 200, 15 * MINUTE);
  // 10 password checks an hour by the account's own signed-in sessions (changing the password, deleting the
  // account): strangers can't use these up, and a stolen session can't guess the password.
  const perOwner = limit("owner", 10, HOUR);
  // 3 links of each kind emailed to one address in 15 minutes: no more, but quietly, so the answer is the same
  // either way. Each exact address counts alone: another spelling that reaches the same inbox can't use up its
  // allowance (its links go to that spelling, and its account), and the limits on senders bound the rest.
  const perInbox = limit("inbox", 3, 15 * MINUTE);
  // 5 links asked for from one address, and 20 from one IPv6 /48, in 15 minutes: so nobody can use sign-up to email
  // strangers in bulk.
  const linksFrom = limit("links", 5, 15 * MINUTE);
  const linksFromBlock = limit("links-block", 20, 15 * MINUTE);
  /** Counts a try from an address with `each`, and from its IPv6 /48 (if it has one) with `inBlock`. */
  const andBlock = (each: Limit, inBlock: Limit) => (from: string) => {
    each(from);
    const block = blockOf(from);
    if (block) inBlock(block);
  };
  const countFrom = andBlock(perAddress, perBlock);
  /** A link asked for (from has been checked by fromWhere or verify). */
  const countLinkFrom = andBlock(linksFrom, linksFromBlock);
  const fromWhere = (from: string) => {
    // Without an address, everyone would share one allowance: that's a mistake in the calling code.
    if (typeof from !== "string" || !ADDRESS.test(from)) throw new Error("from must be where the request came from, as addressKey gives it.");
    countFrom(from);
  };
  /** Counts a link of `kind` to `email`; false, quietly, past the limit, so the answer is the same either way. */
  const inboxHasRoom = (kind: LinkKind, email: string) => {
    try {
      perInbox(`${kind}\0${email}`);
      return true;
    } catch (error) {
      if (error instanceof AuthError) return false;
      throw error;
    }
  };

  // Checked against when there's no such account, so a wrong email takes as long as a wrong password:
  // a hash of the current form and cost that nothing matches (made from random bytes, so no hashing at start-up).
  const nobody = unmatchableHash();

  // The password hash each signed-in user was checked against: a session starts only while it's still theirs.
  // And how, and from where, for the event when a session starts.
  const checked = new WeakMap<User, { hash: string; by: "password" | "link"; from: string }>();

  /** A user just checked (by password or link), ready for startSession: once, while the account still has `hash`. */
  const handOver = <U extends User>(user: U, hash: string, by: "password" | "link", from: string): U => {
    checked.set(user, { hash, by, from });
    return user;
  };
  /** After a new password: every session ends, and every link of the account and to its address. */
  const afterNewPassword = (userId: string, email: string) => {
    endAllSessions(userId);
    endLinks(email, userId);
    flush();
  };

  const userRow = (where: "email" | "id", value: string) =>
    db.prepare(`SELECT id, email, password FROM auth_users WHERE ${where} = ?`).get(value) as { id: string; email: string; password: string } | undefined;
  /** The signed-in user's account and its password's hash, after checking the password they gave (as the owner). */
  const verifyOwner = async (userId: string, password: string, from: string) => {
    const row = userRow("id", userId);
    if (!row) throw WRONG();
    return { row, hash: await verify(row, row.email, password, from, true) };
  };

  /** check, telling of a wrong password or a pause (not of "busy": nobody was counted). */
  async function verify(row: { id: string; password: string } | undefined, key: string, password: string, from: string, owner = false): Promise<string> {
    try {
      return await check(row, key, password, from, owner);
    } catch (error) {
      if (error instanceof AuthError && error.code !== "busy") {
        const type = error.code === "too-many-tries" ? "paused" : owner ? "password-check-failed" : "sign-in-failed";
        emit(type, { ...(row ? { userId: row.id } : {}), from });
      }
      throw error;
    }
  }
  /**
   * The account's hash after checking its password (made again if at an older cost), limited as a
   * sign-in is. `owner`: the account's own signed-in session is asking, so the per-account pause,
   * which strangers can trigger, doesn't apply.
   */
  async function check(row: { id: string; password: string } | undefined, key: string, password: string, from: string, owner: boolean): Promise<string> {
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

  /** How many sessions ended. */
  const endAllSessions = (userId: string) => db.prepare("DELETE FROM auth_sessions WHERE user = ?").run(userId).changes;
  /**
   * Every link to an email ends, and every link to move the account `userId` to another: once one is used, or
   * the password or email changes, or the account goes.
   */
  // Not an undo link: that stays with the address a move took the account from, whatever is done to the account.
  const endLinks = (email: string, userId = "") =>
    void db.prepare("DELETE FROM auth_links WHERE (email = ? OR user = ?) AND kind != 'undo'").run(email, userId);
  type LinkRow = { kind: LinkKind; email: string; user: string | null; expires: number };
  /**
   * A live link of one of `kinds` (never "none": those are stored only to do the same work), by its token: looked
   * at (`take` false) or used, once only (`take` true). "invalid-link" if there's none.
   */
  const findLink = (token: string, kinds: LinkKind[], take: boolean): LinkRow => {
    if (typeof token !== "string" || !LINK_TOKEN.test(token)) throw EXPIRED();
    const which = `token = ? AND kind IN (${kinds.map(() => "?").join(", ")}) AND expires > ?`;
    const sql = take
      ? `DELETE FROM auth_links WHERE ${which} RETURNING kind, email, user, expires`
      : `SELECT kind, email, user, expires FROM auth_links WHERE ${which}`;
    const row = db.prepare(sql).get(tokenHash(token), ...kinds, Date.now()) as LinkRow | undefined;
    if (!row) throw EXPIRED();
    return row;
  };
  const takeLink = (token: string, kind: LinkKind) => findLink(token, [kind], true);
  /** The account a link moves, which must still be there. */
  const accountOf = (link: LinkRow) => {
    const row = link.user ? userRow("id", link.user) : undefined;
    if (!row) throw EXPIRED();
    return row;
  };
  /** Gives the account `userId` the address `email` (and `password`, if given); "invalid-link" if another account has it. */
  const moveTo = (userId: string, email: string, password?: string) => {
    const holder = userRow("email", email);
    if (holder && holder.id !== userId) throw EXPIRED();
    try {
      if (password === undefined) db.prepare("UPDATE auth_users SET email = ? WHERE id = ?").run(email, userId);
      else db.prepare("UPDATE auth_users SET email = ?, password = ? WHERE id = ?").run(email, password, userId);
    } catch (error) {
      // Taken by another process sharing the database, between the check and the change.
      if (userRow("email", email)) throw EXPIRED();
      throw error;
    }
  };
  /**
   * Moves an account back to the address a move took it from (an undo, ending at `undoExpires`), with `password`:
   * every session ends, and every link of the account and of both addresses, but not an earlier move's undo link.
   */
  const moveBack = (userId: string, current: string, email: string, password: string, undoExpires: number) => {
    moveTo(userId, email, password);
    endAllSessions(userId);
    // Undo links stay unless they're this account's own, from a later move: so the earliest owner always wins.
    db.prepare("DELETE FROM auth_links WHERE (user = ? OR email IN (?, ?)) AND NOT (kind = 'undo' AND (expires < ? OR user != ?))").run(
      userId,
      current,
      email,
      undoExpires,
      userId,
    );
  };
  /**
   * The account `email` can still take back by an undo (its oldest live one), if only one can: whoever reads
   * that inbox moved it away. Several accounts moved away from one address is left to their undo links.
   */
  const undoTo = (email: string) => {
    const rows = db
      .prepare(
        "SELECT l.user AS user, l.expires AS expires, u.email AS current FROM auth_links l JOIN auth_users u ON u.id = l.user WHERE l.kind = 'undo' AND l.email = ? AND l.expires > ? ORDER BY l.expires",
      )
      .all(email, Date.now()) as { user: string; expires: number; current: string }[];
    return new Set(rows.map((row) => row.user)).size === 1 ? rows[0] : undefined;
  };
  /** A new link of `kind` to `email` (for the account `userId`, if it moves one): its token. */
  const makeLink = (kind: LinkKind | "none", email: string, expires: number, userId: string | null = null) => {
    const token = newToken();
    db.prepare("INSERT INTO auth_links (token, kind, email, expires, user) VALUES (?, ?, ?, ?, ?)").run(tokenHash(token), kind, email, expires, userId);
    return token;
  };
  // Whether the WAL may still hold rows that were removed (it couldn't be emptied last time).
  let unflushed = false;
  /**
   * Empties the WAL into the file, so removed rows don't linger beside it: after a deletion or a new password
   * (waiting, as any write does, for another process), and after clearing old links on an everyday request
   * (`wait` false: not waiting at all). Best effort, never failing the request: if another process is reading,
   * or the app is part-way through its own transaction or query on this connection (it's the app's connection
   * too), it's tried again at every clearing until it's done. The app's own busy_timeout is left as it was.
   */
  const flush = (wait = true) => {
    unflushed = true;
    if (db.isTransaction) return;
    const timeout = (db.prepare("PRAGMA busy_timeout").get() as { timeout: number }).timeout;
    try {
      if (!wait) db.exec("PRAGMA busy_timeout = 0;");
      unflushed = (db.prepare("PRAGMA wal_checkpoint(TRUNCATE)").get() as { busy: number }).busy !== 0;
    } catch {
      // Left for the next clearing.
    } finally {
      if (!wait) db.exec(`PRAGMA busy_timeout = ${timeout};`);
    }
  };

  let swept = 0;
  /** Expired and idle sessions, cleared a batch at a time, at most every ten seconds. */
  const sweep = (now: number) => {
    if (now - swept < 10_000) return;
    swept = now;
    db.prepare(
      "DELETE FROM auth_sessions WHERE token IN (SELECT token FROM auth_sessions WHERE expires <= ? UNION SELECT token FROM auth_sessions WHERE seen <= ? LIMIT 2000)",
    ).run(now, now - IDLE_DAYS * DAY);
    // Links hold the emails of people who may have no account: once they've gone, not left in the WAL either.
    const cleared = db.prepare("DELETE FROM auth_links WHERE token IN (SELECT token FROM auth_links WHERE expires <= ? LIMIT 2000)").run(now).changes;
    if (cleared || unflushed) flush(false);
  };

  return {
    requestLink(kind, given, from) {
      if (kind !== "password" && kind !== "sign-in") throw new Error('kind must be "password" or "sign-in" (an email link comes from requestEmailChange).');
      fromWhere(from);
      countLinkFrom(from);
      const email = emailOrRefuse(given);
      sweep(Date.now());
      // An account here, or one this address can take back (so a password link's email says what it will do).
      // (Both looked up either way: the same work whether or not there's an account.)
      const here = !!userRow("email", email);
      const takeBack = kind === "password" && !!undoTo(email);
      const account = here || takeBack;
      // Counted, a link stored, and an email sent, whether or not there's an account: the same work either way.
      if (!inboxHasRoom(kind, email)) return null;
      const expires = linkExpires(kind);
      // A sign-in link with no account to sign in to is stored as one that does nothing (for the same work), and never sent.
      const usable = kind === "password" || account;
      const token = makeLink(usable ? kind : "none", email, expires);
      return { kind, to: email, token: usable ? token : null, account, expires };
    },

    lookUpLink(token, from) {
      fromWhere(from);
      const { kind, email } = findLink(token, ["password", "sign-in", "email", "undo"], false);
      return { kind, email };
    },

    async usePasswordLink(token, password, from) {
      checkHashingFree();
      fromWhere(from);
      // Looked at first, but only used once the password will do: a password refused doesn't use up the link.
      const link = findLink(token, ["password"], false);
      checkNewPassword(password, link.email);
      await checkBreached(password);
      const hashed = await hashPassword(password);
      const { email } = takeLink(token, "password");
      // An account moved away from this address that it can still take back: back it comes, with this password.
      const back = !userRow("email", email) ? undoTo(email) : undefined;
      if (back) {
        moveBack(back.user, back.current, email, hashed, back.expires);
        flush();
        emit("email-change-undone", { userId: back.user, from });
        return handOver({ id: back.user, email, made: false }, hashed, "link", from);
      }
      const made = !userRow("email", email);
      // Made, or (if there's an account, or one was made meanwhile) its password replaced.
      const { id } = db
        .prepare(
          "INSERT INTO auth_users (id, email, password, created) VALUES (?, ?, ?, ?) ON CONFLICT (email) DO UPDATE SET password = excluded.password RETURNING id",
        )
        .get(randomUUID(), email, hashed, Date.now()) as { id: string };
      afterNewPassword(id, email);
      emit(made ? "account-made" : "password-changed", { userId: id, from });
      return handOver({ id, email, made }, hashed, "link", from);
    },

    useSignInLink(token, from) {
      fromWhere(from);
      const { email } = takeLink(token, "sign-in");
      const row = userRow("email", email);
      if (!row) throw EXPIRED();
      endLinks(email);
      return handOver({ id: row.id, email: row.email }, row.password, "link", from);
    },

    async signIn(given, password, from) {
      const email = cleanEmail(given) ?? "";
      const row = email ? userRow("email", email) : undefined;
      const hash = await verify(row, email || "invalid", password, from);
      // (verify throws without an account: this only tells the type checker so.)
      if (!row) throw WRONG();
      return handOver({ id: row.id, email: row.email }, hash, "password", from);
    },

    startSession(user) {
      const token = newToken();
      const now = Date.now();
      sweep(now);
      const how = checked.get(user);
      if (how === undefined) throw new Error("startSession needs a user just returned by signIn, a link, or changePassword, and starts one session for it.");
      checked.delete(user);
      const { hash } = how;
      // Only while the account exists and still has the password and email that were checked.
      const started = db
        .prepare("INSERT INTO auth_sessions (token, user, expires, seen) SELECT ?, id, ?, ? FROM auth_users WHERE id = ? AND password = ? AND email = ?")
        .run(tokenHash(token), now + SESSION_DAYS * DAY, now, user.id, hash, user.email);
      if (started.changes === 0) throw WRONG();
      emit("signed-in", { userId: user.id, from: how.from, by: how.by });
      db.prepare(
        `DELETE FROM auth_sessions WHERE user = ? AND token NOT IN (SELECT token FROM auth_sessions WHERE user = ? ORDER BY expires DESC LIMIT ${MOST_SESSIONS})`,
      ).run(user.id, user.id);
      return token;
    },

    userOf(token) {
      if (typeof token !== "string" || !token || token.length > LONGEST_TOKEN) return null;
      const now = Date.now();
      sweep(now);
      const hashed = tokenHash(token);
      const row = db
        .prepare(`SELECT u.id AS id, u.email AS email, s.seen AS seen FROM auth_sessions s JOIN auth_users u ON u.id = s.user WHERE s.token = ? AND ${LIVE}`)
        .get(hashed, ...live(now)) as (User & { seen: number }) | undefined;
      if (!row) return null;
      if (now - row.seen > SEEN_EVERY_MS) db.prepare("UPDATE auth_sessions SET seen = ? WHERE token = ?").run(now, hashed);
      return { id: row.id, email: row.email };
    },

    endSession(token) {
      if (typeof token !== "string" || !token) return;
      const ended = db.prepare("DELETE FROM auth_sessions WHERE token = ? RETURNING user").get(tokenHash(token)) as { user: string } | undefined;
      if (ended) emit("signed-out", { userId: ended.user });
    },

    endAllSessions(userId) {
      if (endAllSessions(userId)) emit("signed-out-everywhere", { userId });
    },

    sessionsOf(userId, token) {
      const now = Date.now();
      const mine = typeof token === "string" && token ? tokenHash(token) : "";
      const rows = db.prepare(`SELECT token, expires, seen FROM auth_sessions WHERE user = ? AND ${LIVE} ORDER BY seen DESC`).all(userId, ...live(now)) as {
        token: string;
        expires: number;
        seen: number;
      }[];
      return rows.map((row) => ({ id: sessionId(row.token), started: startedAt(row.expires), lastUsed: row.seen, current: row.token === mine }));
    },

    endSessionOf(userId, id) {
      if (typeof id !== "string" || id.length !== SESSION_ID_LENGTH || !/^[\w-]+$/.test(id)) return false;
      const rows = db.prepare("SELECT token FROM auth_sessions WHERE user = ?").all(userId) as { token: string }[];
      const found = rows.find((row) => sessionId(row.token) === id);
      const ended = !!found && db.prepare("DELETE FROM auth_sessions WHERE token = ? AND user = ?").run(found.token, userId).changes > 0;
      if (ended) emit("session-ended", { userId });
      return ended;
    },

    dataOf(userId) {
      const now = Date.now();
      const row = db.prepare("SELECT email, created FROM auth_users WHERE id = ?").get(userId) as { email: string; created: number } | undefined;
      if (!row) return null;
      const sessions = db.prepare(`SELECT expires, seen FROM auth_sessions WHERE user = ? AND ${LIVE} ORDER BY seen DESC`).all(userId, ...live(now)) as {
        expires: number;
        seen: number;
      }[];
      // Its own links, and those to its address, that do something: not the ones stored only to do the same work.
      const links = db
        .prepare("SELECT kind, email, expires FROM auth_links WHERE (user = ? OR email = ?) AND kind != 'none' AND expires > ? ORDER BY expires")
        .all(userId, row.email, now) as { kind: LinkKind; email: string; expires: number }[];
      return {
        email: row.email,
        created: row.created,
        password: "set",
        sessions: sessions.map((session) => ({ started: startedAt(session.expires), lastUsed: session.seen })),
        links: links.map((link) => ({ kind: link.kind, email: link.email, expires: link.expires })),
      };
    },

    async changePassword(userId, current, next, from) {
      const { row, hash } = await verifyOwner(userId, current, from);
      checkNewPassword(next, row.email);
      await checkBreached(next);
      const fresh = await hashPassword(next);
      // The email as it is now (it may have moved while the password was checked).
      const done = db.prepare("UPDATE auth_users SET password = ? WHERE id = ? AND password = ? RETURNING email").get(fresh, userId, hash) as
        | { email: string }
        | undefined;
      if (!done) throw WRONG();
      afterNewPassword(userId, done.email);
      emit("password-changed", { userId, from });
      return handOver({ id: row.id, email: done.email }, fresh, "password", from);
    },

    async requestEmailChange(userId, password, given, from) {
      const { row, hash } = await verifyOwner(userId, password, from);
      countLinkFrom(from);
      const email = emailOrRefuse(given);
      if (email === row.email) throw new AuthError("invalid-email", "That's the account's email already.");
      const taken = !!userRow("email", email);
      if (!inboxHasRoom("email", email)) return null;
      const token = newToken();
      const expires = linkExpires("email");
      // To an address with an account already, one that does nothing (for the same work), and an email saying so.
      // Only while the password just checked is still the account's: a reset meanwhile ends the request too.
      const stored = db
        .prepare("INSERT INTO auth_links (token, kind, email, expires, user) SELECT ?, ?, ?, ?, id FROM auth_users WHERE id = ? AND password = ?")
        .run(tokenHash(token), taken ? "none" : "email", email, expires, userId, hash);
      if (stored.changes === 0) throw WRONG();
      return { kind: "email", to: email, token: taken ? null : token, account: taken, expires };
    },

    useEmailLink(token, signedIn, from) {
      fromWhere(from);
      // Only by the account it moves, signed in where it's opened: checked before the link is used up.
      if (findLink(token, ["email"], false).user !== signedIn) throw EXPIRED();
      const link = takeLink(token, "email");
      const { email } = link;
      // Gone (or, in moveTo, the address taken meanwhile): nothing to move.
      const row = accountOf(link);
      moveTo(row.id, email);
      endAllSessions(row.id);
      endLinks(row.email, row.id);
      endLinks(email);
      // An undo link for the address it moved from (each move its own: using one ends only later ones).
      const undo = makeLink("undo", row.email, linkExpires("undo"), row.id);
      flush();
      emit("email-changed", { userId: row.id, from });
      return { id: row.id, email, previous: row.email, undo };
    },

    useUndoLink(token, from) {
      fromWhere(from);
      const link = takeLink(token, "undo");
      const { email, expires } = link;
      // Gone (or, in moveBack, the address since taken by another account): nothing to move back.
      const row = accountOf(link);
      // Its password made one that nothing matches: whoever moved it may know it.
      moveBack(row.id, row.email, email, unmatchableHash(), expires);
      const until = linkExpires("password");
      const reset: Link = { kind: "password", to: email, token: makeLink("password", email, until), account: true, expires: until };
      flush();
      emit("email-change-undone", { userId: row.id, from });
      return { id: row.id, email, reset };
    },

    async deleteAccount(userId, password, from) {
      const { row, hash } = await verifyOwner(userId, password, from);
      const done = db.prepare("DELETE FROM auth_users WHERE id = ? AND password = ?").run(userId, hash);
      if (done.changes === 0) throw WRONG();
      endLinks(row.email, userId);
      flush();
      emit("account-deleted", { userId, from });
    },
  };
}
