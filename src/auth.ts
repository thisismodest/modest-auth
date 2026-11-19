// Accounts and sessions. An account is an email, and the ways the site lets
// people sign in to it: an emailed link, and (if the site uses them) a
// password. Signing in starts a session, whose token goes in a cookie
// (cookies.ts). The database keeps a hash of each token, never the token
// itself, and a slow hash of each password, never the password.
//
// An account is made by a link sent to its email, so only the person who reads
// that inbox can make it: where the site uses passwords, whoever opens the link
// chooses one; where it doesn't, opening a sign-in link makes the account. Links
// are single-use and short-lived, and kept only as hashes.
//
// Every account has a stamp, replaced whenever how it's reached changes (a new
// password, a new email, an undone move). Anything checked before a change
// lands (a session about to start, a link about to be stored, an account about
// to go) goes ahead only while the stamp is still the one that was checked, so
// one rule covers every race between them.
//
// It keeps its tables (auth_users, auth_sessions, auth_links, auth_limits) in a
// node:sqlite database you give it, which may be your app's own, and may be
// shared by several processes.

import { createHash, randomBytes, randomUUID } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import { cleanEmail } from "./emails.ts";
import { AuthError } from "./errors.ts";
import { blockOf, databaseLimits, type Limit, settingUp } from "./limits.ts";
import { checkHashingFree, checkNewPassword, checkPassword, hashPassword, LONGEST_TYPED, unmatchableHash } from "./passwords.ts";
import { readAtMost } from "./streams.ts";
import { isPlainLine } from "./text.ts";
import { DAY, HOUR, MINUTE } from "./time.ts";
import { ALGORITHMS, checkAssertion, checkNewPasskey, type NewPasskey, type PasskeyAssertion, relyingParty } from "./webauthn.ts";

export type User = { id: string; email: string };

/** Where an account is reached, for its links and notices. Only email for now; a phone number could follow. */
export type Contact = { email: string };

/**
 * How people sign in day to day: by an emailed link, a password, a passkey, or any mix. Each works on its own.
 * Getting back in (a forgotten password, every passkey lost) isn't one of them: that's a link to the account's
 * email, whatever the site's methods, or only one the app makes (`recovery: "app"`).
 */
export type SignInMethod = "link" | "password" | "passkey";
const METHODS: readonly SignInMethod[] = ["link", "password", "passkey"];

/** Something that happened to an account, for the app to keep: never a password, token, or email. `from` is addressKey's. */
export type AuthEvent = {
  type:
    | "signed-in"
    | "sign-in-failed"
    | "paused"
    | "account-made"
    | "password-changed"
    | "email-changed"
    | "email-change-undone"
    | "signed-out"
    | "signed-out-everywhere"
    | "session-ended"
    | "passkey-added"
    | "passkey-removed"
    | "account-reset"
    | "recovery-link-made"
    | "account-deleted";
  at: number;
  userId?: string;
  from?: string;
  /** For "signed-in" (a session started): after the password was checked, an emailed link used, or a passkey's signature checked. */
  by?: SignInMethod;
};
// "sign-in-failed": a wrong email or password; "paused": a try refused by a limit, on the account or on where it
// came from.

export type AuthOptions = {
  /** How people sign in: any of "link", "password", and "passkey". Required, so nobody gets a way in the site didn't choose. */
  signInWith: readonly SignInMethod[];
  /**
   * How people get back in. By default, a link to the account's email: a link to choose a new password where the
   * site has passwords, else one that signs in once, to add a passkey. "app" only with `signInWith: ["passkey"]`:
   * no link to an existing account is ever sent at anyone's asking, so an inbox is never a way in, and only the
   * app's own code can make one (`recoveryLink`), for someone it has vouched for another way.
   */
  recovery?: "link" | "app";
  /**
   * Who may have an account, if not everyone: true to allow `contact`, anything else to refuse. Asked before a
   * link is sent, an account made, or a session started or used, so someone the app stops allowing is signed out
   * at their next request. It can only refuse: it never lets in anyone modest-auth wouldn't. Synchronous, and
   * quick (it's asked on every signed-in request). The answer to whoever's asking is the same either way, and an
   * address that's refused gets nothing. If it throws, that's a refusal, and logged.
   */
  allow?(contact: Contact): boolean;
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
  /** Whether it has one: kept only as a slow hash, which isn't given. */
  password: "set" | "none";
  sessions: { started: number; lastUsed: number }[];
  /** Emailed links not yet used: what each does, where it went, and when it runs out. */
  links: { kind: LinkKind; email: string; expires: number }[];
  /** Its passkeys, by name: their public keys aren't given (they sign nothing, but they're no use to anyone). */
  passkeys: { name: string; created: number; lastUsed: number | null }[];
};

/** One of an account's passkeys, as its owner sees it: `id` is the passkey's own (it can't sign anyone in). */
export type Passkey = { id: string; name: string; created: number; lastUsed: number | null };

/** What navigator.credentials.create needs to make a passkey, as JSON (PublicKeyCredential.parseCreationOptionsFromJSON takes it). */
export type PasskeyCreationOptions = {
  challenge: string;
  rp: { id: string; name: string };
  user: { id: string; name: string; displayName: string };
  pubKeyCredParams: { type: "public-key"; alg: number }[];
  timeout: number;
  excludeCredentials: { type: "public-key"; id: string }[];
  authenticatorSelection: { residentKey: "required"; requireResidentKey: true; userVerification: "required" };
  attestation: "none";
};
/** What navigator.credentials.get needs to sign in with a passkey, as JSON (PublicKeyCredential.parseRequestOptionsFromJSON takes it). */
export type PasskeyRequestOptions = { challenge: string; rpId: string; timeout: number; userVerification: "required"; allowCredentials: [] };

/** A session lasts this long from signing in, however much it's used. */
export const SESSION_DAYS = 30;
/** And ends sooner if it isn't used for this long. */
export const IDLE_DAYS = 7;
/** Changing the password or email, or deleting the account, needs a session started this recently: sign in again for it. */
export const RECENT_MINUTES = 10;
/** How often a session's last use is written down (not on every request). */
const SEEN_EVERY_MS = HOUR;
/** Sessions one account can have at once: beyond this, the oldest ends. */
const MOST_SESSIONS = 50;
/** How long a link to choose a password lasts. */
export const PASSWORD_LINK_MINUTES = 60;
/** How long a sign-in link lasts. */
export const SIGN_IN_LINK_MINUTES = 15;

/**
 * What an emailed link does: choose a password (making the account, if there isn't one), sign in (making the
 * account, where the site has no passwords), move an account to a new email, or undo a move (sent to the
 * address it moved from).
 */
export type LinkKind = "password" | "sign-in" | "email" | "undo";
/** How long the address an account moved from can undo the move. */
export const UNDO_DAYS = 7;
/** How long a link to move an account to a new email lasts. */
export const EMAIL_LINK_MINUTES = 60;
/** How long someone has to make or use a passkey once asked: the challenge lasts this long. */
export const PASSKEY_MINUTES = 5;
/** The longest name a passkey can be given. */
const LONGEST_PASSKEY_NAME = 60;
/**
 * A passkey's name, chosen by whoever adds it and shown in the owner's list of passkeys (never in an email): one plain
 * line of letters, numbers, spaces, and ' , ( ) - only (no full stop, so no web address), so it can't pass for a link
 * or markup wherever an app shows it.
 */
const isPasskeyName = (name: unknown): name is string => isPlainLine(name, LONGEST_PASSKEY_NAME) && /^[\p{L}\p{N} '’,()-]+$/u.test(name);

export type { NewPasskey, PasskeyAssertion };

/** Why a link asked for has nothing to open, for the message that says so instead. */
export type Refusal = "no-account" | "email-in-use" | "passkey-only";

/**
 * A link to send. `token` goes in it, and only `to` should get it. Null where there's nothing to open, and
 * `refused` says why: a sign-in link asked for an email with no account (where accounts are made by password
 * links), a move to an address that has an account, or a link into an account where only the app may make one; the
 * message says so instead, so one goes either way. `account` says whether there's an account there, and must
 * never change what the person asking is told. Not worth sending after `expires`.
 */
export type Link = { kind: LinkKind; to: string; account: boolean; expires: number } & (
  | { token: string; refused?: undefined }
  | { token: null; refused: Refusal }
);

export type Auth = {
  /** How people sign in here, as given. */
  readonly signInWith: readonly SignInMethod[];
  /** Whether sign-in links are sent here (`send-sign-in-link`): where "link" is a method, or there are no passwords (to make accounts, and to get back in). */
  readonly signInLinks: boolean;
  /**
   * A link into the account at `email`, for the app's own code to send to someone it has vouched for another way
   * (an admin, support): the way back in where `recovery` is "app". A link to choose a new password where the site
   * has passwords, else one that signs in once. Null if there's no such account, or `allow` refuses it. Never from
   * a route, and never to anyone the app hasn't checked: whoever opens it is in.
   */
  recoveryLink(email: string): Link | null;
  /**
   * A link to send to `email`, or null if none should be: at most 3 of each kind to one address in 15 minutes,
   * and the rest quietly aren't sent, so nobody can flood an inbox; every link sent in those 15 minutes still
   * works, so nobody can stop its owner getting one either. One goes whether or not there's an account, so
   * neither the answer nor the work after it shows which; none to an address `allow` refuses. At most 5 asked
   * for from one address in 15 minutes, and 20 from one IPv6 /48. A password link only where the site uses
   * passwords. `from` is who's asking (addressKey in limits.ts).
   */
  requestLink(kind: "password" | "sign-in", email: string, from: string): Link | null;
  /** Which email a link is for, and its kind, without using it: for the page it opens to show, so nobody is signed in to someone else's account unawares. */
  lookUpLink(token: string, from: string): { kind: LinkKind; email: string };
  /** The account, given a password link's token and the password chosen: made (`made`), or its password replaced (every session ending). */
  usePasswordLink(token: string, password: string, from: string): Promise<User & { made: boolean }>;
  /**
   * The account a sign-in link's token is for: made (`made`), where the site has no passwords and it was a sign-up
   * link. A link into an existing account opens only the one it was made for. Where "link" isn't a sign-in method
   * it's the way back in, and a fresh start: every session, link, and passkey of the account ends. Where it is, the
   * person can ask for that (`reset`), to be rid of anything someone else added.
   */
  useSignInLink(token: string, from: string, options?: { reset?: boolean }): User & { made: boolean };
  /**
   * A link to send to `email`, to move the account of `session` (one started in the last RECENT_MINUTES) to it;
   * or null if none should be sent (3 to one address in 15 minutes, as for other links, and none to an address
   * `allow` refuses). If the address already has an account, the message says so instead (`token` null): the
   * same answer and work either way.
   */
  requestEmailChange(session: string, email: string, from: string): Link | null;
  /**
   * Moves the account to the email an email link was sent to, ending every session: only for `userId`, the
   * account signed in where the link is opened (the one it moves), so a link sent to someone else does nothing.
   * `previous` is the email it had; `undo`, a link to send there that undoes the move, for UNDO_DAYS. Null when
   * it moves back to an address it was moved away from, while that move's undo link lasts: that's the undo.
   */
  useEmailLink(token: string, userId: string, from: string): User & { previous: string; undo: Link | null };
  /**
   * Undoes a move, from the address it moved from: the account has that email again, every session ends, and
   * its password stops working (whoever moved it may know it). `reset` is a link to send there (to choose a new
   * password, or to sign in where there are none), made here so no limit can stop it. Every later move's undo
   * link ends; an earlier one stays, so a thief's own undo can't cancel the owner's.
   */
  useUndoLink(token: string, from: string): User & { reset: Link };
  /** The account, if the password is right. A wrong email and a wrong password get the same answer. */
  signIn(email: string, password: string, from: string): Promise<User>;
  /**
   * A new session for a user just returned by signIn, a link, or changePassword: the token to put in their
   * cookie. One session each time, and only while nothing about how the account is reached has changed since.
   */
  startSession(user: User): string;
  /** Who a session's token belongs to, while it lasts and `allow` allows them. */
  userOf(token: string): User | null;
  /** Signing out: the session ends. `from`, where it came from, for the event. */
  endSession(token: string, from?: string): void;
  /** Signing out everywhere: every session of the user ends. `from`, where it came from, for the event. */
  endAllSessions(userId: string, from?: string): void;
  /**
   * The user's sessions, the most recently used first (`lastUsed` is written down at most hourly). `token`: the
   * session asking, marked `current`.
   */
  sessionsOf(userId: string, token: string): Session[];
  /** Ends one of the user's sessions, by its `id`; false if it has none of that id. */
  endSessionOf(userId: string, id: string, from?: string): boolean;
  /** Everything kept about the user's account, or null if there's no such account. */
  dataOf(userId: string): AccountData | null;
  /** A new password, for the account of `session` (started in the last RECENT_MINUTES). Every session ends. */
  changePassword(session: string, next: string, from: string): Promise<User>;
  /** The account of `session` (started in the last RECENT_MINUTES), and everything of it, gone. */
  deleteAccount(session: string, from: string): void;
  /**
   * To add a passkey to the account of `session` (started in the last RECENT_MINUTES), for the site at `origin`:
   * the options for navigator.credentials.create, with a challenge good for PASSKEY_MINUTES, once.
   */
  passkeyOptions(session: string, origin: string, from: string): PasskeyCreationOptions;
  /**
   * The passkey the browser made from passkeyOptions, checked and added to the account of `session` (started in the
   * last RECENT_MINUTES), named `name` (one plain line), or "Passkey". "invalid-passkey" if it doesn't check out.
   */
  addPasskey(session: string, made: NewPasskey, name: string | undefined, origin: string, from: string): Passkey;
  /** To sign in with a passkey at the site at `origin`: the options for navigator.credentials.get, with a challenge good for PASSKEY_MINUTES, once. */
  signInOptions(origin: string, from: string): PasskeyRequestOptions;
  /**
   * The account a passkey signs in to, after checking its signature against the key kept for it, for a challenge
   * signInOptions gave. Nobody types an email: the passkey says which account, by its id. "invalid-passkey" otherwise.
   */
  signInWithPasskey(assertion: PasskeyAssertion, origin: string, from: string): User;
  /** The user's passkeys, the most recently added first. */
  passkeysOf(userId: string): Passkey[];
  /** Removes one of the account's passkeys, by its `id`, for `session` (started in the last RECENT_MINUTES): the one removed, or null if it has none of that id. */
  removePasskey(session: string, id: string, from: string): Passkey | null;
};

const SCHEMA = `
  CREATE TABLE IF NOT EXISTS auth_users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password TEXT,
    stamp TEXT NOT NULL,
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
  CREATE TABLE IF NOT EXISTS auth_passkeys (
    id TEXT PRIMARY KEY,
    user TEXT NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    public_key BLOB NOT NULL,
    algorithm INTEGER NOT NULL,
    counter INTEGER NOT NULL,
    name TEXT NOT NULL,
    created INTEGER NOT NULL,
    used INTEGER
  );
  CREATE INDEX IF NOT EXISTS auth_passkeys_user ON auth_passkeys (user);
  CREATE TABLE IF NOT EXISTS auth_challenges (
    challenge TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    user TEXT REFERENCES auth_users(id) ON DELETE CASCADE,
    expires INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS auth_challenges_expires ON auth_challenges (expires);
`;

/** A new token: 256 random bits, base64url (43 characters). */
const newToken = () => randomBytes(32).toString("base64url");
/** A new stamp: 128 random bits, never told to anyone. */
const newStamp = () => randomBytes(16).toString("base64url");
const tokenHash = (token: string) => createHash("sha256").update(token).digest("base64url");
/** How long a session lasts at most. */
export const SESSION_MS = SESSION_DAYS * DAY;
/** When a session started, from when it runs out. */
const startedAt = (expires: number) => expires - SESSION_MS;
/** The longest token a cookie can carry: longer is no token of ours (they're 43 characters). */
export const LONGEST_TOKEN = 100;
const SESSION_ID_LENGTH = 22;
/** A session's id as sessionId makes it. */
const SESSION_ID = new RegExp(`^[A-Za-z0-9_-]{${SESSION_ID_LENGTH}}$`);
/** A session's name for its owner: a hash of its stored hash, so it can't be used to sign in. */
const sessionId = (stored: string) => createHash("sha256").update(`session\0${stored}`).digest("base64url").slice(0, SESSION_ID_LENGTH);
/** A session that hasn't run out or gone unused, as SQL over auth_sessions, with `live(now)` for its two values. */
const LIVE = "expires > ? AND seen > ?";
const live = (now: number) => [now, now - IDLE_DAYS * DAY] as const;
/** What addressKey gives for a real address: IPv4, or an IPv6 /64. */
const ADDRESS = /^(?:\d{1,3}\.){3}\d{1,3}$|^[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){3}::\/64$/;
const WRONG = () => new AuthError("wrong-credentials", "That email and password don't match.");
const EXPIRED = () => new AuthError("invalid-link", "That link has expired or been used. Please ask for a new one.");
const SIGN_IN_AGAIN = () => new AuthError("sign-in-again", "Please sign in again to do that.");
const BAD_PASSKEY = () => new AuthError("invalid-passkey", "That passkey couldn't be used here. Please try again, or sign in another way.");
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

/** The sign-in methods given, checked: known ones, each once, at least one. */
function methodsOf(given: unknown): readonly SignInMethod[] {
  const methods = Array.isArray(given) ? given : [];
  const known = methods.every((method) => METHODS.includes(method));
  if (!known || methods.length === 0 || new Set(methods).size !== methods.length) {
    throw new Error('signInWith must list how people sign in: any of "link", "password", and "passkey", each once.');
  }
  return Object.freeze([...methods]);
}

/**
 * How people get back in, checked: by link, or only by the app, where nothing on offer already makes an inbox a way
 * in (no link or password sign-in).
 */
function recoveryOf(given: unknown, methods: readonly SignInMethod[]): "link" | "app" {
  if (given === undefined || given === "link") return "link";
  if (given === "app" && !methods.includes("link") && !methods.includes("password")) return "app";
  throw new Error('recovery must be "link", or "app" with signInWith: ["passkey"] (with a link or password on offer, an inbox is a way in anyway).');
}

/** Accounts and sessions, kept in `db` (its tables are made if they aren't there). */
export function createAuth(db: DatabaseSync, options: AuthOptions): Auth {
  const { allow, onEvent, breachedRange } = options ?? {};
  const signInWith = methodsOf(options?.signInWith);
  const recovery = recoveryOf(options?.recovery, signInWith);
  if (allow !== undefined && typeof allow !== "function") throw new Error("allow must be a function: (contact) => true or false.");
  if (onEvent !== undefined && typeof onEvent !== "function") throw new Error("onEvent must be a function.");
  if (breachedRange !== undefined && typeof breachedRange !== "function") throw new Error("breachedRange must be a function.");
  const passwords = signInWith.includes("password");
  /** For what only a site with `method` does: calling it otherwise is a mistake in the app's code. */
  const needs = (method: SignInMethod) => {
    if (!signInWith.includes(method)) throw new Error(`This site doesn't sign in with ${method}s: add "${method}" to signInWith first.`);
  };
  /**
   * The link that makes accounts, and that gets someone back into theirs: a password link where there are passwords
   * (whoever opens it chooses one), else a sign-in link (opened once, to add a passkey).
   */
  const makes: LinkKind = passwords ? "password" : "sign-in";
  /** Whether sign-in links are sent: to sign in, where that's a method; else where they're the link that makes accounts and gets people back in. */
  const signInLinks = signInWith.includes("link") || makes === "sign-in";
  /** The kinds of link this site sends. */
  const linkKinds: LinkKind[] = ["email", "undo", ...(passwords ? (["password"] as const) : []), ...(signInLinks ? (["sign-in"] as const) : [])];
  /** For sign-in links, where they aren't sent: a mistake in the app's code (people get back in by a password link here). */
  const needsSignInLinks = () => {
    if (!signInLinks) throw new Error('This site doesn\'t send sign-in links: add "link" to signInWith first.');
  };

  /** Whether the app allows an account at `email`: only a plain true is a yes, and a mistake in allow is a no. */
  const allowed = (email: string) => {
    if (!allow) return true;
    try {
      const answer = allow({ email });
      if (answer === true) return true;
      if (answer !== false) console.error("modest-auth: allow must answer true or false, at once (not a promise), so this was a refusal");
    } catch (error) {
      console.error("modest-auth: allow failed, so this was a refusal:", error instanceof Error ? error.name : typeof error);
    }
    return false;
  };

  /** An event, told after the answer has gone: the same whatever it is, so it can't show anything by its timing. */
  const emit = (type: AuthEvent["type"], details: { [K in keyof Omit<AuthEvent, "type" | "at">]?: AuthEvent[K] | undefined } = {}) => {
    if (!onEvent) return;
    // Details not known (such as where a sign-out came from, when the app didn't say) are left out, not undefined.
    const known = Object.fromEntries(Object.entries(details).filter(([, value]) => value !== undefined));
    const event: AuthEvent = { type, at: Date.now(), ...known };
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
  // breachedRange is passed in as checkBreached has it: known to be there.
  const checkBreachedForm = async (password: string, breachedRange: NonNullable<AuthOptions["breachedRange"]>) => {
    const sha1 = createHash("sha1").update(password).digest("hex").toUpperCase();
    // Given up on after 5 seconds: the signal stops the fetch, and the check fails (so the password is allowed).
    const signal = AbortSignal.timeout(5000);
    try {
      const late = new Promise<never>((_, fail) => signal.addEventListener("abort", () => fail(new Error("took over 5 seconds")), { once: true }));
      /**
       * The range as text: given as text, or read from a Response (one that isn't OK is a failure), at most 1MB
       * (a padded range is about 40KB), and let go of when 5 seconds pass, so it can't keep sending.
       */
      const fetchRange = async () => {
        const given = await breachedRange(sha1.slice(0, 5), { signal });
        if (typeof given === "string") return given;
        if (!(given instanceof Response)) throw new Error("breachedRange gave neither text nor a Response: give the fetch Response itself, or its text");
        if (!given.ok) {
          await given.body?.cancel().catch(() => {});
          throw new Error(`the range answered ${given.status}`);
        }
        const bytes = await readAtMost(given.body, 1_000_000, signal);
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
    }
  };
  /** A new password, checked against every rule and hashed: given the email it's for, so it can't be made from it. */
  const newPassword = async (password: string, email: string) => {
    checkNewPassword(password, email);
    await checkBreached(password);
    return hashPassword(password);
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
  // 100 tries at one account an hour, from anywhere: guesses spread over many addresses are slowed too. Its owner's
  // own sign-ins count, so a refusal says to wait the whole hour, not when the window started.
  const perAccount = limit("account", 100, HOUR, { wholeWait: true });
  // 200 from one IPv6 /48 in 15 minutes: the block a single site or customer is often given, so its 65,536 /64s count together.
  const perBlock = limit("block", 200, 15 * MINUTE);
  // 3 links of each kind sent to one address in 15 minutes: no more, but quietly, so the answer is the same
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
  /** A link asked for (from has been checked by fromWhere). */
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

  // Checked against when there's no such account, or it has no password, so a wrong email takes as long as a
  // wrong password: a hash of the current form and cost that nothing matches (made from random bytes, so no
  // hashing at start-up).
  const nobody = unmatchableHash();

  // The stamp each signed-in user was checked with: a session starts only while it's still the account's.
  // And how, and from where, for the event when a session starts.
  const checked = new WeakMap<User, { stamp: string; by: SignInMethod; from: string }>();

  /** A user just checked (by password or link), ready for startSession: once, while the account still has `stamp`. */
  const handOver = <U extends User>(user: U, stamp: string, by: SignInMethod, from: string): U => {
    checked.set(user, { stamp, by, from });
    return user;
  };
  /** After a new password: every session ends, and every link of the account and to its address. */
  const afterNewPassword = (userId: string, email: string) => {
    endAllSessions(userId);
    endLinks(email, userId);
    endChallenges(userId);
    flush();
  };
  /**
   * Every passkey of the account goes, and every challenge it was given: after a reset or an undo, whoever had it may
   * have added their own.
   */
  const forgetPasskeys = (userId: string) => {
    db.prepare("DELETE FROM auth_passkeys WHERE user = ?").run(userId);
    endChallenges(userId);
  };
  /**
   * A fresh start for the account: `change` gives it a new stamp (and whatever else), and every session, passkey, and
   * challenge ends, both before and after. Another process can't hold one of these across the stamp's change: one
   * stored before it (a passkey sign-in's session, a passkey being added, both checked against the old stamp) goes
   * with the second clearing, and none can be stored after it, as each needs the stamp it checked.
   */
  const freshStart = (userId: string, change: () => string) => {
    const clear = () => {
      endAllSessions(userId);
      forgetPasskeys(userId);
    };
    clear();
    const stamp = change();
    clear();
    return stamp;
  };
  /** Challenges given to the account to add a passkey, not yet used: they end when anything about how it's reached changes. */
  const endChallenges = (userId: string) => void db.prepare("DELETE FROM auth_challenges WHERE user = ?").run(userId);

  type UserRow = { id: string; email: string; password: string | null; stamp: string };
  /** A link's options: whether it can be opened (else why not, for its message), whether there's an account there, and whose it is. */
  type LinkOptions = { refused?: Refusal | undefined; account?: boolean; of?: { id: string; stamp?: string } };
  const userRow = (where: "email" | "id", value: string) =>
    db.prepare(`SELECT id, email, password, stamp FROM auth_users WHERE ${where} = ?`).get(value) as UserRow | undefined;

  /**
   * A live session's account, by the session's token, while the app allows it: who it is, the account's stamp,
   * and the session's times (and its stored hash). The one place a session is read.
   */
  const sessionRow = (token: string, now: number) => {
    if (typeof token !== "string" || !token || token.length > LONGEST_TOKEN) return undefined;
    const hashed = tokenHash(token);
    const row = db
      .prepare(
        `SELECT u.id AS id, u.email AS email, u.stamp AS stamp, s.expires AS expires, s.seen AS seen FROM auth_sessions s JOIN auth_users u ON u.id = s.user WHERE s.token = ? AND ${LIVE}`,
      )
      .get(hashed, ...live(now)) as (User & { stamp: string; expires: number; seen: number }) | undefined;
    if (!row) return undefined;
    // Refused: every session of the account ends for good, so none comes back if the app allows it again.
    if (!allowed(row.email)) return void endAllSessions(row.id);
    return { ...row, hashed };
  };
  /** An account's live sessions, the most recently used first: each one's stored hash, and its times. */
  const liveSessions = (userId: string, now: number) =>
    db.prepare(`SELECT token, expires, seen FROM auth_sessions WHERE user = ? AND ${LIVE} ORDER BY seen DESC`).all(userId, ...live(now)) as {
      token: string;
      expires: number;
      seen: number;
    }[];
  /**
   * The account of a session started in the last RECENT_MINUTES, as it is now: for a change that should need
   * someone to have just shown who they are, by any way the site has. "sign-in-again" otherwise.
   */
  const recent = (session: string, from: string) => {
    fromWhere(from);
    const now = Date.now();
    const row = sessionRow(session, now);
    if (!row || startedAt(row.expires) <= now - RECENT_MINUTES * MINUTE) throw SIGN_IN_AGAIN();
    return row;
  };

  /** check, telling of a wrong password or a pause (not of "busy": nobody was counted). */
  async function verify(row: UserRow | undefined, key: string, password: string, from: string): Promise<string> {
    try {
      return await check(row, key, password, from);
    } catch (error) {
      if (error instanceof AuthError && error.code !== "busy") {
        emit(error.code === "too-many-tries" ? "paused" : "sign-in-failed", { ...(row ? { userId: row.id } : {}), from });
      }
      throw error;
    }
  }
  /**
   * The account's stamp after checking its password (hashed again if at an older cost), limited as a sign-in
   * is. An account with no password is checked against one nothing matches, so it takes as long, and fails.
   */
  async function check(row: UserRow | undefined, key: string, password: string, from: string): Promise<string> {
    const stored = row?.password ?? nobody;
    // Busy first (and nothing awaited after it until the hash): a try refused for being busy isn't counted.
    checkHashingFree();
    fromWhere(from);
    perAccountAndAddress(`${key}\0${from}`);
    perAccount(key);
    if (typeof password !== "string" || password.length > LONGEST_TYPED || !password.isWellFormed()) throw WRONG();
    const { ok, outdated } = await checkPassword(password, stored);
    if (!row?.password || !ok) throw WRONG();
    if (!outdated) return row.stamp;
    const fresh = await hashPassword(password);
    // Only if nothing changed it meanwhile: a password changed while this was hashing stays changed. (The same
    // password at a new cost isn't a change to how the account is reached, so the stamp stays.)
    if (db.prepare("UPDATE auth_users SET password = ? WHERE id = ? AND password = ?").run(fresh, row.id, row.password).changes) return row.stamp;
    // Changed meanwhile: by another sign-in upgrading it too, or by a new password. Check against what's there now.
    const now = userRow("id", row.id);
    if (now?.password && (await checkPassword(password, now.password)).ok) return now.stamp;
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
  /** Uses a link of `kind`, once only (or, `take` false, only looks at it), for an address the app still allows. */
  const takeLink = (token: string, kind: LinkKind, take = true) => {
    const link = findLink(token, [kind], take);
    if (!allowed(link.email)) throw EXPIRED();
    return link;
  };
  /** The account a link moves, which must still be there. */
  const accountOf = (link: LinkRow) => {
    const row = link.user ? userRow("id", link.user) : undefined;
    if (!row) throw EXPIRED();
    return row;
  };
  /**
   * Gives the account `userId` the address `email` (and `password`, if given: null for none), with a new stamp;
   * "invalid-link" if another account has the address. The new stamp.
   */
  const moveTo = (userId: string, email: string, { password, was, undo }: { password?: string | null; was?: string; undo?: { expires: number } } = {}) => {
    const holder = userRow("email", email);
    if (holder && holder.id !== userId) throw EXPIRED();
    const stamp = newStamp();
    // With `was`, only while the account still has that stamp: nothing changed it (an undo, say) meanwhile. With
    // `undo`, only while that undo link to `email` is still there: an earlier one, used meanwhile in another process,
    // ends it, and holds the claim.
    const unchanged =
      (was === undefined ? "" : " AND stamp = ?") +
      (undo === undefined ? "" : " AND EXISTS (SELECT 1 FROM auth_links WHERE kind = 'undo' AND user = auth_users.id AND email = ? AND expires = ?)");
    const still = [...(was === undefined ? [] : [was]), ...(undo === undefined ? [] : [email, undo.expires])];
    let moved: number;
    try {
      moved =
        password === undefined
          ? Number(db.prepare(`UPDATE auth_users SET email = ?, stamp = ? WHERE id = ?${unchanged}`).run(email, stamp, userId, ...still).changes)
          : Number(
              db.prepare(`UPDATE auth_users SET email = ?, password = ?, stamp = ? WHERE id = ?${unchanged}`).run(email, password, stamp, userId, ...still)
                .changes,
            );
    } catch (error) {
      // Taken by another process sharing the database, between the check and the change.
      if (userRow("email", email)) throw EXPIRED();
      throw error;
    }
    if (moved === 0) throw EXPIRED();
    return stamp;
  };
  /**
   * Moves an account back to the address a move took it from (an undo, ending at `undoExpires`), with `password`
   * (null for none) and no passkeys: every session ends, and every link of the account and of both addresses, but
   * not an earlier move's undo link. The new stamp.
   */
  const moveBack = (userId: string, current: string, email: string, password: string | null, undoExpires: number) => {
    // Every passkey goes too: whoever moved it may have added their own.
    const stamp = freshStart(userId, () => moveTo(userId, email, { password, undo: { expires: undoExpires } }));
    // Undo links stay unless they're this account's own, from a later move: so the earliest owner always wins.
    db.prepare("DELETE FROM auth_links WHERE (user = ? OR email IN (?, ?)) AND NOT (kind = 'undo' AND (expires < ? OR user != ?))").run(
      userId,
      current,
      email,
      undoExpires,
      userId,
    );
    flush();
    return stamp;
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
  /**
   * The account a link opens. A link made for an account (`account`, its id) opens only that one: still at the
   * link's address, or taken back to it after a move. A link made for none (a sign-up) only ever makes a new account,
   * so one that turns up at the address meanwhile isn't opened. With `password`, or `reset`, it's a fresh start: a
   * new stamp, the new password (or, for a reset, none), and every session, link, and passkey of the account ends, so
   * whatever a thief added goes. Otherwise (signing in by link) the account is left as it is.
   */
  const settle = (email: string, account: string | null, password: string | null, reset: boolean, from: string): User & { made: boolean; stamp: string } => {
    const row = userRow("email", email);
    if (account === null) {
      if (row) throw EXPIRED();
      const id = randomUUID();
      const stamp = newStamp();
      try {
        db.prepare("INSERT INTO auth_users (id, email, password, stamp, created) VALUES (?, ?, ?, ?, ?)").run(id, email, password, stamp, Date.now());
      } catch (error) {
        // Made by another process sharing the database, between the check and the insert.
        if (userRow("email", email)) throw EXPIRED();
        throw error;
      }
      endLinks(email);
      emit("account-made", { userId: id, from });
      return { id, email, made: true, stamp };
    }
    if (!row) {
      const back = undoTo(email);
      if (back?.user !== account) throw EXPIRED();
      const stamp = moveBack(back.user, back.current, email, password, back.expires);
      emit("email-change-undone", { userId: back.user, from });
      return { id: back.user, email, made: false, stamp };
    }
    if (row.id !== account) throw EXPIRED();
    if (password === null && !reset) {
      endLinks(email);
      return { id: row.id, email, made: false, stamp: row.stamp };
    }
    // A reset takes the password too (none, until one is chosen at a link): whoever else got in may have set it.
    // Only while the account is as it was read: one moved meanwhile in another process keeps that move's undo link.
    const stamp = freshStart(row.id, () => {
      const next = newStamp();
      if (db.prepare("UPDATE auth_users SET password = ?, stamp = ? WHERE id = ? AND stamp = ?").run(password, next, row.id, row.stamp).changes === 0) {
        throw EXPIRED();
      }
      return next;
    });
    afterNewPassword(row.id, email);
    emit(password === null ? "account-reset" : "password-changed", { userId: row.id, from });
    return { id: row.id, email, made: false, stamp };
  };
  /**
   * A new link of `kind` to `email`, stored as its hash, to send. `refused`: one that does nothing (stored only so
   * the work is the same either way), given with no token, and why, for its message. With `of`, it's that
   * account's own (a move, or its undo); given its `stamp` too, it's stored only while the account still has it, so
   * a change asked for by a session goes nowhere if anything changed since ("sign-in-again").
   */
  const newLink = (kind: LinkKind, email: string, { refused, account = true, of }: LinkOptions = {}): Link => {
    const token = newToken();
    const expires = linkExpires(kind);
    const row = [tokenHash(token), refused ? "none" : kind, email, expires] as const;
    const stored =
      of?.stamp === undefined
        ? db.prepare("INSERT INTO auth_links (token, kind, email, expires, user) VALUES (?, ?, ?, ?, ?)").run(...row, of?.id ?? null)
        : db
            .prepare("INSERT INTO auth_links (token, kind, email, expires, user) SELECT ?, ?, ?, ?, id FROM auth_users WHERE id = ? AND stamp = ?")
            .run(...row, of.id, of.stamp);
    if (stored.changes === 0) throw SIGN_IN_AGAIN();
    const base = { kind, to: email, account, expires };
    return refused ? { ...base, token: null, refused } : { ...base, token };
  };
  /**
   * A link someone asked to have sent to `email`: counted against that inbox (null, quietly, past its limit), and
   * stored either way, so the work is the same whatever the answer; null, too, for an address the app doesn't
   * allow, whose link does nothing.
   */
  const offer = (kind: LinkKind, email: string, options: LinkOptions) => {
    const allows = allowed(email);
    // Past the inbox's limit: nothing sent, but a link that does nothing is still stored, so the work is the same.
    if (!inboxHasRoom(kind, email)) {
      newLink(kind, email, { ...options, refused: "no-account" });
      return null;
    }
    const link = newLink(kind, email, allows ? options : { ...options, refused: options.refused ?? "no-account" });
    return allows ? link : null;
  };
  /** A new challenge for a passkey to sign, of `kind` (for `userId`, adding one), good for PASSKEY_MINUTES: kept as its hash. */
  const newChallenge = (kind: "add" | "sign-in", userId: string | null) => {
    const challenge = newToken();
    db.prepare("INSERT INTO auth_challenges (challenge, kind, user, expires) VALUES (?, ?, ?, ?)").run(
      tokenHash(challenge),
      kind,
      userId,
      Date.now() + PASSKEY_MINUTES * MINUTE,
    );
    return challenge;
  };
  /** Uses a challenge of `kind`, for `userId` (or nobody), once only; "invalid-passkey" if there's no such live one. */
  const takeChallenge = (challenge: string, kind: "add" | "sign-in", userId: string | null) => {
    const taken = db
      .prepare("DELETE FROM auth_challenges WHERE challenge = ? AND kind = ? AND user IS ? AND expires > ? RETURNING 1")
      .get(tokenHash(challenge), kind, userId, Date.now());
    if (!taken) throw BAD_PASSKEY();
  };
  /** The account's new stamp, for a change to how it's reached that a session asked for: only while it's still `stamp`. */
  const restamp = (userId: string, stamp: string) => {
    const next = newStamp();
    if (db.prepare("UPDATE auth_users SET stamp = ? WHERE id = ? AND stamp = ?").run(next, userId, stamp).changes === 0) throw SIGN_IN_AGAIN();
    endChallenges(userId);
    return next;
  };
  type PasskeyRow = { id: string; name: string; created: number; used: number | null };
  /** The account's passkeys, the most recently added first, as its owner sees them. */
  const passkeysOf = (userId: string): Passkey[] =>
    (db.prepare("SELECT id, name, created, used FROM auth_passkeys WHERE user = ? ORDER BY created DESC").all(userId) as PasskeyRow[]).map((row) => ({
      id: row.id,
      name: row.name,
      created: row.created,
      lastUsed: row.used,
    }));

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
    ).run(...live(now));
    // Links hold the emails of people who may have no account: once they've gone, not left in the WAL either.
    const cleared = db.prepare("DELETE FROM auth_links WHERE token IN (SELECT token FROM auth_links WHERE expires <= ? LIMIT 2000)").run(now).changes;
    db.prepare("DELETE FROM auth_challenges WHERE challenge IN (SELECT challenge FROM auth_challenges WHERE expires <= ? LIMIT 2000)").run(now);
    if (cleared || unflushed) flush(false);
  };

  return {
    signInWith,
    signInLinks,

    recoveryLink(given) {
      const email = emailOrRefuse(given);
      const row = userRow("email", email);
      if (!row || !allowed(email)) return null;
      // The app's own code, vouching for someone: not counted against the inbox, made whatever `recovery` says, for
      // this account only, and a fresh start when used wherever it's the way back in (a password link, or a sign-in
      // link where the site doesn't sign in by link). Told as an event, so the app has a record of it.
      emit("recovery-link-made", { userId: row.id });
      return newLink(makes, email, { of: { id: row.id } });
    },

    requestLink(kind, given, from) {
      if (kind === "password") needs("password");
      else if (kind !== "sign-in") throw new Error('kind must be "password" or "sign-in" (an email link comes from requestEmailChange).');
      else needsSignInLinks();
      fromWhere(from);
      countLinkFrom(from);
      const email = emailOrRefuse(given);
      sweep(Date.now());
      // An account here, or one this address can take back by the link that makes accounts (so the message says
      // what it will do). Every one looked up, allowed or not: the same work whatever the answer.
      const here = userRow("email", email);
      const back = kind === makes ? undoTo(email) : undefined;
      // The account a link here would open, if any: one at the address, else one it can take back.
      const opens = here?.id ?? back?.user;
      const account = opens !== undefined;
      // With no account, only the kind that makes one has anything to open; into an existing account (or one this
      // address can take back), only where anyone may ask for one: where only the app may, the message says the
      // account signs in by passkey (the owner of a moved account holds its undo link).
      const refused = account ? (recovery === "link" ? undefined : "passkey-only") : kind === makes ? undefined : "no-account";
      return offer(kind, email, { refused, account, ...(opens && !refused ? { of: { id: opens } } : {}) });
    },

    lookUpLink(token, from) {
      fromWhere(from);
      const { kind, email } = findLink(token, linkKinds, false);
      return { kind, email };
    },

    async usePasswordLink(token, password, from) {
      needs("password");
      checkHashingFree();
      fromWhere(from);
      // Looked at first, but only used once the password will do: a password refused doesn't use up the link.
      const looked = findLink(token, ["password"], false);
      const hashed = await newPassword(password, looked.email);
      const link = takeLink(token, "password");
      const { stamp, ...user } = settle(link.email, link.user, hashed, false, from);
      return handOver(user, stamp, "link", from);
    },

    useSignInLink(token, from, { reset = false } = {}) {
      needsSignInLinks();
      fromWhere(from);
      const link = takeLink(token, "sign-in");
      // Where there are passwords, accounts are made by password links, not sign-in links.
      if (link.user === null && passwords) throw EXPIRED();
      // Where links aren't how people sign in day to day, one into an account is only ever the way back in: a fresh
      // start, so a thief's passkeys and sessions don't outlast it. Where they are, the person can choose one.
      const { stamp, ...user } = settle(link.email, link.user, null, reset || !signInWith.includes("link"), from);
      return handOver(user, stamp, "link", from);
    },

    async signIn(given, password, from) {
      needs("password");
      const email = cleanEmail(given) ?? "";
      const row = email ? userRow("email", email) : undefined;
      const stamp = await verify(row, email || "invalid", password, from);
      // (verify throws without an account: this only tells the type checker so.) Refused by allow: as a wrong password.
      if (!row || !allowed(row.email)) throw WRONG();
      return handOver({ id: row.id, email: row.email }, stamp, "password", from);
    },

    startSession(user) {
      const token = newToken();
      const now = Date.now();
      sweep(now);
      const how = checked.get(user);
      if (how === undefined) throw new Error("startSession needs a user just returned by signIn, a link, or changePassword, and starts one session for it.");
      checked.delete(user);
      // Refused as the way in would be: a password that no longer matches, a link or passkey that no longer works.
      const refused = () => (how.by === "password" ? WRONG() : how.by === "passkey" ? BAD_PASSKEY() : EXPIRED());
      if (!allowed(user.email)) throw refused();
      // Only while the account exists with the stamp it was checked with: nothing about how it's reached has changed.
      const started = db
        .prepare("INSERT INTO auth_sessions (token, user, expires, seen) SELECT ?, id, ?, ? FROM auth_users WHERE id = ? AND stamp = ?")
        .run(tokenHash(token), now + SESSION_MS, now, user.id, how.stamp);
      if (started.changes === 0) throw refused();
      emit("signed-in", { userId: user.id, from: how.from, by: how.by });
      db.prepare(
        `DELETE FROM auth_sessions WHERE user = ? AND token NOT IN (SELECT token FROM auth_sessions WHERE user = ? ORDER BY expires DESC LIMIT ${MOST_SESSIONS})`,
      ).run(user.id, user.id);
      return token;
    },

    userOf(token) {
      const now = Date.now();
      sweep(now);
      const row = sessionRow(token, now);
      if (!row) return null;
      if (now - row.seen > SEEN_EVERY_MS) db.prepare("UPDATE auth_sessions SET seen = ? WHERE token = ?").run(now, row.hashed);
      return { id: row.id, email: row.email };
    },

    endSession(token, from) {
      if (typeof token !== "string" || !token) return;
      const ended = db.prepare("DELETE FROM auth_sessions WHERE token = ? RETURNING user").get(tokenHash(token)) as { user: string } | undefined;
      if (ended) emit("signed-out", { userId: ended.user, from });
    },

    endAllSessions(userId, from) {
      if (endAllSessions(userId)) emit("signed-out-everywhere", { userId, from });
    },

    sessionsOf(userId, token) {
      const mine = typeof token === "string" && token ? tokenHash(token) : "";
      return liveSessions(userId, Date.now()).map((row) => ({
        id: sessionId(row.token),
        started: startedAt(row.expires),
        lastUsed: row.seen,
        current: row.token === mine,
      }));
    },

    endSessionOf(userId, id, from) {
      if (typeof id !== "string" || !SESSION_ID.test(id)) return false;
      const rows = db.prepare("SELECT token FROM auth_sessions WHERE user = ?").all(userId) as { token: string }[];
      const found = rows.find((row) => sessionId(row.token) === id);
      const ended = !!found && db.prepare("DELETE FROM auth_sessions WHERE token = ? AND user = ?").run(found.token, userId).changes > 0;
      if (ended) emit("session-ended", { userId, from });
      return ended;
    },

    dataOf(userId) {
      const now = Date.now();
      const row = db.prepare("SELECT email, password, created FROM auth_users WHERE id = ?").get(userId) as
        | { email: string; password: string | null; created: number }
        | undefined;
      if (!row) return null;
      const sessions = liveSessions(userId, now);
      // Its own links (its move requests shown as such whatever they were stored as, so the copy can't show whether
      // another address has an account), and those to its address that do something.
      const links = db
        .prepare(
          "SELECT CASE WHEN kind = 'none' THEN 'email' ELSE kind END AS kind, email, expires FROM auth_links WHERE (user = ? OR (email = ? AND kind != 'none')) AND expires > ? ORDER BY expires",
        )
        .all(userId, row.email, now) as { kind: LinkKind; email: string; expires: number }[];
      return {
        email: row.email,
        created: row.created,
        password: row.password ? "set" : "none",
        sessions: sessions.map((session) => ({ started: startedAt(session.expires), lastUsed: session.seen })),
        links: links.map((link) => ({ kind: link.kind, email: link.email, expires: link.expires })),
        passkeys: passkeysOf(userId).map(({ name, created, lastUsed }) => ({ name, created, lastUsed })),
      };
    },

    async changePassword(session, next, from) {
      needs("password");
      checkHashingFree();
      const row = recent(session, from);
      const hashed = await newPassword(next, row.email);
      // Only while nothing changed since the session was checked; the email as it is now.
      const stamp = newStamp();
      // And while the session that asked is still there: ended meanwhile (signed out everywhere), it changes nothing.
      const done = db
        .prepare(
          "UPDATE auth_users SET password = ?, stamp = ? WHERE id = ? AND stamp = ? AND EXISTS (SELECT 1 FROM auth_sessions WHERE token = ? AND user = id) RETURNING email",
        )
        .get(hashed, stamp, row.id, row.stamp, row.hashed) as { email: string } | undefined;
      if (!done) throw SIGN_IN_AGAIN();
      afterNewPassword(row.id, done.email);
      emit("password-changed", { userId: row.id, from });
      return handOver({ id: row.id, email: done.email }, stamp, "password", from);
    },

    requestEmailChange(session, given, from) {
      const row = recent(session, from);
      countLinkFrom(from);
      const email = emailOrRefuse(given);
      if (email === row.email) throw new AuthError("invalid-email", "That's the account's email already.");
      // To an address with an account already, one that does nothing, and a message saying so. Only while nothing
      // changed since the session was checked: a new password meanwhile ends the request too.
      const taken = !!userRow("email", email);
      return offer("email", email, { refused: taken ? "email-in-use" : undefined, account: taken, of: { id: row.id, stamp: row.stamp } });
    },

    useEmailLink(token, signedIn, from) {
      fromWhere(from);
      // Only by the account it moves, signed in where it's opened: checked before the link is used up.
      if (findLink(token, ["email"], false).user !== signedIn) throw EXPIRED();
      const link = takeLink(token, "email");
      const { email } = link;
      // Gone (or, in moveTo, the address taken meanwhile): nothing to move.
      const row = accountOf(link);
      // Back to an address it was moved away from, while that move's undo link lasts: the same as using it. Later
      // moves' undo links end, and none goes to the address it leaves, so whoever moved it there can't take it back.
      const home = db.prepare("SELECT expires FROM auth_links WHERE kind = 'undo' AND user = ? AND email = ? AND expires > ?").get(row.id, email, Date.now()) as
        | { expires: number }
        | undefined;
      const stamp = moveTo(row.id, email, { was: row.stamp });
      endAllSessions(row.id);
      endLinks(row.email, row.id);
      endLinks(email);
      if (home) db.prepare("DELETE FROM auth_links WHERE kind = 'undo' AND user = ? AND expires > ?").run(row.id, home.expires);
      // Otherwise an undo link for the address it moved from (each move its own: using one ends only later ones),
      // stored only while the account is still as this move left it, so an undo landing meanwhile in another process
      // (which ends later moves' undo links) isn't outlasted by this one.
      const undo = home ? null : newLink("undo", row.email, { of: { id: row.id, stamp } });
      flush();
      emit("email-changed", { userId: row.id, from });
      return { id: row.id, email, previous: row.email, undo };
    },

    useUndoLink(token, from) {
      fromWhere(from);
      // Looked at, not used: moveBack moves the account only while this link is there, and then ends it, so of two
      // undo links used at once in different processes, the earlier one wins.
      const link = takeLink(token, "undo", false);
      const { email, expires } = link;
      // Gone (or, in moveBack, the address since taken by another account): nothing to move back.
      const row = accountOf(link);
      // No password any more: whoever moved it may know it. The way back in is the link that makes accounts.
      moveBack(row.id, row.email, email, null, expires);
      // The way back in, for this account: none where only the app makes links into accounts (the undo took every
      // passkey, and whoever reads this inbox may be who it was moved away from), so the message says so instead.
      const reset = newLink(makes, email, recovery === "link" ? { of: { id: row.id } } : { refused: "passkey-only" });
      emit("email-change-undone", { userId: row.id, from });
      return { id: row.id, email, reset };
    },

    deleteAccount(session, from) {
      const row = recent(session, from);
      const done = db.prepare("DELETE FROM auth_users WHERE id = ? AND stamp = ?").run(row.id, row.stamp);
      if (done.changes === 0) throw SIGN_IN_AGAIN();
      endLinks(row.email, row.id);
      flush();
      emit("account-deleted", { userId: row.id, from });
    },
    passkeyOptions(session, origin, from) {
      needs("passkey");
      const row = recent(session, from);
      const party = relyingParty(origin);
      return {
        challenge: newChallenge("add", row.id),
        rp: { id: party.id, name: party.id },
        // The account's id, never its email, so a passkey says nothing about whose it is to anyone but its owner.
        user: { id: Buffer.from(row.id).toString("base64url"), name: row.email, displayName: row.email },
        pubKeyCredParams: Object.values(ALGORITHMS).map((alg) => ({ type: "public-key" as const, alg })),
        timeout: PASSKEY_MINUTES * MINUTE,
        excludeCredentials: passkeysOf(row.id).map(({ id }) => ({ type: "public-key" as const, id })),
        authenticatorSelection: { residentKey: "required", requireResidentKey: true, userVerification: "required" },
        attestation: "none",
      };
    },

    addPasskey(session, made, name, origin, from) {
      needs("passkey");
      const row = recent(session, from);
      let checked: ReturnType<typeof checkNewPasskey>;
      try {
        checked = checkNewPasskey(made, relyingParty(origin));
      } catch {
        throw BAD_PASSKEY();
      }
      takeChallenge(checked.challenge, "add", row.id);
      const passkey: Passkey = { id: checked.id, name: isPasskeyName(name) ? name : "Passkey", created: Date.now(), lastUsed: null };
      const stamp = restamp(row.id, row.stamp);
      // Stored only while the stamp is the one just set, so a fresh start landing in another process meanwhile (which
      // ends every passkey) can't be outlasted. A passkey's id is the device's: one already here (this account's or
      // another's) isn't taken again.
      const stored = db
        .prepare(
          "INSERT INTO auth_passkeys (id, user, public_key, algorithm, counter, name, created) SELECT ?, id, ?, ?, ?, ?, ? FROM auth_users WHERE id = ? AND stamp = ? ON CONFLICT (id) DO NOTHING",
        )
        .run(passkey.id, checked.publicKey, checked.algorithm, checked.counter, passkey.name, passkey.created, row.id, stamp);
      if (stored.changes === 0) throw userRow("id", row.id)?.stamp === stamp ? BAD_PASSKEY() : SIGN_IN_AGAIN();
      emit("passkey-added", { userId: row.id, from });
      return passkey;
    },

    signInOptions(origin, from) {
      needs("passkey");
      fromWhere(from);
      sweep(Date.now());
      return {
        challenge: newChallenge("sign-in", null),
        rpId: relyingParty(origin).id,
        timeout: PASSKEY_MINUTES * MINUTE,
        userVerification: "required",
        allowCredentials: [],
      };
    },

    signInWithPasskey(assertion, origin, from) {
      needs("passkey");
      fromWhere(from);
      const id = typeof assertion?.id === "string" ? assertion.id : "";
      const row = db
        .prepare(
          "SELECT p.user AS user, p.public_key AS publicKey, p.algorithm AS algorithm, p.counter AS counter, u.email AS email, u.stamp AS stamp FROM auth_passkeys p JOIN auth_users u ON u.id = p.user WHERE p.id = ?",
        )
        .get(id) as { user: string; publicKey: Uint8Array; algorithm: number; counter: number; email: string; stamp: string } | undefined;
      let checked: { challenge: string; counter: number };
      try {
        if (!row) throw BAD_PASSKEY();
        checked = checkAssertion(assertion, relyingParty(origin), { publicKey: Buffer.from(row.publicKey), algorithm: row.algorithm });
        // The account the passkey says it's for must be given, and be the one it was added to; and one allow allows.
        if (assertion.userHandle !== Buffer.from(row.user).toString("base64url") || !allowed(row.email)) throw BAD_PASSKEY();
        takeChallenge(checked.challenge, "sign-in", null);
        // A counter that doesn't go up, where it counts at all, means a copy of the passkey: refused. Written only
        // while it's still the counter checked, so two processes can't both take the same one.
        if ((checked.counter > 0 || row.counter > 0) && checked.counter <= row.counter) throw BAD_PASSKEY();
        const counted = db
          .prepare("UPDATE auth_passkeys SET counter = ?, used = ? WHERE id = ? AND counter = ?")
          .run(checked.counter, Date.now(), id, row.counter);
        if (counted.changes === 0) throw BAD_PASSKEY();
      } catch {
        emit("sign-in-failed", { ...(row ? { userId: row.user } : {}), from });
        throw BAD_PASSKEY();
      }
      return handOver({ id: row.user, email: row.email }, row.stamp, "passkey", from);
    },

    passkeysOf,

    removePasskey(session, id, from) {
      const row = recent(session, from);
      const passkey = passkeysOf(row.id).find((p) => p.id === id);
      if (!passkey) return null;
      // Gone before the stamp changes, as in freshStart.
      db.prepare("DELETE FROM auth_passkeys WHERE id = ? AND user = ?").run(id, row.id);
      restamp(row.id, row.stamp);
      // Every other session ends: one the passkey started (a thief's, say) mustn't carry on, still recent, and add another.
      db.prepare("DELETE FROM auth_sessions WHERE user = ? AND token != ?").run(row.id, row.hashed);
      emit("passkey-removed", { userId: row.id, from });
      return passkey;
    },
  };
}
