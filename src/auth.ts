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
// password, a new email, a passkey added or removed). Anything checked before a
// change lands (a session about to start, a password about to change, an
// account about to go) goes ahead only while the stamp is still the one that
// was checked. And a change that takes more than one statement is one
// transaction, so another process sharing the file sees all of it or none.
//
// It keeps its tables (auth_users, auth_sessions, auth_links, auth_limits) in a
// node:sqlite database you give it, which may be your app's own, and may be
// shared by several processes.

import { createHash, createHmac, randomBytes, randomInt, randomUUID, timingSafeEqual } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import { cleanEmail } from "./emails.ts";
import { AuthError } from "./errors.ts";
import { blockOf, databaseLimits, IN_TRANSACTION, type Limit, settingUp } from "./limits.ts";
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
export type SignInMethod = "link" | "code" | "password" | "passkey";
const METHODS: readonly SignInMethod[] = ["link", "code", "password", "passkey"];

/** Something that happened to an account, for the app to keep: never a password, token, or email. `from` is addressKey's. */
export type AuthEvent = {
  type:
    | "signed-in"
    | "sign-in-failed"
    | "paused"
    | "account-made"
    | "password-changed"
    | "email-changed"
    | "signed-out"
    | "signed-out-everywhere"
    | "session-ended"
    | "passkey-added"
    | "passkey-removed"
    | "account-reset"
    | "access-ended"
    | "recovery-link-made"
    | "account-deleted";
  at: number;
  userId?: string;
  from?: string;
  /** For "signed-in" (a session started): after the password was checked, an emailed link used (or its code typed), or a passkey's signature checked. */
  by?: SignInMethod;
};
// "sign-in-failed": a wrong email or password; "paused": a try refused by a limit, on the account or on where it
// came from.

export type AuthOptions = {
  /** How people sign in: any of "link", "password", and "passkey", and "code" beside "link". Required, so nobody gets a way in the site didn't choose. */
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
  /**
   * A random secret kept outside the database (an environment variable, such as AUTH_PEPPER), of 32 characters or
   * more: `openssl rand -base64 32` makes one (never one chosen by hand). Every short code is kept as a keyed hash under it, so a copy of the
   * database, without it, can't be searched for one. Required where "code" is a sign-in method (a code is 6 digits).
   * Links and sessions don't need it: their tokens are 256 bits, which no copy can search. Changing it only stops
   * the codes waiting.
   */
  pepper?: string;
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
 * account, where the site has no passwords), approve moving an account to a new email (sent to the address it has),
 * or confirm the new one (sent there).
 */
export type LinkKind = "password" | "sign-in" | "move" | "email";
/** How long a link to approve or confirm moving an account to a new email lasts. */
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
export type Link = {
  kind: LinkKind;
  to: string;
  account: boolean;
  expires: number;
  /** For a move's approval (kind "move"): the address it moves to. */
  newEmail?: string;
  /**
   * Where "code" is a sign-in method, a sign-in link's code (6 digits), to send with it: typed instead of opening
   * the link, in the browser that asked (holding the `asker` given to requestLink).
   */
  code?: string;
} & ({ token: string; refused?: undefined } | { token: null; refused: Refusal });

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
   * Ends every way into the account at `email`, for the app's own code: every session, link, and passkey, and its
   * password, so nobody is in, or can get in, but by a new link to the address (where `recovery` is "app", only one
   * the app makes). For when someone else got in, or the app's own records no longer give the address to the person
   * it was. It only takes away: nothing is sent, and it works whatever `allow` says. The account stays, so the next
   * person to sign in at the address has it, and its id. False if there's no account at `email` (one that isn't an
   * address is refused, as everywhere). Never from a route.
   */
  endAccess(email: string): boolean;
  /**
   * A link to send to `email`, or null if none should be: at most 3 of each kind to one address in 15 minutes,
   * and the rest quietly aren't sent, so nobody can flood an inbox; every link sent in those 15 minutes still
   * works, so nobody can stop its owner getting one either. One goes whether or not there's an account, so
   * neither the answer nor the work after it shows which; none to an address `allow` refuses. At most 5 asked
   * for from one address in 15 minutes, and 20 from one IPv6 /48. A password link only where the site uses
   * passwords. `from` is who's asking (addressKey in limits.ts). Where "code" is a sign-in method, a sign-in link
   * also needs `asker`: a new random token (`newAsker`), given to the browser that asked (`codeCookie`) whatever the
   * answer, null included, so whether one was given shows nothing; its code is stored under it either way.
   */
  requestLink(kind: "password" | "sign-in", email: string, from: string, asker?: string): Link | null;
  /**
   * Which email a link is for (for a move's approval, the address it moves to), and its kind, without using it: for
   * the page it opens to show, so nobody is signed in to, or moves, someone else's account unawares.
   */
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
   * The account a sign-in link is for, by its code instead of the link: typed in the browser that asked (`asker`,
   * from the link it was sent with). The same account the link would open, made if it would make it. A wrong code
   * uses up one of CODE_TRIES, and the last ends the code (the link still works); every code typed for an address
   * counts against CODES_A_DAY. Only where "code" is a sign-in method.
   */
  useSignInCode(asker: string, code: string, from: string): User & { made: boolean };
  /**
   * To move the account of `session` (one started in the last RECENT_MINUTES) to `email`: a link to send to the
   * address it has now, to approve it, or null if none should be sent (3 to one address in 15 minutes, as for other
   * links). Nothing goes to the new address until whoever reads this one approves.
   */
  requestEmailChange(session: string, email: string, from: string): Link | null;
  /**
   * From a move's approval link: the link to send to the new address, to confirm it there, or null if none should be
   * sent (3 to one address in 15 minutes, and none to an address `allow` refuses). If the new address has an account
   * already, the message says so instead (`token` null): the same answer and work either way.
   */
  approveEmailChange(token: string, from: string): Link | null;
  /**
   * Moves the account to the email a confirmation link was sent to, ending every session: only for `userId`, the
   * account signed in where the link is opened (the one it moves), so a link sent to someone else does nothing.
   * `previous` is the email it had.
   */
  useEmailLink(token: string, userId: string, from: string): User & { previous: string };
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
    user TEXT REFERENCES auth_users(id) ON DELETE CASCADE,
    new_email TEXT
  );
  CREATE INDEX IF NOT EXISTS auth_links_email ON auth_links (email);
  CREATE INDEX IF NOT EXISTS auth_links_user ON auth_links (user);
  CREATE INDEX IF NOT EXISTS auth_links_expires ON auth_links (expires);
  CREATE TABLE IF NOT EXISTS auth_codes (
    asker TEXT PRIMARY KEY,
    link TEXT NOT NULL,
    email TEXT NOT NULL,
    expires INTEGER NOT NULL,
    code TEXT NOT NULL,
    tries INTEGER NOT NULL DEFAULT 0
  );
  CREATE INDEX IF NOT EXISTS auth_codes_expires ON auth_codes (expires);
  CREATE INDEX IF NOT EXISTS auth_codes_email ON auth_codes (email);
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
/** A new token for a browser asking for a sign-in link with a code (given to requestLink, and to the browser by codeCookie). */
export const newAsker = (): string => randomBytes(32).toString("base64url");
/** Wrong tries a sign-in link's code takes before it's gone, and a new one has to be asked for. */
export const CODE_TRIES = 5;
/** Codes typed for one address in a day, right or wrong: with CODE_TRIES, how few guesses a 6-digit code gets. */
export const CODES_A_DAY = 10;
const CODE = /^\d{6}$/;
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
const WRONG_CODE = () => new AuthError("wrong-code", "That code isn't right, or has run out. Please check it, or ask for a new one.");
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
  move: EMAIL_LINK_MINUTES * MINUTE,
  email: EMAIL_LINK_MINUTES * MINUTE,
};
const linkExpires = (kind: LinkKind) => Date.now() + LIFETIME[kind];

/** The sign-in methods given, checked: known ones, each once, at least one. */
function methodsOf(given: unknown): readonly SignInMethod[] {
  const methods = Array.isArray(given) ? given : [];
  const known = methods.every((method) => METHODS.includes(method));
  if (!known || methods.length === 0 || new Set(methods).size !== methods.length) {
    throw new Error('signInWith must list how people sign in: any of "link", "code", "password", and "passkey", each once.');
  }
  // A code is a sign-in link's, typed instead of opening it: there's no code without the link.
  if (methods.includes("code") && !methods.includes("link"))
    throw new Error('signInWith with "code" needs "link" too: a code is a sign-in link\'s, typed instead.');
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

/**
 * The pepper, checked, as the one function every short code modest-auth makes is kept through: a keyed hash
 * (HMAC-SHA256) of its parts. Required where a method that makes one is chosen ("code"); refused if it's too short
 * to be a secret (how random it is can't be checked: it must come from `openssl rand`, not be chosen).
 */
function pepperOf(given: unknown, methods: readonly SignInMethod[]): ((...parts: string[]) => string) | null {
  if (given === undefined) {
    if (methods.includes("code")) throw new Error('With "code", a pepper is needed: a secret kept outside the database, such as `openssl rand -base64 32`.');
    return null;
  }
  if (typeof given !== "string" || given.length < 32)
    throw new Error("pepper must be a secret of 32 characters or more, such as `openssl rand -base64 32` makes.");
  return (...parts) => createHmac("sha256", given).update(parts.join("\0")).digest("base64url");
}

/** Accounts and sessions, kept in `db` (its tables are made if they aren't there). */
export function createAuth(db: DatabaseSync, options: AuthOptions): Auth {
  const { allow, onEvent, breachedRange } = options ?? {};
  const signInWith = methodsOf(options?.signInWith);
  const recovery = recoveryOf(options?.recovery, signInWith);
  if (allow !== undefined && typeof allow !== "function") throw new Error("allow must be a function: (contact) => true or false.");
  if (onEvent !== undefined && typeof onEvent !== "function") throw new Error("onEvent must be a function.");
  const peppered = pepperOf(options?.pepper, signInWith);
  /** A code's keyed hash, with the asking browser's token: a copy of the database, without the pepper, can't be searched for it. */
  const codeHash = (asker: string, code: string) => {
    if (!peppered) throw new Error('With "code", a pepper is needed.');
    return peppered(asker, code);
  };
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
  /** Whether sign-in links carry a code, typed instead of opening the link, in the browser that asked. */
  const codes = signInWith.includes("code");
  /** Whether a sign-in link is how people sign in day to day (opened, or its code typed), not only the way back in. */
  const everyday = signInWith.includes("link");
  /** Whether sign-in links are sent: to sign in, where that's a method; else where they're the link that makes accounts and gets people back in. */
  const signInLinks = everyday || makes === "sign-in";
  /** The kinds of link this site sends. */
  const linkKinds: LinkKind[] = ["move", "email", ...(passwords ? (["password"] as const) : []), ...(signInLinks ? (["sign-in"] as const) : [])];
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
    const tell = () =>
      setImmediate(() => {
        // Whether it throws or (being async) rejects: logged, never passed on.
        Promise.resolve()
          .then(() => onEvent(event))
          .catch((error: unknown) => console.error("modest-auth: onEvent failed:", error instanceof Error ? error.name : typeof error));
      });
    // Part of a change: told once it's kept, and not at all if it isn't.
    if (pending) pending.push(tell);
    else tell();
  };
  /** What waits for the change being made (atomically) to be kept: its events, and emptying the WAL. */
  let pending: (() => void)[] | null = null;
  /**
   * Runs `change` as one transaction, so another process sharing the file sees all of it or none, and can't write
   * between two of its statements: waiting first, as any write does, for one that's writing. Never inside one the app
   * opened (its rollback would undo the change after its events were told), and no limit is counted inside (the
   * limits refuse to), as a refusal would undo its own count.
   */
  const atomically = <T>(change: () => T): T => {
    if (pending) return change();
    if (db.isTransaction) throw new Error(IN_TRANSACTION);
    db.exec("BEGIN IMMEDIATE");
    const after: (() => void)[] = [];
    pending = after;
    try {
      const result = change();
      db.exec("COMMIT");
      pending = null;
      for (const run of after) run();
      return result;
    } catch (error) {
      pending = null;
      db.exec("ROLLBACK");
      throw error;
    }
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
  // CODES_A_DAY codes typed for one address a day, from anywhere, account or not: a 6-digit code's guesses stay few, for a year as
  // for a day. Only codes pause; links and passkeys still work.
  const codesPerAddress = limit("codes", CODES_A_DAY, DAY);
  /** Counts a try from an address with `each`, and from its IPv6 /48 (if it has one) with `inBlock`. */
  const andBlock = (each: Limit, inBlock: Limit) => (from: string) => {
    each(from);
    const block = blockOf(from);
    if (block) inBlock(block);
  };
  const countFrom = andBlock(perAddress, perBlock);
  /** A link asked for (from has been checked by fromWhere). */
  const countLinkFrom = andBlock(linksFrom, linksFromBlock);
  /** The asking browser's token, where sign-in links have codes: a mistake in the app's code without one. */
  const askerOrRefuse = (asker: string | undefined): string => {
    if (typeof asker !== "string" || !LINK_TOKEN.test(asker)) {
      throw new Error("With codes, requestLink needs the asking browser's token (asker): newAsker() makes one, and codeCookie gives it to the browser.");
    }
    return asker;
  };
  const fromWhere = (from: string) => {
    // Without an address, everyone would share one allowance: that's a mistake in the calling code.
    if (typeof from !== "string" || !ADDRESS.test(from)) throw new Error("from must be where the request came from, as addressKey gives it.");
    countFrom(from);
  };
  /**
   * Counts a link of `kind` to `email` (and, given, for the account `userId`); false, quietly, past the limit, so the
   * answer is the same either way.
   */
  const inboxHasRoom = (kind: LinkKind, email: string, userId = "") => {
    try {
      perInbox(`${kind}\0${userId}\0${email}`);
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
  /** Every passkey of the account goes, and every challenge it was given: after a reset, whoever got in may have added their own. */
  const forgetPasskeys = (userId: string) => {
    db.prepare("DELETE FROM auth_passkeys WHERE user = ?").run(userId);
    endChallenges(userId);
  };
  /** Challenges given to the account to add a passkey, not yet used: they end when anything about how it's reached changes. */
  const endChallenges = (userId: string) => void db.prepare("DELETE FROM auth_challenges WHERE user = ?").run(userId);

  type UserRow = { id: string; email: string; password: string | null; stamp: string };
  /** A link's options: whether it can be opened (else why not, for its message), whether there's an account there, and whose it is. */
  type LinkOptions = { refused?: Refusal | undefined; account?: boolean; of?: { id: string }; newEmail?: string; asker?: string };
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
   * Every link of the account `userId` ends, and every link to its address that's no other account's: once one is
   * used, or the password or email changes, or the account goes. Another account's move to the address is left to fail
   * on its own, so how long it lasts can't show whether the address has an account.
   */
  const endLinks = (email: string, userId: string) =>
    void db.prepare("DELETE FROM auth_links WHERE user = ? OR (email = ? AND user IS NULL)").run(userId, email);
  type LinkRow = { kind: LinkKind; email: string; user: string | null; expires: number; newEmail: string | null };
  /**
   * A live link of one of `kinds` (never "none": those are stored only to do the same work), by its token: looked
   * at (`take` false) or used, once only (`take` true). "invalid-link" if there's none.
   */
  const findLink = (token: string, kinds: LinkKind[], take: boolean): LinkRow => {
    if (typeof token !== "string" || !LINK_TOKEN.test(token)) throw EXPIRED();
    const which = `token = ? AND kind IN (${kinds.map(() => "?").join(", ")}) AND expires > ?`;
    const columns = "kind, email, user, expires, new_email AS newEmail";
    const sql = take ? `DELETE FROM auth_links WHERE ${which} RETURNING ${columns}` : `SELECT ${columns} FROM auth_links WHERE ${which}`;
    const row = db.prepare(sql).get(tokenHash(token), ...kinds, Date.now()) as LinkRow | undefined;
    if (!row) throw EXPIRED();
    return row;
  };
  /** Uses a link of `kind`, once only, for an address the app still allows. */
  const takeLink = (token: string, kind: LinkKind) => {
    const link = findLink(token, [kind], true);
    if (!allowed(link.email)) throw EXPIRED();
    return link;
  };
  /** Uses the link whose stored hash is `hash` (a code's), as takeLink does a token's. */
  const takeLinkByHash = (hash: string, kind: LinkKind): LinkRow | undefined => {
    const link = db
      .prepare("DELETE FROM auth_links WHERE token = ? AND kind = ? AND expires > ? RETURNING kind, email, user, expires, new_email AS newEmail")
      .get(hash, kind, Date.now()) as LinkRow | undefined;
    // For an address the app no longer allows, the change is undone, as for its link: the link waits, unused.
    if (link && !allowed(link.email)) throw WRONG_CODE();
    return link;
  };
  /**
   * Signs in by a sign-in link, opened or its code typed, as part of a change. Where they aren't how people sign in
   * day to day, one into an account is only ever the way back in: a fresh start, so a thief's passkeys and sessions
   * don't outlast it. Where they are, the person can choose one (`reset`).
   */
  const useSignIn = (link: LinkRow, reset: boolean, from: string) => {
    // Where there are passwords, accounts are made by password links, not sign-in links.
    if (link.user === null && passwords) throw EXPIRED();
    return settle(link.email, link.user, null, reset || !everyday, from);
  };
  /** A code's sign-in: one the link itself couldn't make (a sign-up where accounts come by password) answers as a wrong code. */
  const attempt = <T>(signIn: () => T): T => {
    try {
      return signIn();
    } catch (error) {
      if (error instanceof AuthError && error.code === "invalid-link") throw WRONG_CODE();
      throw error;
    }
  };
  /** The account a link moves, which must still be there. */
  const accountOf = (link: LinkRow) => {
    const row = link.user ? userRow("id", link.user) : undefined;
    if (!row) throw EXPIRED();
    return row;
  };
  /**
   * The account a link opens, as part of a change (atomically). A link made for an account (`account`, its id) opens
   * only that one, still at the link's address. A link made for none (a sign-up) only makes a new account, so one
   * that turns up at the address meanwhile isn't opened. With `password`, or `reset`, it's a fresh start: a new
   * stamp, the new password (or, for a reset, none), and every session, link, and passkey of the account ends, so
   * whatever anyone else added goes. Otherwise (signing in by link) the account is left as it is.
   */
  const settle = (email: string, account: string | null, password: string | null, reset: boolean, from: string): User & { made: boolean; stamp: string } => {
    const row = userRow("email", email);
    if (account === null) {
      if (row) throw EXPIRED();
      const id = randomUUID();
      const stamp = newStamp();
      db.prepare("INSERT INTO auth_users (id, email, password, stamp, created) VALUES (?, ?, ?, ?, ?)").run(id, email, password, stamp, Date.now());
      endLinks(email, id);
      emit("account-made", { userId: id, from });
      return { id, email, made: true, stamp };
    }
    if (row?.id !== account) throw EXPIRED();
    if (password === null && !reset) {
      endLinks(email, row.id);
      return { id: row.id, email, made: false, stamp: row.stamp };
    }
    const stamp = startAfresh(row.id, email, password);
    emit(password === null ? "account-reset" : "password-changed", { userId: row.id, from });
    return { id: row.id, email, made: false, stamp };
  };
  /**
   * A fresh start, as part of a change: a new stamp and `password` (none, for a reset: whoever else got in may have
   * set one), and every session, link, and passkey of the account ends, so whatever anyone else added goes. The new
   * stamp.
   */
  const startAfresh = (userId: string, email: string, password: string | null): string => {
    const stamp = newStamp();
    db.prepare("UPDATE auth_users SET password = ?, stamp = ? WHERE id = ?").run(password, stamp, userId);
    afterNewPassword(userId, email);
    forgetPasskeys(userId);
    return stamp;
  };
  /**
   * A new link of `kind` to `email`, stored as its hash, to send. `refused`: one that does nothing (stored only so
   * the work is the same either way), given with no token, and why, for its message. With `of`, it's that
   * account's own (one into it, or a move it asked for); `newEmail`, where a move goes.
   */
  const newLink = (kind: LinkKind, email: string, { refused, account = true, of, newEmail, asker }: LinkOptions = {}): Link =>
    // The link and its code, together or not at all
    atomically(() => {
      const token = newToken();
      const expires = linkExpires(kind);
      db.prepare("INSERT INTO auth_links (token, kind, email, expires, user, new_email) VALUES (?, ?, ?, ?, ?, ?)").run(
        tokenHash(token),
        refused ? "none" : kind,
        email,
        expires,
        of?.id ?? null,
        newEmail ?? null,
      );
      const base = { kind, to: email, account, expires, ...(newEmail === undefined ? {} : { newEmail }) };
      // A code only on a sign-in link someone asked for (a browser holding its asker): not on one the app makes. One
      // that does nothing gets one too, under its asker, so typing at it does the same work as at a real one.
      const code = asker !== undefined && kind === "sign-in" && codes ? newCode(token, asker, email, expires) : undefined;
      if (refused) return { ...base, token: null, refused };
      return code === undefined ? { ...base, token } : { ...base, token, code };
    });
  /**
   * A sign-in link's code, stored under the asking browser's token: both only as hashes, the code with the asker's.
   * It lasts as long as its link was made to, whatever happens to the link meanwhile, so typing at it does the same
   * work until then: whether the link has been used, or ended, shows nothing.
   */
  const newCode = (token: string, asker: string, email: string, expires: number) => {
    const code = String(randomInt(0, 1_000_000)).padStart(6, "0");
    try {
      db.prepare("INSERT INTO auth_codes (asker, link, email, expires, code) VALUES (?, ?, ?, ?, ?)").run(
        tokenHash(asker),
        tokenHash(token),
        email,
        expires,
        codeHash(asker, code),
      );
    } catch (error) {
      if (String(error).includes("UNIQUE")) throw new Error("That asker has been used: make a new one for each request, with newAsker().");
      throw error;
    }
    return code;
  };
  /**
   * A link someone asked to have sent to `email`: counted against that inbox (null, quietly, past its limit), and
   * stored either way, so the work is the same whatever the answer; null, too, for an address the app doesn't
   * allow, whose link does nothing.
   */
  const offer = (kind: LinkKind, email: string, options: LinkOptions) => {
    const allows = allowed(email);
    // Past the inbox's limit: nothing sent, but a link that does nothing is still stored, so the work is the same.
    // A move to an address counts by the account moving too, so one account's can't use up another's.
    if (!inboxHasRoom(kind, email, kind === "email" ? options.of?.id : undefined)) {
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
  /** A new stamp, for a change to how the account is reached that a session asked for: only while it's still `stamp`. */
  const restamp = (userId: string, stamp: string) => {
    if (db.prepare("UPDATE auth_users SET stamp = ? WHERE id = ? AND stamp = ?").run(newStamp(), userId, stamp).changes === 0) throw SIGN_IN_AGAIN();
    endChallenges(userId);
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
   * (`wait` false: not waiting at all). Best effort, never failing the request: if another process is reading, or
   * the app is part-way through a query on this connection (it may be the app's connection too), it's tried again at
   * every clearing until it's done. The app's own busy_timeout is left as it was.
   */
  const flush = (wait = true) => {
    unflushed = true;
    // Part of a change: once it's kept.
    if (pending) return void pending.push(() => flush(wait));
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
    // Codes hold emails too, and last as their links were made to.
    const codesCleared = db.prepare("DELETE FROM auth_codes WHERE asker IN (SELECT asker FROM auth_codes WHERE expires <= ? LIMIT 2000)").run(now).changes;
    if (cleared || codesCleared || unflushed) flush(false);
  };

  const auth: Auth = {
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

    endAccess(given) {
      const email = emailOrRefuse(given);
      return atomically(() => {
        const row = userRow("email", email);
        if (!row) return false;
        startAfresh(row.id, email, null);
        // Told as an event, so the app has a record of it.
        emit("access-ended", { userId: row.id });
        return true;
      });
    },

    requestLink(kind, given, from, asker) {
      if (kind === "password") needs("password");
      else if (kind !== "sign-in") throw new Error('kind must be "password" or "sign-in" (an email link comes from requestEmailChange).');
      else needsSignInLinks();
      fromWhere(from);
      countLinkFrom(from);
      const email = emailOrRefuse(given);
      sweep(Date.now());
      // Looked up allowed or not: the same work whatever the answer.
      const here = userRow("email", email);
      // With no account, only the kind that makes one has anything to open; into an existing account, only where
      // anyone may ask for one: where only the app may, the message says the account signs in by passkey.
      const refused = here ? (recovery === "link" ? undefined : "passkey-only") : kind === makes ? undefined : "no-account";
      return offer(kind, email, {
        refused,
        account: !!here,
        ...(kind === "sign-in" && codes ? { asker: askerOrRefuse(asker) } : {}),
        ...(here && !refused ? { of: { id: here.id } } : {}),
      });
    },

    lookUpLink(token, from) {
      fromWhere(from);
      const { kind, email, newEmail } = findLink(token, linkKinds, false);
      return { kind, email: newEmail ?? email };
    },

    async usePasswordLink(token, password, from) {
      needs("password");
      checkHashingFree();
      fromWhere(from);
      // Looked at first, but only used once the password will do: a password refused doesn't use up the link.
      const looked = findLink(token, ["password"], false);
      const hashed = await newPassword(password, looked.email);
      const { stamp, ...user } = atomically(() => {
        const link = takeLink(token, "password");
        return settle(link.email, link.user, hashed, false, from);
      });
      return handOver(user, stamp, "link", from);
    },

    useSignInLink(token, from, { reset = false } = {}) {
      needsSignInLinks();
      fromWhere(from);
      const { stamp, ...user } = atomically(() => {
        const link = takeLink(token, "sign-in");
        return useSignIn(link, reset, from);
      });
      return handOver(user, stamp, "link", from);
    },

    useSignInCode(asker, code, from) {
      if (!codes) throw new Error('This site doesn\'t sign in with codes: add "code" to signInWith first.');
      fromWhere(from);
      if (typeof asker !== "string" || !LINK_TOKEN.test(asker) || typeof code !== "string" || !CODE.test(code)) throw WRONG_CODE();
      const hashed = tokenHash(asker);
      // The code alone, not its link: a code lasts as its link was made to, used or not, so the work here is the
      // same until then whatever has happened to the link (or the account) meanwhile.
      const found = db.prepare("SELECT link, code, email FROM auth_codes WHERE asker = ? AND expires > ?").get(hashed, Date.now()) as
        | { link: string; code: string; email: string }
        | undefined;
      // Counted for the address, right or wrong, before it's checked (and outside the change, as every limit is):
      // guesses spread over many codes count together. A link that does nothing has a code too, counted the same.
      // Past the day's, answered as a wrong code: a pause would show that codes were typed at the address today,
      // the owner's own perhaps.
      let capped = false;
      if (found) {
        try {
          codesPerAddress(found.email);
        } catch (error) {
          if (!(error instanceof AuthError && error.code === "too-many-tries")) throw error;
          capped = true;
        }
      }
      // One change, the same past the cap as before it (so how many were typed today shows nothing): a try taken
      // (so tries sent all at once can't share one), the code compared, and then, if it's right and not capped, the
      // link used. Past CODE_TRIES no try is taken, and nothing is right.
      const signedIn = attempt(() =>
        atomically(() => {
          if (!found) return null;
          const taken = db.prepare("UPDATE auth_codes SET tries = tries + 1 WHERE asker = ? AND tries < ? RETURNING tries").get(hashed, CODE_TRIES) as
            | { tries: number }
            | undefined;
          if (!taken) return null;
          if (!timingSafeEqual(Buffer.from(codeHash(asker, code)), Buffer.from(found.code)) || capped) return null;
          const link = takeLinkByHash(found.link, "sign-in");
          if (!link) return null;
          db.prepare("DELETE FROM auth_codes WHERE asker = ?").run(hashed);
          return useSignIn(link, false, from);
        }),
      );
      if (!signedIn) throw WRONG_CODE();
      const { stamp, ...user } = signedIn;
      return handOver(user, stamp, "code", from);
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
      // Its own links (its moves shown as such whatever they were stored as, so the copy can't show whether another
      // address has an account), and those to its address that do something.
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
      const email = atomically(() => {
        const done = db
          .prepare(
            "UPDATE auth_users SET password = ?, stamp = ? WHERE id = ? AND stamp = ? AND EXISTS (SELECT 1 FROM auth_sessions WHERE token = ? AND user = id) RETURNING email",
          )
          .get(hashed, stamp, row.id, row.stamp, row.hashed) as { email: string } | undefined;
        if (!done) throw SIGN_IN_AGAIN();
        afterNewPassword(row.id, done.email);
        emit("password-changed", { userId: row.id, from });
        return done.email;
      });
      return handOver({ id: row.id, email }, stamp, "password", from);
    },

    requestEmailChange(session, given, from) {
      const row = recent(session, from);
      countLinkFrom(from);
      const email = emailOrRefuse(given);
      if (email === row.email) throw new AuthError("invalid-email", "That's the account's email already.");
      // To the address it has first: nothing goes to the new one until whoever reads this one approves.
      return offer("move", row.email, { of: { id: row.id }, newEmail: email });
    },

    approveEmailChange(token, from) {
      fromWhere(from);
      const link = takeLink(token, "move");
      // Moved meanwhile, or gone: the approval was for an address it no longer has.
      const row = accountOf(link);
      if (row.email !== link.email || !link.newEmail) throw EXPIRED();
      // Then, as for any link asked for, one to the new address. To an address with an account already, one that does
      // nothing, and a message saying so: the same answer, and work, either way.
      const taken = !!userRow("email", link.newEmail);
      return offer("email", link.newEmail, { refused: taken ? "email-in-use" : undefined, account: taken, of: { id: row.id } });
    },

    useEmailLink(token, signedIn, from) {
      fromWhere(from);
      // Only by the account it moves, signed in where it's opened: checked before the link is used up.
      if (findLink(token, ["email"], false).user !== signedIn) throw EXPIRED();
      return atomically(() => {
        const link = takeLink(token, "email");
        const row = accountOf(link);
        // Taken by another account meanwhile: nothing to move.
        if (userRow("email", link.email)) throw EXPIRED();
        db.prepare("UPDATE auth_users SET email = ?, stamp = ? WHERE id = ?").run(link.email, newStamp(), row.id);
        endAllSessions(row.id);
        endLinks(row.email, row.id);
        endLinks(link.email, row.id);
        flush();
        emit("email-changed", { userId: row.id, from });
        return { id: row.id, email: link.email, previous: row.email };
      });
    },

    deleteAccount(session, from) {
      const row = recent(session, from);
      atomically(() => {
        const done = db.prepare("DELETE FROM auth_users WHERE id = ? AND stamp = ?").run(row.id, row.stamp);
        if (done.changes === 0) throw SIGN_IN_AGAIN();
        endLinks(row.email, row.id);
        // The address is wiped from its codes, which last to their time (so a try at one does the same work, and shows
        // nothing of the deletion): nothing names the account, or the address, afterwards.
        db.prepare("UPDATE auth_codes SET email = ? WHERE email = ?").run(newToken(), row.email);
        flush();
        emit("account-deleted", { userId: row.id, from });
      });
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
      const passkey: Passkey = { id: checked.id, name: isPasskeyName(name) ? name : "Passkey", created: Date.now(), lastUsed: null };
      return atomically(() => {
        takeChallenge(checked.challenge, "add", row.id);
        restamp(row.id, row.stamp);
        // A passkey's id is the device's: one already here (this account's or another's) isn't taken again.
        const stored = db
          .prepare(
            "INSERT INTO auth_passkeys (id, user, public_key, algorithm, counter, name, created) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (id) DO NOTHING",
          )
          .run(passkey.id, row.id, checked.publicKey, checked.algorithm, checked.counter, passkey.name, passkey.created);
        if (stored.changes === 0) throw BAD_PASSKEY();
        emit("passkey-added", { userId: row.id, from });
        return passkey;
      });
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
      return atomically(() => {
        const passkey = passkeysOf(row.id).find((p) => p.id === id);
        if (!passkey) return null;
        restamp(row.id, row.stamp);
        db.prepare("DELETE FROM auth_passkeys WHERE id = ? AND user = ?").run(id, row.id);
        // Every other session ends: one the passkey started (a thief's, say) mustn't carry on, still recent, and add another.
        db.prepare("DELETE FROM auth_sessions WHERE user = ? AND token != ?").run(row.id, row.hashed);
        emit("passkey-removed", { userId: row.id, from });
        return passkey;
      });
    },
  };
  // Every call refused inside a transaction the app opened on this connection: its rollback would undo what was done
  // (a sign-out reported done, then undone) and the limits' counts.
  return new Proxy(auth, {
    get(target, key, receiver) {
      const value: unknown = Reflect.get(target, key, receiver);
      if (typeof value !== "function") return value;
      // An async one rejects, as its callers await it; any other throws.
      const async = Object.prototype.toString.call(value) === "[object AsyncFunction]";
      return (...args: unknown[]) => {
        if (!db.isTransaction) return Reflect.apply(value, target, args);
        const refusal = new Error(IN_TRANSACTION);
        if (async) return Promise.reject(refusal);
        throw refusal;
      };
    },
  });
}
