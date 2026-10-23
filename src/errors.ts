// What went wrong, in a form an app can act on: a stable code to check, the
// HTTP status that fits, and a message fit to show the person signing in.

export type AuthErrorCode =
  /** Not an email address. */
  | "invalid-email"
  /** Shorter than SHORTEST_PASSWORD. */
  | "short-password"
  /** Longer than LONGEST_PASSWORD (refused before hashing: a huge one would tie the server up). */
  | "long-password"
  /** Too easy to guess: a common password, or made from the email, or with fewer than four different characters. */
  | "common-password"
  /** Not valid text (broken Unicode), which can't be stored faithfully. */
  | "invalid-password"
  /** Signing up with an email that already has an account. */
  | "email-taken"
  /** Signing in with a wrong email or password (the same either way). */
  | "wrong-credentials"
  /** Too many tries: wait, then try again. */
  | "too-many-tries"
  /** Too much at once (password hashing is limited): try again in a minute. */
  | "busy";

const STATUS: Record<AuthErrorCode, number> = {
  "invalid-email": 422,
  "short-password": 422,
  "long-password": 422,
  "common-password": 422,
  "invalid-password": 422,
  "email-taken": 409,
  "wrong-credentials": 401,
  "too-many-tries": 429,
  busy: 503,
};

export class AuthError extends Error {
  readonly code: AuthErrorCode;
  readonly status: number;
  /** For "too-many-tries" and "busy": seconds until it's worth trying again. */
  readonly retryAfter: number | undefined;

  constructor(code: AuthErrorCode, message: string, retryAfter?: number) {
    super(message);
    this.name = "AuthError";
    this.code = code;
    this.status = STATUS[code];
    this.retryAfter = retryAfter;
  }
}
