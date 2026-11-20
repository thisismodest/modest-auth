// modest-auth: simple, effective authentication for Node, with no dependencies.
// Everything public is here; see README.md for how the pieces fit.

export {
  type AccountData,
  type Auth,
  type AuthEvent,
  type AuthOptions,
  CODE_TRIES,
  CODES_A_DAY,
  type Contact,
  createAuth,
  EMAIL_LINK_MINUTES,
  IDLE_DAYS,
  type Link,
  type LinkKind,
  type NewPasskey,
  newAsker,
  PASSKEY_MINUTES,
  PASSWORD_LINK_MINUTES,
  type Passkey,
  type PasskeyAssertion,
  type PasskeyCreationOptions,
  type PasskeyRequestOptions,
  RECENT_MINUTES,
  type Refusal,
  SESSION_DAYS,
  type Session,
  SIGN_IN_LINK_MINUTES,
  type SignInMethod,
  type User,
} from "./auth.ts";
export { clearedCodeCookie, clearedCookie, codeCookie, readCodeCookie, readSessionCookie, sessionCookie } from "./cookies.ts";
export { cleanEmail } from "./emails.ts";
export { AuthError, type AuthErrorCode } from "./errors.ts";
export { createHandler, type Handler, type HandlerOptions } from "./handler.ts";
export { addressKey, type ClientAddress } from "./limits.ts";
export { emailFor, type Message, messageFor, type Site } from "./messages.ts";
export { handleNode, toRequest } from "./node.ts";
export { HASHING, LONGEST_PASSWORD, SHORTEST_PASSWORD } from "./passwords.ts";
