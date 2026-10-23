// modest-auth: simple, effective authentication for Node, with no dependencies.
// Everything public is here; see README.md for how the pieces fit.

export { createAuth, IDLE_DAYS, PASSWORD_LINK_MINUTES, SESSION_DAYS, SIGN_IN_LINK_MINUTES, UNDO_DAYS, type Auth, type Link, type LinkKind, type User } from "./auth.ts";
export { clearedCookie, readSessionCookie, sessionCookie } from "./cookies.ts";
export { cleanEmail } from "./emails.ts";
export { AuthError, type AuthErrorCode } from "./errors.ts";
export { createHandler, type Handler, type HandlerOptions } from "./handler.ts";
export { addressKey, type ClientAddress } from "./limits.ts";
export { handleNode, toRequest } from "./node.ts";
export { LONGEST_PASSWORD, SHORTEST_PASSWORD } from "./passwords.ts";
