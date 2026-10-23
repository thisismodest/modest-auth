# Roadmap

Each step adds as little as it can, and lands with tests for every security property
it brings. Nothing here is a promise of a date.

## Now: the core (0.x, unreleased)

- [x] Accounts: email and password
- [x] Passwords: scrypt at OWASP's cost, constant-time checks, hashing two at a time
- [x] Sessions: hashed 256-bit tokens, sign out, sign out everywhere
- [x] The session cookie: `__Host-`, `Secure`, `HttpOnly`, `SameSite=Lax`
- [x] Limits per account and address, per account, and per address; IPv6 by /64;
      proxies declared, not guessed
- [x] A working example with Node's own `http` server
- [x] **A request handler** for the Web standard `Request` and `Response`, with the
      `Origin` check built in, and an adapter for Node's `http`
- [x] Changing a password (ending every other session), and deleting an account
- [x] Limits kept in the database: shared between processes, surviving a restart
- [x] Password hashes that record their cost, and are upgraded at sign-in
- [x] Sessions that end after 7 days unused
- [x] New passwords per NIST SP 800-63B, with common passwords refused
- [x] Internal adversarial review: repeated rounds, by AI reviewers each given one area
      (cryptography and sessions, web and HTTP, abuse and supply chain, a lead
      auditor, an exploit developer, a final check), and their findings fixed. Not
      independent.
- [x] A name: modest-auth, on npm, at modest-auth.com

## Next: less for the app to get right

- [ ] **Password reset and email confirmation.** Single-use, short-lived, hashed
      tokens, sent by a `sendEmail(to, subject, text)` function the app supplies (any
      email service, called over HTTPS: no SDK). Email confirmation also lets sign-up
      stop saying which emails have accounts.
- [ ] **Changing an email address,** confirmed by email, ending every other session.
- [ ] **A copy of someone's data on request** (UK GDPR).
- [ ] **A record of security events** (sign-ins, failures, pauses, password changes)
      the app can keep, without passwords or tokens in it.
- [ ] **Gentler ways round an account pause,** such as confirming a sign-in from a new
      address by email.
- [ ] **Seeing and ending single sessions** (ASVS Level 2).
- [ ] **Telling people when their password changes,** by email (ASVS Level 2).
- [ ] **Checking new passwords against a full breached-password set** (ASVS Level 2),
      through a function the app supplies, so modest-auth itself still makes no network calls.

## Before 1.0

- [ ] A paid, independent security audit of a release candidate, and its findings fixed
- [ ] A requirement-by-requirement check against OWASP ASVS 5.0 (authentication and
      sessions), in `docs/asvs.md`
- [ ] Pressday, and one more site, using it in production
- [ ] Published to npm with provenance; GitHub's private vulnerability reporting on
- [ ] The public API settled: from 1.0, breaking changes only in major versions

## Later, maybe, one at a time

Each only if it can be made as small and certain as the rest, and kept optional
without becoming a plugin system.

- **One sign-in for several sites** on different domains: the smallest useful part of
  OpenID Connect (authorisation code with PKCE, one registered client per site), so
  each site can use any standard library.
- **Passkeys** (WebAuthn), if they can be verified without a dependency.
- **Two-step sign-in** with an authenticator app (TOTP): the step to ASVS Level 2 and
  NIST AAL2.

## Never

- JWT sessions
- A plugin or hook system
- Database adapters, or an ORM
- Configuration that makes it less secure
