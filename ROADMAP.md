# Roadmap

Each step adds as little as it can, and lands with tests for every security property
it brings. Nothing here is a promise of a date.

## Now: the core (0.x, unreleased)

- [x] Accounts: email and password
- [x] Passwords: scrypt at OWASP's cost, constant-time checks, hashing a few at a time, sized to the machine
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

- [x] **Password reset and email confirmation.** Single-use, short-lived, hashed
      tokens, sent by a function the app supplies (now `deliver(message)`: any
      email service, called over HTTPS: no SDK). Email confirmation also lets sign-up
      stop saying which emails have accounts.
- [x] **Changing an email address,** confirmed by email, ending every other session.
- [x] **A copy of someone's data on request** (UK GDPR).
- [x] **A record of security events** (sign-ins, failures, pauses, password changes)
      the app can keep, without passwords or tokens in it.
- [x] **Signing in by an emailed link,** always offered beside the password: single-use,
      short-lived, and limited per address, so someone whose sign-in is paused by
      another's guessing can still get in.
- [x] **Seeing and ending single sessions** (ASVS Level 2).
- [x] **Telling people when their password changes,** by email (ASVS Level 2).
- [x] **Checking new passwords against a full breached-password set** (ASVS Level 2),
      through a function the app supplies, so modest-auth itself still makes no network calls.

## Sign-in methods (0.6.0)

- [x] **How people sign in is the site's choice,** and must be made (`signInWith`): a
      link alone, or a password and a link. A password never comes without a link,
      which is how someone who forgets it gets back in. A method not chosen is off
      entirely: no routes, and its functions refuse.
- [x] **One stamp per account,** replaced whenever how it's reached changes, so every
      "only if nothing changed meanwhile" check is one rule.
- [x] **Changes need a recent sign-in,** by any method, instead of the password: the
      same rule whatever the site's methods.
- [x] **`allow`:** who may have an account, if not everyone. It can only refuse.
- [x] **Messages as data,** for the app to deliver however it likes (any email service,
      its own words, any language), with `emailFor` for modest-auth's own.

## Next: passkeys

Sign-in that can't be phished (WebAuthn), as a third method beside links and
passwords, before the audit so the audit covers it. No dependency: everything a server
checks is in `node:crypto`, given no attestation (which says what device made a key,
and is for organisations that only allow certain hardware; synced passkeys mostly can't
give one).

- [ ] **The checks,** in their own file, step by step as the WebAuthn spec numbers them,
      with a strict CBOR reader for just the shapes passkeys use, and keys of three
      algorithms (EdDSA, ES256, RS256 of 2048 bits or more).
- [ ] **Passkeys stored:** public keys only, ids unique across every account.
- [ ] **Challenges** single-use, short-lived, kept apart by kind, and stored hashed.
- [ ] **Adding (after a recent sign-in), signing in without an email, listing, and
      removing,** each told to the account's address. An undone move removes every
      passkey.
- [ ] **Tests** with real keys of each algorithm, recorded answers from real
      authenticators, and the reader fuzzed.
- [ ] **Each account's own methods,** and then **passkeys only,** for an account that
      chooses it.

## Before 1.0

- [ ] A paid, independent security audit of a release candidate, and its findings fixed
- [ ] A requirement-by-requirement check against OWASP ASVS 5.0 (authentication and
      sessions), in `docs/asvs.md`
- [ ] Two sites using it in production
- [ ] Published to npm with provenance; GitHub's private vulnerability reporting on
- [ ] The public API settled: from 1.0, breaking changes only in major versions

## Later, maybe, one at a time

Each only if it can be made as small and certain as the rest, and kept optional
without becoming a plugin system.

- **One sign-in for several sites** on different domains: the smallest useful part of
  OpenID Connect (authorisation code with PKCE, one registered client per site), so
  each site can use any standard library.
- **Two-step sign-in** with an authenticator app (TOTP): the step to ASVS Level 2 and
  NIST AAL2, for sites that keep passwords. Passkeys are the stronger way there.
- **Other contacts:** a phone number, or push notifications once there's a standard,
  beside email: another kind of `Contact`, and messages delivered by text or push. Each
  needs its own rows in the threat model first: a SIM swap gives away a number, so a
  number is only as safe as its carrier; a code typed from a text can be phished and
  guessed, so it needs few tries and short lives, and to work only where it was asked
  for; texts cost money, so attackers send them to premium numbers they own, which needs
  limits by number range and country; and prompts to approve a sign-in get approved by
  people worn down by them.
- **More sign-ins at once,** for a site with a few thousand people signing in around
  the same time. Checking a session is already cheap; a password sign-in is costly by
  design (about 170 ms and 130MB each; from 0.5.0, as many at once as the machine's
  cores, memory, and thread pool allow). First a benchmark anyone can run, with
  published numbers; then several processes sharing one database, tested and
  documented. Never by lowering the hashing cost.

## Never

- JWT sessions
- A plugin or hook system
- Database adapters, or an ORM
- Configuration that makes it less secure
