# Changelog

Every change that affects how it's used, or what it promises. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## Unreleased

## [0.1.0] - 2026-10-23

The first release.

### Added

- Accounts: an email and a password; change the password
  (ending every other session); delete the account.
- Passwords hashed with scrypt at OWASP's cost, salted, compared in constant time, two
  at a time. Each hash records its cost, and an older one is made again at sign-in.
- Sessions: 256-bit tokens, stored only as hashes; 30 days at most, 7 days unused;
  sign out, and sign out everywhere.
- The session cookie: `__Host-`, `Secure`, `HttpOnly`, `SameSite=Lax` over HTTPS.
- Emails normalised (NFKC), with invisible characters, quotes, and brackets refused,
  and checked without any slow pattern.
- Limits on sign-in and sign-up, kept in the database: per account and address, per
  account, and per address; IPv6 counted by /64; `X-Forwarded-For` believed only
  through declared proxies.
- `createHandler`: the routes, for Web-standard `Request` and `Response`, with the
  `Origin` check, JSON-only bodies, and a fresh session at each sign-in built in; and
  `handleNode` for Node's own `http` server.
- `AuthError`, with a code, an HTTP status, and a message to show.
- An example app with Node's own `http` server.
- A website (`site/`): the homepage, docs, and security, plain HTML with no JavaScript.
- New passwords per NIST SP 800-63B: 15 to 200 characters, counted as characters;
  the 5,500 passwords that long in two public lists of common ones refused (from
  SecLists: the UK NCSC's list and another), as are ones made from the email or with
  fewer than four different characters;
  broken Unicode refused.
- Sessions start only if the password that was checked is still the account's, so a
  sign-in racing a password change or a deletion gets nothing.
- The signed-in owner can change the password or delete the account while strangers
  have paused sign-in to it.
- Addresses: ports dropped, IPv6 read as numbers, nonsense counted as unknown.
- `handler.fromSite(request)`, for the app's own routes.
- The Node adapter never throws, whatever a client sends.
- The database is opened for sharing between processes (WAL, a short wait for a
  writer), with deleted rows overwritten.
- Common passwords compared as letters and digits only, and without trailing numbers;
  the email check only for addresses whose name has 6 or more letters and digits.
- Limits: 200 tries per IPv6 /48; the owner's own password checks capped at 10 an
  hour; tries refused as "busy" not counted; old rows cleared in batches.
- `startSession` only for a user whose password was just checked; 50 sessions per
  account at most.
- The WAL emptied into the database file after a deletion or a new password.
- The Node adapter leaves the app's own requests untouched, and only plain paths (no
  `.` or `..` segments, encoded dots or slashes, or backslashes) reach
  its routes.
- Refusals for too many tries, or busy, say when to try again (`Retry-After`), worked
  out from the limit that was reached.
- Starting several processes on a new database file at once: start-up tries again
  while SQLite refuses at once.
- Emails: characters drawn as nothing (variation selectors, fillers, the blank braille
  cell) refused too; domains kept in their ASCII form, and only names (not IP
  addresses, paths, or %-escapes).
- Addresses: an IPv4 address carried in IPv6 (NAT64, IPv4-compatible) counts as that
  IPv4 address; a forwarded address with no proxies declared is warned about once.
- CI: types, tests, build, and `scripts/check-rules.ts` (no runtime dependencies,
  only Node's modules imported in any form, no invisible characters in code, a line
  and character budget); CodeQL for the code and the workflows; OpenSSF Scorecard. A
  release workflow that publishes from a tag on main, with provenance.
