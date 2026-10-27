# Changelog

Every change that affects how it's used, or what it promises. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## Unreleased

### Changed

- Password hashing is sized to the machine, not fixed at two at a time: no more hashes
  at once than its cores, than fit in half the memory the process may use (a
  container's limit, if there is one), or than Node's thread pool less two (so file
  reads and DNS lookups always keep a thread), from 1 to 16. The queue is 25 for each.
  Most small servers still hash 2 at once; a single core hashes 1 (as fast, with half
  the memory). For more, raise `UV_THREADPOOL_SIZE` before Node starts.

### Added

- `HASHING`: how many hashes run at once on this machine, and how many may wait,
  beyond which a sign-in is refused as busy.

### Fixed

- The Node adapter's own failure answer (a 500) has every other answer's headers,
  `x-content-type-options: nosniff` included.

## [0.4.1] - 2026-10-27

### Fixed

Found by scenario tests written from the README and threat model alone, by a reviewer
who didn't see the code (`test/scenarios/`, `docs/scenarios.md`).

- A common password made only of digits, with numbers added on the end (such as
  `1234567890123452024`), is refused, as the README promised. Before, taking the
  trailing numbers off left nothing to compare.
- Only `application/json` is taken (with a charset, or none): `application/jsonx`,
  two types run together, and two `Content-Type` headers are refused. Before, any type
  starting `application/json` was taken, and Node kept only the first of two headers.
  A browser asks before sending any of these from another site, so they were never a
  way round the Origin check.
- The `signed-out`, `signed-out-everywhere`, and `session-ended` events say where they
  came from, as every event does. `endSession`, `endAllSessions`, and `endSessionOf`
  take it as an optional last argument.
- Emails not sent (a full queue, or a failing email service) are logged at most 5 times
  a minute, with a count of the rest, so a flood can't fill the log.
- The README says plainly that using a link ends the address's other links, and that
  asking for too many links is answered `429`.

## [0.4.0] - 2026-10-26

### Added

- **A name for the site's emails:** `createHandler`'s optional `name`, such as
  `"Ware Business Club"`. Subjects use it, and the text gives it with the site's
  address ("Ware Business Club (example.org)"), so an email still says where it's from.
  Without it, emails are as before. A name that could add a line to an email, or hide
  text, is refused when the handler is made.

## [0.3.0] - 2026-10-24

Nothing to get quietly wrong: what can be set wrong now is safe when left out, and says
in the log what to set.

### Changed

- **Proxies are named, not counted.** `proxies` is gone (passing it says what replaced
  it): name the proxies in front in `trustedProxies` instead, as `["loopback"]` (nginx or
  Caddy on the same machine), `["private"]` (a hosting platform's load balancer), a
  CDN's ranges, or addresses. `X-Forwarded-For` is read from the right past however
  many named proxies there are, on any path, to the first address that isn't one.
  Nothing named is safe (visitors share the proxy's address), and the log says what to
  set: a proxy passing addresses that isn't named, or (on an HTTPS site) one in front
  passing none. On a Unix socket, `["loopback"]` covers the proxy in front. Ranges
  wide enough to be much of the internet are refused. `addressKey(client,
  trustedProxies?)` takes the list in place of a count.
- The development cookie's name has the port in it, so two apps on localhost don't sign
  each other out (signing out development sessions once).
- `sendEmail` is given `{ signal }`, which aborts after 30 seconds, and a send is let go
  of then whether or not it stops (and that's logged), so a stuck email service can't
  hold up the others.
- `breachedRange` is given `{ signal }` too, and may give the fetch `Response` itself;
  one that isn't OK counts as a failed check (the password is allowed, and that logged)
  rather than as an empty range. It's read to 1MB at most, and let go of at 5 seconds.

### Added

- Setup mistakes said in the log, a few times at most: an `origin` that isn't where the
  site's pages are (`www.`, or a port); a handler given no address, or one that isn't an
  address (with how, for Node, Bun, Deno, and Hono); and the proxy cases above. An
  `origin` that isn't an address says so.
- A body read before the handler (a body parser mounted in front of it) is an error
  that says so, rather than a request with no fields.

## [0.2.0] - 2026-10-24

Emailed links, changing an account's email (with an undo), notices, single
sessions, a record of events, breached passwords refused, and a copy of an
account's data. Sign-up is now email first, which changes the routes and
`createHandler`'s options: see Changed and Removed.

### Added

- A copy of an account's data for its owner: `GET /auth/my-data`, and `dataOf`.
- `createAuth(db, { onEvent, breachedRange })`: a record of events (no passwords,
  tokens, or emails in it), and new passwords checked against a breached-password set
  through a 5-character hash prefix. A `breached-password` error.
- Seeing and ending single sessions: `GET /auth/sessions` and `POST /auth/end-session`;
  `sessionsOf` and `endSessionOf`.
- Changing an account's email: `POST /auth/change-email` (signed in, with the
  password) emails a link to the new address, and `POST /auth/confirm-email`, opened
  where the account is signed in, moves it and ends every session. The old address is
  told, with a link (`POST /auth/undo-email`, for 7 days) that moves it back, signs
  everyone out, and makes the password useless; a link to choose a new one follows.
- Notices: an email when an account's password changes, and to the old address when
  its email does.
- `requestEmailChange`, `useEmailLink`, `useUndoLink`, `UNDO_DAYS`; `usePasswordLink`
  says whether it `made` the account.
- Emailed links. `POST /auth/send-password-link` emails a link to choose a password,
  which makes the account, or replaces a forgotten password (signing out everywhere
  else); `POST /auth/send-sign-in-link` emails a link to sign in, always offered beside
  the password, so someone paused by another's guessing can still get in. Links are
  single-use, kept only as hashes, last 60 and 15 minutes, and carry the token after
  `#`. `POST /auth/link` says which email a link is for, so the page it opens can show
  it before anything happens.
- Limits on links: 3 of each kind to one address in 15 minutes (quietly), and 5 asked
  for from one address and 20 from one IPv6 /48.
- `requestLink`, `lookUpLink`, `usePasswordLink`, and `useSignInLink` for apps using
  the parts; `PASSWORD_LINK_MINUTES` and `SIGN_IN_LINK_MINUTES`.
- An `invalid-link` error.

### Changed

- A session starts only while the account still has the email, as well as the
  password, that was checked.
- Sign-up is email first: an account is made only by a link emailed to the address,
  so nobody can sign up with someone else's email, and sign-up no longer says whether
  an email has an account.
- `createHandler` needs `linkPage` (the app's page that links open) and `sendEmail`
  (how the app sends email).
- Emails with a local part starting `-` or `|` are refused.
- The WAL is also emptied after old links are cleared, without waiting; and emptying
  it never fails a request (if it can't finish, it's tried again later).

### Removed

- `POST /auth/sign-up`, `auth.signUp`, and the `email-taken` error: sign up with a
  password link instead.

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
