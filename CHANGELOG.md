# Changelog

Every change that affects how it's used, or what it promises. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## Unreleased

## [0.6.0] - 2026-11-20

How people sign in is now the site's choice, passkeys are one of the choices, moving an
account to a new email needs its current address to approve, and messages are data for
the app to send. Several changes break the API; upgrading is below.

### Changed

- **`createAuth` needs `signInWith`:** any of `"link"`, `"password"`, and `"passkey"`,
  each on its own or mixed (`["link", "password"]` is as before). A method not chosen is
  off: without passwords, a sign-in link to an email with no account makes the account,
  and the password routes (`send-password-link`, `set-password`, `sign-in`, `password`)
  aren't there; sign-in link routes are there only where `"link"` is chosen or there are
  no passwords.
- **Getting back in is separate from signing in** (`recovery`): a link to the
  account's email by default (a password link where there are passwords, else a
  sign-in link, opened once to add a passkey). With `signInWith: ["passkey"]`,
  `recovery: "app"` sends no link into an existing account at anyone's asking (the
  inbox gets a `passkey-only` message instead), and `recoveryLink(email)` makes one for
  the app's own code alone. Getting back in by a link is a fresh start: every session,
  link, and passkey of the account ends (a sign-in link's `reset` takes the password
  too).
- **Changing the email, as OWASP advises:** the address the account has approves the
  move first (`approve-email`, `approveEmailChange`, the `approve-email` message), and
  only then does the new address get a link to confirm it. Someone with the password,
  or a session, can't move an account away. The undo link to the old address is gone
  with the need for it.
- **Changing the password or email, or deleting the account, needs a recent sign-in**
  (a session started in the last 10 minutes, `RECENT_MINUTES`), not the password. An
  older session is refused with `403` and the code `sign-in-again`. `changePassword`,
  `requestEmailChange`, and `deleteAccount` take the session's token instead of a user
  id and password; `/auth/password` takes `{ next }`, `/auth/change-email` `{ email }`,
  and `/auth/delete-account` no fields. Nothing asks for the password, so a stolen
  session can't be used to guess it, and the 10 checks an hour by an account's own
  sessions are gone with the checks.
- **`sendEmail` is now `deliver(message, { signal })`:** each message is data (`kind`,
  `to`, and its `link` and `expires`, or the new address for `approve-email`), to send
  however the app likes. `emailFor(message, { origin, name })` writes modest-auth's own
  email for one; the handler's `name` moved there.
- **Every account has a stamp,** replaced when how it's reached changes (a new password,
  a new email, a passkey added or removed). A session starts, a password changes, a
  passkey is added, or an account goes only while the stamp is the one checked.
- **Each change of more than one statement is one transaction,** so another process
  sharing the database waits for it and sees all of it or none; one that fails
  part-way changes nothing, and tells no event. Called inside a transaction the app
  opened on its connection, modest-auth refuses (its rollback would undo the limits).
- A password-only sign-in and a link's session refused for a change meanwhile say so
  as their own way would: a wrong password, or an expired link.
- The per-account limit's pause always says to wait the whole hour, so it doesn't tell
  when someone last tried the email.

### Added

- **Passkeys** (WebAuthn), as a third sign-in method (`signInWith: ["link", "passkey"]`,
  with or without `"password"`), checked with nothing but `node:crypto`: added after a
  recent sign-in, used without typing an email, listed, and removed, each told to the
  account's address (without the passkey's name, which whoever added it chose).
  Routes `passkey-options`, `add-passkey`, `sign-in-options`, `sign-in-with-passkey`,
  `passkeys`, and `remove-passkey`; functions `passkeyOptions`, `addPasskey`,
  `signInOptions`, `signInWithPasskey`, `passkeysOf`, and `removePasskey`; the error
  code `invalid-passkey`; the events `passkey-added` and `passkey-removed`; and the
  messages of the same names. Removing a passkey signs every other session out.
  `useSignInLink`'s `reset` option (`reset: "true"` at `sign-in-with-link`) makes a
  sign-in link a fresh start on a site that signs in by link, for someone who has lost
  a passkey.
- `allow(contact)`: who may have an account, if not everyone. Asked before a link is
  sent or used, an account made, or a session started or used, so someone the app stops
  allowing is signed out at their next request, for good. It can only refuse; a mistake
  in it is a refusal. A refused address is answered as any other and sent nothing.
- `Message`, `Site`, `Contact`, `SignInMethod`, `RECENT_MINUTES`, `emailFor`,
  `messageFor` (a link's message, for apps using the parts), `recoveryLink`,
  `approveEmailChange`, `Refusal` (why a link asked for has nothing to open, on the
  link itself), `auth.signInLinks`, and `auth.signInWith`.
- The events `account-reset` (a fresh start by link) and `recovery-link-made`.
- A notice to the account's address when it's deleted (`account-deleted`), and the
  `Cross-Origin-Resource-Policy: same-origin` header on every answer.

### Fixed

Found by adversarial review of this release; each was also in 0.5.0.

- The copy of an account's data (`my-data`) showed a move it asked for only when the new
  address had no account, so anyone with an account could learn whether another address
  had one. Its move requests are now shown the same either way.
- A password change still hashing when its session was signed out still landed. It now
  lands only while the session that asked is there.
- Reading the session cookie trimmed spaces and tabs with a pattern whose time grew with
  the square of a long run of them, so one crafted 16KB `Cookie` header, sent by anyone,
  held the server up for about 90 ms. It's trimmed in one pass now.
- A link opened any account at its address when used: one made, or moved there, after a
  sign-up link was sent could be taken with it. A link to an account now opens only that
  account, and a sign-up link opens nothing that has an account by then.
- A full inbox wasn't stored a link, so the database work told it apart; it's stored
  one either way now. `lookUpLink` refuses kinds of link the site doesn't send.
- The Node adapter answered `PUT` and `DELETE` to reading routes as `GET`; only `GET`
  (and `HEAD`) read now.
- An address could hold `/`, `?`, or `#` before its `@`, so pass for a web link in an
  email; refused now.
- The advice to name a CDN's address ranges in `trustedProxies` is gone: its other
  customers send from them too, with any `X-Forwarded-For`. Put a proxy you run behind
  it, and name that.

### Removed

- The `password-check-failed` event, with the checks it told of.
- Undo links: `useUndoLink`, `/auth/undo-email`, `UNDO_DAYS`, `useEmailLink`'s `undo`,
  and the `email-changed` message. A move needs the old address's approval first.
- The errors naming 0.5.0's settings (`sendEmail`, `name`, `proxies`) when given.

### Upgrading from 0.5.0

Start with an empty database: the schema changed (a `stamp` for every account,
`password` may be empty, and two new tables for passkeys and their challenges).

```ts
// 0.5.0
createAuth(db, options);
createHandler(auth, { origin, linkPage, name: "Example", sendEmail: (to, subject, text, { signal }) => send({ to, subject, text, signal }) });

// 0.6.0
createAuth(db, { signInWith: ["password", "link"], ...options });
createHandler(auth, {
  origin,
  linkPage,
  deliver: (message, { signal }) => send({ to: message.to.email, ...emailFor(message, { origin, name: "Example" }), signal }),
});
```

Pages that change the password, the email, or delete the account no longer send a
password, and should offer to sign in again on `sign-in-again`.

## [0.5.0] - 2026-10-27

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
  `"Example Club"`. Subjects use it, and the text gives it with the site's
  address ("Example Club (example.org)"), so an email still says where it's from.
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
