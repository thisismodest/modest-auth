# Threat model

What modest-auth protects, from whom, and how. Every mitigation here has a test; a
change that weakens one needs a reason in this file first.

## What's worth protecting

1. **Accounts:** nobody signs in as someone else.
2. **Passwords:** nobody learns one, from us or from a copy of our data.
3. **Sessions:** a session is only usable by the browser it was given to, and ends
   when it should.
4. **Who has an account:** sign-in doesn't reveal it.
5. **The service:** it stays usable under ordinary attack.

## Who we defend against

- **Strangers on the internet**, guessing passwords, alone or from many addresses.
- **Other sites**, trying to act for a signed-in person through their browser.
- **Someone with a copy of the database** (a leaked backup, a stolen disk).
- **Someone who can inject a script into the app's pages** (an XSS bug elsewhere),
  as far as stealing the session goes.
- **Someone sending a flood of requests, or crafted ones**, to slow the server, lock
  people out, or confuse one account for another.

Out of scope: someone who controls the server itself or its environment, the
person's own device, or their email account; a script running in the app's own pages
(it can act as the person while it runs, whatever the auth); and the app's own code
round modest-auth.

## How

| Threat | Mitigation | Where |
| --- | --- | --- |
| Guessing a password | scrypt at OWASP's cost (about 50ms a guess); limits per account and address, per account, and per address, counted before hashing so tries sent at once count too | `passwords.ts`, `auth.ts`, `limits.ts` |
| Easily guessed passwords, sprayed across many accounts | At least 15 characters; 5,500 common passwords that long refused, compared as letters and digits only and without trailing numbers (so adding spaces, punctuation, capitals, or a year doesn't get one through); ones made from the email, or a few characters repeated, refused too | `passwords.ts`, `common-passwords.txt` |
| A password that differs from another only in broken Unicode | Passwords that aren't well-formed text are refused, not quietly changed | `passwords.ts` |
| Guessing from many addresses | 100 tries an hour per account from anywhere; IPv6 counted by /64, and 200 tries per /48 | `auth.ts`, `limits.ts` |
| Guessing the password with a stolen session (through a password change) | The owner's own checks are capped at 10 an hour, per account | `auth.ts` |
| Pausing accounts by flooding sign-in until it's "busy" | A try refused as busy isn't counted against the account | `auth.ts`, `passwords.ts` |
| Flooding the limits to push a count out, or restarting to reset them | Limits kept in the database: nothing is evicted, and they outlive the process | `limits.ts` |
| Forging X-Forwarded-For to dodge limits | Only believed through the number of proxies declared, counted from the right; ports dropped; IPv6 read as numbers, so one address can't be written many ways | `limits.ts`, `handler.ts` |
| Every IPv4 visitor sharing one allowance (through NAT64, or a forgotten `proxies`) | An IPv4 address carried in IPv6 counts as that IPv4 address; a forwarded address with no proxies declared is warned about | `limits.ts`, `handler.ts` |
| Locking someone out by guessing at their account | The per-account-and-address limit only pauses that address; the per-account limit is high, and doesn't stop the signed-in owner changing the password or deleting the account | `auth.ts` |
| A sign-in racing a password change (or an account's deletion) | A session starts only for a user whose password was just checked, and only if it's still the account's; upgrading an old hash only replaces the hash that was checked | `auth.ts` |
| Piling up sessions for one account | 50 at most; the oldest ends | `auth.ts` |
| A copy of the database | Passwords only as salted scrypt hashes; sessions only as SHA-256 hashes of 256-bit tokens; limit keys only as hashes | `passwords.ts`, `auth.ts`, `limits.ts` |
| Hashes that grow weaker as computers get faster | Each hash records its cost; an older one is replaced at the current cost at the next sign-in | `passwords.ts`, `auth.ts` |
| A stored hash naming a huge cost, to tie the server up | Costs above the current one are refused unchecked | `passwords.ts` |
| Stealing a session with an injected script | `HttpOnly` cookie | `cookies.ts` |
| Another host setting or reading the cookie | `__Host-` prefix and `Secure` over HTTPS; an unprefixed cookie isn't read over HTTPS | `cookies.ts` |
| Other sites acting for a signed-in person (CSRF) | Every route that changes anything requires the site's own `Origin` (and `Sec-Fetch-Site: same-origin` when sent), and a JSON body, which needs the browser's permission to send cross-site; `SameSite=Lax` cookie | `handler.ts`, `cookies.ts` |
| Planting a session in someone's browser, then waiting (fixation) | Each sign-in starts a fresh session and ends the old one; a request carrying two session cookies is treated as signed out; a cookie whose name only resembles ours (an invisible character round it) isn't read | `handler.ts`, `cookies.ts` |
| A session left signed in on a shared computer | Ends after 7 days unused, and 30 at most; sign out everywhere; a password change ends all others | `auth.ts` |
| Learning who has an account at sign-in | Same answer and the same work (a hash is checked either way) for a wrong email, an unknown one, or a wrong password | `auth.ts` |
| Swamping the server | Hashing two at a time with a short queue; passwords over 200 characters, emails over 254, and bodies over 4KB refused before any hashing; old limit rows and sessions cleared in small batches | `passwords.ts`, `emails.ts`, `handler.ts`, `limits.ts` |
| A crafted email that makes checking it slow | Length checked first; plain string checks, no backtracking pattern | `emails.ts` |
| One account passing for another (compatibility forms, or invisible characters) | Emails normalised (NFKC), so `ａｎｎ` and `ann` are one address, and domains kept in their ASCII form, so `bücher.de` and `xn--bcher-kva.de` are one; control, format, and invisible characters (anything drawn as nothing) refused | `emails.ts` |
| Markup or headers carried in an email | Quotes, brackets, and line breaks refused | `emails.ts` |
| Writing into the cookie header | Tokens checked against a strict pattern when written and read | `cookies.ts` |
| Reading a signed-in person's details from another site | Responses are JSON with no CORS headers, and `no-store` | `handler.ts` |
| Crashing the app with a malformed request (an odd method, a broken URL, a body cut off) | The Node adapter never throws; every such request gets an answer | `node.ts`, `handler.ts` |
| Stepping round a proxy's rule with an odd path (`/auth\x`, `//x`, `/x/../auth`, `%2e%2e`, a full URL) | With the Node adapter, only plain paths reach the routes. Other servers give the handler a URL they've already worked out; a proxy's rules should match that worked-out path | `node.ts` |
| Disturbing the app's own requests | The Node adapter doesn't touch a request that isn't for its routes | `node.ts` |
| Several processes writing at once | WAL, and up to two seconds' wait for another writer (set before anything else, so even starting up waits) | `auth.ts` |
| Deleted accounts and old passwords lingering on disk | `secure_delete`, and the WAL emptied into the file after a deletion or a new password (fully, when no other connection is reading at that moment) | `auth.ts` |

## Known limits

- **Sign-up says when an email already has an account.** Hiding it needs email
  confirmation, which is on the roadmap.
- **No way back from a forgotten password yet.** Password reset needs email, which is
  on the roadmap.
- **A determined attacker can pause signing in to one account for up to an hour** by
  spending 100 guesses at it from several addresses; until it lifts, its owner can't
  sign in either (sessions already open carry on, and can still change the password or
  delete the account). That's the price of slowing spread-out guessing. Gentler
  options, such as confirming a sign-in from a new address by email, are on the roadmap.
- **A flood of sign-ins is refused as "busy"** for everyone until it passes: that keeps
  the server up, at the cost of sign-in for the moment.
- **The per-account limit counts a window, not consecutive failures:** about 2,400
  guesses a day at one account are possible from many addresses (against at least a
  15-character password not on the common list). Successful sign-ins count too.
- **An attacker with a whole IPv6 /48 can pause sign-in to about 8 accounts an hour**
  from it (200 tries per 15 minutes, 100 per account), and more with more blocks.
- **While another process writes, a process waits** (all of it: SQLite calls are
  synchronous) up to two seconds, and then that request fails.
- **Accounts with a hash at an older cost** take a little longer to answer a wrong
  password (the old hash's work as well as the current one's), so after a cost is
  raised, timing could show which accounts haven't signed in since. The difference is
  the old cost, which is small by the time it's replaced.
- **Limit keys are hashes,** but of things that can be guessed (addresses, emails): a
  copy of the database could show which recently tried which. Rows are cleared once
  their window (an hour at most) has passed, as later requests come in.
- **Backups keep deleted accounts** until they're replaced: the app's to manage.
- **No pepper:** password hashes don't also use a secret kept outside the database
  (NIST suggests one). A copy of the database alone is enough to start guessing, at
  scrypt's cost, against passwords of 15 or more characters.
- **`node:sqlite` is marked experimental** in Node 24 (it prints a warning). It's
  SQLite underneath; the API around it may still change.
- **Letters from other alphabets that look alike** (a Cyrillic `а` in `аnn@example.org`)
  make a different address, and so a different account, that looks the same. An app
  that shows emails to other people should bear that in mind.
- **Anyone can sign up with someone else's email,** which that person then can't use
  until the account is deleted. Email confirmation (on the roadmap) is the answer.
- **A stolen session can use up its owner's 10 password checks an hour,** so for that
  hour the owner can't change the password. They can still sign out everywhere (no
  password needed), which ends the stolen session: that should be the first step.
- **A sustained flood from hundreds of addresses can keep sign-in "busy"** for
  everyone while it lasts. Each try still costs the sender a try at their address.
- **Nothing limits how many accounts can be made overall,** beyond the per-address
  limits: someone with many addresses can fill the database with accounts. Email
  confirmation (on the roadmap) is the usual answer.
