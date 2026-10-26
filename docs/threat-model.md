# Threat model

What modest-auth protects, from whom, and how. Every mitigation here has a test; a
change that weakens one needs a reason in this file first.

## What's worth protecting

1. **Accounts:** nobody signs in as someone else.
2. **Passwords:** nobody learns one, from us or from a copy of our data.
3. **Sessions:** a session is only usable by the browser it was given to, and ends
   when it should.
4. **Who has an account:** signing in, signing up, and asking for a link don't reveal it.
5. **The service:** it stays usable under ordinary attack.

## Who we defend against

- **Strangers on the internet**, guessing passwords, alone or from many addresses.
- **Other sites**, trying to act for a signed-in person through their browser.
- **Someone with a copy of the database** (a leaked backup, a stolen disk).
- **Someone who can inject a script into the app's pages** (an XSS bug elsewhere),
  as far as stealing the session goes.
- **Someone sending a flood of requests, or crafted ones**, to slow the server, lock
  people out, or confuse one account for another.
- **Someone asking for emails to be sent** to any address, to flood an inbox, keep its
  owner from getting a link, send strangers mail, or learn who has an account.
- **Someone who sends a person a link of their own**, to sign them in to an account the
  sender controls.

Out of scope: someone who controls the server itself or its environment, the
person's own device, or their email account (an inbox is the way back in to its
account, as on most sites); a script running in the app's own pages
(it can act as the person while it runs, whatever the auth); and the app's own code
round modest-auth.

## How

| Threat | Mitigation | Where |
| --- | --- | --- |
| Signing up with someone else's email | An account is made only by a link emailed to the address: whoever opens it chooses the password | `auth.ts` |
| Guessing, reusing, or stretching a link | 256-bit tokens, kept only as SHA-256 hashes; single-use, taken in one statement; 60 minutes to choose a password, 15 to sign in; a password link can't sign in, nor a sign-in link choose a password; a password refused at a link doesn't use it up; using a link, a new password, or deleting the account ends the email's other links | `auth.ts` |
| A link leaking from its URL | The token follows `#`, which browsers never send to a server or in `Referer`; the link page takes it out of the address bar; a mail service that opens links to check them can't use one | `handler.ts`, `examples/node-http.ts` |
| Sending someone your own link, to sign them in to your account (login CSRF) | The link page asks `/auth/link` which email it's for, shows it, and acts only when the person does | `handler.ts`, `examples/node-http.ts` |
| Learning who has an account by asking for a link | The same answer (`202`, `{}`), the same database work, and an email either way (for a sign-in link to an email with no account, one saying so, with no link), sent after the answer | `auth.ts`, `handler.ts` |
| Flooding an inbox, or keeping its owner from getting a link | At most 3 links of each kind to one address in 15 minutes, the rest quietly not sent; every link sent stays usable at least until those 15 minutes end; each kind counted apart, so sign-in requests can't block a password link (nor the reverse); each exact address counted alone, so another spelling can't use up its owner's | `auth.ts` |
| Emailing strangers in bulk through sign-up | At most 5 links asked for from one address, and 20 from one IPv6 /48, in 15 minutes | `auth.ts` |
| A stuck or slow email service | `sendEmail` is given a signal that aborts after 30 seconds; 10 sends at once, 1,000 waiting, the rest dropped and logged; an email whose link has run out while it waited isn't sent; failures logged without the email's text | `handler.ts` |
| An address a mail program would read as an option or a pipe (`-X/file@…`, `\|cmd@…`) | Refused | `emails.ts` |
| Moving someone's account to your address | Needs the account's password and a session, and a link to the new address, opened where the account is signed in (so a link sent to anyone else does nothing); a move asked for while the password changed isn't stored | `auth.ts`, `handler.ts` |
| Attaching your account to someone else's address (sending them your own move link) | Only the account being moved, signed in, can use its link | `auth.ts`, `handler.ts` |
| A stolen password used to move an account away for good | The old address is told, with a link (for 7 days) that moves it back, signs everyone out, makes the password useless, and sends a link to choose a new one (made by the undo itself, so no limit can stop it); a password link to that address does the same. Every move gets one; nothing done to the account (a new password, another move) ends it, and using one ends only the same account's later moves' undo links, so a thief's own can't cancel the owner's; a password link restores the account only when just one account was moved away from that address | `auth.ts`, `handler.ts` |
| Learning who has an account by asking to move yours to their address | The same answer and work either way, and an email either way (to an address with an account, one saying so) | `auth.ts`, `handler.ts` |
| A change its owner didn't make, unnoticed | A notice to the account's email when its password changes, and to the old address when its email does | `handler.ts` |
| A session started by a sign-in still checking when the account moves | A session starts only while the account has the email and password that were checked | `auth.ts` |
| Guessing a password | scrypt at OWASP's cost (about 50ms a guess); limits per account and address, per account, and per address, counted before hashing so tries sent at once count too | `passwords.ts`, `auth.ts`, `limits.ts` |
| Easily guessed passwords, sprayed across many accounts | At least 15 characters; 5,500 common passwords that long refused, compared as letters and digits only and without trailing numbers (so adding spaces, punctuation, capitals, or a year doesn't get one through); ones made from the email, or a few characters repeated, refused too | `passwords.ts`, `common-passwords.txt` |
| A password that differs from another only in broken Unicode | Passwords that aren't well-formed text are refused, not quietly changed | `passwords.ts` |
| Guessing from many addresses | 100 tries an hour per account from anywhere; IPv6 counted by /64, and 200 tries per /48 | `auth.ts`, `limits.ts` |
| Guessing the password with a stolen session (through a password change) | The owner's own checks are capped at 10 an hour, per account | `auth.ts` |
| Pausing accounts by flooding sign-in until it's "busy" | A try refused as busy isn't counted against the account | `auth.ts`, `passwords.ts` |
| Flooding the limits to push a count out, or restarting to reset them | Limits kept in the database: nothing is evicted, and they outlive the process | `limits.ts` |
| Forging X-Forwarded-For to dodge limits | Only believed from the proxies named in `trustedProxies` (none by default: a proxy that passes a visitor's own header on can't be told from one that adds to it, so nothing is assumed); read from the right, past each named proxy, to the first address that isn't one, so whatever a client writes is further left and never reached; ranges wide enough to be much of the internet refused; ports dropped; IPv6 read as numbers, so one address can't be written many ways | `limits.ts`, `handler.ts` |
| Every visitor sharing one allowance (through NAT64, or a proxy in front) | An IPv4 address carried in IPv6 counts as that IPv4 address; a proxy passing addresses on but not named, or one in front passing none, is said in the log, with what to set | `limits.ts`, `handler.ts` |
| Getting the proxy setup wrong | Leaving it out is always safe (visitors share the proxy's address); the usual cases are named (`loopback`, `private`), with no count to get right; mistakes are said in the log, a few times each at most, so nobody can flood it; an `origin` mistake is only said for this site's own host, so nobody else's can crowd it out | `limits.ts`, `handler.ts` |
| Locking someone out by guessing at their account | The per-account-and-address limit only pauses that address; the per-account limit is high, and doesn't stop the signed-in owner changing the password or deleting the account; and a sign-in link, always offered, isn't paused by it | `auth.ts` |
| A sign-in racing a password change (or an account's deletion) | A session starts only for a user whose password was just checked, and only if it's still the account's; upgrading an old hash only replaces the hash that was checked | `auth.ts` |
| A session someone else started, left running | The owner sees every session (when each started and was last used) and can end any one, by a name that can't sign anyone in | `auth.ts`, `handler.ts` |
| Passwords known from breaches elsewhere | If the app gives a `breachedRange`, new passwords found in that set (Have I Been Pwned's, say) are refused; only the first 5 characters of the password's SHA-1 leave (for its normal form, and the form typed if that differs), so the service never learns it | `auth.ts` |
| An event's record giving secrets or who has an account away | Events carry the account's id and where it came from, never a password, token, or email; they're told after the answer, and a failing `onEvent` is logged, not passed on | `auth.ts` |
| Piling up sessions for one account | 50 at most; the oldest ends | `auth.ts` |
| A copy of the database | Passwords only as salted scrypt hashes; sessions and links only as SHA-256 hashes of 256-bit tokens; limit keys only as hashes | `passwords.ts`, `auth.ts`, `limits.ts` |
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
| The site's name in emails adding a line to one, hiding text, or standing in for the address | Up to 60 characters on one line, with no control, invisible, or line-separating characters, or it's refused when the handler is made; the text always gives the site's address with it | `handler.ts` |
| Writing into the cookie header | Tokens checked against a strict pattern when written and read | `cookies.ts` |
| Reading a signed-in person's details from another site | Responses are JSON with no CORS headers, and `no-store` | `handler.ts` |
| Crashing the app with a malformed request (an odd method, a broken URL, a body cut off) | The Node adapter never throws; every such request gets an answer | `node.ts`, `handler.ts` |
| Stepping round a proxy's rule with an odd path (`/auth\x`, `//x`, `/x/../auth`, `%2e%2e`, a full URL) | With the Node adapter, only plain paths reach the routes. Other servers give the handler a URL they've already worked out; a proxy's rules should match that worked-out path | `node.ts` |
| Disturbing the app's own requests | The Node adapter doesn't touch a request that isn't for its routes | `node.ts` |
| Several processes writing at once | WAL, and up to two seconds' wait for another writer (set before anything else, so even starting up waits) | `auth.ts` |
| Deleted accounts and old passwords lingering on disk | `secure_delete`, and the WAL emptied into the file after a deletion, a new password, or clearing old links (when nothing else is reading at that moment; otherwise tried again, without waiting, at each clearing until done; never failing the request) | `auth.ts` |

## Known limits

- **Whoever reads an inbox can take over its account,** by choosing a new password or
  signing in by link, as on most sites. Email is the way back in. After a move, the old
  address has 7 days to undo it; after that, the account belongs to its new address.
  So an account handed on to someone else (sold, or given to a colleague) can be taken
  back by its old address for 7 days.
- **`trustedProxies: ["private"]` trusts everyone on the app's own private network** to
  say who they are: on a network strangers can reach (some container and cluster setups
  translate outside connections to private addresses), name the proxy's own address
  instead. A named proxy that passes a visitor's own `X-Forwarded-For` on, rather than
  adding to it, lets visitors choose their address: nginx needs
  `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;`.
- **A proxy or CDN that isn't named** makes its visitors share its address for the
  limits (safe, but a busy address can pause); the log says so, naming the setting.
  Each kind of note is said for 5 sources at most, so someone sending from 5 networks
  first can use them up; the 5 notes still say what to check.
- **Someone with an account's password and a session can move it,** and has the
  account until its old address undoes the move (and, if they also read the old
  inbox, for good). That's why the undo link also makes the password useless.
- **A determined attacker can pause signing in with the password to one account for up
  to an hour** by spending 100 guesses at it from several addresses. Its owner can still
  sign in by an emailed link (unless someone on the same address, or the same IPv6 /48,
  has used up its 5 or 20 links; from another network it still works), and sessions
  already open carry on.
- **Anyone can have emails sent to any address,** up to 5 from one IPv4 address or IPv6
  /64, and 20 from one IPv6 /48, every 15 minutes; with many addresses, more. The text is
  fixed (it says who sent it, and offers a link or says there's no account), but it's
  mail the address's owner didn't ask for, and it costs the site's sending reputation.
- **One inbox can get 3 links of each kind (password, sign-in, email move) in 15
  minutes,** so 9 in all, besides notices of changes to its own account.
- **One inbox can get more than 3 links of a kind in 15 minutes** through spellings
  that reach it (`ann+x@`, and Gmail's dots), each counted as its own address: bounded
  by the limits on senders above.
- **A flood of link requests from many addresses can fill the email queue,** so other
  people's emails are dropped (and logged) until it drains; and since each of those
  still counted against its address's 3, its owner may have to wait out the 15 minutes
  for another. A link that waited in the queue arrives with less of its time left.
- **A shared address (an office, a mobile network) shares its 5 links** in 15 minutes,
  and everyone in one IPv6 /48 (an organisation, or a carrier's pool) shares 20: one
  person there can use them up for the rest.
- **Someone can still be fooled by a look-alike email** on the link page (`ann@` written
  with a Cyrillic `а`), or by an app whose link page acts by itself or doesn't show the
  email: then they could be signed in to someone else's account.
- **Asking for a link keeps the email in the database** until the link runs out (60
  minutes for a password link) and the next request after that clears it, whether or
  not it has an account, so a copy of the database would show who was sent a link
  recently. Emptying the WAL after clearing old links never waits for, or fails, a
  request (after a deletion or a new password it waits as any write does, but never
  fails it): if another process is reading, or the app is part-way through its own
  query or transaction on the connection, the email can stay in the WAL or the file
  until a later request finishes it; it's tried again at each clearing, at most every
  ten seconds.
- **The emails' words differ** by whether the address has an account ("choose a new
  password" or "finish signing up"; "there's no account"): only the inbox's owner sees
  them.
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
- **`onEvent` runs after the answer,** but on the same thread: if it does more work for
  some events than others (looking an account up for a failure that names one, say),
  how long the next request waits could show which. Keep it to the same work for every
  event, such as appending it to a log.
- **The breached-password check allows a password if the service fails or takes over
  5 seconds** (and logs it), so an outage can't stop anyone choosing one. The 5 seconds
  doesn't cancel the app's own request: `breachedRange` should have a timeout of its own.
  A password whose typed form differs from its normal one is checked twice, so a hung
  service can hold its answer for 10 seconds.
- **A stolen session can end its owner's sessions one at a time** (and keep its own),
  as fast as they start. A password link needs no session, and ends every other one,
  the thief's too: that's the way out.
- **A stolen session can use up its owner's 10 password checks an hour,** so for that
  hour the owner can't change the password. They can still sign out everywhere (no
  password needed), which ends the stolen session: that should be the first step.
- **A sustained flood from hundreds of addresses can keep sign-in "busy"** for
  everyone while it lasts. Each try still costs the sender a try at their address.
- **Nothing limits how many accounts can be made overall,** beyond the per-address
  limits and the need to read each address's inbox: someone with many addresses and
  inboxes can make many.
