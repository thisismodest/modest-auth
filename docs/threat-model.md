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
| A way in the site didn't choose | How people sign in must be given (`signInWith`): any of a link, a password, and a passkey; anything else refused at start-up. A way not chosen is off entirely: its routes aren't there, and its functions refuse to run. Sign-in links are sent only where "link" is chosen, or there are no passwords (where they make accounts and get people back in) | `auth.ts`, `handler.ts` |
| An inbox as a way into a passkey account | `recovery: "app"`, only with `signInWith: ["passkey"]`: no link into an existing account is sent at anyone's asking (the same answer, and work, as for any address; the inbox is told the account signs in by passkey), so only the app's own code can make one (`recoveryLink`). Sign-up still proves the address by a link, which makes a new account and nothing else | `auth.ts` |
| Someone the app doesn't want having an account | `allow`, if given, is asked before a link is sent or used, an account made, or a session started or used, so someone it stops allowing is signed out at their next request, for good: their sessions end, so none comes back if it allows them again. It can only refuse: only a plain `true` is a yes, and a mistake in it (throwing, or answering anything else, a promise included) is a refusal, logged without details. A refused address is answered as any other, does the same work, and is sent nothing | `auth.ts`, `handler.ts` |
| Signing up with someone else's email | An account is made only by a link emailed to the address: where there are passwords, whoever opens it chooses one; where there aren't, opening a sign-in link makes it | `auth.ts` |
| Guessing, reusing, or stretching a link | 256-bit tokens, kept only as SHA-256 hashes; single-use, taken in one statement; 60 minutes to choose a password, 15 to sign in; a password link can't sign in, nor a sign-in link choose a password; a password refused at a link doesn't use it up; using a link, a new password, or deleting the account ends the email's other links | `auth.ts` |
| A link leaking from its URL | The token follows `#`, which browsers never send to a server or in `Referer`; the link page takes it out of the address bar; a mail service that opens links to check them can't use one | `handler.ts`, `examples/node-http.ts` |
| Sending someone your own link, to sign them in to your account (login CSRF) | The link page asks `/auth/link` which email it's for, shows it, and acts only when the person does | `handler.ts`, `examples/node-http.ts` |
| Phishing a passkey (a look-alike site, or one framing ours) | The browser's client data must name exactly the handler's origin, of the right type (making one, or signing in), not from inside another site's frame (`crossOrigin` or `topOrigin` refused); the authenticator data must be for this site's host | `webauthn.ts` |
| Replaying a passkey's answer, or using one made for another purpose | Challenges are 256-bit, single-use, kept only as hashes, taken in one statement, kept apart by kind (making one, signing in) and, for making one, by account, and good for 5 minutes; a creation's answer can't be used as a sign-in (its type differs, and a sign-in carrying a new passkey is refused) | `auth.ts`, `webauthn.ts` |
| A forged or altered passkey answer | Its signature is checked over exactly the bytes received (the authenticator data and the client data's hash), with the key kept when it was added; nothing is re-written before checking | `webauthn.ts` |
| A passkey used without its owner there | The authenticator data must say the person was present and verified (a fingerprint, a face, or a PIN), both when it's made and at every sign-in | `webauthn.ts` |
| Malformed passkey data (CBOR, keys) | Read by a strict CBOR reader taking only what passkeys use: no indefinite lengths, tags, floats, or null; no key twice; integers JavaScript holds exactly; nesting and item counts capped; nothing left over. Keys only of three algorithms (EdDSA on Ed25519, ES256 on P-256, RS256 of 2048 bits or more counted from the top bit, odd, with an odd exponent from 3 to 2^32), each with exactly its own type, curve, and fields; P-256 points off the curve refused (an Ed25519 key is taken as given: a bad one only harms whoever added it). Fuzzed with random and mutated input | `webauthn.ts` |
| Taking over someone's passkey, or adding one to someone else's account | A passkey's id is unique across every account, so one already added isn't added again; a sign-in's passkey must name, by id, the account it was added to (a sign-in naming none is refused); an address `allow` refuses can't sign in by passkey; adding one needs a session started in the last 10 minutes, and a challenge given to that account | `auth.ts` |
| A copied passkey (cloned from a device) | Where a passkey keeps a counter, it must go up each time, or the sign-in is refused; the new count is written only while it's still the one checked, so two processes can't both take it | `auth.ts` |
| A thief keeping a way back after the owner moves the account home | Moving back to an address the account was moved away from, while that move's undo link lasts, is that undo: later moves' undo links end, and none goes to the address it leaves | `auth.ts`, `handler.ts` |
| A thief's passkey left behind | Adding or removing one is told to the account's email, and changes the stamp, ending the account's unused challenges; removing one signs every other session out, so a session it started can't carry on and add another; getting back in is a fresh start: a new password chosen at a link, a sign-in link where the site doesn't sign in by link (or one opened with `reset`), and an undone move each change the stamp and end every session, link, and passkey of the account (a reset sign-in link takes the password too); a passkey, or a move's undo link, is stored only while the stamp is the one just set, and a fresh start ends every session, passkey, and challenge both before and after the stamp changes, so nothing stored in another process across it outlasts it | `auth.ts`, `handler.ts` |
| A link opening an account it wasn't sent for | A link to an existing account names it, and opens only that one; a sign-up link opens nothing that has an account by then, so an account made, or moved to the address, after it was sent can't be taken with it | `auth.ts` |
| An undo link as a way into a passkey account | Under `recovery: "app"`, undoing a move sends no link in: the old address can move the account back, which signs everyone out, but can't sign in | `auth.ts` |
| A thief's words in the owner's notice | A notice of a passkey added or removed doesn't name it (whoever added it chose the name) | `messages.ts`, `handler.ts` |
| A copy of the database signing in by passkey | Only public keys are kept | `auth.ts` |
| Learning who has an account by asking for a link | The same answer (`202`, `{}`), the same database work, and a message either way (for a sign-in link to an email with no account, where there are passwords, one saying so, with no link; where there aren't, one that signs up), sent after the answer | `auth.ts`, `handler.ts` |
| Flooding an inbox, or keeping its owner from getting a link | At most 3 links of each kind to one address in 15 minutes, the rest quietly not sent; asking for more never ends a link sent (using one ends the address's others); each kind counted apart, so sign-in requests can't block a password link (nor the reverse); each exact address counted alone, so another spelling can't use up its owner's | `auth.ts` |
| Emailing strangers in bulk through sign-up | At most 5 links asked for from one address, and 20 from one IPv6 /48, in 15 minutes | `auth.ts` |
| A stuck or slow email service | `deliver` is given a signal that aborts after 30 seconds; 10 sends at once, 1,000 waiting, the rest dropped and logged (at most 5 lines a minute, and a count of the rest, so a flood can't fill the log); a message whose link has run out while it waited isn't sent; failures logged without the message | `handler.ts` |
| A link reaching anyone but its address | A message, with its link, goes only to the app's `deliver`, after the answer, never in the answer to whoever asked; README's checklist for whatever sends it: click tracking off (a service that rewrites links would see the token), the link once and unchanged, and no logging of messages | `handler.ts`, `README.md` |
| An address a mail program would read as an option or a pipe (`-X/file@…`, `\|cmd@…`) | Refused | `emails.ts` |
| An address that passes for a web link in a notice (`www.x.example/undo?@y.example`) | A path, query, or fragment (`/`, `?`, `#`) refused before the `@` as after it | `emails.ts` |
| Moving someone's account to your address | Needs a session started in the last 10 minutes, and a link to the new address, opened where the account is signed in (so a link sent to anyone else does nothing); a move asked for while the password changed isn't stored | `auth.ts`, `handler.ts` |
| A stolen session changing the account (its password, its email, or deleting it) | Each needs a session started in the last 10 minutes (`RECENT_MINUTES`); an older one is told to sign in again, by any way the site has. Nothing asks for the password, so a stolen session can't be used to guess it | `auth.ts` |
| Attaching your account to someone else's address (sending them your own move link) | Only the account being moved, signed in, can use its link | `auth.ts`, `handler.ts` |
| A stolen password used to move an account away for good | The old address is told, with a link (for 7 days) that moves it back, signs everyone out, makes the password useless, and sends a link to get back in (to choose a new password, or, without passwords, to sign in; made by the undo itself, so no limit can stop it); the link that makes accounts (a password link, or without passwords a sign-in link) to that address does the same. Every move gets one; nothing done to the account (a new password, another move) ends it, and using one ends only the same account's later moves' undo links, so a thief's own can't cancel the owner's; such a link restores the account only when just one account was moved away from that address | `auth.ts`, `handler.ts` |
| Learning who has an account by asking to move yours to their address | The same answer and work either way, and an email either way (to an address with an account, one saying so); the copy of the account's data shows the request the same way whatever the address | `auth.ts`, `handler.ts` |
| A change its owner didn't make, unnoticed | A notice to the account's email when its password changes or it's deleted, and to the old address when its email does | `handler.ts` |
| Anything checked going ahead after the account changed (a session starting, a move being stored, a password changing, an account going) | Every account has a stamp, a random value replaced whenever how it's reached changes (a new password, a new email, an undone move); each of these goes ahead only while the stamp is still the one that was checked (a recovery's too, so it can't land on an account moved meanwhile, and take that move's undo link with it); an undo moves the account only while its own undo link is still there, and ends later moves' undo links first, so of two used at once the earlier wins. One rule for every race | `auth.ts` |
| Guessing a password | scrypt at OWASP's cost (about 50ms a guess); limits per account and address, per account, and per address, counted before hashing so tries sent at once count too | `passwords.ts`, `auth.ts`, `limits.ts` |
| Easily guessed passwords, sprayed across many accounts | At least 15 characters; 5,500 common passwords that long refused, compared as letters and digits only and without trailing numbers (so adding spaces, punctuation, capitals, or a year doesn't get one through); ones made from the email, or a few characters repeated, refused too | `passwords.ts`, `common-passwords.txt` |
| A password that differs from another only in broken Unicode | Passwords that aren't well-formed text are refused, not quietly changed | `passwords.ts` |
| Guessing from many addresses | 100 tries an hour per account from anywhere; IPv6 counted by /64, and 200 tries per /48 | `auth.ts`, `limits.ts` |
| Pausing accounts by flooding sign-in until it's "busy" | A try refused as busy isn't counted against the account | `auth.ts`, `passwords.ts` |
| Flooding the limits to push a count out, or restarting to reset them | Limits kept in the database: nothing is evicted, and they outlive the process | `limits.ts` |
| Forging X-Forwarded-For to dodge limits | Only believed from the proxies named in `trustedProxies` (none by default: a proxy that passes a visitor's own header on can't be told from one that adds to it, so nothing is assumed); read from the right, past each named proxy, to the first address that isn't one, so whatever a client writes is further left and never reached; ranges wide enough to be much of the internet refused; ports dropped; IPv6 read as numbers, so one address can't be written many ways | `limits.ts`, `handler.ts` |
| Every visitor sharing one allowance (through NAT64, or a proxy in front) | An IPv4 address carried in IPv6 counts as that IPv4 address; a proxy passing addresses on but not named, or one in front passing none, is said in the log, with what to set | `limits.ts`, `handler.ts` |
| Getting the proxy setup wrong | Leaving it out is always safe (visitors share the proxy's address); the usual cases are named (`loopback`, `private`), with no count to get right; mistakes are said in the log, a few times each at most, so nobody can flood it; an `origin` mistake is only said for this site's own host, so nobody else's can crowd it out | `limits.ts`, `handler.ts` |
| Locking someone out by guessing at their account | The per-account-and-address limit only pauses that address; the per-account limit is high, and only pauses signing in by password; and a sign-in link, always offered, isn't paused by it | `auth.ts` |
| A sign-in racing a password change (or an account's deletion) | A session starts only while the account's stamp is the one checked with its password; upgrading an old hash only replaces the hash that was checked, and isn't a change to the stamp | `auth.ts` |
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
| Learning who has an account by passkey | A passkey sign-in needs no email; options for one name nobody; a passkey names its account only by a random id, never the email | `auth.ts` |
| Swamping the server | Hashing only a few at a time, sized to the machine (its cores, half its memory, and Node's thread pool less two, so file reads keep a thread), with a short queue; passwords over 200 characters, emails over 254, and bodies over 4KB refused before any hashing; old limit rows and sessions cleared in small batches | `passwords.ts`, `emails.ts`, `handler.ts`, `limits.ts` |
| A crafted email that makes checking it slow | Length checked first; plain string checks, no backtracking pattern | `emails.ts` |
| A crafted Cookie header that makes reading it slow | Each part trimmed in one pass, never by a pattern that backtracks | `cookies.ts` |
| One account passing for another (compatibility forms, or invisible characters) | Emails normalised (NFKC), so `ａｎｎ` and `ann` are one address, and domains kept in their ASCII form, so `bücher.de` and `xn--bcher-kva.de` are one; control, format, and invisible characters (anything drawn as nothing) refused | `emails.ts` |
| Markup or headers carried in an email | Quotes, brackets, and line breaks refused | `emails.ts` |
| The site's name in emails adding a line to one, hiding text, or standing in for the address | In `emailFor`: up to 60 characters on one line, with no control, invisible, or line-separating characters, or it's refused; the text always gives the site's address with it | `messages.ts` |
| Writing into the cookie header | Tokens checked against a strict pattern when written and read | `cookies.ts` |
| Reading a signed-in person's details from another site | Responses are JSON with no CORS headers, `no-store`, and `Cross-Origin-Resource-Policy: same-origin` (so not even a sibling subdomain can load them) | `handler.ts` |
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
  `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;`. A CDN's address
  ranges are never named: its other customers can send from them, with any
  `X-Forwarded-For`. A proxy the site runs behind the CDN sets the address from the
  CDN's own header instead, and is named.
- **A proxy or CDN that isn't named** makes its visitors share its address for the
  limits (safe, but a busy address can pause); the log says so, naming the setting.
  Each kind of note is said for 5 sources at most, so someone sending from 5 networks
  first can use them up; the 5 notes still say what to check.
- **Someone with an account's password, or its inbox, can sign in and move it,** and has
  the account until its old address undoes the move (and, if they also read the old
  inbox, for good). That's why the undo link also makes the password useless. Once
  the undo link has run out (7 days), the account's new address is its own: an owner
  who then moves it back by hand sends that address an undo link, as for any move.
  Within those 7 days, the earliest address holds the claim: whoever reads it can take
  the account back (by its undo link, or by moving the account there), which ends any
  later move's undo link.
- **The address in an "email changed" notice is chosen by whoever moved the account,**
  so its local part can read as words (`no-action-needed@…`). It can't hold a path or
  query, and the notice still carries the undo link.
- **A session stolen in its first 10 minutes** can change the account: its password, its
  email, its passkeys, or deleting it. After that it must sign in again. A notice goes to the account's
  email for a password or email change, with a way back.
- **The per-account limit counts everyone's tries,** its owner's sign-ins too: someone
  who spends 100 guesses on an email can tell, by when they're refused, whether anyone
  else tried it in that hour (not when; the pause always says to wait the whole hour).
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
  person there can use them up for the rest. So with its 20 tries in 15 minutes: one
  person can pause signing in there, links and passkeys included, for everyone else.
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
- **The messages differ** by whether the address has an account (`new-password` or
  `sign-up`; `no-account`), and an address `allow` refuses is sent nothing: only the
  inbox's owner sees the difference. An app writing its own words, or delivering
  messages itself, takes on README's checklist (click tracking off, the link unchanged,
  nothing logged); modest-auth can't test what it doesn't write.
- **`allow` is asked on every signed-in request,** on the same thread: if it takes longer
  for some addresses than others, how long requests take could show which. Keep it
  quick, and the same work for everyone, such as looking an email up in a set.
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
- **`node:sqlite` is marked experimental** in Node 24 (it prints a warning), and a
  release candidate in Node 26. It's SQLite underneath; the API around it may still
  change.
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
- **A sustained flood from hundreds of addresses can keep sign-in "busy"** for
  everyone while it lasts. Each try still costs the sender a try at their address.
- **Nothing limits how many accounts can be made overall,** beyond the per-address
  limits and the need to read each address's inbox: someone with many addresses and
  inboxes can make many.
- **No attestation:** a passkey isn't asked what device made it, so a site can't limit
  passkeys to certain hardware. Nothing here relies on it.
- **Synced passkeys don't count,** so a copy of one (in a compromised password manager,
  say) can't be told from the original. The counter check only catches copies of
  passkeys that count.
- **An account is only as strong as its way back in.** Unless a site signs in by passkey
  alone with `recovery: "app"`, that's a link to its email: `["passkey"]` is as strong as
  `["link", "passkey"]` against someone who reads the inbox. Choosing passkeys only, for
  one account on a site that offers more, is on the roadmap.
- **With `recovery: "app"`, someone who signs up and leaves before adding a passkey,**
  or loses every passkey, can only get back in by `recoveryLink`, so the app needs a way
  to vouch for them.
- **`recoveryLink` lets in whoever opens it.** It's for the app's own code, after the
  app has checked who it's for; sent to the wrong person, it's an account handed over.
- **A session that's ended doesn't stop a change already checked against it,** except a
  password change, which lands only while its session is there. The others don't wait
  on anything, so there's no gap to use.
- **Turning passwords off keeps the stored hashes,** unused; turned back on, they work
  again. Clear them first if that's not wanted.
- **Signing out everywhere, or changing the password while signed in, keeps the
  account's passkeys:** a thief's passkey goes when the owner removes it (which signs
  everyone else out), chooses a new password at a link, or undoes a move.
- **Turning passkeys off keeps stored passkeys,** unused; turned back on, they work
  again. Remove them first (`passkeysOf`, `removePasskey`, which work whatever the
  site's methods) if that's not wanted.
- **The passkey counter's two-process check** relies on SQLite's own locking, like
  every other write here.
- **`deliver` runs after the answer,** but on the same thread: if it does synchronous
  work before handing the message over, how long the next request waits could show
  which addresses got one. Nothing is delivered to an address `allow` refuses or a
  full inbox, so keep `deliver` to handing the message to a queue or service, without
  waiting on it.
- **Links already sent outlive a change to the site's methods** until they run out (60
  minutes at most): turning `link` off, or `recovery` to `"app"`, doesn't end them.
- **Under a flood, notices can be dropped** with everything else past the 1,000 waiting
  (and logged), so an owner may not hear of a change made during one.
