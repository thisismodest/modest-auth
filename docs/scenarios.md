# Scenarios: what an attacker would try

Adversarial scenarios for modest-auth, written by an independent reviewer from
README.md and docs/threat-model.md alone, without seeing the code. They're tested in
`test/scenarios/`, against a real server built with the public API, from outside.
**[LIKELY]** marks the ones the reviewer thought most likely to find a hole.

## Account creation and links

1. **[LIKELY]** One password link, 20 parallel `set-password` calls: exactly one gets 200 and a cookie; the rest the same refusal; one account.
2. A password link at `sign-in-with-link`, and a sign-in link at `set-password`: refused, no cookie; whether the wrong-kind use spends the token is recorded.
3. A too-short password at `set-password`: refused; the same token then works with a valid one.
4. **[LIKELY]** Two password links and a sign-in link; use one: what happens to the other two, against "every link sent stays usable for 15 minutes".
5. `POST /auth/link` twice with one token: both give `{kind, email}`; the link still works.
6. 1,000 `POST /auth/link` with random tokens from one address: refused the same way; whether a limit applies.
7. Tokens altered (an extra character, spaces, case, number, array, null, 5KB): each a 4xx, never a 500.
8. The token is only after `#` in the email: never `?token=`, never in the path.
9. (With the clock moved on) a password link at 61 minutes and a sign-in link at 16: refused.
10. **[LIKELY]** A sign-in link for `ann@`, then the account moved to `bob@`, then the link used: no session for the moved account.
11. A password link, the account deleted, the link used: a fresh empty account or a refusal; never the old sessions or data.
12. Two accounts moved away from `ann@` in turn, then a password link at `ann@`: neither restored.

## Sign-in and sessions

13. A planted cookie, then sign-in: a new token; the planted one gives `{user:null}`.
14. Two valid session cookies in one request: signed out.
15. **[LIKELY]** A session id from `/auth/sessions` used as a cookie: signs nobody in. A ends B's session by id: B's survives; the answer matches a missing id.
16. **[LIKELY]** 10 sign-ins with the old password raced against a password change: none started with the old password survives.
17. 51 sessions: the first ended, 50 remain.
18. After `sign-out-everywhere`, `password`, `confirm-email`, `undo-email`, or `delete-account`: each old cookie gives `{user:null}`, as promised.
19. (With the clock moved on) a session unused 7 days has ended; one used daily ends at 30.

## The cookie

20. HTTPS origin: `__Host-`, `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`, no `Domain`. Localhost: no `Secure`, no prefix. Plain HTTP not localhost: the handler refuses to start.
21. Over HTTPS, a valid token under an unprefixed name, a zero-width or spaced or differently cased name: not read.
22. Cookie values with `;`, CRLF, quotes, or 10KB: signed out, no crash, nothing reflected.

## Limits and pausing

23. **[LIKELY]** 30 wrong passwords to one account from one address at once: at most 10 checked; the rest 429 with `Retry-After`; onEvent's wrong-password count at most 10.
24. Paused at address A: the right password from A gets 429, from B 200.
25. 100 tries at one account from 11 addresses: a 12th address gets 429; a sign-in link from a fresh /48 still works; the owner's session can still change the password or delete the account.
26. 20 tries at different accounts from one address: the 21st, at any account, 429.
27. 200 tries across /64s in one /48: the 201st paused; another /48 isn't.
28. **[LIKELY]** One /64 spelt differently (compressed, expanded, case, leading zeros, `%zone`, bracketed with a port): one bucket. `::ffff:1.2.3.4` and `64:ff9b::1.2.3.4` count as `1.2.3.4`.
29. 6 links of mixed kinds from one address: what the 6th gets; no 6th email; the same at 21 from a /48.
30. 4 sign-in-link requests for one inbox: exactly 3 emails, all working within 15 minutes; a password link to it is still sent.
31. The server restarted: every count and pause survives.
32. 10 wrong `current` passwords at `/auth/password` from a session: the 11th, even right, 429; `sign-out-everywhere` still works.

## Not telling who has an account

33. **[LIKELY]** An unknown email, and a known one with a wrong password: identical status, body, and headers; times the same within noise over 200 tries each.
34. **[LIKELY]** 11 tries from one address at an unknown and a real email: both pause at the same count; 101 from many addresses: both the same.
35. `send-password-link` and `send-sign-in-link`: 202 `{}` byte for byte, same timing, an email each time; the no-account sign-in email has no link.
36. **[LIKELY]** A slow `sendEmail` (2 seconds): the next request's time doesn't differ between an existing and a missing address.
37. `change-email` to an address with an account and one without: the same answer and timing, and an email to each.
38. One inbox's 3 password links used up, with and without an account: the 4th request looks the same.
39. A malformed email and a well-formed unknown one: each its own fixed error, whatever accounts exist.

## Password rules

40. 14 characters refused, 15 accepted; 200 accepted, 201 refused; 15 emoji accepted, 14 refused.
41. **[LIKELY]** `current` and `next` each 200 astral characters, JSON-escaped (about 4.8KB): if the 4KB body limit refuses a password the rules allow, that's a contradiction.
42. A lone surrogate in a password: refused, not changed.
43. Common passwords with `!!`, `2024`, capitals, spaces, or punctuation added: refused; so are the email, its local part repeated, and `abcabcabcabcabc`.
44. A password with NUL, a newline, or right-to-left marks: accepted ("any characters"); signing in with its NFKC form and as typed: which work is recorded.
45. `breachedRange` gets exactly 5 hex characters, once or twice; a hanging one lets the password through after about 5 seconds, logged without the password.

## Changing password and email, and the undo link

46. A password change keeps this session, ends the rest, and emails a notice without the password.
47. **[LIKELY]** A `confirm-email` link opened signed out, signed in to another account, or by the victim when the attacker sent it: nothing happens, and the link isn't spent.
48. **[LIKELY]** A move to `new@`, someone signs up `new@` before the confirm, then the confirm: fails cleanly, with no merge and no second account on that address.
49. **[LIKELY]** After a move away from `ann@`, a fresh account at `ann@`, then the undo link: no two accounts may share `ann@`.
50. A thief moves the account twice and changes the password: the owner's first undo still restores it, ends every session, makes the old password useless, and emails a password link even past the link limits.
51. The thief undoes their own second move: the owner's undo for the first still works.
52. `change-email` raced with a password change: the move isn't stored.
53. A change to the same address, its NFKC-equal form, or its Punycode form: refused or a no-op, with no "old address" notice to the same inbox.
54. (With the clock moved on) an undo link at 7 days and a minute: refused.

## Deleting an account, and the copy of data

55. `delete-account` with a wrong password counts towards the 10 an hour; with the right one, sessions and links end (undo links too), and sign-in then looks like an unknown email.
56. `my-data`: email, creation time, sessions, pending links; no hashes, tokens, salt, cost, or limit keys; `no-store`, no CORS even with an `Origin`; 401 signed out.
57. An app table referencing `auth_users` with `ON DELETE CASCADE`: its rows go.

## The Origin check and request shapes

58. **[LIKELY]** Every POST refused with `Origin` missing, `null`, ending in `/`, another port or scheme, another case, or a subdomain; also with the right `Origin` but `Sec-Fetch-Site: cross-site` or `same-site`.
59. Content types `text/plain`, `application/jsonx`, `application/json, text/html`, two `Content-Type` headers, a missing one with an empty body: refused; `application/json; charset=utf-8` accepted.
60. Bodies of 4,097 bytes, chunked over 4KB, a short `Content-Length`, a stalled body, gzip: each a 4xx, with no hashing and no crash.
61. Duplicate keys, `__proto__` or `constructor` keys, top-level arrays, a number for the email: a clean 4xx; duplicate `email` keys never act on one and show the other.
62. GET on a POST route, POST on `/auth/session`, `HEAD`, `OPTIONS`, `PROPFIND`, an invalid method: an answer, with no CORS headers.
63. **[LIKELY]** Odd paths reach the right route or none, consistently: `/auth/sign-in/`, `/AUTH/sign-in`, `/auth//sign-in`, `/auth/%73ign-in`, `/auth/../auth/sign-in`, `/x/../auth/sign-in`, `/auth\sign-in`, `/authx`, absolute-form `http://evil/auth/sign-in`. Anything outside `/auth` reaches the app untouched.
64. After a malformed URL, a truncated body, or a dropped socket, the server answers the next request.

## Proxies and X-Forwarded-For

65. Loopback trusted: `1.1.1.1, 2.2.2.2` counts as `2.2.2.2`; forged entries to the left never change it.
66. **[LIKELY]** Loopback trusted: `127.0.0.1`, `127.0.0.1, ::1`, empty, `unknown`, garbage, 1,000 entries, two header lines: none escapes or resets one's own limits; an address that can't be worked out gives 400.
67. Nothing trusted: `X-Forwarded-For` on a direct socket is ignored, and logged a few times at most.
68. Ports (`1.2.3.4:999`, `[2001:db8::1]:80`) are dropped.
69. `trustedProxies: ["0.0.0.0/0"]` or `["::/1"]`: refused when the handler is made.
70. `Forwarded` and `X-Real-IP`: ignored.
71. 6 sources, each with an unnamed proxy's header: at most 5 log notes, the log bounded.

## The concurrency gate

72. 60 sign-ins at once: some 503 with `Retry-After`; the account's count rises only by those checked; `GET /auth/session` stays fast.
73. Busy, unknown and known emails get 503 at the same rate.
74. Whether `set-password`, `password`, and `delete-account` go through the same gate, and whether busy there counts towards the 10 an hour.

### Sized to the machine (added with 0.5.0, before the code)

85. How many hashes at once, for machines of each shape: 1 core gives 1; a 512MB container gives 2; many cores and plenty of memory, with Node's usual pool of 4 threads, gives 2; 16 cores, 32GB, and a pool of 10 give 8; nothing gives more than 16, or fewer than 1. However big the flood, hashing never takes more than half the memory the process may use.
86. The memory it sizes from: a container's limit when there is one; the machine's when there's none (Node says 0), or when the "limit" is more than the machine has.
87. A thread-pool setting that's odd (unset, empty, `abc`, `0`, `-3`, `6x`, `2000`): read as Node's own libuv reads it, and never taken as more threads than there are.
88. `HASHING` says how many at once and how many may wait (25 for each), matching what a flood meets: sign-ins beyond both are refused as busy.
89. While hashing is as busy as it gets, reading a file (which shares Node's thread pool) still takes moments, not seconds.

## Events and the log

75. **[LIKELY]** A full run's stdout, stderr, and every onEvent: no password, token, cookie value, email, or token's SHA-256.
76. **[LIKELY]** `sendEmail` throws an `Error` whose message holds the link: the log doesn't contain the link.
77. `onEvent` throws: the answer is unchanged, and the failure logged.
78. Every event has an account id and the address key, never the raw `X-Forwarded-For`; an unknown-email sign-in carries no email.

## What the known limits imply

79. The email queue past 1,000: the extra dropped and logged; a link run out while waiting isn't sent; requests stay responsive.
80. A `sendEmail` that never settles: aborted after 30 seconds; later sends still go.
81. Accounts differing by a Cyrillic `а` are separate, and `/auth/link` returns the stored form, so the page can show the difference.
82. After 100 tries in an hour, the owner signs in by link from another /48: it works.
83. A raised scrypt cost: an old hash replaced at the next correct sign-in; a stored cost above the current one refused quickly.
84. (With the clock moved on) emails of accounts sent a link are gone from the file and WAL after 60 minutes and one later request; also old limit rows and expired sessions.

## Promises the reviewer found unclear as written

- The link routes answer "202 `{}` whatever happens", yet asking for links is limited (5 per address): which status does the 6th get?
- Does using one link end the email's other links? If so, it contradicts "every link sent stays usable at least until those 15 minutes end".
- Does using a link at the wrong kind of route spend it?
- "Counted as characters": code points or grapheme clusters?
- The 4KB body limit may refuse 200-character passwords the rules allow.
- "The same work" and "the same timing" have no stated tolerance.
- The hashing queue's size and the busy threshold aren't stated. (From 0.5.0: `HASHING` states them.)
- Log notes are "a few times each at most" in one place, "5 sources" in another.
- "Ranges wide enough to be much of the internet": no threshold.
- "Opened where the account is signed in": the same session, or any of the account's?
- What should undo do when the old address now has another account?
- For `Sec-Fetch-Site`, are `none` and `same-site` refused?
- `my-data`'s "links waiting to be used": does that include move links to other addresses, and in what form?
- NFKC passwords: does signing in accept both the typed and the normal form?
- "Successful sign-ins count too" towards the 100 an hour, so an owner's own sign-ins can pause their account.
