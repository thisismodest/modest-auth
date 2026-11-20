# modest-auth

Zero-dependency authentication for Node.js: sign-in by emailed link, and by password or passkey if you choose, with sessions.

> **Status: early (0.x).** The core
> works and is tested; see [ROADMAP.md](ROADMAP.md) for what comes next, and don't
> use it for anything real until it has had an independent security audit. (So far it
> has had repeated rounds of internal adversarial review, by AI reviewers each given one
> area, whose findings are fixed: useful, but not a substitute for an independent one.)

## In a minute

```ts
import { createServer } from "node:http";
import { DatabaseSync } from "node:sqlite";
import { createAuth, createHandler, emailFor, handleNode, toRequest } from "modest-auth";

const ORIGIN = "http://localhost:3000";
const auth = createAuth(new DatabaseSync("app.db"), { signInWith: ["link"] });
const handler = createHandler(auth, {
  origin: ORIGIN,
  linkPage: "/account/link", // your page that emailed links open
  deliver: (message) => console.log(emailFor(message, { origin: ORIGIN }).text), // print, for now
});

createServer(async (req, res) => {
  if (await handleNode(handler, req, res)) return; // the /auth/* routes
  const user = handler.userOf(toRequest(req));
  res.end(user ? `Hello, ${user.email}` : "Hello");
}).listen(3000);
```

`POST /auth/send-sign-in-link` with `{ "email": "ann@example.org" }` prints a sign-in
link; your link page sends its token to `/auth/sign-in-with-link`, and Ann is signed in.
[`examples/node-http.ts`](examples/node-http.ts) is the same with every page, passwords,
and passkeys (`node examples/node-http.ts`). For a real site, see the quick start below.

## Why another one

Most authentication breaches aren't in the cryptography. They're logic bugs in
features: two options that interact in a way nobody tested, a flow added for one
case that opens a door in another. The more an auth library does, and the more
it can be configured, the more of those there are to find.

modest-auth does the least that sign-in needs, the same way every time:

- **No runtime dependencies.** Only Node's own `crypto` and `node:sqlite`. Nothing
  else to trust, update, or have compromised.
- **Few features, and no options that change how secure it is.** The secure way is
  the only way.
- **Hard to use wrongly.** The routes come ready-made, with the checks an app could
  forget built in.
- **Small.** About 3,000 lines of source: only what sign-in needs.
- **Every security property has a test** that fails if it stops being true.

If you need social sign-in, single sign-on, organisations, or sign-in by phone number today, use a
larger library. If you need people to sign in with an email, by a link, a password, or a passkey,
safely, this is for you.

## What it does

- **Sign in by an emailed link (or its code), a password, or a passkey:** the site
  chooses which (`signInWith`).
- **Accounts made only by a link to their email,** so nobody can sign up with someone
  else's.
- **Getting back in, separate from signing in** (`recovery`): a link to the account's
  email, or, on a passkey-only site, only a link the app's own code makes.
- **Passkeys** (WebAuthn), checked with nothing but `node:crypto`. Only public keys are
  kept.
- **Sessions** in the database, with only a hash of each token kept: sign out, sign out
  everywhere, or see and end any one.
- **Forgotten passwords;** and **changing the password or email** (as OWASP advises),
  **or deleting the account,** after a recent sign-in.
- **Notices** to the account when its password changes, a passkey is added or removed,
  or it's deleted.
- **Who may have an account,** if not everyone (`allow`), which can only refuse.
- **Messages as data,** for you to send however you like (`deliver`), in modest-auth's
  words (`emailFor`) or your own.
- **A copy of an account's data** for its owner, **a record of events** (`onEvent`), and
  **breached passwords refused** (`breachedRange`), if you want them.
- **Guessing slowed, no telling who has an account,** sign-ins that can't take the
  server down, and changes only from the site's own pages.

How each works is in "In detail" below.

## Quick start

New to it? [Step by step](https://modest-auth.com/start.html) builds a whole site with
sign-in, from an empty folder to going live.

```sh
npm install modest-auth
```

Node 24 or later, and tested on 24 and 26. The first time `node:sqlite` is used, Node
24 prints a warning that SQLite is experimental: that's Node's own notice about its
built-in module, not an error. In Node 26, `node:sqlite` is a release candidate
(stability 1.2).

It needs a long-running Node server with a persistent disk: the accounts live in one
SQLite file. Several processes on one machine can share it; several machines can't (each
would have its own accounts). So not serverless (Vercel or Netlify functions), and not
a disk that's wiped on each deploy or restart (Heroku's, or a container's own): give it a
volume.

```ts
import { createServer } from "node:http";
import { DatabaseSync } from "node:sqlite";
import { createAuth, createHandler, emailFor, handleNode, toRequest } from "modest-auth";

const ORIGIN = "https://example.org"; // your site's address (HTTPS)

// Its tables (auth_users, auth_sessions, auth_links, auth_codes, auth_passkeys, auth_challenges, auth_limits) can live in your app's own database.
// On a persistent disk or volume, outside the code (so a deploy or rebuild doesn't wipe it).
const auth = createAuth(new DatabaseSync(process.env.DATABASE_PATH ?? "app.db"), {
  // How people sign in: by an emailed link, and a password. ["link"] alone for no passwords at all.
  signInWith: ["password", "link"],
  // Optional: only some people may have an account (true to allow; it can only refuse).
  // allow: ({ email }) => members.has(email),
  // Optional: a record of who did what (no passwords, tokens, or emails in it).
  onEvent: (event) => console.log(JSON.stringify(event)),
  // Optional: refuse passwords from known breaches. Only 5-character prefixes of hashes leave.
  breachedRange: (prefix, { signal }) => fetch(`https://api.pwnedpasswords.com/range/${prefix}`, { headers: { "add-padding": "true" }, signal }),
});
const handler = createHandler(auth, {
  origin: ORIGIN,
  // Your page that emailed links open (see "The link page" below).
  linkPage: "/account/link",
  // Your way of sending each message (see "Delivering messages" below): here, modest-auth's own
  // words, by your email service. Pass the signal on, and return or await the send, so a failure
  // is caught and logged.
  deliver: (message, { signal }) => {
    const { subject, text } = emailFor(message, { origin: ORIGIN, name: "Example" });
    return sendWithYourService({ to: message.to.email, subject, text, signal });
  },
  // Only behind a proxy (see "Behind a proxy" below), such as:
  // trustedProxies: ["loopback"],
});

const server = createServer(async (req, res) => {
  if (await handleNode(handler, req, res)) return; // /auth/*, answered; anything else untouched
  const user = handler.userOf(toRequest(req)); // who's signed in, or null
  res.end(user ? `Hello, ${user.email}` : "Hello");
});
// Slow clients get ten seconds, not Node's five minutes.
server.requestTimeout = 10_000;
server.headersTimeout = 10_000;
server.listen(3000);
```

The routes take and give JSON:

| Route | Body | Does |
| --- | --- | --- |
| `GET /auth/session` | | `{ user: { email } }`, or `{ user: null }` |
| `POST /auth/link` | `{ token }` | Which email a link is for, and its kind: `{ kind, email }` |
| `POST /auth/sign-out` | none, or `{}` | Ends this session |
| `POST /auth/sign-out-everywhere` | none, or `{}` | Ends every session of the account |
| `GET /auth/sessions` | | The account's sessions: `{ sessions: [{ id, started, lastUsed, current }] }` |
| `POST /auth/end-session` | `{ id }` | Ends one of them |
| `GET /auth/my-data` | | Everything kept about the account, as a file to save |
| `POST /auth/change-email` | `{ email }` | Emails the address the account has a link to approve moving it (signed in recently) |
| `POST /auth/approve-email` | `{ token }` | From that link: emails the new address a link to confirm it (or, if it has an account, a message saying so) |
| `POST /auth/confirm-email` | `{ token }` | From the new address's link, signed in to the account: moves it, and ends every session |
| `POST /auth/delete-account` | none, or `{}` | Deletes the account and its sessions (signed in recently) |

Where sign-in links are sent: a site that signs in by link, or has no passwords (where
these links make accounts and get people back in). Otherwise they're not there at all:

| Route | Body | Does |
| --- | --- | --- |
| `POST /auth/send-sign-in-link` | `{ email }` | Emails a link to sign in, sign up, or get back in (with `recovery: "app"`, only to sign up). Where the site signs in by code, the link has a code too, and the asking browser gets the cookie its code needs |
| `POST /auth/sign-in-with-link` | `{ token, reset }`, or `{ code }` | From a sign-in link: signs in, making the account if need be. With `reset: "true"` (for someone who has lost a passkey), a fresh start: every other session, link, and passkey of the account ends. Where the site doesn't sign in by link, always. Or, by code: the link's code, typed in the browser that asked |

And only where there are passwords:

| Route | Body | Does |
| --- | --- | --- |
| `POST /auth/send-password-link` | `{ email }` | Emails a link to choose a password: to sign up, or for a forgotten one |
| `POST /auth/set-password` | `{ token, password }` | From a password link: makes the account or replaces its password, signs in, and ends every other session |
| `POST /auth/sign-in` | `{ email, password }` | Signs in (a fresh session; any old one ends) |
| `POST /auth/password` | `{ next }` | Changes the password (signed in recently), and ends every other session |

And only where there are passkeys, each part a base64url string, as the browser gives it:

| Route | Body | Does |
| --- | --- | --- |
| `POST /auth/sign-in-options` | none, or `{}` | Options for `navigator.credentials.get` (a challenge good for 5 minutes, once) |
| `POST /auth/sign-in-with-passkey` | `{ id, clientDataJSON, authenticatorData, signature, userHandle }` | Signs in (a fresh session; any old one ends) |
| `POST /auth/passkey-options` | none, or `{}` | Options for `navigator.credentials.create` (signed in recently) |
| `POST /auth/add-passkey` | `{ clientDataJSON, attestationObject, name }` | Adds the passkey made (signed in recently), named as given, or "Passkey" |
| `GET /auth/passkeys` | | The account's passkeys: `{ passkeys: [{ id, name, created, lastUsed }] }` |
| `POST /auth/remove-passkey` | `{ id }` | Removes one (signed in recently) |

"Signed in recently" is a session started in the last 10 minutes; an older one is
refused with `403` and the code `sign-in-again`, and signing in again (by any way the
site has) starts a fresh one.

The two that send a link answer `202` and `{}` whether or not the email has an account,
so nobody can tell which. (An address that has asked for too many links is answered `429`,
with `Retry-After`, again whether or not the email has one.) Every `POST` must come from the site's own pages, with
`Content-Type: application/json` (even with no body). A refusal is `{ error: { code, message } }`, with an HTTP status to
match (and `Retry-After` when paused or busy); the message is fit to show. [`examples/node-http.ts`](examples/node-http.ts) is a whole working app
in one file: run it with `node examples/node-http.ts`.

`createAuth` alone gives the same accounts, sessions, and limits, without the routes,
for an app that needs its own; see "Using the parts" below.

### The link page

Emailed links open your page at `linkPage`, with the token after `#`:
`/account/link#password=…`, `#sign-in=…`, `#move=…`, or `#email=…`. The example has one. The page:

1. **Reads the token first,** before any other script runs, and takes it out of the
   address bar (`history.replaceState`). Keep analytics and other sites' scripts off it.
2. **Asks `POST /auth/link` which email it's for, and says so:** "Choose a password for
   ann@example.org", "Sign in as ann@example.org", "Move your account to ann@new.example"
   (for a move's approval, `email` is where it moves to), or "Use this address for your
   account: ann@new.example".
3. **Waits for the person to act:** a password and a button, or just a button. It never
   acts by itself, because someone could send a person their own link, to sign them in
   to the wrong account unawares; showing the email is what lets them notice.
4. **Sends the token** with the password to `set-password`, or alone to
   `sign-in-with-link`, `approve-email`, or `confirm-email`.

Because the token is after `#`, a mail service that opens links to check them can't
use one up.

### Codes

With `"code"` in `signInWith` (beside `"link"`: a code is a sign-in link's, so it needs
links on), and a `pepper`, each sign-in link also has a 6-digit code, in the same
message (`code`), for someone reading it on another device than the one signing in:
their phone, say, signing in on a desktop. The page where they asked shows a box for it
and sends `{ code }` to `sign-in-with-link`. It works only in the browser that asked: that
browser was given a short-lived, `HttpOnly`, `SameSite=Strict` cookie (`__Host-code`),
and the code means nothing without it. A link and its code are one: either used, both
are gone. A code takes 5 wrong tries (`CODE_TRIES`), then it's gone (its link still
works, in the address's own inbox); and 10 codes a day can be typed for one address,
right or wrong (`CODES_A_DAY`), so a 6-digit code's guesses stay few. Past that, only
codes stop working for the day, answered as a wrong code (a pause would show that codes
were typed at the address today): links and passkeys still work.
A browser holds one request at a time, so only the code of the latest link it asked for
works there; asking again, even past the address's limit of links (when none is sent),
replaces it. A code lasts as its link was made to, even once the link is used or ended
(when it does nothing), so typing at it shows nothing of what happened to the account
meanwhile; deleting the account wipes its address from them at once.

Codes need a `pepper`: a random secret of 32 characters or more (never one chosen by
hand), kept outside the database, in the app's environment. Make one once, with `openssl rand -base64 32`, and give it to
`createAuth` (`pepper: process.env.AUTH_PEPPER`), the same in every process that shares
the database. A code is only 6 digits, so it's kept as a hash keyed by the pepper: a copy
of the database, without it, can't be searched for one. Changing it only stops the codes
waiting. Links and sessions don't use it: their tokens are 256 bits, so their hashes
already can't be searched.

A code can be phished, as any typed code can: a fake site asks for one for you, then
asks you for it. So the message says where to type it, and that nobody will ask for it,
and passkeys stay the way in that can't be phished. A code is only as safe as wherever
it's sent: your `deliver` can send it by email, or to the person's own chat, but never
anywhere other people, or your app's other features, can read it.

### Passkeys on your pages

The browser's own `navigator.credentials` makes and uses them; the parts travel as
base64url text. [`examples/node-http.ts`](examples/node-http.ts) does both:

```js
// Adding one, signed in recently.
const o = await post("passkey-options", {});
const made = await navigator.credentials.create({
  publicKey: { ...o, challenge: bytes(o.challenge), user: { ...o.user, id: bytes(o.user.id) }, excludeCredentials: o.excludeCredentials.map((c) => ({ ...c, id: bytes(c.id) })) },
});
await post("add-passkey", { clientDataJSON: text(made.response.clientDataJSON), attestationObject: text(made.response.attestationObject), name: "Laptop" });

// Signing in with one.
const s = await post("sign-in-options", {});
const used = await navigator.credentials.get({ publicKey: { ...s, challenge: bytes(s.challenge) } });
const r = used.response;
await post("sign-in-with-passkey", { id: used.id, clientDataJSON: text(r.clientDataJSON), authenticatorData: text(r.authenticatorData), signature: text(r.signature), userHandle: r.userHandle && text(r.userHandle) });
```

Where `bytes` and `text` turn base64url into bytes and back. Browsers that have
`PublicKeyCredential.parseCreationOptionsFromJSON` and `parseRequestOptionsFromJSON` can
take the options as they come.

### With other servers

`handler.handle(request, remoteAddress)` takes a Web-standard `Request` and gives a
`Response`, or `null` for paths that aren't its own:

- **Bun:** `Bun.serve({ fetch: async (req, server) => (await handler.handle(req, server.requestIP(req)?.address)) ?? app(req) })`
- **Deno:** `Deno.serve(async (req, info) => (await handler.handle(req, info.remoteAddr.hostname)) ?? app(req))`
- **Express:** mount it first, before any body parser (which would read the body
  first; if one does, the handler says so, rather than reading no fields; called from a
  Next.js Pages Router API route, turn Next's own off for that route:
  `export const config = { api: { bodyParser: false } }`):
  `app.use(async (req, res, next) => (await handleNode(handler, req, res)) || next())`
- **Fastify:** in an `onRequest` hook (before Fastify reads the body), take over the
  handler's own paths:

  ```ts
  fastify.addHook("onRequest", async (request, reply) => {
    if (request.url !== handler.base && !request.url.startsWith(`${handler.base}/`)) return;
    reply.hijack();
    if (!(await handleNode(handler, request.raw, reply.raw))) reply.raw.writeHead(404).end();
  });
  ```

On a Unix socket there's no client address: put a proxy in front, have it add the
client's, and name it as `trustedProxies: ["loopback"]`.

### Behind a proxy

Rate limits count each visitor's address. Behind a proxy (nginx, Caddy, a hosting
platform's load balancer, a CDN), every connection comes from the proxy, so name it and
have it pass the visitor's address on in `X-Forwarded-For`:

| In front | `trustedProxies` |
| --- | --- |
| Nothing (Node faces the internet) | leave it out |
| nginx or Caddy on the same machine | `["loopback"]` |
| nginx in another container (Docker Compose) | `["private"]` |
| A hosting platform's load balancer (Render, Fly, Railway, and the like) | `["private"]` |
| Cloudflare Tunnel (`cloudflared` on the same machine) | `["loopback"]` |
| A CDN such as Cloudflare | a proxy you run behind it (see below), never the CDN's own ranges |

A named proxy must **add** the visitor's address, not pass on whatever the visitor sent,
or visitors can choose their own: nginx passes the visitor's header on unless told
`proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;` (Caddy and most hosting
platforms add it). And `["private"]` trusts everyone on your private network: where
outside connections can arrive from private addresses (some container port-forwarding
and cluster address translation), name the proxy's own address instead.

Don't name a CDN's address ranges: its other customers can send requests from them too,
with any `X-Forwarded-For` they like. Put a proxy you run between the CDN and Node (nginx
or Caddy), have it set `X-Forwarded-For` from the CDN's own visitor header (Cloudflare's
is `CF-Connecting-IP`), accept connections only from the CDN, and name that proxy.

Any number of named proxies, on any path, is read past. Naming nothing is always safe:
at worst, visitors share the proxy's address for limits. The log says what to set: a
proxy passing addresses that isn't named, or (on an HTTPS site) one in front passing none.

### Delivering messages

modest-auth sends nothing itself. After answering, it gives your `deliver(message, { signal })`
each message as data: what it's for, who it's to, and the link in it, if any.

| `kind` | To | Has |
| --- | --- | --- |
| `sign-up` | an address with no account | `link`, `expires`: to choose a password, or (without passwords) to sign in; and, without passwords, where the site signs in by code, `code` |
| `sign-in` | an account | `link`, `expires`; and where the site signs in by code, `code` (not on a link the app's own code makes, which nobody asked for) |
| `new-password` | an account | `link`, `expires`: a forgotten password |
| `no-account` | an address with no account, that asked to sign in where there are passwords | |
| `passkey-only` | an account that signs in by passkey only, where someone asked for a link into it (`recovery: "app"`) | |
| `approve-email` | an account, someone signed in to it having asked to move it | `email` (where it would go), `link` (to approve it), `expires` |
| `confirm-email` | an account's new address, once the move's approved | `link`, `expires` |
| `email-in-use` | an address with an account of its own, that another account asked to move to | |
| `password-changed` | an account | |
| `passkey-added`, `passkey-removed` | an account | nothing more: a passkey's name is chosen by whoever added it, so it isn't given |

Each has `to`, a contact: `{ email }`. With TypeScript, a `switch` on `kind` that misses
one fails to build, so a new kind in a later version can't go unsent.

`emailFor(message, { origin, name })` writes modest-auth's own plain-text email for any
of them: its subject names the site (`name`, or its host), and its text names it with its
host ("Example (example.org)"), which a copycat can't borrow. Or write your own, in your
words and language, from `kind` and the rest. Either way, send it with any email service
with an HTTPS API, using Node's own `fetch`, with nothing to install. With Resend, say:

```ts
deliver: async (message, { signal }) => {
  const { subject, text } = emailFor(message, { origin: ORIGIN, name: "Example" });
  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { authorization: `Bearer ${process.env.RESEND_API_KEY}`, "content-type": "application/json" },
    body: JSON.stringify({ from: "Example <signin@example.org>", to: message.to.email, subject, text }),
    signal, // aborts after 30 seconds, so a stuck service can't hold up others
  });
  if (!res.ok) throw new Error(`Resend answered ${res.status}`); // logged, without the message
},
```

Whatever sends them:

- **Turn off click tracking** in the email service. Many rewrite links to go through
  their own servers first, which would hand the sign-in token to them, and their logs.
- **Put the link in once, as it is:** no shortening, nothing added to it.
- **Say how long it lasts,** and that it can be ignored if it wasn't asked for
  (`emailFor`'s text shows how).
- **Never log a message or its link.**
- **Hand the message over and return,** doing the same work for every kind: `deliver`
  runs on the same thread as the requests, and nothing is delivered to an address
  `allow` refuses, so slow synchronous work for some messages could show which
  addresses got one. Sending it with `fetch`, as above, is fine.

Verify your sending domain with the service (SPF, DKIM, and DMARC records), or the emails
land in spam. Keep the API key in an environment variable.

In development, with no email service yet, print the emails instead:

```ts
deliver: (message) => console.log(message.to.email, emailFor(message, { origin: ORIGIN }).text),
```

Each email, with its link, appears where the app's output does: open the whole link,
including the part after `#`. Each link works once, and only 3 of each kind go to one
address in 15 minutes: past that nothing is printed (the page still says it was sent,
as it does for an address with no account), so use another address or wait. Don't
print messages in production: they hold the link, and logs are kept.

## What your app does

- **Has a link page** that does the four things above.
- **Delivers messages,** passing the `signal` on, returning (or awaiting) the send so a
  failure is caught, with click tracking off, and without logging them (they hold the
  link).
- **Checks its own changing routes come from its own pages,** with `handler.fromSite(request)`,
  as the handler does for its own.
- **Sets short timeouts** for slow clients, such as `server.requestTimeout = 10_000` and
  `server.headersTimeout = 10_000` (Node waits five minutes by default).
- **Serves the site over HTTPS.** The handler won't start with a plain-HTTP origin,
  except `localhost` for development.
- **Leaves its routes' path to the handler:** everything under `/auth` (or `base`) is
  the handler's.
- **Names the proxies in front, if any,** as `trustedProxies`, and has them add the
  client's address (see "Behind a proxy"). If it doesn't, its visitors share the
  proxy's address for limits (safe, if shared), and the log says what to set.
- **Sends JSON from its pages,** with `fetch` (a plain HTML form can't send JSON; see
  the example).
- **Keeps its pages free of injected scripts** (a content security policy helps). No
  auth library can protect an account from a script running in its own pages.
- **Backs up the database,** and keeps it as private as the server. Backups keep
  deleted accounts until they're replaced.
- **Links its own tables to accounts,** so they go when an account is deleted:
  `user TEXT REFERENCES auth_users(id) ON DELETE CASCADE`.
- **Keeps passwords out of its logs,** and its proxy's: log no request bodies for `/auth`.
- **Keeps the database on a local disk** (SQLite's locking isn't safe on network drives).
- **Watches for refusals:** a run of `429` (too many tries) or `503` (busy) is someone
  guessing.

Worth knowing:

- **`createAuth` sets up the database connection** it's given: WAL, a two-second wait
  for another writer, foreign keys on, and deleted rows overwritten. Those are settings
  of the connection, so if it's your app's own, its deleted rows are overwritten too.
  Giving modest-auth a database file of its own keeps the two apart.
- **Database calls are synchronous** (that's `node:sqlite`): each is a small, indexed
  query, but it holds the event loop for that moment. Several processes can share one
  database file: each change that takes more than one statement is one transaction, and
  while one process writes, the others wait (the whole process waits) up to two
  seconds, then that request fails. Don't call modest-auth inside a transaction of your
  own on its connection, nor hold one open across an `await` there: every call refuses
  inside one, as your rollback would undo what it did (a sign-out, say) and its limits.
  If your app does either, give modest-auth a connection of its own.
- **Deleting an account leaves nothing to find,** in the file or its WAL: an erasure
  request after it is answered by there being nothing left (backups aside, until
  they're replaced). If you need a record that it happened, keep one from the
  `account-deleted` event, which names the account by its id. Anything you must keep
  (orders, invoices) belongs in your own tables, keyed by that id. Where the site signs
  in by code, the day's count of codes for the address, kept as a hash of it, lasts out
  its day.
- **Many people can share one address,** behind an office, a school, or a mobile
  network. They share its allowance of 20 sign-ins and 5 links in 15 minutes, so a busy
  shared address can pause briefly. Likewise everyone in one IPv6 /48 (often one
  organisation) shares 200, and 20 links.
- **Hashing is sized when modest-auth loads,** from the machine: 2 at once on most
  small servers, 1 on a single core, and up to 16 on a large one. `HASHING` says how
  many run at once and how many may wait. Node's thread pool is 4 threads unless
  `UV_THREADPOOL_SIZE` is set before Node starts, so a machine with more cores hashes
  more at once only once that's raised (to the cores plus two, say).
- **With `trustedProxies: ["private"]`,** anyone on your own private network is trusted
  as a proxy would be, so could write their own address into `X-Forwarded-For`: name
  the proxy's address instead if strangers can reach that network.

## Using the parts

Without the handler, the app takes on what it does: check every changing request's
`Origin` is the site's own; start a fresh session at each sign-in, ending the old one;
work out the caller's address with `addressKey`; and for links, turn the link
`requestLink` gives into its message with `messageFor(link, url)` (the URL being your
link page, with `#`, the kind, `=`, and the token), send it after answering, whatever it
says, and answer the same either way; when it gives null, send nothing. Never send a
link back to whoever asked: it goes only to its address.

`recoveryLink(email)` is the one link made for the app's own code alone: the way back
in where `recovery` is `"app"`, for someone the app has vouched for another way (an
admin, support). Whoever opens it is in, so it's never a route, and never sent to anyone
the app hasn't checked. It isn't counted against the address's links, so it's also the
one for a link the app's own code hands someone for an existing account (printed in a
terminal, say): `requestLink` is for people asking, and its limits are theirs. Wherever
it's the way back in (a password link, or a sign-in link on a site that doesn't sign in
by link), opening it is a fresh start: every session, link, and passkey of the account
ends, not just a sign-in.

With codes, a sign-in link asked for needs the asking browser's token: make a new one
each time with `newAsker()`, pass it to `requestLink` as its fourth argument, and give it
to the browser with `codeCookie(asker, origin)` whatever the answer, null included, so
whether a cookie was set shows nothing. Its code is stored under it either way. When the
code comes back, read the token with `readCodeCookie(header, origin)` and pass both to
`useSignInCode(asker, code, from)`; once signed in, clear it with `clearedCodeCookie(origin)`.

`endAccess(email)` is the other side, also the app's own code alone: every session,
link, and passkey of the account ends, and its password, so nobody is in, or can get in,
but by a new link to the address (where `recovery` is `"app"`, only one the app makes,
with `recoveryLink`). For when someone else got in, or the app's own records no longer
give the address to the person it was. It only takes away, and sends nothing. It works
whatever `allow` says, so someone the app stops allowing keeps no password or passkey
that would work if they were allowed back. The account stays, so the next person to sign
in at that address has it, and its id: whatever the app keeps under that id, it moves or
removes first.

```ts
// Who's asking (behind a proxy, name it as a second argument, such as ["loopback"]).
// Refuse a request whose address isn't known.
const from = addressKey({ remoteAddress: req.socket.remoteAddress, forwardedFor: req.headers["x-forwarded-for"] });
if (from === "unknown") return res.writeHead(400).end();
const user = await auth.signIn(email, password, from); // or usePasswordLink, useSignInLink; throws AuthError
// The cookie is worked out from your site's origin (HTTPS: Secure, and __Host-).
res.setHeader("set-cookie", sessionCookie(auth.startSession(user), "https://example.org"));
const current = auth.userOf(readSessionCookie(req.headers.cookie, "https://example.org") ?? "");
```

## In detail

- **How people sign in is the site's choice,** and has to be made (`signInWith`): any of
  an emailed link, a password, and a passkey, each on its own or mixed, and, beside the
  link, its code (typed in the browser that asked). Every account is still made by a
  link to its email, which proves the address.
- **Getting back in is separate:** a link to the account's email, whatever the methods
  (to choose a new password where there are passwords, else to sign in once and add a
  passkey). Or, on a site that signs in by passkey alone, `recovery: "app"`: no link
  into an existing account is sent at anyone's asking, so an inbox is never a way in,
  and only the app's own code makes one (`recoveryLink`), for someone it has vouched for.
- **Passkeys** (WebAuthn), which can't be phished: added after a recent sign-in, and
  used without typing an email (the device offers the site's passkeys). Checked with
  nothing but `node:crypto`, step by step as the spec numbers them; no attestation, which
  is for organisations that only allow certain hardware. Only public keys are kept, so a
  copy of the database signs nothing. A counter that doesn't go up, where a passkey
  counts at all, means a copy of it, and is refused. Adding or removing one is told to the
  account's email; removing one signs every other session out; and getting back in by a
  link is a fresh start, ending every session, link, and passkey of the account, so one a
  thief added goes too.
- **Accounts:** an email, made by a link emailed to that address, so nobody can sign up
  with someone else's email. Where there are passwords, whoever opens the link chooses
  one; where there aren't, opening a sign-in link makes the account.
- **Who may have an account,** if not everyone: your `allow(contact)` is asked before a
  link is sent, an account made, or a session started or used, so someone you stop
  allowing is signed out at their next request, for good (their sessions end). It can
  only refuse, never let anyone in,
  and the answer to whoever's asking is the same either way.
- **Changes need a recent sign-in:** changing the password or email, or deleting the
  account, needs a session started in the last 10 minutes (`RECENT_MINUTES`); an older
  one is asked to sign in again, by any way the site has. Nothing asks for the password,
  so a stolen session can't be used to guess it.
- **Forgotten passwords:** a password link, sent to an email that has an account,
  chooses a new password, and signs out everywhere else.
- **Changing the email,** as OWASP advises: the address the account has approves it
  first, by a link, then the new address confirms it, by a link opened where the account
  is signed in. Nothing goes to the new address until the old one approves, so someone
  with the password, or a session, can't move the account away. Every session ends.
- **Notices:** a message to the account when its password changes, a passkey is added
  or removed, or it's deleted.
- **A copy of an account's data** for its owner (as UK GDPR asks): its email, when it
  was made, its sessions, and links waiting to be used; nothing that signs anyone in.
- **A record of events,** if you want one: sessions started, wrong passwords, pauses,
  new accounts, password and email changes, signing out, access the app ended, and
  deletions, given to your `onEvent` after each answer, with the account's id and where
  it came from, but never a password, token, or email.
- **Breached passwords refused,** if you want: new passwords checked against a
  breached-password set such as Have I Been Pwned's, through your `breachedRange`,
  which is given only the first 5 characters of the password's SHA-1 (of its normal
  form, and of the form typed if that differs).
- **Signing in** with a link emailed on request, always offered, or with the password
  where there is one: so someone whose sign-in is paused by another's guessing can still
  get in.
- **Messages are yours to send:** modest-auth gives your `deliver` each one as data
  (what it's for, who it's to, and its link), after answering. Send it with any email
  service, in modest-auth's own words (`emailFor`) or your own, in any language.
- **Emailed links:** single-use, kept only as a hash, and short-lived (60 minutes to
  choose a password, 15 to sign in). The token follows `#` in the link, which browsers
  never send to a server, so it stays out of logs and `Referer` headers. At most 3 of
  each kind to one address in 15 minutes, and asking for more never ends the ones sent
  (using one does: then the address's other links end too), so nobody can flood an
  inbox, or (while the email queue isn't full) stop its owner getting a link.
- **New passwords** follow NIST SP 800-63B: 15 to 200 characters (counted as
  characters, not bytes), any characters at all, no rules about mixing them, but not
  one of the 5,500 passwords that long in two public lists of common ones (one from
  the UK's National Cyber Security Centre), nor one with just spaces, punctuation,
  capitals, or numbers on the end added; not made from the email; and not with fewer
  than four different characters.
- **Passwords:** hashed with scrypt at OWASP's suggested cost (N=2¹⁷, r=8), salted,
  compared in constant time. Never stored, never logged. Each hash records its cost,
  so the cost can be raised: an older hash is made again at the new cost the next time
  its owner signs in.
- **Sessions:** a 256-bit random token in a cookie. The database keeps only a hash of
  it, so a copy of the database can't be used to sign in as anyone. A session lasts 30
  days, or ends after 7 days unused. Sign out, sign out everywhere, or see the account's
  sessions (when each started, and was last used) and end any one.
- **The cookie:** `HttpOnly`, `SameSite=Lax`, and over HTTPS `Secure` with the
  `__Host-` prefix, so no script can read it and no other host can set or receive it.
- **Emails:** normalised, so the same letters in compatibility forms (`ａｎｎ` and
  `ann`) are one account, and domains kept in their ASCII form (`bücher.de` is kept as
  `xn--bcher-kva.de`); and invisible characters, quotes, and brackets refused, so
  one can't carry markup into a page that shows it. (Letters from other alphabets that
  look alike, such as a Cyrillic `а`, make a different address: see the threat model.)
- **Guessing is slowed,** counted before any password is checked, and kept in the
  database (so a restart doesn't reset it, every process shares it, and nothing can
  flood it out):
  - 10 tries at one account from one address in 15 minutes pauses that address for
    that account (but not its owner, signing in from elsewhere);
  - 100 tries at one account an hour from anywhere pauses signing in to it by password
    (its owner can still sign in by link);
  - 20 sign-ins, links, or password checks from one address in 15 minutes pauses
    that address, and 200 from one IPv6 /48;
  - 5 links asked for from one address in 15 minutes, and 20 from one IPv6 /48, so
    nobody can use sign-up to email strangers in bulk.

  IPv6 addresses count by their /64; a port added by a proxy is ignored; and
  `X-Forwarded-For` is only believed from the proxies you name, read past however
  many there are. Name none and it's ignored, which is always safe; get it wrong and
  the log says what to set.
- **No telling who has an account:** signing in, signing up, and asking for a link
  each give the same answer, after the same work, whether or not the email has one;
  and an email goes either way (for a sign-in link to an email with no account, one
  saying so). See the threat model for one small exception.
- **Sign-ins can't take the server down:** password hashing runs only a few at a time,
  sized to the machine (no more than its cores, half its memory, or Node's thread pool
  less two, so file reads always keep a thread), with a short queue. Under a flood,
  further sign-ins are refused as "busy" (without counting against anyone) until it
  passes.
- **Only the site's own pages can change anything:** every route that does requires
  the site's own `Origin`, and a small JSON body (which another site's page can't send
  without the browser asking first).

## Standards

- **NIST SP 800-63B:** passwords as it asks (length, blocklist, no composition rules,
  any characters, rate limiting, salted memory-hard hashing). A passkey that verifies
  the person (a fingerprint, face, or PIN on the device) is phishing-resistant and two
  factors in one, which NIST counts towards **Authenticator Assurance Level 2**; but an
  account is only as strong as its weakest way in, and a link or a password is one
  factor (**Level 1**). An account that keeps only passkeys is on the roadmap.
- **OWASP ASVS 5.0:** written with its authentication and session requirements in
  mind, but not yet checked against them requirement by requirement (that mapping is
  on the roadmap), so it makes no claim to a level.

## Deliberately not here

| Not here | Why |
| --- | --- |
| JWTs | A session in the database can be ended at once; a JWT is valid until it expires. For a site with a server, sessions are simpler and safer. |
| Attestation | It proves what device made a passkey, for organisations that only allow certain hardware; synced passkeys mostly can't give it, and nothing here relies on it. |
| Plugins, adapters, hooks | Every extension point is a way to break the guarantees above. The functions you give it only deliver (`deliver`), observe (`onEvent`), or refuse (`allow`, `breachedRange`): none can let anyone in. |
| Other databases | `node:sqlite` is built into Node; one database is one thing to get right. Postgres perhaps later, beside SQLite, only if it adds no way in: see the roadmap. |
| Social sign-in, SSO | Possibly later, one at a time, and only if they can be made as small and certain as the rest. See the roadmap. |
| A user interface | Your forms, your words. |

## Documents

- [The site](site/): the homepage, docs, security, and legal pages, published to GitHub Pages at [modest-auth.com](https://modest-auth.com).

- [SECURITY.md](SECURITY.md): how to report a vulnerability, and what's in scope.
- [docs/threat-model.md](docs/threat-model.md): what it protects, against whom, and how.
- [ROADMAP.md](ROADMAP.md): what's next, and what will never be.
- [CONTRIBUTING.md](CONTRIBUTING.md): how to help, and the rules every change follows.
- [CHANGELOG.md](CHANGELOG.md): what changed, version by version.

## License

[MIT](LICENSE).
