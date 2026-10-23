# modest-auth

Email and password authentication for Node.js, with sessions. No dependencies.

> **Status: early (0.x).** The core
> works and is tested; see [ROADMAP.md](ROADMAP.md) for what comes next, and don't
> use it for anything real until it has had an independent security audit. (So far it
> has had repeated rounds of internal adversarial review, by AI reviewers each given one
> area, whose findings are fixed: useful, but not a substitute for an independent one.)

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
- **Small.** About 900 lines of source: only what sign-in needs.
- **Every security property has a test** that fails if it stops being true.

If you need social sign-in, single sign-on, organisations, or passkeys today, use a
larger library. If you need people to sign in with an email and a password, safely,
this is for you.

## What it does

- **Accounts:** an email and a password. Change the password (which ends every other
  session), or delete the account.
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
  days, or ends after 7 days unused. Sign out, or sign out everywhere.
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
  - 100 tries at one account an hour from anywhere pauses signing in to it (its
    signed-in owner can still change the password or delete the account);
  - 20 sign-ins, sign-ups, or password checks from one address in 15 minutes pauses
    that address, and 200 from one IPv6 /48;
  - 10 password checks an hour by an account's own signed-in sessions (changing the
    password, deleting the account), so a stolen session can't be used to guess it.

  IPv6 addresses count by their /64; a port added by a proxy is ignored; and
  `X-Forwarded-For` is only believed through the proxies you declare.
- **No telling who has an account at sign-in:** a wrong email and a wrong password get
  the same answer, after the same work (see the threat model for one small exception).
- **Sign-ins can't take the server down:** password hashing runs two at a time, with a
  short queue. Under a flood, further sign-ins are refused as "busy" (without counting
  against anyone) until it passes.
- **Only the site's own pages can change anything:** every route that does requires
  the site's own `Origin`, and a small JSON body (which another site's page can't send
  without the browser asking first).

## Quick start

```sh
npm install modest-auth
```

Node 24 or later, and tested on 24 and 26. The first time `node:sqlite` is used, Node
24 prints a warning that SQLite is experimental: that's Node's own notice about its
built-in module, not an error. In Node 26, `node:sqlite` is a release candidate
(stability 1.2).

```ts
import { createServer } from "node:http";
import { DatabaseSync } from "node:sqlite";
import { createAuth, createHandler, handleNode, toRequest } from "modest-auth";

// Its tables (auth_users, auth_sessions, auth_limits) can live in your app's own database.
const auth = createAuth(new DatabaseSync("app.db"));
// Your site's address (HTTPS), and how many reverse proxies are in front of it:
// 0 if none, so nobody can claim another address in X-Forwarded-For.
const handler = createHandler(auth, { origin: "https://example.org", proxies: 0 });

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
| `POST /auth/sign-up` | `{ email, password }` | Makes the account, and signs in |
| `POST /auth/sign-in` | `{ email, password }` | Signs in (a fresh session; any old one ends) |
| `POST /auth/sign-out` | none, or `{}` | Ends this session |
| `POST /auth/sign-out-everywhere` | none, or `{}` | Ends every session of the account |
| `POST /auth/password` | `{ current, next }` | Changes the password, and ends every other session |
| `POST /auth/delete-account` | `{ password }` | Deletes the account and its sessions |

Every `POST` must come from the site's own pages, with `Content-Type: application/json`
(even with no body). A refusal is `{ error: { code, message } }`, with an HTTP status to
match (and `Retry-After` when paused or busy); the message is fit to show. [`examples/node-http.ts`](examples/node-http.ts) is a whole working app
in one file: run it with `node examples/node-http.ts`.

`createAuth` alone gives the same accounts, sessions, and limits, without the routes,
for an app that needs its own; see "Using the parts" below.

### With other servers

`handler.handle(request, remoteAddress)` takes a Web-standard `Request` and gives a
`Response`, or `null` for paths that aren't its own:

- **Bun:** `Bun.serve({ fetch: async (req, server) => (await handler.handle(req, server.requestIP(req)?.address)) ?? app(req) })`
- **Deno:** `Deno.serve(async (req, info) => (await handler.handle(req, info.remoteAddr.hostname)) ?? app(req))`
- **Express:** mount it first, before any body parser (which would read the body
  first): `app.use(async (req, res, next) => (await handleNode(handler, req, res)) || next())`
- **Fastify:** in an `onRequest` hook (before Fastify reads the body), take over the
  handler's own paths:

  ```ts
  fastify.addHook("onRequest", async (request, reply) => {
    if (request.url !== handler.base && !request.url.startsWith(`${handler.base}/`)) return;
    reply.hijack();
    if (!(await handleNode(handler, request.raw, reply.raw))) reply.raw.writeHead(404).end();
  });
  ```

On a Unix socket there's no client address: put it behind a proxy and set `proxies`.

## What your app does

- **Checks its own changing routes come from its own pages,** with `handler.fromSite(request)`,
  as the handler does for its own.
- **Sets short timeouts** for slow clients, such as `server.requestTimeout = 10_000` and
  `server.headersTimeout = 10_000` (Node waits five minutes by default).
- **Serves the site over HTTPS.** The handler won't start with a plain-HTTP origin,
  except `localhost` for development.
- **Leaves its routes' path to the handler:** everything under `/auth` (or `base`) is
  the handler's.
- **Declares its proxies.** Pass how many reverse proxies are in front of the server
  as `proxies`, and don't let the server, or any proxy but the outermost, be reached
  any other way. Otherwise every visitor looks like the proxy, and one person could use
  up everyone's sign-in limit; or someone could name any address they like.
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
  for another writer, foreign keys on, and deleted rows overwritten.

- **Database calls are synchronous** (that's `node:sqlite`): each is a small, indexed
  query, but it holds the event loop for that moment. Several processes can share one
  database file; while one writes, the others wait (the whole process waits) up to two
  seconds, then that request fails.
- **Many people can share one address,** behind an office, a school, or a mobile
  network. They share its allowance of 20 sign-ins in 15 minutes, so a busy shared
  address can pause briefly. Likewise everyone in one IPv6 /48 (often one organisation)
  shares 200.

## Using the parts

Without the handler, the app takes on what it does: check every changing request's
`Origin` is the site's own; start a fresh session at each sign-in, ending the old one;
and work out the caller's address with `addressKey`.

```ts
// Who's asking: here, one reverse proxy is in front. Refuse a request whose address isn't known.
const from = addressKey({ remoteAddress: req.socket.remoteAddress, forwardedFor: req.headers["x-forwarded-for"] }, 1);
if (from === "unknown") return res.writeHead(400).end();
const user = await auth.signIn(email, password, from); // or signUp; throws AuthError
// The cookie is worked out from your site's origin (HTTPS: Secure, and __Host-).
res.setHeader("set-cookie", sessionCookie(auth.startSession(user), "https://example.org"));
const current = auth.userOf(readSessionCookie(req.headers.cookie, "https://example.org") ?? "");
```

## Standards

- **NIST SP 800-63B:** passwords as it asks (length, blocklist, no composition rules,
  any characters, rate limiting, salted memory-hard hashing). One factor, so
  **Authenticator Assurance Level 1** only.
- **OWASP ASVS 5.0:** written with its authentication and session requirements in
  mind, but not yet checked against them requirement by requirement (that mapping is
  on the roadmap), so it makes no claim to a level. Level 2 would also need
  multi-factor sign-in, checking new passwords against a full breached-password set,
  letting people see and end single sessions, and telling them when their password
  changes.

## Deliberately not here

| Not here | Why |
| --- | --- |
| JWTs | A session in the database can be ended at once; a JWT is valid until it expires. For a site with a server, sessions are simpler and safer. |
| Plugins, adapters, hooks | Every extension point is a way to break the guarantees above. |
| Other databases | `node:sqlite` is built into Node; one database is one thing to get right. |
| Social sign-in, SSO, magic links | Possibly later, one at a time, and only if they can be made as small and certain as the rest. See the roadmap. |
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
