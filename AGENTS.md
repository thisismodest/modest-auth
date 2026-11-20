# modest-auth: agent guide

Simple, effective authentication for Node, with no dependencies. Security through
less: the smallest code that signs people in safely, the same way every time. Read
README.md for what it promises, and docs/threat-model.md for how.

## Rules

1. **No runtime dependencies, ever.** Only Node's built-ins (`node:crypto`,
   `node:sqlite`, …). Ask before adding even a development dependency.
2. **Never weaken a default, and never add an option that could.** If a change makes
   anything in docs/threat-model.md less true, stop and ask.
3. **Every security property has a test.** Add one with each; show it fails without the change.
4. **Only what's needed.** Write no more than a feature needs, and prefer removing code to adding it.
5. **No secrets or tokens in logs, errors, or test output.**
6. **Git:** commit each finished piece of work on its own; never push or publish unless
   asked. Never add a co-author line or any other attribution.
7. **Words:** British English, the serial (Oxford) comma, plain sentences, no em dashes.
   Comments explain why.

## Design: three separate questions

Keep these apart; a change that blurs them is the wrong change.

- **How people sign in day to day** (`signInWith`): any of `"link"`, `"password"`, and
  `"passkey"`. Each works on its own; no method is required by another.
- **How people get back in** (`recovery`): not a sign-in method. By default, a link to the
  account's email: a link to choose a new password where the site has passwords, else one
  that signs in once, to add a passkey. `"app"`, only with `signInWith: ["passkey"]`: no
  link into an existing account is sent at anyone's asking, so an inbox is never a way in,
  and only the app's own code makes one (`recoveryLink`).
- **Where an account is reached and proven** (the contact): email, the only kind for now.
  Sign-up always proves it by a link, whatever the methods; notices and recovery go there.
  Phones are on the roadmap, with the design written down there; nothing for them is
  built ahead of need. Accounts with no contact (a username and password) are out: the
  weakest sign-in there is, with no recovery and no notices.

## Design: how changes stay safe

- **One transaction per change.** A change of more than one statement runs in
  `atomically`, so another process sharing the database sees all of it or none. Don't
  close a race between two statements with a condition, an ordering, or a second
  clearing: put them in one transaction. Count limits before it, never inside (they
  refuse to count inside any transaction, as a rollback would undo the count).
- **The stamp is for what's checked in one step and acted on in another** (a password
  checked, then a session started; a session checked, then a passkey added): act only
  while it's still the stamp that was checked.
- **Standard practice over cleverness.** Email moves follow OWASP: the address the
  account has approves, then the new one confirms. Before adding a mechanism that fixes
  a side effect of another, ask whether the other should go instead.

## Layout

| What | Where |
| --- | --- |
| Public API (everything exported) | `src/index.ts` |
| Accounts, sign-in methods, sessions, the stamp, `allow`, passkeys kept, and the limits on sign-in | `src/auth.ts` |
| The routes (Web-standard Request/Response), with the Origin check | `src/handler.ts` |
| Messages to send (data), and `emailFor`, modest-auth's own email for one | `src/messages.ts` |
| Passkeys: the WebAuthn checks, the CBOR reader, and public keys | `src/webauthn.ts` |
| The one-plain-line rule for names (a site's, a passkey's) | `src/text.ts` |
| A software passkey authenticator, for the tests | `test/authenticator.ts` |
| Node's own http server, to and from the handler | `src/node.ts` |
| Password hashing (scrypt, with its cost recorded), and the rules for new passwords | `src/passwords.ts` |
| The common passwords refused (data, made by `scripts/common-passwords.ts`) | `src/common-passwords.txt` |
| Email addresses: the one form they're kept in | `src/emails.ts` |
| The session cookie | `src/cookies.ts` |
| Rate limits (in the database), the concurrency gate, client addresses | `src/limits.ts` |
| Errors (codes, HTTP statuses, messages) | `src/errors.ts` |
| Tests, beside what they test | `src/*.test.ts` |
| A whole app using it | `examples/node-http.ts` |
| What it protects, and how | `docs/threat-model.md` |
| What's next, and what never will be | `ROADMAP.md` |
| CI: checks, the no-dependency and import rules; CodeQL, Scorecard, releases | `.github/workflows/` |
| Repository settings, releasing, and security fixes | `docs/maintaining.md` |
| The website (plain HTML on modest-ui, no build, no JavaScript), published by `pages.yml` | `site/` |

## Commands

```sh
npm test            # node --test, TypeScript run directly
npm run typecheck   # tsc --noEmit (strict)
npm run build       # dist/ for publishing
npm run rules       # no dependencies, only node: imports, no hidden characters
npx @biomejs/biome check .  # lint and format: keep it clean
npm run check       # all four
node examples/node-http.ts
```

## Style

TypeScript that Node runs directly: erasable syntax only, `.ts` in relative imports,
`import type` for types. Strict compiler settings (see `tsconfig.json`). Small
functions, named for what they do; data in plain objects; no classes beyond
`AuthError`. Tests use `node:test` and `node:assert/strict`, named as sentences that
state the promise ("a wrong password and an unknown email get the same answer").

## Status

Early (0.x), and on npm: published by the release workflow from a version tag (see
docs/maintaining.md). 1.0 waits for an independent security audit (ROADMAP.md,
"Before 1.0").
