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

## Layout

| What | Where |
| --- | --- |
| Public API (everything exported) | `src/index.ts` |
| Accounts, sign-in, sessions, and the limits on sign-in | `src/auth.ts` |
| The routes (Web-standard Request/Response), with the Origin check | `src/handler.ts` |
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

Unreleased, and `"private": true` in package.json until it's ready to publish (so it
can't be published by accident). It grew out of the sign-in written for a
magazine-layout app, which will move onto it.
