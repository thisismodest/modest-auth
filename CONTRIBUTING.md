# Contributing

Thank you for helping. modest-auth stays secure by staying small, so the most useful
contributions often take something away, and every addition is held to the rules
below.

**Found a security problem?** Don't open an issue: see [SECURITY.md](SECURITY.md).

## Before you write code

Open an issue first for anything beyond a small fix, and say:

- **what it's for:** the problem, for a real app;
- **the smallest version** that solves it;
- **what it changes in [the threat model](docs/threat-model.md):** what new could go
  wrong, and what would stop it.

A feature that needs an option to be safe, or that only some apps need, probably
belongs in the app rather than here. That's not a judgement on the idea; it's how this
library stays small enough to trust.

## The rules every change follows

1. **No runtime dependencies.** Only Node's built-in modules. CI fails otherwise.
   Development tools need a good reason, and are installed with their scripts off.
2. **No options that change how secure it is.** If there's a safest way, it's the only way.
3. **A test for every security property**, named for what it promises, and failing if
   the promise breaks. Show it failing without your fix.
4. **Fewer lines is better.** The source stays under 1,000 lines. Prefer removing to adding.
5. **Plain, typed TypeScript** that Node runs directly: erasable syntax only (no enums,
   namespaces, or parameter properties), strict settings, relative imports with `.ts`.
6. **Comments say why,** in plain English. Docs are written for someone in a hurry: short
   sentences, no jargon left unexplained, British spelling, and the serial comma.
7. **Public API changes** update the README, the threat model if needed, and the changelog.

## Working on it

Node 24 or later.

```sh
npm ci            # development tools only; install scripts are off (.npmrc)
npm test          # the tests
npm run typecheck
npm run build     # dist/, as it would be published
npm run rules     # no dependencies, only Node's modules, no hidden characters, the size budget
npm run check     # all four, as CI runs them
```

Try a change in a real app with `node examples/node-http.ts`.

## Pull requests

- One change per pull request, with its tests.
- Describe what it does and what it changes in the threat model.
- `npm run check` passes.
- Commits say what changed and why, in plain words.

By contributing, you agree your work is released under the [MIT License](LICENSE).
