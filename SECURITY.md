# Security

modest-auth exists to be secure by being small. A report that shows it isn't is the
most useful contribution there is.

## Reporting a vulnerability

**Please don't describe it in a public issue.** Report it privately through GitHub:
the repository's **Security** tab → **Report a vulnerability**. Include what you found,
how to reproduce it, and what an attacker could do with it.

If that isn't offered, open an issue that says only that you have a security report
(no details), and the maintainer will arrange a private way to receive it.

You'll hear back within 5 working days. Once a fix is ready, it's released, an
advisory is published (crediting you, if you'd like), and the affected versions are
named.

## Supported versions

Until 1.0, only the latest release gets fixes. From 1.0, the latest minor version of
each supported major version does.

## In scope

Anything that breaks a promise in [README.md](README.md) or
[docs/threat-model.md](docs/threat-model.md), for example:

- signing in as someone else, or keeping a session after it should have ended;
- learning a password, or anything that makes one easier to guess;
- learning whether an email has an account, at sign-in;
- getting round a limit, or making the server unusable with modest effort;
- a session token, password, or hash appearing anywhere it shouldn't (logs, errors).

## Out of scope

Things the app round modest-auth is responsible for (see "What your app does" in the
README), such as serving over HTTPS, listing a CDN in front, keeping scripts out of its
pages, and, if it uses the parts without the handler, checking the `Origin` of requests. Reports of weaknesses there that modest-auth could make harder to get
wrong are still welcome, as ordinary issues.

## What we do to stay secure

- No runtime dependencies, and development tools installed with their install scripts
  turned off (`.npmrc`).
- CI fails if a runtime dependency is ever added, if anything but Node's own modules
  is imported, or if a code file holds an invisible or direction-changing character
  ("Trojan Source").
- CodeQL's security queries run on every change, and weekly.
- Every security property has a test, which must pass before anything is merged.
- GitHub Actions are pinned to exact commits.
- Releases are published to npm only by the release workflow, from a version tag on
  `main`, after every check, using npm's trusted publishing (no token is stored), with
  provenance linking each one to the commit and build that made it. Only the
  maintainer can create release tags, and `main` can't be force-pushed. (The first
  release, 0.1.0, was published by hand, without provenance: see docs/maintaining.md.)
- OpenSSF Scorecard grades the project's practices weekly.
- An independent audit before 1.0, and after any change to how passwords, sessions,
  or limits work. (So far it has had internal reviews only.)
