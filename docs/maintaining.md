# Maintaining

How the repository and releases are set up, so the code that reaches people is the
code that was reviewed. Do these once, when the repository goes public.

## The repository (GitHub settings)

- **A ruleset on `main`:** changes only by pull request; at least one approving
  review; CI, CodeQL, and Scorecard passing; no force pushes; no deletion; signed
  commits required.
- **Private vulnerability reporting on** (Security → Settings), so SECURITY.md's
  link works. Until it is, SECURITY.md must give another private way to report.
- **Secret scanning and push protection on.**
- **Dependabot alerts on** (the updates themselves are in `.github/dependabot.yml`).
- **Actions:** allow only actions pinned to a full commit SHA; workflow permissions
  read-only by default.
- **An `npm` environment** (Settings → Environments) with required reviewers, and
  limited to tags matching `v*`, which the release workflow uses: nothing is published
  without a person approving it.
- **A tag ruleset for `v*`:** only maintainers can create or move version tags. (The
  release workflow also refuses a tag that isn't on `main`.)
- **Two-factor authentication** required for everyone with write access.
- **A CODEOWNERS file** naming the maintainers, once there's more than one.

## npm

- **Trusted publishing** (npmjs.com → the package → Settings → Trusted publishing):
  GitHub Actions, this repository, workflow `release.yml`, environment `npm`. No npm
  token is stored anywhere. Under "Allowed actions", tick `npm publish` only (not
  `npm dist-tag`): a pushed tag publishes straight to npm, with no approval step.
  Then, in the package's publishing access, disallow tokens, so the workflow is the
  only way to publish. (Publishing from a laptop would also skip
  the checks: `.npmrc` turns off `prepublishOnly` along with every other script.)
- **Two-factor authentication** on every maintainer's npm account, for publishing
  and settings changes.
- **The first release** (0.1.0) is published by hand, because npm sets up trusted
  publishing only for a package that already exists: on a clean clone of main, with
  Node 24, `npm ci`, `npm run check`, then `npm publish --provenance=false` (provenance
  needs CI). Then set up trusted publishing as above. Every later release follows the
  steps below.

## A release

1. Update CHANGELOG.md: move "Unreleased" under the new version, with the date.
2. Set the version: `npm version <patch|minor|major> --no-git-tag-version`.
3. Commit, then tag the commit, signed: `git tag -s v1.2.3 -m "v1.2.3"`.
4. Push the commit and the tag. The release workflow checks the tag matches the
   version, runs every check, and publishes with provenance.
5. Check the provenance on npmjs.com links to the tagged commit.

## A security fix

1. Work in a private fork from the advisory (GitHub → Security → Advisories), not in
   public.
2. Release it as above, then publish the advisory with the affected and fixed
   versions, crediting the reporter if they'd like.

## Updating the common passwords

`node scripts/common-passwords.ts` remakes `src/common-passwords.txt` from SecLists at
the commit named in the script. To update, change the commit, run it, and review the
difference like any other change.
