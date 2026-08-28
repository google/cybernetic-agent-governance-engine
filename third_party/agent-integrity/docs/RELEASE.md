# Public release runbook

The repository and packages are engineered for a public alpha release, but publication remains a manual maintainer decision.

## Required controls before changing visibility

1. Protect `main`; require pull requests, at least one maintainer review, and the `exact-head-proof` check. Disable force pushes and branch deletion.
2. Create the `npm-release` GitHub environment and require maintainer approval.
3. Enable GitHub private vulnerability reporting.
4. Configure npm trusted publishing for this repository and workflow for all four scoped packages.
5. Confirm the `@agent-integrity` npm scope is controlled by the maintainer.
6. Run `npm ci`, `npm run verify`, `npm run pack:check`, `npm audit --audit-level=high`, and `npm run release:check` from a clean checkout.
7. Inspect the exact commit after protected merge. Confirm its `exact-head-proof` run passed, then create `v<package-version>` on that commit. Do not run `npm publish` manually.

## Pre-release proof

From a clean checkout of the exact candidate:

```bash
npm ci
npm audit --audit-level=high
npm run verify
npm run release:check
npm run pack:check
git diff --check
```

The `npm-release` environment must require a human reviewer. The reviewer must confirm the workflow run is for the intended immutable tag and commit before approving deployment. The release workflow separately proves the tag commit is reachable from `origin/main`.

## Post-publication proof

Copy `docs/release-status-manifest.example.json`, replace its zero commit with the exact 40-character release commit, and run:

```bash
export GITHUB_TOKEN="$(gh auth token)"
npm run release:status -- /absolute/path/release-status-manifest.json
```

Exit `0` and status `CURRENT` mean the tag, protected-main ancestry, successful exact-commit release workflow, human environment approval, package versions, npm attestations, and downloaded tarball integrity all agree. Exit `2` or status `BLOCKED` means do not announce the release. Provider errors also fail closed and output no token or package bytes.

GitHub Free does not make every desired organization rule available. The minimum accepted public control is protected `main`, mandatory pull requests and exact-head CI, a separately reviewed `npm-release` environment, immutable release tags, npm trusted publishing, and this post-publication proof. If the account cannot enforce any of those controls, stop before publication.

The tag workflow uses SHA-pinned actions, the protected `npm-release` environment, npm OIDC provenance, exact version/tag matching, and ordered publication. Each package step is idempotent: it skips an existing version only when the registry tarball integrity exactly matches the local tarball, allowing safe recovery after a partial multi-package publish. A mismatch fails closed.

Rollback cannot delete an npm version. Deprecate a bad version, publish a forward fix with a new version, and document it in the changelog. Never move or recreate a published tag.
