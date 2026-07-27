# Git Workflow Standards — Cybernetic Governance Engine

> **⚠️ REFERENCE ARCHITECTURE ONLY — NOT FOR PRODUCTION USE**
> CAGE is a reference architecture. The workflow standards below are
> illustrative best practices. There is no production deployment target.
> `hotfix/*` and `release/*` branch patterns are documented for
> reference only — no production release process exists.

**Version:** 1.1
**Effective:** 2026-06-14
**Applies to:** All contributors to `cybernetic-governance-engine`

> **v0.1.0 Release Note (2026-06-08):** The stable `v0.1.0` tag has been pushed to origin and the GitHub Release is published as Latest. The `rc-v0.1.0` branch is retained as a permanent release boundary marker per §4.3 of `docs/RELEASE_PLAN.md`. All future feature work branches from `main`. The `pre-push` hook blocks direct pushes to both `main` and `rc-v0.1.0`.

This document is the authoritative reference for Git commit standards, branch naming, local setup requirements, pull request process, and protected branch workflow. Compliance is mandatory. Deviations will cause CI failures, rejected commits, or blocked pushes.

---

## Table of Contents

1. [Local Setup Requirements](#1-local-setup-requirements)
2. [Commit Message Format](#2-commit-message-format)
3. [Branch Naming Conventions](#3-branch-naming-conventions)
4. [Pull Request Standards](#4-pull-request-standards)
5. [Protected Branch Workflow](#5-protected-branch-workflow)
6. [What Not to Do](#6-what-not-to-do)

---

## 1. Local Setup Requirements

### 1.1 Run the hook installer immediately after cloning

Every engineer must run the following command once after cloning the repository:

```bash
bash scripts/setup_git_hooks.sh
```

This is not optional. The script installs two enforcement mechanisms that are prerequisites for contributing:

| Installed artifact | Location | Purpose |
|---|---|---|
| Commit message template | `.gitmessage` (via `git config commit.template`) | Pre-fills your editor with the required format on every `git commit` |
| `commit-msg` hook | `.git/hooks/commit-msg` | Validates the commit message before the commit is recorded |
| `pre-push` hook | `.git/hooks/pre-push` | Blocks direct pushes to `main` and `rc-v0.1.0` |

### 1.2 What the `commit-msg` hook enforces

The hook runs synchronously at commit time. It will **reject** the commit and print a descriptive error if any of the following conditions are true:

- The subject line does not match the Conventional Commits pattern `<type>(<scope>)?: <description>`
- The type is not one of the ten permitted values (see [§2.2](#22-valid-types))
- The subject line exceeds 72 characters (warning, not hard rejection — but treat it as a hard limit)
- The subject is empty after stripping comment lines

Merge commits (`Merge branch ...`) are automatically exempted from validation.

### 1.3 Verifying the installation

After running the script, confirm the hooks are active:

```bash
git config --get commit.template   # should print: /path/to/repo/.gitmessage
ls -la .git/hooks/commit-msg       # should be executable
ls -la .git/hooks/pre-push         # should be executable
```

If you reinstall or re-clone, re-run the script. The `.git/` directory is not tracked by version control.

---

## 2. Commit Message Format

This project follows [Conventional Commits v1.0.0](https://www.conventionalcommits.org/). Every commit must conform to this specification. The `commit-msg` hook enforces the subject line format automatically; the body and footer rules are enforced by code review.

### 2.1 Structure

```
<type>(<scope>): <short summary>
│       │         │
│       │         └─ Imperative mood. No period. ≤ 72 chars total for this line.
│       └─ Optional. One of the permitted scopes listed in §2.3.
└─ Required. One of the ten permitted types listed in §2.2.

[blank line]

[optional body — wrap at 72 chars per line]

[blank line]

[optional footer(s)]
```

The subject line (first line) is the only mandatory element. The blank line separating the subject from the body is mandatory whenever a body is present.

### 2.2 Valid Types

| Type | When to use |
|---|---|
| `feat` | Introduces a new feature visible to users or operators |
| `fix` | Corrects a defect in existing behaviour |
| `docs` | Documentation changes only — no code logic altered |
| `style` | Whitespace, formatting, missing semicolons — zero logic change |
| `refactor` | Code restructuring that neither adds a feature nor fixes a bug |
| `perf` | A change that improves performance without altering behaviour |
| `test` | Adding missing tests or correcting existing tests |
| `chore` | Build system changes, dependency bumps, tooling updates |
| `ci` | Changes to CI/CD pipeline configuration or scripts |
| `revert` | Reverts a previous commit; subject must reference the reverted SHA |

No other types are permitted. If your change does not fit any of these, decompose it into smaller commits that do.

### 2.3 Valid Scopes

Scope is optional but strongly recommended. Use exactly one of:

`gateway` · `compliance` · `infra` · `governance` · `tests` · `docs` · `ci` · `agentsight` · `advisor` · `nemo` · `opa`

If your change genuinely spans multiple scopes, prefer the scope of the primary affected subsystem. If no scope applies (e.g., a root-level tooling change), omit the parentheses entirely.

### 2.4 Subject Line Rules

- **Imperative mood:** Write "add rate limiter", not "added rate limiter" or "adds rate limiter"
- **No period** at the end of the subject line
- **≤ 72 characters** for the entire subject line including type, scope, and colon
- **No capitalisation** of the first word of the description (the type is already lowercase)
- **Be specific:** the subject must convey what changed, not just that something changed

### 2.5 Body Rules

The body is optional but required for any commit that is not self-evident from the subject line alone. When present:

- Separate from the subject with exactly one blank line
- Wrap every line at **72 characters**
- Explain **what** changed and **why** — not how (the diff shows how)
- Reference design decisions, trade-offs, links to ADRs, or relevant context
- Do not repeat the subject line verbatim

### 2.6 Footer Rules

Footers appear after the body, separated by a blank line. Two footer tokens are defined for this project:

**Issue references:**
```
Closes #42
Refs #18, #19
```

**Breaking changes** — use either the footer token or the `!` shorthand in the subject:

```
BREAKING CHANGE: The /v1/policy endpoint now requires an Authorization header.
All callers must update their request configuration before deploying.
```

Or equivalently in the subject:

```
feat(gateway)!: require Authorization header on /v1/policy
```

Both forms are valid. The `!` shorthand is preferred for brevity when the breaking change is self-evident from the subject.

**Co-authorship:**
```
Co-authored-by: Jane Smith <jane@example.com>
```

### 2.7 Complete Examples

**Minimal valid commit:**
```
fix(compliance): correct OSCAL component UUID collision on re-export
```

**Full commit with body and footer:**
```
feat(gateway): add Redis-backed rate limiter for OPA policy calls

Implements token-bucket rate limiting at the gateway layer to prevent
OPA from being overwhelmed during burst traffic. The limit is
configurable via the GOVERNANCE_THRESHOLDS_PATH JSON file under the
key "opa_rate_limit_rps".

Without this change, a burst of concurrent advisor requests causes OPA
to queue indefinitely, producing P99 latencies above the 2-second SLA
threshold defined in config/governance_thresholds.json.

Closes #42
```

**Breaking change:**
```
refactor(compliance)!: rename oscal_exporter module to oscal_pipeline

BREAKING CHANGE: Any code importing from src.compliance_bridge.oscal_exporter
must be updated to import from src.compliance_bridge.oscal_pipeline.
The old module name is removed with no compatibility shim.
```

**Revert:**
```
revert: feat(gateway): add Redis-backed rate limiter for OPA policy calls

Reverts commit a3f9c12. The Redis client introduced a connection leak
under high concurrency that was not caught in integration tests. Will
re-land after the leak is fixed in the client wrapper.
```

---

## 3. Branch Naming Conventions

### 3.1 Required patterns

All branch names must use **lowercase kebab-case**. No underscores. No uppercase letters. No spaces.

| Branch purpose | Pattern | Example |
|---|---|---|
| New feature | `feat/<ticket-id>-short-description` | `feat/42-redis-rate-limiter` |
| Bug fix | `fix/<ticket-id>-short-description` | `fix/18-oscal-uuid-collision` |
| Chore / tooling | `chore/<description>` | `chore/pin-ci-actions-sha` |
| Documentation | `docs/<description>` | `docs/stpa-control-diagram` |
| Release candidate | `release/v<X.Y.Z>` | `release/v2.1.0` |
| Hotfix | `hotfix/<ticket-id>-description` | `hotfix/99-redis-timeout` |
| Refactor | `refactor/<description>` | `refactor/gateway-middleware` |
| CI / pipeline | `ci/<description>` | `ci/add-license-guard` |
| Experiment / spike | `spike/<description>` | `spike/cbf-formal-proof` |

When a ticket ID exists, it must be included in `feat/` and `fix/` branches. For `chore/`, `docs/`, `ci/`, and `spike/` branches, a ticket ID is optional.

### 3.2 Length limit

The description segment after the prefix must be **≤ 30 characters**. Branch names that are too long become unwieldy in terminal output and GitHub UI.

### 3.3 Lifetime

Feature and fix branches are **short-lived**. They must be deleted after their PR is merged. Do not leave stale branches in the remote. The pre-push hook will warn if you attempt to push to a protected branch directly.

### 3.4 Branches that trigger CI

The following branches trigger the full CI suite (including the License Guard workflow at `.github/workflows/license_guard.yml`):

| Branch pattern | Trigger type |
|---|---|
| `main` | `push` and `pull_request` |
| `rc-v0.1.0` | `push` and `pull_request` |
| `release/**` | `push` and `pull_request` |

Feature branches (`feat/**`, `fix/**`, etc.) trigger CI only when a pull request is opened against one of the above protected branches. CI does not run on arbitrary pushes to feature branches unless a PR exists.

This means: **CI gates are only exercised through the PR process.** Pushing directly to a protected branch bypasses all CI gates. This is why direct pushes are prohibited.

---

## 4. Pull Request Standards

### 4.1 PR title format

The PR title becomes the squash-merge commit message on the integration branch. It must follow Conventional Commits format exactly:

```
feat(gateway): add Redis rate limiter
fix(compliance): correct UUID collision on OSCAL re-export
chore(ci): pin actions/checkout to SHA for supply-chain hardening
```

GitHub will use this title verbatim as the commit message when you squash-merge. A malformed PR title produces a malformed commit on `main`. There are no exceptions.

### 4.2 Using the PR template

When you open a PR, GitHub automatically populates the description with `.github/pull_request_template.md`. Every section must be completed before requesting review. Do not delete sections. Do not leave placeholder text.

**Required sections:**

| Section | What to write |
|---|---|
| **Summary** | One paragraph explaining what the PR does and why it is needed. Not a list of files changed — that is what the diff is for. |
| **Type of Change** | Check every applicable box. If you check `BREAKING CHANGE`, the PR title must include `!` or the body must include a `BREAKING CHANGE:` footer. |
| **Related Issues / ADRs** | Every PR must reference at least one issue (`Closes #n`) or explicitly state `N/A` with a justification. |
| **Changes Made** | A bullet list of the specific components or files changed and the reason for each change. |
| **Testing** | Check every applicable testing method. If you check "No tests needed", you must explain why in the same line. |
| **Compliance & Security Checklist** | All five items must be checked. If an item does not apply, check it and add a parenthetical note. |
| **Deployment Notes** | Describe any migration steps, environment variable changes, or rollout sequencing requirements. Write `N/A` only if there are genuinely none. |

### 4.3 CI requirements before merge

All of the following checks must be green before a PR can be merged:

- **License Guard** (`.github/workflows/license_guard.yml`) — no GPL/AGPL/LGPL dependencies introduced
- **CI suite** (`.github/workflows/ci.yml`) — all tests pass, linting clean
- Any other workflow that runs on the target branch

A single failing check blocks merge. Do not ask reviewers to approve a PR with failing CI.

### 4.4 Review requirements

- At least **one approving review** from a maintainer is required before merge
- The author may not approve their own PR
- Review comments marked as "blocking" must be resolved before merge
- Do not dismiss reviews without addressing the underlying concern

### 4.5 Merge strategy

**Squash merge is the required strategy for all feature, fix, chore, docs, ci, and refactor PRs into the integration branch.**

Squash merging produces one clean commit per PR on the integration branch, keeping the history linear and bisectable. The squash commit message is taken from the PR title — which is why the PR title must follow Conventional Commits format.

Merge commits are reserved for merging the integration branch (`rc-v*`) into `main` at release time, where preserving the release boundary in the graph is intentional.

Rebase merging is not used in this repository.

---

## 5. Protected Branch Workflow

The following is the complete, required lifecycle for every change. There are no shortcuts.

### Step 1 — Branch from the integration branch

```bash
git checkout main          # or rc-v<current> if a release cycle is active
git pull origin main
git checkout -b feat/42-redis-rate-limiter
```

Never branch from a stale local copy. Always pull before branching.

### Step 2 — Make focused, atomic commits

Each commit should represent one logical unit of change. If you find yourself writing "and" in the commit subject, split the commit.

```bash
# Good — one logical change per commit
git commit -m "feat(gateway): add Redis client wrapper with connection pooling"
git commit -m "test(gateway): add unit tests for Redis client retry logic"

# Bad — multiple unrelated changes in one commit
git commit -m "feat: add Redis client and fix OSCAL bug and update docs"
```

The `commit-msg` hook validates each commit as you make it. Fix rejections immediately — do not accumulate invalid commits and try to fix them at push time.

### Step 3 — Push the feature branch

```bash
git push origin feat/42-redis-rate-limiter
```

The `pre-push` hook will block this command if your current branch is `main` or `rc-v0.1.0`. If you are on a feature branch, the push proceeds normally.

### Step 4 — Open a pull request

Open a PR on GitHub targeting `main` (or the active release branch). GitHub will auto-populate the PR description from `.github/pull_request_template.md`.

- Set the PR title to a valid Conventional Commits subject line
- Complete every section of the template
- Assign at least one reviewer

### Step 5 — Pass all CI checks

CI runs automatically on PR open and on every subsequent push to the branch. Monitor the checks panel. If a check fails:

1. Read the failure output
2. Fix the issue locally
3. Commit the fix (using a valid commit message)
4. Push — CI re-runs automatically

Do not merge with failing checks.

### Step 6 — Obtain review approval

Address all review comments. When all blocking comments are resolved and at least one maintainer has approved, proceed to merge.

### Step 7 — Squash merge

Use the "Squash and merge" button on GitHub. Confirm that the squash commit message matches the PR title (GitHub pre-fills it). Do not edit the message to something that does not follow Conventional Commits.

### Step 8 — Delete the branch

After merge, delete the feature branch both remotely (GitHub offers a button) and locally:

```bash
git branch -d feat/42-redis-rate-limiter
git remote prune origin
```

---

## 6. What Not to Do

The following practices are **prohibited**. They will be caught by hooks, CI, or code review and must be corrected before any work is merged.

### 6.1 Committing directly to protected branches

```bash
# PROHIBITED
git checkout main
git commit -m "fix: quick patch"
git push origin main
```

The `pre-push` hook blocks pushes to `main` and `rc-v0.1.0`. GitHub branch protection rules enforce this server-side as a second layer. There are no exceptions, including for maintainers.

### 6.2 Vague or non-conforming commit messages

The following subject lines will be rejected by the `commit-msg` hook or by code review:

```
# PROHIBITED — rejected by hook
fix stuff
update
WIP
fixup! previous commit
squash! add thing
done
misc changes
addressing review comments
```

Every commit message must pass the Conventional Commits pattern. `WIP` commits must not be pushed to the remote. Use `git stash` or a local draft branch instead.

### 6.3 Skipping the git hooks setup

Running `git commit` without having installed the hooks means your commits are not validated locally. You will discover format errors only when a reviewer or CI rejects them — at which point you must rewrite history with `git rebase -i`, which is disruptive. Run `bash scripts/setup_git_hooks.sh` immediately after cloning.

### 6.4 Opening PRs without completing the template

A PR with an empty Summary, unchecked compliance boxes, or missing testing evidence will be returned for revision without review. Reviewers are not responsible for inferring context that the author should have documented.

### 6.5 Force-pushing to shared branches

```bash
# PROHIBITED on any branch that has been pushed to the remote and shared
git push --force origin feat/42-redis-rate-limiter
```

Force-pushing rewrites history that other contributors may have based work on. If you need to amend a commit on a feature branch that no one else has checked out, `git push --force-with-lease` is acceptable. Force-pushing to `main`, `rc-v*`, or `release/**` is never acceptable under any circumstances.

### 6.6 Merging with failing CI

A green CI status is a hard prerequisite for merge, not a courtesy check. Merging with failing CI introduces known-broken code into the integration branch and invalidates the compliance audit trail that CI checks produce.

### 6.7 Mega-commits

A single commit that touches more than ~20 files or ~500 lines (excluding generated files) is a signal that the change was not decomposed into logical units. Such commits make `git bisect` ineffective and `git revert` destructive. Decompose large changes into a sequence of smaller, independently-meaningful commits before opening a PR.

---

*This document is version-controlled. Proposed changes must go through the standard PR process and require maintainer approval.*

---

**Document Control:**

| Version | Date       | Change Summary |
|---------|------------|----------------|
| 1.0     | 2026-06-03 | Initial Git workflow standards |
| 1.1     | 2026-06-14 | Added v0.1.0 release note; clarified `rc-v0.1.0` is retained as permanent release boundary marker; confirmed `pre-push` hook blocks both `main` and `rc-v0.1.0` |
