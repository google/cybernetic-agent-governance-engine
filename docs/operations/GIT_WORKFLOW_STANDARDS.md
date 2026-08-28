# Git Workflow Standards — Cybernetic Governance Engine

> **Reference architecture only.** CAGE demonstrates governance patterns.
> The workflow standards below are illustrative best practices.
> `hotfix/*` and `rc-v*` branch patterns are documented for reference only —
> no production release process is currently active.

**Version:** 1.3  
**Effective:** 2026-08-05  
**Applies to:** All contributors to `cybernetic-governance-engine`

> **Release Note:** The stable `v3.0.0` tag has been pushed to origin and
> the GitHub Release is published as Latest (prior stable: `v2.1.2`). There
> is no `rc-v*` branch currently retained — release-candidate branches are
> deleted once their tag is cut. All feature work branches from `main`. The
> `pre-push` hook blocks direct pushes to `main`.

> **Canonical source:** [`AGENTS.md`](../../AGENTS.md) §Commit Message Standard
> and §Branch Naming & Merge Strategy are the authoritative summaries for
> AI agents and contributors. This document provides the full operational detail.

This document is the authoritative reference for Git commit standards, branch
naming, local setup requirements, pull request process, and protected branch
workflow. Compliance is mandatory. Deviations will cause CI failures, rejected
commits, or blocked pushes.

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

This is not optional. The script installs two enforcement mechanisms that are
prerequisites for contributing:

| Installed artifact | Location | Purpose |
|---|---|---|
| Commit message template | `.gitmessage` (via `git config commit.template`) | Pre-fills your editor with the required format on every `git commit` |
| `commit-msg` hook | `.git/hooks/commit-msg` | Validates the commit message before the commit is recorded |
| `pre-push` hook | `.git/hooks/pre-push` | Blocks direct pushes to `main` |

### 1.2 What the `commit-msg` hook enforces

The hook runs synchronously at commit time. It will **reject** the commit and
print a descriptive error if any of the following conditions are true:

- The subject line does not match the Conventional Commits pattern
  `<type>(<scope>)?: <description>`
- The type is not one of the ten permitted values (see [§2.2](#22-valid-types))
- The subject line exceeds 72 characters (warning printed, not hard rejection —
  treat it as a hard limit)
- The subject is empty after stripping comment lines

Merge commits (`Merge branch ...`) are automatically exempted from validation.

### 1.3 What the `pre-push` hook enforces

The `pre-push` hook blocks direct pushes to `main`. It does **not** block
pushes to `rc-v*` branches at the local-hook level; GitHub branch protection
rules enforce that server-side.

### 1.4 Verifying the installation

After running the script, confirm the hooks are active:

```bash
git config --get commit.template   # should print: /path/to/repo/.gitmessage
ls -la .git/hooks/commit-msg       # should be executable
ls -la .git/hooks/pre-push         # should be executable
```

If you reinstall or re-clone, re-run the script. The `.git/` directory is not
tracked by version control.

---

## 2. Commit Message Format

This project follows [Conventional Commits v1.0.0](https://www.conventionalcommits.org/).
Every commit must conform to this specification. The `commit-msg` hook enforces
the subject line format automatically; the body and footer rules are enforced by
code review.

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

The subject line (first line) is the only mandatory element. The blank line
separating the subject from the body is mandatory whenever a body is present.

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

No other types are permitted. If your change does not fit any of these,
decompose it into smaller commits that do.

### 2.3 Valid Scopes

Scope is optional but strongly recommended. Use exactly one of:

`gateway` · `compliance` · `infra` · `governance` · `tests` · `docs` · `ci` · `agentsight` · `advisor` · `nemo` · `opa`

If your change genuinely spans multiple scopes, prefer the scope of the primary
affected subsystem. If no scope applies (e.g., a root-level tooling change),
omit the parentheses entirely.

### 2.4 Subject Line Rules

- **Imperative mood:** Write "add rate limiter", not "added rate limiter"
- **No period** at the end of the subject line
- **≤ 72 characters** for the entire subject line including type, scope, and colon
- **No capitalisation** of the first word of the description (the type is lowercase)
- **Be specific:** the subject must convey what changed, not just that something changed

### 2.5 Body Rules

The body is optional but required for any commit that is not self-evident from
the subject line alone. When present:

- Separate from the subject with exactly one blank line
- Wrap every line at **72 characters**
- Explain **what** changed and **why** — not how (the diff shows how)
- Reference design decisions, trade-offs, links to ADRs, or relevant context
- Do not repeat the subject line verbatim

### 2.6 Footer Rules

Footers appear after the body, separated by a blank line.

**Issue references:**
```
Closes #42
Refs #18, #19
```

**Breaking changes** — use the footer token or the `!` shorthand in the subject
(both must be present together — never just one):

```
feat(gateway)!: require Authorization header on /v1/policy

BREAKING CHANGE: The /v1/policy endpoint now requires an Authorization header.
All callers must update their request configuration before deploying.
```

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

All branch names must use **lowercase kebab-case**. No underscores. No uppercase
letters. No spaces.

| Branch purpose | Pattern | Example |
|---|---|---|
| New feature | `feat/<short-description>` | `feat/redis-rate-limiter` |
| Bug fix | `fix/<short-description>` | `fix/oscal-uuid-collision` |
| Documentation | `docs/<short-description>` | `docs/stpa-control-diagram` |
| Refactor | `refactor/<short-description>` | `refactor/gateway-middleware` |
| CI / tooling | `ci/<short-description>` | `ci/pin-actions-sha` |
| Chore | `chore/<short-description>` | `chore/bump-langfuse-version` |
| Hotfix on release | `hotfix/<version>-<description>` | `hotfix/2.0.1-redis-timeout` |
| Release candidate | `rc-v<semver>` | `rc-v3.0.0` |
| Experiment / spike | `spike/<short-description>` | `spike/cbf-formal-proof` |

### 3.2 Length limit

The description segment after the prefix must be **≤ 30 characters**. Branch
names that are too long become unwieldy in terminal output and the GitHub UI.

### 3.3 Lifetime

Feature and fix branches are **short-lived**. They must be deleted after their
PR is merged. Do not leave stale branches in the remote.

### 3.4 Branches that trigger CI

The full CI suite (`.github/workflows/ci.yml`) triggers on push to the following
branch patterns **and** on pull requests targeting `main`:

| Branch pattern | Trigger type |
|---|---|
| `main` | `push` and `pull_request` |
| `feature/**` | `push` |
| `feat/**` | `push` |
| `fix/**` | `push` |
| `chore/**` | `push` |
| `docs/**` | `push` |
| `refactor/**` | `push` |
| `ci/**` | `push` |
| `hotfix/**` | `push` |

CI runs on push to any of the above branches — it does not require an open PR
to trigger. However, **all checks must be green on the PR before merge** is the
hard gate. Direct pushes to `main` bypass the PR review gate, which is why they
are prohibited.

---

## 4. Pull Request Standards

### 4.1 PR title format

The PR title becomes the squash-merge commit message on the integration branch.
It must follow Conventional Commits format exactly:

```
feat(gateway): add Redis rate limiter
fix(compliance): correct UUID collision on OSCAL re-export
chore(ci): pin actions/checkout to SHA for supply-chain hardening
```

GitHub uses this title verbatim as the commit message when you squash-merge. A
malformed PR title produces a malformed commit on `main`. There are no exceptions.

### 4.2 Using the PR template

When you open a PR, GitHub automatically populates the description from
`.github/pull_request_template.md`. Every section must be completed before
requesting review.

**Required sections:**

| Section | What to write |
|---|---|
| **Summary** | One paragraph explaining what the PR does and why it is needed |
| **Type of Change** | Check every applicable box |
| **Related Issues / ADRs** | Reference at least one issue (`Closes #n`) or state `N/A` with justification |
| **Changes Made** | Bullet list of specific components or files changed and the reason |
| **Testing** | Check every applicable testing method |
| **Compliance & Security Checklist** | All items must be checked |
| **Deployment Notes** | Migration steps, env variable changes, rollout sequencing |

### 4.3 CI requirements before merge

All of the following CI jobs (`.github/workflows/ci.yml`) must pass:

| Job | What it checks |
|---|---|
| `squash-merge-guard` | Detects two-parent merge commits reaching `main` |
| `license-check` | Apache 2.0 header on all `src/*.py`, `*.ts`, `*.tsx`, `*.js` |
| `pytest-logic` | Unit tests across all three regions (`US_FED`, `EU_ECB`, `APAC_MAS`) |
| `lint` | Ruff lint + format check + Mypy type check |
| `stpa-freshness-check` | STPA artifacts match source (`scripts/check_stpa_freshness.py`) |
| `nemo-freshness-check` | `config/rails/actions.py` matches the embedded snapshot in `deployment/k8s/nemo-rails-configmap.yaml` |
| `no-direct-bind-proof` | Exhaustive NoDirectBind state-space proof (`proof/model.py`) |
| `langfuse-posture-check` | Langfuse config dry-run (`scripts/verify_langfuse_posture.py`) |
| `lula-ai600-validation` | Lula AI 600-1 manifest syntax and count checks |
| `sbom-generate` | CycloneDX SBOM generation and schema validation |
| `ai600-unit-tests` | AI 600-1 specific unit tests |
| `cbrn-keyword-check` | CBRN keyword list validation in `config/governance_thresholds.json` |

**Never suggest disabling or skipping a CI check as a fix.**

### 4.4 Review requirements

- At least **one approving review** from a maintainer is required before merge
- The author may not approve their own PR
- Review comments marked as "blocking" must be resolved before merge
- Do not dismiss reviews without addressing the underlying concern

### 4.5 Merge strategy

**Squash merge is the required strategy for all PRs into `main` — no
exceptions, including release integration branches.**

The `squash-merge-guard` CI job (`.github/workflows/ci.yml`) detects any
two-parent merge commit that reaches `main` and fails the build with an
actionable error message.

**Never suggest:**
- `git merge <branch>` into `main`
- `git merge --no-ff`
- GitHub's "Create a merge commit" or "Rebase and merge" options

**Always say:** *"Use 'Squash and merge' on GitHub; confirm the pre-filled
commit message matches the PR title and follows Conventional Commits format."*

**Repository settings (Settings → General → Pull Requests):**

| Setting | Required value |
|---|---|
| Allow merge commits | ❌ Disabled |
| Allow squash merging | ✅ Enabled — default message: Pull request title |
| Allow rebase merging | ❌ Disabled |

> **Root cause of PRs #41–#44 non-squash merges (2026-07-27):** These PRs were
> merged with standard merge commits because "Allow merge commits" had never
> been disabled. The CI `squash-merge-guard` job and the repository settings
> above close that gap.

---

## 5. Protected Branch Workflow

The complete, required lifecycle for every change:

### Step 1 — Branch from the integration branch

```bash
git checkout main
git pull origin main
git checkout -b feat/redis-rate-limiter
```

Never branch from a stale local copy. Always pull before branching.

### Step 2 — Make focused, atomic commits

Each commit represents one logical unit of change.

```bash
# Good — one logical change per commit
git commit -m "feat(gateway): add Redis client wrapper with connection pooling"
git commit -m "test(gateway): add unit tests for Redis client retry logic"

# Bad — multiple unrelated changes in one commit
git commit -m "feat: add Redis client and fix OSCAL bug and update docs"
```

The `commit-msg` hook validates each commit as you make it.

### Step 3 — Push the feature branch

```bash
git push origin feat/redis-rate-limiter
```

The `pre-push` hook blocks this if your current branch is `main`. Feature
branch pushes proceed normally and trigger CI automatically.

### Step 4 — Open a pull request

Open a PR on GitHub targeting `main`. GitHub auto-populates the description
from `.github/pull_request_template.md`.

- Set the PR title to a valid Conventional Commits subject line
- Complete every section of the template
- Assign at least one reviewer

### Step 5 — Pass all CI checks

Monitor the checks panel. If a check fails:

1. Read the failure output
2. Fix the issue locally
3. Commit the fix (using a valid commit message)
4. Push — CI re-runs automatically

Do not merge with failing checks.

### Step 6 — Obtain review approval

Address all review comments. When all blocking comments are resolved and at
least one maintainer has approved, proceed to merge.

### Step 7 — Squash merge

Use the **"Squash and merge"** button on GitHub. Confirm that the squash commit
message matches the PR title (GitHub pre-fills it). Do not edit the message to
something that does not follow Conventional Commits.

### Step 8 — Delete the branch

After merge, delete the feature branch remotely (GitHub offers a button) and
locally:

```bash
git branch -d feat/redis-rate-limiter
git remote prune origin
```

---

## 6. What Not to Do

### 6.1 Committing directly to protected branches

```bash
# PROHIBITED
git checkout main
git commit -m "fix: quick patch"
git push origin main
```

The `pre-push` hook blocks pushes to `main`. GitHub branch protection enforces
this server-side. No exceptions, including for maintainers.

### 6.2 Vague or non-conforming commit messages

The following subject lines will be rejected by the `commit-msg` hook:

```
# PROHIBITED — rejected by hook
fix stuff
update
WIP
done
misc changes
addressing review comments
```

Every commit message must match the Conventional Commits pattern. `WIP` commits
must not be pushed to the remote — use `git stash` or a local draft branch.

### 6.3 Skipping the git hooks setup

Running `git commit` without having installed the hooks means commits are not
validated locally. Format errors surface only when CI or a reviewer rejects
them, requiring `git rebase -i`. Run `bash scripts/setup_git_hooks.sh`
immediately after cloning.

### 6.4 Opening PRs without completing the template

A PR with an empty Summary, unchecked compliance boxes, or missing testing
evidence will be returned for revision without review.

### 6.5 Force-pushing to shared branches

```bash
# PROHIBITED on any branch pushed to the remote and shared with others
git push --force origin feat/redis-rate-limiter
```

Force-pushing rewrites history others may have based work on. If you need to
amend a commit on a feature branch that no one else has checked out,
`git push --force-with-lease` is acceptable. Force-pushing to `main`, `rc-v*`,
or any other protected branch is never acceptable.

### 6.6 Merging with failing CI

A green CI status is a hard prerequisite for merge. Merging with failing CI
introduces known-broken code into the integration branch and invalidates the
compliance audit trail.

### 6.7 Mega-commits

A single commit touching more than ~20 files or ~500 lines (excluding generated
files) signals the change was not decomposed into logical units. Such commits
make `git bisect` ineffective and `git revert` destructive.

---

## Release Process

1. Create a release branch: `git checkout -b rc-v<X.Y.Z>`
2. Update `CHANGELOG.md` with release date under the version header
3. Create an annotated tag:
   ```bash
   git tag -a v<X.Y.Z> -m "release: v<X.Y.Z> — Cybernetic Governance Engine"
   git push origin v<X.Y.Z>
   ```
4. Open a PR from the integration branch into `main` and **squash-merge** it
5. Create a GitHub Release from the tag, copying the CHANGELOG section as body
6. Delete the `rc-v*` branch after the tag is cut

Stable tags follow SemVer: `v<MAJOR>.<MINOR>.<PATCH>`. Regional compliance
gates (US_FED, EU_ECB, APAC_MAS) block regional deployment posture only —
they never block the global stable tag.

---

*This document is version-controlled. Proposed changes must go through the
standard PR process and require maintainer approval.*

---

**Document Control:**

| Version | Date | Change Summary |
|---------|------|----------------|
| 1.0 | 2026-06-03 | Initial Git workflow standards |
| 1.1 | 2026-06-14 | Added v0.1.0 (later v2.0.0) release note; clarified `rc-v0.1.0` retained as release boundary marker; confirmed `pre-push` hook blocks `main` |
| 1.2 | 2026-07-29 | Corrected fictional `v0.1.0`/`rc-v0.1.0` refs to actual `v2.1.0` release; noted `rc-v*` release branches are deleted after tag is cut |
| 1.3 | 2026-08-05 | Corrected CI trigger table to match `.github/workflows/ci.yml` (CI runs on push to feature branches, not only on PRs); corrected `pre-push` hook scope (blocks `main` only — `rc-v*` is enforced server-side); updated branch table to match `AGENTS.md` canonical patterns; added full CI job table |
