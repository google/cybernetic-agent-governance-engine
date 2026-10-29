# CAGE — GitHub Repository Protection Configuration

> **Authority:** This document is the canonical specification for all GitHub
> repository-level protection settings. It supplements the code-level enforcement
> in `.github/CODEOWNERS`, `.github/workflows/`, and local Git hooks
> (`scripts/setup_git_hooks.sh`).
>
> **Audience:** Repository maintainer / GitHub org admin.
>
> **When to apply:** On initial repository setup, after any branch protection
> rule is accidentally removed, or when onboarding a new maintainer.

---

## 1. Branch Protection — `main`

**Settings → Branches → Branch protection rules → Add rule**
**Branch name pattern:** `main`

| Setting | Value | Rationale |
|---|---|---|
| Require a pull request before merging | ✅ Enabled | No direct push to `main`; server-side equivalent of the local pre-push hook |
| Required number of approvals before merging | **1** | Cannot be met for the maintainer's own pull requests while the project has one maintainer: GitHub does not let an author approve their own pull request, so each such merge is an admin bypass (POAM-2026-115) |
| Dismiss stale pull request approvals when new commits are pushed | ✅ Enabled | Prevents approval-then-sneak-commit pattern |
| Require review from Code Owners | ❌ Disabled | The maintainer is the only code owner and cannot approve their own pull requests, so the rule could never be met. `.github/CODEOWNERS` stays advisory until a second maintainer is onboarded (POAM-2026-115) |
| Require status checks to pass before merging | ✅ Enabled | See §3 for the required check list |
| Require branches to be up to date before merging | ✅ Enabled | Prevents stale-branch merges that pass CI on an outdated base |
| Require conversation resolution before merging | ✅ Enabled | Ensures all review comments are addressed before merge |
| Require signed commits | ✅ Enabled (recommended) | CM-5 compliance; GPG-signed commits provide non-repudiation |
| Restrict who can push to matching branches | ✅ Enabled | Add `@lahlfors` only |
| Allow force pushes | ❌ Disabled | Protects immutable audit trail on `main` |
| Allow deletions | ❌ Disabled | `main` must not be deleted |

> **Two rulesets on `main` (POAM-2026-115):** ruleset 19769096 holds the review rule, which
> cannot be met for the maintainer's own pull requests, so each of their merges is an admin
> bypass of that rule. The eight required status checks are in ruleset 25966171, which has no
> bypass actor, so no merge skips them. The one exception, an advisory fix landed from a
> private fork, is described in [`SECURITY.md`](../SECURITY.md). Before each merge, run
> `scripts/check_pr_mergeable.sh <pr> --comment` as a double-check and record.

**Settings → General → Pull Requests** (repository-level, not branch-protection-rule):

| Setting | Value | Rationale |
|---|---|---|
| Allow merge commits | ❌ Disabled | Removes the "Create a merge commit" button; enforces squash-only strategy per GIT_WORKFLOW_STANDARDS §4.5 |
| Allow squash merging | ✅ Enabled — default message: **Pull request title** | One clean commit per PR on `main`; PR title must follow Conventional Commits |
| Allow rebase merging | ❌ Disabled | Not used in this repository; disabling prevents accidental use |

> **Why this matters:** Without disabling merge commits at the repository level, GitHub presents all three merge buttons regardless of documented policy. PRs #41–#44 were merged with standard merge commits because this setting was never applied. The CI non-squash-merge detection step (see §3) provides a secondary signal if the setting is ever accidentally re-enabled.

---

## 2. Branch Protection — `release/**`

**Branch name pattern:** `release/**`

| Setting | Value | Rationale |
|---|---|---|
| Require a pull request before merging | ✅ Enabled | Release branches are integration points; no direct push |
| Required number of approvals | **1** | Maintainer review required |
| Require review from Code Owners | ❌ Disabled | As for `main` (§1) |
| Require status checks to pass | ✅ Enabled | Same check list as `main` (§3) |
| Require branches to be up to date | ✅ Enabled | |
| Allow force pushes | ❌ Disabled | |
| Allow deletions | ❌ Disabled | Release branches are retained as audit artifacts |

---

## 3. Required Status Checks on `main` (Ruleset 25966171)

Ruleset `25966171` (`Require status checks on main`, `enforcement: active`, `bypass_actors: []`) enforces the following **eight** required status checks on `refs/heads/main`. The **exact check context** must match what GitHub Actions reports:

| Check context (exact) | Workflow file | Integration pin |
|---|---|---|
| `Lint` | `ci.yml` | GitHub Actions |
| `AI 600-1 Unit Tests` | `ci.yml` | GitHub Actions |
| `OPA Rego Policy Lint and Test (Universal — NIST CM-6/SI-7 reporting: US_FED only)` | `ci.yml` | GitHub Actions |
| `Secret Scanning (Gitleaks)` | `security-scan.yml` | GitHub Actions |
| `license-check` | `license_guard.yml` | GitHub Actions |
| `Pytest Logic Tests` | `ci.yml` | `integration_id: 15368` (GitHub Actions) |
| `Terraform Tests (gcp-gke, mock providers)` | `ci.yml` | `integration_id: 15368` (GitHub Actions) |
| `Quickstart Bootstrap & First-DENY Smoke Gate` | `ci.yml` | `integration_id: 15368` (GitHub Actions) |

### Additional non-required pull-request workflows

| Job name (exact) | Workflow file | Notes |
|---|---|---|
| `Python Dependency Vulnerability Scan (Universal — NIST RA-5/SI-2 reporting: US_FED only)` | `security-scan.yml` | Runs on every PR |
| `Dependency Review (POAM-013)` | `dependency-review.yml` | Requires GHAS (§5); path-filtered |
| `EU AI Act Compliance Posture (EU_ECB only)` | `eu-ecb-compliance.yml` | Runs on every PR |
| `MAS FEAT Compliance Posture (APAC_MAS only)` | `apac-mas-compliance.yml` | Runs on every PR |
| `Compile STPA → Governance Artifacts` | `policy_compile.yml` | Path-filtered; only runs when STPA files change |

> **Note on path-filtered workflows:** GitHub only reports a status check as
> "required" when the workflow actually runs. For path-filtered workflows
> (e.g., `dependency-review.yml`, `policy_compile.yml`), GitHub will show the
> check as "skipped" (green) when the triggering paths are not changed — this
> is correct behaviour and does not block merge.

---

## 4. Tag Protection — Release Tags

Tag ruleset 25965917, "Protect release tags" (**Settings → Rules → Rulesets**):

| Setting | Value | Rationale |
|---|---|---|
| Target | Tags matching `refs/tags/v*` and `refs/tags/client-v*` | Every release tag, including the `client-v*` SDK releases |
| Restrict deletions | ✅ Enabled | A published release tag must not disappear |
| Restrict updates | ✅ Enabled | A published release tag must not move, not even by fast-forward |
| Block force pushes | ✅ Enabled | |
| Bypass list | None | Changing a release tag means editing or disabling the ruleset, which ruleset history records (POAM-2026-116) |

Tag creation is not restricted; only admins have write access.

---

## 5. GitHub Advanced Security (GHAS)

**Settings → Security → Code security and analysis**

Enable the following to unblock `dependency-review.yml` (currently hardened to
fail without `continue-on-error`):

| Feature | Setting | Required for |
|---|---|---|
| Dependency graph | ✅ Enable | `actions/dependency-review-action` |
| Dependabot alerts | ✅ Enable | Automated CVE notifications |
| Dependabot security updates | ✅ Enable | Automated patch PRs |
| GitHub Advanced Security | ✅ Enable | `dependency-review-action` hard gate; SARIF upload from Trivy |
| Secret scanning | ✅ Enable | Complements Gitleaks workflow scan |
| Secret scanning push protection | ✅ Enable | Blocks pushes containing detected secrets |

> **If GHAS is not yet available** (e.g., private repo on a free plan):
> Temporarily re-add `continue-on-error: true` to the `Dependency Review` step
> in `.github/workflows/dependency-review.yml` and track enablement under POAM-013.

---

## 6. Actions Workflow Permissions

**Settings → Actions → General → Workflow permissions**

| Setting | Value | Required for |
|---|---|---|
| Workflow permissions | **Read and write permissions** | `ref_impl_signoff.yml` `publish-release` job (GitHub Release creation via `softprops/action-gh-release@v2`) |
| Allow GitHub Actions to create and approve pull requests | ✅ Enabled | Dependabot auto-approve workflows (if added later) |

---

## 7. Dependabot Auto-Merge (Optional)

If the maintainer wants Dependabot PRs for GitHub Actions bumps to merge
automatically after CI passes:

**Settings → Actions → General → Allow GitHub Actions to create and approve pull requests:** ✅

Then add a workflow (e.g., `.github/workflows/dependabot-automerge.yml`) that
calls `gh pr merge --auto --squash` when the actor is `dependabot[bot]` and
all required checks pass.

---

## 8. Verification Checklist

After applying all settings above, verify with a test PR:

- [ ] Open a PR from a feature branch to `main`
- [ ] Confirm all eight required status checks in ruleset 25966171 appear and must pass before merge is enabled
- [ ] Confirm the "Review required" badge appears (code-owner review stays disabled while the project has one maintainer; see §1)
- [ ] Confirm direct push to `main` is rejected: `git push origin HEAD:main` should fail with `remote: error: GH006`
- [ ] Confirm a `v0.0.1-ref` tag push triggers the `publish-release` job and creates a GitHub Release
- [ ] Confirm a `v0.0.1-ref` tag push from a non-maintainer account is rejected

---

## 9. Mapping: Code Enforcement → GitHub UI Settings

| Code-level enforcement | GitHub UI setting that activates it |
|---|---|
| `.github/CODEOWNERS` | None while the project has one maintainer: §1 leaves "Require review from Code Owners" disabled, so the file is advisory (POAM-2026-115) |
| `ci.yml` (`Lint`, `AI 600-1 Unit Tests`, `OPA Rego Policy Lint and Test ...`, `Pytest Logic Tests`, `Terraform Tests (gcp-gke, mock providers)`, `Quickstart Bootstrap & First-DENY Smoke Gate`) | §3 → Ruleset `25966171` required status checks |
| `security-scan.yml` `secret-scan` job | §3 → Ruleset `25966171` required status check: `Secret Scanning (Gitleaks)` |
| `license_guard.yml` `license-check` job | §3 → Ruleset `25966171` required status check: `license-check` |
| `dependency-review.yml` (hardened) | §3 + §5 → GHAS must be enabled |
| `ref_impl_signoff.yml` `publish-release` job | §4 → Tag protection + §6 → write permissions |
| `scripts/setup_git_hooks.sh` pre-push hook | §1 → "Restrict who can push" (server-side equivalent) |
| `dependabot.yml` weekly Actions scan | §5 → Dependabot alerts enabled |
