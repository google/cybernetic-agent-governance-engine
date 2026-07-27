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
| Required number of approvals before merging | **1** | Single-maintainer model; CODEOWNERS designates the reviewer |
| Dismiss stale pull request approvals when new commits are pushed | ✅ Enabled | Prevents approval-then-sneak-commit pattern |
| Require review from Code Owners | ✅ Enabled | Activates `.github/CODEOWNERS`; without this, CODEOWNERS is advisory only |
| Require status checks to pass before merging | ✅ Enabled | See §3 for the required check list |
| Require branches to be up to date before merging | ✅ Enabled | Prevents stale-branch merges that pass CI on an outdated base |
| Require conversation resolution before merging | ✅ Enabled | Ensures all review comments are addressed before merge |
| Require signed commits | ✅ Enabled (recommended) | CM-5 compliance; GPG-signed commits provide non-repudiation |
| Restrict who can push to matching branches | ✅ Enabled | Add `@lahlfors` only |
| Allow force pushes | ❌ Disabled | Protects immutable audit trail on `main` |
| Allow deletions | ❌ Disabled | `main` must not be deleted |

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
| Require review from Code Owners | ✅ Enabled | |
| Require status checks to pass | ✅ Enabled | Same check list as `main` (§3) |
| Require branches to be up to date | ✅ Enabled | |
| Allow force pushes | ❌ Disabled | |
| Allow deletions | ❌ Disabled | Release branches are retained as audit artifacts |

---

## 3. Required Status Checks for `main` and `release/**`

Add each of the following as a required status check. The **exact job name** must
match what appears in the GitHub Actions run UI (copy from a recent run if unsure).

### Minimum viable set (single-maintainer reference repo)

| Job name (exact) | Workflow file | Blocks merge? |
|---|---|---|
| `CI Gate — Lint & Tests` | `ref_impl_signoff.yml` | ✅ Hard block |
| `Secret Scanning (Gitleaks)` | `security-scan.yml` | ✅ Hard block |
| `License Guard / license-check` | `license_guard.yml` | ✅ Hard block |

### Full set (add as workflows stabilise)

| Job name (exact) | Workflow file | Notes |
|---|---|---|
| `build / license-check` | `ci.yml` | Apache 2.0 header enforcement |
| `Pytest Logic Tests (US_FED)` | `ci.yml` | |
| `Pytest Logic Tests (EU_ECB)` | `ci.yml` | |
| `Pytest Logic Tests (APAC_MAS)` | `ci.yml` | |
| `Lint` | `ci.yml` | ruff + mypy |
| `STPA Artifact Freshness Check` | `ci.yml` | |
| `Python Dependency Vulnerability Scan (Universal — NIST RA-5/SI-2 reporting: US_FED only)` | `security-scan.yml` | Requires GHAS (§5) |
| `Dependency Review (POAM-013)` | `dependency-review.yml` | Requires GHAS (§5); path-filtered |
| `EU AI Act Compliance Posture (EU_ECB only)` | `eu-ecb-compliance.yml` | |
| `MAS FEAT Compliance Posture (APAC_MAS only)` | `apac-mas-compliance.yml` | |
| `Compile STPA → Governance Artifacts` | `policy_compile.yml` | Path-filtered; only required when STPA files change |

> **Note on path-filtered workflows:** GitHub only reports a status check as
> "required" when the workflow actually runs. For path-filtered workflows
> (e.g., `dependency-review.yml`, `policy_compile.yml`), GitHub will show the
> check as "skipped" (green) when the triggering paths are not changed — this
> is correct behaviour and does not block merge.

---

## 4. Tag Protection — Release Tags

**Settings → Tags → Protected tags → Add rule**

Create one rule per pattern:

| Tag pattern | Who can create | Rationale |
|---|---|---|
| `v*-ref` | Maintainer only | Triggers `publish-release` job in `ref_impl_signoff.yml` |
| `v*-cage-*` | Maintainer only | Triggers `publish-release` job in `ref_impl_signoff.yml` |
| `v[0-9]*` | Maintainer only | Protects all semver release tags |

> **How to add:** Settings → Tags → Add rule → enter pattern → select
> "Restrict tag creation" → add maintainer handle.

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
- [ ] Confirm all required status checks appear and must pass before merge is enabled
- [ ] Confirm "Review required" badge appears and is satisfied only by the CODEOWNERS reviewer
- [ ] Confirm direct push to `main` is rejected: `git push origin HEAD:main` should fail with `remote: error: GH006`
- [ ] Confirm a `v0.0.1-ref` tag push triggers the `publish-release` job and creates a GitHub Release
- [ ] Confirm a `v0.0.1-ref` tag push from a non-maintainer account is rejected

---

## 9. Mapping: Code Enforcement → GitHub UI Settings

| Code-level enforcement | GitHub UI setting that activates it |
|---|---|
| `.github/CODEOWNERS` | §1 → "Require review from Code Owners" |
| `ref_impl_signoff.yml` `ci-gate` job | §3 → Required status check: `CI Gate — Lint & Tests` |
| `security-scan.yml` `secret-scan` job | §3 → Required status check: `Secret Scanning (Gitleaks)` |
| `license_guard.yml` `license-check` job | §3 → Required status check: `License Guard / license-check` |
| `dependency-review.yml` (hardened) | §3 + §5 → GHAS must be enabled |
| `ref_impl_signoff.yml` `publish-release` job | §4 → Tag protection + §6 → write permissions |
| `scripts/setup_git_hooks.sh` pre-push hook | §1 → "Restrict who can push" (server-side equivalent) |
| `dependabot.yml` weekly Actions scan | §5 → Dependabot alerts enabled |
