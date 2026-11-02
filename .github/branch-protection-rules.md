# CAGE — GitHub Repository Protection Configuration

> **What this is:** the protection configuration this repository runs with, as the
> GitHub API returned it on the date given in each section. §10 has the commands
> that read it. Where the configuration differs from what the project would want,
> this document says so instead of describing the wanted setting as if it applied.
> Earlier versions listed settings for `main` that no rule applied (POAM-2026-169).
>
> **Audience:** Repository maintainer / GitHub org admin.
>
> **When to use:** before relying on a protection in an assessment, after any ruleset
> change, and when onboarding a new maintainer. Re-run §10 and update the dates.
>
> Code-level enforcement lives in `.github/CODEOWNERS`, `.github/workflows/`, and the
> local Git hooks installed by `scripts/setup_git_hooks.sh`. Local hooks run only on
> the machine that installed them; they are not server-side controls.

---

## 1. `main` (verified 2026-11-02)

Classic branch protection is off: `GET /repos/{owner}/{repo}/branches/main/protection`
returns `404 Branch not protected`. Three repository rulesets apply to `refs/heads/main`,
and no organisation ruleset does:

| Ruleset | Rules | Parameters | Bypass actors |
|---|---|---|---|
| 19769096 "Protect main branch" | `pull_request` | One approving review; stale approvals dismissed on push; code-owner review off; review-thread resolution off | Repository admin role, mode `always` |
| 25966171 "Require status checks on main" | `required_status_checks` | The eight checks in §3, each pinned to GitHub Actions (`integration_id` 15368); branches need not be up to date (`strict_required_status_checks_policy: false`) | None |
| 26377312 "Protect main history" | `non_fast_forward`, `deletion` | — | None |

What that enforces:

- **Pull requests and review.** A change reaches `main` through a pull request with one
  approving review, except that a repository admin bypasses the rule. The maintainer cannot
  approve their own pull requests, so each of their merges is such a bypass. This is an
  accepted risk (POAM-2026-115).
- **Required checks.** A pull request merges only after the eight checks in §3 passed on its
  head, and the admin bypass does not reach this ruleset. Each run tests the head merged into
  `main` as it stood when the run started, and the checks are not re-run when `main` moves
  before the merge, so the commit that lands may never have been tested; its own runs start
  after it lands. #598's head passed `Pytest Logic Tests`, and its squash commit `43528275`
  failed it on `main` (POAM-2026-171).
- **History.** `main` cannot be force-pushed or deleted, by anyone, since 2026-11-02. Before
  that, nothing blocked either (POAM-2026-170).
- **Not enforced.** Up-to-date branches, review-thread resolution, signed commits, and any push
  restriction beyond the pull-request rule. Earlier versions of this document listed all four
  as enabled.

The one exception to ruleset 25966171 is an advisory fix landed from a private fork, where
Actions does not run: the ruleset is disabled for that single merge and re-enabled, and its
history records both edits ([`SECURITY.md`](../SECURITY.md)). Ruleset 26377312 stays enabled
throughout, which is why the history rules are not in 25966171.

Before each merge, run `scripts/check_pr_mergeable.sh <pr> --comment`. It verifies the
required checks on the exact head SHA and posts the result on the pull request. Nothing
enforces running it (POAM-2026-115).

### 1.1 Repository merge settings (verified 2026-11-02)

| Setting | Value | Note |
|---|---|---|
| Allow merge commits | ❌ (`allow_merge_commit: false`) | Squash-only, per GIT_WORKFLOW_STANDARDS §4.5 |
| Allow squash merging | ✅ (`allow_squash_merge: true`) | Title `COMMIT_OR_PR_TITLE`, message `COMMIT_MESSAGES` |
| Allow rebase merging | ❌ (`allow_rebase_merge: false`) | |
| Allow auto-merge | ❌ (`allow_auto_merge: false`) | |

With `COMMIT_OR_PR_TITLE`, a one-commit pull request's squash commit takes the commit's
subject, not the pull request's title, so the two must match for the title rule in
`AGENTS.md` to hold.

> **Why the merge buttons matter:** PRs #41–#44 were merged with standard merge commits before
> merge commits were disabled at the repository level. The CI non-squash-merge detection step
> gives a second signal if the setting is ever re-enabled.

---

## 2. Other branches (verified 2026-11-02)

No ruleset covers any other branch. `GET /repos/{owner}/{repo}/rules/branches/{branch}` returns
no rules for `release/x` or `rc-v9.9.9`, and no `release/*` or `rc-v*` branch exists. A
release branch needs a ruleset before it is created.

---

## 3. Required Status Checks on `main` (ruleset 25966171, verified 2026-11-02)

Ruleset `25966171` (`Require status checks on main`, `enforcement: active`, no bypass actors)
requires the following **eight** checks on `refs/heads/main`. Each is pinned to the GitHub
Actions app, so a check run or commit status of the same name from any other source does not
satisfy it. Until 2026-11-02 only the last three were pinned. The check context must match
what GitHub Actions reports exactly:

| Check context (exact) | Workflow file | Integration pin |
|---|---|---|
| `Lint` | `ci.yml` | `integration_id: 15368` (GitHub Actions) |
| `AI 600-1 Unit Tests` | `ci.yml` | `integration_id: 15368` (GitHub Actions) |
| `OPA Rego Policy Lint and Test (Universal — NIST CM-6/SI-7 reporting: US_FED only)` | `ci.yml` | `integration_id: 15368` (GitHub Actions) |
| `Secret Scanning (Gitleaks)` | `security-scan.yml` | `integration_id: 15368` (GitHub Actions) |
| `license-check` | `license_guard.yml` | `integration_id: 15368` (GitHub Actions) |
| `Pytest Logic Tests` | `ci.yml` | `integration_id: 15368` (GitHub Actions) |
| `Terraform Tests (gcp-gke, mock providers)` | `ci.yml` | `integration_id: 15368` (GitHub Actions) |
| `Quickstart Bootstrap & First-DENY Smoke Gate` | `ci.yml` | `integration_id: 15368` (GitHub Actions) |

### Additional non-required pull-request workflows

From the workflow files, not the API:

| Job name (exact) | Workflow file | Notes |
|---|---|---|
| `Python Dependency Vulnerability Scan (Universal — NIST RA-5/SI-2 reporting: US_FED only)` | `security-scan.yml` | Runs on every PR |
| `Dependency Review (POAM-013)` | `dependency-review.yml` | Requires the dependency graph (§5); path-filtered |
| `EU AI Act Compliance Posture (EU_ECB only)` | `eu-ecb-compliance.yml` | Runs on every PR |
| `MAS FEAT Compliance Posture (APAC_MAS only)` | `apac-mas-compliance.yml` | Runs on every PR |
| `Compile STPA → Governance Artifacts` | `policy_compile.yml` | Path-filtered; only runs when STPA files change |

`compliance-matrix.yml` runs only on pushes to `main` and on demand, so a pull request that
breaks it shows nothing until after the merge (POAM-2026-169).

> **Note on path-filtered workflows:** a path-filtered workflow that does not run reports no
> check. None of them is required, so this does not block a merge.

---

## 4. Tag Protection — Release Tags (verified 2026-11-02)

Tag ruleset 25965917, "Protect release tags":

| Setting | Value | Rationale |
|---|---|---|
| Target | Tags matching `refs/tags/v*` and `refs/tags/client-v*` | Every release tag, including the `client-v*` SDK releases |
| Restrict deletions | ✅ (`deletion`) | A published release tag must not disappear |
| Restrict updates | ✅ (`update`) | A published release tag must not move, not even by fast-forward |
| Block force pushes | ✅ (`non_fast_forward`) | |
| Bypass list | None | Changing a release tag means editing or disabling the ruleset, which ruleset history records (POAM-2026-116) |

Tag creation is not restricted by a rule.

---

## 5. Security and analysis (verified 2026-11-02)

| Feature | State |
|---|---|
| Dependency graph and Dependabot alerts | ✅ (`GET /repos/{owner}/{repo}/vulnerability-alerts` returns 204) |
| Dependabot security updates | ✅ |
| Secret scanning | ✅ |
| Secret scanning push protection | ✅ |
| Secret scanning validity checks | ✅ |
| Secret scanning for non-provider patterns | ✅ |
| Secret scanning AI detection | ❌ |

Secret scanning complements the required `Secret Scanning (Gitleaks)` check; it does not
replace it.

---

## 6. Actions Workflow Permissions (verified 2026-11-02)

| Setting | Value | Why |
|---|---|---|
| Default `GITHUB_TOKEN` permissions | Read (`default_workflow_permissions: read`) | A workflow that needs more declares it in a `permissions:` block |
| Allow GitHub Actions to create and approve pull requests | ❌ (`can_approve_pull_request_reviews: false`) since 2026-11-02 | A workflow's approval counts toward the review rule without anyone reviewing (POAM-2026-115). No workflow creates or approves pull requests |

---

## 7. Dependabot Pull Requests

Dependabot's pull requests are by another author, so the maintainer can approve them and
they meet the review rule without a bypass. Do not re-enable Actions approvals to merge them
automatically (§6).

---

## 8. Verification Checklist

After any ruleset change:

- [ ] Run `python scripts/check_repo_rules.py` and update its pins with the change; run the
      §10 commands for §1.1, §5 and §6
- [ ] Open a pull request and confirm the eight required checks in §3 are listed and must pass
- [ ] Confirm the review requirement appears on a pull request by the maintainer
- [ ] Confirm a direct push of a new commit to `main` is refused with `remote: error: GH013`

---

## 9. Mapping: Code Enforcement → Server-Side Settings

| Code-level enforcement | Server-side setting that activates it |
|---|---|
| `.github/CODEOWNERS` | None while the project has one maintainer: code-owner review is off (§1), so the file is advisory (POAM-2026-115) |
| `ci.yml` (`Lint`, `AI 600-1 Unit Tests`, `OPA Rego Policy Lint and Test ...`, `Pytest Logic Tests`, `Terraform Tests (gcp-gke, mock providers)`, `Quickstart Bootstrap & First-DENY Smoke Gate`) | §3 → ruleset `25966171` |
| `security-scan.yml` `secret-scan` job | §3 → ruleset `25966171`: `Secret Scanning (Gitleaks)` |
| `license_guard.yml` `license-check` job | §3 → ruleset `25966171`: `license-check` |
| `dependency-review.yml` | §5 → dependency graph |
| `scripts/setup_git_hooks.sh` pre-push hook (refuses pushes to `main`) | Local only. Server side, ruleset `19769096` requires pull requests and `26377312` blocks force pushes and deletion |
| `dependabot.yml` weekly Actions scan | §5 → Dependabot alerts |

---

## 10. How to verify

`repo-rules.yml` runs `scripts/check_repo_rules.py` on every pull request, every push to
`main` and daily. It compares the rules on `main` (§1), the required checks and their pins
(§3) and the release-tag ruleset (§4) with the API, and fails on any difference in either
direction; `tests/test_check_repo_rules.py` holds the §3 table equal to the checker's pins.
An intended change updates the ruleset, the checker and this document together. The other
sections are checked by hand with the commands below.

Bypass actors are returned only to repository admins; everything else is readable without
credentials on a public repository.

```bash
R=google/cybernetic-agent-governance-engine
gh api "repos/$R/rules/branches/main" --jq '[.[] | "\(.type)@\(.ruleset_id)"]'
gh api "repos/$R/branches/main/protection"   # 404: classic protection is off
gh api "repos/$R/rulesets/19769096" --jq '{enforcement, bypass_actors, rules}'
gh api "repos/$R/rulesets/25966171" --jq '{enforcement, bypass_actors, checks: .rules[0].parameters}'
gh api "repos/$R/rulesets/26377312" --jq '{enforcement, bypass_actors, conditions, rules: [.rules[].type]}'
gh api "repos/$R/rulesets/25965917" --jq '{enforcement, bypass_actors, conditions, rules: [.rules[].type]}'
gh api "repos/$R" --jq '{allow_merge_commit, allow_squash_merge, allow_rebase_merge, allow_auto_merge, squash_merge_commit_title, security_and_analysis}'
gh api "repos/$R/actions/permissions/workflow"
```
