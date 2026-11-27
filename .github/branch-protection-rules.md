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

## 1. `main` (verified 2026-11-02; ruleset 25966171 updated 2026-11-27)

Classic branch protection is off: `GET /repos/{owner}/{repo}/branches/main/protection`
returns `404 Branch not protected`. Three repository rulesets apply to `refs/heads/main`,
and no organisation ruleset does:

| Ruleset | Rules | Parameters | Bypass actors |
|---|---|---|---|
| 19769096 "Protect main branch" | `pull_request` | One approving review; stale approvals dismissed on push; code-owner review off; review-thread resolution off | Repository admin role, mode `always` |
| 25966171 "Require status checks on main" | `required_status_checks` | The eleven checks in §3 (`Approved review or recorded bypass` added 2026-11-15; `Apache 2.0 License Headers` split from `license-check` and `Client SDK Built-Wheel Smoke (Bare + [langgraph])` added 2026-11-27), each pinned to GitHub Actions (`integration_id` 15368); branches must be up to date (`strict_required_status_checks_policy: true`) | None |
| 26377312 "Protect main history" | `non_fast_forward`, `deletion` | — | None |

What that enforces:

- **Pull requests and review.** A change reaches `main` through a pull request with one
  approving review, except that a repository admin bypasses the rule. The maintainer cannot
  approve their own pull requests, so each of their merges is such a bypass. This is an
  accepted risk (POAM-2026-115). The bypass skips the review rule but not ruleset 25966171,
  whose check `Approved review or recorded bypass` passes only on an approving review or on a
  signed, publicly verifiable record that the head was unreviewed (§3.1). A recorded bypass is
  not a review: the record discloses the unreviewed merge, and the separation-of-duties gap
  stays open.
- **Required checks.** A pull request merges only after the eleven checks in §3 passed on its
  head against the current `main` (`strict_required_status_checks_policy: true`,
  POAM-2026-171 Remediation 1), and the admin bypass does not reach ruleset 25966171.
  Previously (`strict_required_status_checks_policy: false`), #598's head passed
  `Pytest Logic Tests` against an earlier `main`, and its squash commit `43528275` failed it
  on `main`. [`ci.yml`](workflows/ci.yml), [`security-scan.yml`](workflows/security-scan.yml)
  and [`license_guard.yml`](workflows/license_guard.yml) also cancel superseded runs on
  `pull_request` events only and key `push` concurrency groups by `github.sha` so every
  commit on `main` finishes, and [`main-result-reconciler.yml`](workflows/main-result-reconciler.yml)
  ([`reconcile_main_check_results.py`](../scripts/reconcile_main_check_results.py))
  reconciles every commit older than the grace window against the eleven post-merge checks
  (`EXPECTED_MAIN_PUSH_CHECKS`, 1:1 per context after POAM-2026-172, plus `Record an
  unreviewed merge`), updating the durable `main-check-reconciliation` GitHub issue first
  and publishing heartbeats and `CRITICAL` violation alerts to GCP Pub/Sub and Cloud
  Monitoring (`google_monitoring_alert_policy.main_result_reconciler_absent`).
- **History.** `main` cannot be force-pushed or deleted, by anyone, since 2026-11-02. Before
  that, nothing blocked either (POAM-2026-170).
- **Not enforced.** Review-thread resolution, signed commits, and any push restriction beyond
  the pull-request rule. Earlier versions of this document listed all four (including
  up-to-date branches) as enabled before `strict_required_status_checks_policy: true` was
  enabled on 2026-11-27.

Advisory fixes publish first and land through public pull requests under ruleset 25966171
([`SECURITY.md`](../SECURITY.md#landing-an-advisory-fix-maintainers)), so all eleven required
checks (including `Approved review or recorded bypass`) still run. Historically — and if an
unavoidable embargoed private-fork merge ever happened where Actions does not run —
disabling 25966171 for a single merge leaves a commit without a pre-merge record, so its
ledger run on `main` fails (§3.1) while `/history` records both edits. Ruleset 26377312 stays
enabled throughout, which is why the history rules are not in 25966171.

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

## 3. Required Status Checks on `main` (ruleset 25966171, verified 2026-11-27)

Ruleset `25966171` (`Require status checks on main`, `enforcement: active`, no bypass actors,
`strict_required_status_checks_policy: true`) requires the following **eleven** checks on
`refs/heads/main`. Each is pinned to the GitHub Actions app, so a check run or commit status
of the same name from any other source does not satisfy it, and each context is reported by
exactly one workflow job (`POAM-2026-172` separated `ci.yml`'s Apache 2.0 header check from
`license_guard.yml`'s dependency-license audit on 2026-11-27;
`Client SDK Built-Wheel Smoke (Bare + [langgraph])` was promoted to required the same day).
The check context must match what GitHub Actions reports exactly:

| Check context (exact) | Workflow files | Integration pin |
|---|---|---|
| `Lint` | `ci.yml` | `integration_id: 15368` (GitHub Actions) |
| `AI 600-1 Unit Tests` | `ci.yml` | `integration_id: 15368` (GitHub Actions) |
| `OPA Rego Policy Lint and Test (Universal — NIST CM-6/SI-7 reporting: US_FED only)` | `security-scan.yml` | `integration_id: 15368` (GitHub Actions) |
| `Secret Scanning (Gitleaks)` | `security-scan.yml` | `integration_id: 15368` (GitHub Actions) |
| `license-check` | `license_guard.yml` | `integration_id: 15368` (GitHub Actions) |
| `Apache 2.0 License Headers` | `ci.yml` | `integration_id: 15368` (GitHub Actions) |
| `Pytest Logic Tests` | `ci.yml` | `integration_id: 15368` (GitHub Actions) |
| `Terraform Tests (gcp-gke, mock providers)` | `ci.yml` | `integration_id: 15368` (GitHub Actions) |
| `Quickstart Bootstrap & First-DENY Smoke Gate` | `ci.yml` | `integration_id: 15368` (GitHub Actions) |
| `Client SDK Built-Wheel Smoke (Bare + [langgraph])` | `ci.yml` | `integration_id: 15368` (GitHub Actions) |
| `Approved review or recorded bypass` | `review-bypass-attestation.yml` | `integration_id: 15368` (GitHub Actions) |

`tests/test_check_repo_rules.py` fails unless the workflow column names exactly the
workflows whose jobs report each check (1:1 per context).

### 3.1 `Approved review or recorded bypass`

The admin bypass skips ruleset 19769096's review rule, but this check is in ruleset 25966171,
which has no bypass actor, so `--admin` cannot skip it.
[`review-bypass-attestation.yml`](workflows/review-bypass-attestation.yml) runs on every pull
request push and on every review submitted, dismissed or edited, and the check passes in one of
two ways:

- **Approved.** A reviewer other than the author, with write access and not a bot, approved the
  current head, and that approval is their latest approval, change request or dismissal.
  [`review_bypass_attestation.py`](../scripts/review_bypass_attestation.py) states the rule.
- **Unreviewed and recorded.** Otherwise the workflow signs a record that the head was unreviewed
  (a Sigstore attestation, logged in Sigstore's public transparency log) and verifies it from the
  attestations API before the check passes. An unreviewed pull request from a fork fails
  instead: it needs an approving review.

**A recorded bypass is not a review.** The check passing means "approved, or unreviewed and
recorded". Every record says `"reviewed": false` and "It is not a review or an approval and
makes no claim about the change", and the repository's own CI makes it, not an independent
party. The control is disclosure, a durable and verifiable record of each unreviewed merge, not
review: the separation-of-duties gap (AC-5) stays open and accepted (POAM-2026-115), and no
claim that a change was reviewed may rest on a record or on the ledger.

The check fails closed. No step continues on error, and the last step passes only on an approval
or a verified record, so a recording step that errors fails the check and the merge stays
blocked; it cannot proceed unrecorded. After each merge,
[`review-bypass-ledger.yml`](workflows/review-bypass-ledger.yml) decides the merged head again,
verifies its pre-merge record and signs a ledger record of the merge commit. A merge with
neither an approval nor a verified pre-merge record fails that run on `main`.
[`test_review_bypass_attestation.py`](../tests/test_review_bypass_attestation.py) fails on a
workflow edit that breaks any of this.

| Record | Subject: canonical JSON, sorted keys, no whitespace | Predicate type |
|---|---|---|
| Pre-merge | `{"head_sha":"<sha>","pr":<number>,"repo":"<owner>/<name>"}` | `https://github.com/google/cybernetic-agent-governance-engine/attestations/review-bypass/v1` |
| Ledger | `{"merge_sha":"<sha>","repo":"<owner>/<name>"}` | `https://github.com/google/cybernetic-agent-governance-engine/attestations/review-bypass-ledger/v1` |

A record's subject digest is the sha256 of its subject, so anyone can rebuild the subject from
public data and verify the record with the commands in §10. The pre-merge predicate also records
the base branch and SHA, the author, the observed approving-review count, the evaluation time
and the run; the ledger predicate records the merger, the merge time and the pre-merge subject
digest.

Limits. GitHub takes the workflow and the script from the pull request's merge ref, so a pull
request that edits them decides its own check; the edit is in the merged diff, and each record's
signing certificate names the workflow ref that signed it. Any historical merge landed while
ruleset 25966171 was disabled has no pre-merge record, and its ledger run fails.

### Additional non-required pull-request workflows

From the workflow files, not the API:

| Job name (exact) | Workflow file | Notes |
|---|---|---|
| `Python Dependency Vulnerability Scan (Universal — NIST RA-5/SI-2 reporting: US_FED only)` | `security-scan.yml` | Runs on every PR |
| `Dependency Review (POAM-013)` | `dependency-review.yml` | Requires the dependency graph (§5); path-filtered |
| `EU AI Act Compliance Posture (EU_ECB only)` | `eu-ecb-compliance.yml` | Runs on every PR |
| `MAS FEAT Compliance Posture (APAC_MAS only)` | `apac-mas-compliance.yml` | Runs on every PR |
| `Compile STPA → Governance Artifacts` | `policy_compile.yml` | Path-filtered; only runs when STPA files change |

Live Lula and regional posture validation runs against a deployed cluster via
[`scripts/staging_lifecycle.sh`](../scripts/staging_lifecycle.sh) Phases 3–5 rather than in
pull-request CI (the former on-demand `385e502e^:.github/workflows/compliance-matrix.yml`
stub was retired; POAM-2026-169).

> **Note on path-filtered workflows:** a path-filtered workflow that does not run reports no
> check. None of them is required, so this does not block a merge.

---

## 4. Tag Protection — Release Tags (verified 2026-11-02)

Tag ruleset 25965917, "Protect release tags":

| Setting | Value | Rationale |
|---|---|---|
| Target | Tags matching `refs/tags/v*`, `refs/tags/client-v*` and `refs/tags/conformance-v*` | Every release tag, including the `client-v*` SDK releases and the `conformance-v*` verifier releases (`conformance-v*` added 2026-11-27) |
| Restrict deletions | ✅ (`deletion`) | A published release tag must not disappear |
| Restrict updates | ✅ (`update`) | A published release tag must not move, not even by fast-forward |
| Block force pushes | ✅ (`non_fast_forward`) | |
| Bypass list | None | Changing a release tag means editing or disabling the ruleset, which ruleset history records (POAM-2026-116) |

Tag creation is not restricted by a rule.

What has been observed for `conformance-v*` (added 2026-11-27): when `conformance-v0.4.2` was
created, rule suite `5416775387` evaluated this ruleset's `deletion`, `update` and
`non_fast_forward` rules on `refs/tags/conformance-v0.4.2` with enforcement `active`, so the
ruleset applies to that pattern. A refused deletion or move of a `conformance-v*` tag has not
been probed; that effect is inferred from the 2026-10-27 probe on a `v*` tag
([`RULESET_PROBES.md`](../docs/operations/RULESET_PROBES.md) §6).

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
- [ ] Open a pull request and confirm the eleven required checks in §3 are listed and must pass
- [ ] Confirm the review requirement appears on a pull request by the maintainer
- [ ] Confirm a direct push of a new commit to `main` is refused with `remote: error: GH013`
- [ ] Before applying a ruleset change to `main` (via throwaway dry-run copy first) and before a document states what a rule refuses or allows, probe on a disposable ref with zero Actions runs ([`RULESET_PROBES.md`](../docs/operations/RULESET_PROBES.md))

---

## 9. Mapping: Code Enforcement → Server-Side Settings

| Code-level enforcement | Server-side setting that activates it |
|---|---|
| `.github/CODEOWNERS` | None while the project has one maintainer: code-owner review is off (§1), so the file is advisory (POAM-2026-115) |
| `ci.yml` (`Lint`, `AI 600-1 Unit Tests`, `Apache 2.0 License Headers`, `Pytest Logic Tests`, `Terraform Tests (gcp-gke, mock providers)`, `Quickstart Bootstrap & First-DENY Smoke Gate`, `Client SDK Built-Wheel Smoke (Bare + [langgraph])`) | §3 → ruleset `25966171` |
| `security-scan.yml` `secret-scan` and `rego-policy-lint` jobs | §3 → ruleset `25966171`: `Secret Scanning (Gitleaks)`, `OPA Rego Policy Lint and Test ...` |
| `license_guard.yml` `license-check` job (dependency licences) | §3 → ruleset `25966171`: `license-check` |
| `review-bypass-attestation.yml` | §3 → ruleset `25966171`: `Approved review or recorded bypass` (§3.1) |
| `review-bypass-ledger.yml` | None: it runs after each merge, and a failed run on `main` is the signal (§3.1; reconciled post-merge by `main-result-reconciler.yml`) |
| `main-result-reconciler.yml` (`scripts/reconcile_main_check_results.py`) | Scheduled post-merge reconciliation of the eleven push checks on `main` (POAM-2026-171): stamps `last-checked: <UTC>` on the durable `main-check-reconciliation` GitHub issue first and publishes heartbeats + `CRITICAL` violation envelopes via keyless WIF to GCP Pub/Sub and Cloud Monitoring (`google_monitoring_alert_policy.main_result_reconciler_absent`). Guarded in CI by `check_repo_rules.py` (`workflow_guard_drift()`) |
| `dependency-review.yml` | §5 → dependency graph |
| `scripts/setup_git_hooks.sh` pre-push hook (refuses pushes to `main`) | Local only. Server side, ruleset `19769096` requires pull requests and `26377312` blocks force pushes and deletion |
| `dependabot.yml` weekly Actions scan | §5 → Dependabot alerts |

---

## 10. How to verify

`repo-rules.yml` runs `scripts/check_repo_rules.py` on every pull request, every push to
`main` and daily. It compares the rules on `main` (§1), the required checks and their pins
(§3), the release-tag ruleset (§4) and the committed post-merge workflow guards
(`workflow_guard_drift()`: PR-only `cancel-in-progress`, per-SHA `push` concurrency groups
and `main-result-reconciler.yml`) against the pinned configuration, and fails on any
difference in either direction; `tests/test_check_repo_rules.py` holds the §3 table equal
to the checker's pins.
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

A pre-merge record (§3.1) is checked by rebuilding its subject from public data, and a ledger
record likewise from the merge commit. Each command fails unless a record of that type, signed by
that workflow for that ref, exists for the subject:

```bash
R=google/cybernetic-agent-governance-engine
PR=<number>; HEAD=$(gh api "repos/$R/pulls/$PR" --jq .head.sha)
printf '{"head_sha":"%s","pr":%d,"repo":"%s"}' "$HEAD" "$PR" "$R" > subject.json
gh attestation verify subject.json --repo "$R" \
  --predicate-type https://github.com/google/cybernetic-agent-governance-engine/attestations/review-bypass/v1 \
  --signer-workflow "$R/.github/workflows/review-bypass-attestation.yml" --source-ref "refs/pull/$PR/merge"
MERGE=<merge commit SHA>
printf '{"merge_sha":"%s","repo":"%s"}' "$MERGE" "$R" > ledger.json
gh attestation verify ledger.json --repo "$R" \
  --predicate-type https://github.com/google/cybernetic-agent-governance-engine/attestations/review-bypass-ledger/v1 \
  --signer-workflow "$R/.github/workflows/review-bypass-ledger.yml" --source-ref refs/heads/main
```

Counts of unreviewed merges are read from the ledger, not restated in documents. From the merge
that added `review-bypass-ledger.yml`, every merge on `main` has a ledger run that either passed
(approved, or unreviewed and recorded) or failed, and the ledger records can be listed by merge
commit:

```bash
git log --first-parent --format=%H "<first ledger merge>^..origin/main" | while read -r sha; do
  digest=$(python3 scripts/review_bypass_attestation.py ledger-subject --repo "$R" --merge-sha "$sha")
  printf '%s %s\n' "$sha" "$(gh api "repos/$R/attestations/sha256:$digest" --jq '.attestations | length' 2>/dev/null || echo 0)"
done
gh run list --workflow review-bypass-ledger.yml --branch main --limit 1000 --json headSha,conclusion
```
