# OPA Policy Migration Runbook — A.9.2 Account Management

> **Authority:** NIST SP 800-53 Rev 5 Control AC-2 (Account Management), mapped
> internally as **A.9.2** per the CAGE compliance taxonomy.
> **Scope:** All OPA policy files used in the CAGE LangGraph governance harness,
> specifically those evaluated by `create_opa_safety_node()` in
> `src/gateway/governance/langgraph_harness/opa_node_factory.py`.

---

## 1. Purpose

This runbook governs the process for creating, modifying, or retiring OPA (Open
Policy Agent) Rego policies that implement NIST SP 800-53 **A.9.2 — Account
Management** controls within the Cybernetic Governance Engine (CAGE).

### Why This Runbook Exists

OPA policies are the primary enforcement mechanism for access control decisions
in the CAGE LangGraph governance harness. The `symbolic_governor.govern()` call
inside every `opa_safety_node` evaluates a Rego policy at runtime; if that
policy drifts from the A.9.2 control requirements, the system may silently
under-enforce or over-enforce access decisions without triggering any test
failure.

**Specific risks addressed:**

| Risk | Description |
|---|---|
| **Policy drift** | A Rego rule is modified to relax an RBAC limit without updating the corresponding Rego unit test, causing the CI gate to pass while the control is weakened. |
| **Role allow-list erosion** | The `allowed_roles` set in `trade_governance.rego` is expanded without a corresponding A.9.2 sub-control review. |
| **Fail-closed regression** | The `default allow = "DENY"` posture is accidentally removed or overridden by a new rule that matches too broadly. |
| **Test staleness** | A new decision path ships without a Rego unit test in [`constraints_test.rego`](../../compliance/postures/us_fed/opa/constraints_test.rego), so `opa test` cannot catch its regression. |

This runbook, combined with the `rego-policy-lint` CI job
([`security-scan.yml`](../../.github/workflows/security-scan.yml)), creates a
closed loop: every policy change must be accompanied by Rego unit tests, and the
job runs `opa check` and `opa test` over the policy and those tests.

---

## 2. A.9.2 Control Requirements Summary

The table below maps each A.9.2 sub-control to the Rego policy assertions that
**must** be present in any OPA policy deployed in CAGE. The assertions are
expressed as invariants that the `opa test` suite must verify.

| Sub-Control | Title | Required Rego Assertion(s) |
|---|---|---|
| **A.9.2.1** | User Registration and De-registration | `default allow = "DENY"` (fail-closed); unknown/missing `trader_role` must produce `"DENY"` |
| **A.9.2.2** | User Access Provisioning | `allowed_roles` set is explicitly declared; any role not in `allowed_roles` must be denied for non-read-only actions |
| **A.9.2.3** | Management of Privileged Access Rights | Senior-role limits are more permissive than junior-role limits but still bounded (≤ $500 k ALLOW, ≤ $1 M MANUAL_REVIEW, > $1 M DENY), for every trade action (`trade_actions`: `execute_trade`, `execute_trade_bounded`); a trade whose `currency` is not in `tradable_currencies`, or whose `currency` or `symbol` is in `restricted_assets` (any case or padding), is `"DENY"` |
| **A.9.2.4** | Management of Secret Authentication Information | No credentials, tokens, or secrets may appear in Rego source; policy must not evaluate `input.password` or `input.token` directly |
| **A.9.2.5** | Review of User Access Rights | `MANUAL_REVIEW` outcome must be reachable for boundary-condition amounts (junior $5 001–$10 000; senior $500 001–$1 000 000) |
| **A.9.2.6** | Removal or Adjustment of Access Rights | Token quota exhaustion (`quota.quota_exhausted == true`) must produce `"DENY"` for every trade action; below-minimum-reserve must produce `"MANUAL_REVIEW"` |

### Invariants That Must Never Be Removed

The following Rego constructs are load-bearing for A.9.2 compliance. Any PR
that removes or weakens them **must** include an explicit A.9.2 impact
assessment in the PR description and requires CAB review (Change Category N or
higher):

```rego
# A.9.2.1 — fail-closed default
default allow = "DENY"

# A.9.2.2 — explicit role allow-list
allowed_roles := {"junior", "senior"}

# A.9.2.3 — every order-placing action is a trade action, held to the RBAC
# limits, quota rules and asset restrictions; a trade's currency must be a
# tradable currency (an allowlist), and restricted assets are refused on both
# currency and symbol, all compared trimmed and upper-cased (GHSA-f6xq-23f7-9grm)
trade_actions := {"execute_trade", "execute_trade_bounded"}
tradable_currencies := {"USD"}
restricted_assets := {"BTC", "XBT"}

# A.9.2.6 — token quota hard deny, for every trade action
_quota_exhausted if {
    _is_trade
    quota := input.token_quota
    quota.quota_available == true
    quota.quota_exhausted == true
}

allow = "DENY" if {
    _quota_exhausted
}
```

---

## 3. Migration Checklist

Use this checklist for every PR that creates, modifies, or retires an OPA
policy file used in the CAGE governance harness. Check off each item before
requesting review.

- [ ] **Identify the A.9.2 sub-controls affected by the change** — consult the
  table in §2 and note which sub-controls (A.9.2.1 through A.9.2.6) are
  impacted. Record them in the PR description under `[A.9.2]`.

- [ ] **Update the Rego policy file** — make the minimum necessary change.
  Preserve `default allow = "DENY"` and `allowed_roles` unless the change
  explicitly requires modifying them (which triggers CAB review).

- [ ] **Add or update Rego unit tests in
  [`constraints_test.rego`](../../compliance/postures/us_fed/opa/constraints_test.rego)**
  — every new decision path introduced by the policy change must have at least
  one `test_*` rule asserting its decision, and a fix must have a test that
  fails on the policy before the fix.

- [ ] **Run the CI test bundle locally** — all tests must pass before pushing.
  Zero failures is the acceptance criterion. Pass `compliance/postures/us_fed/opa/`
  together with all `src/cage_*/opa/` directories:
  ```bash
  opa check compliance/postures/us_fed/opa/ src/cage_*/opa/
  opa test compliance/postures/us_fed/opa/ src/cage_*/opa/ -v
  ```
  If the change affects EU_ECB or APAC_MAS postures, add their test directories.

- [ ] **Verify the CI `rego-policy-lint` job passes** — push to a feature branch
  and confirm the job in
  [`security-scan.yml`](../../.github/workflows/security-scan.yml) completes
  green. Do not merge until this job passes.

- [ ] **Update `compliance/lula/lula-validation-a92.yaml` if the control
  implementation changed** — if the Rego change alters how an A.9.2 sub-control
  is implemented (not just a refactor), update the corresponding Lula validation
  manifest. Include the Lula update in the same PR or open a follow-on PR within
  2 business days of merge.

- [ ] **Tag the PR description with `[A.9.2]`** — this tag enables automated
  filtering in the compliance audit trail. Keep it out of the title: PR titles
  become squash-merge commit messages and must follow Conventional Commits
  (AGENTS.md), e.g. title `fix(opa): restrict BTC for every trade action` with
  `[A.9.2]` in the description.

---

## 4. Compatibility Matrix

The table below maps each `OpaNodeConfig.policy_action_name` value (as used in
`create_opa_safety_node()` calls across the codebase) to the A.9.2 sub-controls
it exercises, and the Rego rules in `trade_governance.rego` that implement them.

| `policy_action_name` | Rego Package | Primary Rule(s) | A.9.2 Sub-Controls |
|---|---|---|---|
| `execute_trade` | `trade.governance` | Junior/Senior ALLOW/MANUAL_REVIEW/DENY rules; `_rbac_deny` helper; token quota rules | A.9.2.1, A.9.2.2, A.9.2.3, A.9.2.5, A.9.2.6 |
| `market_analysis` | `trade.governance` | `allow = "ALLOW" if { input.action == "market_analysis" }` | A.9.2.2 (read-only access always permitted for valid roles) |
| `prompt_injection_check` | `trade.governance` | `allow = "GOVERNANCE_VIOLATION"` rules (semantic score > 0.85; "system override" content) | A.9.2.1 (de-registration of compromised sessions) |
| `custom_policy` | Caller-defined | Caller-supplied Rego package; must implement `default allow = "DENY"` | A.9.2.1 (minimum), plus any sub-controls relevant to the domain |

### Decision Outcome → A.9.2 Mapping

| OPA Decision | `opa_safety_node` Status | A.9.2 Interpretation |
|---|---|---|
| `"ALLOW"` | `APPROVED` | Access provisioned per A.9.2.2/A.9.2.3 |
| `"MANUAL_REVIEW"` | `ESCALATED` | Human-in-the-loop review per A.9.2.5 |
| `"DENY"` | `BLOCKED` | Access denied per A.9.2.1/A.9.2.6 |
| `"GOVERNANCE_VIOLATION"` | `BLOCKED` | Session invalidation per A.9.2.1 |
| *(exception / timeout)* | `BLOCKED` | Fail-closed per A.9.2.1 (unregistered/unknown state) |

### Role → Permission Boundary Matrix

Derived from `trade_governance.rego` RBAC rules. "Trade" is any action in
`trade_actions` (`execute_trade`, `execute_trade_bounded`); the risk-profile
rules never admit one. Values are trimmed and upper-cased before comparison
(`" usd "` is `USD`, `btc` is `BTC`). "Tradable" means the `currency` is in
`tradable_currencies` (`USD`, an allowlist); "restricted" means the `currency`
or `symbol` is in `restricted_assets` (`BTC`, `XBT`):

| Role | Action | Amount | Currency / symbol | Decision |
|---|---|---|---|---|
| `junior` | trade | ≤ $5,000 | tradable currency, nothing restricted | `ALLOW` |
| `junior` | trade | $5,001–$10,000 | tradable currency, nothing restricted | `MANUAL_REVIEW` |
| `junior` | trade | > $10,000 | any | `DENY` |
| `senior` | trade | ≤ $500,000 | tradable currency, nothing restricted | `ALLOW` |
| `senior` | trade | $500,001–$1,000,000 | tradable currency, nothing restricted | `MANUAL_REVIEW` |
| `senior` | trade | > $1,000,000 | any | `DENY` |
| any | trade | any | restricted | `DENY` |
| any | trade | any | currency missing, not a string or not tradable | `DENY` |
| *(unknown)* | trade | any | any | `DENY` |
| any valid role | `market_analysis` | N/A | N/A | `ALLOW` |

---

## 5. Rollback Procedure

If a merged OPA policy change is found to weaken a control (the CI
`rego-policy-lint` job on `main`, or a check in a downstream environment, fails),
follow this procedure:

### Step 1 — Identify the Failing Commit

```bash
git log --oneline -10 -- src/cage_finance/opa/ compliance/postures/us_fed/opa/
```

Note the commit SHA of the policy change that introduced the regression.

### Step 2 — Create a Revert Branch

```bash
git checkout main && git pull origin main
git checkout -b fix/<ticket-id>-revert-a92-policy-regression
git revert <failing-commit-sha> --no-edit
```

### Step 3 — Verify Locally Before Pushing

```bash
# The CI invocation (rego-policy-lint)
opa check compliance/postures/us_fed/opa/ src/cage_finance/opa/ config/opa/ deployment/
opa test compliance/postures/us_fed/opa/ src/cage_finance/opa/ config/opa/ -v
```

### Step 4 — Push and Open Emergency PR

```bash
git push origin fix/<ticket-id>-revert-a92-policy-regression
```

Open a PR titled `fix(opa): revert A.9.2 policy regression`, with `[A.9.2]` in
its description.

- Tag as **Cat-E (Emergency)** change per the adopting organization's own change-management process
- Notify the AO within 1 hour of the revert push
- Update `docs/POAM.md` with: revert commit SHA, Lula result, and closure date

### Step 5 — Post-Incident Review

Within 5 business days of the revert merge:
1. Conduct a root-cause analysis of why the Rego unit tests did not catch the
   regression before merge.
2. Add a Rego unit test that would have caught the regression.
3. Open a follow-on PR with the corrected policy change and the new test.

---

## 6. CI Gate Reference

The `rego-policy-lint` job is defined in
[`security-scan.yml`](../../.github/workflows/security-scan.yml) and runs on
every pull request to `main`, every push to `main`, and nightly (`cron: 0 2 * * *`).

### Job Summary

| Property | Value |
|---|---|
| **Job name** | `rego-policy-lint` ("OPA Rego Policy Lint and Test") |
| **Runner** | `ubuntu-latest` |
| **OPA version** | v0.61.0 (pinned download) |
| **Fail behaviour** | `opa check` and `opa test` failures fail the job; the `opa fmt --diff` step is advisory (`\|\| true`) |

### Steps Executed

1. **Checkout**
2. **Install OPA** — the pinned v0.61.0 static binary.
3. **Check Rego formatting** — `opa fmt --diff` over every `*.rego` (advisory).
4. **OPA check all Rego files**
   ```bash
   opa check compliance/postures/us_fed/opa/ src/cage_finance/opa/ config/opa/ deployment/
   ```
5. **Run OPA tests** — the policy directories are loaded with the tests, so the
   posture tests can import `data.trade.governance`:
   ```bash
   opa test compliance/postures/us_fed/opa/ src/cage_finance/opa/ config/opa/ -v
   ```

### Interpreting Failures

| Failure symptom | Likely cause | Remediation |
|---|---|---|
| `opa test` exits non-zero | A Rego unit test assertion failed | Check the `-v` output for the failing test name; fix the policy or the test |
| `opa check` exits non-zero | A parse, type or safety error (e.g. an unsafe variable, an unknown built-in) in a loaded file | Fix the reported file and line |
| Job not triggered | The change is not in a pull request to `main` | Open the pull request; feature-branch pushes alone do not trigger this workflow |

### Relationship to Lula Validation

The `rego-policy-lint` job is a **pre-merge** gate that validates policy logic in
CI. It is complementary to — but does not replace — the Lula validation
(`compliance/lula/lula-validation-a92.yaml`) which runs post-cluster-provisioning
against a live Kubernetes environment. Both gates must pass for a policy change
to be considered fully validated per the CAGE compliance posture.
