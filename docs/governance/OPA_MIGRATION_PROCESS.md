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
| **Policy drift** | A Rego rule is modified to relax an RBAC limit without updating the corresponding A.9.2 snapshot test vector, causing the CI gate to pass while the control is weakened. |
| **Role allow-list erosion** | The `allowed_roles` set in `trade_governance.rego` is expanded without a corresponding A.9.2 sub-control review. |
| **Fail-closed regression** | The `default allow = "DENY"` posture is accidentally removed or overridden by a new rule that matches too broadly. |
| **Snapshot staleness** | OPA snapshot test vectors in `tests/opa_snapshots/` are not updated when policy logic changes, giving false confidence in CI. |

This runbook, combined with the `opa-a92-gate` CI job, creates a closed loop:
every policy change must be accompanied by updated snapshot vectors, and the CI
gate verifies both the policy logic and the snapshot coverage.

---

## 2. A.9.2 Control Requirements Summary

The table below maps each A.9.2 sub-control to the Rego policy assertions that
**must** be present in any OPA policy deployed in CAGE. The assertions are
expressed as invariants that the `opa test` suite must verify.

| Sub-Control | Title | Required Rego Assertion(s) |
|---|---|---|
| **A.9.2.1** | User Registration and De-registration | `default allow = "DENY"` (fail-closed); unknown/missing `trader_role` must produce `"DENY"` |
| **A.9.2.2** | User Access Provisioning | `allowed_roles` set is explicitly declared; any role not in `allowed_roles` must be denied for non-read-only actions |
| **A.9.2.3** | Management of Privileged Access Rights | Senior-role limits are more permissive than junior-role limits but still bounded (≤ $500 k ALLOW, ≤ $1 M MANUAL_REVIEW, > $1 M DENY) |
| **A.9.2.4** | Management of Secret Authentication Information | No credentials, tokens, or secrets may appear in Rego source; policy must not evaluate `input.password` or `input.token` directly |
| **A.9.2.5** | Review of User Access Rights | `MANUAL_REVIEW` outcome must be reachable for boundary-condition amounts (junior $5 001–$10 000; senior $500 001–$1 000 000) |
| **A.9.2.6** | Removal or Adjustment of Access Rights | Token quota exhaustion (`quota.quota_exhausted == true`) must produce `"DENY"` for `execute_trade`; below-minimum-reserve must produce `"MANUAL_REVIEW"` |

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

# A.9.2.6 — token quota hard deny
allow = "DENY" if {
    input.action == "execute_trade"
    quota := input.token_quota
    quota.quota_available == true
    quota.quota_exhausted == true
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

- [ ] **Add/update OPA snapshot test vectors in `tests/opa_snapshots/`** —
  every new decision path introduced by the policy change must have at least one
  corresponding snapshot JSON file. Follow the naming convention
  `NN_<description>.json` (e.g. `04_senior_quota_exhausted.json`). Each file
  must contain `input` and `expected_allow` fields matching the existing format.

- [ ] **Run `opa test ./src/governed_financial_advisor/governance/policy/ -v`
  locally** — all tests must pass before pushing. Zero failures is the
  acceptance criterion.

- [ ] **Run `opa test ./compliance/postures/us_fed/opa/ -v` locally** — all
  US_FED posture tests must pass. If the change affects EU_ECB or APAC_MAS
  postures, run those directories as well.

- [ ] **Verify the CI `opa-a92-gate` job passes** — push to a feature branch
  and confirm the `opa-a92-gate` job in `.github/workflows/ci.yml` completes
  green. Do not merge until this job passes.

- [ ] **Update `compliance/lula/lula-validation-a92.yaml` if the control
  implementation changed** — if the Rego change alters how an A.9.2 sub-control
  is implemented (not just a refactor), update the corresponding Lula validation
  manifest. Include the Lula update in the same PR or open a follow-on PR within
  2 business days of merge.

- [ ] **Submit PR with `[A.9.2]` tag in the title** — example:
  `[A.9.2] feat(opa): add BTC trading restriction for junior role`. This tag
  enables automated filtering in the compliance audit trail.

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

Derived from `trade_governance.rego` RBAC rules:

| Role | Action | Amount | Currency | Decision |
|---|---|---|---|---|
| `junior` | `execute_trade` | ≤ $5,000 | non-BTC | `ALLOW` |
| `junior` | `execute_trade` | $5,001–$10,000 | non-BTC | `MANUAL_REVIEW` |
| `junior` | `execute_trade` | > $10,000 | any | `DENY` |
| `junior` | `execute_trade` | any | BTC | `DENY` |
| `senior` | `execute_trade` | ≤ $500,000 | non-BTC | `ALLOW` |
| `senior` | `execute_trade` | $500,001–$1,000,000 | non-BTC | `MANUAL_REVIEW` |
| `senior` | `execute_trade` | > $1,000,000 | any | `DENY` |
| `senior` | `execute_trade` | any | BTC | `DENY` |
| *(unknown)* | `execute_trade` | any | any | `DENY` |
| any valid role | `market_analysis` | N/A | N/A | `ALLOW` |

---

## 5. Rollback Procedure

If a merged OPA policy change causes the `opa-a92-gate` CI job to fail in a
downstream environment (staging or production), follow this procedure:

### Step 1 — Identify the Failing Commit

```bash
git log --oneline --grep="\[A.9.2\]" -10
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
# Verify OPA tests pass after revert
opa test ./src/governed_financial_advisor/governance/policy/ -v
opa test ./compliance/postures/us_fed/opa/ -v

# Verify snapshot vectors still match
for f in tests/opa_snapshots/*.json; do
  echo "Validating snapshot: $f"
  opa eval -d src/governed_financial_advisor/governance/policy/trade_governance.rego \
    -i "$f" "data.trade.governance" --format pretty
done
```

### Step 4 — Push and Open Emergency PR

```bash
git push origin fix/<ticket-id>-revert-a92-policy-regression
```

Open a PR with title: `fix(opa): revert A.9.2 policy regression [A.9.2]`

- Tag as **Cat-E (Emergency)** change per the adopting organization's own change-management process
- Notify the AO within 1 hour of the revert push
- Update `docs/POAM.md` with: revert commit SHA, Lula result, and closure date

### Step 5 — Post-Incident Review

Within 5 business days of the revert merge:
1. Conduct a root-cause analysis of why the snapshot test vectors did not catch
   the regression before merge.
2. Add a new snapshot test vector that would have caught the regression.
3. Open a follow-on PR with the corrected policy change and the new snapshot.

---

## 6. CI Gate Reference

The `opa-a92-gate` job is defined in `.github/workflows/ci.yml`
and runs on every push and pull request to `main` (matching the same `on:`
triggers as all other CI jobs).

### Job Summary

| Property | Value |
|---|---|
| **Job name** | `opa-a92-gate` |
| **Runner** | `ubuntu-latest` |
| **Depends on** | `lint` (or the appropriate upstream job — see `needs:` in the workflow file) |
| **Fail behaviour** | `continue-on-error: false` (default) — any step failure fails the job and blocks merge |

### Steps Executed

1. **Checkout** — `actions/checkout@v4`

2. **Install OPA** — downloads the latest static OPA binary from the official
   release endpoint:
   ```bash
   curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static
   chmod +x opa
   sudo mv opa /usr/local/bin/opa
   ```

3. **🔐 OPA A.9.2 Policy Gate — run `opa test` against trade governance policy**
   ```bash
   opa test ./src/governed_financial_advisor/governance/policy/ -v
   ```
   Fails the job if any Rego unit test fails.

4. **🔐 OPA A.9.2 Policy Gate — run `opa test` against US_FED posture**
   ```bash
   opa test ./compliance/postures/us_fed/opa/ -v
   ```
   Fails the job if any posture-level test fails.

5. **🔐 OPA A.9.2 Policy Gate — validate snapshot test vectors**
   Iterates over every JSON file in `tests/opa_snapshots/` and runs `opa eval`
   against `trade_governance.rego`, printing the policy output for each vector.
   This step ensures that snapshot inputs are syntactically valid and that the
   policy evaluates without errors for all known test cases.

### Interpreting Failures

| Failure symptom | Likely cause | Remediation |
|---|---|---|
| `opa test` exits non-zero | A Rego unit test assertion failed | Check the `-v` output for the failing test name; fix the policy or the test |
| `opa eval` exits non-zero for a snapshot | The snapshot JSON is malformed or references a non-existent policy path | Validate the JSON and the `opa eval` path argument |
| Job not triggered | Branch name does not match the `on: push: branches:` pattern | Ensure the branch follows the naming convention in `docs/operations/GIT_WORKFLOW_STANDARDS.md` |

### Relationship to Lula Validation

The `opa-a92-gate` job is a **pre-merge** gate that validates policy logic in
CI. It is complementary to — but does not replace — the Lula validation
(`compliance/lula/lula-validation-a92.yaml`) which runs post-cluster-provisioning
against a live Kubernetes environment. Both gates must pass for a policy change
to be considered fully validated per the CAGE compliance posture.
