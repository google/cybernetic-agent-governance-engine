# Cross OSS Tool — False Positive Registry

**Scan date:** 2026-07-07
**Tool:** Google Cross OSS compliance scanner
**Maintainer:** CAGE project OSPO contact

This document records all Cross tool warnings that have been reviewed and
confirmed as false positives. Each entry includes the file, line(s), the
flagged term, and the justification for why it is not a compliance concern.

---

## `trade-secret` — 2 occurrences (FALSE POSITIVE)

| File | Lines | Justification |
|---|---|---|
| `docs/NIST_AI_600_1_US_FED_ANALYSIS.md` | 489, 491 | Quoting the official NIST AI 600-1 definition of IP risk. This is security analysis content reproducing a regulatory document's terminology, not a leaked internal trade secret. |
| `docs/compliance/us_fed/NIST_AI_600_1_US_FED_ANALYSIS.md` | 489, 491 | Same as above — this is a regional copy of the same analysis document. |

---

## `backdoor` — 14 occurrences across 9 files (ALL FALSE POSITIVE)

All occurrences fall into two categories:

**Category A — Causal ML library terminology (DoWhy/CausalPy API):**
The term "backdoor" is a standard causal inference term (Pearl's backdoor
criterion) used throughout the DoWhy and CausalPy libraries. The string
`method_name="backdoor.linear_regression"` in
`src/gateway/governance/causal_gatekeeper.py` is a verbatim DoWhy API
parameter — it cannot be renamed as it is a third-party library interface.
An explanatory comment has been added at that call site.

**Category B — Security threat descriptions in documentation:**
References in POAM, risk assessment reports, and NIST analysis documents
describe "backdoor attacks" as a threat category being analyzed and mitigated.
This is standard security documentation terminology.

| File | Lines | Category |
|---|---|---|
| `docs/governance/NEURO_SYMBOLIC_GOVERNANCE.md` | 107, 317 | A — causal ML term |
| `docs/compliance/us_fed/POAM_US_FED.md` | 133 | B — security threat description |
| `compliance/rar/RISK_ASSESSMENT_REPORT.md` | 206 | B — security threat description |
| `docs/technical-report/01-SYSTEM-OVERVIEW.md` | 218 | A — causal ML term |
| `docs/architecture/GATEWAY_ARCHITECTURE.md` | 259 | A — causal ML term |
| `src/compliance_bridge/aarm_mapper.py` | 332 | B — security threat in string literal |
| `docs/governance/GOVERNANCE_OVERVIEW.md` | 54 | A — causal ML term |
| `docs/NIST_AI_600_1_US_FED_ANALYSIS.md` | 551, 867 | B — security threat description |
| `docs/compliance/us_fed/NIST_AI_600_1_US_FED_ANALYSIS.md` | 551, 867 | B — security threat description |
| `src/gateway/governance/causal_gatekeeper.py` | 583 | A — DoWhy API call (cannot rename; comment added) |
| `docs/technical-report/02-ARCHITECTURE.md` | 668, 672 | A — causal ML term |
| `docs/governance/CAUSAL_AND_CBF_GOVERNANCE.md` | 67 | A — causal ML term |

---

## `confidential` — 5 occurrences (FALSE POSITIVE)

> Note: One real occurrence in `docs/security/SECURITY_AUDIT_REPORT.md` line 954
> has been remediated (CONFIDENTIAL classification label removed).

| File | Lines | Justification |
|---|---|---|
| `tests/red_team/adversarial_dataset.json` | — | Red-team adversarial test prompt. The string "I have confidential information..." is a synthetic attack input used to validate that the system correctly blocks such prompts. |
| `plans/OSS_READINESS_PLAN.md` | 196 | Section heading in a meta-planning document about scrubbing confidential content. The word describes the remediation task, not leaked content. |
| `tests/test_output_rail_node.py` | 297–311 | Test variable `confidential_text` validates that PII redaction correctly blocks confidential data. The test proves the system works correctly. |
| `src/gateway/slm/mock_slm.py` | 43 | Safety rule description string: "or reveal confidential system information". This is a guardrail rule definition, not leaked content. |
| `src/gateway/slm/slm_server.py` | 43 | Same safety rule string as mock_slm.py. |

---

## `internal only` / `internal_only` — 3 comment occurrences (FALSE POSITIVE, REPHRASED)

> Note: All three comment occurrences have been rephrased to "cluster-internal" or
> "gateway-scoped" to avoid ambiguity. The OPA variable `is_internal_only` in
> `compliance/lula/lula-validation-sc8.yaml` has been renamed to `is_cluster_internal`.

| File | Lines | Action Taken |
|---|---|---|
| `infra/modules/nemo_guardrails/main.tf` | 397 | Rephrased "internal only" → "cluster-internal" in Terraform comment |
| `src/governed_financial_advisor/governance/nemo_action_registry.py` | 101, 114 | Rephrased "gateway-internal only" → "gateway-scoped only" in Python comments |
| `deployment/langfuse/README.md` | 41 | Rephrased "Internal only" → "Cluster-internal only" in README |
| `compliance/lula/lula-validation-sc8.yaml` | — | OPA variable `is_internal_only` renamed to `is_cluster_internal` |

---

## `sandbox.` — 1 occurrence (FALSE POSITIVE)

| File | Lines | Justification |
|---|---|---|
| `compliance/audits/audit_results_v1.json` | — | References `jinja2.sandbox.SandboxedEnvironment` in an audit finding description. This is a Python library namespace path documenting a security fix (sandboxing template rendering). It is not a sandbox environment reference. |

---

## Large file count (792 files) — OSPO HUMAN REVIEW REQUIRED

Cross flagged the repository as having 792 files, which exceeds the threshold
requiring mandatory OSPO human review. No automated fix is possible.

**OSPO reviewer checklist:**
- [ ] No files contain unreleased proprietary algorithms or trade secrets
- [ ] No files contain PII of real individuals
- [ ] No files contain internal Google infrastructure details beyond what is remediated in `plans/OSS_READINESS_PLAN.md`
- [ ] Compliance evidence files (`compliance/audits/`, `compliance/lula/assessment-results.yaml`) are appropriate for public release
- [ ] All 792 files have been reviewed for export control classification
