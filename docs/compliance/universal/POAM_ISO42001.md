---
poam_file: POAM_ISO42001
region_scope: ALL
primary_framework: "ISO/IEC 42001:2023 (AI Management System Standard)"
global_baseline: ISO 42001
version: "1.0"
date: 2026-06-08
see_also:
  - compliance/us_fed/POAM_US_FED.md    # NIST SP 800-53 / ATO track (US_FED only)
  - compliance/eu_ecb/POAM_EU_ECB.md    # EU AI Act / DORA / GDPR weaknesses (EU_ECB only)
  - compliance/apac_mas/POAM_APAC_MAS.md  # MAS FEAT / Notice 655 / TRM weaknesses (APAC_MAS only)
  - compliance/cross-region/POAM_INDEX.md     # cross-region traceability matrix
---

# Plan of Action and Milestones (POA&M) — ISO 42001 Universal

**System:** Cybernetic AI Governance Engine (CAGE) — Governed Financial Advisor
**Reference:** ISO/IEC 42001:2023 — AI Management System Standard
**Region Scope:** ALL (`US_FED`, `EU_ECB`, `APAC_MAS`)
**Global Baseline:** ISO/IEC 42001:2023
**Version:** 1.0
**Date:** 2026-06-08
**Status:** ACTIVE

> **Scope:** This document tracks weaknesses in the CAGE **ISO 42001 AI Management System (AIMS)** that apply to **all deployment regions** regardless of `CAGE_DEPLOYMENT_REGION`. Entries here are anchored to ISO 42001 Annex A controls or Clauses as their primary identifier. NIST SP 800-53, EU AI Act, and MAS FEAT control IDs appear as co-framework citations only.
>
> For US_FED-specific NIST SP 800-53 weaknesses, see [`compliance/us_fed/POAM_US_FED.md`](../us_fed/POAM_US_FED.md).
> For EU_ECB-specific weaknesses, see [`compliance/eu_ecb/POAM_EU_ECB.md`](../eu_ecb/POAM_EU_ECB.md).
> For APAC_MAS-specific weaknesses, see [`compliance/apac_mas/POAM_APAC_MAS.md`](../apac_mas/POAM_APAC_MAS.md).

---

## POA&M Summary

| Metric          | Count |
| --------------- | ----- |
| **Total Items** | 8     |
| **Critical**    | 0     |
| **High**        | 2     |
| **Moderate**    | 5     |
| **Low**         | 1     |
| **Open**        | 4     |
| **In Progress** | 1     |
| **Closed**      | 3     |

---

## POA&M Items

| POA&M ID | ISO 42001 Control | Co-Frameworks | Regions | Weakness Description | Detection Method | Risk Level | Scheduled Completion | Resources Required | Status | Milestone |
| -------- | ----------------- | ------------- | ------- | -------------------- | ---------------- | ---------- | -------------------- | ------------------ | ------ | --------- |
| POAM-018 | §A.9.4 — Telemetry and Monitoring | NIST SP 800-53 AU-9; DORA Art. 10; MAS Notice 655 §10 | ALL | ~~Compliance-bridge telemetry project credentials fail silently when absent.~~ **✅ Closed (verified 2026-09-22; scope note: covers fail-closed compliance-bridge startup/health validation only, not authoritative `AU-9` decision audit storage, which uses `EvidenceStream` → KMS WORM under `POAM-2026-084`/`197`).** (1) `_validate_langfuse_credentials()` raises `RuntimeError` in non-development environments ([`audit_workflow.py`](../../../src/compliance_bridge/audit_workflow.py), commit `489949a`); (2) `GET /health` returns `langfuse_compliance_configured` ([`main.py`](../../../src/compliance_bridge/main.py), commit `fd5e28b`), asserted by [`tests/test_compliance_bridge_lifespan_posture.py`](../../../tests/test_compliance_bridge_lifespan_posture.py) (real FastAPI lifespan startup under every enforcing posture). | Code review + test verification 2026-09-22 | **High** | 2026-07-15 | 4 hrs | **Closed** | Fail-fast credential checks asserted by [`tests/test_compliance_bridge_lifespan_posture.py`](../../../tests/test_compliance_bridge_lifespan_posture.py) (real FastAPI lifespan startup under every enforcing posture) (commits `489949a`, `fd5e28b`). **Originally tracked in:** [`compliance/us_fed/POAM_US_FED.md#POAM-018`](../us_fed/POAM_US_FED.md). |
| POAM-019 | §A.9.4 — Telemetry and Monitoring | NIST SP 800-53 AU-9, SC-7; DORA Art. 10; MAS Notice 655 §10 | ALL | ~~Terraform fallback silently collapses dual-project telemetry isolation.~~ **✅ Closed (verified 2026-09-22).** Enforced by `poam_019_empty_key_guard` and `poam_019_shared_key_guard` in [`infra/targets/gcp-gke/main.tf`](../../../infra/targets/gcp-gke/main.tf) plus `nullable = false` validations in [`infra/targets/gcp-gke/variables.tf`](../../../infra/targets/gcp-gke/variables.tf) (commit `fd5e28b`), verified by [`infra/targets/gcp-gke/tests/posture_guards.tftest.hcl`](../../../infra/targets/gcp-gke/tests/posture_guards.tftest.hcl) and [`tests/infrastructure/test_guard_placement.py`](../../../tests/infrastructure/test_guard_placement.py) (`POAM-2026-180` in [`POAM.md`](../../POAM.md)). (Scope note: isolates operational vs. compliance telemetry credentials; authoritative `AU-9` audit records remain in `EvidenceStream` → WORM.) | Terraform test + guard placement test | **High** | 2026-07-15 | 2 hrs | **Closed** | Fail-closed guards verified by [`posture_guards.tftest.hcl`](../../../infra/targets/gcp-gke/tests/posture_guards.tftest.hcl) and [`test_guard_placement.py`](../../../tests/infrastructure/test_guard_placement.py) (commit `fd5e28b`). **Originally tracked in:** [`compliance/us_fed/POAM_US_FED.md#POAM-019`](../us_fed/POAM_US_FED.md). |
| ISO-001 | §A.4 — Resource Management | NIST SP 800-53 SC-5; NIST AI RMF GOVERN-1.7 | ALL | `CTRL_TQP_007` OPA runtime injection deferred. The OPA `quota_within_limits` and `token_quota_within_limits` rules in `385e502e:deployment/system_authz.rego` (retired in favor of [`infra/modules/opa_policy/main.tf`](../../../infra/modules/opa_policy/main.tf)) provide secondary declarative evidence for token quota enforcement, but they currently evaluate against static policy data — not live Redis session state from `TokenQuotaProxy`. Until `governance_middleware.py` injects the current session counters into the OPA input document, the OPA rules cannot enforce the quota independently of the Python `TokenQuotaProxy`. This means OPA provides no independent verification of quota compliance. | Code review — `src/gateway/server/governance_middleware.py`, `infra/modules/opa_policy/main.tf` | **Moderate** | 2026-07-31 | 8 hrs | Open | Inject Redis session state (`step_count`, `token_count`, `session_ttl`) into the OPA input document in `governance_middleware.py` before each policy evaluation; update `system_authz.rego` to evaluate against live session data; add integration test asserting OPA blocks a request when quota is exceeded. |
| ISO-002 | §6.1 — Risk Treatment / STPA | NIST SP 800-53 SI-2; ISO 42001 §A.4 | ALL | The `TokenQuotaProxy` Unsafe Control Action (quota enforcement failure when Redis is unavailable) is not present in [`config/stpa/core_system.yaml`](../../../config/stpa/core_system.yaml) (split from `3a59da98^:config/stpa_control_structure.yaml`). The STPA compiler (`src/gateway/governance/stpa_compiler.py`) generates Rego, Colang, and Python enforcement from the STPA control structure YAML, so until the UCA is added the compiler cannot generate the corresponding enforcement artifacts and the UCA is not formally tracked in the safety case. **Correction (2026-09-22):** this item previously referred to the missing UCA as "UCA-4". That identifier is **already occupied** by an unrelated UCA — [`trade_hazards.yaml`](../../../src/cage_finance/config/stpa/trade_hazards.yaml) defines `UCA-4` as `execute_trade` / `stopped_too_soon` ("Agent debits account but fails to credit asset"). The quota UCA must therefore be allocated a **new, unused identifier**; adding it as "UCA-4" would collide. | Code review — `config/stpa/core_system.yaml`, `src/gateway/governance/stpa_compiler.py` | **Moderate** | 2026-07-15 | 4 hrs | Open | Allocate an unused UCA identifier (not `UCA-4`) for the `TokenQuotaProxy` fail-CLOSED scenario and add it to `config/stpa/core_system.yaml`; regenerate STPA artifacts (`generated_stpa_validator.py`, `generated_saga_nodes.py`); verify STPA freshness check passes in CI. |
| ISO-003 | §9.1 — Management Review | NIST SP 800-53 CA-5; ISO 42001 §9.3 | ALL | No ISO 42001 Clause 9 management review records exist. ISO 42001 §9.1 requires the organization to evaluate the performance and effectiveness of the AIMS at planned intervals. ISO 42001 §9.3 requires management review of the AIMS including review of audit results, nonconformities, and corrective actions. No management review records have been produced for any deployment region. This is a mandatory AIMS documentation requirement independent of any regional regulatory framework. | Gap analysis — ISO 42001 §9.1, §9.3 | **Moderate** | 2026-09-30 | 8 hrs | Open | Produce first ISO 42001 §9.1 performance evaluation report covering: Lula validation results, POAM status, UCA coverage, and STPA freshness; obtain management sign-off; establish quarterly review cadence. |
| ISO-004 | §A.6.1 — Policy Enforcement | NIST SP 800-53 CA-7; ISO 42001 §A.4 | ALL | `compliance/oscal/component-definition.yaml` missing `CTRL_TQP_007` entry. The OSCAL component definition maps technical enforcement components to ISO 42001 Annex A controls and links each to a Lula validation manifest. The `TokenQuotaProxy` (`CTRL_TQP_007`) was introduced in `fix/track-b-v2-release-gates` but has no corresponding entry in the component definition. This means the control is not formally registered in the OSCAL compliance artifact and cannot be assessed by automated Lula validation. | Documentation audit — `compliance/oscal/component-definition.yaml` | **Moderate** | 2026-06-20 | 2 hrs | **In Progress** | Add `CTRL_TQP_007` component entry to `compliance/oscal/component-definition.yaml` referencing `token_quota_proxy.py` and linking to a new `lula-validation-tqp007.yaml` manifest (stub); update `compliance/oscal/README.md`. Due within 2 business days of PR merge per `.roo/rules` §11.1. |
| POAM-023 | §A.4 — Resource Management / §8 — Operation | NIST SP 800-53 SA-9; ISO 42001 §A.6 | ALL | **Closure withdrawn 2026-11-05 (`PR-9` Check 1).** Closed `2026-07-27` with zero runnable test citation while `AnchorageGrpcLedgerProvider.fetch_balance()` raises `NotImplementedError` and [`daemon.py`](../../../src/gateway/governance/reconciliation/daemon.py) defaults to `_DefaultSimulatedProvider` without a Terraform-reconciled production ledger feed (`POAM-2026-096` in [`POAM.md`](../../POAM.md)). | Architecture review + closure audit 2026-11-05 | **Moderate** | 2026-12-31 | 40 hrs | Open | **Closes on:** concrete non-simulated `LedgerProvider` verified end-to-end by runnable test coverage and an in-state reconciler workload (`POAM-2026-096`). |
| POAM-024 | §8.4 — Operational Planning and Control | NIST SP 800-53 CA-2; ISO 42001 §9.1 | ALL | ~~End-to-end staging lifecycle validation unrecorded.~~ **✅ Closed (2026-11-12; Observed 2026-11-12: matched-SHA clean-room + recovery `scripts/staging_lifecycle.sh --fresh-project=<PROJECT_ID>` -> `exit_code=0, overall_status=PASS, 26/26 active Lula specs satisfied, 0 restarts`).** Matched-SHA two-project Gate W certification from `main` (`fa772122`, archived at `gs://<PROJECT_ID>-evidence-worm-staging/gate-w-certification/fa772122/`, clean-room manifest SHA-256 `70513815ba2cfe7f57a1bf5d5106528cad5f605387307717569bd254e6551be4`, recovery manifest SHA-256 `99b750ace711674d5266b130629c2918d727beb0ac3385078b9fdeb33b2f0eb6`, [`gate_w_certification.json`](../../../compliance/gate_w_certification.json)) passed zero-drift Stage 2 & Stage 5 plans, `0` restarts across all workloads, 26/26 active Lula v0.16.0 specs under `startup_grace_hours=0`, regional/integration/E2E advisor suites, cross-teardown `CustodyVerifier` `BOUND_CHAIN_ROTATION` (`verified=7, bound_rotations=1, gaps=0` clean-room; `verified=6, bound_rotations=2, gaps=0` recovery) + `AS-6` Cloud Audit Log KMS corroboration (`module.evidence_domain`, `POAM-2026-197`), and Stage 6 `PF9` zero unexpected survivors. | Clean-room + matched-SHA recovery Gate W execution + automated quarterly freshness gate | **Low** | 2026-12-15 | 16 hrs | **Closed** | ✅ Certified 2026-11-12 (`fa772122`); guarded by [`tests/infrastructure/test_staging_lifecycle.py`](../../../tests/infrastructure/test_staging_lifecycle.py), [`tests/unit/test_check_gate_w_freshness.py`](../../../tests/unit/test_check_gate_w_freshness.py), and [`scripts/check_gate_w_freshness.py`](../../../scripts/check_gate_w_freshness.py). |

---

## POA&M Process

### Review Cadence

- **Monthly:** Review open items, update milestones, escalate slipped items
- **Quarterly:** ISO 42001 §9.1 management review; AO briefing on cross-region AIMS posture
- **Annual:** Full AIMS review per ISO 42001 §9.3

### Entry Criteria

New entries are created when:

- ISO 42001 Annex A control assessments identify weaknesses applicable to all regions
- New governance controls are introduced without complete AIMS documentation
- STPA compiler source changes introduce new UCAs not yet formally tracked
- Lula validation manifests identify AIMS gaps

### Closure Criteria

Items are closed when:

1. Remediation actions are fully implemented across all deployment regions
2. Implementation is verified by the ISSO or Security Control Assessor
3. Supporting evidence (code changes, Lula results, OSCAL artifacts) is archived
4. ISO 42001 §9.1 management review records the closure

---

_This document is a living record and must be updated within 5 business days of any status change. For the cross-region traceability matrix, see [`compliance/cross-region/POAM_INDEX.md`](../cross-region/POAM_INDEX.md)._
