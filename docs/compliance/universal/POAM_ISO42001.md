---
poam_file: POAM_ISO42001
region_scope: ALL
primary_framework: "ISO/IEC 42001:2023 (AI Management System Standard)"
global_baseline: ISO 42001
version: "1.0"
date: 2026-06-08
see_also:
  - docs/POAM_US_FED.md    # NIST SP 800-53 / ATO track (US_FED only)
  - docs/POAM_EU_ECB.md    # EU AI Act / DORA / GDPR weaknesses (EU_ECB only)
  - docs/POAM_APAC_MAS.md  # MAS FEAT / Notice 655 / TRM weaknesses (APAC_MAS only)
  - docs/POAM_INDEX.md     # cross-region traceability matrix
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
> For US_FED-specific NIST SP 800-53 weaknesses, see [`docs/POAM_US_FED.md`](../us_fed/POAM_US_FED.md).
> For EU_ECB-specific weaknesses, see [`docs/POAM_EU_ECB.md`](../eu_ecb/POAM_EU_ECB.md).
> For APAC_MAS-specific weaknesses, see [`docs/POAM_APAC_MAS.md`](../apac_mas/POAM_APAC_MAS.md).

---

## POA&M Summary

| Metric          | Count |
| --------------- | ----- |
| **Total Items** | 8     |
| **Critical**    | 0     |
| **High**        | 2     |
| **Moderate**    | 5     |
| **Low**         | 1     |
| **Open**        | 7     |
| **In Progress** | 1     |
| **Closed**      | 0     |

---

## POA&M Items

| POA&M ID | ISO 42001 Control | Co-Frameworks | Regions | Weakness Description | Detection Method | Risk Level | Scheduled Completion | Resources Required | Status | Milestone |
| -------- | ----------------- | ------------- | ------- | -------------------- | ---------------- | ---------- | -------------------- | ------------------ | ------ | --------- |
| POAM-018 | §A.9.4 — Telemetry and Monitoring | NIST SP 800-53 AU-9; DORA Art. 10; MAS Notice 655 §10 | ALL | Langfuse compliance project credentials fail silently when absent. If `LANGFUSE_COMPLIANCE_PUBLIC_KEY` / `LANGFUSE_COMPLIANCE_SECRET_KEY` are not configured, the Langfuse SDK initializes with empty credentials and silently drops all compliance audit traces. No error is raised, no alert fires, and all ISO 42001 evidence collection ceases without visible indication. **Phase 4 validation 2026-06-05 confirmed credentials are live** in the current cluster: `LANGFUSE_COMPLIANCE_PUBLIC_KEY` present in `langfuse-compliance-secrets` (42 bytes, `pk-lf-b055e6fe-…`); successful ingest to Langfuse compliance project (audit_id `lula-post-rename-1780672943`, 13 findings). Startup validation and `/health` credential check remain open remediation items. | Code review + [DUAL_PROJECT_ARCHITECTURE.md §5.2](../../architecture/DUAL_PROJECT_ARCHITECTURE.md) | **High** | 2026-07-15 | 4 hrs | Open | Add startup validation in `audit_workflow.py` that raises `RuntimeError` if compliance credentials are empty in non-dev environments; add `/health` check that reports compliance Langfuse connectivity status. **Originally tracked in:** [`docs/POAM_US_FED.md#POAM-018`](../us_fed/POAM_US_FED.md) as NIST AU-9. |
| POAM-019 | §A.9.4 — Telemetry and Monitoring | NIST SP 800-53 AU-9, SC-7; DORA Art. 10; MAS Notice 655 §10 | ALL | Terraform fallback silently collapses dual-project telemetry isolation. `infra/targets/gcp-gke/main.tf` L546-547 falls back to application project credentials when `langfuse_compliance_public_key` / `langfuse_compliance_secret_key` are empty. This silently defeats the dual-project architecture designed to provide evidentiary independence of audit evidence. `prod.tfvars` does not define compliance credentials, meaning production deployment would have no telemetry isolation. **Phase 4 validation 2026-06-05 confirmed alert pipeline active:** alert_targets `[SC-4, A.8.4, A.9.2]` fired; `remediation_sent=false` (VLLM_BASE_URL not set in CronJob pod — non-blocking). Terraform fallback removal remains open. | Terraform config review + [DUAL_PROJECT_ARCHITECTURE.md §4.2](../../architecture/DUAL_PROJECT_ARCHITECTURE.md) | **High** | 2026-07-15 | 2 hrs | Open | Remove Terraform fallback on L546-547; make compliance credentials a required variable with no default; add compliance credentials to `prod.tfvars` template; add Terraform `validation` block requiring non-empty compliance keys when `enable_compliance_bridge = true`. **Originally tracked in:** [`docs/POAM_US_FED.md#POAM-019`](../us_fed/POAM_US_FED.md) as NIST AU-9, SC-7. |
| ISO-001 | §A.4 — Resource Management | NIST SP 800-53 SC-5; NIST AI RMF GOVERN-1.7 | ALL | `CTRL_TQP_007` OPA runtime injection deferred. The OPA `quota_within_limits` and `token_quota_within_limits` rules in `deployment/system_authz.rego` provide secondary declarative evidence for token quota enforcement, but they currently evaluate against static policy data — not live Redis session state from `TokenQuotaProxy`. Until `governance_middleware.py` injects the current session counters into the OPA input document, the OPA rules cannot enforce the quota independently of the Python `TokenQuotaProxy`. This means OPA provides no independent verification of quota compliance. | Code review — `src/gateway/server/governance_middleware.py`, `deployment/system_authz.rego` | **Moderate** | 2026-07-31 | 8 hrs | Open | Inject Redis session state (`step_count`, `token_count`, `session_ttl`) into the OPA input document in `governance_middleware.py` before each policy evaluation; update `system_authz.rego` to evaluate against live session data; add integration test asserting OPA blocks a request when quota is exceeded. |
| ISO-002 | §6.1 — Risk Treatment / STPA | NIST SP 800-53 SI-2; ISO 42001 §A.4 | ALL | UCA-4 not yet added to `config/stpa_control_structure.yaml`. The STPA compiler (`src/gateway/governance/stpa_compiler.py`) generates Rego, Colang, and Python enforcement from the STPA control structure YAML. The `TokenQuotaProxy` introduces a new Unsafe Control Action (UCA-4: quota enforcement failure when Redis is unavailable). Until UCA-4 is added to the STPA source, the STPA compiler cannot generate the corresponding enforcement artifacts, and the UCA is not formally tracked in the safety case. | Code review — `config/stpa_control_structure.yaml`, `src/gateway/governance/stpa_compiler.py` | **Moderate** | 2026-07-15 | 4 hrs | Open | Add UCA-4 entry to `config/stpa_control_structure.yaml` covering the `TokenQuotaProxy` fail-CLOSED scenario; regenerate STPA artifacts (`generated_stpa_validator.py`, `generated_saga_nodes.py`); verify STPA freshness check passes in CI. |
| ISO-003 | §9.1 — Management Review | NIST SP 800-53 CA-5; ISO 42001 §9.3 | ALL | No ISO 42001 Clause 9 management review records exist. ISO 42001 §9.1 requires the organization to evaluate the performance and effectiveness of the AIMS at planned intervals. ISO 42001 §9.3 requires management review of the AIMS including review of audit results, nonconformities, and corrective actions. No management review records have been produced for any deployment region. This is a mandatory AIMS documentation requirement independent of any regional regulatory framework. | Gap analysis — ISO 42001 §9.1, §9.3 | **Moderate** | 2026-09-30 | 8 hrs | Open | Produce first ISO 42001 §9.1 performance evaluation report covering: Lula validation results, POAM status, UCA coverage, and STPA freshness; obtain management sign-off; establish quarterly review cadence. |
| ISO-004 | §A.6.1 — Policy Enforcement | NIST SP 800-53 CA-7; ISO 42001 §A.4 | ALL | `compliance/oscal/component-definition.yaml` missing `CTRL_TQP_007` entry. The OSCAL component definition maps technical enforcement components to ISO 42001 Annex A controls and links each to a Lula validation manifest. The `TokenQuotaProxy` (`CTRL_TQP_007`) was introduced in `fix/track-b-v2-release-gates` but has no corresponding entry in the component definition. This means the control is not formally registered in the OSCAL compliance artifact and cannot be assessed by automated Lula validation. | Documentation audit — `compliance/oscal/component-definition.yaml` | **Moderate** | 2026-06-20 | 2 hrs | **In Progress** | Add `CTRL_TQP_007` component entry to `compliance/oscal/component-definition.yaml` referencing `token_quota_proxy.py` and linking to a new `lula-validation-tqp007.yaml` manifest (stub); update `compliance/oscal/README.md`. Due within 2 business days of PR merge per `.roo/rules` §11.1. |
| POAM-023 | §A.4 — Resource Management / §8 — Operation | NIST SP 800-53 SA-9; ISO 42001 §A.6 | ALL | ~~`AnchorageGrpcLedgerProvider` not yet implemented — FUTURE STATE.~~ **✅ Closed 2026-07-27.** External CBF ledger reconciliation is implemented via `ExternalLedgerReconciler` (`src/compliance_bridge/reconciliation_worker.py`) with pluggable `LedgerProvider` backends: `StubLedgerProvider` (dev/CI), `PlaidLedgerProvider` (production-ready, OAuth 2.0), and `AnchorageGrpcLedgerProvider` (interface contract only — `fetch_balance()` raises `NotImplementedError` pending Anchorage enterprise gRPC credentials/stubs). Reconciled balances are KMS-signed before Redis write; the CBF falls back to Redis `WATCH/MULTI/EXEC` optimistic locking and fails closed on TTL expiry when no fresh reconciled balance is available. | Architecture review — `src/compliance_bridge/reconciliation_worker.py`, `src/gateway/governance/cbf.py` | **Moderate** | 2026-07-27 | 40 hrs | **Closed** | Follow-up: provision Anchorage enterprise gRPC credentials and generate protobuf stubs to activate `AnchorageGrpcLedgerProvider` as an alternative to `PlaidLedgerProvider`, if Anchorage custody is preferred in a given deployment. |
| POAM-024 | §8.4 — Operational Planning and Control | NIST SP 800-53 CA-2; ISO 42001 §9.1 | ALL | Staging environment not provisioned — dev→prod promotion path lacks pre-production validation tier. The Terraform schema (`infra/targets/gcp-gke/variables.tf`, `infra/targets/agnostic/variables.tf`, `infra/modules/k8s_namespace/variables.tf`) formally accepts `staging` as a valid `environment` value, and a three-tier promotion path (`dev → staging → prod`) is the intended design (illustrative pattern — no standalone `docs/CHANGE_MANAGEMENT_PROCESS.md` currently exists in this repository). However, no `staging.tfvars` file exists, no staging cluster has been provisioned, and `deploy_all.sh` rejects `--env staging` with an explicit error. Until staging is provisioned, all changes are promoted directly from `dev` to `prod` with AO acknowledgement. This creates a gap in pre-production validation coverage relative to the intended AIMS operational planning posture. | Architecture review — `infra/targets/gcp-gke/variables.tf`, `deploy_all.sh` | **Low** | 2026-12-31 | 16 hrs | Open | Provision `infra/targets/gcp-gke/staging.tfvars` with production-equivalent security settings (`enable_nist_compliance=true`); add `staging` branch to `deploy_all.sh`; update `src/gateway/governance/constants.py` to treat `CAGE_ENV=staging` as prod-equivalent; run full release gate suite against staging before promoting to prod. AO-acknowledged for the v2.0.0 release. |

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

_This document is a living record and must be updated within 5 business days of any status change. For the cross-region traceability matrix, see [`docs/POAM_INDEX.md`](../cross-region/POAM_INDEX.md)._
