# Plan of Action and Milestones (POAM)

<!-- Authority: .clinerules §11.3, docs/CHANGE_MANAGEMENT_PROCESS.md §9 -->
<!-- Format: Each closed entry must include commit SHA, Lula result, and closure date -->

## Overview

This document is the authoritative Plan of Action and Milestones (POAM) for the Cybernetic Governance Engine (CAGE) project. It tracks every open compliance finding, deferred control implementation, and known security gap that must be remediated before or after production deployment.

**How to use this document:**

- Every stub Lula manifest in `compliance/lula/` has a corresponding OPEN entry below.
- When a finding is remediated, move its entry to [Closed Findings](#closed-findings) and populate the Commit SHA, Lula Result, and Closure Date fields per `.clinerules` §11.3.
- POAM IDs are permanent — do not renumber closed entries.
- Reference POAM IDs in commit messages, PR descriptions, and Lula manifest comments.

**Numbering scheme:** `POAM-2026-NNN` for universal/US_FED findings; `EU-*` for EU_ECB-specific; `APAC-*` for APAC_MAS-specific.

---

## Status Legend

| ID | Control | Weakness | Severity | Status | Target Date |
|----|---------|----------|----------|--------|-------------|
| POAM-023 | SI-2 | CVE-2025-13462 in `libpython3.11` (python:3.12-slim-bookworm base layer) — 19 CRITICAL CVEs; no Debian bookworm fix available as of 2026-06-08; suppressed via `.trivyignore`; Cilium egress lockdown reduces exploitability; risk accepted with review date 2026-09-08 | Critical | Open | 2026-09-08 |

> POAM-023 is tracked in [`docs/POAM_US_FED.md`](POAM_US_FED.md) and [`docs/SECURITY_STATUS.md`](SECURITY_STATUS.md). The gateway Dockerfile was pinned to `python:3.12-slim-bookworm` with `apt-get upgrade -y` applied at build time; residual CVE-2025-13462 (`libpython3.11`) has no Debian bookworm fix as of 2026-06-08 and is suppressed via `.trivyignore` with Cilium egress lockdown reducing exploitability. The OPA runtime injection deferral (CTRL_TQP_007 secondary enforcement) is tracked separately as ISO-001 in [`docs/POAM_ISO42001.md`](POAM_ISO42001.md).

---

## Quick Reference Index

| POAM ID | Control | Framework | Region | Status |
|---------|---------|-----------|--------|--------|
| [POAM-2026-001](#poam-2026-001-ac-2-account-management-procedures-gap) | AC-2 | NIST SP 800-53 | US_FED | CLOSED |
| [POAM-2026-007](#poam-2026-007-ia-3-device-identification-no-mtls) | IA-3 | NIST SP 800-53 | US_FED | CLOSED |
| [POAM-2026-010](#poam-2026-010-ra-5-no-vulnerability-scanning-in-ci) | RA-5 | NIST SP 800-53 | US_FED | OPEN |
| [POAM-2026-011](#poam-2026-011-sc-8-no-tls-assertion-in-test-suite) | SC-8 | NIST SP 800-53 | US_FED | OPEN |
| [POAM-2026-012](#poam-2026-012-sc-12-cage_routing_seal_secret-lifecycle-gap) | SC-12 / IA-5 | NIST SP 800-53 | US_FED | OPEN |
| [POAM-2026-013](#poam-2026-013-si-2-unpinned-python-dependencies-and-latest-image-tags) | SI-2 | NIST SP 800-53 | US_FED | OPEN |
| [POAM-2026-016](#poam-2026-016-torch-dev-only-cve-pysec-2026-139) | RA-5 / SI-2 | NIST SP 800-53 | US_FED | OPEN |
| [POAM-2026-023](#poam-2026-023-trivy-critical-cves-libpython311) | RA-5 | NIST SP 800-53 | US_FED | OPEN |
| [POAM-2026-024](#poam-2026-024-staging-compliance-posture-not-verified) | CM-6 | NIST SP 800-53 | Universal | OPEN |
| [POAM-2026-025](#poam-2026-025-ai-600-1-26-cbrn-harmful-content-stub-validation) | AI 600-1 §2.6 | NIST AI 600-1 | US_FED | OPEN |
| [POAM-2026-026](#poam-2026-026-iso-42001-a84-tokenquotaproxy-stub-validation) | ISO 42001 A.8.4 | ISO 42001 | Universal | OPEN |
| [POAM-2026-027](#poam-2026-027-docs-poammd-absent-from-repository) | Structural | Governance | Universal | CLOSED |
| [EU-DORA-001](#eu-dora-001-dora-art-10-compliance-bridge-endpoint-not-implemented) | DORA Art. 10 | DORA | EU_ECB | OPEN |
| [EU-AI-ACT-001](#eu-ai-act-001-eu-ai-act-art-9-risk-management-endpoint-not-implemented) | EU AI Act Art. 9 | EU AI Act | EU_ECB | OPEN |
| [EU-GDPR-001](#eu-gdpr-001-gdpr-art-22-human-oversight-endpoint-not-implemented) | GDPR Art. 22 | GDPR | EU_ECB | OPEN |
| [EU-001](#eu-001-eu-ai-act-art-29a-fria-gating-normative-provider-stub) | EU AI Act Art. 29a | EU AI Act | EU_ECB | OPEN |
| [APAC-MAS-FEAT-001](#apac-mas-feat-001-mas-feat-compliance-bridge-endpoint-not-implemented) | MAS FEAT | MAS FEAT | APAC_MAS | OPEN |
| [APAC-MAS-N655-001](#apac-mas-n655-001-mas-notice-655-compliance-bridge-endpoint-not-implemented) | MAS Notice 655 | MAS Notice 655 | APAC_MAS | OPEN |
| [APAC-MAS-TRM-001](#apac-mas-trm-001-mas-trm-63-compliance-bridge-endpoint-not-implemented) | MAS TRM §6.3 | MAS TRM | APAC_MAS | OPEN |

---

## Open Findings


### POAM-2026-010: RA-5 — No In-Cluster Vulnerability Scanning CronJob

| Field | Value |
|-------|-------|
| **Status** | OPEN |
| **Control** | NIST SP 800-53 Rev 5 RA-5 — Vulnerability Monitoring and Scanning |
| **Manifest** | `compliance/lula/lula-validation-ra5.yaml` |
| **Region Scope** | US_FED |
| **Deferred Since** | 2026-06-08 |
| **Target Remediation** | 2026-09-30 |
| **Owner** | Compliance Engineering |
| **Risk** | `lula validate` on `lula-validation-ra5.yaml` will FAIL if `security-scanner-cronjob` is absent from the `governance-stack` namespace. Blocks US_FED RA-5 continuous monitoring evidence. |
| **Closure Criteria** | `kubectl apply -f deployment/k8s/sbom-cronjob.yaml` applied to cluster; `lula validate` passes on `lula-validation-ra5.yaml`; CronJob labeled `cage.io/purpose: vulnerability-scan` confirmed present. |
| **Closed** | — |
| **Commit SHA** | — |
| **Lula Result** | PENDING |

---

### POAM-2026-011: SC-8 — No Encryption-in-Transit Assertion in Test Suite

| Field | Value |
|-------|-------|
| **Status** | OPEN |
| **Control** | NIST SP 800-53 Rev 5 SC-8 — Transmission Confidentiality and Integrity |
| **Manifest** | `compliance/lula/lula-validation-sc8.yaml` |
| **Region Scope** | US_FED |
| **Deferred Since** | 2026-06-08 |
| **Target Remediation** | 2026-09-30 |
| **Owner** | Compliance Engineering |
| **Risk** | `tests/test_gateway_connectivity.py` lacks an assertion that all intra-cluster connections use TLS. The Lula manifest `lula-validation-sc8.yaml` provides automated SC-8 evidence in lieu of the missing test, but the test gap remains a finding. Redis TLS (`rediss://`) was enabled in Sprint 2 (H-04) but the test suite does not assert this. |
| **Closure Criteria** | `tests/test_gateway_connectivity.py` updated with TLS assertion; `lula validate` passes on `lula-validation-sc8.yaml` against live cluster. |
| **Closed** | — |
| **Commit SHA** | — |
| **Lula Result** | PENDING |

---

### POAM-2026-012: SC-12 / IA-5 — CAGE_ROUTING_SEAL_SECRET Lifecycle Gap

| Field | Value |
|-------|-------|
| **Status** | OPEN |
| **Control** | NIST SP 800-53 Rev 5 SC-12 — Cryptographic Key Establishment and Management; IA-5 — Authenticator Management |
| **Manifest** | `compliance/lula/lula-validation-ia5.yaml` |
| **Region Scope** | US_FED |
| **Deferred Since** | 2026-06-08 |
| **Target Remediation** | 2026-09-30 |
| **Owner** | Security Engineering |
| **Risk** | The `cage-routing-seal` Kubernetes Secret (HMAC signing key for governance routing seals) must exist in the `governance-stack` namespace with `cage.io/rotation-schedule` annotation and `cage.io/sensitivity-level` label. If absent or missing annotations, `lula validate` on `lula-validation-ia5.yaml` will FAIL. Additionally, no automated rotation procedure is documented for `CAGE_ROUTING_SEAL_SECRET`. |
| **Closure Criteria** | `cage-routing-seal` Secret deployed with required annotations and labels; rotation schedule documented in `docs/SECRET_ROTATION_RUNBOOK.md`; `lula validate` passes on `lula-validation-ia5.yaml`. |
| **Closed** | — |
| **Commit SHA** | — |
| **Lula Result** | PENDING |

---

### POAM-2026-013: SI-2 — Unpinned Python Dependencies and `:latest` Image Tags

| Field | Value |
|-------|-------|
| **Status** | OPEN |
| **Control** | NIST SP 800-53 Rev 5 SI-2 — Flaw Remediation |
| **Manifest** | `compliance/lula/lula-validation-si2.yaml` |
| **Region Scope** | US_FED |
| **Deferred Since** | 2026-06-08 |
| **Target Remediation** | 2026-09-30 |
| **Owner** | Platform Engineering |
| **Risk** | `deployment/k8s/backend-deployment.yaml` uses `:latest` image tags. `lula-validation-si2.yaml` asserts that `governed-financial-advisor` and `compliance-bridge` Deployments do NOT use `:latest`. If not remediated before ATO, this validation will FAIL. Additionally, Python dependency lockfiles (`pip freeze` / `uv.lock`) must be verified to pin all transitive dependencies. |
| **Closure Criteria** | All CAGE Deployment manifests updated to use pinned image digests or semantic version tags; `imagePullPolicy: Always` confirmed on all containers; vulnerability-scan CronJob labeled `cage.io/purpose: vulnerability-scan` present; `lula validate` passes on `lula-validation-si2.yaml`. |
| **Closed** | — |
| **Commit SHA** | — |
| **Lula Result** | PENDING |

---

### POAM-2026-016: RA-5 / SI-2 — torch Dev-Only CVE (PYSEC-2026-139)

| Field | Value |
|-------|-------|
| **Status** | OPEN |
| **Control** | NIST SP 800-53 Rev 5 RA-5 — Vulnerability Monitoring and Scanning; SI-2 — Flaw Remediation |
| **Manifest** | `compliance/lula/lula-validation-ra5.yaml` (supporting evidence) |
| **Region Scope** | US_FED |
| **Deferred Since** | 2026-06-09 |
| **Target Remediation** | 2026-12-31 |
| **Owner** | Security Engineering |
| **Risk** | `torch 2.10.0` carries PYSEC-2026-139. No upstream fix available as of 2026-06-09. `torch` is a dev-only dependency (not present in production images). Suppressed via `--ignore-vuln PYSEC-2026-139` in `.github/workflows/security-scan.yml`. Risk is LOW given dev-only scope, but must be reviewed quarterly. |
| **Closure Criteria** | Upstream `torch` fix released and dependency upgraded; `pip-audit` scan passes without suppression; POAM entry closed with review date and CVE resolution confirmation. |
| **Closed** | — |
| **Commit SHA** | — |
| **Lula Result** | N/A (dev-only dependency, not in production image) |

---

### POAM-2026-023: RA-5 — Trivy CRITICAL CVEs in libpython3.11 (CVE-2025-13462)

| Field | Value |
|-------|-------|
| **Status** | OPEN |
| **Control** | NIST SP 800-53 Rev 5 RA-5 — Vulnerability Monitoring and Scanning |
| **Manifest** | `compliance/lula/lula-validation-ra5.yaml` (supporting evidence) |
| **Region Scope** | US_FED |
| **Deferred Since** | 2026-06-08 |
| **Target Remediation** | 2026-09-08 |
| **Owner** | Security Engineering |
| **Risk** | Trivy container scan identified 19 CRITICAL CVEs in `libpython3.11` (CVE-2025-13462) in the `python:3.12-slim-bookworm` base layer. No Debian bookworm fix available as of 2026-06-08. `apt-get upgrade -y` applied during image build cannot remediate this CVE. Suppressed via `.trivyignore`. Network egress locked down via Cilium to reduce exploitability. |
| **Closure Criteria** | Debian bookworm fix released for CVE-2025-13462; base image rebuilt; Trivy scan passes without suppression; `.trivyignore` entry removed; POAM closed with scan artifact reference. |
| **Closed** | — |
| **Commit SHA** | — |
| **Lula Result** | N/A (Trivy scan, not Lula) |

---

### POAM-2026-024: CM-6 — Staging Compliance Posture Not Verified

| Field | Value |
|-------|-------|
| **Status** | OPEN |
| **Control** | NIST SP 800-53 Rev 5 CM-6 — Configuration Settings |
| **Manifest** | `compliance/lula/lula-validation-cm6.yaml` (staging environment) |
| **Region Scope** | Universal |
| **Deferred Since** | 2026-06-14 |
| **Target Remediation** | 2026-09-30 |
| **Owner** | Compliance Engineering |
| **Risk** | Staging compliance posture verification was deferred at v0.1.0 release (CHANGELOG.md, `9373ef4`). Lula validations have only been executed against the `cage-dev` GKE cluster. A staging environment with equivalent compliance posture has not been verified. This blocks the dev → staging → production promotion chain required by `.clinerules` §8.2. |
| **Closure Criteria** | Staging GKE cluster provisioned; all universal Lula validations executed against staging; `lula validate` passes on all manifests in `compliance/lula/`; CHANGELOG.md updated with staging gate results. |
| **Closed** | — |
| **Commit SHA** | — |
| **Lula Result** | PENDING |


### POAM-2026-025: AI 600-1 §2.6 — CBRN / Harmful Content Stub Validation

| Field | Value |
|-------|-------|
| **Status** | OPEN |
| **Control** | NIST AI 600-1 §2.6 — CBRN and Harmful Content Controls |
| **Manifest** | `compliance/lula/lula-validation-ai600-cbrn.yaml` |
| **Region Scope** | US_FED |
| **Deferred Since** | 2026-06-30 |
| **Target Remediation** | 2026-12-31 |
| **Owner** | Compliance Engineering |
| **Risk** | The manifest is a Phase 0 stub (`default allow = true`). It always passes regardless of whether NeMo CBRN rails are actually deployed. This means the AI 600-1 §2.6 control is not being automatically verified. The NeMo CBRN rail deployment (`NEMO_CBRN_RAILS_ENABLED=true`) requires AO pre-approval (Cat-M change) before Phase 3 real assertions can be activated. US_FED ATO is blocked until this control is verified. |
| **Closure Criteria** | AO pre-approval obtained for NeMo CBRN rail deployment; `nemo` Deployment updated with `NEMO_CBRN_RAILS_ENABLED=true` and `cbrn_rails.co` mounted; stub replaced with Phase 3 real assertions per `AI_600_1_IMPLEMENTATION_PLAN.md §7.2`; `lula validate` passes on `lula-validation-ai600-cbrn.yaml`. |
| **Closed** | — |
| **Commit SHA** | — |
| **Lula Result** | STUB |

---

### POAM-2026-026: ISO 42001 A.8.4 — TokenQuotaProxy Stub Validation

| Field | Value |
|-------|-------|
| **Status** | OPEN |
| **Control** | ISO 42001 Annex A.8.4 — AI System Operation Controls (TokenQuotaProxy fail-closed) |
| **Manifest** | `compliance/lula/lula-validation-tqp007.yaml` |
| **Region Scope** | Universal |
| **Deferred Since** | 2026-06-30 |
| **Target Remediation** | 2026-09-30 |
| **Owner** | Platform Engineering |
| **Risk** | The `token-quota-proxy` Deployment does not yet exist in the `governance-stack` namespace. `lula validate` on `lula-validation-tqp007.yaml` will FAIL because the Deployment resource is absent. STPA hazard H-7 (TokenQuotaProxy fail-OPEN when Redis unavailable) is not yet mitigated by a dedicated sidecar. The `TokenQuotaProxy` Python module (`src/gateway/governance/token_quota_proxy.py`) is deployed inline in the gateway, but the standalone Deployment required by CTRL_TQP_007 is pending. |
| **Closure Criteria** | `token-quota-proxy` Deployment created in `governance-stack` namespace with `REDIS_URL` and `TOKEN_QUOTA_FAIL_CLOSED=true` env vars; `lula validate` passes on `lula-validation-tqp007.yaml`; STPA hazard H-7 marked mitigated. |
| **Closed** | — |
| **Commit SHA** | — |
| **Lula Result** | STUB |

---

### EU-DORA-001: DORA Art. 10 — Compliance Bridge Endpoint Not Implemented

| Field | Value |
|-------|-------|
| **Status** | OPEN |
| **Control** | DORA Art. 10 — ICT Operational Resilience Testing |
| **Manifest** | `compliance/lula/lula-validation-dora-art10.yaml` |
| **Region Scope** | EU_ECB |
| **Deferred Since** | 2026-06-30 |
| **Target Remediation** | 2026-12-31 |
| **Owner** | Compliance Engineering |
| **Risk** | The compliance-bridge endpoint `GET /v1/compliance/dora/art10` is not yet implemented. `lula validate` on `lula-validation-dora-art10.yaml` will FAIL with a connection error. EU_ECB deployment is blocked until DORA Art. 10 ICT audit logging, 5-year log retention, incident classification, and resilience testing evidence is surfaced via this endpoint. |
| **Closure Criteria** | `GET /v1/compliance/dora/art10` implemented in `src/compliance_bridge/main.py` returning `ict_audit_logging_active`, `log_retention_years`, `incident_classification_active`, `tamper_evident_storage`, `resilience_testing_days_since_last`, `threat_led_penetration_testing_active`, and `evidence_age_seconds` fields; `lula validate` passes on `lula-validation-dora-art10.yaml`. |
| **Closed** | — |
| **Commit SHA** | — |
| **Lula Result** | PENDING |

---

### EU-AI-ACT-001: EU AI Act Art. 9 — Risk Management Endpoint Not Implemented

| Field | Value |
|-------|-------|
| **Status** | OPEN |
| **Control** | EU AI Act Art. 9 — Risk Management System for High-Risk AI |
| **Manifest** | `compliance/lula/lula-validation-eu-ai-act-art9.yaml` |
| **Region Scope** | EU_ECB |
| **Deferred Since** | 2026-06-30 |
| **Target Remediation** | 2026-12-31 |
| **Owner** | Compliance Engineering |
| **Risk** | The compliance-bridge endpoint `GET /v1/compliance/eu-ai-act/art9` is not yet implemented. `lula validate` on `lula-validation-eu-ai-act-art9.yaml` will FAIL. CAGE is classified as a High-Risk AI system under EU AI Act Annex III §5(b). EU_ECB deployment is blocked until the Art. 9 risk management system evidence is surfaced. Annual reassessment cadence (365-day staleness guard) must be maintained post-closure. |
| **Closure Criteria** | `GET /v1/compliance/eu-ai-act/art9` implemented returning `risk_management_system_active`, `risk_identification_complete`, `residual_risk_accepted`, `high_risk_classification_documented`, `continuous_monitoring_enabled`, `post_market_monitoring_active`, and `evidence_age_days` fields; `lula validate` passes on `lula-validation-eu-ai-act-art9.yaml`. |
| **Closed** | — |
| **Commit SHA** | — |
| **Lula Result** | PENDING |

---

### EU-GDPR-001: GDPR Art. 22 — Human Oversight Endpoint Not Implemented

| Field | Value |
|-------|-------|
| **Status** | OPEN |
| **Control** | GDPR Art. 22 — Human Oversight of Automated Individual Decision-Making |
| **Manifest** | `compliance/lula/lula-validation-gdpr-art22.yaml` |
| **Region Scope** | EU_ECB |
| **Deferred Since** | 2026-06-30 |
| **Target Remediation** | 2026-12-31 |
| **Owner** | Compliance Engineering |
| **Risk** | The compliance-bridge endpoint `GET /v1/compliance/gdpr/art22` is not yet implemented. `lula validate` on `lula-validation-gdpr-art22.yaml` will FAIL. CAGE financial advisory decisions may constitute automated individual decision-making with legal or similarly significant effects under GDPR Art. 22(1). EU_ECB deployment is blocked until HITL active status, consensus threshold (≤EUR 7,500), human review SLA (≤24h), data subject rights implementation, and automated decision audit trail are surfaced. |
| **Closure Criteria** | `GET /v1/compliance/gdpr/art22` implemented returning `hitl_active`, `consensus_threshold_eur`, `human_review_sla_hours`, `data_subject_rights_implemented`, `automated_decision_audit_trail_active`, `contest_mechanism_available`, and `evidence_age_seconds` fields; `lula validate` passes on `lula-validation-gdpr-art22.yaml`. |
| **Closed** | — |
| **Commit SHA** | — |
| **Lula Result** | PENDING |

---

### EU-001: EU AI Act Art. 29a — FRIA Gating Normative Provider in Stub Mode

| Field | Value |
|-------|-------|
| **Status** | OPEN |
| **Control** | EU AI Act Art. 29a — Fundamental Rights Impact Assessment Gating |
| **Manifest** | `compliance/lula/lula-validation-eu-fria.yaml` |
| **Region Scope** | EU_ECB |
| **Deferred Since** | 2026-06-30 |
| **Target Remediation** | 2026-12-31 |
| **Owner** | Compliance Engineering |
| **Risk** | The `cage-gateway` Deployment must have `CAGE_NORMATIVE_PROVIDER` set to a non-stub value (not `"static"`) and `CAGE_NORMATIVE_ENDPOINT` set to the TrustLayers API URL for EU_ECB deployments. If `CAGE_NORMATIVE_PROVIDER=static`, FRIA gating is bypassed — all governance decisions are self-admitted without independent external compliance validation, which does not satisfy EU AI Act Art. 29a for High-Risk AI systems. |
| **Closure Criteria** | EU_ECB `cage-gateway` Deployment configured with `CAGE_NORMATIVE_PROVIDER=trustlayers` (or equivalent non-stub provider) and `CAGE_NORMATIVE_ENDPOINT` set; `lula validate` passes on `lula-validation-eu-fria.yaml`; `docs/FRIA_ATTESTATION.md` updated with provider details. |
| **Closed** | — |
| **Commit SHA** | — |
| **Lula Result** | PENDING |


### APAC-MAS-FEAT-001: MAS FEAT — Compliance Bridge Endpoint Not Implemented

| Field | Value |
|-------|-------|
| **Status** | OPEN |
| **Control** | MAS FEAT Principles — Fairness, Ethics, Accountability, Transparency |
| **Manifest** | `compliance/lula/lula-validation-mas-feat.yaml` |
| **Region Scope** | APAC_MAS |
| **Deferred Since** | 2026-06-30 |
| **Target Remediation** | 2026-12-31 |
| **Owner** | Compliance Engineering |
| **Risk** | The compliance-bridge endpoint `GET /v1/compliance/mas/feat` is not yet implemented. `lula validate` on `lula-validation-mas-feat.yaml` will FAIL. APAC_MAS deployment is blocked until MAS FEAT Fairness Impact Assessment status, demographic parity gap (≤8%), accountability controls, transparency reporting cadence (≤180 days), ethics review cadence (≤365 days), and explainability mechanism status are surfaced. |
| **Closure Criteria** | `GET /v1/compliance/mas/feat` implemented returning `fairness_impact_assessment_active`, `demographic_parity_gap`, `accountability_controls_documented`, `transparency_report_days_since_last`, `ethics_review_days_since_last`, `explainability_mechanism_active`, and `evidence_age_seconds` fields; `lula validate` passes on `lula-validation-mas-feat.yaml`. |
| **Closed** | — |
| **Commit SHA** | — |
| **Lula Result** | PENDING |

---

### APAC-MAS-N655-001: MAS Notice 655 — Compliance Bridge Endpoint Not Implemented

| Field | Value |
|-------|-------|
| **Status** | OPEN |
| **Control** | MAS Notice 655 — Technology Risk Management Audit Logging |
| **Manifest** | `compliance/lula/lula-validation-mas-notice655.yaml` |
| **Region Scope** | APAC_MAS |
| **Deferred Since** | 2026-06-30 |
| **Target Remediation** | 2026-12-31 |
| **Owner** | Compliance Engineering |
| **Risk** | The compliance-bridge endpoint `GET /v1/compliance/mas/notice655` is not yet implemented. `lula validate` on `lula-validation-mas-notice655.yaml` will FAIL. APAC_MAS deployment is blocked until MAS Notice 655 audit logging status, 5-year log retention, `asia-southeast1` data residency, tamper-evident storage, TRM framework documentation, incident detection, and RTO definition are surfaced. The SR 26-2 "no legal force" sentinel must remain active to suppress US Federal Reserve-specific telemetry. |
| **Closure Criteria** | `GET /v1/compliance/mas/notice655` implemented returning `audit_logging_active`, `log_retention_years`, `data_residency_region` (must equal `"asia-southeast1"`), `tamper_evident_storage`, `trm_framework_documented`, `incident_detection_active`, `recovery_time_objective_defined`, and `evidence_age_seconds` fields; `lula validate` passes on `lula-validation-mas-notice655.yaml`. |
| **Closed** | — |
| **Commit SHA** | — |
| **Lula Result** | PENDING |

---

### APAC-MAS-TRM-001: MAS TRM §6.3 — Compliance Bridge Endpoint Not Implemented

| Field | Value |
|-------|-------|
| **Status** | OPEN |
| **Control** | MAS TRM Guidelines §6.3 — AI and Machine Learning Controls |
| **Manifest** | `compliance/lula/lula-validation-mas-trm-s6.yaml` |
| **Region Scope** | APAC_MAS |
| **Deferred Since** | 2026-06-30 |
| **Target Remediation** | 2026-12-31 |
| **Owner** | Compliance Engineering |
| **Risk** | The compliance-bridge endpoint `GET /v1/compliance/mas/trm-s6` is not yet implemented. `lula validate` on `lula-validation-mas-trm-s6.yaml` will FAIL. APAC_MAS deployment is blocked until MAS TRM §6.3 AI governance framework documentation, model risk management controls, confidence threshold (≥0.96), HITL controls, model performance monitoring, model drift threshold definition, and `asia-southeast1` data residency are surfaced. |
| **Closure Criteria** | `GET /v1/compliance/mas/trm-s6` implemented returning `ai_governance_framework_documented`, `model_risk_management_active`, `confidence_threshold`, `hitl_controls_active`, `model_performance_monitoring_active`, `data_residency_region` (must equal `"asia-southeast1"`), `model_drift_threshold_defined`, and `evidence_age_seconds` fields; `lula validate` passes on `lula-validation-mas-trm-s6.yaml`. |
| **Closed** | — |
| **Commit SHA** | — |
| **Lula Result** | PENDING |

---

## Closed Findings

### POAM-2026-001: AC-2 — Account Management Procedures Gap

| Field | Value |
|-------|-------|
| **Status** | CLOSED |
| **Control** | NIST SP 800-53 Rev 5 AC-2 — Account Management |
| **Manifest** | `compliance/lula/lula-validation-ac2.yaml` |
| **Region Scope** | US_FED |
| **Deferred Since** | 2026-05-01 |
| **Closed** | 2026-06-08 |
| **Commit SHA** | See `compliance/lula/lula-validation-ac2.yaml` notes — remediated via `financial-advisor-sa` ServiceAccount pattern in `deployment/k8s/service-account.yaml` and GCP workload identity bindings in `deployment/terraform/iam.tf`. |
| **Lula Result** | PASS — `lula validate` on `lula-validation-ac2.yaml` passes: all named ServiceAccounts carry `cage.io/account-purpose` label; `default` SA has `automountServiceAccountToken: false`; no Pod uses the `default` ServiceAccount. |
| **Remediation Summary** | Implemented named ServiceAccount (`financial-advisor-sa`) with `cage.io/account-purpose` label; disabled auto-mount on default SA; all Pods bound to named SAs. Lula validation updated from compensating-control stub to full AC-2 assertion. |

---

### POAM-2026-007: IA-3 — Device Identification — No mTLS

| Field | Value |
|-------|-------|
| **Status** | CLOSED |
| **Control** | NIST SP 800-53 Rev 5 IA-3 — Device Identification and Authentication |
| **Manifest** | `compliance/lula/lula-validation-ia3.yaml` |
| **Region Scope** | US_FED |
| **Deferred Since** | 2026-04-01 |
| **Closed** | 2026-05-17 |
| **Commit SHA** | See `compliance/lula/lula-validation-ia3.yaml` annotation: `cage.poam-007: "CLOSED 2026-05-17 — Linkerd mTLS implemented."` |
| **Lula Result** | PASS — `lula validate` on `lula-validation-ia3.yaml` passes: Linkerd namespace exists; all `governance-stack` Deployments carry `linkerd.io/inject: enabled` annotation; `default-deny-ingress` NetworkPolicy present; OPA Deployment running. |
| **Remediation Summary** | Linkerd service mesh deployed across all intra-cluster service communication in `governance-stack` namespace. Per-pod cryptographic identity via SPIFFE/X.509 certificates issued by Linkerd CA. Validation updated from compensating-control assertion (NetworkPolicy + OPA + intent annotation) to full Linkerd mTLS assertion. `default-deny-ingress` NetworkPolicy retained as defence-in-depth L3/L4 control. |

---

### POAM-2026-027: Structural — docs/POAM.md Absent from Repository

| Field | Value |
|-------|-------|
| **Status** | CLOSED |
| **Control** | Structural compliance gap — `.clinerules` §11.3 mandates POAM tracking |
| **Manifest** | N/A |
| **Region Scope** | Universal |
| **Deferred Since** | 2026-06-08 (v0.1.0 release — file referenced but absent) |
| **Closed** | 2026-06-30 |
| **Commit SHA** | *(populated on commit of this file)* |
| **Lula Result** | N/A — structural documentation gap, not a Lula validation |
| **Remediation Summary** | Created `docs/POAM.md` as the authoritative Plan of Action and Milestones document. Inventoried all 29 Lula manifests in `compliance/lula/`; identified 2 stubs (POAM-2026-025, POAM-2026-026) and 9 active manifests with unimplemented compliance-bridge endpoints (EU/APAC findings). All open findings documented with control references, region scope, risk statements, and closure criteria. |

---

## Manifest Status Summary

| Manifest | Framework | Control | Region | Lula Status |
|----------|-----------|---------|--------|-------------|
| `lula-validation-a52.yaml` | ISO 42001 | A.5.2 Social Impact Assessment | Universal | ACTIVE |
| `lula-validation-a53.yaml` | ISO 42001 | A.5.3 Logging and Monitoring | Universal | ACTIVE |
| `lula-validation-a92.yaml` | ISO 42001 | A.9.2 Data Transfer to Suppliers | Universal | ACTIVE |
| `lula-validation-aarm-vectors.yaml` | CSA AARM | All 11 threat vectors | Universal | ACTIVE |
| `lula-validation-iso001-token-quota.yaml` | ISO 42001 | A.4 Token Quota OPA Injection | Universal | ACTIVE (Phase 1) |
| `lula-validation-tqp007.yaml` | ISO 42001 | A.8.4 TokenQuotaProxy fail-closed | Universal | **STUB** — POAM-2026-026 |
| `lula-validation-ac2.yaml` | NIST SP 800-53 | AC-2 Account Management | US_FED | ACTIVE |
| `lula-validation-ac3.yaml` | NIST SP 800-53 | AC-3 Access Enforcement | US_FED | ACTIVE |
| `lula-validation-au12.yaml` | NIST SP 800-53 | AU-12 Audit Record Generation | US_FED | ACTIVE |
| `lula-validation-cm6.yaml` | NIST SP 800-53 | CM-6 Configuration Settings | US_FED | ACTIVE |
| `lula-validation-ia3.yaml` | NIST SP 800-53 | IA-3 Device Identification | US_FED | ACTIVE (POAM-007 CLOSED) |
| `lula-validation-ia5.yaml` | NIST SP 800-53 | IA-5 Authenticator Management | US_FED | ACTIVE |
| `lula-validation-ir6.yaml` | NIST SP 800-53 | IR-6 Incident Reporting | US_FED | ACTIVE |
| `lula-validation-ra5.yaml` | NIST SP 800-53 | RA-5 Vulnerability Scanning | US_FED | ACTIVE |
| `lula-validation-sc4.yaml` | NIST SP 800-53 | SC-4 Fiscal Limits / RBAC | US_FED | ACTIVE |
| `lula-validation-sc8.yaml` | NIST SP 800-53 | SC-8 Transmission Confidentiality | US_FED | ACTIVE |
| `lula-validation-si2.yaml` | NIST SP 800-53 | SI-2 Flaw Remediation | US_FED | ACTIVE |
| `lula-validation-ai600-cbrn.yaml` | NIST AI 600-1 | §2.6 CBRN / Harmful Content | US_FED | **STUB** — POAM-2026-025 |
| `lula-validation-ai600-confabulation.yaml` | NIST AI 600-1 | §2.1 Confabulation | US_FED | ACTIVE (Phase 2) |
| `lula-validation-ai600-data-privacy.yaml` | NIST AI 600-1 | §2.2 Data Privacy | US_FED | ACTIVE (Phase 2) |
| `lula-validation-ai600-human-ai-config.yaml` | NIST AI 600-1 | §2.5 Human-AI Configuration | US_FED | ACTIVE (Phase 2) |
| `lula-validation-ai600-prompt-injection.yaml` | NIST AI 600-1 | §2.3 Prompt Injection | US_FED | ACTIVE (Phase 2) |
| `lula-validation-dora-art10.yaml` | DORA | Art. 10 ICT Resilience | EU_ECB | ACTIVE (endpoint pending — EU-DORA-001) |
| `lula-validation-eu-ai-act-art9.yaml` | EU AI Act | Art. 9 Risk Management | EU_ECB | ACTIVE (endpoint pending — EU-AI-ACT-001) |
| `lula-validation-eu-fria.yaml` | EU AI Act | Art. 29a FRIA Gating | EU_ECB | ACTIVE (provider stub — EU-001) |
| `lula-validation-gdpr-art22.yaml` | GDPR | Art. 22 Automated Decisions | EU_ECB | ACTIVE (endpoint pending — EU-GDPR-001) |
| `lula-validation-mas-feat.yaml` | MAS FEAT | Fairness/Ethics/Accountability/Transparency | APAC_MAS | ACTIVE (endpoint pending — APAC-MAS-FEAT-001) |
| `lula-validation-mas-notice655.yaml` | MAS Notice 655 | Technology Risk Management | APAC_MAS | ACTIVE (endpoint pending — APAC-MAS-N655-001) |
| `lula-validation-mas-trm-s6.yaml` | MAS TRM | §6.3 AI/ML Controls | APAC_MAS | ACTIVE (endpoint pending — APAC-MAS-TRM-001) |

---

## Closure Procedure

When remediating a finding, follow this procedure per `.clinerules` §11.3:

1. Implement the remediation in a `fix(compliance):` or `feat(compliance):` PR targeting the appropriate branch.
2. Run `lula validate` against the relevant manifest on the live cluster.
3. Record the output: pass/fail status and any assertion details.
4. Update this file:
   - Change `**Status**` from `OPEN` / `IN_PROGRESS` to `CLOSED`.
   - Populate `**Closed**` with the ISO 8601 date (e.g., `2026-09-30`).
   - Populate `**Commit SHA**` with the full 40-character SHA of the remediation commit.
   - Populate `**Lula Result**` with `PASS` and the manifest name.
   - Move the entry from [Open Findings](#open-findings) to [Closed Findings](#closed-findings).
5. Update `docs/POAM.md` in the same PR or a follow-on PR within 2 business days of merge.
6. If the finding remediates a NIST SP 800-53 control, update the OSCAL component in `compliance/oscal/` within 2 business days per `.clinerules` §11.1.

