# MAS Notice 655 Audit Certification Runbook — CAGE Governed Financial Advisor

**Document:** MAS-002 / MAS Notice 655 §12 / MAS FEAT Accountability Principle A2 / ISO 42001 §A.9.4
**Date:** 2026-06-24
**Status:** Draft — MAS-accredited auditor not yet engaged
**POAM:** MAS-002 (POAM_APAC_MAS.md)
**Region Scope:** `CAGE_DEPLOYMENT_REGION=APAC_MAS` only

---

> [!IMPORTANT]
> MAS Notice 655 audit certification requires engagement of a **MAS-accredited auditor**. This runbook describes the preparation steps; the certification itself must be conducted by the accredited auditor and the results submitted to MAS if required.

---

## 1. Regulatory Basis

**MAS Notice 655 §12** (Technology Risk Management) requires financial institutions to ensure that audit logs for critical systems:
- Enable complete reconstruction of all material system events
- Are protected from unauthorised modification
- Are retained for a minimum period

**MAS FEAT Accountability Principle A2** requires AI systems in financial services to maintain audit trails that enable complete reconstruction of all AI system decisions for regulatory review.

---

## 2. Current Audit Capability Assessment

### 2.1 What is Logged

| Event | Log Type | Storage | Tamper-Evidence |
|---|---|---|---|
| Every governance decision | OTel span (Langfuse APAC_MAS project) | Langfuse (Singapore-region) | Langfuse project access controls |
| Every HITL escalation | `hitl_override_audit` span | Langfuse APAC_MAS project | Same as above |
| Every trade governance outcome | WORM UCA record | GCS (`cage-apac-mas-audit`) | KMS signature + hash chain |
| Model integrity verification | SHA-256 hash record | GCS (`cage-apac-mas-audit/model-provenance/`) | Hash chain |
| Lula compliance assessments | OSCAL assessment result | GCS (`cage-apac-mas-audit/lula-results/`) | GCS bucket lock |
| System configuration changes | Terraform audit trail | GCP Audit Logs | Cloud Audit Log immutability |

### 2.2 Reconstruction Capability

For any historical governance decision, MAS auditors can reconstruct:
1. The exact request context (hashed, not PII)
2. Which governance controls were applied and their outcomes
3. Whether human review was triggered and the operator's decision
4. The customer-facing recommendation delivered
5. The KMS governance signature chain

**Gap:** OTel span metadata does not include the full request payload (intentional — GDPR compliance). Reconstruction is based on the SHA-256 hash chain linking spans.

### 2.3 Retention

See `docs/AUDIT_LOG_RETENTION_SCHEDULE.md` — APAC_MAS retention periods:
- OTel spans: 5 years
- WORM UCA records: 7 years
- Lula results: 3 years

### 2.4 Recovery Time Objective (RTO)

**Target RTO for governance enforcement path:** < 4 hours (MAS Notice 655 §12 RTO requirement for critical systems)

**Current RTO:** To be measured in DORA/MAS resilience testing. Based on GKE StatefulSet recovery characteristics:
- Redis failure → recovery: < 5 minutes (StatefulSet restart)
- Gateway pod failure → recovery: < 2 minutes (Deployment rolling update)
- Full cluster recovery: < 30 minutes (estimated — formal measurement pending)

---

## 3. Auditor Briefing Pack

The following materials should be provided to the MAS-accredited auditor:

### Technical Documentation

| Document | Location | Description |
|---|---|---|
| System architecture | `docs/AGENT_OPS_ARCHITECTURE.md` | Full system component diagram |
| Governance overview | `docs/GOVERNANCE_OVERVIEW.md` | AI governance enforcement stack |
| Audit log schema | `docs/AUDIT_LOG_SCHEMA.md` | OTel span schema and WORM UCA record format |
| Retention schedule | `docs/AUDIT_LOG_RETENTION_SCHEDULE.md` | Retention periods per log category |
| HITL scope | `docs/HUMAN_OVERSIGHT_SCOPE.md` | Human oversight gate and SLAs |
| Model card | `docs/MODEL_CARD_REVIEW.md` | Model provenance and integrity |
| MAS FEAT T1 report | `docs/MAS_FEAT_T1_TRANSPARENCY_REPORT.md` | Explainability and decision process |

### Compliance Evidence

| Evidence | Location | Access Method |
|---|---|---|
| Lula validation results | `gs://$CAGE_AUDIT_BUCKET_APAC_MAS/lula-results/` | GCS read access (auditor SA) |
| WORM UCA records (sample) | `gs://$CAGE_AUDIT_BUCKET_APAC_MAS/uca-records/` | GCS read access (auditor SA) |
| Langfuse APAC_MAS traces (sample) | Langfuse APAC_MAS project | Langfuse viewer role (auditor) |
| GCP Audit Logs | GCP Console — Audit Logs | IAM `roles/logging.viewer` (auditor) |

### Test Evidence

| Test | Status | Evidence Location |
|---|---|---|
| Redis fail-closed verification | Planned Q3 2026 | `gs://$CAGE_AUDIT_BUCKET_APAC_MAS/dora-resilience/` |
| HITL SLA resilience test | Planned Q3 2026 | Same as above |
| Lula compliance scan | Ongoing (CronJob) | `gs://$CAGE_AUDIT_BUCKET_APAC_MAS/lula-results/` |

---

## 4. Certification Procedure

### Step 1: Pre-Audit Preparation (4 weeks before audit)

- [ ] Provision auditor GCP service account with `roles/logging.viewer` and GCS read access
- [ ] Provision auditor Langfuse viewer role on APAC_MAS project
- [ ] Run Lula validation scan: `lula validate -f compliance/lula/ --region APAC_MAS`
- [ ] Verify retention schedule is implemented: check GCS lifecycle rules
- [ ] Prepare auditor briefing pack (documents listed in §3)
- [ ] Confirm HITL SLA metrics for previous quarter (target: 100% within 1 hour)

### Step 2: Audit Execution (by MAS-accredited auditor)

The auditor will:
1. Review technical documentation and architecture
2. Inspect GCS audit buckets (sample of WORM UCA records)
3. Inspect Langfuse APAC_MAS project (sample of OTel traces)
4. Verify reconstruction capability for selected historical decisions
5. Verify RTO measurement methodology
6. Test audit trail integrity (hash chain verification)

### Step 3: Certification Report

- Auditor produces MAS Notice 655 §12 certification report
- Report is archived to `gs://$CAGE_AUDIT_BUCKET_APAC_MAS/certifications/`
- Report is submitted to MAS if required under Notice 655 reporting obligations

### Step 4: Post-Certification Actions

- Update POAM-MAS-002 status to **Closed**
- Brief MAS supervisor contact on certification outcome
- Schedule next certification (annual)

---

## 5. Certification Schedule

| Certification | Target Date | Status |
|---|---|---|
| Initial MAS Notice 655 §12 certification | 2026-09-30 | Planned |
| Annual re-certification (Year 2) | 2027-09-30 | Scheduled |

---

## Related Documents

- `docs/AUDIT_LOG_SCHEMA.md` — Audit record schema
- `docs/AUDIT_LOG_RETENTION_SCHEDULE.md` — Retention periods
- `docs/MAS_FEAT_T1_TRANSPARENCY_REPORT.md` — MAS FEAT T1 transparency
- `docs/AI_FAIRNESS_ASSESSMENT.md` — MAS FEAT F2 fairness metrics
- `docs/POAM_APAC_MAS.md` — MAS-002 POAM item
