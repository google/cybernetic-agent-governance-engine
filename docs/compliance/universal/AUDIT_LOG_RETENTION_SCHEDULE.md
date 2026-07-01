# Audit Log Retention Schedule — CAGE Governed Financial Advisor

**Document:** EU-005 / EU AI Act Art. 12 / GDPR Art. 5(1)(e) / ISO 42001 §A.9.4
**Date:** 2026-06-24
**Status:** Draft — pending DPO approval for EU_ECB; in effect for US_FED and APAC_MAS
**POAM:** EU-005 (POAM_EU_ECB.md)
**Region Scope:** ALL regions (EU_ECB, US_FED, APAC_MAS) — different retention periods apply per region

---

> [!IMPORTANT]
> EU_ECB retention periods are governed by **EU AI Act Art. 12** (operational lifetime) and **GDPR Art. 5(1)(e)** (storage limitation). Retention must be the minimum necessary for the stated purpose. This schedule requires **DPO sign-off** for EU_ECB deployment before it takes effect.

---

## 1. Purpose

This document defines the mandatory retention periods and deletion policies for all CAGE audit log categories. It satisfies:

- **EU AI Act Art. 12** — mandatory logging for High-Risk AI system operational lifetime
- **GDPR Art. 5(1)(e)** — personal data kept no longer than necessary for stated purpose
- **MiFID II Art. 25** — 5-year trade record retention for investment firms
- **NIST SP 800-53 AU-11** — audit record retention (US_FED only)
- **MAS Notice 655 §12** — MAS audit log retention requirements (APAC_MAS only)
- **ISO 42001 §A.9.4** — AI management system audit record management

---

## 2. Audit Log Categories and Retention Periods

### 2.1 OTel Spans (Langfuse Traces)

| Field | Details |
|---|---|
| **Description** | Per-request governance decision traces: NeMo, OPA, CausalGatekeeper, HITL, FRIA attestation spans |
| **Storage** | Langfuse project (region-specific): `cage-compliance` (US_FED), `cage-eu-ecb` (EU_ECB, Frankfurt), `cage-apac-mas` (APAC_MAS) |
| **Contains PII?** | No — Presidio PII scrubbing applied before emission (`score_threshold ≥ 0.5`) |
| **Retention — US_FED** | 3 years (NIST AU-11 HIGH baseline: 3 years) |
| **Retention — EU_ECB** | Until end of system operational lifetime + 10 years (EU AI Act Art. 12); minimum 5 years for MiFID II financial records |
| **Retention — APAC_MAS** | 5 years (MAS Notice 655 §12 minimum; MAS FEAT A2 reconstruction requirement) |
| **Deletion method** | Langfuse project data retention policy; GCS bucket lifecycle rule (if archived) |
| **DPO approval required?** | Yes (EU_ECB only) |

### 2.2 WORM UCA Records (GCS OSCAL Artifacts)

| Field | Details |
|---|---|
| **Description** | KMS-signed WORM audit records of all governance decisions. Hash-chained for tamper evidence. |
| **Storage** | GCS bucket: `gs://$CAGE_AUDIT_BUCKET/uca-records/` (Write-Once via bucket lock) |
| **Contains PII?** | No — UCA records contain governance decision metadata, not client personal data |
| **Retention — US_FED** | 7 years (NIST AU-11 HIGH + FedRAMP; system accountability) |
| **Retention — EU_ECB** | System operational lifetime + 10 years (EU AI Act Art. 12) — minimum 7 years |
| **Retention — APAC_MAS** | 7 years (MAS FEAT A2 requires reconstruction capability; 7yr conservative retention) |
| **Deletion method** | GCS bucket retention lock — cannot be deleted earlier than retention period |
| **DPO approval required?** | No (no PII content) |

### 2.3 OSCAL Component Assessment Results (Lula Outputs)

| Field | Details |
|---|---|
| **Description** | Automated compliance assessment results from Lula validation runs |
| **Storage** | GCS bucket: `gs://$CAGE_AUDIT_BUCKET/lula-results/` |
| **Contains PII?** | No |
| **Retention — ALL regions** | 3 years (ISO 42001 §A.9.4 AIMS audit record requirement) |
| **Deletion method** | GCS bucket lifecycle rule: delete objects older than 1095 days |
| **DPO approval required?** | No |

### 2.4 HITL Escalation Records

| Field | Details |
|---|---|
| **Description** | Human-in-the-loop escalation events: escalation reason, operator decision, override rationale. Stored in Langfuse as `hitl_override_audit` spans. |
| **Storage** | Langfuse compliance project (region-specific, same as OTel spans above) |
| **Contains PII?** | Operator name may be present. PII fields: operator_id. |
| **Retention — US_FED** | 3 years (AU-11) |
| **Retention — EU_ECB** | 5 years (MiFID II Art. 25; GDPR Art. 5(1)(e) minimisation applies to operator PII) |
| **Retention — APAC_MAS** | 5 years (MAS Notice 655 §12) |
| **Deletion method** | Langfuse retention policy; operator_id pseudonymised after 1 year |
| **DPO approval required?** | Yes (EU_ECB — operator PII content) |

### 2.5 DORA Resilience Test Results (EU_ECB only)

| Field | Details |
|---|---|
| **Description** | Results of DORA Art. 12 resilience testing (WAL rollback tests, Redis failure injection, TLPT reports) |
| **Storage** | GCS bucket: `gs://$CAGE_AUDIT_BUCKET/dora-resilience/` |
| **Contains PII?** | No |
| **Retention — EU_ECB** | 5 years (DORA Art. 12 requires maintenance of testing programme documentation) |
| **Deletion method** | GCS bucket lifecycle rule: delete objects older than 1825 days |
| **DPO approval required?** | No |

### 2.6 Model Weight Provenance Records

| Field | Details |
|---|---|
| **Description** | SHA-256 hash records from `mirror_models.py` — records of which model weight files were loaded at what time (supply chain integrity) |
| **Storage** | GCS bucket: `gs://$CAGE_AUDIT_BUCKET/model-provenance/` |
| **Contains PII?** | No |
| **Retention — ALL regions** | System operational lifetime + 3 years (AI600-007 supply chain integrity) |
| **Deletion method** | GCS bucket lifecycle rule |
| **DPO approval required?** | No |

---

## 3. GCS Lifecycle Rule Configuration

Add the following lifecycle rules to the CAGE audit GCS bucket (`gs://$CAGE_AUDIT_BUCKET`):

```json
{
  "lifecycle": {
    "rule": [
      {
        "action": {"type": "Delete"},
        "condition": {
          "matchesPrefix": ["lula-results/"],
          "age": 1095
        }
      },
      {
        "action": {"type": "Delete"},
        "condition": {
          "matchesPrefix": ["dora-resilience/"],
          "age": 1825
        }
      },
      {
        "action": {"type": "SetStorageClass", "storageClass": "NEARLINE"},
        "condition": {
          "matchesPrefix": ["uca-records/"],
          "age": 365
        }
      },
      {
        "action": {"type": "SetStorageClass", "storageClass": "COLDLINE"},
        "condition": {
          "matchesPrefix": ["uca-records/"],
          "age": 730
        }
      }
    ]
  }
}
```

> [!NOTE]
> WORM UCA records (`uca-records/`) are NOT deleted by lifecycle rules — they are protected by the GCS bucket retention lock. Lifecycle rules only transition them to cheaper storage classes.

---

## 4. Retention Summary Table

| Log Category | US_FED | EU_ECB | APAC_MAS | PII? | DPO Sign-off |
|---|---|---|---|---|---|
| OTel spans (Langfuse) | 3 years | System lifetime + 10yr (min 5yr) | 5 years | No | EU_ECB only |
| WORM UCA records | 7 years | System lifetime + 10yr (min 7yr) | 7 years | No | No |
| Lula assessment results | 3 years | 3 years | 3 years | No | No |
| HITL escalation records | 3 years | 5 years | 5 years | Yes (operator_id) | EU_ECB: Yes |
| DORA resilience test results | N/A | 5 years | N/A | No | No |
| Model provenance records | Operational + 3yr | Operational + 3yr | Operational + 3yr | No | No |

---

## 5. DPO Approval

| Role | Name | Date | Signature |
|---|---|---|---|
| Data Protection Officer | TBD | TBD | TBD |
| AIMS Manager | TBD | TBD | TBD |

---

## Related Documents

- `docs/GDPR_DPIA.md` — GDPR Art. 35 DPIA
- `docs/FRIA_ATTESTATION.md` — EU AI Act Art. 29a FRIA
- `docs/DORA_RESILIENCE_TESTING_PROGRAMME.md` — DORA Art. 12 resilience testing
- `docs/POAM_EU_ECB.md` — EU-005 POAM item
