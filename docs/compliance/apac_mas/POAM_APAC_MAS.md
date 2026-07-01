---
poam_file: POAM_APAC_MAS
region_scope: APAC_MAS
primary_framework: "MAS FEAT Principles / MAS Notice 655 / MAS TRM Guidelines"
global_baseline: ISO 42001
version: "1.0"
date: 2026-06-24
see_also:
  - docs/POAM_ISO42001.md   # universal ISO 42001 AIMS weaknesses (all regions)
  - docs/POAM_US_FED.md     # NIST SP 800-53 / ATO track (US_FED only)
  - docs/POAM_EU_ECB.md     # EU AI Act / DORA / GDPR weaknesses (EU_ECB only)
  - docs/POAM_INDEX.md      # cross-region traceability matrix
---

# Plan of Action and Milestones (POA&M) — APAC_MAS

**System:** Cybernetic AI Governance Engine (CAGE) — Governed Financial Advisor
**Reference:** MAS FEAT Principles (Nov 2019), MAS Notice 655, MAS TRM Guidelines (Jan 2021), MAS ENRM Guidelines (Dec 2020)
**Region Scope:** `CAGE_DEPLOYMENT_REGION=APAC_MAS` only
**Global Baseline:** ISO/IEC 42001:2023 (AI Management System Standard)
**Version:** 1.0
**Date:** 2026-06-08
**Status:** ACTIVE

> **Scope:** This document tracks weaknesses specific to **APAC_MAS deployments** governed by MAS FEAT Principles, MAS Notice 655, and MAS TRM Guidelines. Entries are anchored to MAS FEAT principles or MAS Notice 655 / TRM sections as their primary identifier. ISO 42001 Annex A controls appear as co-framework citations. NIST SP 800-53 and SR 26-2 have **no legal force** in Singapore jurisdiction (see `APAC_MAS_BASELINE.json` `_comment`).
>
> For universal ISO 42001 AIMS weaknesses (all regions), see [`docs/POAM_ISO42001.md`](../universal/POAM_ISO42001.md).
> For US_FED-specific NIST SP 800-53 weaknesses, see [`docs/POAM_US_FED.md`](../us_fed/POAM_US_FED.md).
> For EU_ECB-specific weaknesses, see [`docs/POAM_EU_ECB.md`](../eu_ecb/POAM_EU_ECB.md).

---

## POA&M Summary

| Metric          | Count |
| --------------- | ----- |
| **Total Items** | 4     |
| **Critical**    | 0     |
| **High**        | 2     |
| **Moderate**    | 2     |
| **Low**         | 0     |
| **Open**        | 1     |
| **In Progress** | 3     |
| **Closed**      | 0     |

---

## POA&M Items

| POA&M ID | Primary Framework | ISO 42001 Co-ref | Regions | Weakness Description | Detection Method | Risk Level | Scheduled Completion | Resources Required | Status | Milestone |
| -------- | ----------------- | ---------------- | ------- | -------------------- | ---------------- | ---------- | -------------------- | ------------------ | ------ | --------- |
| MAS-001 | MAS FEAT — Fairness Principle F2: Quantitative Fairness Metrics | §A.5.2 | APAC_MAS | Quantitative fairness metrics not computed. MAS FEAT Principle F2 expects ongoing Fairness Impact Assessments (FIA) with quantitative bias metrics across demographic groups (demographic parity, equalized odds). The DoWhy causal gatekeeper satisfies the qualitative fairness requirement (CTRL_AGT_001 confidence threshold), but no quantitative fairness metrics have been computed or documented for the CAGE governed financial advisor pipeline in the APAC_MAS deployment profile. MAS TRM Guidelines §6.3 require documented model risk management for AI/ML systems including drift detection and performance monitoring with quantitative metrics. | Gap analysis — MAS FEAT F2, MAS TRM §6.3 | **High** | 2026-09-30 | 24 hrs | **In Progress** | **🔄 In Progress** — APAC_MAS FIA section added to `docs/AI_FAIRNESS_ASSESSMENT.md` (2026-06-24): protected characteristics defined (age, race, gender, nationality), DPD and PSOR metrics specified, MAS TRM §6.3 model risk management integration documented, quarterly FIA procedure with PDPA proxy variable methodology; first FIA run target 2026-06-30. |
| MAS-002 | MAS Notice 655 §12 — Recovery Time Objectives / Audit Certification | §A.9.4 | APAC_MAS | MAS Notice 655 audit certification not obtained. MAS Notice 655 §12 specifies Recovery Time Objectives (RTOs) for critical systems and requires financial institutions to certify compliance with audit logging requirements. The CAGE OTel + Langfuse audit trail satisfies the technical logging requirement, but no formal MAS Notice 655 audit certification has been obtained for the APAC_MAS deployment profile. MAS FEAT Accountability Principle A2 requires audit trails that enable reconstruction of all AI system decisions — the KMS-signed WORM UCA records satisfy this technically, but formal certification is pending. | Gap analysis — MAS Notice 655 §12, MAS FEAT A2 | **High** | 2026-09-30 | 16 hrs | **In Progress** | **🔄 In Progress** — `docs/MAS_NOTICE_655_CERTIFICATION.md` created (2026-06-24): 4-step certification procedure documented, auditor briefing pack defined, RTO measurement methodology specified; pending engagement of MAS-accredited auditor (target: Q3 2026). |
| MAS-003 | MAS TRM Guidelines §6.3 — AI and Machine Learning Controls | §A.6.2 | APAC_MAS | MAS ENRM validation not performed. MAS Guidelines on Environmental Risk Management (ENRM) for Banks (Dec 2020) require financial institutions to assess and manage environmental risks in their operations and lending activities. CAGE's governed financial advisor pipeline makes credit-adjacent decisions that may have environmental risk implications. No MAS ENRM validation has been performed for the APAC_MAS deployment profile. MAS TRM Guidelines §6.3 require a documented AI/ML governance framework covering model development, validation, deployment, and monitoring — the ENRM dimension of this framework is absent. | Gap analysis — MAS ENRM Guidelines, MAS TRM §6.3 | **Moderate** | 2026-10-31 | 8 hrs | Open | Assess CAGE APAC_MAS deployment against MAS ENRM Guidelines: (1) determine whether CAGE's financial advisory decisions fall within ENRM scope; (2) if in scope, document environmental risk assessment methodology; (3) integrate ENRM findings into MAS TRM §6.3 AI governance framework documentation. |
| MAS-004 | MAS FEAT — Transparency Principle T1: Decision Explainability | §A.9.4 | APAC_MAS | Formal transparency report not produced. MAS FEAT Transparency Principle T1 requires that AI systems be able to explain their decisions to affected customers and regulators. The `explainer` agent node in the CAGE LangGraph pipeline satisfies the technical explainability requirement, but no formal transparency report has been produced for the APAC_MAS deployment profile. MAS Notice 655 §10 requires audit logs that enable reconstruction of all system decisions — the WORM UCA records satisfy this technically, but a human-readable transparency report for MAS supervisors and affected customers is absent. | Gap analysis — MAS FEAT T1, MAS Notice 655 §10 | **Moderate** | 2026-09-30 | 12 hrs | **In Progress** | **🔄 In Progress** — `docs/MAS_FEAT_T1_TRANSPARENCY_REPORT.md` created (2026-06-24): decision-making pipeline documented, customer explainability (at-time-of-recommendation) described, WORM UCA regulatory reconstruction procedure defined, model transparency and PDPA/FEAT F2 fairness disclosure included; pending MAS supervisor acknowledgement. |

---

## POA&M Process

### Review Cadence

- **Monthly:** Review open items, update milestones, escalate slipped items
- **Quarterly:** MAS supervisor briefing on FEAT compliance posture; FIA results review
- **Annual:** Full MAS TRM §6.3 AI governance framework review

### Entry Criteria

New entries are created when:

- MAS FEAT, Notice 655, or TRM compliance assessments identify weaknesses specific to APAC_MAS deployments
- MAS supervisor feedback identifies gaps
- New MAS guidelines or circulars create new obligations
- Automated Lula validation identifies APAC_MAS-specific compliance failures

### Closure Criteria

Items are closed when:

1. Remediation actions are fully implemented for APAC_MAS deployment
2. Implementation is verified by the designated MAS compliance officer
3. Supporting evidence (FIA report, MAS Notice 655 certification, ENRM assessment, transparency report) is archived
4. MAS supervisor is notified of closure for HIGH items

---

_This document is a living record and must be updated within 5 business days of any status change. SR 26-2 has no legal force in Singapore jurisdiction — US Federal Reserve guidance is suppressed in APAC_MAS OTel spans via the sentinel mechanism (§15.5). For the cross-region traceability matrix, see [`docs/POAM_INDEX.md`](../cross-region/POAM_INDEX.md)._
