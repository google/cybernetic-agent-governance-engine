---
poam_file: POAM_EU_ECB
region_scope: EU_ECB
primary_framework: "EU AI Act (Reg. 2024/1689) / DORA (Reg. 2022/2554) / GDPR (Reg. 2016/679)"
global_baseline: ISO 42001
version: "1.0"
date: 2026-06-24
see_also:
  - docs/POAM_ISO42001.md   # universal ISO 42001 AIMS weaknesses (all regions)
  - docs/POAM_US_FED.md     # NIST SP 800-53 / ATO track (US_FED only)
  - docs/POAM_APAC_MAS.md   # MAS FEAT / Notice 655 / TRM weaknesses (APAC_MAS only)
  - docs/POAM_INDEX.md      # cross-region traceability matrix
---

# Plan of Action and Milestones (POA&M) — EU_ECB

**System:** Cybernetic AI Governance Engine (CAGE) — Governed Financial Advisor
**Reference:** EU AI Act (Reg. 2024/1689), DORA (Reg. 2022/2554), GDPR (Reg. 2016/679), EBA/GL/2023/02
**Region Scope:** `CAGE_DEPLOYMENT_REGION=EU_ECB` only
**Global Baseline:** ISO/IEC 42001:2023 (AI Management System Standard)
**Version:** 1.0
**Date:** 2026-06-08
**Status:** ACTIVE

> **Scope:** This document tracks weaknesses specific to **EU_ECB deployments** governed by the EU AI Act, DORA, and GDPR. Entries are anchored to EU AI Act articles or DORA articles as their primary identifier. ISO 42001 Annex A controls appear as co-framework citations. NIST SP 800-53 has **no legal force** in EU jurisdiction (see `EU_ECB_BASELINE.json` `_comment`).
>
> For universal ISO 42001 AIMS weaknesses (all regions), see [`docs/POAM_ISO42001.md`](../universal/POAM_ISO42001.md).
> For US_FED-specific NIST SP 800-53 weaknesses, see [`docs/POAM_US_FED.md`](../us_fed/POAM_US_FED.md).
> For APAC_MAS-specific weaknesses, see [`docs/POAM_APAC_MAS.md`](../apac_mas/POAM_APAC_MAS.md).

---

## POA&M Summary

| Metric          | Count |
| --------------- | ----- |
| **Total Items** | 5     |
| **Critical**    | 1     |
| **High**        | 2     |
| **Moderate**    | 2     |
| **Low**         | 0     |
| **Open**        | 0     |
| **In Progress** | 5     |
| **Closed**      | 0     |

---

## POA&M Items

| POA&M ID | Primary Framework | ISO 42001 Co-ref | Regions | Weakness Description | Detection Method | Risk Level | Scheduled Completion | Resources Required | Status | Milestone |
| -------- | ----------------- | ---------------- | ------- | -------------------- | ---------------- | ---------- | -------------------- | ------------------ | ------ | --------- |
| EU-001 | EU AI Act Art. 29a — Fundamental Rights Impact Assessment | §A.6.1 | EU_ECB | FRIA gating in stub mode — TrustLayers credentials not provisioned. `normative_provider.py` implements the full `enforce_fria_boundary()` adaptive gating primitive required by EU AI Act Art. 29a, but `CAGE_NORMATIVE_PROVIDER=static` (default) means no external FRIA validation is performed. All FRIA checks are stub-admitted. Under Art. 29a, deployers of High-Risk AI systems must perform a documented FRIA before deployment. The stub mode means CAGE cannot demonstrate independent FRIA validation to the EU AI Office or ECB supervisors. **NIST SA-9/CA-7 aspect tracked separately:** [`docs/POAM_US_FED.md#POAM-022`](../us_fed/POAM_US_FED.md). | Code review — `src/gateway/governance/normative_provider.py` | **Critical** | 2026-08-31 | 4 hrs | **In Progress** | ~~Coordinate with TrustLayers team for API key provisioning~~ **🔄 In Progress** — `docs/FRIA_ATTESTATION.md` created (2026-06-24); `compliance/lula/lula-validation-eu-fria.yaml` created asserting `CAGE_NORMATIVE_PROVIDER!=static` in EU_ECB; TrustLayers provisioning runbook documented; pending credential provisioning and DPO sign-off. |
| EU-002 | DORA Art. 12 — Digital Operational Resilience Testing | §A.8.4 | EU_ECB | No DORA resilience testing performed. DORA Art. 12 requires financial entities to establish, maintain, and review a digital operational resilience testing programme. No DORA-compliant resilience testing has been performed for CAGE in the EU_ECB deployment profile. The WAL LIFO rollback mechanism satisfies DORA Art. 12 at the architectural level, but no formal testing programme with documented results exists. | Gap analysis — DORA Art. 12 | **High** | 2026-09-30 | 40 hrs | **In Progress** | **🔄 In Progress** — `docs/DORA_RESILIENCE_TESTING_PROGRAMME.md` created (2026-06-24): 4 test scenarios defined (WAL rollback, Redis fail-closed, governance TLPT, HITL SLA); target Q3/Q4 2026 execution. Pending: test execution and ECB supervisor notification. |
| EU-003 | EU AI Act Art. 6 + Annex III §5(b) — High-Risk AI Registration | §A.5.2 | EU_ECB | EU AI Office registration pending. Under EU AI Act Art. 6 and Annex III Point 5(b), any AI system used by a financial institution to evaluate creditworthiness or gate access to financial resources is a High-Risk AI System. CAGE's governed financial advisor pipeline meets this definition. High-Risk AI systems must be registered in the EU AI Office database before deployment. No registration has been initiated. | Gap analysis — EU AI Act Art. 6, Annex III §5(b) | **High** | 2026-09-30 | 16 hrs | **In Progress** | **🔄 In Progress** — `docs/EU_AI_OFFICE_REGISTRATION.md` created (2026-06-24): 5-step registration procedure documented, Art. 11 technical documentation checklist completed, Annex VI self-assessment path identified; pending legal designation of EU authorised representative and registration portal submission. |
| EU-004 | GDPR Art. 35 — Data Protection Impact Assessment | §A.6.2 | EU_ECB | DPIA not integrated with CAGE EU_ECB deployment. GDPR Art. 35 requires a Data Protection Impact Assessment (DPIA) for processing operations that are likely to result in a high risk to the rights and freedoms of natural persons. CAGE's automated creditworthiness evaluation pipeline meets the Art. 35(3)(a) threshold (systematic and extensive evaluation of personal aspects based on automated processing). No DPIA has been conducted or integrated with the EU_ECB deployment profile. | Gap analysis — GDPR Art. 35 | **Moderate** | 2026-09-30 | 24 hrs | **In Progress** | **🔄 In Progress** — `docs/GDPR_DPIA.md` created (2026-06-24): processing description, data flow diagram, necessity/proportionality assessment, risk assessment, and GDPR Art. 22 automated decision-making safeguards documented; pending DPO sign-off. |
| EU-005 | EU AI Act Art. 12 — Record-Keeping and Logging Obligations | §A.9.4 | EU_ECB | GDPR-compliant audit log retention schedule not documented. EU AI Act Art. 12 mandates automatic logging of High-Risk AI system operations for the entire operational lifetime. GDPR Art. 5(1)(e) requires personal data to be kept in a form that permits identification of data subjects for no longer than necessary. No documented retention schedule exists for CAGE audit logs (OTel spans, Langfuse traces, WORM UCA records) in the EU_ECB deployment profile. The absence of a retention schedule creates both an EU AI Act Art. 12 compliance gap and a GDPR Art. 5(1)(e) data minimisation risk. | Gap analysis — EU AI Act Art. 12, GDPR Art. 5(1)(e) | **Moderate** | 2026-08-31 | 8 hrs | **In Progress** | **🔄 In Progress** — `docs/AUDIT_LOG_RETENTION_SCHEDULE.md` created (2026-06-24): retention periods defined for 6 log categories across all 3 regions; GCS lifecycle rule configuration provided; pending DPO approval for EU_ECB. |

---

## POA&M Process

### Review Cadence

- **Monthly:** Review open items, update milestones, escalate slipped items
- **Quarterly:** ECB supervisor briefing on EU AI Act compliance posture; DORA resilience testing status
- **Annual:** Full EU AI Act Art. 61 post-market monitoring review

### Entry Criteria

New entries are created when:

- EU AI Act, DORA, or GDPR compliance assessments identify weaknesses specific to EU_ECB deployments
- ECB supervisor or EU AI Office feedback identifies gaps
- New EU regulatory guidance (EBA guidelines, EU AI Office decisions) creates new obligations
- Automated Lula validation identifies EU_ECB-specific compliance failures

### Closure Criteria

Items are closed when:

1. Remediation actions are fully implemented for EU_ECB deployment
2. Implementation is verified by the EU Data Protection Officer (DPO) or designated EU compliance officer
3. Supporting evidence (DPIA, FRIA attestation, DORA test results, EU AI Office registration) is archived
4. ECB supervisor is notified of closure for HIGH/CRITICAL items

---

_This document is a living record and must be updated within 5 business days of any status change. SR 26-2 has no legal force in EU jurisdiction — US Federal Reserve guidance is suppressed in EU_ECB OTel spans via the sentinel mechanism (§15.5). For the cross-region traceability matrix, see [`docs/POAM_INDEX.md`](../cross-region/POAM_INDEX.md)._
