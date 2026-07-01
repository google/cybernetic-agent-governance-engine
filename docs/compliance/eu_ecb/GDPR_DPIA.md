# GDPR Art. 35 — Data Protection Impact Assessment (DPIA)

**Document:** EU-004 / GDPR (Reg. 2016/679) Art. 35 / ISO 42001 §A.6.2
**Date:** 2026-06-24
**Status:** Draft — pending DPO sign-off
**POAM:** EU-004 (POAM_EU_ECB.md)
**Region Scope:** `CAGE_DEPLOYMENT_REGION=EU_ECB` only

---

> [!IMPORTANT]
> This DPIA has not been signed off by the Data Protection Officer. EU-004 remains **In Progress** until DPO review and sign-off is obtained.

---

## 1. Introduction

GDPR Art. 35(1) requires a Data Protection Impact Assessment (DPIA) for processing operations that are "likely to result in a high risk to the rights and freedoms of natural persons." GDPR Art. 35(3)(a) specifies that a DPIA is mandatory for "systematic and extensive evaluation of personal aspects relating to natural persons which is based on automated processing, including profiling, and on which decisions are based that produce legal effects concerning the natural person or similarly significantly affect the natural person."

CAGE's Governed Financial Advisor pipeline meets this threshold: it performs automated analysis of personal financial data to generate financial recommendations that may significantly affect a natural person's financial position.

---

## 2. Processing Activity Description

### 2.1 Controller and Processor Information

| Role | Entity | Contact |
|---|---|---|
| Data Controller | [Organization — TBD] | [DPO contact — TBD] |
| Data Processor (AI inference) | [Google LLC / Cloud provider — TBD] | [TBD] |
| Data Protection Officer | [Name — TBD] | [TBD] |

### 2.2 Purpose of Processing

| Purpose | Legal Basis (GDPR Art. 6) | Special Category? |
|---|---|---|
| AI-assisted financial advisory recommendations | Art. 6(1)(b) — necessary for contract performance | No |
| Audit trail and compliance evidence | Art. 6(1)(c) — legal obligation (EU AI Act Art. 12, MiFID II) | No |
| Fraud detection and governance enforcement | Art. 6(1)(f) — legitimate interests | No |

### 2.3 Personal Data Categories Processed

| Data Category | Sensitivity | Source | Processed By |
|---|---|---|---|
| Client financial profile (income, assets, portfolio) | High | Client-submitted | LangGraph supervisor, governed financial advisor |
| Transaction history | High | Banking ledger | DoWhy causal gatekeeper (read-only) |
| Investment preferences and risk tolerance | Medium | Client-submitted | NeMo Guardrails, OPA policy engine |
| Client identity (name, account ID) | High | Banking system | Presidio PII sanitizer (strips before Langfuse) |
| Behavioral patterns (request frequency, amounts) | Medium | Derived | Token Quota Proxy, Redis counter |

### 2.4 Data Flow Diagram

```
Client Request
    │
    ▼
[Gateway — NeMo + OPA + CausalGatekeeper]
    │  PII stripped by Presidio before this point
    │
    ▼
[LangGraph — Supervised Financial Advisor]
    │  Client data processed in-memory only
    │
    ▼
[vLLM Inference — Gemma 3 / DeepSeek-R1]
    │  No client PII in inference request (stripped upstream)
    │
    ▼
[Compliance Bridge → Langfuse EU_ECB project (Frankfurt)]
    │  OTel spans: PII-free audit records only
    │
    ▼
[GCS — EU_ECB region — OSCAL artifacts]
    │  Encrypted at rest (CMEK: EU_ECB KMS key)
    │
    ▼
Human-in-the-Loop (if required)
```

---

## 3. Necessity and Proportionality Assessment

### 3.1 Necessity

The processing is **necessary** for the stated purposes:
- Financial advisory recommendations require access to client financial profile to be meaningful
- Audit trails require sufficient data to reconstruct decisions (EU AI Act Art. 12, MiFID II)
- Fraud detection requires behavioral pattern analysis

### 3.2 Proportionality

Measures taken to limit data processing to what is necessary:
- **Data minimisation (GDPR Art. 5(1)(c)):** Presidio PII sanitizer (`score_threshold ≥ 0.5`) strips client identity before Langfuse trace emission. Only financial parameters required for governance decision reach the OTel audit trail.
- **Purpose limitation (GDPR Art. 5(1)(b)):** Client financial data is processed only for advisory recommendation purposes. The Langfuse compliance project (db=1) is segregated from the application project (db=0).
- **Storage limitation (GDPR Art. 5(1)(e)):** See `docs/AUDIT_LOG_RETENTION_SCHEDULE.md` for retention periods.

---

## 4. Risk Assessment

| Risk | Likelihood | Severity | Mitigation |
|---|---|---|---|
| AI recommendation causes significant adverse financial decision for client | Medium | High | HITL review for amounts > €10,000; explainer chain; right to explanation |
| Client PII inadvertently retained in Langfuse traces | Low | High | Presidio PII scrubbing (score_threshold ≥ 0.5); regular trace audit |
| Unauthorized access to client financial data in GCS | Low | High | CMEK encryption; IAM least-privilege (`cage-compliance-bridge-sa`) |
| Cross-border data transfer outside EU (Langfuse traces) | Low | High | Langfuse EU_ECB project scoped to Frankfurt (eu-west data centre) |
| Data subject cannot exercise GDPR Art. 22 rights (automated decision-making) | Low | Medium | Human oversight mandatory; HITL available for all high-value decisions |

---

## 5. GDPR Art. 22 — Automated Decision-Making Assessment

GDPR Art. 22 gives data subjects the right not to be subject to decisions based solely on automated processing where those decisions produce legal or similarly significant effects.

**CAGE position:** The Governed Financial Advisor does NOT make final autonomous decisions for high-value recommendations. All decisions with:
- Confidence < 0.95, OR
- Amount > €10,000

...are escalated to a Human-in-the-Loop operator before action. The AI system produces **recommendations**, not binding decisions. Human operators retain final authority.

**Safeguards in place (GDPR Art. 22(2)(b)):**
- Human review gate with 1-hour SLA (APAC_MAS) / 4-hour SLA (default)
- HITL override mechanism with full audit trail
- Explainability chain per request (explainer agent node)
- Right to explanation: WORM UCA records provide reconstruction of any decision

---

## 6. Residual Risk and DPO Consultation

**Residual risk level:** **Moderate**

No high-residual-risk items were identified that require prior consultation with the supervisory authority under GDPR Art. 36. The risk mitigations described in §4 are sufficient to reduce risks to an acceptable level for processing activities under Art. 6(1)(b) and (c).

**DPO consultation required?** Yes — standard DPO sign-off on DPIA before deployment.

**Supervisory authority consultation required?** No — residual risk does not meet Art. 36 threshold.

---

## 7. DPO Sign-Off

| Role | Name | Date | Signature |
|---|---|---|---|
| Data Protection Officer | TBD | TBD | TBD |
| AI System Owner | TBD | TBD | TBD |

---

## Related Documents

- `docs/FRIA_ATTESTATION.md` — EU AI Act Art. 29a FRIA
- `docs/PII_SCRUBBING_POLICY.md` — Presidio PII scrubbing configuration
- `docs/AUDIT_LOG_RETENTION_SCHEDULE.md` — GDPR Art. 5(1)(e) retention periods
- `docs/HUMAN_OVERSIGHT_SCOPE.md` — HITL gate and Art. 22 safeguards
- `docs/POAM_EU_ECB.md` — EU-004 POAM item
