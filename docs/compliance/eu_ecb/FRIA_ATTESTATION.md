# Fundamental Rights Impact Assessment (FRIA) — CAGE Governed Financial Advisor

**Document:** EU-001 / EU AI Act Art. 29a / ISO 42001 §A.6.1
**Date:** 2026-06-24
**Status:** Draft — pending external normative provider credential provisioning and DPO sign-off
**POAM:** EU-001 (POAM_EU_ECB.md)
**Region Scope:** `CAGE_DEPLOYMENT_REGION=EU_ECB` only

---

> [!IMPORTANT]
> This FRIA is a **draft** and has not been signed off by the Data Protection Officer (DPO) or reviewed by the EU AI Office. EU-001 remains **In Progress** until:
> 1. External normative provider credentials are provisioned and `CAGE_NORMATIVE_PROVIDER=provider_01` is active in EU_ECB prod
> 2. DPO sign-off is obtained
> 3. A completed FRIA attestation is submitted to the EU AI Office

---

## 1. Purpose and Legal Basis

Under EU AI Act Art. 29a, deployers of High-Risk AI systems must perform a Fundamental Rights Impact Assessment (FRIA) before deploying the system. CAGE's Governed Financial Advisor pipeline meets the High-Risk AI definition under Art. 6 + Annex III §5(b) (AI used in financial services to evaluate creditworthiness or gate access to financial resources).

This document records the FRIA for the EU_ECB deployment profile.

---

## 2. System Description

**System:** CAGE Governed Financial Advisor (LangGraph multi-agent pipeline)
**Purpose:** AI-assisted financial advisory and investment recommendations for retail/institutional clients in EU_ECB deployment region
**Deployer:** [Organization name — TBD]
**EU-based authorised representative:** [Name — TBD; required under Art. 22 if deployer is established outside EU]

**Processing activities with fundamental rights implications:**
- Automated analysis of client financial profiles (income, assets, debt)
- AI-generated investment and portfolio allocation recommendations
- Confidence-gated trade execution recommendations

**Is the system making autonomous decisions?** No. All recommendations with confidence < 0.95 or amounts > €10,000 are routed to Human-in-the-Loop (HITL) review before action (see `docs/HUMAN_OVERSIGHT_SCOPE.md`).

---

## 3. Affected Persons

| Group | Fundamental Rights at Risk |
|---|---|
| **Retail financial services clients** | Art. 8 (data protection), Art. 20 (equality), Art. 21 (non-discrimination) |
| **Institutional clients (ECB-supervised entities)** | Art. 16 (freedom to conduct business), Art. 17 (right to property) |
| **Employees of client organizations** | Art. 31 (fair working conditions — indirectly, via financial advisory affecting employer liquidity) |

---

## 4. Rights and Risks Analysis

### 4.1 Right to Non-Discrimination (Art. 21 CFREU)

**Risk:** The AI model may exhibit demographic bias in financial recommendations, potentially providing lower-quality advice to persons based on age, sex, national origin, or other protected characteristics.

**Mitigation measures:**
- DoWhy causal gatekeeper (CTRL_AGT_001) performs counterfactual fairness assessment on all recommendations
- AI Fairness Assessment (DPD threshold ≤ 0.05) — see `docs/AI_FAIRNESS_ASSESSMENT.md`
- MAS FEAT F2 quantitative fairness metrics computed quarterly
- HITL review required for all high-value recommendations

**Residual risk:** **Moderate** — first quarterly FIA pending (Q2 2026 baseline not yet established)

### 4.2 Right to Data Protection (Art. 8 CFREU / GDPR)

**Risk:** Client financial data processed by the LLM inference pipeline may be retained in Langfuse traces beyond the purposes for which it was collected.

**Mitigation measures:**
- Presidio PII sanitizer (`pii_sanitizer.py`) strips PII before Langfuse trace emission (score_threshold ≥ 0.5)
- Langfuse EU_ECB project scoped to EU region (Frankfurt data centre)
- Audit log retention schedule: see `docs/AUDIT_LOG_RETENTION_SCHEDULE.md`
- GDPR Art. 35 DPIA: see `docs/GDPR_DPIA.md`

**Residual risk:** **Low** — Presidio PII scrubbing and GCS lifecycle rules implemented

### 4.3 Right to an Effective Remedy (Art. 47 CFREU)

**Risk:** If the AI system makes an adverse recommendation, the affected person may not have a meaningful way to challenge it.

**Mitigation measures:**
- All governed financial advisory decisions produce a WORM UCA audit record with a human-readable explainability chain
- The `explainer` LangGraph node generates a plain-language explanation of every decision
- HITL override mechanism allows compliance officers to override any AI recommendation
- HITL override is audited via `hitl_override_audit_span()` (ISO 42001 A.8.4)

**Residual risk:** **Low** — explainability chain and HITL override available for all decisions

### 4.4 Right to Equal Treatment (Art. 20 CFREU)

**Risk:** The consensus scoring mechanism may systematically disadvantage clients from certain demographic groups.

**Mitigation measures:** See §4.1 (fairness mitigations apply here equally).

**Residual risk:** **Moderate** — same as §4.1

---

## 5. FRIA Zone Mathematical Definition

The CAGE governance kernel implements a three-zone FRIA scoring model in Tier 6b of the Symbolic Governor pipeline ([`src/gateway/governance/symbolic_governor.py`](../../../src/gateway/governance/symbolic_governor.py)). This model operationalises the EU AI Act Art. 29a requirement for proportionate human oversight of High-Risk AI decisions.

### 5.1 Zone Thresholds

| Constant | Value | Zone | Enforcement Action |
|----------|-------|------|--------------------|
| `FRIA_ZONE_ALLOW` | `0.95` | Allow zone | Async attestation — decision proceeds without blocking; FRIA record written asynchronously |
| `FRIA_ZONE_DEFER` | `0.70` | Defer zone lower bound | Synchronous blocking gate — decision is held pending HITL review |
| *(implicit)* | `< 0.70` | Block zone | Hard BLOCK — decision denied; no override path available |

### 5.2 FRIA Score Computation

The FRIA score is a composite of the confabulation risk score and the causal gatekeeper estimate, normalised to `[0, 1]`:

```
fria_score = 1.0 − risk_score
           = confidence          (when risk_score = 1.0 − confidence)
```

A higher `fria_score` indicates higher confidence and lower fundamental-rights risk. The three zones map to EU AI Act Art. 29a as follows:

| Score Range | FRIA Zone | EU AI Act Art. 29a Mapping |
|-------------|-----------|---------------------------|
| `fria_score ≥ 0.95` | ALLOW | Deployer has verified the system operates within intended purpose; async attestation sufficient |
| `0.70 ≤ fria_score < 0.95` | DEFER | Human oversight required before action; deployer must ensure meaningful human review (Art. 29a §2) |
| `fria_score < 0.70` | BLOCK | System output is inadmissible; fundamental rights risk too high for any action |

### 5.3 Relationship to Existing FRIA Controls

The mathematical thresholds complement the qualitative FRIA controls documented in §4:

- **§4.1 Non-discrimination (Art. 21):** The DEFER zone (`0.70 ≤ score < 0.95`) ensures that recommendations with moderate uncertainty are always reviewed by a human before affecting a client — directly mitigating demographic bias risk.
- **§4.3 Effective remedy (Art. 47):** The BLOCK zone (`score < 0.70`) provides an absolute safety net: no AI recommendation with high fundamental-rights risk can be autonomously executed, preserving the client's right to challenge decisions made by a human reviewer rather than an opaque algorithm.
- **§4.2 Data protection (Art. 8):** The FRIA score is computed after PII sanitization (a pre-pipeline / audit-log stage, not a numbered `_run_checks()` tier) — the score never incorporates raw PII, satisfying GDPR Art. 25 data minimisation.

### 5.4 External Normative Provider Integration

When `CAGE_NORMATIVE_PROVIDER=provider_01`, every decision with `fria_score < 0.95` (i.e., in the DEFER or BLOCK zone) is submitted to the external normative provider for independent FRIA validation before the zone decision is finalised. The external provider may upgrade a DEFER to ALLOW or downgrade an ALLOW to DEFER based on its own assessment. The Langfuse trace records `fria.path` as one of:
- `ASYNC_ATTESTED` — score ≥ 0.95, async path
- `SYNC_GATE_ADMITTED` — 0.70 ≤ score < 0.95, external provider admitted
- `SYNC_GATE_DEFERRED` — 0.70 ≤ score < 0.95, HITL required
- `BLOCKED` — score < 0.70, hard deny

---

## 6. External Normative Provider FRIA Validation (EU AI Act Art. 29a — External Validation)

The `normative_provider.py` module implements adaptive FRIA enforcement gating:
- When `CAGE_NORMATIVE_PROVIDER=provider_01` and external provider credentials are configured, every execute_trade decision with confidence < 0.95 is submitted to the external normative provider for independent FRIA validation before action
- The external provider returns an admissibility determination and a set of findings
- Non-admitted decisions are blocked (DENY) or escalated to HITL (DEFER)

**Current status:** `CAGE_NORMATIVE_PROVIDER=static` (stub mode) — external normative provider credentials not yet provisioned. All FRIA checks are stub-admitted. **EU-001 is In Progress pending credential provisioning.**

### External Normative Provider Provisioning Runbook

1. Obtain external provider API key from external provider team (contact: [TBD])
2. Store API key in GCP Secret Manager: `gcloud secrets create cage-normative-provider-api-key --data-file=-`
3. Add to EU_ECB `prod.tfvars`:
   ```hcl
   cage_normative_provider         = "provider_01"
   cage_normative_endpoint         = "https://api.example.com/normative/v1"
   cage_normative_api_key_secret   = "projects/${project_id}/secrets/cage-normative-provider-api-key/versions/latest"
   ```
4. Set in EU_ECB gateway Deployment env:
   ```yaml
   - name: CAGE_NORMATIVE_PROVIDER
     value: "provider_01"
   - name: CAGE_NORMATIVE_ENDPOINT
     value: "https://api.example.com/normative/v1"
   ```
5. Verify boot-time baseline fetch: `kubectl logs -n governance-stack deploy/cage-gateway | grep NormativeDaemon`
6. Verify adaptive gating: Submit a test trade with confidence 0.80 and confirm Langfuse trace shows `fria.path=SYNC_GATE_ADMITTED`
7. Run Lula validation: `lula validate -f compliance/lula/lula-validation-eu-fria.yaml`

---

## 7. Conclusions

| Rights Category | Risk Level | Mitigation Status |
|---|---|---|
| Non-discrimination (Art. 21) | Moderate | FIA Q2 2026 baseline pending |
| Data protection (Art. 8 / GDPR) | Low | PII scrubbing + retention schedule implemented |
| Effective remedy (Art. 47) | Low | Explainability chain + HITL override implemented |
| Equal treatment (Art. 20) | Moderate | Same as non-discrimination |

**Overall residual risk:** **Moderate** — acceptable for controlled deployment with mandatory HITL for high-value transactions. The FRIA zone thresholds (§5) provide a mathematical enforcement layer that ensures no high-risk decision (score < 0.70) can be autonomously executed.

---

## 8. Sign-Off

| Role | Name | Date | Signature |
|---|---|---|---|
| AI System Owner | TBD | TBD | TBD |
| Data Protection Officer | TBD | TBD | TBD |
| EU AI Act Compliance Lead | TBD | TBD | TBD |

---

## Related Documents

- `docs/GDPR_DPIA.md` — GDPR Art. 35 DPIA
- `docs/AI_FAIRNESS_ASSESSMENT.md` — Fairness metrics (ECOA / Reg B / MAS FEAT F2)
- `docs/HUMAN_OVERSIGHT_SCOPE.md` — HITL scope and SLAs
- `docs/AUDIT_LOG_RETENTION_SCHEDULE.md` — EU AI Act Art. 12 + GDPR Art. 5(1)(e) retention
- `compliance/lula/lula-validation-eu-fria.yaml` — Lula validation manifest
- `docs/POAM_EU_ECB.md` — EU-001 POAM item
