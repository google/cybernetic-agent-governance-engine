# Fundamental Rights Impact Assessment (FRIA) — CAGE Governed Financial Advisor

**Document:** EU-001 / EU AI Act Art. 27 / ISO 42001 §A.6.1
**Date:** 2026-06-24
**Status:** Draft — pending external normative provider credential provisioning and DPO sign-off
**POAM:** EU-001 (POAM_EU_ECB.md)
**Region Scope:** `CAGE_DEPLOYMENT_REGION=EU_ECB` only

---

> **Legal Status:** This FRIA represents an architectural reference (AssuranceStatus: ILLUSTRATIVE_REFERENCE). See [../ASSURANCE_STATUS_GUIDE.md](../ASSURANCE_STATUS_GUIDE.md) for the canonical 4-stage lifecycle and legal boundaries. CAGE demonstrates EU AI Act FRIA technical implementation patterns for adopters to customize; no institutional FRIA sign-off, DPO approval, or EU AI Office submission is complete or claimed.

> [!IMPORTANT]
> This FRIA is a **draft** and has not been signed off by the Data Protection Officer (DPO) or reviewed by the EU AI Office. EU-001 remains **In Progress** until:
> 1. External normative provider credentials are provisioned and `CAGE_NORMATIVE_PROVIDER=provider_01` is active in EU_ECB prod
> 2. DPO sign-off is obtained
> 3. A completed FRIA attestation is submitted to the EU AI Office

---

## 1. Purpose and Legal Basis

Under EU AI Act Art. 27, deployers of High-Risk AI systems must perform a Fundamental Rights Impact Assessment (FRIA) before deploying the system. CAGE's Governed Financial Advisor pipeline meets the High-Risk AI definition under Art. 6 + Annex III §5(b) (AI used in financial services to evaluate creditworthiness or gate access to financial resources).

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

**Is the system making autonomous decisions?** No. All recommendations with confidence < 0.95 or amounts > €10,000 are routed to Human-in-the-Loop (HITL) review before action (see `docs/governance/HUMAN_OVERSIGHT_SCOPE.md`).

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
- AI Fairness Assessment (DPD threshold ≤ 0.05) — see `compliance/universal/AI_FAIRNESS_ASSESSMENT.md`
- MAS FEAT F2 quantitative fairness metrics computed quarterly
- HITL review required for all high-value recommendations

**Residual risk:** **Moderate** — first quarterly FIA pending (Q2 2026 baseline not yet established)

### 4.2 Right to Data Protection (Art. 8 CFREU / GDPR)

**Risk:** Client financial data processed by the LLM inference pipeline may be retained in Langfuse traces beyond the purposes for which it was collected.

**Mitigation measures:**
- Presidio PII sanitizer (`pii_sanitizer.py`) strips PII before Langfuse trace emission (score_threshold ≥ 0.5)
- Langfuse EU_ECB project scoped to EU region (Frankfurt data centre)
- Audit log retention schedule: see `compliance/universal/AUDIT_LOG_RETENTION_SCHEDULE.md`
- GDPR Art. 35 DPIA: see `compliance/eu_ecb/GDPR_DPIA.md`

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

## 5. Runtime Enforcement — the `fria` Jurisdiction Tier (EU_ECB only)

`CTRL_FRIA_006` is enforced by the `fria` tier, [`FriaTier`](../../../src/gateway/governance/jurisdiction/eu_ai_act/fria_tier.py). It is contributed by the EU jurisdiction entry in [`jurisdiction/registry.py`](../../../src/gateway/governance/jurisdiction/registry.py) and is assembled into the Symbolic Governor pipeline **only** when the loaded regional profile is `EU_ECB` (`CAGE_DEPLOYMENT_REGION=EU_ECB`). `US_FED` and `APAC_MAS` contribute no jurisdiction tier, so no `fria` stage exists there.

The tier is phase 1 (read-only) and runs right after `causal` in every committing and DRY_RUN profile. It never runs after a human approval (POST_HITL), so it cannot hold barrier headroom. It claims every action by default. An adopter narrows it to the Annex III high-risk actions through the `claims` classifier of [`contribution()`](../../../src/gateway/governance/jurisdiction/eu_ai_act/__init__.py), never through model confidence.

### 5.1 Decision table

`FriaTier.evaluate()` runs these checks in order:

| Step | Condition | Violation | Verdict |
|---|---|---|---|
| 1. Currency (Art. 27(2)) | No FRIA artefact for the action or system-wide (`"*"`); `assessed_at` missing, not ISO-8601, without a timezone, future-dated, or older than `fria.fria_reassessment_interval_days` (365, [`config/thresholds/EU_ECB_BASELINE.json`](../../../config/thresholds/EU_ECB_BASELINE.json)) | HARD `FRIA_ASSESSMENT_STALE` | DENY. The provider is not called. |
| 2. Provider | `validate_fria()` times out (`CAGE_NORMATIVE_GATE_TIMEOUT_SECONDS`, default 5 s), raises, or returns `error` | HARD `FRIA_PROVIDER_UNAVAILABLE` | DENY |
| 3. Admitted | Provider admits | — | Pass |
| 4. Escalated | Provider refuses with a `needs_human_review: true` finding | HITL `FRIA_EXTERNAL_HOLD` | REQUIRE_APPROVAL. A `HITL_REQUIRED` DeferToken is parked. |
| 5. Refused | Any other refusal | HARD `FRIA_REJECTED` | DENY |

Every violation message is prefixed `[CTRL_FRIA_006]`, so the refusal receipt resolves this control's citation. Model confidence plays no part: a confident model is not an impact assessment. The universal confidence band (`confidence.agent_threshold` 0.95 / `confidence.defer_floor` 0.70) is a separate, jurisdiction-neutral tier (`ConfidenceStage`) that runs in every region.

### 5.2 FRIA artefact schema

The deployer's assessments are read from the loaded regional baseline (`ControlRegistry`), under `CTRL_FRIA_006.assessments`. The `NormativeProviderDaemon` boot fetch (`fetch_baseline()`) writes this baseline, so the request path never touches the network:

```json
"CTRL_FRIA_006": {
  "assessments": {
    "execute_trade": {"assessed_at": "2026-09-15T00:00:00+00:00"},
    "*":             {"assessed_at": "2026-06-01T00:00:00+00:00"}
  }
}
```

The committed reference baseline ([`config/compliance/EU_ECB_BASELINE.json`](../../../config/compliance/EU_ECB_BASELINE.json)) deliberately carries **no** assessment. CAGE does not fabricate a deployer's FRIA. A reference EU_ECB run therefore denies every claimed action with `FRIA_ASSESSMENT_STALE` until the deployer's assessment is loaded.

### 5.3 Startup posture

`assert_production_posture()` ([`governor/posture.py`](../../../src/gateway/governance/governor/posture.py)) runs the `jurisdiction_requirements` check. An enforcing EU_ECB posture **refuses to start** when the resolved `NormativeProvider` is the stub, because the stub admits every assessment. Development, test and CI postures log the failure at CRITICAL and continue.

### 5.4 Relationship to the qualitative controls in §4

- **§4.1 Non-discrimination (Art. 21):** a provider escalation (`needs_human_review`) is always decided by a human before it affects a client.
- **§4.3 Effective remedy (Art. 47):** every refusal (HARD) produces a refusal receipt in the tamper-evident evidence chain, which preserves the client's ability to challenge the decision.
- **§4.2 Data protection (Art. 8):** the provider receives the action, its parameters, the thread id, the region and the control id. PII sanitisation of parameters is the integrating deployment's responsibility before they reach the governor.

---

## 6. External Normative Provider FRIA Validation (EU AI Act Art. 27 — External Validation)

The `fria` tier calls the deployment's `NormativeProvider` (`CAGE_NORMATIVE_PROVIDER`; see [`normative_provider.py`](../../../src/gateway/governance/normative_provider.py)) for every claimed action whose artefact is current:
- The external provider returns an admissibility determination and a set of findings.
- Non-admitted decisions are denied, or escalated to a human when a finding sets `needs_human_review`.
- Async FRIA attestation via `submit_evidence()` is **not** currently wired into the evidence-seal path. It is tracked as a follow-up.

**Current status:** the reference configuration resolves `CAGE_NORMATIVE_PROVIDER=static` (the stub). External provider credentials are not yet provisioned. An enforcing EU_ECB posture refuses to start on the stub (§5.3). Development postures run it, and without a loaded FRIA artefact every claimed action is denied as stale (§5.2). **EU-001 is In Progress pending credential provisioning.**

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
6. Load the deployer's FRIA artefact into `CTRL_FRIA_006.assessments` (§5.2). Submit a test trade, then confirm that the governor runs the `fria` stage and that the provider's decision appears in the verdict: no `FRIA_*` violation when admitted, `FRIA_EXTERNAL_HOLD` when escalated.
7. Run Lula validation: `lula validate -f compliance/lula/lula-validation-eu-fria.yaml`

---

## 7. Conclusions

| Rights Category | Risk Level | Mitigation Status |
|---|---|---|
| Non-discrimination (Art. 21) | Moderate | FIA Q2 2026 baseline pending |
| Data protection (Art. 8 / GDPR) | Low | PII scrubbing + retention schedule implemented |
| Effective remedy (Art. 47) | Low | Explainability chain + HITL override implemented |
| Equal treatment (Art. 20) | Moderate | Same as non-discrimination |

**Overall residual risk:** **Moderate** — acceptable for controlled deployment with mandatory HITL for high-value transactions. The `fria` tier (§5) fails closed: in an EU_ECB deployment no claimed action executes without a current FRIA artefact and an admitting (or human-approved) normative-provider assessment.

---

## 8. Sign-Off

| Role | Name | Date | Signature |
|---|---|---|---|
| AI System Owner | TBD | TBD | TBD |
| Data Protection Officer | TBD | TBD | TBD |
| EU AI Act Compliance Lead | TBD | TBD | TBD |

---

## Related Documents

- `compliance/eu_ecb/GDPR_DPIA.md` — GDPR Art. 35 DPIA
- `compliance/universal/AI_FAIRNESS_ASSESSMENT.md` — Fairness metrics (ECOA / Reg B / MAS FEAT F2)
- `docs/governance/HUMAN_OVERSIGHT_SCOPE.md` — HITL scope and SLAs
- `compliance/universal/AUDIT_LOG_RETENTION_SCHEDULE.md` — EU AI Act Art. 12 + GDPR Art. 5(1)(e) retention
- `compliance/lula/lula-validation-eu-fria.yaml` — Lula validation manifest
- `compliance/eu_ecb/POAM_EU_ECB.md` — EU-001 POAM item
