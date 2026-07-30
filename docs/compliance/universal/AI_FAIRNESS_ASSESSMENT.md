# AI Fairness Assessment — CAGE v2.1.0

**Document:** AI600-004 / ECOA / Reg B / MAS FEAT F2 / ISO 42001 §A.6
**Date:** 2026-06-23
**Status:** Draft — placeholder results pending first quarterly FIA run
**POAM:** AI600-004 (POAM_US_FED.md)
**Review cadence:** Quarterly (next: Q3 2026)

---

## Purpose

This document records the AI Fairness Assessment (FIA) for the CAGE Governed Financial Advisor. It satisfies:

- **NIST AI 600-1 §2.6** — Demographic fairness assessment for AI systems used in financial services
- **ECOA (15 U.S.C. §1691)** — Equal Credit Opportunity Act prohibition on credit discrimination
- **Regulation B (12 CFR Part 202)** — ECOA implementing regulation
- **MAS FEAT Principle F2** — Fairness assessment for AI in financial services (APAC_MAS)
- **ISO 42001 §A.6** — Data lineage and fairness monitoring

---

## System Description

The CAGE Governed Financial Advisor provides AI-assisted investment and financial planning advisory outputs. It does **not** make autonomous credit decisions. All outputs require HITL review for amounts > $10,000 USD (see `docs/HUMAN_OVERSIGHT_SCOPE.md`).

**Classification for ECOA purposes:** The system constitutes an "automated system" that influences financial recommendations. While it does not make final credit decisions, its outputs may influence downstream decisions and therefore fall within ECOA's scope of concern.

---

## Protected Classes (ECOA / Reg B)

| Protected Class | ECOA/Reg B Basis | CAGE Risk Level |
|---|---|---|
| Race / Color | 15 U.S.C. §1691(a)(1) | **Moderate** — training data may contain racial correlates |
| National origin | 15 U.S.C. §1691(a)(1) | **Moderate** — multilingual financial contexts |
| Sex | 15 U.S.C. §1691(a)(1) | **Low-Moderate** — gender-correlated investment patterns possible |
| Marital status | 15 U.S.C. §1691(a)(1) | **Low** — limited exposure in advisory context |
| Age | 15 U.S.C. §1691(a)(2) | **Moderate** — age-correlated financial risk profiles |
| Receipt of public assistance | 15 U.S.C. §1691(a)(3) | **Low** — limited signals in advisory context |

---

## Fairness Metrics

### Metric 1: Demographic Parity Difference

**Definition:** The difference in positive outcome rates between the most-favored and least-favored demographic group.

```
DPD = max(P(Y=1|G=g)) - min(P(Y=1|G=g))  for all groups g
```

**Threshold:** DPD ≤ 0.05 (5 percentage points) — consistent with fair lending regulatory guidance.

**Measurement method:** `compute_fairness_metrics()` in `scripts/evaluate_langfuse_traces.py`. Requires Langfuse traces with `demographic_group` metadata tag populated (see §Data Collection).

**Q2 2026 Baseline (placeholder):**

| Group | Positive Rate | Sample Size |
|---|---|---|
| *Pending first FIA run* | — | — |
| **DPD** | **N/A** | — |

### Metric 2: Equalized Odds Difference

**Definition:** The maximum difference in true positive rates and false positive rates across demographic groups.

```
EOD = max(|TPR_g - TPR_g'|, |FPR_g - FPR_g'|)  for all group pairs (g, g')
```

**Threshold:** EOD ≤ 0.05 — consistent with NIST AI RMF GOVERN 1.6 fairness guidance.

**Q2 2026 Baseline (placeholder):**

| Metric | Value |
|---|---|
| *Pending first FIA run* | — |

---

## MAS FEAT F2 Compliance Statement (APAC_MAS)

For APAC_MAS deployments, MAS FEAT Principle F2 requires:

1. **Fairness objective defined:** The fairness objective for CAGE is demographic parity in financial advisory recommendations, with a DPD threshold of ≤ 0.05.
2. **Fairness measurement:** Quarterly fairness assessment using `compute_fairness_metrics()`.
3. **Bias mitigation:** Human review gate for high-value recommendations; HITL SLA of 1 hour (APAC_MAS).
4. **Monitoring:** Continuous Langfuse score monitoring for demographic group outcome disparities.

---

## Data Collection Methodology

To measure fairness metrics, Langfuse traces must include `demographic_group` metadata. This metadata is:

- **Derived from** — synthetic demographic proxies (age band, jurisdiction) where explicit demographic data is unavailable
- **NOT derived from** — actual protected class data (ECOA prohibits collecting most protected class data for credit decisions)
- **Populated by** — the governed financial advisor when the user profile includes jurisdiction and account type metadata

> [!CAUTION]
> CAGE does not collect actual race, sex, or national origin data in Langfuse traces. Fairness assessment uses proxy variables (jurisdiction, account type, age band) as permitted under Reg B statistical analysis provisions. Legal review required before expanding proxy variable set.

---

## Quarterly FIA Procedure

1. Run `python scripts/evaluate_langfuse_traces.py --fairness-report --window-hours=2160` (90-day lookback)
2. Review DPD and EOD against thresholds
3. If DPD > 0.05 or EOD > 0.05: escalate to compliance team for bias mitigation planning
4. Update this document with new baseline results
5. Archive FIA report to `gs://$CAGE_AUDIT_BUCKET/fia/YYYY-QN/`

---

## Quarterly Assessment Schedule

| Quarter | Target Date | Status |
|---|---|---|
| Q2 2026 | 2026-06-30 | **Pending** — first FIA run |
| Q3 2026 | 2026-09-30 | Scheduled |
| Q4 2026 | 2026-12-31 | Scheduled |

---

## Related Documents

- `scripts/evaluate_langfuse_traces.py` — Fairness metric computation (`compute_fairness_metrics()`)
- `docs/HUMAN_OVERSIGHT_SCOPE.md` — HITL controls
- `docs/POAM_US_FED.md` — AI600-004 POAM item
- `docs/MODEL_CARD_REVIEW.md` — Bias risk assessment per model

---

## APAC_MAS — Fairness Impact Assessment (MAS FEAT F2 / MAS TRM §6.3)

**Document scope:** `CAGE_DEPLOYMENT_REGION=APAC_MAS` only
**POAM:** MAS-001 (POAM_APAC_MAS.md)
**Review cadence:** Quarterly (next: Q3 2026)

### Singapore Regulatory Context

MAS FEAT Principle F2 (Fairness) and MAS TRM Guidelines §6.3 (AI and Machine Learning Controls) require:
1. Defined fairness objectives for each AI/ML system
2. Quantitative fairness metrics computed across relevant demographic groups
3. Documented model risk management process including drift detection
4. Quarterly FIA cadence with results reported to MAS TRM governance committee

### Protected Characteristics — APAC_MAS

Under Singapore's **Personal Data Protection Act (PDPA)** and MAS FEAT F2, the relevant protected characteristics for CAGE's financial advisory pipeline are:

| Characteristic | MAS FEAT Relevance | CAGE Risk Level |
|---|---|---|
| Age | Age-correlated investment risk appetite and product suitability | **Moderate** — older clients may receive systematically different recommendations |
| Race / Ethnicity | Cultural investment preferences may be correlated with demographic proxies | **Moderate** — training data may embed correlations |
| Gender | Gender pay gap affects available investment capital; model may exhibit indirect bias | **Low-Moderate** |
| Nationality / Residency status | Singapore Permanent Resident vs. Citizen status affects some financial products | **Low** |

> [!NOTE]
> Singapore's PDPA does not include race or religion as explicit prohibited grounds for automated decision-making in financial services. However, MAS FEAT F2 requires that AI systems in financial services do not produce systematically less favourable outcomes for any identifiable group. The above classifications are assessed under this broader FEAT obligation.

### APAC_MAS Fairness Metrics

**Metric 1: Demographic Parity Difference (MAS FEAT F2)**

Same definition and threshold as §Fairness Metrics above:
- DPD threshold: ≤ 0.05 (5 percentage points)
- Grouping variable: Age band (18–35, 36–55, 56+)
- Measurement: `compute_fairness_metrics()` with `jurisdiction=APAC_MAS` filter

**Metric 2: Product Suitability Outcome Rate**

**Definition:** The rate at which recommendations match the client's declared risk profile.

```
PSOR_g = P(recommendation_risk_level matches declared_risk_profile | G=g)
```

**Threshold:** PSOR variation ≤ 0.10 across age bands — CAGE should produce equally well-matched recommendations regardless of client age.

**APAC_MAS Q2 2026 Baseline (placeholder):**

| Age Band | Sample Size | DPD | PSOR |
|---|---|---|---|
| *Pending first FIA run* | — | — | — |
| **Threshold** | — | ≤ 0.05 | ≤ 0.10 variation |

### MAS TRM §6.3 — Model Risk Management Integration

Per MAS TRM Guidelines §6.3, CAGE's AI model governance must document:

| Requirement | CAGE Implementation | Status |
|---|---|---|
| Model development documentation | `docs/MODEL_CARD_REVIEW.md` | ✅ Available |
| Model validation | DoWhy causal gatekeeper (CTRL_AGT_001) + quarterly FIA | ✅ Operational |
| Model deployment controls | OPA policy, HITL gate, NeMo guardrails | ✅ Operational |
| Model performance monitoring | Langfuse safety_rate, confabulation_rate metrics | ✅ Operational |
| Drift detection | Quarterly FIA DPD/EOD trend analysis | 🟡 Q2 2026 baseline pending |
| Model retirement/replacement criteria | `docs/MODEL_CARD_REVIEW.md` §5 | ✅ Defined |

### APAC_MAS FIA Procedure

1. Run `python scripts/evaluate_langfuse_traces.py --fairness-report --window-hours=2160 --jurisdiction=APAC_MAS`
2. Review DPD, EOD, and PSOR metrics against APAC_MAS thresholds
3. Verify: results stratified by age band, not by PDPA-protected characteristics directly
4. If DPD > 0.05 or PSOR variation > 0.10: escalate to MAS TRM governance committee
5. Update this section with new baseline results
6. Archive FIA report to `gs://$CAGE_AUDIT_BUCKET_APAC_MAS/fia/YYYY-QN/`
7. Brief MAS supervisor contact on FIA results (quarterly)

### APAC_MAS Assessment Schedule

| Quarter | Target Date | Status |
|---|---|---|
| Q2 2026 | 2026-06-30 | **Pending** — first APAC_MAS FIA run |
| Q3 2026 | 2026-09-30 | Scheduled |
| Q4 2026 | 2026-12-31 | Scheduled |

### Additional APAC_MAS Documents

- `docs/MAS_FEAT_T1_TRANSPARENCY_REPORT.md` — Decision explainability (MAS FEAT T1)
- `docs/MAS_NOTICE_655_CERTIFICATION.md` — Audit certification runbook (MAS-002)
- `docs/POAM_APAC_MAS.md` — MAS-001 POAM item
