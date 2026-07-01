# Model Card Review — CAGE v0.1.0

**Document:** AI600-007 / SA-12 / SR-3 / SI-7 Model Supply Chain Review
**Date:** 2026-06-23
**Reviewed by:** TBD — requires security engineer and compliance officer sign-off
**Status:** Draft (placeholder review — pending formal AO review)

---

## Purpose

This document records the formal model card review for all AI model weights deployed by the Cybernetic AI Governance Engine (CAGE). It satisfies:

- **NIST AI 600-1 §2.12** — Value chain and component provenance assessment
- **NIST SP 800-53 SA-12** — Supply chain protection
- **NIST SP 800-53 SR-3** — Supply chain controls and processes
- **NIST SP 800-53 SI-7** — Software, firmware, and information integrity
- **ISO 42001 §A.8.3** — Software Bill of Materials
- **POAM item:** AI600-007 (POAM_US_FED.md)

---

## Models Under Review

### 1. DeepSeek-R1-Distill-Llama-8B

| Field | Value |
|---|---|
| **Model ID** | `deepseek-ai/DeepSeek-R1-Distill-Llama-8B` |
| **Source** | HuggingFace Hub: https://huggingface.co/deepseek-ai/DeepSeek-R1-Distill-Llama-8B |
| **Role in CAGE** | Reasoning model (`MODEL_REASONING`) for consensus critic and HITL escalation decisions |
| **Architecture** | LLaMA-8B distilled from DeepSeek-R1 |
| **Parameters** | ~8 billion |
| **Training data** | Not fully disclosed by DeepSeek. Training cutoff ~2024. Includes reasoning chain distillation from DeepSeek-R1-671B. |
| **License** | DeepSeek License v1.0 (see §License Assessment below) |
| **Integrity verification** | SHA-256 of anchor files (config.json, tokenizer.json) — see `config/model_hashes.json` |

#### License Assessment — US_FED Compatibility

The DeepSeek License v1.0 contains the following relevant provisions for US Federal deployments:

- **Permitted use:** The model may be used for research, commercial, and government purposes subject to the license terms.
- **Use restrictions:** The license prohibits use for activities violating applicable law. US Federal deployments must comply with EO 14110 (AI safety and security) and OMB M-24-10 (generative AI governance).
- **Data provenance:** Training data provenance is not fully disclosed. This creates uncertainty for GDPR (not applicable) and ECOA/Reg B bias risk assessment (see §Bias Risk Assessment).
- **Export controls:** DeepSeek is a PRC-based company. US Federal agencies must assess whether use of PRC-origin model weights is consistent with Section 102 of the Foreign Intelligence Authorization Act and NSPM-33. **Legal review recommended before ATO.**

> [!CAUTION]
> **ATO Prerequisite:** The use of PRC-origin model weights (DeepSeek-R1) in a US Federal deployment may require legal review under NSPM-33 and applicable export control regulations. This item must be resolved before the system can receive an ATO under FISMA High baseline.

#### Known Limitations

- Chain-of-thought reasoning traces may contain factual errors (confabulation). CAGE's confabulation scorer (CTRL_AGT_001) mitigates this at inference time.
- Potential demographic bias in financial domain outputs — see §Bias Risk Assessment.

---

### 2. Meta-Llama-3.1-8B-Instruct

| Field | Value |
|---|---|
| **Model ID** | `meta-llama/Meta-Llama-3.1-8B-Instruct` |
| **Source** | HuggingFace Hub (gated): https://huggingface.co/meta-llama/Meta-Llama-3.1-8B-Instruct |
| **Role in CAGE** | Fast governance model (`MODEL_FAST`) for Tier 2 governance decisions and NeMo Guardrails base |
| **Architecture** | LLaMA 3.1 8B instruction-tuned |
| **Parameters** | ~8 billion |
| **Training data** | Meta discloses: "a new mix of publicly available online data" with cutoff December 2023. |
| **License** | Meta Llama 3.1 Community License Agreement |
| **Integrity verification** | SHA-256 of anchor files (config.json, tokenizer.json) — see `config/model_hashes.json` |

#### License Assessment — US_FED Compatibility

The Meta Llama 3.1 Community License Agreement:

- **Permitted use:** Commercial and research use permitted. Government use permitted subject to standard license terms.
- **Use restrictions:** Prohibited uses include unlawful activity, military weapons, CBRN weapons. CAGE's governance controls (CBRN rails, OPA policies) enforce these restrictions at the application layer.
- **Monthly active users > 700M:** Requires a separate license from Meta. CAGE is a single-enterprise system; this threshold is not relevant.
- **US_FED compatibility:** ✅ The Meta Llama 3.1 Community License is compatible with US Federal use. No PRC-origin concerns. Legal review is **not required** for this model.

#### Known Limitations

- Instruction-following performance may vary on complex financial compliance tasks. CAGE's ConsensusEngine cross-validates responses using the DeepSeek-R1 reasoning model.
- Potential demographic bias — see §Bias Risk Assessment.

---

### 3. NeMo Guardrails Runtime

| Field | Value |
|---|---|
| **Package** | `nemo-guardrails` (PyPI) |
| **Source** | https://github.com/NVIDIA/NeMo-Guardrails |
| **Role in CAGE** | CBRN keyword rail (`cbrn_rails.co`) and conversation safety layer |
| **License** | Apache 2.0 — ✅ universally compatible, including US Federal deployment |
| **Integrity verification** | Verified via `uv.lock` hash pinning (POAM-013 dependency pinning) |

---

## Bias Risk Assessment — ECOA / Reg B (AI600-004)

### Applicable Framework

For financial services AI systems deployed in US Federal context, Equal Credit Opportunity Act (ECOA, 15 U.S.C. §1691) and Regulation B (12 CFR Part 202) prohibit credit discrimination based on race, color, religion, national origin, sex, marital status, age, or receipt of public assistance.

### Risk Assessment

| Protected Class | Potential Risk | Mitigation |
|---|---|---|
| Race / National origin | Both models may reflect training data biases in financial decision patterns | Demographic parity monitoring (AI600-004); `compute_fairness_metrics()` in `evaluate_langfuse_traces.py` |
| Sex | Gender-correlated financial patterns possible | Equalized odds monitoring |
| Age | Age-correlated financial patterns possible | Quarterly fairness assessment (see `docs/AI_FAIRNESS_ASSESSMENT.md`) |

### Residual Risk Rating

**Moderate** — CAGE does not make final credit decisions; it provides governed financial advisory outputs that are subject to human review (HITL). Bias risk is lower than for fully automated credit scoring systems. Annual AI Fairness Assessment required (POAM: AI600-004).

---

## NeMo Guardrails Integrity Verification

NeMo Guardrails is installed as a Python package (`nemo-guardrails` in `pyproject.toml`). Integrity is verified by the `uv.lock` file SHA-256 hash pinning. The Colang CBRN rail file (`src/gateway/governance/nemo/colang/cbrn_rails.co`) is part of the CAGE repository and is protected by the Git commit hash chain.

> [!NOTE]
> Phase 3 work created the NeMo CBRN rail (see POAM_US_FED.md AI600-007 Phase 3). This model card completes the Phase 3 documentation requirement.

---

## Sign-Off Requirements

This document requires the following sign-offs before the POAM-AI600-007 item can be closed:

| Role | Name | Date | Signature |
|---|---|---|---|
| Security Engineer | TBD | TBD | TBD |
| Compliance Officer | TBD | TBD | TBD |
| Authorizing Official (AO) | TBD | TBD | TBD |

> [!IMPORTANT]
> The **DeepSeek-R1 PRC-origin legal review** (noted under §License Assessment) must be completed before the AO signs this document. If the legal review determines DeepSeek-R1 cannot be used in US_FED, `MODEL_REASONING` must be replaced with a US-origin alternative (e.g., `meta-llama/Llama-3.3-70B-Instruct`) and this document updated accordingly.

---

## Related Documents

- `config/model_hashes.json` — SHA-256 anchor file manifest (AI600-007)
- `deployment/scripts/mirror_models.py` — Model weight download with integrity verification
- `docs/AI_FAIRNESS_ASSESSMENT.md` — Annual fairness assessment methodology (AI600-004)
- `docs/POAM_US_FED.md` — POAM item AI600-007
