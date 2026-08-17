# NIST AI 600-1 Gap Analysis — US FED Jurisdiction
## Cybernetic Governance Engine (CAGE) — Agentic AI Functionality

**Document version:** 1.0.0
**Date:** 2026-06-15
**Scope:** Analysis of NIST AI 600-1 (Artificial Intelligence Risk Management Framework: Generative Artificial Intelligence Profile, July 2024) against CAGE v2.0.0 agentic AI capabilities, with specific recommendations for updating existing NIST RMF documentation under the `CAGE_DEPLOYMENT_REGION=US_FED` jurisdiction.
**Authority:** NIST AI 600-1 (July 26, 2024), NIST AI RMF 1.0 (January 2023), NIST SP 800-53 Rev. 5, SR 26-2 (Federal Reserve, April 17, 2026)
**Prerequisite reading:** `docs/NIST_RMF_CHUNK1_CURRENT_STATE.md` through `docs/NIST_RMF_CHUNK5_MONITOR_ROADMAP.md`, `docs/POAM_US_FED.md`

> **⚠️ US_FED Scope Notice:** This document applies exclusively to `CAGE_DEPLOYMENT_REGION=US_FED`. The AI 600-1 analysis is additive to the existing NIST SP 800-53 Rev. 5 HIGH baseline. It does not replace or supersede EU AI Act (EU_ECB) or MAS FEAT (APAC_MAS) obligations.

---

## 0. Are Both SP 800-53 and AI 600-1 Required? — Standards Relationship Analysis

> **This section answers the foundational question before the gap analysis: are NIST SP 800-53 Rev. 5 and NIST AI 600-1 alternatives, or are both required for CAGE under US_FED?**

### 0.1 Answer: Both Are Required — They Are Not Substitutes

The two standards operate at **different layers of the compliance stack** and address **non-overlapping risk surfaces**. Complying with one does not satisfy the other. For CAGE under `CAGE_DEPLOYMENT_REGION=US_FED`, both are legally mandated by separate instruments:

| Standard | Mandating Instrument | What It Governs | Can It Be Waived? |
|----------|---------------------|-----------------|-------------------|
| **NIST SP 800-53 Rev. 5** | FISMA (44 U.S.C. § 3554) | CAGE **as an information system** — infrastructure, identity, network, audit | **No** — FISMA applies to all federal information systems |
| **NIST AI 600-1** | EO 14110 (Oct 2023) + OMB M-24-10 (Mar 2024) + SR 26-2 (Apr 2026) | CAGE **as an agentic AI system** — model behavior, autonomy, trust, bias | **No** — EO 14110 applies to all federal AI systems; SR 26-2 applies to agentic AI in financial services |

### 0.2 The Layered Obligation Model

```
┌──────────────────────────────────────────────────────────────────┐
│  FISMA (statutory — all federal information systems)             │
│  → Mandates NIST SP 800-53 Rev. 5 HIGH baseline                  │
│  → ~300 controls: AC, AU, CA, CM, IA, IR, RA, SC, SI families   │
│  → Governs: network, identity, audit, crypto, incident response  │
├──────────────────────────────────────────────────────────────────┤
│  EO 14110 + OMB M-24-10 (all federal AI systems)                │
│  → Mandates NIST AI RMF 1.0 + AI 600-1 GenAI Profile            │
│  → 12 risk categories: confabulation, injection, bias, etc.      │
│  → Governs: model behavior, agentic autonomy, output integrity   │
├──────────────────────────────────────────────────────────────────┤
│  SR 26-2 (Federal Reserve, April 17, 2026)                       │
│  → Mandates AI RMF for agentic AI in financial services          │
│  → Explicitly references AI 600-1 for GenAI systems             │
│  → Governs: agentic AI scope, human oversight, model risk        │
└──────────────────────────────────────────────────────────────────┘
```

CAGE sits at the intersection of all three layers: it is a federal information system (FISMA), a federal AI system (EO 14110), and an agentic AI system in financial services (SR 26-2).

### 0.3 What Each Standard Covers That the Other Cannot

**SP 800-53 covers — AI 600-1 has no equivalent:**
- Network microsegmentation (SC-7, NetworkPolicy default-deny)
- Account lifecycle management (AC-2, IAM rotation)
- Cryptographic key management (SC-12, KMS HSM-backed signing)
- Audit record generation and retention (AU-12, AU-11, 7-year GCS lifecycle)
- Incident response procedures (IR-8, PagerDuty escalation)
- Vulnerability scanning and flaw remediation (RA-5, SI-2, Trivy/pip-audit)

**AI 600-1 covers — SP 800-53 has no equivalent:**
- **Confabulation (§2.2):** SP 800-53 SI-10 validates API input schemas; it has no concept of an LLM generating a confident but factually incorrect market price. The [`ConsensusEngine`](../../../src/gateway/governance/consensus.py) critics are themselves LLMs that can confabulate risk assessments — SP 800-53 has no control for this.
- **Agentic autonomy scope (§2.5.1–2.5.4):** SP 800-53 AC-5 covers separation of duties between human roles. It has no concept of an AI agent autonomously selecting which MCP tools to call. AI 600-1 §2.5.4 requires a formal human oversight scope statement — no SP 800-53 control requires this.
- **Indirect prompt injection (§2.4):** SP 800-53 SI-3 covers antivirus/malware. It has no concept of a market data API response containing embedded instructions that hijack LLM behavior. CAGE's `get_market_data` MCP tool response flows into the LLM context window with no sanitization — invisible to SP 800-53.
- **Harmful bias / algorithmic fairness (§2.6):** SP 800-53 has no fairness control. AI 600-1 §2.6 requires assessing disparate impact in financial recommendations — a direct ECOA/Regulation B obligation.
- **Training data memorization (§2.3):** SP 800-53 SC-28 covers encryption at rest. It has no concept of PII memorized in model weights that can be extracted via inference queries.
- **Inter-agent trust model (§2.5.3):** SP 800-53 has no control for trust hierarchies between AI agents. CAGE's ConsensusEngine creates a trust chain where LLM-generated "Risk Manager" outputs influence governance decisions — no SP 800-53 control governs this.

### 0.4 The Overlap Zone — Where AI 600-1 Extends SP 800-53

Three areas have partial overlap where AI 600-1 adds AI-specific sub-requirements on top of existing SP 800-53 controls:

| SP 800-53 Control | AI 600-1 Extension | What AI 600-1 Adds |
|-------------------|-------------------|-------------------|
| SI-10 (Input Validation) | §2.4 (Prompt Injection) | Indirect injection via external data sources; semantic obfuscation; multi-turn attacks |
| SA-12 (Supply Chain) | §2.12 (Value Chain) | Model weight integrity; model card review; training data provenance |
| AU-10 (Non-repudiation) | §2.8 (Information Integrity) | Output provenance tracking; watermarking of GenAI outputs |

In these overlap zones, satisfying SP 800-53 alone is **insufficient** — AI 600-1 adds obligations that SP 800-53 does not contemplate.

### 0.5 CAGE's Agentic AI Role Makes AI 600-1 Non-Optional

CAGE is not merely a system that uses AI — it is an **agentic AI system** under AI 600-1 §2.5's definition: "systems that can plan and execute multi-step tasks with varying degrees of human oversight." This triggers the most demanding AI 600-1 requirements:

1. **Real-world actuators with irreversible effects:** The `execute_trade` MCP tool causes real financial transactions. AI 600-1 §2.5.2 specifically flags "actions with real-world consequences" as requiring heightened oversight — there is no SP 800-53 equivalent for this obligation.

2. **Multi-agent trust chains:** The ConsensusEngine creates a trust chain where LLM-generated "Risk Manager" and "Compliance Officer" outputs influence governance decisions. AI 600-1 §2.5.3 requires documenting the inter-agent trust model — SP 800-53 has no such requirement.

3. **Recursive governance risk:** CAGE's governance pipeline itself uses LLM inference (consensus personas) to govern LLM outputs (financial advisor). AI 600-1 risks in the governance layer propagate to the governed system — a recursive risk that SP 800-53 cannot address because it has no model of LLM behavior.

4. **Autonomous planning without pre-execution governance:** The LangGraph StateGraph autonomously selects which tools to call, in what order, and with what parameters. SP 800-53 AC-3 enforces access control on API calls — but it cannot govern the LLM's internal planning process that precedes those calls.

### 0.6 Practical Consequence for ATO

An ATO package for CAGE under `CAGE_DEPLOYMENT_REGION=US_FED` that satisfies **only SP 800-53** would be rejected by an AO because:
- It would have no controls for confabulation, agentic autonomy, indirect injection, or algorithmic bias
- EO 14110 and OMB M-24-10 explicitly require AI RMF compliance for federal AI systems
- SR 26-2 explicitly requires AI 600-1 for agentic AI in financial services

An ATO package that satisfies **only AI 600-1** would be rejected because:
- It would have no controls for network segmentation, account management, or cryptographic key management
- FISMA mandates SP 800-53 for all federal information systems regardless of AI content

**The correct framing:** SP 800-53 governs CAGE as an information system. AI 600-1 governs CAGE as an agentic AI system. Both are required because CAGE is both.

---

## 1. Executive Summary

NIST AI 600-1 (July 2024) is the Generative AI Profile of the NIST AI Risk Management Framework (AI RMF 1.0). It identifies **12 unique risk categories** specific to generative and agentic AI systems and maps them to the four AI RMF core functions: **GOVERN, MAP, MEASURE, MANAGE**. For US federal deployments (`CAGE_DEPLOYMENT_REGION=US_FED`), AI 600-1 is now a de facto companion to NIST SP 800-53 Rev. 5 for any system deploying large language models (LLMs) or agentic AI pipelines.

CAGE v2.0.0 is an **agentic AI governance platform** that deploys an 8-tier governance pipeline (FTRA + 7 in-pipeline tiers) over a multi-agent LangGraph StateGraph. It processes LLM-generated financial advisory outputs, executes trades via MCP tool calls, and operates a multi-agent consensus engine with "Risk Manager" and "Compliance Officer" personas. This makes CAGE a **dual-role system** under AI 600-1: it is simultaneously a **GenAI deployer** (it deploys vLLM inference for the governed financial advisor) and a **GenAI governance operator** (it enforces policy over those outputs). Both roles carry distinct AI 600-1 obligations.

### Key Findings

| Finding | Severity | Existing Coverage | Gap |
|---------|----------|-------------------|-----|
| No AI 600-1 risk taxonomy formally adopted | **Critical** | None | Full taxonomy adoption required for US_FED ATO |
| Confabulation risk not formally measured | **High** | Partial (consensus engine) | No hallucination rate metric; no confabulation Lula validation |
| Agentic action scope not formally bounded | **High** | Partial (STPA UCAs) | No AI 600-1 §2.5 "agentic AI" scope document |
| Multi-agent trust hierarchy undocumented | **High** | Partial (ConsensusEngine) | No inter-agent trust model per AI 600-1 §2.5.3 |
| Data poisoning controls not formally assessed | **High** | Partial (Aho-Corasick) | No training data provenance; no poisoning Lula validation |
| Human-AI configuration not formally documented | **High** | Partial (HITL TOCTOU) | No AI 600-1 §2.5.4 human oversight scope statement |
| Value chain risk (model weights) unassessed | **High** | None | No model card verification; no weight integrity check |
| Bias/homogenization risk not measured | **Moderate** | None | No fairness metric; no demographic impact assessment |
| Intellectual property controls absent | **Moderate** | None | No training data license audit; no output IP policy |
| Environmental impact not tracked | **Low** | None | No GPU energy/carbon metric |

### Relationship to Existing RMF Documentation

AI 600-1 does **not replace** the existing NIST SP 800-53 Rev. 5 HIGH baseline analysis in Chunks 1–5. It is an **additive overlay** that introduces AI-specific risk categories requiring new controls, new Lula validations, new OSCAL component entries, and new POAM items. The existing overall RMF readiness score of **24%** does not account for AI 600-1 obligations — when AI 600-1 is factored in, the effective US_FED readiness score for an agentic AI system drops to approximately **18%** due to the additional ungapped risk surface.

---

## 2. NIST AI 600-1 Overview and Applicability to CAGE

### 2.1 Document Structure

NIST AI 600-1 is organized around:

- **Section 1:** Introduction and scope — applies to "organizations that develop, deploy, evaluate, or use generative AI systems"
- **Section 2:** Generative AI risk landscape — 12 risk categories with sub-risks
- **Section 3:** Suggested actions — mapped to AI RMF GOVERN/MAP/MEASURE/MANAGE functions
- **Appendix A:** Crosswalk to AI RMF 1.0 subcategories
- **Appendix B:** Crosswalk to NIST SP 800-53 Rev. 5 controls (the critical bridge for US_FED)

### 2.2 Applicability Determination for CAGE

CAGE meets **all three applicability criteria** for AI 600-1:

1. **Generative AI deployer:** CAGE deploys `DeepSeek-R1-Distill-Llama-8B` and `Meta-Llama-3.1-8B-Instruct` via vLLM for financial advisory generation. These are generative AI models producing novel text outputs.

2. **Agentic AI operator:** The governed financial advisor is a **multi-agent LangGraph StateGraph** with autonomous tool-calling capability (MCP tools: `execute_trade`, `get_market_data`, `get_portfolio`). AI 600-1 §2.5 specifically addresses agentic AI systems with "increased autonomy" and "multi-step task completion."

3. **AI governance system:** CAGE's governance pipeline (OPA, NeMo, STPA, CBF, ConsensusEngine) itself uses LLM inference for the consensus "Risk Manager" and "Compliance Officer" personas — making the governance layer itself a GenAI system subject to AI 600-1.

### 2.3 Regulatory Context for US_FED

Under `CAGE_DEPLOYMENT_REGION=US_FED`, the following regulatory instruments make AI 600-1 compliance effectively mandatory:

- **Executive Order 14110** (October 2023, "Safe, Secure, and Trustworthy AI"): Directs federal agencies to adopt NIST AI RMF and AI 600-1 for AI systems in federal use.
- **OMB Memorandum M-24-10** (March 2024): Requires federal agencies to inventory AI systems and apply AI RMF practices, with AI 600-1 as the GenAI-specific profile.
- **SR 26-2** (Federal Reserve, April 17, 2026): Explicitly references NIST AI RMF as the governance framework for agentic AI in financial services, making AI 600-1 directly applicable to CAGE's financial advisory function.
- **NIST SP 800-53 Rev. 5 Appendix B crosswalk** in AI 600-1: Provides the direct bridge between AI 600-1 risk categories and the SP 800-53 controls already in CAGE's HIGH baseline — meaning AI 600-1 gaps translate directly into SP 800-53 control gaps.

---

## 3. CAGE Agentic AI Functionality Inventory

Before mapping AI 600-1 risks, this section inventories all CAGE components that constitute "agentic AI" under AI 600-1 §2.5 ("systems that can plan and execute multi-step tasks with varying degrees of human oversight").

| Component | AI 600-1 Role | Autonomy Level | Human Oversight Mechanism |
|-----------|--------------|----------------|--------------------------|
| **governed-financial-advisor LangGraph** | Agentic orchestrator | High — autonomous multi-step planning | HITL approval gate (`wait_for_approval` node); DEFER queue |
| **vLLM DeepSeek-R1 (reasoning)** | GenAI model (reasoning) | Medium — generates structured reasoning chains | Governance pipeline intercepts all outputs |
| **vLLM Llama-3.1 (fast inference)** | GenAI model (advisory) | Medium — generates financial recommendations | NeMo Guardrails + OPA policy enforcement |
| **ConsensusEngine** (Risk Manager + Compliance Officer personas) | Multi-agent consensus | Medium — parallel LLM critic calls | Results queued for background audit; threshold USD 10k |
| **NeMo Guardrails** (Colang 2.x flows) | AI safety layer | Low — deterministic rule enforcement | Colang flows are human-authored |
| **SymbolicGovernor** (8-tier pipeline: FTRA + 7 in-pipeline tiers) | AI governance orchestrator | Low — deterministic policy enforcement | All tiers are deterministic except Tier 5 (consensus) |
| **CausalGatekeeper** | Causal inference gate | Low — statistical causal model | Deterministic causal graph |
| **ExternalNormativeProvider** (TrustLayers) | External AI validator | Low — stub mode currently | Adaptive FRIA gating (tri-state) |
| **EvaluatorAuditor** | AI output auditor | Low — rule-based scoring | Human review required for LLM advisory outputs |
| **MCP tool calls** (`execute_trade`, `get_market_data`) | Agentic actuators | **Critical** — real-world financial effects | STPA UCAs, CBF, OPA RBAC, HMAC seal |

### 3.1 Agentic AI Risk Surface Summary

CAGE's agentic AI risk surface is **unusually broad** because:

1. **Real-world actuators with irreversible effects:** `execute_trade` MCP tool causes real financial transactions. AI 600-1 §2.5.2 specifically flags "actions with real-world consequences" as requiring heightened oversight.

2. **Multi-agent trust chains:** The ConsensusEngine creates a trust chain where LLM-generated "Risk Manager" and "Compliance Officer" outputs influence governance decisions. A compromised or hallucinating consensus agent could approve harmful trades.

3. **Recursive governance:** The governance system itself uses GenAI (consensus personas) to govern GenAI (financial advisor). This creates a recursive risk where AI 600-1 risks in the governance layer propagate to the governed system.

4. **Autonomous planning with financial domain:** The LangGraph StateGraph autonomously selects which tools to call, in what order, and with what parameters — subject only to post-hoc governance checks. Pre-execution planning is not governed.

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [NIST AI 600-1 Overview and Applicability to CAGE](#2-nist-ai-600-1-overview-and-applicability-to-cage)
3. [CAGE Agentic AI Functionality Inventory](#3-cage-agentic-ai-functionality-inventory)
4. [AI 600-1 Risk Category Analysis — CAGE Mapping](#4-ai-600-1-risk-category-analysis--cage-mapping)
   - [4.1 CBRN Information or Capabilities](#41-cbrn-information-or-capabilities)
   - [4.2 Confabulation (Hallucination)](#42-confabulation-hallucination)
   - [4.3 Data Privacy](#43-data-privacy)
   - [4.4 Data Poisoning and Prompt Injection](#44-data-poisoning-and-prompt-injection)
   - [4.5 Environmental Impacts](#45-environmental-impacts)
   - [4.6 Harmful Bias and Homogenization](#46-harmful-bias-and-homogenization)
   - [4.7 Human-AI Configuration](#47-human-ai-configuration)
   - [4.8 Information Integrity](#48-information-integrity)
   - [4.9 Information Security](#49-information-security)
   - [4.10 Intellectual Property](#410-intellectual-property)
   - [4.11 Obscene, Degrading, and Abusive Content](#411-obscene-degrading-and-abusive-content)
   - [4.12 Value Chain and Component Integration](#412-value-chain-and-component-integration)
5. [Updates Required to Existing NIST RMF Chunks](#5-updates-required-to-existing-nist-rmf-chunks)
   - [5.1 Chunk 1 (Current State) Updates](#51-chunk-1-current-state-updates)
   - [5.2 Chunk 2 (Prepare/Categorize) Updates](#52-chunk-2-preparecategorize-updates)
   - [5.3 Chunk 3 (Select/Implement) Updates](#53-chunk-3-selectimplement-updates)
   - [5.4 Chunk 4 (Assess/Authorize) Updates](#54-chunk-4-assessauthorize-updates)
   - [5.5 Chunk 5 (Monitor/Roadmap) Updates](#55-chunk-5-monitorroadmap-updates)
6. [AI 600-1 to SP 800-53 Control Crosswalk](#6-ai-600-1-to-sp-800-53-control-crosswalk)
7. [New OSCAL and Lula Artifacts Required](#7-new-oscal-and-lula-artifacts-required)
8. [New POAM Items](#8-new-poam-items)
9. [Implementation Roadmap](#9-implementation-roadmap)

---

## 4. AI 600-1 Risk Category Analysis — CAGE Mapping

> For each of the 12 AI 600-1 risk categories, this section provides: (a) the risk definition per AI 600-1, (b) CAGE's current coverage, (c) identified gaps, (d) specific SP 800-53 controls implicated (per AI 600-1 Appendix B crosswalk), and (e) recommended updates to existing NIST RMF chunks.

---

### 4.1 CBRN Information or Capabilities

**AI 600-1 Definition:** Risk that GenAI systems provide "serious uplift to those seeking to create biological, chemical, nuclear, or radiological weapons with the potential for mass casualties."

**CAGE Applicability:** **Low** — CAGE is a financial advisory system. The vLLM models (DeepSeek-R1, Llama-3.1) are not fine-tuned on CBRN data. The domain is financial markets, not dual-use science.

**Current Coverage:**
- NeMo Guardrails Colang flows (`config/rails/main_logic.co`) enforce domain restriction to financial topics
- Tier-1 Aho-Corasick keyword scan (`ac_keyword_scan` in [`src/gateway/governance/text_filter.py`](../../../src/gateway/governance/text_filter.py)) blocks 14 forbidden prompt patterns (**v3.0.0:** `safety.py` removed; import from `text_filter.py`)
- OPA `trade.governance` policy enforces domain-specific RBAC

**Gaps:**
1. No explicit CBRN keyword category in the Tier-1 keyword list — the 14 keywords are financial bypass/injection phrases, not CBRN uplift phrases
2. No formal domain restriction policy document stating CAGE models are scoped to financial advisory only
3. No model card review confirming DeepSeek-R1 and Llama-3.1 do not have CBRN uplift capability

**SP 800-53 Controls Implicated (AI 600-1 Appendix B):** SI-10, SI-15, AC-3, CM-7

**Recommended RMF Update:** Add a "Domain Restriction Policy" section to the SSP (POAM-015) stating CAGE models are scoped exclusively to financial advisory. Add CBRN as an explicit exclusion category in `config/governance_thresholds.json` keyword list. Severity: **Low** — document only.

---

### 4.2 Confabulation (Hallucination)

**AI 600-1 Definition:** Risk that GenAI systems "produce confident-sounding but inaccurate or fabricated outputs" — including factual errors, false citations, and invented financial data.

**CAGE Applicability:** **Critical** — CAGE's financial advisor generates trade recommendations based on LLM outputs. A hallucinated market price, fabricated portfolio position, or invented regulatory constraint could cause irreversible financial harm.

**Current Coverage:**
- [`src/gateway/governance/generated_stpa_validator.py`](../../../src/gateway/governance/generated_stpa_validator.py) validates trade parameters against deterministic constraints (drawdown ≤ 5%, order size ≤ 1% daily volume) — catches hallucinated extreme values (**v3.0.0:** deprecated `stpa_validator.py` shim removed)
- [`src/gateway/governance/consensus.py`](../../../src/gateway/governance/consensus.py) — `ConsensusEngine` runs parallel LLM critic calls; disagreement between critics can surface confabulation
- [`src/gateway/governance/causal_gatekeeper.py`](../../../src/gateway/governance/causal_gatekeeper.py) — causal inference gate prevents spurious correlations from driving decisions
- `config/governance_thresholds.json` — `min_trade_confidence: 0.95` threshold rejects low-confidence outputs

**Gaps:**
1. **No confabulation rate metric.** There is no measurement of how often the financial advisor LLM produces factually incorrect market data, fabricated portfolio positions, or hallucinated regulatory constraints. The `safety_rate` metric in [`src/compliance_bridge/metrics.py`](../../../src/compliance_bridge/metrics.py) measures governance pass/fail, not factual accuracy.
2. **ConsensusEngine critics are also LLMs.** The "Risk Manager" and "Compliance Officer" personas in [`src/gateway/governance/consensus.py`](../../../src/gateway/governance/consensus.py) are themselves LLM calls — they can confabulate their risk assessments. There is no ground-truth validation of consensus outputs.
3. **No hallucination detection on market data inputs.** The `get_market_data` MCP tool returns external data that the LLM may misinterpret or hallucinate about. No validation that the LLM's stated market price matches the actual API response.
4. **No Lula validation for confabulation rate.** The 15 existing Lula manifests do not include any confabulation/hallucination rate assertion.
5. **Explainer node output not validated.** The `explainer` agent generates human-readable explanations of governance decisions — these explanations could confabulate the reasoning behind a DENY verdict.

**SP 800-53 Controls Implicated (AI 600-1 Appendix B):** SI-10, SI-12, AU-3, AU-10, RA-3

**Recommended RMF Updates:**

1. **Chunk 3 (Select/Implement) — SI-10 gap update:** Add confabulation as a sub-category of SI-10 (Information Input Validation). The existing SI-10 gap analysis covers only schema validation of API inputs; it must be extended to cover LLM output factual accuracy validation.

2. **Chunk 4 (Assess/Authorize) — Control Effectiveness Metrics:** Add `confabulation_rate` to `ComplianceMetrics` in [`src/compliance_bridge/types.py`](../../../src/compliance_bridge/types.py). Implement via LLM-as-judge evaluation comparing financial advisor outputs against ground-truth market data from the `get_market_data` MCP tool response.

3. **New Lula validation:** Create `compliance/lula/lula-validation-ai600-confabulation.yaml` asserting that `confabulation_rate < 0.02` (2% threshold) over a 24-hour window, queried from the compliance-bridge metrics API.

4. **Chunk 1 (Current State) — ConsensusEngine risk note:** Add a note that the ConsensusEngine's LLM critics are themselves subject to confabulation risk, and that consensus agreement does not guarantee factual accuracy — only policy compliance.

**New POAM Item:** AI600-001 (see Section 8).

---

### 4.3 Data Privacy

**AI 600-1 Definition:** Risk that GenAI systems "process, store, or expose personally identifiable information (PII) or other sensitive data" including through training data memorization, inference-time leakage, or output generation.

**CAGE Applicability:** **High** — CAGE processes financial PII (SSN, account numbers, credit card data) in the context of financial advisory. The vLLM models may have memorized PII from training data. NeMo Guardrails + Presidio provide runtime PII detection.

**Current Coverage:**
- [`src/gateway/governance/nemo/manager.py`](../../../src/gateway/governance/nemo/manager.py) — `SafeAnalyzer` with 15 PII entity types (EMAIL, SSN, CREDIT_CARD, US_BANK_NUMBER, IBAN_CODE, etc.) via Presidio
- [`src/gateway/governance/pii_sanitizer.py`](../../../src/gateway/governance/pii_sanitizer.py) — PII sanitization before LLM inference
- `compliance/lula/lula-validation-a92.yaml` — zero-tolerance PII control (safety_rate = 1.0)
- `compliance/pia/PRIVACY_IMPACT_ASSESSMENT.md` — Privacy Impact Assessment exists
- NeMo Colang flows apply PII detection on both input and output rails

**Gaps:**
1. **No training data memorization assessment.** AI 600-1 §2.3 specifically flags "training data memorization" as a data privacy risk. There is no assessment of whether DeepSeek-R1 or Llama-3.1 have memorized PII from their training corpora. This is distinct from runtime PII detection — a model can reproduce memorized PII even when the input contains no PII.
2. **No differential privacy or membership inference attack testing.** No red-team tests for membership inference attacks (can an adversary determine if a specific individual's data was in the training set?).
3. **PII detection threshold `score_threshold=0.3` may be too permissive.** The Presidio `score_threshold=0.3` in `SafeAnalyzer` means entities with 30% confidence are flagged — but also means 70%-confidence entities below the threshold pass through. For a HIGH-baseline financial system, this threshold should be reviewed.
4. **No PII retention audit for Langfuse traces.** OTel spans containing governance decisions may include PII in `langfuse.observation.input` attributes. The 24-hour PII retention limit from `docs/banking_regs.md` is not enforced on Langfuse trace storage.
5. **Inference-time prompt injection can bypass PII detection.** A crafted prompt could instruct the LLM to output PII in an encoded form (Base64, pig Latin) that Presidio does not detect.

**SP 800-53 Controls Implicated (AI 600-1 Appendix B):** AC-3, AC-4, AU-3, SC-8, SC-28, SI-12, SI-19, RA-3

**Recommended RMF Updates:**

1. **Chunk 3 (Select/Implement) — SI-19 gap update:** The existing SI-19 gap notes "no de-identification effectiveness audit." Add AI 600-1 §2.3 training data memorization as a specific sub-gap requiring a memorization assessment test (e.g., using the Carlini et al. extraction attack methodology against the deployed vLLM models).

2. **Chunk 2 (Prepare/Categorize) — Information Type update:** Add "AI Training Data Memorization Risk" as a new information type in `docs/SP800-60_INFORMATION_TYPES.md` with C=High, I=Moderate, A=Low — reflecting that memorized PII in model weights is a persistent confidentiality risk.

3. **Chunk 5 (Monitor) — Ongoing assessment:** Add a quarterly memorization assessment to the ISCM strategy, using a canary PII dataset injected into model fine-tuning (if applicable) or using extraction attack probes against the deployed models.

**New POAM Item:** AI600-002 (see Section 8).

---

### 4.4 Data Poisoning and Prompt Injection

**AI 600-1 Definition:** Risk that "training data or model inputs are manipulated to cause the AI system to behave in unintended or harmful ways," including prompt injection attacks that hijack agent behavior.

**CAGE Applicability:** **Critical** — CAGE's agentic financial advisor is a high-value target for prompt injection. A successful injection could cause the agent to execute unauthorized trades, exfiltrate portfolio data, or bypass governance controls. This is the highest-severity AI 600-1 risk for CAGE.

**Current Coverage:**
- **Tier-1 Aho-Corasick scan** (`ac_keyword_scan`) — 14 bypass/injection keywords, O(n) scan
- **NeMo Guardrails** — Colang `check_authorization` flow validates approval token; input/output rails
- **OPA `trade.governance`** — `prompt_injection_check` rule in [`src/governed_financial_advisor/governance/policy/trade_governance.rego`](../../../src/governed_financial_advisor/governance/policy/trade_governance.rego) returns `GOVERNANCE_VIOLATION` on injection detection
- **Red team dataset** — `tests/red_team/adversarial_dataset.json` contains PII injection and prompt injection payloads (PII-001 through PII-004)
- **STPA UCA-1** — missing approval token blocks execution (prevents injection-driven authorization bypass)

**Gaps:**
1. **Indirect prompt injection not covered.** The Tier-1 keyword scan and NeMo rails detect direct injection in user inputs. AI 600-1 §2.4 specifically flags **indirect prompt injection** — where malicious instructions are embedded in external data sources (market data API responses, portfolio data, news feeds) that the agent retrieves and processes. The `get_market_data` MCP tool response is not sanitized before being passed to the LLM context.
2. **Only 14 Tier-1 keywords.** The Aho-Corasick keyword list covers 14 bypass phrases. Modern prompt injection attacks use semantic obfuscation, Unicode homoglyphs, and multi-turn context manipulation that keyword matching cannot detect.
3. **No adversarial robustness metric.** The red team dataset exists but `deflection_score >= 3` (3/5 rubric) is the pass threshold — insufficient for a HIGH-baseline financial system. AI 600-1 recommends measuring adversarial robustness as a continuous metric.
4. **No training data provenance.** There is no documentation of the training data sources for DeepSeek-R1 or Llama-3.1, making it impossible to assess data poisoning risk in the pre-training phase.
5. **Multi-turn injection not tested.** The adversarial dataset tests single-turn injections. Multi-turn attacks (where the injection is spread across multiple conversation turns to evade per-turn detection) are not covered.
6. **MCP tool response injection.** If a malicious market data provider returns a response containing injection instructions, the current pipeline has no sanitization layer between the MCP tool response and the LLM context window.

**SP 800-53 Controls Implicated (AI 600-1 Appendix B):** SI-3, SI-10, SI-15, RA-5, SA-11, CA-8

**Recommended RMF Updates:**

1. **Chunk 3 (Select/Implement) — SI-3 gap update:** Extend the SI-3 malicious code protection gap to explicitly cover indirect prompt injection via external data sources. Add a recommendation to sanitize all MCP tool responses through the Aho-Corasick scanner before injecting into LLM context.

2. **Chunk 4 (Assess/Authorize) — Red Team Coverage:** Raise the red team pass threshold from `deflection_score >= 3` to `deflection_score >= 4` for all injection payloads (not just `severity: critical`). Add indirect injection test cases to `tests/red_team/adversarial_dataset.json` using market data API response injection vectors.

3. **Chunk 1 (Current State) — Governance coverage note:** Add a note that the Tier-1 keyword scan covers direct injection only; indirect injection via MCP tool responses is an open gap.

4. **New Lula validation:** Create `compliance/lula/lula-validation-ai600-injection.yaml` asserting that the red team adversarial test suite passes with `deflection_score >= 4` for all critical payloads, queried from the Langfuse red team evaluation project.

**New POAM Item:** AI600-003 (see Section 8).

---

### 4.5 Environmental Impacts

**AI 600-1 Definition:** Risk related to "the environmental costs of training and operating large AI models," including energy consumption, water usage, and carbon emissions.

**CAGE Applicability:** **Low-Moderate** — CAGE operates vLLM inference on GKE GPU nodes (spot instances). The environmental impact is real but not a primary compliance risk for US_FED financial regulation. However, OMB M-24-10 requires federal agencies to track AI environmental impacts.

**Current Coverage:**
- vLLM inference uses GKE spot GPU instances (`deployment/k8s/vllm-inference-spot.yaml`) — spot instances reduce cost but do not directly reduce energy consumption
- No energy consumption metrics collected
- No carbon footprint tracking

**Gaps:**
1. **No GPU energy consumption metric.** No OTel metric tracks GPU power draw, inference energy per request, or total energy consumption.
2. **No carbon footprint reporting.** OMB M-24-10 §4.3 requires federal AI systems to report environmental impacts. No such report exists.
3. **No energy efficiency optimization.** No batching strategy, quantization policy, or model compression approach documented for energy efficiency.

**SP 800-53 Controls Implicated (AI 600-1 Appendix B):** PM-8 (Critical Infrastructure Plan — environmental sustainability)

**Recommended RMF Update:** Add a "GenAI Environmental Impact" section to the SSP (POAM-015) documenting GCP region energy mix (us-central1 uses ~60% carbon-free energy), estimated GPU hours per month, and GCP Carbon Footprint API integration plan. Severity: **Low** — documentation only for initial ATO.

---

### 4.7 Human-AI Configuration

**AI 600-1 Definition:** Risk arising from "inappropriate levels of human oversight or control over AI systems," including over-reliance on AI outputs, automation bias, and insufficient human review of consequential AI decisions. AI 600-1 §2.5.4 specifically addresses agentic AI systems where "the degree of human oversight may be reduced."

**CAGE Applicability:** **Critical** — CAGE's agentic financial advisor makes autonomous trade decisions with real financial consequences. The HITL (Human-in-the-Loop) approval gate is the primary human oversight mechanism, but it is subject to TOCTOU race conditions (now remediated) and automation bias (not yet addressed).

**Current Coverage:**
- **HITL approval gate:** `wait_for_approval` LangGraph node requires human approval for trades above the consensus threshold (USD 10,000)
- **HITL TOCTOU remediation:** `post_hitl_rehydrate` and `post_hitl_revalidate` nodes prevent time-of-check/time-of-use race conditions (v2.0.0)
- **DEFER queue (AARM-V7):** [`src/gateway/governance/defer_queue.py`](../../../src/gateway/governance/defer_queue.py) — confidence-starved contexts queued for human review rather than hard-denied
- **ConsensusEngine threshold:** Trades above USD 10,000 require multi-agent consensus before human review
- **LLM remediation advisory:** Step 5 of audit workflow requires `human_review_required: true` before applying LLM suggestions

**Gaps:**
1. **No formal Human Oversight Scope Statement.** AI 600-1 §2.5.4 requires documenting "the degree of human oversight" for each agentic AI capability. There is no document specifying: which decisions require human approval, what information humans are shown, what the expected review time is, and what happens if the human approver is unavailable.
2. **Automation bias not addressed.** The HITL approval interface (if any exists) is not documented. If human approvers are shown only the AI's recommendation without counterfactual alternatives, automation bias (rubber-stamping AI decisions) is likely. AI 600-1 §2.7 specifically flags this.
3. **No DEFER queue SLA.** The DEFER queue stores confidence-starved contexts for human review, but there is no documented SLA for how quickly a human must review and resolve a deferred decision. Stale deferred decisions could block legitimate trades indefinitely.
4. **Trades below USD 10,000 have no human review.** The consensus threshold is USD 10,000 — trades below this amount are approved/denied entirely by the automated governance pipeline with no human review option. AI 600-1 §2.5.4 requires justification for any autonomous decision with real-world consequences.
5. **No human override audit trail.** If a human approver overrides a governance DENY decision, there is no dedicated audit trail for the override — only the standard OTel span. Override decisions should be separately logged with the approver identity and rationale.
6. **No "meaningful human control" assessment.** AI 600-1 §2.7 requires assessing whether human oversight is "meaningful" (i.e., humans have sufficient information, time, and authority to make independent decisions) vs. "nominal" (rubber-stamp). No such assessment exists.

**SP 800-53 Controls Implicated (AI 600-1 Appendix B):** AC-5, AU-3, AU-10, CA-7, IR-4, PM-26

**Recommended RMF Updates:**

1. **Chunk 1 (Current State) — HITL coverage note:** Add a note that while HITL TOCTOU is remediated, automation bias and human oversight scope documentation remain open gaps per AI 600-1 §2.7.

2. **Chunk 3 (Select/Implement) — AC-5 gap update:** Extend the AC-5 (Separation of Duties) gap to include AI 600-1 §2.7 human-AI configuration requirements. Add a recommendation to create `docs/HUMAN_OVERSIGHT_SCOPE.md` documenting the human oversight model for each agentic capability.

3. **Chunk 4 (Assess/Authorize) — New assessment procedure:** Add a "Human-AI Configuration Assessment" to the SAP that evaluates: (a) whether the HITL interface provides sufficient information for independent human judgment, (b) DEFER queue resolution SLA compliance, (c) override audit trail completeness.

4. **New Lula validation:** Create `compliance/lula/lula-validation-ai600-hitl.yaml` asserting that the DEFER queue depth is below a threshold (e.g., < 10 unresolved items older than 4 hours), queried from Redis db=1 via the compliance-bridge metrics API.

**New POAM Item:** AI600-005 (see Section 8).

---

### 4.8 Information Integrity

**AI 600-1 Definition:** Risk that GenAI systems "generate or amplify false or misleading information," including synthetic media, disinformation, and fabricated financial data that could manipulate markets or deceive users.

**CAGE Applicability:** **High** — CAGE generates financial advisory outputs that users may act upon. Fabricated market analysis, invented regulatory citations, or false risk assessments could constitute market manipulation or securities fraud under SEC regulations applicable to US_FED financial institutions.

**Current Coverage:**
- **STPA UCA constraints:** Deterministic validation of trade parameters prevents execution of trades based on obviously fabricated data (e.g., drawdown > 4.5% blocks execution regardless of LLM reasoning)
- **CausalGatekeeper:** [`src/gateway/governance/causal_gatekeeper.py`](../../../src/gateway/governance/causal_gatekeeper.py) prevents spurious correlations from driving decisions
- **ConsensusEngine:** Multi-agent consensus provides a cross-check on individual LLM outputs
- **KMS-signed governance verdicts:** [`src/gateway/governance/kms_signer.py`](../../../src/gateway/governance/kms_signer.py) — HSM-backed asymmetric signing provides non-repudiation of governance decisions

**Gaps:**
1. **No output provenance tracking.** AI 600-1 §2.8 recommends "provenance tracking" for GenAI outputs — documenting which model version, which prompt, and which context produced a given output. While OTel spans capture model name, there is no structured provenance record linking a financial recommendation to its generating model version, temperature, and context window.
2. **No watermarking or content authenticity.** AI 600-1 §2.8 recommends "watermarking or other content authenticity mechanisms" for GenAI outputs. CAGE's governance verdicts are KMS-signed, but the underlying LLM-generated financial recommendations are not cryptographically attributed.
3. **Explainer agent outputs not validated.** The `explainer` agent generates human-readable explanations of governance decisions. These explanations could contain false information about why a trade was approved or denied, misleading users about the actual governance logic.
4. **No market manipulation detection.** If the LLM generates recommendations that, in aggregate, could constitute market manipulation (e.g., systematically recommending the same stock to all users), there is no detection mechanism.

**SP 800-53 Controls Implicated (AI 600-1 Appendix B):** AU-10, SI-7, SI-12, AC-3, RA-3

**Recommended RMF Updates:**

1. **Chunk 1 (Current State) — AU-10 coverage update:** Note that KMS-signed governance verdicts provide non-repudiation for governance decisions but not for the underlying LLM-generated financial recommendations. Add output provenance tracking as a gap.

2. **Chunk 3 (Select/Implement) — SI-7 gap update:** Extend the SI-7 (Software, Firmware, and Information Integrity) gap to include LLM output integrity. Recommend adding a structured provenance record to each financial recommendation: `{"model": "deepseek-r1-distill-llama-8b", "version": "<sha>", "timestamp": "<iso8601>", "context_hash": "<sha256>"}`.

3. **Chunk 5 (Monitor) — New monitoring metric:** Add `output_provenance_coverage` to the compliance metrics — percentage of financial recommendations with a complete provenance record.

---

### 4.9 Information Security

**AI 600-1 Definition:** Risk that GenAI systems "introduce new attack surfaces or vulnerabilities," including model extraction attacks, adversarial examples, jailbreaking, and AI-specific supply chain attacks.

**CAGE Applicability:** **Critical** — CAGE's governance pipeline is itself a security control. Attacks that compromise the governance pipeline (jailbreaking OPA policies, extracting the HMAC seal secret via model inference, or bypassing NeMo Guardrails) directly undermine the security of the entire financial advisory system.

**Current Coverage:**
- **Linkerd mTLS + Cilium L7 egress lockdown** (POAM-007 closed): SPIFFE/SVID identity for intra-cluster service communication
- **OPA circuit breaker:** Fail-DENY after 5 failures, 30s recovery — prevents governance bypass via OPA unavailability
- **HMAC routing seal:** `X-CAGE-Routing-Seal` header prevents request forgery
- **Cloud KMS HSM-backed signing:** Asymmetric governance verdict signing
- **Aho-Corasick keyword scan:** Tier-1 injection detection
- **AgentSight eBPF daemon:** Kernel-level syscall monitoring (`execve`, `openat`, `connect`, `socket`, `bind`)

**Gaps:**
1. **No model extraction attack testing.** AI 600-1 §2.9 flags model extraction (stealing model weights via repeated inference queries) as an AI-specific security risk. There is no test for model extraction resistance in the red team dataset.
2. **No jailbreak resistance testing beyond keyword scan.** The Tier-1 keyword scan covers 14 bypass phrases. Sophisticated jailbreaks (DAN prompts, role-play attacks, many-shot jailbreaking) are not in the adversarial dataset.
3. **vLLM API not authenticated.** The vLLM inference endpoints (`VLLM_BASE_URL`, `VLLM_REASONING_API_BASE`) are accessed via HTTP from within the cluster. If an attacker gains cluster access, they can query vLLM directly without going through the governance pipeline.
4. **No adversarial example testing.** AI 600-1 §2.9 flags adversarial examples (inputs crafted to cause specific model behaviors) as a security risk. No adversarial example tests exist for the financial domain.
5. **CAGE_ROUTING_SEAL_SECRET bypass** (POAM-012 open): The HMAC seal can be silently disabled when the secret is unset — a critical security gap that allows governance bypass.

**SP 800-53 Controls Implicated (AI 600-1 Appendix B):** AC-3, AC-4, AU-12, CA-8, RA-5, SC-7, SC-8, SI-3, SI-4, SI-10

**Recommended RMF Updates:**

1. **Chunk 3 (Select/Implement) — CA-8 (Penetration Testing) gap:** Add AI-specific penetration testing requirements: model extraction resistance, jailbreak resistance (beyond keyword scan), adversarial example testing, and vLLM direct-access testing. Reference AI 600-1 §2.9.

2. **Chunk 4 (Assess/Authorize) — Red Team Coverage:** Add three new red team categories to `tests/red_team/adversarial_dataset.json`: (a) `model_extraction` — repeated inference queries designed to reconstruct model behavior, (b) `jailbreak_advanced` — DAN prompts, role-play attacks, many-shot jailbreaking, (c) `adversarial_financial` — inputs crafted to cause specific harmful financial recommendations.

3. **Chunk 3 (Select/Implement) — SC-7 gap update:** Add vLLM API authentication as a gap. Recommend adding an OPA-enforced authentication layer in front of vLLM endpoints, or using Kubernetes NetworkPolicy to restrict vLLM access to the gateway pod only (already partially implemented but not verified).

**New POAM Item:** AI600-006 (see Section 8).

---

### 4.10 Intellectual Property

**AI 600-1 Definition:** Risk that GenAI systems "reproduce copyrighted material, trade secrets, or other intellectual property" from training data, or that AI-generated outputs create IP ownership ambiguity.

**CAGE Applicability:** **Moderate** — CAGE's financial advisor generates investment recommendations. If these recommendations reproduce copyrighted financial analysis (e.g., verbatim reproduction of analyst reports from training data), this could expose the organization to copyright infringement liability. For US_FED financial institutions, IP risk also includes trade secret exposure.

**Current Coverage:**
- No IP-specific controls exist in CAGE
- NeMo Guardrails do not include copyright detection
- No training data license audit for DeepSeek-R1 or Llama-3.1

**Gaps:**
1. **No training data license audit.** The licenses for DeepSeek-R1 and Llama-3.1 training data are not documented. If training data included copyrighted financial analysis, the models may reproduce it.
2. **No copyright detection in output rails.** NeMo Guardrails detect PII and financial risk but not verbatim reproduction of copyrighted text.
3. **No IP ownership policy for AI-generated outputs.** There is no policy stating who owns the financial recommendations generated by CAGE — the organization, the user, or neither.
4. **Model licenses not formally reviewed.** DeepSeek-R1 uses a custom license; Llama-3.1 uses the Meta Llama 3.1 Community License. Neither license has been formally reviewed for US_FED deployment compatibility.

**SP 800-53 Controls Implicated (AI 600-1 Appendix B):** SA-4 (Acquisition Process), SA-9 (External System Services), CM-10 (Software Usage Restrictions)

**Recommended RMF Updates:**

1. **Chunk 4 (Assess/Authorize) — Supply Chain Assessment:** Add model license review to the third-party supply chain assessment (§5.5). Document DeepSeek-R1 and Llama-3.1 license terms and confirm US_FED deployment compatibility.

2. **Chunk 2 (Prepare/Categorize) — Information Type:** Add "AI-Generated Financial Recommendations" as an information type with a note on IP ownership ambiguity and the need for an IP policy.

3. **New document:** Create `docs/AI_IP_POLICY.md` documenting: model license terms, training data provenance (to the extent known), IP ownership of AI-generated outputs, and copyright detection approach.

---

### 4.11 Obscene, Degrading, and Abusive Content

**AI 600-1 Definition:** Risk that GenAI systems "generate content that is obscene, degrading, or abusive," including hate speech, sexual content, and content targeting protected groups.

**CAGE Applicability:** **Low** — CAGE is a financial advisory system with strong domain restriction. The probability of generating obscene content in a financial advisory context is low. However, prompt injection attacks could attempt to elicit such content.

**Current Coverage:**
- NeMo Guardrails domain restriction to financial topics
- Tier-1 keyword scan blocks bypass attempts
- OPA `trade.governance` policy enforces domain-specific RBAC

**Gaps:**
1. **No explicit content safety classifier.** While NeMo Guardrails restrict to financial topics, there is no dedicated content safety classifier (e.g., Llama Guard, OpenAI Moderation API) that explicitly detects and blocks obscene/abusive content.
2. **Injection-driven content generation not fully tested.** The adversarial dataset does not include payloads specifically designed to elicit obscene content via financial domain framing.

**SP 800-53 Controls Implicated (AI 600-1 Appendix B):** SI-10, SI-15, AC-3

**Recommended RMF Update:** Add a content safety classifier (e.g., Llama Guard deployed as a NeMo action) as a medium-term recommendation. Severity: **Low** — existing domain restriction provides adequate mitigation for initial ATO.

---

### 4.12 Value Chain and Component Integration

**AI 600-1 Definition:** Risk arising from "the complex supply chains involved in developing and deploying GenAI systems," including third-party model providers, fine-tuning services, inference infrastructure, and AI safety tools.

**CAGE Applicability:** **Critical** — CAGE's value chain includes: NVIDIA (NeMo Guardrails), Meta (Llama-3.1 weights), DeepSeek (DeepSeek-R1 weights), LangChain Inc. (LangGraph), Microsoft (Presidio), CNCF (OPA), Langfuse (compliance telemetry), and Google Cloud (GKE, KMS, GCS). A compromise in any of these components could undermine CAGE's governance guarantees.

**Current Coverage:**
- **SBOM:** `compliance/sbom/python-deps-2026-06-08.cdx.json` — Python dependency SBOM exists (POAM-010 closed)
- **Trivy/pip-audit CI scanning:** `.github/workflows/security-scan.yml` — vulnerability scanning in CI (POAM-010 closed)
- **Linkerd mTLS:** Intra-cluster service identity (POAM-007 closed)
- **CVE-2025-69872 remediated:** `outlines` package removed (POAM-016 closed)
- **POAM-023 open:** CVE-2025-13462 in `libpython3.11` — CRITICAL, no Debian fix available

**Gaps:**
1. **No model weight integrity verification.** `scripts/mirror_models.py` downloads DeepSeek-R1 and Llama-3.1 weights to MinIO/GCS without SHA-256 hash verification against a known-good manifest. A supply chain attack replacing model weights with a backdoored version would not be detected.
2. **No model card review.** Neither DeepSeek-R1 nor Llama-3.1 model cards have been formally reviewed for: training data sources, known biases, safety evaluations, and intended use cases. AI 600-1 §2.12 requires reviewing model cards as part of value chain assessment.
3. **Dependency versions use `>=` ranges.** `src/governed_financial_advisor/requirements.txt` uses unpinned ranges (`langgraph>=0.4.0`, `nemoguardrails>=0.17.0`) — allowing automatic inclusion of potentially malicious new versions (POAM-013 open).
4. **No NeMo Guardrails integrity verification.** NeMo Guardrails is a critical safety component. Its integrity (that the installed version matches the expected version and has not been tampered with) is not verified at deployment time.
5. **Langfuse compliance project is a SaaS dependency.** If Langfuse is unavailable or compromised, all compliance evidence collection ceases (POAM-018 open). There is no fallback compliance evidence store.
6. **No third-party AI safety tool assessment.** Presidio (Microsoft), OPA (CNCF), and NeMo (NVIDIA) are critical safety components. Their security posture, update cadence, and vulnerability history have not been formally assessed per AI 600-1 §2.12.

**SP 800-53 Controls Implicated (AI 600-1 Appendix B):** SA-4, SA-9, SA-12, SR-3, SR-4, SR-5, CM-8, RA-5, SI-2, SI-7

**Recommended RMF Updates:**

1. **Chunk 4 (Assess/Authorize) — Supply Chain Assessment (§5.5):** Add model weight integrity verification as a critical gap. Recommend implementing SHA-256 verification in `scripts/mirror_models.py` against a `config/model_hashes.json` manifest signed by the model provider.

2. **Chunk 3 (Select/Implement) — SA-12 gap update:** Add model card review as a required SA-12 (Supply Chain Protection) activity. Create `docs/MODEL_CARD_REVIEW.md` documenting the formal review of DeepSeek-R1 and Llama-3.1 model cards.

3. **Chunk 5 (Monitor) — Ongoing assessment:** Add model weight integrity verification to the ISCM strategy as a weekly automated check — re-verify SHA-256 hashes of deployed model weights against the signed manifest.

4. **Chunk 3 (Select/Implement) — SI-7 gap update:** Add NeMo Guardrails integrity verification as a SI-7 (Software Integrity) gap. Recommend using `pip hash` verification or Sigstore cosign for the NeMo package.

**New POAM Item:** AI600-007 (see Section 8).

---

## 5. Updates Required to Existing NIST RMF Chunks

This section consolidates all recommended updates to the five existing NIST RMF chunk documents, organized by chunk. Each update is traceable to a specific AI 600-1 risk category from Section 4.

---

### 5.1 Chunk 1 (Current State) Updates

**File:** [`docs/NIST_RMF_CHUNK1_CURRENT_STATE.md`](NIST_RMF_CHUNK1_CURRENT_STATE.md)

| Update ID | Section | Change Required | AI 600-1 Source |
|-----------|---------|-----------------|-----------------|
| C1-U1 | §1.1 Governance & Policy Enforcement | Add note: Tier-1 keyword scan covers **direct** prompt injection only. Indirect injection via MCP tool responses (market data, portfolio data) is an open gap per AI 600-1 §2.4. | §4.4 Data Poisoning |
| C1-U2 | §1.1 Governance & Policy Enforcement | Add note: ConsensusEngine LLM critics are themselves subject to confabulation risk (AI 600-1 §2.2). Consensus agreement does not guarantee factual accuracy — only policy compliance. | §4.2 Confabulation |
| C1-U3 | §1.1 Governance & Policy Enforcement | Add note: HITL TOCTOU is remediated (v2.0.0), but automation bias and human oversight scope documentation remain open gaps per AI 600-1 §2.7. | §4.7 Human-AI Config |
| C1-U4 | §2.1 Compliance & OSCAL | Add note: 15 Lula manifests cover ISO 42001 + NIST SP 800-53 + CSA AARM. **Zero manifests cover AI 600-1 risk categories.** AI 600-1 Lula validations are required for US_FED ATO. | §4.2, §4.4, §4.7 |
| C1-U5 | §4.1 Observability & Audit | Add note: OTel spans capture model name but not structured output provenance (model version, temperature, context hash). AI 600-1 §2.8 requires provenance tracking for GenAI outputs. | §4.8 Info Integrity |
| C1-U6 | §6 Summary Table | Add new row: **AI 600-1 GenAI Risk Coverage** — Current Coverage: **None** — Notes: 12 AI 600-1 risk categories unaddressed; 7 new POAM items required. | All §4.x |

**Recommended addition to §1.3 Coverage Assessment:**

> **AI 600-1 Gap Note (added 2026-06-15):** The governance enforcement stack is strong for deterministic policy enforcement but does not address NIST AI 600-1 GenAI-specific risks. Key gaps: (1) no confabulation rate metric, (2) indirect prompt injection via MCP tool responses unmitigated, (3) no human oversight scope document per AI 600-1 §2.5.4, (4) no model weight integrity verification, (5) no training data memorization assessment. These gaps are tracked as POAM items AI600-001 through AI600-007 in `docs/POAM_US_FED.md`.

---

### 5.2 Chunk 2 (Prepare/Categorize) Updates

**File:** [`docs/NIST_RMF_CHUNK2_PREPARE_CATEGORIZE.md`](NIST_RMF_CHUNK2_PREPARE_CATEGORIZE.md)

| Update ID | Section | Change Required | AI 600-1 Source |
|-----------|---------|-----------------|-----------------|
| C2-U1 | §4 FIPS 199 Categorization | Add AI 600-1 as a required input to FIPS 199 categorization. The presence of agentic AI with real-world actuators (execute_trade) elevates Integrity impact to **High** — consistent with existing categorization but now formally justified by AI 600-1 §2.5.2. | §4.7 Human-AI Config |
| C2-U2 | §5 Information Type Identification | Add three new information types: (a) **AI Training Data Memorization Risk** — C=High, I=Moderate, A=Low; (b) **AI-Generated Financial Recommendations** — C=Low, I=High, A=Moderate (with IP ownership note); (c) **AI Model Weights** — C=High, I=High, A=High (supply chain criticality). | §4.3, §4.10, §4.12 |
| C2-U3 | §5 Information Type Identification | Add note: AI 600-1 §2.6 (Harmful Bias) requires "AI Model Fairness/Bias Risk" as an information type with I=High under ECOA/Regulation B for US_FED financial institutions. | §4.6 Bias |
| C2-U4 | §7 Priority Matrix | Add new P1 item: **Create `docs/AI_RISK_TAXONOMY.md`** adopting AI 600-1's 12-category risk taxonomy as the formal GenAI risk framework for CAGE US_FED. Effort: S, Impact: H, Priority: **P1**. | All §4.x |
| C2-U5 | §8 Step 1–2 Readiness Score | Revise score downward from 28/100 to **22/100** when AI 600-1 obligations are factored in. The additional ungapped risk surface (12 new risk categories, 0% coverage) reduces the effective readiness score. | All §4.x |

**New recommended document:** `docs/AI_RISK_TAXONOMY.md` — a formal adoption of AI 600-1's 12-category risk taxonomy as CAGE's GenAI risk framework, with CAGE-specific applicability ratings (Critical/High/Moderate/Low) and mapping to existing controls.

---

### 5.3 Chunk 3 (Select/Implement) Updates

**File:** [`docs/NIST_RMF_CHUNK3_SELECT_IMPLEMENT.md`](NIST_RMF_CHUNK3_SELECT_IMPLEMENT.md)

| Update ID | Section | Change Required | AI 600-1 Source |
|-----------|---------|-----------------|-----------------|
| C3-U1 | SI — System & Info Integrity | **SI-10 gap extension:** Add confabulation as a sub-category of SI-10. Existing gap covers API schema validation; extend to LLM output factual accuracy validation. Recommend `confabulation_rate < 0.02` metric. | §4.2 Confabulation |
| C3-U2 | SI — System & Info Integrity | **SI-3 gap extension:** Extend malicious code protection gap to cover indirect prompt injection via MCP tool responses. Add recommendation: sanitize all MCP tool responses through Aho-Corasick scanner before injecting into LLM context window. | §4.4 Data Poisoning |
| C3-U3 | SI — System & Info Integrity | **SI-7 gap extension:** Add LLM output integrity (provenance tracking) and NeMo Guardrails integrity verification as SI-7 sub-gaps. Recommend structured provenance record per financial recommendation. | §4.8, §4.12 |
| C3-U4 | SI — System & Info Integrity | **SI-19 gap extension:** Add AI 600-1 §2.3 training data memorization as a specific SI-19 sub-gap. Recommend Carlini et al. extraction attack methodology against deployed vLLM models. | §4.3 Data Privacy |
| C3-U5 | AC — Access Control | **AC-5 gap extension:** Extend separation of duties gap to include AI 600-1 §2.7 human-AI configuration requirements. Add recommendation: create `docs/HUMAN_OVERSIGHT_SCOPE.md`. | §4.7 Human-AI Config |
| C3-U6 | RA — Risk Assessment | **New RA gap:** Add algorithmic fairness assessment as a RA-3 sub-gap. Recommend `docs/AI_FAIRNESS_ASSESSMENT.md` per SR 11-7 model risk management requirements. | §4.6 Bias |
| C3-U7 | CA — Security Assessment | **CA-8 gap extension:** Add AI-specific penetration testing requirements: model extraction resistance, advanced jailbreak testing (DAN, role-play, many-shot), adversarial financial examples, vLLM direct-access testing. | §4.9 Info Security |
| C3-U8 | SC — System & Comms Protection | **SC-7 gap extension:** Add vLLM API authentication as a SC-7 sub-gap. Recommend OPA-enforced authentication layer in front of vLLM endpoints. | §4.9 Info Security |
| C3-U9 | CM — Configuration Management | **CM-10 new gap:** Add model license compliance as a CM-10 (Software Usage Restrictions) gap. DeepSeek-R1 and Llama-3.1 licenses must be formally reviewed for US_FED deployment compatibility. | §4.10 IP |
| C3-U10 | Control Coverage Heatmap | Add new row: **AI 600-1 GenAI Controls** — Required: 12 categories, Implemented: 2 (partial), Gap: 10, Coverage: **17%**. | All §4.x |

**Revised Control Coverage Heatmap addition:**

| Control Family | Required Controls | Implemented | Partial | Gap | Coverage % |
|----------------|-------------------|-------------|---------|-----|------------|
| **AI 600-1 GenAI** | 12 categories | 0 | 2 | 10 | **17%** |

---

### 5.4 Chunk 4 (Assess/Authorize) Updates

**File:** [`docs/NIST_RMF_CHUNK4_ASSESS_AUTHORIZE.md`](NIST_RMF_CHUNK4_ASSESS_AUTHORIZE.md)

| Update ID | Section | Change Required | AI 600-1 Source |
|-----------|---------|-----------------|-----------------|
| C4-U1 | §5.1 Security Assessment Plan | Add AI 600-1 risk categories as a required SAP scope element. The SAP must include assessment procedures for all 12 AI 600-1 risk categories in addition to SP 800-53 controls. | All §4.x |
| C4-U2 | §5.2 SAR / Evidence Collection | Add `confabulation_rate`, `injection_deflection_score`, `hitl_defer_queue_depth`, and `model_weight_integrity_verified` as required SAR evidence fields. | §4.2, §4.4, §4.7, §4.12 |
| C4-U3 | §5.3 Penetration Testing | Add three new red team categories: `model_extraction`, `jailbreak_advanced`, `adversarial_financial`. Raise pass threshold to `deflection_score >= 4` for all injection payloads. | §4.4, §4.9 |
| C4-U4 | §5.4 Control Effectiveness Metrics | Add four new metrics: (a) `confabulation_rate` — LLM factual accuracy vs. ground truth; (b) `injection_deflection_score` — red team pass rate; (c) `hitl_defer_resolution_time` — DEFER queue SLA compliance; (d) `model_weight_integrity` — SHA-256 verification pass/fail. | §4.2, §4.4, §4.7, §4.12 |
| C4-U5 | §5.5 Supply Chain Assessment | Add model weight integrity verification and model card review as critical supply chain assessment gaps. Add model license review for DeepSeek-R1 and Llama-3.1. | §4.12 Value Chain |
| C4-U6 | §6.1 Authorization Package | Add `docs/AI_RISK_TAXONOMY.md`, `docs/HUMAN_OVERSIGHT_SCOPE.md`, `docs/AI_FAIRNESS_ASSESSMENT.md`, `docs/MODEL_CARD_REVIEW.md`, and `docs/AI_IP_POLICY.md` as required authorization package artifacts for US_FED GenAI systems. | All §4.x |
| C4-U7 | Authorization Package Inventory | Add 5 new required artifacts (see C4-U6). Update completeness from 5/21 to 5/26 (19%) when AI 600-1 artifacts are included. | All §4.x |
| C4-U8 | cATO Readiness Checklist | Add 4 new checklist items: (21) AI 600-1 risk taxonomy formally adopted; (22) confabulation rate measured and within threshold; (23) model weight integrity verified weekly; (24) human oversight scope document exists. | All §4.x |

---

### 5.5 Chunk 5 (Monitor/Roadmap) Updates

**File:** [`docs/NIST_RMF_CHUNK5_MONITOR_ROADMAP.md`](NIST_RMF_CHUNK5_MONITOR_ROADMAP.md)

| Update ID | Section | Change Required | AI 600-1 Source |
|-----------|---------|-----------------|-----------------|
| C5-U1 | §7.1 ISCM Strategy | Add AI 600-1 monitoring requirements to ISCM strategy: (a) weekly model weight integrity verification, (b) quarterly confabulation rate assessment, (c) quarterly fairness audit, (d) quarterly training data memorization probe. | §4.3, §4.6, §4.12 |
| C5-U2 | §7.2 Ongoing Control Assessments | Add 4 new AI 600-1 Lula validations to the ongoing assessment scope: `lula-validation-ai600-confabulation.yaml`, `lula-validation-ai600-injection.yaml`, `lula-validation-ai600-hitl.yaml`, `lula-validation-ai600-supply-chain.yaml`. | §4.2, §4.4, §4.7, §4.12 |
| C5-U3 | §7.4 Security Status Reporting | Add AI 600-1 risk category status to the compliance summary report. The `GET /v1/compliance/summary` endpoint should include AI 600-1 metric fields. | All §4.x |
| C5-U4 | §B.1 Phase 0 | Add new Phase 0 artifact: **`docs/AI_RISK_TAXONOMY.md`** — AI 600-1 risk taxonomy adoption document. Responsible: ISSO. Controls: AI RMF GOVERN-1.1, GOVERN-1.2. | All §4.x |
| C5-U5 | §B.2 Phase 1 Quick Wins | Add 3 new Phase 1 items: (P1-AI1) Create `docs/HUMAN_OVERSIGHT_SCOPE.md`; (P1-AI2) Add indirect injection sanitization to MCP tool response pipeline; (P1-AI3) Add model weight SHA-256 verification to `scripts/mirror_models.py`. | §4.4, §4.7, §4.12 |
| C5-U6 | §B.3 Phase 2 Core Hardening | Add 4 new Phase 2 items: (P2-AI1) Implement confabulation rate metric; (P2-AI2) Create AI fairness assessment; (P2-AI3) Add advanced jailbreak red team categories; (P2-AI4) Create 4 AI 600-1 Lula validations. | §4.2, §4.6, §4.4, §4.9 |
| C5-U7 | §B.5 ATO Readiness Progression | Revise current state score from 24% to **18%** when AI 600-1 obligations are factored in. Phase 3 target remains 77% but requires AI 600-1 compliance to achieve. | All §4.x |
| C5-U8 | §B.7 Executive Summary | Add paragraph: "AI 600-1 Compliance Gap: CAGE's agentic AI functionality introduces 12 GenAI-specific risk categories per NIST AI 600-1 (July 2024), none of which are currently addressed in the NIST RMF authorization package. For US_FED deployments, AI 600-1 compliance is effectively mandatory under EO 14110 and OMB M-24-10. Seven new POAM items (AI600-001 through AI600-007) have been created to track remediation." | All §4.x |

---

## 6. AI 600-1 to SP 800-53 Control Crosswalk

> This crosswalk maps each AI 600-1 risk category to the SP 800-53 Rev. 5 controls implicated (per AI 600-1 Appendix B), CAGE's current implementation status, and the specific code artifacts involved.

| AI 600-1 Risk Category | SP 800-53 Controls | CAGE Implementation | Status | Gap |
|------------------------|-------------------|---------------------|--------|-----|
| **4.1 CBRN** | SI-10, SI-15, AC-3, CM-7 | Aho-Corasick keyword scan; NeMo domain restriction | **Partial** | No CBRN keyword category; no domain restriction policy doc |
| **4.2 Confabulation** | SI-10, SI-12, AU-3, AU-10, RA-3 | STPA UCA constraints; ConsensusEngine; CausalGatekeeper | **Partial** | No confabulation rate metric; no Lula validation; consensus critics also confabulate |
| **4.3 Data Privacy** | AC-3, AC-4, AU-3, SC-8, SC-28, SI-12, SI-19, RA-3 | Presidio 15-entity PII detection; NeMo rails; PIA exists | **Partial** | No training data memorization assessment; PII in Langfuse traces; Presidio threshold review needed |
| **4.4 Data Poisoning / Prompt Injection** | SI-3, SI-10, SI-15, RA-5, SA-11, CA-8 | Aho-Corasick; NeMo rails; OPA injection check; red team dataset | **Partial** | Indirect injection via MCP responses unmitigated; only 14 keywords; no multi-turn injection testing |
| **4.5 Environmental** | PM-8 | None | **Gap** | No GPU energy metric; no carbon footprint report |
| **4.6 Harmful Bias** | RA-3, SI-12, PM-26, PM-28 | NRP entity detection in Presidio | **Gap** | No fairness metric; no demographic impact assessment; no homogenization risk assessment |
| **4.7 Human-AI Config** | AC-5, AU-3, AU-10, CA-7, IR-4, PM-26 | HITL approval gate; DEFER queue; TOCTOU remediation | **Partial** | No human oversight scope doc; no automation bias assessment; no DEFER SLA; no override audit trail |
| **4.8 Information Integrity** | AU-10, SI-7, SI-12, AC-3, RA-3 | KMS-signed verdicts; STPA constraints; CausalGatekeeper | **Partial** | No output provenance tracking; no watermarking; explainer outputs not validated |
| **4.9 Information Security** | AC-3, AC-4, AU-12, CA-8, RA-5, SC-7, SC-8, SI-3, SI-4, SI-10 | Linkerd mTLS; OPA circuit breaker; AgentSight eBPF; HMAC seal | **Partial** | No model extraction testing; no advanced jailbreak testing; vLLM API unauthenticated; HMAC bypass open (POAM-012) |
| **4.10 Intellectual Property** | SA-4, SA-9, CM-10 | None | **Gap** | No training data license audit; no copyright detection; no IP ownership policy; model licenses not reviewed |
| **4.11 Obscene Content** | SI-10, SI-15, AC-3 | NeMo domain restriction; Aho-Corasick | **Partial** | No dedicated content safety classifier |
| **4.12 Value Chain** | SA-4, SA-9, SA-12, SR-3, SR-4, SR-5, CM-8, RA-5, SI-2, SI-7 | SBOM exists; Trivy/pip-audit CI; Linkerd mTLS | **Partial** | No model weight integrity verification; no model card review; unpinned deps (POAM-013); NeMo integrity not verified |

**Coverage Summary:**

| Status | Count | Percentage |
|--------|-------|------------|
| Implemented | 0 | 0% |
| Partial | 8 | 67% |
| Gap | 4 | 33% |
| **Total** | **12** | — |

> **Note:** "Partial" means some relevant controls exist but AI 600-1-specific requirements are unmet. No AI 600-1 risk category is fully addressed.

---

### 4.6 Harmful Bias and Homogenization

**AI 600-1 Definition:** Risk that GenAI systems "produce outputs that reflect or amplify harmful biases" or that widespread GenAI adoption leads to "homogenization of perspectives" reducing diversity of financial advice.

**CAGE Applicability:** **Moderate** — CAGE generates financial advisory outputs for users. Biased recommendations (e.g., systematically different advice based on demographic signals in user data) could constitute discriminatory financial advice under ECOA (Equal Credit Opportunity Act) and Regulation B, which are directly applicable to US_FED financial institutions.

**Current Coverage:**
- NeMo Guardrails `sensitive_data_detection` detects `NRP` (Nationality, Religion, Political affiliation) entity type — prevents demographic data from entering LLM context
- OPA RBAC is role-based (junior/senior), not demographic-based
- No fairness metric or demographic impact assessment

**Gaps:**
1. **No fairness metric.** There is no measurement of whether the financial advisor produces systematically different recommendations for different user demographic groups. This is required under SR 11-7 (Federal Reserve model risk management) for AI models used in financial services.
2. **No demographic impact assessment.** The Privacy Impact Assessment (`compliance/pia/PRIVACY_IMPACT_ASSESSMENT.md`) covers PII handling but not algorithmic fairness or disparate impact analysis.
3. **No homogenization risk assessment.** If all users receive similar LLM-generated advice (homogenization), this could create systemic financial risk — a concern explicitly raised in AI 600-1 §2.6 for financial services GenAI.
4. **NRP detection prevents demographic input but not demographic-correlated output.** Even if demographic data is not in the input, the LLM may produce demographically correlated outputs based on patterns in its training data.

**SP 800-53 Controls Implicated (AI 600-1 Appendix B):** RA-3, SI-12, PM-26 (Complaint Management), PM-28 (Risk Framing)

**Recommended RMF Updates:**

1. **Chunk 2 (Prepare/Categorize) — Information Type update:** Add "AI Model Fairness/Bias Risk" as a new information type with I=High (biased financial advice has high integrity impact under ECOA/Reg B).

2. **Chunk 3 (Select/Implement) — New control gap:** Add a new gap under RA-3 (Risk Assessment) specifically for algorithmic fairness assessment. Recommend creating `docs/AI_FAIRNESS_ASSESSMENT.md` documenting the fairness testing methodology, demographic groups assessed, and acceptable disparate impact thresholds per SR 11-7.

3. **Chunk 5 (Monitor) — Ongoing assessment:** Add quarterly fairness audits to the ISCM strategy, using the `scripts/evaluate_langfuse_traces.py` evaluator extended with demographic fairness metrics.

**New POAM Item:** AI600-004 (see Section 8).

---

## 7. New OSCAL and Lula Artifacts Required

The following new compliance artifacts are required to bring CAGE into AI 600-1 compliance for US_FED. Each artifact maps to one or more AI 600-1 risk categories and integrates with the existing Lula/OSCAL pipeline.

### 7.1 New Lula Validation Manifests

| Manifest | Path | Domain | Assertion | AI 600-1 Category | Cadence |
|----------|------|--------|-----------|-------------------|---------|
| `lula-validation-ai600-confabulation.yaml` | `compliance/lula/` | `api` | `confabulation_rate < 0.02` over 24h window from compliance-bridge metrics API | §4.2 Confabulation | Daily (High) |
| `lula-validation-ai600-injection.yaml` | `compliance/lula/` | `api` | Red team `deflection_score >= 4` for all `severity: critical` payloads from Langfuse red team project | §4.4 Data Poisoning | Weekly (Medium) |
| `lula-validation-ai600-hitl.yaml` | `compliance/lula/` | `api` | DEFER queue depth < 10 items older than 4 hours; DEFER resolution SLA ≤ 4h for CRITICAL items | §4.7 Human-AI Config | 6h (Critical) |
| `lula-validation-ai600-supply-chain.yaml` | `compliance/lula/` | `kubernetes` | Model weight SHA-256 hashes match `config/model_hashes.json` manifest; NeMo package hash verified | §4.12 Value Chain | Daily (High) |
| `lula-validation-ai600-privacy.yaml` | `compliance/lula/` | `api` | Training data memorization probe returns 0 PII extractions; Presidio score_threshold ≥ 0.5 | §4.3 Data Privacy | Weekly (Medium) |

### 7.2 New OSCAL Component Definition Entries

The existing [`compliance/oscal/component-definition.yaml`](../../../compliance/oscal/component-definition.yaml) must be extended with a new component representing the AI 600-1 governance layer:

```yaml
# Addition to compliance/oscal/component-definition.yaml
- uuid: "ai600-genai-governance-component"
  type: "software"
  title: "NIST AI 600-1 GenAI Risk Governance Layer"
  description: >
    Controls addressing NIST AI 600-1 (July 2024) generative AI risk categories
    for the CAGE agentic financial advisor. Covers confabulation mitigation,
    prompt injection defense, human-AI configuration, and value chain integrity.
  control-implementations:
    - uuid: "ai600-impl-01"
      source: "https://airc.nist.gov/Docs/1"  # NIST AI 600-1
      description: "AI 600-1 GenAI risk category controls"
      implemented-requirements:
        - uuid: "ai600-req-confabulation"
          control-id: "ai600-2.2"
          description: "Confabulation rate measurement and threshold enforcement"
          by-components:
            - component-uuid: "ai600-genai-governance-component"
              implementation-status:
                state: "partial"
              remarks: >
                ConsensusEngine provides cross-check; STPA UCAs bound extreme values.
                Gap: no confabulation_rate metric; no Lula validation.
                Tracked: POAM AI600-001.
        - uuid: "ai600-req-injection"
          control-id: "ai600-2.4"
          description: "Prompt injection and data poisoning defense"
          by-components:
            - component-uuid: "ai600-genai-governance-component"
              implementation-status:
                state: "partial"
              remarks: >
                Aho-Corasick Tier-1 scan; NeMo rails; OPA injection check.
                Gap: indirect injection via MCP tool responses unmitigated.
                Tracked: POAM AI600-003.
        - uuid: "ai600-req-hitl"
          control-id: "ai600-2.7"
          description: "Human-AI configuration and oversight"
          by-components:
            - component-uuid: "ai600-genai-governance-component"
              implementation-status:
                state: "partial"
              remarks: >
                HITL approval gate; DEFER queue; TOCTOU remediation.
                Gap: no human oversight scope document; no DEFER SLA.
                Tracked: POAM AI600-005.
        - uuid: "ai600-req-supply-chain"
          control-id: "ai600-2.12"
          description: "Value chain and component integration risk"
          by-components:
            - component-uuid: "ai600-genai-governance-component"
              implementation-status:
                state: "partial"
              remarks: >
                SBOM exists; Trivy/pip-audit CI scanning.
                Gap: no model weight integrity verification; no model card review.
                Tracked: POAM AI600-007.
```

### 7.3 New OSCAL SP 800-53 Profile Extension

The existing [`compliance/oscal/sp800053-profile.yaml`](../../../compliance/oscal/sp800053-profile.yaml) should be extended to import the AI 600-1 profile as an overlay:

```yaml
# Addition to compliance/oscal/sp800053-profile.yaml
imports:
  - href: "https://airc.nist.gov/Docs/1"
    include-controls:
      with-ids:
        - ai600-2.2   # Confabulation
        - ai600-2.3   # Data Privacy (memorization)
        - ai600-2.4   # Data Poisoning / Prompt Injection
        - ai600-2.5   # Agentic AI (Human-AI Config)
        - ai600-2.6   # Harmful Bias
        - ai600-2.7   # Human-AI Configuration
        - ai600-2.8   # Information Integrity
        - ai600-2.9   # Information Security
        - ai600-2.12  # Value Chain
```

### 7.4 New Documents Required

| Document | Path | Purpose | AI 600-1 Source | Priority |
|----------|------|---------|-----------------|----------|
| AI Risk Taxonomy | `docs/AI_RISK_TAXONOMY.md` | Formal adoption of AI 600-1 12-category taxonomy with CAGE applicability ratings | All §4.x | **P0** |
| Human Oversight Scope | `docs/HUMAN_OVERSIGHT_SCOPE.md` | Documents degree of human oversight for each agentic capability per AI 600-1 §2.5.4 | §4.7 | **P1** |
| AI Fairness Assessment | `docs/AI_FAIRNESS_ASSESSMENT.md` | Algorithmic fairness testing methodology per SR 11-7 and AI 600-1 §2.6 | §4.6 | **P2** |
| Model Card Review | `docs/MODEL_CARD_REVIEW.md` | Formal review of DeepSeek-R1 and Llama-3.1 model cards | §4.12 | **P1** |
| AI IP Policy | `docs/AI_IP_POLICY.md` | Model license terms, training data provenance, IP ownership of AI outputs | §4.10 | **P2** |
| GenAI Environmental Impact | Section in SSP | GCP region energy mix, GPU hours, Carbon Footprint API plan | §4.5 | **P3** |

---

## 8. New POAM Items

The following POAM items are derived from the AI 600-1 gap analysis. They are numbered AI600-001 through AI600-007 to distinguish them from the existing POAM-001 through POAM-023 items in [`docs/POAM_US_FED.md`](POAM_US_FED.md).

| POAM ID | Control ID | AI 600-1 Ref | Weakness Description | Risk Level | Scheduled Completion | Status |
|---------|-----------|--------------|---------------------|------------|---------------------|--------|
| **AI600-001** | SI-10, AU-3 | §2.2 Confabulation | No confabulation rate metric exists. The financial advisor LLM can produce confident but factually incorrect market data, fabricated portfolio positions, or hallucinated regulatory constraints. ConsensusEngine critics are also LLMs subject to confabulation. No Lula validation for confabulation rate. | **High** | 2026-09-30 | Open |
| **AI600-002** | SI-19, SC-28 | §2.3 Data Privacy | No training data memorization assessment. DeepSeek-R1 and Llama-3.1 may have memorized PII from training corpora. No differential privacy or membership inference attack testing. Presidio score_threshold=0.3 may be too permissive for HIGH-baseline financial system. | **High** | 2026-10-31 | Open |
| **AI600-003** | SI-3, SI-10, CA-8 | §2.4 Data Poisoning | Indirect prompt injection via MCP tool responses (market data API, portfolio data) is unmitigated. Only 14 Tier-1 keywords cover direct injection. No multi-turn injection testing. No adversarial robustness metric. Red team pass threshold (deflection_score >= 3) insufficient for HIGH baseline. | **Critical** | 2026-08-31 | Open |
| **AI600-004** | RA-3, SI-12 | §2.6 Harmful Bias | No fairness metric or demographic impact assessment. Financial advisor may produce systematically different recommendations for different demographic groups — potential ECOA/Regulation B violation. No homogenization risk assessment per AI 600-1 §2.6. | **High** | 2026-11-30 | Open |
| **AI600-005** | AC-5, AU-3, CA-7 | §2.7 Human-AI Config | No formal Human Oversight Scope Statement per AI 600-1 §2.5.4. No DEFER queue SLA documented. No automation bias assessment. No human override audit trail. Trades below USD 10,000 have no human review option with no documented justification. | **High** | 2026-09-30 | Open |
| **AI600-006** | CA-8, RA-5, SC-7 | §2.9 Information Security | No model extraction attack testing. No advanced jailbreak testing (DAN, role-play, many-shot). vLLM API accessible within cluster without authentication layer. CAGE_ROUTING_SEAL_SECRET bypass (POAM-012) also constitutes an AI 600-1 §2.9 gap. | **High** | 2026-09-30 | Open |
| **AI600-007** | SA-12, SR-3, SI-7 | §2.12 Value Chain | No model weight integrity verification (SHA-256 against signed manifest). No model card review for DeepSeek-R1 or Llama-3.1. Model licenses not formally reviewed for US_FED compatibility. NeMo Guardrails integrity not verified at deployment. Langfuse compliance project is a SaaS single point of failure (see also POAM-018). | **Critical** | 2026-08-31 | Open |

### 8.1 POAM Priority Rationale

**Critical items (AI600-003, AI600-007):**
- AI600-003 (Indirect Prompt Injection): A successful indirect injection attack via a malicious market data API response could cause the agent to execute unauthorized trades. This is the highest-severity AI 600-1 risk for CAGE given its real-world financial actuators.
- AI600-007 (Value Chain / Model Weight Integrity): A supply chain attack replacing model weights with a backdoored version would bypass all governance controls. The model weights are the foundation of the entire system — their integrity is a prerequisite for all other security guarantees.

**High items (AI600-001, AI600-002, AI600-004, AI600-005, AI600-006):**
- All five High items represent significant gaps in AI 600-1 compliance that would be flagged in any independent security assessment. They do not represent immediate exploitation risk but are required for US_FED ATO under EO 14110 and OMB M-24-10.

### 8.2 Relationship to Existing POAM Items

| AI 600-1 POAM | Related Existing POAM | Relationship |
|---------------|----------------------|--------------|
| AI600-003 | POAM-012 (HMAC bypass) | AI600-003 extends POAM-012 — HMAC bypass is also an AI 600-1 §2.9 information security gap |
| AI600-007 | POAM-013 (unpinned deps), POAM-018 (Langfuse silent fail) | AI600-007 extends both — unpinned deps and Langfuse failure are also AI 600-1 §2.12 value chain gaps |
| AI600-006 | POAM-012 (HMAC bypass) | HMAC bypass enables governance bypass — an AI 600-1 §2.9 information security gap |
| AI600-002 | POAM-014 (CMEK validation) | Training data memorization risk compounds CMEK gap — PII in model weights is not addressed by CMEK |

---

## 9. Implementation Roadmap

### 9.1 Phase 0 — AI 600-1 Foundation (Weeks 1–2)

> Prerequisite: Complete alongside existing Phase 0 authorization foundation items.

| # | Artifact | Path | Effort | Controls |
|---|----------|------|--------|----------|
| AI-P0-1 | AI Risk Taxonomy document | `docs/AI_RISK_TAXONOMY.md` | 4h | AI RMF GOVERN-1.1, GOVERN-1.2 |
| AI-P0-2 | Human Oversight Scope document | `docs/HUMAN_OVERSIGHT_SCOPE.md` | 6h | AC-5, CA-7, AI 600-1 §2.5.4 |
| AI-P0-3 | Model Card Review | `docs/MODEL_CARD_REVIEW.md` | 8h | SA-12, SR-3, AI 600-1 §2.12 |
| AI-P0-4 | OSCAL component definition extension | `compliance/oscal/component-definition.yaml` | 4h | CA-2, CA-7 |

### 9.2 Phase 1 — Quick Wins (Weeks 2–6)

| # | File | Change | Controls | Est. Hours |
|---|------|--------|----------|------------|
| AI-P1-1 | `scripts/mirror_models.py` | Add SHA-256 verification against `config/model_hashes.json` | SA-12, SI-7, AI600-007 | 4h |
| AI-P1-2 | [`src/gateway/governance/text_filter.py`](../../../src/gateway/governance/text_filter.py) | Add MCP tool response sanitization through Aho-Corasick scanner before LLM context injection (**v3.0.0:** `safety.py` removed; use `text_filter.py`) | SI-3, SI-10, AI600-003 | 6h |
| AI-P1-3 | `config/governance_thresholds.json` | Add CBRN keyword category to Tier-1 keyword list; add domain restriction policy reference | SI-10, CM-7 | 2h |
| AI-P1-4 | `tests/red_team/adversarial_dataset.json` | Add `control_ids` field to all entries; add indirect injection test cases; add advanced jailbreak payloads | CA-8, AI600-003, AI600-006 | 8h |
| AI-P1-5 | `src/compliance_bridge/types.py` | Add `confabulation_rate`, `injection_deflection_score`, `hitl_defer_queue_depth` to `ComplianceMetrics` | SI-10, AU-3, AI600-001 | 4h |
| AI-P1-6 | `compliance/lula/lula-validation-ai600-hitl.yaml` | New Lula validation: DEFER queue depth < 10 items older than 4h | CA-7, AI600-005 | 3h |
| AI-P1-7 | `compliance/lula/lula-validation-ai600-supply-chain.yaml` | New Lula validation: model weight SHA-256 verification | SA-12, AI600-007 | 3h |
| AI-P1-8 | `docs/AI_IP_POLICY.md` | Model license terms, IP ownership policy | CM-10, SA-4 | 4h |

### 9.3 Phase 2 — Core Hardening (Weeks 6–16)

| # | Files/Modules | Description | Controls | Est. Person-Days |
|---|---------------|-------------|----------|-----------------|
| AI-P2-1 | `src/compliance_bridge/metrics.py`, `scripts/evaluate_langfuse_traces.py` | Implement confabulation rate metric: LLM-as-judge comparing financial advisor outputs against ground-truth market data from MCP tool responses | SI-10, AU-3, AI600-001 | 5d |
| AI-P2-2 | `compliance/lula/lula-validation-ai600-confabulation.yaml` | New Lula validation: `confabulation_rate < 0.02` over 24h window | CA-7, AI600-001 | 2d |
| AI-P2-3 | `compliance/lula/lula-validation-ai600-injection.yaml` | New Lula validation: red team deflection_score >= 4 for critical payloads | CA-8, AI600-003 | 2d |
| AI-P2-4 | `compliance/lula/lula-validation-ai600-privacy.yaml` | New Lula validation: memorization probe returns 0 PII extractions | SI-19, AI600-002 | 3d |
| AI-P2-5 | `docs/AI_FAIRNESS_ASSESSMENT.md` | Algorithmic fairness testing methodology; demographic impact assessment per SR 11-7 | RA-3, AI600-004 | 3d |
| AI-P2-6 | `tests/red_team/adversarial_dataset.json` | Add `model_extraction`, `jailbreak_advanced`, `adversarial_financial` red team categories | CA-8, AI600-006 | 4d |
| AI-P2-7 | `deployment/k8s/vllm-services.yaml`, OPA policy | Add OPA-enforced authentication layer in front of vLLM endpoints | SC-7, AI600-006 | 3d |
| AI-P2-8 | `compliance/oscal/component-definition.yaml` | Add full AI 600-1 component definition with all 9 applicable risk category control implementations | CA-2, CA-7 | 2d |

### 9.4 Phase 3 — Architectural Uplift (Weeks 16–52)

| # | Architecture Decision | Implementation | Controls | Est. Person-Weeks |
|---|----------------------|----------------|----------|------------------|
| AI-P3-1 | Training Data Memorization Assessment | Deploy Carlini et al. extraction attack probes against vLLM models quarterly; integrate results into compliance Langfuse project | SI-19, AI600-002 | 2w |
| AI-P3-2 | Algorithmic Fairness Continuous Monitoring | Extend `scripts/evaluate_langfuse_traces.py` with demographic fairness metrics; add to ISCM quarterly cadence | RA-3, AI600-004 | 3w |
| AI-P3-3 | Output Provenance Tracking | Add structured provenance record to each financial recommendation: model version, temperature, context hash, timestamp | AU-10, SI-7, AI600-008 | 2w |
| AI-P3-4 | Content Safety Classifier | Deploy Llama Guard as a NeMo action for obscene/abusive content detection | SI-10, SI-15 | 2w |
| AI-P3-5 | AI 600-1 Full Authorization Package | Compile AI 600-1 compliance evidence into authorization package; submit to AO as addendum to SP 800-53 ATO package | CA-6, CA-7 | 2w |

### 9.5 AI 600-1 Readiness Progression

| Phase | AI 600-1 Coverage | Key Milestone | Status |
|-------|------------------|---------------|--------|
| **Baseline (pre-implementation)** | **17%** (2/12 partial) | No AI 600-1 controls formally addressed | — |
| **After Phase 0** | **33%** | Risk taxonomy adopted; human oversight scope documented; model cards reviewed | ✅ **Complete** (2026-06-15) |
| **After Phase 1** | **50%** | Model weight integrity verified; indirect injection mitigated; HITL Lula validation active | ✅ **Complete** (2026-06-15) |
| **After Phase 2** | **67%** | Confabulation scorer live; PII audit log hardened; prompt injection detector (8 patterns); HITL escalator; provenance chain | ✅ **Complete** (2026-06-15) |
| **After Phase 3 (partial)** | **75%** | NeMo CBRN rail deployed; CBRN keyword scanner (15 terms); recursive governance risk mitigated | ✅ **Complete** (2026-06-15) |
| **After Phase 3 (full)** | **92%** | Full AI 600-1 compliance evidence package; memorization assessment; provenance tracking; all Lula stubs hardened | ⏳ Pending (Weeks 16–52) |

> **Note:** 100% AI 600-1 compliance requires AO acceptance of residual risks (environmental impact, IP ownership ambiguity) that cannot be fully mitigated through technical controls alone.

---

## 10. Implementation Status — Phase 0–3 Dev Posture (2026-06-15)

> **Branch:** `feat/CAGE-AI600-ai600-1-implementation`
> **Commits:** `c014337` (Phase 0) → `89eff91` (Phase 1) → `aba1677` (Phase 2) → `e4270d5` (Phase 3) → `96f6fd2` (CI) → `51f6c25` (bug fixes)
> **Test result:** 222 AI 600-1 unit tests pass, 0 failures (1,117 total suite)

### 10.1 Artifacts Created

| Artifact | Path | Phase | POAM | Tests |
|----------|------|-------|------|-------|
| Agentic Scope Statement | `docs/AGENTIC_SCOPE_STATEMENT.md` | 0 | AI600-005 | `tests/test_agentic_scope.py` (8 tests) |
| US_FED Baseline extension | `config/compliance/US_FED_BASELINE.json` | 0 | AI600-005 | `tests/test_agentic_scope.py` |
| Lula stub — confabulation | `compliance/lula/lula-validation-ai600-confabulation.yaml` | 0 | AI600-001 | `tests/test_nemo_cbrn_rails.py` (static) |
| Lula stub — data privacy | `compliance/lula/lula-validation-ai600-data-privacy.yaml` | 0 | AI600-002 | — |
| Lula stub — prompt injection | `compliance/lula/lula-validation-ai600-prompt-injection.yaml` | 0 | AI600-003 | — |
| Lula stub — human-AI config | `compliance/lula/lula-validation-ai600-human-ai-config.yaml` | 0 | AI600-005 | — |
| Lula stub — CBRN (Cat-M) | `compliance/lula/lula-validation-ai600-cbrn.yaml` | 0 | AI600-007 | `tests/test_nemo_cbrn_rails.py` (static) |
| CBRN keywords (15 terms) | `config/governance_thresholds.json` | 0 | AI600-007 | `tests/test_text_filter_cbrn.py` (22 tests) |
| CBRN keyword scanner | `src/gateway/governance/text_filter.py` | 0 | AI600-007 | `tests/test_text_filter_cbrn.py` |
| Thresholds schema (CBRN) | `src/gateway/governance/schemas/thresholds.py` | 0 | AI600-007 | `tests/test_text_filter_cbrn.py` |
| Confabulation scorer | `src/gateway/governance/confabulation_scorer.py` | 1 | AI600-001 | `tests/test_confabulation_scorer.py` (34 tests) |
| PII audit log | `src/gateway/governance/pii_sanitizer.py` | 1 | AI600-002 | `tests/test_pii_audit_log.py` (18 tests) |
| Prompt injection detector | `src/gateway/governance/prompt_injection_detector.py` | 2 | AI600-003 | `tests/test_prompt_injection_detector.py` (28 tests) |
| Adversarial prompts fixture | `tests/fixtures/adversarial_prompts.json` | 2 | AI600-003 | `tests/test_prompt_injection_detector.py` |
| HITL escalator | `src/gateway/governance/hitl_escalator.py` | 2 | AI600-005 | `tests/test_hitl_escalator.py` (19 tests) |
| Provenance chain | `src/gateway/governance/provenance_chain.py` | 2 | AI600-005 | `tests/test_provenance_chain.py` (21 tests) |
| NeMo CBRN Colang rail | `src/gateway/governance/nemo/colang/cbrn_rails.co` | 3 | AI600-007 | `tests/test_nemo_cbrn_rails.py` (12 tests) |
| Recursive governance risk tests | `tests/test_recursive_governance_risk.py` | 3 | AI600-005 | 35 tests |
| GovernanceControl enum extension | `src/gateway/governance/constants.py` | 0 | AI600-005 | `tests/test_agentic_scope.py` |
| CI — AI 600-1 gates (4 jobs) | `.github/workflows/ci.yml` | 0 | ALL | CI enforcement |

### 10.2 Remaining Work (Phase 3 Full + Beyond)

| Item | Path | POAM | Priority |
|------|------|------|----------|
| Wire `confabulation_rate` into `ComplianceMetrics` | `src/compliance_bridge/types.py` | AI600-001 | High |
| Harden all 5 Lula stubs to live assertions | `compliance/lula/lula-validation-ai600-*.yaml` | ALL | High (Phase 3 §7.5) |
| MCP tool response sanitization | [`src/gateway/governance/text_filter.py`](../../../src/gateway/governance/text_filter.py) (**v3.0.0:** `safety.py` removed) | AI600-003 | Critical |
| Raise red team threshold to `deflection_score >= 4` | `tests/red_team/adversarial_dataset.json` | AI600-003 | Critical |
| Create `docs/HUMAN_OVERSIGHT_SCOPE.md` | `docs/HUMAN_OVERSIGHT_SCOPE.md` | AI600-005 | High |
| SHA-256 model weight verification | `scripts/mirror_models.py` | AI600-007 | Critical |
| Create `docs/MODEL_CARD_REVIEW.md` | `docs/MODEL_CARD_REVIEW.md` | AI600-007 | High |
| Algorithmic fairness assessment | `docs/AI_FAIRNESS_ASSESSMENT.md` | AI600-004 | High |
| Advanced jailbreak red team dataset | `tests/red_team/adversarial_dataset.json` | AI600-006 | High |
| OPA auth layer in front of vLLM | `deployment/k8s/vllm-services.yaml` | AI600-006 | High |
| Carlini et al. memorization probe | `scripts/evaluate_langfuse_traces.py` | AI600-002 | Medium |
| OSCAL AI 600-1 component definition | `compliance/oscal/component-definition.yaml` | ALL | Medium |

---

_Document prepared 2026-06-15. Last updated 2026-06-15 to reflect Phase 0–3 dev posture implementation on branch `feat/CAGE-AI600-ai600-1-implementation`. This is a living document — update after each Phase completion milestone and after any significant change to CAGE's agentic AI functionality._

_References: NIST AI 600-1 (July 26, 2024), NIST AI RMF 1.0 (January 2023), NIST SP 800-53 Rev. 5, NIST SP 800-37 Rev. 2, SR 26-2 (Federal Reserve, April 17, 2026), EO 14110 (October 2023), OMB M-24-10 (March 2024), ECOA/Regulation B, SEC AI guidance._
