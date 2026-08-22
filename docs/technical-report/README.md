# CAGE Technical Report Series

| Field              | Value                  |
| ------------------ | ---------------------- |
| **Classification** | PUBLIC                 |
| **Date**           | 2026-08-22             |
| **Version**        | 3.0.0                  |
| **Status**         | Complete (10 documents) — v3.0.0 stable (GKE deployment verified; 2,841 passed, 0 failed, 67 skipped; 75.40% statement coverage) |

---

## Introduction

The Cybernetic Governance Engine (CAGE) is a production-grade, multi-agent AI governance framework designed for regulated financial advising, deployed on Google Kubernetes Engine (GKE). CAGE v3.0.0 implements **evidentiary independence** — the system cannot manufacture the conditions necessary to satisfy its own governance checks — via Cloud KMS HSM-backed signing, strictly human-gated NeMo refinement, heterogeneous multi-model consensus, Lua-atomic Control Barrier Functions (`atomic_verify_and_commit()`), synchronous replica `WAIT` verification with fail-closed automatic rollback, canonical 1.1 evidence stream hashing with mandatory blocking durability (`validate_evidence_stream_preconditions()`), and externally reconciled Control Barrier Function balances (POAM-023 / POAM-2026-038 closed; GCS WORM ledger + Cloud KMS signing with 300s TTL in Redis). This technical report series documents the full system across **ten** specialized documents, covering its architecture, technology stack, agent pipeline design, neuro-symbolic governance engine, regulatory compliance posture, security controls, deployment infrastructure, an operational runbook capturing verified recovery procedures and integration test results, and a formal verification proof. Together, the documents provide a complete engineering and compliance record for security assessors, architects, compliance officers, operations teams, and AI/ML engineers evaluating or operating the system.

---

## Document Series

| #   | Document                      | File                                                                     | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| --- | ----------------------------- | ------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 01  | System Overview               | [`01-SYSTEM-OVERVIEW.md`](01-SYSTEM-OVERVIEW.md)                         | High-level introduction to CAGE — purpose, stakeholders, regulatory constraints, primary capabilities, current compliance posture, and authorization boundary. **v3.0.0:** 6 governance primitives, No-Direct-Bind BFS model, Distributed CBF multi-agent proof, and external attestation layers. |
| 02  | Architecture                  | [`02-ARCHITECTURE.md`](02-ARCHITECTURE.md)                               | Structural design of all major subsystems — LangGraph StateGraph (10 nodes including mandatory NeMo input/output rails), Hybrid Gateway (MCP + Inference + Governance + KMS Signer + ConsensusModelRegistry), Compliance Bridge, AgentSight UI, eBPF DaemonSet, and **Vendor Integrations** (`src/integrations/` — VEIP, NexArt, TrustLayers, Archytan, Veritas) — including component interaction diagrams, HITL workflow, gRPC interfaces, observability, the human-gated NeMo refinement flow, and Linkerd mTLS mesh policies. |
| 03  | Technology Stack              | [`03-TECHNOLOGY-STACK.md`](03-TECHNOLOGY-STACK.md)                       | Exhaustive inventory of all languages (Python, TypeScript, Rego, Colang 2.x, HCL, proto3), frameworks (LangGraph 10-node pipeline, FastAPI, NeMo, OPA), LLM infrastructure (vLLM, DeepSeek-R1, Llama-3.1, Qwen), Python libraries, vendor integrations (VEIP, TrustLayers, NexArt, Archytan, Veritas), frontend stack, Kubernetes/GCP platform components, protocols, and data stores. |
| 04  | Agent System                  | [`04-AGENT-SYSTEM.md`](04-AGENT-SYSTEM.md)                               | Complete multi-agent pipeline design — all 9 agents (thinker, doer, data analyst, execution analyst, evaluator, explainer, governed trader, risk analyst, financial advisor), full AgentState TypedDict (including `hitl_expires_at`, `guardrail_blocked`, `guardrail_reason`, `output_rail_applied`), graph routing logic, subgraph designs, HITL approval workflow, checkpointing, EvaluatorAuditor scoring, and red team adversarial harness (290+ payloads). |
| 05  | AI Governance & Policy Engine | [`05-AI-GOVERNANCE-POLICY-ENGINE.md`](05-AI-GOVERNANCE-POLICY-ENGINE.md) | The neuro-symbolic governance core — full SymbolicGovernor pipeline (STPA/UCA validation, SR 26-2 §IV.B agentic confidence, Control Barrier Function with externally reconciled balances, OPA Rego, heterogeneous multi-model consensus, DoWhy causal gatekeeper, adaptive FRIA gate, DEFER / NARROW / PAUSE state machines, NeMo Guardrails Colang flows and actions, OPA role-based policy rules, Cloud KMS HSM-backed governance signing, threshold management, ISO 42001 control stamping, Policy Transpiler, and STPA-to-Policy Compiler CLI |
| 06  | Compliance & Standards        | [`06-COMPLIANCE-STANDARDS.md`](06-COMPLIANCE-STANDARDS.md)               | Full regulatory framework coverage — NIST SP 800-53 Rev 5, NIST RMF 7-step posture and ATO roadmap, ISO/IEC 42001:2023 (Clauses 6/8/9/10 + Annex A), OSCAL artifacts, **30 Lula validation manifests (6 Active, 24 Stub)**, ISCM 2-tier strategy, Privacy Impact Assessment, SAR-CAGE-2026Q1, and threshold traceability |
| 07  | Security Infrastructure       | [`07-SECURITY-INFRASTRUCTURE.md`](07-SECURITY-INFRASTRUCTURE.md)         | Defense-in-depth security — authorization boundary (9 NetworkPolicy objects), Cloud KMS HSM-backed governance signing with documented 90-day rotation and 30-day HMAC seal secret lifecycle (`KEY_ROTATION.md`), NIST SP 800-52 Rev. 2 TLS test enforcement (`test_tls_enforcement.py`), base image CVE hardening, OPA RBAC, two-layer PII protection (Presidio, 15 entity types), 7-year audit logging, AgentSight eBPF monitoring, externally reconciled CBF, and red team coverage |
| 08  | Deployment & Infrastructure   | [`08-DEPLOYMENT-INFRASTRUCTURE.md`](08-DEPLOYMENT-INFRASTRUCTURE.md)     | Full deployment architecture — 16-service Kubernetes topology, Kubernetes Inference Gateway, Docker image inventory with `python:3.12-slim-bookworm` base and pinned third-party tags, Cloud Build CI/CD pipelines, modular Terraform IaC (`infra/targets/` + `infra/modules/`), vLLM GPU configuration, Langfuse self-hosted deployment, storage backends, network policies, latency strategy, and Redis db=1 noeviction |
| 09  | Operational Runbook           | [`09-OPERATIONAL-RUNBOOK.md`](09-OPERATIONAL-RUNBOOK.md)                 | Verified operational procedures — vLLM model update verification, `governed-financial-advisor` recovery, full integration test results (**2,841 passing, 0 failed, 67 skipped** across all three regional postures), `uv run pytest` execution with `--dist=loadfile`, emergency key revocation runbooks (`KEY_ROTATION.md`), Saga engine ghost-state recovery, and GKE deployment lifecycle |
| 10  | Formal Verification           | [`10-FORMAL-VERIFICATION.md`](10-FORMAL-VERIFICATION.md)                 | Composite Verification Framework (CVF) proof — STPA hazard completeness (UCA-5/FIN-1 TOCTOU eliminated), VSM structural completeness, hybrid automata reachability, AARM 11-vector neutralization, FiscalLimitGuard race-condition proof, Cloud KMS HSM non-repudiation proof, discrete-time Control Barrier Function proof, Routing Seal v2 Integrity, No-Direct-Bind BFS model (57/66 states), and **Distributed CBF Multi-Agent Formal Proof** ($N \in \{2, 3, 4\}$ agents) |

---

## Quick Reference: Key Facts

| Fact                           | Value                                     |
| ------------------------------ | ----------------------------------------- |
| CAGE Version                   | 3.0.0                                     |
| NIST RMF Overall Readiness     | 24%                                       |
| System Risk Level              | HIGH (no ATO)                             |
| Compliance Frameworks          | 19 (NIST, ISO, SEC, FINRA, GLBA, SR 26-2, EU AI Act, DORA, GDPR, EBA, MAS FEAT, MAS TRM, CSA AARM) |
| Supported Jurisdictions        | 3 (`US_FED`, `EU_ECB`, `APAC_MAS`)        |
| Regional Compliance Profiles   | 3 (config/compliance/)                    |
| Regional Threshold Profiles    | 3 (config/thresholds/)                    |
| OSCAL Framework Routing Tables | 4 (NIST, ISO 42001, EU AI Act, MAS FEAT)  |
| Agent Nodes                    | 10 (LangGraph StateGraph)                 |
| AgentState Fields              | 25 (including `hitl_expires_at`, `guardrail_blocked`, `guardrail_reason`, `output_rail_applied`) |
| Governance Tiers               | 7 + tier 6b (SymbolicGovernor, tiers 0–6 + 6b adaptive FRIA gate) |
| Decision Primitives            | 6 (`ALLOW`, `DENY`, `REQUIRE_APPROVAL`, `DEFER`, `NARROW`, `PAUSE`) |
| SLM Sidecar                    | Deprecated (v2.0.x) — `slm_available=false` sentinel; 0ms latency |
| Governance Thresholds          | 22 (in `governance_thresholds.json`)      |
| Governance Signing             | Cloud KMS HSM (RSA-PKCS1-4096-SHA256)     |
| Consensus Architecture         | Heterogeneous (DeepSeek-R1 + Llama 3.1)   |
| CBF Ground Truth               | Reconciled WORM ledger (GCS + Cloud KMS signing with 300s TTL in Redis, POAM-2026-038 CLOSED) |
| NeMo Refinement Model          | Human-gated propose → approve → apply     |
| NeMo PII Entity Types          | 15 (Presidio; input + output rails)       |
| Vendor Integrations            | 5 (`veip/`, `trustlayers/`, `nexart/`, `archytan/`, `veritas/`) |
| Lula Validation Manifests      | 30 (6 Active, 24 Stub — see [`compliance/lula/README.md`](../../compliance/lula/README.md)) |
| Open Critical Findings         | 1 (FIND-007 FIPS 199 unsigned — POAM-009) |
| Open High Findings             | 6 (POAM-001, 002, 008, 018, 019, 022; POAM-011, 012, 013, 037, 038 closed) |
| Resolved Critical Findings     | 2 (FIND-010 HMAC bypass — resolved; FIND-011 mTLS — POAM-007 closed) |
| AARM Vectors Neutralized       | 10/11 (V11 PARTIAL — POAM-022)            |
| Red Team Payloads              | 290+                                      |
| Automated Tests                | **2,841 passing, 0 failed, 67 skipped** (v3.0.0 stable, 2026-08-22) |
| Audit Log Retention            | 7 years                                   |
| Latency SLA                    | 200 ms US / 150 ms EU (real-time interbank rail infrastructure requirement — FedNow / SEPA Instant) |
| Primary LLM (Reasoning)        | DeepSeek-R1-Distill-Llama-8B (AWQ)        |
| Primary LLM (Fast)             | Meta-Llama-3.1-8B-Instruct                |
| Technical Report Documents     | 10 (TR-01 through TR-10)                  |

---

## Mathematical Formalism Summary

The following key formulas appear across the technical report series. Each formula is implemented directly in source code and enforced at runtime; the table provides a cross-reference to the primary document where the derivation or proof appears.

| Formula / Invariant | Expression | Source File | Primary TR Document |
|---------------------|------------|-------------|---------------------|
| **CBF safe set** | `S = {x ∈ ℝⁿ : h(x) ≥ 0}` | [`src/gateway/governance/cbf.py`](../../src/gateway/governance/cbf.py) | [TR-10](10-FORMAL-VERIFICATION.md), [TR-05](05-AI-GOVERNANCE-POLICY-ENGINE.md) |
| **CBF barrier function** | `h(x) = cash_balance − min_cash_balance` | [`src/gateway/governance/cbf.py`](../../src/gateway/governance/cbf.py) | [TR-10](10-FORMAL-VERIFICATION.md) |
| **Discrete-time CBF condition** | `h(S(t+1)) ≥ (1−γ)·h(S(t)), γ ∈ (0,1)` | [`src/gateway/governance/cbf.py`](../../src/gateway/governance/cbf.py) | [TR-10](10-FORMAL-VERIFICATION.md) |
| **Confabulation risk score** | `risk_score = 1.0 − confidence` | [`src/gateway/governance/confabulation_scorer.py`](../../src/gateway/governance/confabulation_scorer.py) | [TR-05](05-AI-GOVERNANCE-POLICY-ENGINE.md) |
| **FRIA zone — allow threshold** | `FRIA_ZONE_ALLOW = 0.95` | [`src/gateway/governance/symbolic_governor.py`](../../src/gateway/governance/symbolic_governor.py) | [TR-05](05-AI-GOVERNANCE-POLICY-ENGINE.md) |
| **FRIA zone — defer threshold** | `FRIA_ZONE_DEFER = 0.70` | [`src/gateway/governance/symbolic_governor.py`](../../src/gateway/governance/symbolic_governor.py) | [TR-05](05-AI-GOVERNANCE-POLICY-ENGINE.md) |
| **Causal marginal risk boundary** | `(0.5 + estimate.value × amount) > 0.95` | [`src/gateway/governance/causal_gatekeeper.py`](../../src/gateway/governance/causal_gatekeeper.py) | [TR-05](05-AI-GOVERNANCE-POLICY-ENGINE.md), [TR-10](10-FORMAL-VERIFICATION.md) |
| **PlaceboTreatmentRefuter criteria** | 50 sims, p < 0.05, \|eff\| > 0.2 | [`src/gateway/governance/causal_gatekeeper.py`](../../src/gateway/governance/causal_gatekeeper.py) | [TR-05](05-AI-GOVERNANCE-POLICY-ENGINE.md) |
| **Routing seal v2 token format** | `<expire_ts_hex>.<action_slug>.<record_hash_hex>.<hmac_hex>` (30 s TTL) | [`src/gateway/governance/routing_seal.py`](../../src/gateway/governance/routing_seal.py) | [TR-10](10-FORMAL-VERIFICATION.md), [TR-07](07-SECURITY-INFRASTRUCTURE.md) |
| **Provenance hash chain** | `record_hash[n] = SHA-256(record_hash[n-1] ‖ content_json[n])` | [`src/gateway/governance/provenance_chain.py`](../../src/gateway/governance/provenance_chain.py) | [TR-10](10-FORMAL-VERIFICATION.md) |
| **Fiscal daily cap** | $500,000 over 86,400 s rolling window | [`src/gateway/governance/fiscal_limit_guard.py`](../../src/gateway/governance/fiscal_limit_guard.py) | [TR-10](10-FORMAL-VERIFICATION.md), [TR-05](05-AI-GOVERNANCE-POLICY-ENGINE.md) |
| **STPA UCA FIN-1** | `trade_value > position_limit` | [`src/gateway/governance/ontology.py`](../../src/gateway/governance/ontology.py) | [TR-05](05-AI-GOVERNANCE-POLICY-ENGINE.md) |
| **STPA UCA FIN-2** | `portfolio_concentration > 0.25` | [`src/gateway/governance/ontology.py`](../../src/gateway/governance/ontology.py) | [TR-05](05-AI-GOVERNANCE-POLICY-ENGINE.md) |
| **STPA UCA-5** | `order_size > 0.1 × daily_volume` | [`src/gateway/governance/ontology.py`](../../src/gateway/governance/ontology.py) | [TR-05](05-AI-GOVERNANCE-POLICY-ENGINE.md) |
| **STPA UCA-6** | `order_size > fraction × daily_vol` | [`src/gateway/governance/ontology.py`](../../src/gateway/governance/ontology.py) | [TR-05](05-AI-GOVERNANCE-POLICY-ENGINE.md) |

For full derivations and proofs, see [`10-FORMAL-VERIFICATION.md`](10-FORMAL-VERIFICATION.md). For the governance pipeline design that applies these formulas at runtime, see [`05-AI-GOVERNANCE-POLICY-ENGINE.md`](05-AI-GOVERNANCE-POLICY-ENGINE.md). For the causal and CBF mathematical background, see [`docs/governance/CAUSAL_AND_CBF_GOVERNANCE.md`](../governance/CAUSAL_AND_CBF_GOVERNANCE.md).

---

## Related Architecture Documents

| Document | Description |
| -------- | ----------- |
| [`EXTENSIBILITY_ARCHITECTURE.md`](../architecture/EXTENSIBILITY_ARCHITECTURE.md) | Domain-agnostic kernel design and multi-domain extensibility roadmap (includes TrustLayers and NexArt as implemented vendor integration examples) |
| [`DUAL_PROJECT_ARCHITECTURE.md`](../architecture/DUAL_PROJECT_ARCHITECTURE.md) | Dual-project Langfuse telemetry isolation architecture; evidentiary independence design; POAM-018/019 remediation guidance |

---

## Reading Guide

Recommended reading order by audience:

| Audience                    | Recommended Order                                                                                                                 |
| --------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| **Security Assessors / AO** | [01 Overview](01-SYSTEM-OVERVIEW.md) → [07 Security](07-SECURITY-INFRASTRUCTURE.md) → [06 Compliance](06-COMPLIANCE-STANDARDS.md) → [10 Formal Verification](10-FORMAL-VERIFICATION.md) |
| **Architects / Engineers**  | [02 Architecture](02-ARCHITECTURE.md) → [04 Agents](04-AGENT-SYSTEM.md) → [05 Governance](05-AI-GOVERNANCE-POLICY-ENGINE.md) → [10 Formal Verification](10-FORMAL-VERIFICATION.md) |
| **Operations / DevOps**     | [08 Deployment](08-DEPLOYMENT-INFRASTRUCTURE.md) → [09 Runbook](09-OPERATIONAL-RUNBOOK.md) → [03 Stack](03-TECHNOLOGY-STACK.md)   |
| **Compliance Officers**     | [06 Compliance](06-COMPLIANCE-STANDARDS.md) → [07 Security](07-SECURITY-INFRASTRUCTURE.md) → [01 Overview](01-SYSTEM-OVERVIEW.md) → [10 Formal Verification](10-FORMAL-VERIFICATION.md) |
| **AI/ML Engineers**         | [04 Agents](04-AGENT-SYSTEM.md) → [05 Governance](05-AI-GOVERNANCE-POLICY-ENGINE.md) → [03 Stack](03-TECHNOLOGY-STACK.md)         |
