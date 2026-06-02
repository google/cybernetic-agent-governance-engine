# CAGE Technical Report Series

| Field              | Value                  |
| ------------------ | ---------------------- |
| **Classification** | PUBLIC                 |
| **Date**           | 2026-05-29             |
| **Version**        | 1.6                    |
| **Status**         | Complete (10 documents) |

---

## Introduction

The Cybernetic Governance Engine (CAGE) is a production-grade, multi-agent AI governance framework designed for regulated financial advising, deployed on Google Kubernetes Engine (GKE). CAGE v2.0.0 implements **evidentiary independence** — the system cannot manufacture the conditions necessary to satisfy its own governance checks — via Cloud KMS HSM-backed signing, human-gated NeMo refinement, heterogeneous multi-model consensus, and externally reconciled Control Barrier Function balances (Anchorage Digital, OCC-chartered). This technical report series documents the full system across **ten** specialized documents, covering its architecture, technology stack, agent pipeline design, neuro-symbolic governance engine, regulatory compliance posture, security controls, deployment infrastructure, an operational runbook capturing verified recovery procedures and integration test results, and a formal verification proof. Together, the documents provide a complete engineering and compliance record for security assessors, architects, compliance officers, operations teams, and AI/ML engineers evaluating or operating the system.

---

## Document Series

| #   | Document                      | File                                                                     | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| --- | ----------------------------- | ------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 01  | System Overview               | [`01-SYSTEM-OVERVIEW.md`](01-SYSTEM-OVERVIEW.md)                         | High-level introduction to CAGE — purpose, stakeholders, regulatory constraints, primary capabilities, current compliance posture (24% NIST RMF), and authorization boundary. **v1.1 (2026-05-31):** mTLS finding resolved (POAM-007), POAM-018/019 added, GCP Secret Manager removed from external dependencies, SLM sidecar deprecation noted, PII entity count corrected to 15. |
| 02  | Architecture                  | [`02-ARCHITECTURE.md`](02-ARCHITECTURE.md)                               | Structural design of all **6** major subsystems — LangGraph StateGraph (10 nodes including mandatory NeMo input/output rails), Hybrid Gateway (MCP + Inference + Governance + KMS Signer + ConsensusModelRegistry), Compliance Bridge, AgentSight UI, eBPF DaemonSet, and **Vendor Integrations** (`src/integrations/` — NexArt [`adapter.py` + `provider.py`], TrustLayers) — including component interaction diagrams, HITL workflow, gRPC interfaces, observability, the **human-gated NeMo refinement flow** (v2.0.0: propose → approve → apply), **vendor-isolated integrations** (v2.0.0: `src/integrations/{vendor}/` boundary), and **mTLS resolved** (POAM-007 closed 2026-05-17: Linkerd + Cilium L7). **v1.1 (2026-05-31).** |
| 03  | Technology Stack              | [`03-TECHNOLOGY-STACK.md`](03-TECHNOLOGY-STACK.md)                       | Exhaustive inventory of all languages (Python, TypeScript, Rego, Colang 2.x, HCL, proto3), frameworks (LangGraph **10-node** pipeline, FastAPI, NeMo, OPA), LLM infrastructure (vLLM, DeepSeek-R1, Llama-3.1, Qwen), Python libraries, **vendor integrations** (TrustLayers, NexArt — Section 5), frontend stack, Kubernetes/GCP platform components, protocols, and data stores. **Updated:** 8-node → 10-node; 20 PII → 15 PII; vendor integrations section added. |
| 04  | Agent System                  | [`04-AGENT-SYSTEM.md`](04-AGENT-SYSTEM.md)                               | Complete multi-agent pipeline design — all 9 agents (thinker, doer, data analyst, execution analyst, evaluator, explainer, governed trader, risk analyst, financial advisor), full **AgentState TypedDict (25 fields** including `hitl_expires_at`, `guardrail_blocked`, `guardrail_reason`, `output_rail_applied`), graph routing logic, subgraph designs, HITL approval workflow, checkpointing, EvaluatorAuditor scoring, and red team adversarial harness (290+ payloads). All legacy shim directories removed; canonical agent location is `src/governed_financial_advisor/agents/` |
| 05  | AI Governance & Policy Engine | [`05-AI-GOVERNANCE-POLICY-ENGINE.md`](05-AI-GOVERNANCE-POLICY-ENGINE.md) | The neuro-symbolic governance core — full SymbolicGovernor pipeline (STPA/UCA validation, SR 26-2 §IV.B agentic confidence, Control Barrier Function with externally reconciled balances, **SLM sidecar deprecated** (v2.0.x: permanently offline, `slm_available=false` sentinel), OPA Rego, **heterogeneous multi-model consensus** (v2.0.0: ConsensusModelRegistry routing each critic persona to distinct vLLM backends — DeepSeek-R1 Risk Manager + Llama 3.1 Compliance Officer), DoWhy causal gatekeeper, **adaptive FRIA gate** (v2.0.0: `enforce_fria_boundary()` tri-state confidence-mapped external normative validation via `normative_provider.py`)), DEFER State Machine (confidence-starvation bypass + `EXTERNAL_VALIDATION` DeferReason, Redis `db=1` token parking), NeMo Guardrails Colang flows and actions, OPA role-based policy rules, **Cloud KMS HSM-backed governance signing** (v2.0.0: asymmetric signing via HSM, local PEM verification, HMAC fallback), threshold management (22 thresholds), ISO 42001 control stamping, Policy Transpiler, and STPA-to-Policy Compiler CLI |
| 06  | Compliance & Standards        | [`06-COMPLIANCE-STANDARDS.md`](06-COMPLIANCE-STANDARDS.md)               | Full regulatory framework coverage — NIST SP 800-53 Rev 5 (24% readiness across 9 families), NIST RMF 7-step posture and ATO roadmap, ISO/IEC 42001:2023 (Clauses 6/8/9/10 + Annex A), OSCAL artifacts, all 15 Lula validation manifests, ISCM 2-tier strategy, Privacy Impact Assessment (8 risks), SAR-CAGE-2026Q1 (9 findings), and threshold traceability                                                                                                             |
| 07  | Security Infrastructure       | [`07-SECURITY-INFRASTRUCTURE.md`](07-SECURITY-INFRASTRUCTURE.md)         | Defense-in-depth security — authorization boundary (9 NetworkPolicy objects), **Cloud KMS HSM-backed governance signing** (v2.0.0: asymmetric signing via HSM replacing HMAC self-signing) + routing seal, OPA RBAC, secret management (Kubernetes-native secrets via Terraform), two-layer PII protection (NeMo + Presidio, **15 entity types**), 7-year audit logging, AgentSight eBPF monitoring, cryptographic controls, **externally reconciled CBF** (v2.0.0: Anchorage Digital OCC-chartered custody, KMS-signed balances), red team coverage, and all open security findings |
| 08  | Deployment & Infrastructure   | [`08-DEPLOYMENT-INFRASTRUCTURE.md`](08-DEPLOYMENT-INFRASTRUCTURE.md)     | Full deployment architecture — 16-service Kubernetes topology, Kubernetes Inference Gateway (ADR-002 nginx GatewayClass), Docker image inventory, Cloud Build CI/CD pipelines, modular Terraform IaC (`infra/targets/` + `infra/modules/`), vLLM GPU configuration (DeepSeek-R1 AWQ on L4), Langfuse self-hosted deployment, storage backends, network policies, latency strategy (200ms ISO-20022 SLA), **Redis db=1 noeviction** (v2.0.0: Guaranteed QoS, `maxmemory-policy noeviction` for DEFER state machine), and operational runbooks |
| 09  | Operational Runbook           | [`09-OPERATIONAL-RUNBOOK.md`](09-OPERATIONAL-RUNBOOK.md)                 | Verified operational procedures — vLLM model update verification, `governed-financial-advisor` CrashLoopBackOff recovery, full integration test results (**561 passing** as of v2.0.0, up from 152 in 2026-03-08 session), 7 code fixes applied, known connectivity-only failure classification, Saga engine ghost-state recovery, and **v2.0.0 procedures** (KMS HSM signing verification, DEFER queue inspection, dual-project Langfuse credential validation, normative provider boot-time baseline check). **v1.1 (2026-05-31).** |
| 10  | Formal Verification           | [`10-FORMAL-VERIFICATION.md`](10-FORMAL-VERIFICATION.md)                 | Composite Verification Framework (CVF) proof — STPA hazard completeness (UCA-5/FIN-1 TOCTOU eliminated), VSM structural completeness (algedonic feedback loop closed), hybrid automata reachability (ghost state eliminated), **AARM 11-vector neutralization table** (10/11 NEUTRALIZED; V11 PARTIAL pending POAM-022), **FiscalLimitGuard race-condition proof** (Redis WATCH/MULTI/EXEC optimistic lock invariant), and **Cloud KMS HSM non-repudiation proof** (ISO 42001 §A.7.5, NIST AU-10, FINRA Rule 4511). **v1.1 (2026-05-31).** |

---

## Quick Reference: Key Facts

| Fact                           | Value                                     |
| ------------------------------ | ----------------------------------------- |
| CAGE Version                   | 2.0.0                                     |
| NIST RMF Overall Readiness     | 24%                                       |
| System Risk Level              | HIGH (no ATO)                             |
| Compliance Frameworks          | 19 (NIST, ISO, SEC, FINRA, GLBA, SR 11-7, SR 26-2, EU AI Act, DORA, GDPR, EBA, MAS FEAT, MAS TRM, CSA AARM) |
| Supported Jurisdictions        | 3 (`US_FED`, `EU_ECB`, `APAC_MAS`)        |
| Regional Compliance Profiles   | 3 (config/compliance/)                    |
| Regional Threshold Profiles    | 3 (config/thresholds/)                    |
| OSCAL Framework Routing Tables | 4 (NIST, ISO 42001, EU AI Act, MAS FEAT)  |
| Agent Nodes                    | 10 (LangGraph StateGraph)                 |
| AgentState Fields              | 25 (including `hitl_expires_at`, `guardrail_blocked`, `guardrail_reason`, `output_rail_applied`) |
| Governance Tiers               | 7 + tier 6b (SymbolicGovernor, tiers 0–6 + 6b adaptive FRIA gate) |
| SLM Sidecar                    | Deprecated (v2.0.x) — `slm_available=false` sentinel; 0ms latency |
| Governance Thresholds          | 22 (in `governance_thresholds.json`)      |
| Governance Signing             | Cloud KMS HSM (RSA-PKCS1-4096-SHA256)     |
| Consensus Architecture         | Heterogeneous (DeepSeek-R1 + Llama 3.1)   |
| CBF Ground Truth               | Anchorage Digital (OCC-chartered, gRPC)   |
| NeMo Refinement Model          | Human-gated propose → approve → apply     |
| NeMo PII Entity Types          | 15 (Presidio; input + output rails)       |
| Vendor Integrations            | 2 (`src/integrations/trustlayers/`, `src/integrations/nexart/`) |
| Lula Validation Manifests      | 15                                        |
| Open Critical Findings         | 1 (FIND-007 FIPS 199 unsigned — POAM-009) |
| Open High Findings             | 9 (POAM-001, 002, 003, 008, 012, 013, 018, 019, 022) |
| Resolved Critical Findings     | 2 (FIND-010 HMAC bypass — POAM-012 closed; FIND-011 mTLS — POAM-007 closed) |
| AARM Vectors Neutralized       | 10/11 (V11 PARTIAL — POAM-022)            |
| Red Team Payloads              | 290+                                      |
| Automated Tests                | 561 passing                               |
| Audit Log Retention            | 7 years                                   |
| Latency SLA                    | 200ms US / 150ms EU (ISO-20022)           |
| Primary LLM (Reasoning)        | DeepSeek-R1-Distill-Llama-8B (AWQ)        |
| Primary LLM (Fast)             | Meta-Llama-3.1-8B-Instruct                |
| Technical Report Documents     | 10 (TR-01 through TR-10)                  |

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
