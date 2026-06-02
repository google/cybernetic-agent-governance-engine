# Cybernetic Agent Governance Engine (CAGE) — One-Pager

**Authors:** CAGE Engineering Team · **Last updated:** 2026-05-23 · **Status:** Production (v1.0.0)

---

## Problem, Why It Matters, Solution & Consequence

Regulated industries deploying agentic AI face a fundamental audit gap: LLM-based agents make consequential decisions (trade execution, risk classification, customer data handling) through opaque, stateless inference calls with no enforceable policy boundary, no tamper-evident audit trail, and no mechanism for human override once a workflow is in motion. The current state of the art—prompt engineering and post-hoc log analysis—is neither deterministic nor regulatorily defensible under **SR 26-2** (Federal Reserve's April 2026 guidance on generative and agentic AI risk management), ISO/IEC 42001 (AI management system), or SOC 2 Type II. SR 26-2 explicitly declares that agentic systems are *outside the prescriptive scope of SR 11-7*, directing institutions to apply their own rigorous internal frameworks — CAGE is that framework.

The cost of inaction is concrete: a single unchecked `execute_trade_action` call can bypass drawdown limits, leak PII in the response payload, and produce no evidence of the policy evaluation that should have blocked it. Automated red-team exercises against naive gateway implementations routinely achieve **100% adversarial success rates** on RBAC-002 (excessive permissions) and PII-004 (data leakage) attack classes.

**CAGE** is an open-source, Python-first governance runtime that wraps every LLM call and tool invocation in a deterministic, 10-layer policy enforcement pipeline—without sacrificing production latency. The architecture is bifurcated: application logic (a LangGraph `StateGraph` of 8 nodes) is fully decoupled from the cloud provider, while a dedicated **Inference Gateway** handles all model traffic through a split-brain topology routing to two specialized vLLM pools (DeepSeek-R1-Distill-Llama-8B for reasoning; Meta-Llama-3.1-8B-Instruct for structured governance output). The governance stack executes sequentially on every request: Aho-Corasick keyword scan → NeMo Guardrails (Colang 2.x + in-process Presidio PII) → STPA hazard validator → OPA policy engine (with deprecated SLM sidecar permanently bypassed to meet the 200ms latency budget, running under the `slm_available = False` sentinel for elevated 0.97 confidence checks) → Control Barrier Function → multi-agent consensus → output masking. A deterministic TypeScript OSCAL parser replaces generative LLMs for compliance mapping, achieving sub-millisecond audit-trail generation. End-to-end gateway overhead is **<2 ms P99**, validated under load.

Human oversight is enforced structurally, not by convention: the LangGraph graph pauses via `interrupt_before=["governed_trader"]` for all trades exceeding $10k or risk score > 0.7, checkpointing state to Redis (AsyncRedisSaver) and resuming only on an explicit `POST /v1/approvals/{thread_id}/resume`. The evaluator node generates an HMAC-SHA256 governance seal that must be present before the governed-trader subgraph executes—forged or absent seals route the request to the explainer node without trade execution. A Kubeflow Pipelines v2 feedback loop (the "Green Stack") continuously polls the compliance bridge for ISO 42001 safety-rate metrics and automatically triggers NeMo Guardrails policy refinement when the 95% threshold is breached, closing the cybernetic loop without human intervention. After deployment, CAGE achieves a **100% pass rate** against the same red-team toolchain that previously produced catastrophic defeats.

---

## Status of This Document

| Attribute             | Value                                                                                                                                                                   |
| --------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Document type         | Engineering one-pager                                                                                                                                                   |
| Audience              | Engineering leads, compliance reviewers, AI governance evaluators                                                                                                       |
| Companion documents   | [`ARCHITECTURE.md`](../ARCHITECTURE.md), [`docs/GOVERNANCE_CROSSWALK.md`](GOVERNANCE_CROSSWALK.md), [`docs/NEURO_SYMBOLIC_GOVERNANCE.md`](NEURO_SYMBOLIC_GOVERNANCE.md) |
| Implementation status | v1.0.0 — 2026-03-12                                                                                                                                                     |
| Open issues           | File a GitHub issue for any defects or feature requests                                                                                                                 |
| Feedback              | File a GitHub issue or suggest edits via pull request                                                                                                                   |
