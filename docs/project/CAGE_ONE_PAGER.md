# Cybernetic Agent Governance Engine (CAGE) — One-Pager

**Authors:** CAGE Engineering Team · **Last updated:** 2026-06-08 · **Status:** GO — STABLE RELEASE APPROVED (v0.1.0, 2026-06-08)

---

## Problem, Why It Matters, Solution & Consequence

Regulated industries deploying agentic AI face a fundamental audit gap: LLM-based agents make consequential decisions (trade execution, risk classification, customer data handling) through opaque, stateless inference calls with no enforceable policy boundary, no tamper-evident audit trail, and no mechanism for human override once a workflow is in motion. The current state of the art—prompt engineering and post-hoc log analysis—is neither deterministic nor regulatorily defensible under **SR 26-2** (Federal Reserve's April 2026 guidance on generative and agentic AI risk management), ISO/IEC 42001 (AI management system), or SOC 2 Type II. SR 26-2 explicitly declares that agentic systems are *outside the prescriptive scope of SR 11-7*, directing institutions to apply their own rigorous internal frameworks — CAGE is that framework.

The cost of inaction is concrete: a single unchecked `execute_trade_action` call can bypass drawdown limits, leak PII in the response payload, and produce no evidence of the policy evaluation that should have blocked it. Automated red-team exercises against naive gateway implementations routinely achieve **100% adversarial success rates** on RBAC-002 (excessive permissions) and PII-004 (data leakage) attack classes.

**CAGE v0.1.0** is an open-source, Python-first governance runtime that wraps every LLM call and tool invocation in a deterministic, 7-tier policy enforcement pipeline — without sacrificing production latency. The architecture is bifurcated: application logic (a LangGraph `StateGraph` multi-agent pipeline) is fully decoupled from the cloud provider, while a dedicated **Inference Gateway** (`src/gateway/`) handles all model traffic through a split-brain topology routing to two specialized vLLM pools (DeepSeek-R1 for reasoning; Llama 3.1 for structured governance output). The governance stack executes on every request: Aho-Corasick keyword scan → NeMo Guardrails (Colang 2.x + in-process Presidio PII) → STPA hazard validator → OPA policy engine → Control Barrier Function → multi-agent consensus → causal gatekeeper → adaptive FRIA gate. The SLM sidecar (formerly Tier 3) has been deprecated and replaced by a permanent `slm_available=false` sentinel to optimize latency. All compliance mapping is performed by the Python OSCAL exporter (`src/compliance_bridge/oscal_exporter.py`), achieving sub-millisecond audit-trail generation.

**v0.1.0 introduces evidentiary independence** — the system cannot manufacture the conditions necessary to satisfy its own governance checks:

- **Cloud KMS HSM-backed governance signing** — asymmetric signing via Google Cloud KMS; private key never leaves the HSM; HMAC-SHA256 fallback for dev/CI only
- **Human-gated NeMo refinement** — the autonomous Langfuse → KFP → NeMo hot-reload loop is severed; all config refinements require explicit human approval with reviewer identity and rationale before applying
- **Heterogeneous multi-model consensus** — `ConsensusModelRegistry` routes each critic persona to a distinct vLLM backend; no single model can consent to its own output
- **Externally reconciled CBF** — the Control Barrier Function's `cash_balance` is sourced from an independently reconciled external custody ledger (Anchorage Digital, OCC-chartered) via `AnchorageGrpcLedgerProvider` (**FUTURE STATE / POAM-023, target 2026-09-08 — not yet implemented**; current implementation uses Redis `WATCH/MULTI/EXEC` optimistic locking); reconciled balances will be KMS-signed before Redis write when implemented
- **Token Quota Proxy** — per-session step-count (≤12) and token (≤100k) quota enforcement via Redis atomic Lua counters; fail-closed; HTTP 429 on quota exceeded; two-phase commit (reserve → reconcile); rollback on downstream failure (ISO 42001 Annex A.4)
- **PII Sanitizer** — pre-ledger regex sanitization pipeline (SSN, CC, email, phone, API key/Bearer token) applied to all UCA records before WORM persistence (ISO 42001 Annex A.6)
- **UCA Logger** — ISO 42001 Clause 6.1 UCA record builder; KMS-signed; region-gated WORM persistence (`CAGE_DEPLOYMENT_REGION` → `OSCAL_S3_BUCKET_{REGION}`); UCA types: `quota_exceeded`, `prompt_injection`, `pii_sanitization`

Human oversight is enforced structurally, not by convention: the LangGraph graph pauses via `interrupt_before=["governed_trader"]` for all trades exceeding $10k or risk score > 0.7, checkpointing state to Redis and resuming only on an explicit `POST /v1/approvals/{thread_id}/resume`. The evaluator node generates a KMS-signed governance seal that must be present before the governed-trader subgraph executes — forged or absent seals return HTTP 403. After deployment, CAGE achieves a **100% pass rate** against the same red-team toolchain that previously produced catastrophic defeats.

---

## Mathematical Foundations

The CAGE governance kernel is grounded in formal mathematical theory, providing provable safety guarantees rather than best-effort heuristics.

### Control Barrier Function — Financial Safety

```
h(S(t+1)) ≥ (1−γ)·h(S(t))     where h(x) = cash_balance − min_cash_balance
```

This discrete-time CBF condition ([`src/gateway/governance/cbf.py`](../src/gateway/governance/cbf.py)) guarantees that the system state never leaves the safe set `S = {x ∈ ℝⁿ : h(x) ≥ 0}`. Any proposed trade that would violate the condition is denied before execution. State reads are atomic (Redis `WATCH/MULTI/EXEC`, `_MAX_RETRIES=5`).

### 7-Tier Symbolic Governor Pipeline

| Tier | Control | Key Invariant |
|------|---------|---------------|
| 1 | NoDirectBind | No tool call bypasses the governance wrapper |
| 2 | PII sanitization | All inputs scrubbed before downstream processing |
| 3 | CBF + OPA concurrent | `asyncio.gather` — barrier check + policy engine in parallel |
| 4 | Causal gatekeeper | SCM + PlaceboTreatmentRefuter (50 sims, p < 0.05, \|eff\| > 0.2); marginal risk boundary: `(0.5 + estimate.value × amount) > 0.95` |
| 5 | Confabulation scoring | `risk_score = 1.0 − confidence` |
| 6 | Consensus | ≥$10k trades, 30s timeout, heterogeneous multi-model quorum |
| 7 | FRIA zones | `FRIA_ZONE_ALLOW=0.95` / `FRIA_ZONE_DEFER=0.70` / score < 0.70 → BLOCK |

Source: [`src/gateway/governance/symbolic_governor.py`](../src/gateway/governance/symbolic_governor.py)

### FRIA Zone Thresholds (EU AI Act Art. 29a)

| Score | Zone | Action |
|-------|------|--------|
| ≥ 0.95 | ALLOW | Async attestation |
| 0.70 – 0.95 | DEFER | Synchronous HITL gate |
| < 0.70 | BLOCK | Hard deny |

### Key Invariants

| Invariant | Formula / Mechanism |
|-----------|---------------------|
| NoDirectBind | Structural — enforced at Python import level |
| Confabulation risk | `risk_score = 1.0 − confidence` |
| Causal lock | `(0.5 + estimate.value × amount) > 0.95` → DENY |
| Fiscal cap | $500k/day (integer cents), 86,400s window, exponential backoff |
| Provenance chain | SHA-256 hash chain, O(n) construction, sorted-key JSON |

---

## Status of This Document

| Attribute             | Value                                                                                                                                                                   |
| --------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Document type         | Engineering one-pager                                                                                                                                                   |
| Audience              | Engineering leads, compliance reviewers, AI governance evaluators                                                                                                       |
| Companion documents   | [`README.md`](../README.md), [`COMPLIANCE.md`](../COMPLIANCE.md), [`docs/GOVERNANCE_CROSSWALK.md`](../compliance/cross-region/GOVERNANCE_CROSSWALK.md), [`docs/NEURO_SYMBOLIC_GOVERNANCE.md`](../governance/NEURO_SYMBOLIC_GOVERNANCE.md) |
| Implementation status | v0.1.0 — 2026-06-08                                                                                                                                                    |
| Production readiness  | **GO — STABLE RELEASE APPROVED (v0.1.0, 2026-06-08)**; see [`docs/PRODUCTION_READINESS_REPORT.md`](PRODUCTION_READINESS_REPORT.md)                                     |
| Open issues           | File a GitHub issue for any defects or feature requests                                                                                                                 |
| Feedback              | File a GitHub issue or suggest edits via pull request                                                                                                                   |
