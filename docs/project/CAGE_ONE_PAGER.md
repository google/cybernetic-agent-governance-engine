# Cybernetic Agent Governance Engine (CAGE) — One-Pager

**Authors:** CAGE Engineering Team · **Last updated:** 2026-08-28 · **Status:** GO — STABLE RELEASE (v3.0.0)

---

## Problem, Why It Matters, Solution & Consequence

Any operator deploying high-reliability agentic AI faces a fundamental audit gap: LLM-based agents make consequential decisions (trade execution, risk classification, customer data handling, actuator commands, drug-dosage recommendations) through opaque, stateless inference calls with no enforceable policy boundary, no tamper-evident audit trail, and no mechanism for human override once a workflow is in motion. The current state of the art—prompt engineering and post-hoc log analysis—is neither deterministic nor regulatorily defensible under **SR 26-2** (Federal Reserve's April 2026 guidance on generative and agentic AI risk management), ISO/IEC 42001 (AI management system), or SOC 2 Type II. SR 26-2 explicitly declares that agentic systems are *outside the prescriptive scope of SR 11-7*, directing institutions to apply their own rigorous internal frameworks — CAGE is that framework, and its structural properties generalise beyond financial services to any domain where an agent can trigger consequential writes to authoritative state stores.

The cost of inaction is concrete: a single unchecked `execute_trade_action` call can bypass drawdown limits, leak PII in the response payload, and produce no evidence of the policy evaluation that should have blocked it. Automated red-team exercises against naive gateway implementations routinely achieve **100% adversarial success rates** on RBAC-002 (excessive permissions) and PII-004 (data leakage) attack classes.

**CAGE v3.0.0** is an open-source, Python-first governance runtime that wraps every LLM call and tool invocation in a deterministic, **8-tier policy enforcement pipeline** — without sacrificing production latency. The architecture is bifurcated: application logic (a LangGraph `StateGraph` multi-agent pipeline) is fully decoupled from the cloud provider, while a dedicated **Inference Gateway** (`src/gateway/`) handles all model traffic through a split-brain topology routing to two specialized vLLM pools (DeepSeek-R1 for reasoning; Llama 3.1 for structured governance output). The governance stack executes on every request: Aho-Corasick keyword scan → NeMo Guardrails (Colang 2.x + in-process Presidio PII) → **FTRA Pre-Pipeline Boundary Gate** (`src/gateway/governance/ftra/`, whole-graph reachability check before per-tool-call checks begin) → STPA hazard validator (Tier 0) → agent confidence pre-check (Tier 1) → Control Barrier Function + OPA policy engine (concurrent, Tiers 2/4) → Fiscal Limit Pre-Reservation (Tier 3) → multi-agent consensus (Tier 5) → causal gatekeeper (Tier 6) → adaptive FRIA gate (Tier 6b). The legacy SLM sidecar has been fully deprecated and replaced by a permanent `slm_available=false` sentinel to optimize latency. All compliance mapping is performed by the Python OSCAL exporter (`src/compliance_bridge/oscal_ssp_exporter.py`), achieving sub-millisecond audit-trail generation.

**CAGE introduces evidentiary independence & fail-closed runtime safety:**

- **Cloud KMS HSM-backed governance signing & Routing Seal v2** — asymmetric signing via Google Cloud KMS; private key never leaves the HSM; 4-tuple HMAC seal `<expire_hex>.<action_slug>.<record_hash_hex>.<hmac_hex>` binds SHA-256 evidence record hash with fail-closed actuator enforcement (`CAGE_REQUIRE_EVIDENCE_BINDING=true`)
- **6 Governance State Machine Primitives** — full first-class runtime execution for `ALLOW | DENY | REQUIRE_APPROVAL | DEFER | NARROW | PAUSE`
- **Lua-Atomic CBF with Strict Replica Barrier & Monotonic Fence Epoch** — collapses barrier check and balance deduction into atomic Redis Lua (`atomic_verify_and_commit()`), enforces synchronous `WAIT` replication with automatic fail-closed rollback on replica timeout, and prevents stale-state replay via monotonic `safety:fence_epoch`
- **Human-gated NeMo refinement** — the autonomous Langfuse → KFP → NeMo hot-reload loop is severed; all config refinements require explicit human approval with reviewer identity and rationale before applying
- **Heterogeneous multi-model consensus** — `ConsensusModelRegistry` routes each critic persona to a distinct vLLM backend; no single model can consent to its own output
- **Externally reconciled CBF (POAM-023 / POAM-2026-038 CLOSED)** — the Control Barrier Function's `cash_balance` is sourced from an independently reconciled external ledger via `src/compliance_bridge/reconciliation_worker.py` (GCS WORM ledger + Cloud KMS ECDSA-P256 signing with 300s TTL in Redis)
- **Token Quota Proxy** — per-session step-count (≤12) and token (≤100k) quota enforcement via Redis atomic Lua counters; fail-closed; HTTP 429 on quota exceeded; two-phase commit (reserve → reconcile); rollback on downstream failure (ISO 42001 Annex A.4)
- **PII Sanitizer** — pre-ledger regex sanitization pipeline (SSN, CC, email, phone, API key/Bearer token) applied to all UCA records before WORM persistence (ISO 42001 Annex A.6)
- **UCA Logger** — ISO 42001 Clause 6.1 UCA record builder; KMS-signed; region-gated WORM persistence (`CAGE_DEPLOYMENT_REGION` → `OSCAL_S3_BUCKET_{REGION}`); UCA types: `quota_exceeded`, `prompt_injection`, `pii_sanitization`
- **Evidence Stream Durability Preconditions** — `validate_evidence_stream_preconditions()` halts in production if blocking evidence durability is bypassed

Human oversight is enforced structurally, not by convention: the LangGraph graph pauses via `interrupt_before=["governed_trader"]` for all trades exceeding $10k or risk score > 0.7, checkpointing state to Redis and resuming only on an explicit `POST /v1/approvals/{thread_id}/resume`. The evaluator node generates a KMS-signed governance seal that must be present before the governed-trader subgraph executes — forged or absent seals return HTTP 403. After deployment, CAGE achieves a **100% pass rate** against the same red-team toolchain that previously produced catastrophic defeats.

---

## Mathematical Foundations

The CAGE governance kernel is grounded in formal mathematical theory, providing provable safety guarantees rather than best-effort heuristics.

### Control Barrier Function — Resource Invariant Safety

```
h(S(t+1)) ≥ (1−γ)·h(S(t))     where h(x) = cash_balance − min_cash_balance
```

This discrete-time CBF condition ([`src/gateway/governance/cbf.py`](../../src/gateway/governance/cbf.py)) guarantees that the system state never leaves the safe set `S = {x ∈ ℝⁿ : h(x) ≥ 0}`. Any proposed action that would violate the condition is denied before execution. State reads are atomic (Redis Lua script, monotonic fence epoch check, synchronous replica `WAIT` barrier). In the financial reference deployment `h(x) = cash_balance − min_cash_balance`; in other high-reliability deployments the same invariant structure applies to any continuous resource variable (API call budget, actuator torque envelope, drug-dosage ceiling, etc.).

### Pre-Pipeline Boundary Gate

| Gate | Control | Key Invariant |
|------|---------|---------------|
| **FTRA** | Forward-Looking Trajectory Reachability Analyzer | `create_ftra_node()` / `PlanGraphAnalyzer` / `IrreversibilityClassifier` — pre-execution graph reachability; CLEAR / HITL_REQUIRED / BLOCKED **before any tool call**. Operates on the **whole execution graph** — NOT a peer of Tiers 0–6b. |

### Two-Phase Eight-Tier Pipeline (`_run_checks()`)

| Phase | Tier | Control | Key Invariant |
|-------|------|---------|---------------|
| **Phase 1** | 0 | STPA/STAMP UCA validation | `GeneratedSTPAValidator.validate()` checks Unsafe Control Actions |
| **Phase 1** | 1 | Agent confidence pre-check | Fast-fail local check against `AGENT_CONFIDENCE_THRESHOLD` (default 0.95) |
| **Phase 1** | 2b | OPA policy engine | Declarative rule enforcement; validates structural policy prior to mutation |
| **Phase 1** | 5 | Consensus | High-stakes actions (≥$10k trades in the financial deployment), 30s timeout, heterogeneous multi-model quorum |
| **Phase 1** | 6 | Causal gatekeeper | SCM $\beta \le 0$ fail-closed guard + PlaceboTreatmentRefuter (50 sims, p < 0.05, \|eff\| > 0.2); bounded risk score $\le 0.95$ |
| **Phase 1** | 6b | FRIA zones | `FRIA_ZONE_ALLOW=0.95` / `FRIA_ZONE_DEFER=0.70` / score < 0.70 → DENY |
| **Phase 2** | 2a | Control Barrier Function | Redis-backed cash balance invariant; Lua atomic check+commit; `WAIT` replication barrier |
| **Phase 2** | 3 | Fiscal Limit Pre-Reservation | `FiscalLimitGuard.reserve()` — atomic Redis WATCH/MULTI/EXEC against daily cap |

> **Zero Budget Leakage:** Phase 2 state mutations execute only after all Phase 1 validation checks emit `ALLOW`. Rejections in Phase 1 prevent any ledger mutation or spending cap consumption.

Source: [`src/gateway/governance/symbolic_governor.py`](../../src/gateway/governance/symbolic_governor.py)

### FRIA Zone Thresholds (EU AI Act Art. 29a)

| Score | Zone | Action |
|-------|------|--------|
| ≥ 0.95 | ALLOW | Async attestation |
| 0.70 – 0.95 | DEFER | Synchronous HITL gate |
| < 0.70 | BLOCK | Hard deny |

### Key Invariants

| Invariant | Formula / Mechanism |
|-----------|---------------------|
| NoDirectBind | Machine-verified via BFS state model (57 sequential / 66 concurrent reachable states) — 100% satisfied |
| Evidence Sufficiency | 4-tuple HMAC Routing Seal v2 `<expire_hex>.<action_slug>.<record_hash_hex>.<hmac_hex>` binds SHA-256 evidence record hash |
| Bounded Composite Authority | Lua atomic check+commit + synchronous replica `WAIT` barrier + fail-closed automatic rollback |
| Mediation Coverage | Whole-graph FTRA + 7 in-pipeline tiers + fail-closed actuator enforcement |
| Confabulation risk | `risk_score = 1.0 − confidence` |
| Causal lock | $\beta \le 0 \lor \min(1.0, 0.5 + \beta \times \text{amount}) > 0.95 \lor \text{placebo invalid} \implies \text{DENY}$ |
| Operational budget cap | $500k/day (integer cents) in the financial reference deployment; 86,400s window, exponential backoff — threshold is domain-configurable |
| Provenance chain | SHA-256 hash chain, O(n) construction, sorted-key JSON |

---

## Status of This Document

| Attribute             | Value                                                                                                                                                                   |
| --------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Document type         | Engineering one-pager                                                                                                                                                   |
| Audience              | Engineering leads, compliance reviewers, AI governance evaluators                                                                                                       |
| Companion documents   | [`README.md`](../README.md), [`COMPLIANCE.md`](../../COMPLIANCE.md), [`docs/GOVERNANCE_CROSSWALK.md`](../compliance/cross-region/GOVERNANCE_CROSSWALK.md), [`docs/NEURO_SYMBOLIC_GOVERNANCE.md`](../governance/NEURO_SYMBOLIC_GOVERNANCE.md) |
| Implementation status | v3.0.0 — 2026-08-28                                                                                                                                                    |
| Production readiness  | **GO — STABLE RELEASE (v3.0.0, 2026-08-28)**; see `CHANGELOG.md` and `docs/security/SECURITY_STATUS.md` for current posture. CAGE has not received a NIST Authorization to Operate (ATO) — see the ATO caveat in `README.md`.                                     |
| Open issues           | File a GitHub issue for any defects or feature requests                                                                                                                 |
| Feedback              | File a GitHub issue or suggest edits via pull request                                                                                                                   |
