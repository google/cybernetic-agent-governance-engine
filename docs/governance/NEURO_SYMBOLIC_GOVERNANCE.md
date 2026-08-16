# Neuro-Symbolic Governance Architecture — v2.1.0

## Overview

The **Neuro-Symbolic Governance** layer implements the "Cybernetic" control system for the Financial Advisor. It combines probabilistic AI (Neural) with deterministic logic (Symbolic) to ensure safety and compliance.

> **Jurisdiction separation principle:** **ISO/IEC 42001:2023** is the **sole universal governance baseline**. All pipeline steps, controls, and audit artifacts marked *(All Regions)* apply to every deployment. Controls marked with a specific region (`US_FED`, `EU_ECB`, `APAC_MAS`) are additive obligations for that jurisdiction only, activated by `CAGE_DEPLOYMENT_REGION`.

---

## Bifurcated Governance Architecture (Handling Goal-Directed Persistence)

A known vulnerability in autonomous agentic systems is **goal-directed persistence**. If a policy engine blocks an action and feeds a verbose error back to the LLM (e.g., `Policy Denied: amount > 50000`), the agent does not interpret this as a hard stop. It views the error as a puzzle to solve (e.g., "I will split the 80,000 trade into two 40,000 trades").

To prevent the AI from learning how to circumvent rules, CAGE employs a **Bifurcated Governance Architecture**:

1. **Soft Planning Boundaries (System 4 → System 3 Loop):**
   Feedback is allowed *only* during the internal planning phase. The Execution Analyst (Planner) proposes a strategy, and the Evaluator checks it against STPA and CBF constraints. If rejected, the Evaluator feeds the error back to the Planner so it can adjust its financial strategy. A strict circuit breaker trips after 3 failures, terminating the loop.
2. **Hard Governance Black Boxes (The Graph Edge):**
   Once a plan is approved, it hits the hard governance gates: **NeMo Guardrails** and the **OPA Policy Engine**. When these gates trigger a block, the error is caught at the graph edge and the agent's context window is physically severed. The workflow routes instantly to a terminal `END` or `explainer` state. The LLM never sees the error payload and therefore cannot negotiate or reason about how to bypass it.

---

## Architecture Components

### 1. Symbolic Governor (`src/gateway/governance/symbolic_governor.py`)

The central enforcement engine residing in the Gateway. It wraps every tool execution request.

- **Responsibility:** Intercepts tool calls and validates them against safety rules _before_ execution (or concurrently in Optimistic mode).
- **Module-level startup guards:** `symbolic_governor.py` raises `RuntimeError` at import time if any of the following unsafe conditions are detected: `CBF_FAIL_OPEN=true` in production, `dowhy` package absent in production, KMS readiness failure, Redis readiness failure, or `RECONCILIATION_PROVIDER=stub` with `CAGE_ENV=production` (CAGE-SEC-007).
- **Checks (7-Tier Pipeline):**

  > **See also:** [`docs/governance/GOVERNANCE_OVERVIEW.md`](GOVERNANCE_OVERVIEW.md) for the canonical layer model and infrastructure context.

  | Tier | Name | Implementation | Notes |
  |------|------|---------------|-------|
  | **0** | STPA UCA Constraint Check | `GeneratedSTPAValidator.validate()` | Aho-Corasick keyword scan against 14 tier-1 keywords; checks for Unsafe Control Actions (UCAs) defined in the ontology *(All Regions)* |
  | **1** | Agentic Confidence Pre-check | Fast-fail local check | `AGENT_CONFIDENCE_THRESHOLD` fast-fail before CBF/OPA; OPA `trade_governance.rego` (package `trade.governance`) is the **sole enforcer** of `CTRL_AGT_001` — three-zone confidence model: ALLOW ≥ 0.95, DEFER 0.70–0.95, DENY < 0.70. `min_trade_confidence` in `governance_thresholds.json` is **deprecated** — OPA is now authoritative. ISO 42001 §A.5.2 *(All Regions)* |
  | **2/4** | CBF + OPA concurrent evaluation | `asyncio.gather(cbf_check, opa_check)` | **Tier 2:** `ControlBarrierFunction.atomic_verify_and_commit()` (`cbf.py`) — Redis-backed Lua atomic cash balance invariant `h(x) = cash_balance − min_cash_balance ≥ 0` (γ=0.5, min=$1,000). `atomic_verify_and_commit()` collapses check+commit into a single Lua hop. CBF tracks `_local_debits` locally; `effective_balance = snapshot_balance - _local_debits` is used for all checks to prevent intra-window double-spend; `reset_local_debits()` is called by the reconciliation daemon on each snapshot refresh. `_read_cbf_state_atomic()` prioritises `reconciliation:verified_balance` (KMS-signed external balance from reconciliation worker, POAM-023) then falls back to `safety:current_cash` with CRITICAL audit log. **Tier 4:** `OPAClient.evaluate_policy()` evaluates `trade_governance.rego`. Combined latency = `max(CBF_ms, OPA_ms)`. *(All Regions)* |
  | **2 (post)** | POAM-TIER2-001 Structural Corroboration | Inline in `_run_checks()` after Tier 2/4 | Structural corroboration heuristic: derives independent confidence signal from STPA violation count and OPA margin. Flags structural risk when STPA violation count ≥ 1 AND OPA margin below threshold, overriding the model-supplied confidence signal. *(All Regions)* |
  | **3** | Fiscal Limit Pre-Reservation | `FiscalLimitGuard.reserve()` | Atomically reserves the requested USD amount against the daily cap in Redis (WATCH/MULTI/EXEC) **before** the consensus gate, closing the TOCTOU race between the CBF balance check and actual trade execution. Released on any subsequent pipeline failure. *(All Regions)* |
  | **5** | Multi-Agent Consensus | `ConsensusEngine.check_consensus()` | Triggers heterogeneous multi-model consensus via `ConsensusModelRegistry` for trades exceeding threshold ($10k default **US_FED**; $7.5k **EU_ECB**; $5k **APAC_MAS**). Unanimity required — any dissent blocks the trade. 30-second hard timeout per critic. Degraded-quorum routing: `ERROR + APPROVE → ESCALATE` (HITL) is explicitly handled before catch-all. Background audit logging via `_AUDIT_QUEUE` (`asyncio.Queue(maxsize=1000)`). *(All Regions)* |
  | **6** | DoWhy Causal Gatekeeper | `causal_safety_check()` (`causal_gatekeeper.py`) | 50-simulation placebo refutation causal validation (p<0.05). **Fails closed** when no live telemetry is provided in production — no mock fallback. Sync cache helpers (`_causal_cache_get_sync`/`_causal_cache_set_sync`) used for `asyncio.to_thread` safety. Active in **US_FED** and **APAC_MAS**; suppressed in **EU_ECB** per GDPR / MAS Notice 655 telemetry restriction. |
  | **6b** | FRIA Normative Boundary + Attestation | `enforce_fria_boundary()` + OTel stamp | **Merged step** (formerly Steps 6b and 7): adaptive FRIA enforcement (ALLOW/DEFER/DENY based on consensus score) combined with EU AI Act Art. 29a OTel attestation (`CTRL_FRIA_006`). Enforcement runs when `CAGE_NORMATIVE_PROVIDER != "static"`; attestation stamp always applied for **EU_ECB** deployments. **EU_ECB only** — no-op for US_FED and APAC_MAS. |

  > **Note — SLM Tier removed:** The former Tier 3 (SLM Semantic Similarity) has been fully retired. The SLM sidecar code has been deleted. The confidence threshold (Tier 1) is now enforced exclusively by OPA, with the SLM-degraded escalation (0.95 → 0.97) baked into `trade_governance.rego`.

### 1a. LangGraph Harness — Governance Node Composition (v2.1.0)

The LangGraph harness (`src/gateway/governance/langgraph_harness/`) is the **composition layer** that bridges the neural (NeMo) and symbolic (OPA, STPA, CBF) components into typed LangGraph `StateGraph` nodes:

| Module | Bridges | Pattern |
|---|---|---|
| [`nemo_node_factory.py`](../../src/gateway/governance/langgraph_harness/nemo_node_factory.py) | NeMo Guardrails (neural) → LangGraph node | `GovernanceNodeInput → GovernanceNodeOutput` |
| [`opa_node_factory.py`](../../src/gateway/governance/langgraph_harness/opa_node_factory.py) | OPA Rego (symbolic) → LangGraph node | `GovernanceNodeInput → GovernanceNodeOutput` |
| [`types.py`](../../src/gateway/governance/langgraph_harness/types.py) | Shared TypedDicts | `GovernanceNodeInput`, `GovernanceNodeOutput` |

The harness ensures that both neural and symbolic governance checks participate in the same typed state machine, with deterministic state transitions and full OTel tracing. The FTRA node factory (`src/gateway/governance/ftra/node_factory.py`) uses the same pattern for the pre-execution structural reachability check.

### 1b. NeMo Guardrails Phase 4.2 Changes (`src/gateway/governance/nemo/manager.py`)

Phase 4.2 introduced the following changes to the NeMo Guardrails integration:

- **Removed substring heuristics:** Phrase-list matching (e.g., "I cannot answer") has been removed and replaced with structured rail evaluation. The old approach was brittle and produced false positives on legitimate refusals.
- **Transparent fallback mode (`DEGRADED_FAIL_OPEN`):** When `RailsConfig` parse fails due to a Colang 2.x `lark.UnexpectedToken` error, NeMo runs as a no-op stub rather than crashing the gateway. This is a production-safe degradation path — OPA + STPA remain authoritative.
  - When degraded: all requests are stamped `DEGRADED_FAIL_OPEN` in Langfuse with `stpa_hazard=UCA-1_SEMANTIC_BYPASS` and `iso_control=A.5.2` so the degradation is fully observable.
- **Pre-check injection:** A pre-check is injected to break re-entrant loops that could cause NeMo to call itself recursively.
- **Response deduplication:** Duplicate rail processing is prevented to avoid double-stamping governance decisions.

### 2. STPA Validator (`src/gateway/governance/generated_stpa_validator.py`)

Implements the System-Theoretic Process Analysis (STPA) logic via the auto-generated `GeneratedSTPAValidator` class.

- **Primary class:** [`GeneratedSTPAValidator`](../../src/gateway/governance/generated_stpa_validator.py) — auto-generated by `stpa_compiler.py` from `config/stpa_control_structure.yaml`. Contains `validate()` (canonical entry-point, delegates to `validate_generated()`) and per-UCA check methods (`_check_uca_1()` through `_check_uca_9()`).
- **v3.0.0:** The deprecated `stpa_validator.py` shim was removed. Import `GeneratedSTPAValidator` directly from `generated_stpa_validator.py`.
- **Ontology:** Uses `src/gateway/governance/ontology.py` to define:
  - **UCAs (Unsafe Control Actions):** Specific hazards (e.g., "Trade with >200ms latency", "Write DB without Auth").
  - **Constraints:** Logic to detect these hazards in tool parameters.
- **Logic:** Deterministic rule engine. If a parameter violates a constraint, `validate()` returns a list of violation strings; an empty list means no violations.

### 3. KMS Asymmetric Governance Signing (PRIMARY) — HMAC-SHA256 Fallback (Dev/CI Only)

Enables the **Explicit Lifecycle** model, replacing asynchronous interrupts with deterministic authorization backed by an external Hardware Security Module.

- **Concept:** The Executor cannot act unless it possesses a valid `governance_signature` generated by the Evaluator after a successful policy check. In production, this signature is produced by Google Cloud KMS — the private key never leaves the HSM.
- **Primary Path — GCP KMS Asymmetric Signing (`src/gateway/governance/kms_signer.py`):**
  - **Sign:** The Evaluator Node calls `KMSGovernanceSigner.sign(plan)`, which computes a SHA-256 digest of the canonical plan and calls `asymmetricSign` on the KMS HSM via gRPC. The hex-encoded signature is stored in `AgentState.governance_signature`.
  - **Verify:** The `explainer_node` calls `KMSGovernanceSigner.verify(plan, signature)`, which validates the signature locally using the RSA/EC public key embedded at container build time — no KMS call required for verification.
  - **External Trust Anchor:** The trust root (KMS HSM) is outside the application's control plane. Cloud Audit Logs provide immutable, external attestation of every signing operation. A compromised container cannot forge a signature without calling KMS.
  - **Non-repudiation:** The private signing key never leaves the HSM. A forensic auditor can request the Cloud Audit Log for the key ring and confirm exactly when and by what workload identity a signature was created.
- **Fallback Path — HMAC-SHA256 (dev/CI only):**
  - When Cloud KMS is unavailable (local dev, CI, missing credentials), `KMSGovernanceSigner` falls back to a local HMAC-SHA256 using `GOVERNANCE_SALT` (if set) and emits a WARNING.
  - The `is_kms_active` property returns `False` when in fallback mode; the compliance bridge will flag this as a compliance gap.
  - The HMAC fallback is **not acceptable for production** — it reintroduces the recursive self-authentication vulnerability where the signing key lives in the same process memory as both signer and verifier.
- **Shared State:** `governance_signature` field in the `AgentState` TypedDict.
- **Enforcement (Graph):** The LangGraph `StateGraph` uses a conditional edge function `check_safety_signature` that inspects the state. If the signature is invalid or mismatched, the flow is routed to a `REJECTED` or `SELF_CORRECTION` state.
- **Enforcement (Tool):** The `execute_trade` tool explicitly validates the signature against the current plan before initiating any external connection.
- **Environment Variables:**
  - `KMS_GOVERNANCE_KEY` — Full KMS key version resource name (enables KMS path)
  - `KMS_GOVERNANCE_PUBLIC_PEM` — Path to PEM-encoded public key file (embedded at build time for sub-millisecond verification)
  - `GOVERNANCE_SALT` — Legacy HMAC salt (fallback only; used when KMS is not configured)
- **Compliance:** Satisfies strict financial audit requirements under SR 26-2 (agentic systems) and ISO 42001 §6.1. Closes the recursive self-authentication vulnerability identified in the evidentiary independence analysis (v2.0.0).

### 4. DoWhy Causal Gatekeeper (`src/gateway/governance/causal_gatekeeper.py`)

The **"Lock on the CAGE"** — a causal inference layer that validates the system's world-model integrity before allowing high-stakes actions.

- **Responsibility:** Uses Microsoft DoWhy's causal inference framework to determine whether the system's understanding of market dynamics is trustworthy enough to execute a trade.
- **Causal Graph:**
  ```
  market_volatility → trade_amount
  market_volatility → risk_score
  trade_amount → risk_score
  ```
- **Mechanism:**
  1. **Model Construction:** Builds a `CausalModel` from historical telemetry data (market volatility, trade amounts, risk scores).
  2. **Effect Identification:** Uses the backdoor criterion to identify the causal effect of `trade_amount` on `risk_score`, controlling for `market_volatility`.
  3. **Estimation:** Estimates the Average Treatment Effect (ATE) via linear regression for real-time speed.
  4. **Refutation (The Lock):** Applies a Placebo Treatment Refuter — replaces the real treatment with random noise. If the model still detects a significant effect (p < 0.05 or |effect| > 0.2), the world-model is deemed untrustworthy.
  5. **Safety Boundary:** Also blocks trades where the estimated marginal effect pushes the predicted risk score above 0.95.
- **Fail-Safe:** Returns `False` (blocks trade) on any exception — if causal validity cannot be proven, the action is denied. In production (`CAGE_ENV=production`), the function **fails closed** when no live telemetry is provided — there is no mock fallback for missing telemetry.
- **Cache:** Results cached in Redis using synchronous helpers `_causal_cache_get_sync` / `_causal_cache_set_sync` — these are safe for `asyncio.to_thread` worker pools. TTL = `CAUSAL_CACHE_TTL_SECONDS` (60 s). Telemetry staleness limit = `TELEMETRY_MAX_STALENESS_SECONDS` (300 s).
- **Integration:** Injected as Tier 6 in `SymbolicGovernor._run_checks()`, executed only for `execute_trade` actions via `validate_causal_ordering()`.
- **Telemetry Source — Dual Phase:** Accepts a `BaseTelemetryProvider`. In production, `LangfuseTelemetryProvider` sources live governance spans from Langfuse. The function emits **two OTel child spans**:
  - `causal_gatekeeper.statistical_kernel` — tagged `CTRL_MRM_004` (SR 26-2 MRM): causal model setup, effect identification, and coefficient estimation.
  - `causal_gatekeeper.placebo_refutation` — tagged `CTRL_TEL_003` (ISO 42001 §A.9.4): 50-simulation placebo refuter against live telemetry.

---

## Workflow

The 10-node LangGraph StateGraph governs the full execution lifecycle:

| # | Node | Purpose |
|---|------|---------|
| 1 | `nemo_input_rail` | NeMo Guardrails input screening |
| 2 | `stpa_validator` | STPA UCA policy check |
| 3 | `causal_gatekeeper` | DoWhy SCM intervention simulation |
| 4 | `symbolic_governor` | 7-tier symbolic check pipeline (Tiers 0–6b) |
| 5 | `consensus_node` | Multi-model consensus (≥$10k trades) |
| 6 | `hitl_gate` | Human-in-the-loop interrupt |
| 7 | `post_hitl_rehydrate` | TOCTOU remediation — state rehydration |
| 8 | `post_hitl_revalidate` | TOCTOU remediation — Tiers 2/4 re-validation only (CBF + OPA) |
| 9 | `saga_router` | LangGraph Saga WAL + LIFO rollback |
| 10 | `nemo_output_rail` | NeMo Guardrails output screening |

### Step-by-Step Execution

1.  **Plan:** Agent generates a plan.
2.  **Evaluate:** Graph routes to the **Evaluator** node.
3.  **Governance Check:** Evaluator calls `check_safety_constraints` (OPA, CBF, STPA) in the Gateway via the 7-tier `SymbolicGovernor._run_checks()` pipeline (Tiers 0–6b: STPA → Confidence/OPA concurrent with CBF → POAM-TIER2-001 structural corroboration → Fiscal Limit Pre-Reservation → Consensus → Causal → FRIA).
4.  **Context Accumulation (AARM-V1):** The SHA-256 hash-chained context accumulator (`src/compliance_bridge/context_accumulator.py`) appends each governance decision to the immutable chain, preventing context poisoning.
5.  **Causal Validation:** DoWhy Causal Gatekeeper validates world-model integrity via 50-simulation placebo refutation (p<0.05). Fails closed if no live telemetry in production.
6.  **Sign:** If safe, Evaluator generates a **Cloud KMS HSM-backed asymmetric signature** (primary) and appends it to the shared state. HMAC-SHA256 is used only in dev/CI when KMS is unavailable.
7.  **HITL Gate:** For trades >$10,000 USD or risk_score >0.7, the `hitl_gate` node interrupts the graph for human review.
    - **TOCTOU Remediation:** On human approval, `post_hitl_rehydrate` reloads the latest state from the Redis checkpointer (preventing stale-state execution), then `revalidate_post_hitl()` in `symbolic_governor.py` re-runs **only Tiers 2 and 4** (CBF + OPA) — the tiers most likely to drift during a HITL review window. STPA, consensus, causal, and FRIA tiers are not re-run.
8.  **DEFER Queue (AARM-V7):** Contexts failing the confidence threshold but not outright denied are pushed to Redis `db=1` (noeviction, key prefix `DEFER:`, TTL 4 h) for deferred human review.
9.  **Audit Gate:**
    - _Path A (Safe):_ Signature verified → Graph transitions to `governed_trader` node.
    - _Path B (Unsafe):_ Signature missing/failed → Graph routes to `explainer` node (no trade executed).
    - _Path C (Causal Lock):_ DoWhy refutation failed → Trade blocked; violation logged.
    - _Path D (DEFER):_ Confidence below threshold → Context pushed to DEFER queue; response deferred.
10. **Explain:** The `explainer` node generates a user-facing narrative; the NeMo output rail runs a final in-process Presidio PII egress scan before returning the response.

---

## Neuro-Symbolic Architecture Summary (v2.1.0)

The CAGE neuro-symbolic governance architecture has three distinct layers:

| Layer | Components | Role |
|---|---|---|
| **Neural** | NeMo Guardrails (`src/gateway/governance/nemo/`), Colang rails (`cbrn_rails.co`) | Learned safety rails; CBRN keyword detection; PII masking; hot-reloadable. **Note (2026-08-06):** inside the GFA pod, all consumers (LangGraph guardrail nodes, `tools/api.py`, `server.py` hot-reload endpoints) share a single `LLMRails` singleton owned by `nemo_node_factory.py`, reloaded atomically via `reload_nemo_rails()` — see [`src/gateway/governance/nemo/README.md`](../../src/gateway/governance/nemo/README.md#gfa-pod--singleton-consolidation-2026-08-06). |
| **Symbolic** | OPA Rego (`src/governed_financial_advisor/governance/policy/trade_governance.rego`, `config/opa/`), STPA validator (`generated_stpa_validator.py`), CBF (`cbf.py`) | Formal invariants; mathematical safety properties; fail-closed. **v3.0.0:** The deprecated `safety.py` shim was removed — import directly from `cbf.py`. |
| **Composition** | LangGraph harness (`langgraph_harness/`), FTRA gate (`ftra/`) | Typed node factories; StateGraph integration; pre-execution structural checks |

The symbolic layer provides the **safety floor** (CBF invariance theorem: `h(x) ≥ 0` must hold at all times). The neural layer provides **learned pattern recognition** (CBRN keywords, PII entities, confabulation signals) that the symbolic layer cannot express as closed-form invariants. The composition layer ensures both participate in the same typed state machine with deterministic transitions.

---

## Compliance Mapping

All regulatory citations are decoupled from Python execution code via the `GovernanceControl` registry ([`src/gateway/governance/constants.py`](../../src/gateway/governance/constants.py)). The `ControlRegistry` singleton loads the JSON baseline profile for the active region; `active_hash` returns the SHA-256 of the loaded profile, used for drift detection via `validate_action(policy_version_id=...)`. Violation messages carry structured `[CTRL_*]` prefixes.

### Universal Controls (All Deployment Regions — ISO 42001 Baseline)

| Control ID | Framework | Component | Requirement |
|---|---|---|---|
| `CTRL_AGT_001` | **ISO 42001 §A.5.2** | `symbolic_governor.py` Tier 1 + `trade_governance.rego` (package `trade.governance`) | Agentic AI bounding; minimum confidence threshold enforced **exclusively by OPA** (0.95 normal; 0.97 SLM-degraded). `min_trade_confidence` in `governance_thresholds.json` is deprecated. *(All Regions)* |
| `CTRL_WAL_002` | **ISO 42001 §A.8.4** | `generated_saga_nodes.py` WAL SAGA nodes | Non-determinism containment; transactional atomicity + rollback *(All Regions)* |
| `CTRL_TEL_003` | **ISO 42001 §A.9.4** | `causal_gatekeeper.py` (Phase 2), `telemetry_provider.py` | Live telemetry validation; DoWhy 50-simulation placebo refutation monitoring *(All Regions)* |
| `CTRL_OPA_005` | **ISO 42001 §A.6.1** | `symbolic_governor.py` OPA policy check | Enterprise policy enforcement gate *(All Regions)* |
| `CTRL_FRIA_006` | **EU AI Act Art. 29a** | `symbolic_governor.py` Tier 6b — `enforce_fria_boundary()` + OTel stamp | FRIA normative boundary enforcement + attestation — **EU_ECB only** |
| `CTRL_TQP_007` | **ISO 42001 §A.6.1** | Token quota exhaustion policy in `trade_governance.rego` | Token quota hard deny via OPA *(All Regions)* |
| `CTRL_FTRA_001` | **FTRA reachability** | `ftra/` structural analysis | Pre-execution FTRA commencement reachability gate *(All Regions)* |
| KMS Signed Trail | **ISO 42001 §A.7.4** | `kms_signer.py`, `evaluator_node.py` | Non-repudiation; HSM-backed asymmetric signed auditor trail for agentic actions (KMS primary; HMAC fallback dev/CI only) *(All Regions)* |
| AARM-V1 Context Chain | **CSA AARM v1.0** | `context_accumulator.py` | SHA-256 hash-chained context accumulator; prevents context poisoning *(All Regions)* |
| AARM-V7 DEFER Queue | **CSA AARM v1.0** | `defer_queue.py` (Redis db=1 noeviction) | Confidence starvation handling; deferred human review *(All Regions)* |

### US_FED Jurisdiction Controls (`CAGE_DEPLOYMENT_REGION=US_FED`)

| Control ID | Framework | Component | Requirement |
|---|---|---|---|
| `CTRL_MRM_004` | **SR 26-2 §IV** — Model Risk Management (Federal Reserve, April 17, 2026) | `cbf.py` (`ControlBarrierFunction`), `causal_gatekeeper.py` (Phase 1) | Agentic AI MRM: deterministic formula validation + causal coefficient back-testing — **US_FED only** |
| NIST AI RMF | **NIST AI RMF MEASURE-2.6** | DoWhy both phases | Explicit `CONTROL` transitions + continuous world-model `MEASURE` validation — **US_FED only** |

### EU_ECB Jurisdiction Controls (`CAGE_DEPLOYMENT_REGION=EU_ECB`)

| Control ID | Framework | Component | Requirement |
|---|---|---|---|
| `CTRL_FRIA_006` | **EU AI Act Art. 29a** | `symbolic_governor.py` Tier 6b — `enforce_fria_boundary()` + OTel stamp | FRIA normative boundary enforcement + attestation stamped on OTel span attributes — **EU_ECB only** |
| `CTRL_WAL_002` addendum | **DORA Art. 12** | `generated_saga_nodes.py` WAL SAGA nodes | DORA operational resilience logging obligation — **EU_ECB only** (addendum to ISO 42001 §A.8.4 base control) |

---

## Symbolic Governor Architecture

> **Source:** [`src/gateway/governance/symbolic_governor.py`](../../src/gateway/governance/symbolic_governor.py)

### 7-Tier Pipeline Diagram

The `SymbolicGovernor._run_checks()` method executes the following tiers in strict sequential order (Tiers 2 and 4 run concurrently with each other). A failure at any tier halts the pipeline and denies the request.

```
┌─────────────────────────────────────────────────────────────────────┐
│                  SymbolicGovernor._run_checks()                     │
│                                                                     │
│  Tier 0 ──► STPA/STAMP UCA validation                               │
│      │      (GeneratedSTPAValidator.validate() — ontology checks)   │
│      ▼                                                              │
│  Tier 1 ──► Agent confidence pre-check                              │
│      │      (fast-fail local check; AGENT_CONFIDENCE_THRESHOLD)     │
│      ▼                                                              │
│  Tier 2/4 ─► CBF + OPA concurrent evaluation                        │
│      │      asyncio.gather(cbf_check, opa_check)                    │
│      │      CBF: atomic_verify_and_commit() — single Lua hop        │
│      │      latency = max(CBF_ms, OPA_ms)                           │
│      ▼                                                              │
│  Tier 2 post ► POAM-TIER2-001 structural corroboration              │
│      │      (STPA violation count + OPA margin heuristic)           │
│      ▼                                                              │
│  Tier 3 ──► Fiscal Limit Pre-Reservation                            │
│      │      FiscalLimitGuard.reserve() — Redis WATCH/MULTI/EXEC     │
│      ▼                                                              │
│  Tier 5 ──► Consensus (high-value trades ≥ $10k)                   │
│      │      asyncio.gather — unanimity required; 30 s timeout       │
│      ▼                                                              │
│  Tier 6 ──► Causal gatekeeper                                       │
│      │      (DoWhy CausalModel + PlaceboTreatmentRefuter)           │
│      │      fails closed in production with no live telemetry       │
│      ▼                                                              │
│  Tier 6b ─► FRIA normative boundary + attestation                   │
│             score ≥ 0.95 → ALLOW (async attestation)               │
│             0.70 ≤ score < 0.95 → DEFER (blocking gate)            │
│             score < 0.70 → DENY (hard deny)                         │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼ (all tiers pass)
                    KMS Routing Seal issued
                    (X-CAGE-Routing-Seal header)
```

> **Note:** PII sanitization (`pii_sanitizer.py`) and confabulation scoring (`confabulation_scorer.py`) are **not** tiers of `_run_checks()`. PII sanitization runs inside `uca_logger.py` immediately before a UCA audit record is written to the WORM ledger; confabulation scoring is a standalone Langfuse observability metric.

### Tier 2/4 — Concurrent CBF + OPA Execution

Tiers 2 and 4 are the only tiers that execute two sub-checks in parallel. The implementation uses `asyncio.gather` so that the Control Barrier Function and the OPA policy evaluation run concurrently:

```python
cbf_result, opa_result = await asyncio.gather(
    cbf_check(),   # src/gateway/governance/cbf.py — atomic_verify_and_commit()
    opa_check(),   # trade_governance.rego via OPAClient
)
```

Both results must be `ALLOW` for the tier to pass. The combined latency is `max(CBF_ms, OPA_ms)` rather than their sum.

The preferred CBF path is `ControlBarrierFunction.atomic_verify_and_commit()` — a single Lua script (`LUA_ATOMIC_CBF`) that collapses the read-check-write sequence into one atomic Redis hop, eliminating the TOCTOU window. **v3.0.0:** `update_state()` was renamed to `_update_state_unsafe()` and is now internal-only — use `atomic_verify_and_commit()` instead.

### FRIA Zone Decision Boundaries (Tier 6b)

The Fundamental Rights Impact Assessment at Tier 6b uses two threshold constants to partition the governance score space:

| Constant | Value | Zone | Decision Semantics |
|----------|-------|------|--------------------|
| `FRIA_ZONE_ALLOW` | `0.95` | ALLOW | Score ≥ 0.95 → request proceeds; async OTel attestation emitted (EU AI Act Art. 29a) |
| `FRIA_ZONE_DEFER` | `0.70` | DEFER | 0.70 ≤ score < 0.95 → synchronous blocking gate; request pushed to DEFER queue (Redis db=1, 4 h TTL) |
| *(implicit)* | `< 0.70` | BLOCK | Score < 0.70 → hard deny; violation logged with `[CTRL_FRIA_006]` prefix |

Both constants are env-overridable at startup. The FRIA enforcement path (`enforce_fria_boundary()`) runs only when `CAGE_NORMATIVE_PROVIDER != "static"`. The OTel attestation stamp is always applied for `EU_ECB` deployments regardless of the normative provider setting.

---

## Formal Safety Properties

This section states the mathematical safety properties that the governance pipeline is designed to enforce. Each property is derived directly from the source implementation.

### CBF Invariance Theorem

**Barrier function:** `h(x) = cash_balance − min_cash_balance`

**Discrete-time CBF condition:**

```
h(S(t+1)) ≥ (1−γ) · h(S(t))
```

**Theorem:** If `h(S(0)) ≥ 0` (initial state is safe) and the condition `h(S(t+1)) ≥ (1−γ)·h(S(t))` holds for all t ≥ 0, then `h(S(t)) ≥ 0` for all t ≥ 0.

**Proof sketch:** By induction. Base case: `h(S(0)) ≥ 0` by assumption. Inductive step: if `h(S(t)) ≥ 0` then `h(S(t+1)) ≥ (1−γ)·h(S(t)) ≥ 0` since γ ∈ (0,1]. Therefore the cash balance never falls below `min_cash_balance` as long as every proposed state transition satisfies the CBF condition.

Parameters (from `config/governance_thresholds.json`): γ = 0.5, `min_cash_balance` = $1,000.

> **Source:** [`src/gateway/governance/cbf.py`](../../src/gateway/governance/cbf.py)

> **BFS proof scope:** The current BFS proof covers the governance state machine only; a TLA+/Alloy model of the full implementation (including LangGraph harness, Redis state, and FTRA boundary) is tracked as future work. Note: Tier 0.5 (FTRA) executes before `_run_checks()` and is **not** included in the 21-state BFS automaton; this is a documented verification gap.

### NoDirectBind Invariant — Formal Statement

Let `LLM_output` be any token sequence produced by the language model and `exec(·)` be any executable action (trade, API call, state mutation). The NoDirectBind invariant requires:

```
∀ LLM_output: exec(LLM_output) is permitted
    only if SymbolicGovernor._run_checks(LLM_output) = ALLOW
```

Equivalently, there is no code path from LLM inference to tool execution that bypasses `_run_checks()`. This is enforced structurally by `validate_action()` — the single choke point for tool execution — combined with the HMAC-SHA256 routing seal (`generate_seal()` / `verify_seal()` in `routing_seal.py`). A seal is issued only after all tiers of `_run_checks()` complete successfully, and the downstream actuator raises `GovernanceError` (refusing to execute) if `verify_seal()` fails.

> **Source:** [`src/gateway/governance/symbolic_governor.py`](../../src/gateway/governance/symbolic_governor.py)

### Confabulation Risk Formula

```
risk_score = 1.0 − confidence
```

**Decision rule:**

```
risk_score ≥ 0.95  →  BLOCK  (confidence ≤ 0.05)
risk_score < 0.95  →  PASS   (confidence > 0.05)
```

The threshold of 0.95 ensures that only LLM outputs with meaningful grounding confidence (> 5%) are permitted to proceed to execution tiers.

> **Source:** [`src/gateway/governance/confabulation_scorer.py`](../../src/gateway/governance/confabulation_scorer.py)

### Causal Marginal Risk Boundary

The causal gatekeeper enforces a safety boundary on the estimated marginal effect of `trade_amount` on `risk_score`:

```
(0.5 + estimate.value × amount) > 0.95  →  LOCK (trade blocked)
```

where `estimate.value` is the Average Treatment Effect (ATE) estimated via backdoor linear regression on the causal graph:

```
market_volatility → trade_amount → risk_score
market_volatility → risk_score
```

Additionally, the **Placebo Treatment Refuter** (50 simulations) validates world-model integrity:

```
p < 0.05  OR  |placebo_effect| > 0.2  →  BLOCK (world-model untrustworthy)
```

**Fail-safe:** any exception in the causal pipeline returns `False` (blocks the trade). In production, missing live telemetry also returns `False` — causal validity must be positively proven; it cannot be assumed.

> **Source:** [`src/gateway/governance/causal_gatekeeper.py`](../../src/gateway/governance/causal_gatekeeper.py)

---

## Regional Compliance Mapping

> **Source:** [`src/gateway/governance/ontology.py`](../../src/gateway/governance/ontology.py)

The ontology defines three regional control maps. The active map is selected at runtime by the `CAGE_DEPLOYMENT_REGION` environment variable. ISO 42001 controls apply universally to all regions; regional maps add jurisdiction-specific obligations on top.

### How `CAGE_DEPLOYMENT_REGION` Gates Regional Behaviour

```bash
export CAGE_DEPLOYMENT_REGION=US_FED    # Federal Reserve / NIST obligations
export CAGE_DEPLOYMENT_REGION=EU_ECB    # EU AI Act / GDPR / DORA obligations
export CAGE_DEPLOYMENT_REGION=APAC_MAS  # MAS FEAT / MAS Notice 655 / MAS TRM obligations
```

The `ControlRegistry` singleton reads this variable at startup and loads the corresponding baseline profile. `active_hash` (SHA-256 of the loaded profile JSON) is compared against `policy_version_id` in `validate_action()` calls for drift detection. `reconfigure(region)` uses a TOCTOU-safe atomic swap. No Python source changes are required to add or modify a regional mapping — it is a JSON-only operation.

### US_FED Regional Control Map (`CAGE_DEPLOYMENT_REGION=US_FED`)

| Control | Framework | Pipeline Tier | Obligation |
|---------|-----------|--------------|------------|
| `CTRL_MRM_004` | SR 26-2 §IV — Model Risk Management (Federal Reserve, April 17, 2026) | Tier 2 (CBF) + Tier 6 (Causal) | Deterministic formula validation + causal coefficient back-testing |
| NIST AI RMF MEASURE-2.6 | NIST AI RMF | Tier 6 (Causal) | Explicit CONTROL transitions + continuous world-model MEASURE validation |
| NIST SP 800-53 | NIST SP 800-53 (10 Lula assertions) | All tiers | Access control, audit, system integrity controls |
| `CTRL_AGT_001` | ISO 42001 §A.5.2 + NIST AI 600-1 | Tier 4 (OPA) | Agentic AI bounding; confidence threshold ≥ 0.95 |
| Consensus threshold | SR 26-2 §IV.B | Tier 5 | $10,000 USD threshold for multi-agent consensus |

### EU_ECB Regional Control Map (`CAGE_DEPLOYMENT_REGION=EU_ECB`)

| Control | Framework | Pipeline Tier | Obligation |
|---------|-----------|--------------|------------|
| `CTRL_FRIA_006` | EU AI Act Art. 29a | Tier 6b (FRIA) | Fundamental Rights Impact Assessment; ALLOW/DEFER/BLOCK zone enforcement + OTel attestation |
| GDPR Art. 22 | GDPR | Tier 6b (FRIA) | Automated decision-making safeguards; DEFER zone triggers human review |
| `CTRL_WAL_002` addendum | DORA Art. 12 | WAL SAGA nodes | Operational resilience logging obligation |
| Telemetry suppression | SR 26-2 "no legal force" sentinel | Tier 6 (Causal) | Causal gatekeeper suppressed in EU_ECB; GDPR / MAS Notice 655 telemetry restriction |
| Consensus threshold | EU AI Act | Tier 5 | $7,500 USD threshold (lower than US_FED) |
| Data residency | GDPR Art. 44 | All storage paths | All GCS writes and Langfuse sinks must remain within `europe-west1` |

### APAC_MAS Regional Control Map (`CAGE_DEPLOYMENT_REGION=APAC_MAS`)

| Control | Framework | Pipeline Tier | Obligation |
|---------|-----------|--------------|------------|
| MAS FEAT Principles | MAS FEAT | All tiers | Fairness, Ethics, Accountability, Transparency obligations |
| MAS Notice 655 | MAS Notice 655 | Tier 6 (Causal) | Audit logging enabled; telemetry suppression sentinel active |
| MAS TRM §4.2 | MAS TRM | All storage paths | All data paths must remain within `asia-southeast1` |
| Consensus threshold | MAS FEAT | Tier 5 | $5,000 USD threshold (most conservative) |
| SR 26-2 sentinel | "no legal force" | Tier 6 (Causal) | Telemetry suppression active — same sentinel as EU_ECB |

### Cross-Region Shared-Module Guard Obligation

Any change to [`src/gateway/governance/`](../../src/gateway/governance/) or [`src/compliance_bridge/`](../../src/compliance_bridge/) affects all three regional deployments simultaneously. Per the CAGE shared-module policy:

- New storage paths, GCS writes, Langfuse sinks, or telemetry exports in shared modules **must** be gated on `CAGE_DEPLOYMENT_REGION` to prevent silent cross-region data leakage (GDPR Art. 44 / MAS TRM §4.2).
- The "no legal force" SR 26-2 sentinel in EU and APAC baselines must never be removed — its presence suppresses telemetry that lacks legal basis under GDPR / MAS Notice 655.
- Cross-region impact must be declared in the PR description for any PR touching these modules (US_FED, EU_ECB, and APAC_MAS impact sections required).
