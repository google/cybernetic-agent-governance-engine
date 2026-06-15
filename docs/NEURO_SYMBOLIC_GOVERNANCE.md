# Neuro-Symbolic Governance Architecture — v2.0.0

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
- **Checks (8-Step Pipeline (Steps 0–6 including Step 2b)):**

  > **Note on Step 2b:** Step 2b (OPA Policy Evaluation) runs concurrently with Step 2 (CBF) via `asyncio.gather` as a conditional branch within the pipeline. It is counted as a distinct step, making the total 8 steps (Steps 0, 1, 2, 2b, 3, 4, 5, 6).

  > **See also:** [`README_GOVERNANCE.md`](../README_GOVERNANCE.md) for the canonical layer model and infrastructure context.

  | Step | Name | Implementation | Notes |
  |------|------|---------------|-------|
  | **0** | STPA UCA Constraint Check | `stpa_validator.validate()` | Aho-Corasick keyword scan against 14 tier-1 keywords; checks for Unsafe Control Actions (UCAs) defined in the ontology *(All Regions)* |
  | **1** | Agentic Confidence Gate | OPA `system_authz.rego` | **OPA is the sole enforcer** of `CTRL_AGT_001` — three-zone confidence model: ALLOW ≥ 0.95, DEFER 0.70–0.95, DENY < 0.70 (`DEFER_CONFIDENCE_THRESHOLD = 0.70`). Normal threshold 0.95; SLM-degraded escalation to 0.97 baked into `system_authz.rego`. The Python-side confidence check has been removed. Contexts in the DEFER zone are pushed to the **DEFER queue** (Redis db=1, 4h TTL, AARM-V7) rather than outright denied. **Note:** `min_trade_confidence` in `governance_thresholds.json` is **deprecated** — OPA `system_authz.rego` is now authoritative for confidence enforcement. ISO 42001 §A.5.2 *(All Regions)* |
  | **2** | Control Barrier Function | `ControlBarrierFunction.verify_action()` (`cbf.py`) | Redis-backed cash balance invariant `h(x) = cash_balance − min_cash_balance ≥ 0` (γ=0.5, min=$1,000; 5% drawdown default; 4% for EU_ECB). Currently reads position state from Redis cache. External reconciliation via `AnchorageGrpcLedgerProvider` is planned (POAM-023, not yet implemented). *(All Regions)* |
  | **2b** | OPA Policy Evaluation | `OPAClient.evaluate_policy()` | Runs **concurrently** with CBF via `asyncio.gather` — combined latency is `max(CBF_ms, OPA_ms)`. Evaluates declarative, role-based authorization constraints *(All Regions)*. |
  | **3** | Fiscal Limit Pre-Reservation | `FiscalLimitGuard.reserve()` | **Active in pipeline.** Atomically reserves the requested USD amount against the daily cap in Redis (WATCH/MULTI/EXEC) **before** the consensus gate, closing the TOCTOU race between the CBF balance check and actual trade execution. Released on any subsequent failure. *(All Regions)* |
  | **4** | Multi-Agent Consensus | `consensus_engine.check_consensus()` | Triggers heterogeneous multi-model consensus via ConsensusModelRegistry for trades exceeding threshold ($10k default **US_FED**; $7.5k **EU_ECB**; $5k **APAC_MAS**). Unanimity required — any dissent blocks the trade *(All Regions)*. |
  | **5** | DoWhy Causal Gatekeeper | `causal_safety_check()` | 50-simulation placebo refutation causal validation of world-model (p<0.05). Active in **US_FED** and **APAC_MAS**; suppressed in **EU_ECB** per SR 26-2 "no legal force" sentinel (GDPR / MAS Notice 655 telemetry restriction). |
  | **6** | FRIA Normative Boundary + Attestation | `enforce_fria_boundary()` + OTel stamp | **Merged step** (formerly Steps 6b and 7): adaptive FRIA enforcement (ALLOW/DEFER/DENY based on consensus score) combined with EU AI Act Art. 29a OTel attestation (`CTRL_FRIA_006`). Enforcement runs when `CAGE_NORMATIVE_PROVIDER != "static"`; attestation stamp always applied for **EU_ECB** deployments. **EU_ECB only** — no-op for US_FED and APAC_MAS. |

  > **Note — SLM Tier removed:** The former Tier 3 (SLM Semantic Similarity) has been fully retired. The SLM sidecar code has been deleted. The confidence threshold (Step 1) is now enforced exclusively by OPA, with the SLM-degraded escalation (0.95 → 0.97) baked into `system_authz.rego`.

### 1b. NeMo Guardrails Phase 4.2 Changes (`src/gateway/governance/nemo/manager.py`)

Phase 4.2 introduced the following changes to the NeMo Guardrails integration:

- **Removed substring heuristics:** Phrase-list matching (e.g., "I cannot answer") has been removed and replaced with structured rail evaluation. The old approach was brittle and produced false positives on legitimate refusals.
- **Transparent fallback mode (`DEGRADED_FAIL_OPEN`):** When `RailsConfig` parse fails due to a Colang 2.x `lark.UnexpectedToken` error, NeMo runs as a no-op stub rather than crashing the gateway. This is a production-safe degradation path — OPA + STPA remain authoritative.
  - When degraded: all requests are stamped `DEGRADED_FAIL_OPEN` in Langfuse with `stpa_hazard=UCA-1_SEMANTIC_BYPASS` and `iso_control=A.5.2` so the degradation is fully observable.
- **Pre-check injection:** A pre-check is injected to break re-entrant loops that could cause NeMo to call itself recursively.
- **Response deduplication:** Duplicate rail processing is prevented to avoid double-stamping governance decisions.

### 2. STPA Validator (`src/gateway/governance/generated_stpa_validator.py`)

Implements the System-Theoretic Process Analysis (STPA) logic via the auto-generated `GeneratedSTPAValidator` class.

- **Primary class:** [`GeneratedSTPAValidator`](../src/gateway/governance/generated_stpa_validator.py) — auto-generated by `stpa_compiler.py` from `config/stpa_control_structure.yaml`. Contains `validate()` (canonical entry-point, delegates to `validate_generated()`) and per-UCA check methods (`_check_uca_1()` through `_check_uca_9()`).
- **Deprecated shim:** `stpa_validator.py` re-exports `GeneratedSTPAValidator` as `STPAValidator` for backward compatibility and emits a `DeprecationWarning` on import. It will be removed in the next major version. New code should import `GeneratedSTPAValidator` directly from `generated_stpa_validator.py`.
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
- **Fail-Safe:** Returns `False` (blocks trade) on any exception — if causal validity cannot be proven, the action is denied.
- **Integration:** Injected as Step 6 in `SymbolicGovernor._run_checks()`, executed only for `execute_trade` actions.
- **Telemetry Source — Dual Phase:** Accepts a `BaseTelemetryProvider`. In production, `LangfuseTelemetryProvider` sources live governance spans from Langfuse. The function now emits **two OTel child spans**:
  - `causal_gatekeeper.statistical_kernel` — tagged `CTRL_MRM_004` (SR 26-2 MRM): causal model setup, effect identification, and coefficient estimation.
  - `causal_gatekeeper.placebo_refutation` — tagged `CTRL_TEL_003` (ISO 42001 §A.9.4): 50-simulation placebo refuter against live telemetry. Falls back to `MockTelemetryProvider` when live sample count is below `CAUSAL_MIN_LIVE_SAMPLES` (default: 50).

---

## Workflow

The 10-node LangGraph StateGraph governs the full execution lifecycle:

| # | Node | Purpose |
|---|------|---------|
| 1 | `nemo_input_rail` | NeMo Guardrails input screening |
| 2 | `stpa_validator` | STPA UCA policy check |
| 3 | `causal_gatekeeper` | DoWhy SCM intervention simulation |
| 4 | `symbolic_governor` | 7-step symbolic check pipeline (Steps 0–6) |
| 5 | `consensus_node` | Multi-model consensus (≥$10k trades) |
| 6 | `hitl_gate` | Human-in-the-loop interrupt |
| 7 | `post_hitl_rehydrate` | TOCTOU remediation — state rehydration |
| 8 | `post_hitl_revalidate` | TOCTOU remediation — re-validation |
| 9 | `saga_router` | LangGraph Saga WAL + LIFO rollback |
| 10 | `nemo_output_rail` | NeMo Guardrails output screening |

### Step-by-Step Execution

1.  **Plan:** Agent generates a plan.
2.  **Evaluate:** Graph routes to the **Evaluator** node.
3.  **Governance Check:** Evaluator calls `check_safety_constraints` (OPA, CBF, STPA) in the Gateway via the 7-step `SymbolicGovernor._run_checks()` pipeline (Steps 0–6: STPA → Confidence/OPA → CBF → Fiscal Limit Pre-Reservation → Consensus → Causal → FRIA).
4.  **Context Accumulation (AARM-V1):** The SHA-256 hash-chained context accumulator (`src/compliance_bridge/context_accumulator.py`) appends each governance decision to the immutable chain, preventing context poisoning.
5.  **Causal Validation:** DoWhy Causal Gatekeeper validates world-model integrity via 50-simulation placebo refutation (p<0.05).
6.  **Sign:** If safe, Evaluator generates a **Cloud KMS HSM-backed asymmetric signature** (primary) and appends it to the shared state. HMAC-SHA256 is used only in dev/CI when KMS is unavailable.
7.  **HITL Gate:** For trades >$10,000 USD or risk_score >0.7, the `hitl_gate` node interrupts the graph for human review.
    - **TOCTOU Remediation:** On human approval, `post_hitl_rehydrate` reloads the latest state from the Redis checkpointer (preventing stale-state execution), then `post_hitl_revalidate` re-runs the full 7-step pipeline before proceeding.
8.  **DEFER Queue (AARM-V7):** Contexts failing the confidence threshold but not outright denied are pushed to Redis `db=1` (noeviction) for deferred human review.
9.  **Audit Gate:**
    - _Path A (Safe):_ Signature verified → Graph transitions to `governed_trader` node.
    - _Path B (Unsafe):_ Signature missing/failed → Graph routes to `explainer` node (no trade executed).
    - _Path C (Causal Lock):_ DoWhy refutation failed → Trade blocked; violation logged.
    - _Path D (DEFER):_ Confidence below threshold → Context pushed to DEFER queue; response deferred.
10. **Explain:** The `explainer` node generates a user-facing narrative; the NeMo output rail runs a final in-process Presidio PII egress scan before returning the response.

---

## Compliance Mapping

All regulatory citations are decoupled from Python execution code via the `GovernanceControl` registry ([`src/gateway/governance/constants.py`](../src/gateway/governance/constants.py) → `config/control_mappings.json`). Violation messages carry structured `[CTRL_*]` prefixes; legacy citation strings are stored only in the JSON registry.

### Universal Controls (All Deployment Regions — ISO 42001 Baseline)

| Control ID | Framework | Component | Requirement |
|---|---|---|---|
| `CTRL_AGT_001` | **ISO 42001 §A.5.2** | `symbolic_governor.py` Step 1 — OPA `system_authz.rego` | Agentic AI bounding; minimum confidence threshold enforced **exclusively by OPA** (0.95 normal; 0.97 SLM-degraded). Python-side check removed. *(All Regions)* |
| `CTRL_WAL_002` | **ISO 42001 §A.8.4** | `generated_saga_nodes.py` WAL SAGA nodes | Non-determinism containment; transactional atomicity + rollback *(All Regions)* |
| `CTRL_TEL_003` | **ISO 42001 §A.9.4** | `causal_gatekeeper.py` (Phase 2), `telemetry_provider.py` | Live telemetry validation; DoWhy 50-simulation placebo refutation monitoring *(All Regions)* |
| `CTRL_OPA_005` | **ISO 42001 §A.6.1** | `symbolic_governor.py` OPA policy check | Enterprise policy enforcement gate *(All Regions)* |
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
| `CTRL_FRIA_006` | **EU AI Act Art. 29a** | `symbolic_governor.py` Step 6 — `enforce_fria_boundary()` + OTel stamp | FRIA normative boundary enforcement + attestation stamped on OTel span attributes — **EU_ECB only** |
| `CTRL_WAL_002` addendum | **DORA Art. 12** | `generated_saga_nodes.py` WAL SAGA nodes | DORA operational resilience logging obligation — **EU_ECB only** (addendum to ISO 42001 §A.8.4 base control) |
