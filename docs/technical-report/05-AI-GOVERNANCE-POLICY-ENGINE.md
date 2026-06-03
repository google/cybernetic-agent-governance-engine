---
title: "AI Governance & Policy Engine"
document: "05-AI-GOVERNANCE-POLICY-ENGINE"
version: "2.3"
date: "2026-06-01"
classification: "INTERNAL"
project: "Cybernetic Governance Engine (CAGE)"
---

# AI Governance & Policy Engine

## Overview

The AI Governance & Policy Engine is the most complex and safety-critical component of the Cybernetic Governance Engine (CAGE). It enforces a layered, **neuro-symbolic hybrid governance** model over every agent action, combining deterministic symbolic constraints with LLM-based semantic judgment. No action reaches execution unless it passes all governance tiers. All governance is **fail-closed**: any tier failure raises `GovernanceError` and blocks the action.

---

## 1. Governance Philosophy

CAGE implements neuro-symbolic hybrid governance (see [`docs/NEURO_SYMBOLIC_GOVERNANCE.md`](../NEURO_SYMBOLIC_GOVERNANCE.md)) — a defense-in-depth approach grounded in two complementary paradigms:

- **Neural (semantic)**: LLM consensus critics in `ConsensusEngine` provide contextual judgment for high-value trades, detecting nuanced compliance violations that symbolic rules cannot express.
- **Symbolic (deterministic)**: STPA/STAMP unsafe control action checks, Control Barrier Functions, Aho-Corasick keyword scans, and OPA Rego policies enforce hard constraints regardless of LLM state.

Neither paradigm alone is sufficient. Neural systems can hallucinate; symbolic systems cannot reason over context. The pipeline requires both.

**Four Governance Automation Patterns** (see [`docs/GOVERNANCE_CROSSWALK.md`](../GOVERNANCE_CROSSWALK.md)):

| Pattern                      | Mechanism                                                     |
| ---------------------------- | ------------------------------------------------------------- |
| Automated Policy Derivation  | Policy Transpiler: regulatory text → Rego + NeMo action stubs |
| Structural Enforcement       | OPA + CBF + STPA deterministic validators                     |
| Continuous Compliance Audit  | Lula 6-hour CronJob against OSCAL component definitions       |
| Evidence-Age Staleness Guard | OSCAL `prop` extraction for evidence freshness validation     |

**Single source of truth** for all thresholds: [`config/governance_thresholds.json`](../../config/governance_thresholds.json), loaded and validated by the `GovernanceThresholds` Pydantic model at startup.

---

## 2. The Multi-Region Symbolic Governor (7-Tier Pipeline)

[`SymbolicGovernor._run_checks()`](../../src/gateway/governance/symbolic_governor.py) executes seven governance tiers in strict, sequential order. A failure at any tier raises `GovernanceError` immediately; subsequent tiers are not reached. For the `EU_ECB` region, an additional 8th step (FRIA Attestation) is executed to stamp pre-market assessment compliance into the OpenTelemetry telemetry records.

```
GovernanceError ← Tier 0: STPA UCA Validation
GovernanceError ← Tier 1: Agentic Confidence Check (SR 26-2 / EU AI Act Art. 10)
GovernanceError ← Tier 2: Control Barrier Function (suppressed in EU_ECB)
      sentinel ← Tier 3: SLM Sidecar (Deprecated / Bypassed / slm_available=false)
GovernanceError ← Tier 4: OPA Policy Evaluation
GovernanceError ← Tier 5: Multi-Agent Consensus
GovernanceError ← Tier 6: Causal Gatekeeper (DoWhy Placebo Refutation)
         adaptive ← Tier 6b: Adaptive FRIA Gate (External Normative Provider)
      attestation ← Step 8: Fundamental Rights Impact Assessment (EU_ECB only)
```

| Tier | Name                                    | Class / Function                                                                                    | Threshold Source                                                   | Fail Behavior                                 | Active Regions |
| ---- | --------------------------------------- | --------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ | --------------------------------------------- | --- |
| 0    | STPA UCA Validation                     | `STPAValidator.validate()` in [`src/gateway/governance/stpa_validator.py`](../../src/gateway/governance/stpa_validator.py) | `governance_thresholds.json` `stpa.*`                              | `GovernanceError`                             | *All Regions* |
| 1    | Agentic Confidence Check                | inline logic in `src/gateway/governance/symbolic_governor.py`                                                              | Region-specific thresholds (`Confidence: 0.95` or `0.97` for EU)   | `GovernanceError`                             | *All Regions* |
| 2    | Control Barrier Function                | `ControlBarrierFunction` in [`safety.py:115`](../../src/gateway/governance/safety.py)               | Region-specific thresholds (`Drawdown: 5%` or `4%` for EU)         | `GovernanceError`                             | `US_FED`, `APAC_MAS` |
| 3    | SLM Sidecar (Deprecated)               | Bypassed to optimize latency budget (runs permanently offline)                            | N/A (0ms)                                                         | Runs with `slm_available=False` sentinel | *All Regions* |
| 4    | OPA Policy Evaluation                   | `OPAClient` in [`core/policy.py`](../../src/gateway/core/policy.py) + `CircuitBreaker`              | `trade.governance` Rego package                                    | `GovernanceError`; DENY on circuit open       | *All Regions* |
| 5    | Multi-Agent Consensus                   | `ConsensusEngine` in [`consensus.py:71`](../../src/gateway/governance/consensus.py)                 | Region-specific thresholds (`Consensus: $10k` / `$7.5k` / `$5k`)   | `GovernanceError`                             | *All Regions* |
| 6    | Causal Gatekeeper                       | `causal_safety_check()` in `src/gateway/governance/causal_gatekeeper.py`                           | Placebo p-value < 0.05 or placebo effect > 0.2                      | `GovernanceError`                             | *All Regions* |
| 6b   | Adaptive FRIA Gate                      | `enforce_fria_boundary()` in [`normative_provider.py`](../../src/gateway/governance/normative_provider.py)  | Confidence-mapped: ≥0.95 async; [0.70,0.95) sync gate; <0.70 deny  | `GovernanceError` (on DENY path)              | *All Regions* (when `CAGE_NORMATIVE_PROVIDER != "static"`) |
| 8    | Step 8 FRIA Attestation                 | inline logic in `src/gateway/governance/symbolic_governor.py`                                                              | `CTRL_FRIA_006` in `EU_ECB_BASELINE.json`                          | Logs attestation on OTel span attributes      | `EU_ECB` only |

> **Numbering note:** Tier 7 is intentionally skipped. Tier 6b (Adaptive FRIA Gate, v2.1.0) is a confidence-dependent gate that invokes external normative providers only when `CAGE_NORMATIVE_PROVIDER != "static"` and only after all local tiers (0–6) have passed. FRIA Attestation remains "Step 8" rather than a tier because it is a non-blocking pre-market attestation stamp, not a runtime enforcement gate.

**Public methods on `SymbolicGovernor`:**

- `govern(request)` — enforces all active tiers; raises `GovernanceError` on any failure
- `verify(request)` — dry-run mode; returns result without blocking execution

**ControlRegistry Configuration:**
The `ControlRegistry` handles dynamic, thread-safe loading of active baseline mappings from `/config/compliance/{REGION}_BASELINE.json` based on the `CAGE_DEPLOYMENT_REGION` environment variable (`US_FED`, `EU_ECB`, `APAC_MAS`). In `EU_ECB` mode, the registry provides safe mapping queries via `get_mapping_safe()` to gracefully handle region-specific controls like `CTRL_FRIA_006` without throwing `KeyError` exceptions when executing outside of the EU.

### Pipeline Flowchart

```mermaid
flowchart TD
    A[Incoming Trade Request] --> T0[Tier 0: STPA UCA Validation]
    T0 -->|FAIL| GE0[GovernanceError BLOCKED]
    T0 -->|PASS| T1["Tier 1: SR 26-2 §IV.B Agentic Confidence Check"]
    T1 -->|confidence < 0.95| GE1[GovernanceError BLOCKED]
    T1 -->|PASS| T2[Tier 2: Control Barrier Function]
    T2 -->|h-x < 0| GE2[GovernanceError BLOCKED]
    T2 -->|PASS| T3[Tier 3: SLM (Deprecated / Bypassed)]
    T3 -->|slm_available=false| T4[Tier 4: OPA Policy Evaluation]
    T4 -->|DENY or circuit open| GE4[GovernanceError BLOCKED]
    T4 -->|ALLOW| T5[Tier 5: Multi-Agent Consensus]
    T5 -->|disagreement| GE5[GovernanceError BLOCKED]
    T5 -->|consensus reached| T6[Tier 6: Causal Gatekeeper]
    T6 -->|FAIL| GE6[GovernanceError BLOCKED]
    T6 -->|PASS| EXEC[Execution APPROVED]
```

### Execution-Time Revalidation

A critical architecture shift in CAGE v2.0 separates pre-check reasoning from execution-time commitment. While the full 7-tier `SymbolicGovernor` pipeline is executed pre-HITL to evaluate the broad intent and strategy, only a subset of deterministic tiers reliant on continuous environmental variables are re-evaluated immediately prior to execution.

Specifically, the `post_hitl_revalidate_node` runs the transaction through:
- **Tier 2 (Control Barrier Function)**: Ensures that the cash balance boundary remains satisfied under live, fresh pricing.
- **Tier 4 (OPA Policy Engine)**: Re-runs the Rego policies to confirm that the live trade pricing still falls within role-based limits.

Non-deterministic or context-free tiers (such as Tier 0 STPA, Tier 1 Agentic Confidence, and Tier 5 Multi-Agent Consensus) do not run again post-HITL, as they do not depend on high-frequency, continuous environmental changes, thus avoiding unnecessary computational latency and protecting the human intent from non-deterministic rejections.

---

## 3. STPA/STAMP Safety Analysis — Tier 0

Full analysis: [`docs/STPA_ANALYSIS.md`](../STPA_ANALYSIS.md).

[`STPAValidator`](../../src/gateway/governance/stpa_validator.py) enforces **9 Unsafe Control Actions (UCAs)** derived from STAMP hazard analysis of the CAGE financial control loop (UCA-1 through UCA-9, compiled by `stpa_compiler.py`). Each UCA maps to a threshold in `governance_thresholds.json`. The STPA check runs synchronously as Step 0 (`cage.stpa_check` OTel span), always first.

> **Implementation note (2026-06-03):** The STPA compiler generates `src/gateway/governance/generated_stpa_validator.py` containing `GeneratedSTPAValidator`. A `validate()` alias was added to `GeneratedSTPAValidator` that delegates to `validate_generated()`, resolving an `AttributeError` when `symbolic_governor.py` called `.validate()` on the generated class. Both `stpa_validator.py` (hand-authored) and `generated_stpa_validator.py` (compiler output) are now present and operational.

| UCA ID | Name                        | Check                                                | Threshold                                                 |
| ------ | --------------------------- | ---------------------------------------------------- | --------------------------------------------------------- |
| SC-1   | Unauthorized Control Action | `approval_token` required for all controlled actions | Any trade without token → BLOCK                           |
| FIN-1  | Portfolio Fraction Exceeded | `qty / portfolio ≤ 0.1`                              | `stpa.max_sell_portfolio_fraction = 0.10`                 |
| FIN-2  | Latency SLA Breach          | `latency ≤ 200ms`                                    | `stpa.max_latency_ms = 200.0` (ISO-20022)                 |
| UCA-5  | Drawdown Limit Breach       | `drawdown > 4.5%` → block                            | `stpa.uca5_drawdown_threshold_pct = 4.5`                  |
| UCA-6  | Order Volume Fraction       | `order_size > 1% daily_vol` → block                  | `stpa.uca6_max_order_volume_fraction = 0.01`              |
| UCA-7  | Ontology Violation          | `TradingKnowledgeGraph` semantic constraint check    | [`src/gateway/governance/ontology.py`](../../src/gateway/governance/ontology.py) |

**`TradingKnowledgeGraph`** in [`src/gateway/governance/ontology.py`](../../src/gateway/governance/ontology.py) maintains an ontology of valid trading patterns. UCA-7 checks every request against known semantic constraints — blocking trades that structurally violate domain invariants even if all numeric thresholds pass.

---

## 4. Control Barrier Function — Tier 2

[`ControlBarrierFunction`](../../src/gateway/governance/safety.py) (line 115) enforces the core financial safety invariant using control theory formalism:

**Safety invariant:**

```
h(x) = cash_balance - min_cash_balance ≥ 0
```

Where `cbf.min_cash_balance = 1000.0` and `cbf.gamma = 0.5` (decay rate on the barrier gradient constraint).

### Redis Atomic Enforcement

Balance updates use a WATCH/MULTI/EXEC pattern (5 retries on contention) to guarantee atomicity:

```python
# Atomic CBF enforcement pattern (safety.py)
await redis.watch(cash_balance_key)
current_balance = float(await redis.get(cash_balance_key))
# Evaluate h(x) = current_balance - min_cash_balance
if current_balance - trade_cost < cbf.min_cash_balance:
    raise GovernanceError("CBF invariant violated")
async with redis.multi_exec() as pipe:
    pipe.set(cash_balance_key, current_balance - trade_cost)
    await pipe.execute()  # EXEC — atomic commit
```

Concurrent modifications trigger an `asyncio.CancelledError` on `EXEC`, caught and retried up to 5 times before raising `GovernanceError`.

### Execution-Time Price Resolution

To prevent Time-Of-Check to Time-Of-Use (TOCTOU) exploits and drift under volatile market conditions, the Redis `WATCH/MULTI/EXEC` transaction utilizes the **fresh execution price** fetched by the `post_hitl_revalidate_node` immediately prior to committing the trade, rather than relying on the stale quoted price recorded during pre-HITL evaluation. This ensures that $h(x) \geq 0$ is validated against the actual, real-time capital exposure at the moment of actuation.

### Aho-Corasick Keyword Scan

`ac_keyword_scan()` (lines 83+) performs a Tier-1 text scan using a `pyahocorasick` automaton:

- **14 keyword entries** loaded from `tier1_keywords` in `governance_thresholds.json`
- Pattern matching runs in **O(n)** time against the request content string
- Any match triggers an immediate `GovernanceError` before numeric checks proceed

---

## 5. OPA Policy Engine — Tier 4

[`OPAClient`](../../src/gateway/core/policy.py) is an HTTP client to the OPA REST API with integrated `CircuitBreaker`:

- **Circuit breaker**: 5 consecutive failures → open; 30-second recovery window
- **Fail-closed**: when circuit is open, decision defaults to DENY
- **Decision path**: `v1/data/trade/governance/allow`

### `src/governed_financial_advisor/governance/policy/trade_governance.rego` — Package `trade.governance`

Canonical policy file: [`src/governed_financial_advisor/graph/governance/trade_policy.rego`](../../src/governed_financial_advisor/graph/governance/trade_policy.rego)

```rego
package trade.governance

default allow = false
default decision = "DENY"

# Junior trader authorization
allow {
    input.role == "junior"
    input.amount <= 5000
}

decision = "ALLOW" {
    input.role == "junior"
    input.amount <= 5000
}

decision = "MANUAL_REVIEW" {
    input.role == "junior"
    input.amount > 5000
    input.amount <= 10000
}

# Senior trader authorization
allow {
    input.role == "senior"
    input.amount <= 500000
}

decision = "ALLOW" {
    input.role == "senior"
    input.amount <= 500000
}

decision = "MANUAL_REVIEW" {
    input.role == "senior"
    input.amount > 500000
    input.amount <= 1000000
}

# Governance violations — override all role-based decisions
decision = "GOVERNANCE_VIOLATION" {
    input.semantic_score > 0.85
}

decision = "GOVERNANCE_VIOLATION" {
    contains(input.content, "system override")
}
```

**Role-based trade authorization matrix:**

| Role     | Amount                         | Decision             |
| -------- | ------------------------------ | -------------------- |
| `junior` | ≤ $5,000                       | ALLOW                |
| `junior` | $5,000 – $10,000               | MANUAL_REVIEW        |
| `junior` | > $10,000                      | DENY                 |
| `senior` | ≤ $500,000                     | ALLOW                |
| `senior` | $500,000 – $1,000,000          | MANUAL_REVIEW        |
| `senior` | > $1,000,000                   | DENY                 |
| Any      | `semantic_score > 0.85`        | GOVERNANCE_VIOLATION |
| Any      | `"system override"` in content | GOVERNANCE_VIOLATION |
| Default  | —                              | DENY (fail-closed)   |

### `deployment/system_authz.rego`

[`deployment/system_authz.rego`](../../deployment/system_authz.rego):

- Identity-based allow list for system principals
- `confidence_sufficient ≥ 0.95` (SR 26-2 §IV.B agentic model confidence requirement)

### Deprecated Policy Stubs

The stubs `finance_policy.rego` and `generated_rules.rego` have been completely purged from the active repository to maintain compliance and audit hygiene. The consolidated canonical policy is strictly `src/governed_financial_advisor/governance/policy/trade_governance.rego`. An R-12 conflict is resolved; old files are removed.

**OPA test snapshots:** [`tests/opa_snapshots/01_no_identity_match.json`](../../tests/opa_snapshots/01_no_identity_match.json), [`02_trade_no_auth.json`](../../tests/opa_snapshots/02_trade_no_auth.json)

---

## 6. NeMo Guardrails — Colang 2.x

NeMo Guardrails configuration resides in `config/rails/`.

### `config/rails/config.yml`

- Colang 2.x syntax
- **15 PII entity types** configured for input/output scanning (Microsoft Presidio)
- Model: `GUARDRAILS_MODEL_NAME` (environment variable)

> **Implementation note (2026-06-03 — `nemo_node_factory.py`):** Both hardcoded `"BLOCKED"` sentinel strings in `src/gateway/governance/langgraph_harness/nemo_node_factory.py` were replaced with `cfg.output_blocked_sentinel` — in the semantic validation BLOCKED path and the exception path. This ensures the sentinel value is always read from configuration rather than hardcoded, preventing mismatches when the sentinel is configured differently in tests or non-default deployments.

### NeMo Phase 4.2 Changes (`src/gateway/governance/nemo/manager.py`)

| Change | Description |
| ------ | ----------- |
| **Removed substring heuristics** | The "I cannot answer" phrase-list bypass detection has been removed |
| **Transparent fallback mode** | When `RailsConfig` parse fails (Colang 2.x `lark.UnexpectedToken`), enters `DEGRADED_FAIL_OPEN` mode |
| **Pre-check injection** | Pre-checks injected to break re-entrant loops |
| **Response deduplication** | Duplicate responses deduplicated before returning |
| **Degraded mode stamping** | When degraded: all requests stamped `DEGRADED_FAIL_OPEN` in Langfuse with `stpa_hazard=UCA-1_SEMANTIC_BYPASS` and `iso_control=A.5.2`; OPA + STPA remain authoritative |

### `main_logic.co` — Primary Flows

| Flow                   | UCA Enforced     | Check                                   |
| ---------------------- | ---------------- | --------------------------------------- |
| `check_authorization`  | SC-1             | `approval_token` presence validation    |
| `check_latency`        | FIN-2            | Latency ≤ 200ms enforcement             |
| `check_financial_risk` | UCA-5 + slippage | Combined drawdown + slippage risk check |

### NeMo Action Implementations — Two Distinct Patterns

CAGE maintains two separate NeMo action implementations serving different roles:

#### Gateway-Internal Actions (`src/gateway/governance/nemo/actions.py`)

These async action functions execute **directly in-process** within the Hybrid Gateway, calling the `SymbolicGovernor` singleton and `STPAValidator` without any HTTP round-trip. They are for **gateway-internal use only** and are NOT registered with the top-level NeMo Guardrails instance used by the governed financial advisor.

| Action Function              | Purpose                                          | Enforcement Mechanism                                      |
| ---------------------------- | ------------------------------------------------ | ---------------------------------------------------------- |
| `CheckApprovalTokenAction`   | SC-1 approval token validation                   | `symbolic_governor.stpa_validator.validate()` in-process   |
| `CheckDataLatencyAction`     | FIN-2 latency check                              | `symbolic_governor.stpa_validator.validate()` in-process   |
| `CheckDrawdownLimitAction`   | UCA-5 drawdown enforcement                       | `symbolic_governor.safety_filter.verify_action()` in-process |
| `CheckSlippageRiskAction`    | UCA-6 slippage risk check                        | `symbolic_governor.safety_filter.verify_action()` in-process |
| `CheckAtomicExecutionAction` | Multi-leg trade atomicity validation             | Audit trail leg-index consistency check in-process         |
| `InvokeVllmFallbackAction`   | vLLM fallback response generation                | Direct `VLLMLLM` client call in-process                    |

All actions are **fail-closed**: missing or invalid inputs return `False` (block). Snake_case aliases (`check_approval_token`, `check_data_latency`, etc.) are provided for test imports.

#### Advisor NeMo Actions (`src/governed_financial_advisor/governance/nemo_actions.py`)

These are **synchronous, in-process** fallback implementations used by the governed financial advisor service. They implement the same safety checks as the gateway-internal actions but operate independently of the gateway singleton — reading thresholds directly from the `GovernanceThresholds` Pydantic model with a **60-second TTL cache**.

These implementations serve three purposes:
1. **Fallback** when the HTTP gateway is unavailable
2. **Unit testing** without gateway dependency
3. **Reference implementations** documenting expected behavior

> **Production registration note:** In production, the governed financial advisor registers HTTP-delegating NeMo actions (the **Governance-as-Sidecar Pattern**) that call the gateway's `POST /governance/validate-action` endpoint. The synchronous implementations in this file are NOT registered with production NeMo Guardrails — they are fallbacks only.

| Function               | Purpose                                          | Threshold Source                                      |
| ---------------------- | ------------------------------------------------ | ----------------------------------------------------- |
| `check_drawdown_limit` | Portfolio drawdown limit enforcement (UCA-5)     | `GovernanceThresholds.drawdown.limit` (60s TTL cache) |
| `check_slippage_risk`  | Market order slippage limit (UCA-6, 1% of daily volume) | Hardcoded 1% limit per governance spec          |
| `check_approval_token` | SC-1 approval token presence and validity        | Token non-empty and not equal to `"bad_sig"` sentinel |
| `check_data_latency`   | FIN-2 market data freshness (≤ 200ms)            | `DEFAULT_MAX_LATENCY_MS = 200.0`                      |
| `check_atomic_execution` | Multi-leg trade history consistency            | Audit trail leg-index completeness check              |

All functions are **fail-closed**: missing required fields return `False` (block). Threshold values hot-reload with a **60-second TTL** to pick up `governance_thresholds.json` updates without service restart.

---

## 7. Multi-Agent Consensus Engine — Tier 5

[`ConsensusEngine`](../../src/gateway/governance/consensus.py) (line 71) implements a multi-agent "Critic" voting mechanism for high-value trade decisions. Two independent LLM-backed personas — a **Risk Manager** and a **Compliance Officer** — are queried concurrently and must reach consensus before a trade above the activation threshold can proceed.

### 7.1 Activation Threshold & Regional Calibration

The consensus check activates only for trades exceeding the `consensus.threshold_usd` value from the regional threshold profile:

| Region    | Activation Threshold | Source |
| --------- | -------------------- | ------ |
| `US_FED`  | $10,000 USD          | `config/thresholds/US_FED_BASELINE.json` |
| `EU_ECB`  | $7,500 USD           | `config/thresholds/EU_ECB_BASELINE.json` |
| `APAC_MAS`| $5,000 USD           | `config/thresholds/APAC_MAS_BASELINE.json` |

Below the threshold, the `ConsensusEngine` returns `{"status": "SKIPPED"}` immediately — no LLM calls are made. Single-agent judgment is accepted per risk acceptance RA-002.

### 7.2 Voting Mechanism

Both critic personas are dispatched concurrently using `asyncio.gather()` (Phase 4.4), replacing the original sequential `await` chain. Each critic receives a structured prompt:

```
You are a {Risk Manager | Compliance Officer} for a financial institution.
Review the following trade proposal:
ACTION: {action}  AMOUNT: {amount}  SYMBOL: {symbol}

Respond with one of: APPROVE | REJECT | ESCALATE
```

Each critic independently returns one of three verdicts:

| Critic Verdict | Meaning |
| -------------- | ------- |
| `APPROVE`      | Trade is reasonable for a standard portfolio |
| `REJECT`       | Trade is suspicious, reckless, or undefined |
| `ESCALATE`     | Trade is legitimate but requires human verification (e.g., large withdrawals, complex life events) |

### 7.3 Decision Priority Ladder

The `ConsensusEngine` applies a strict priority ladder over the two critic votes:

| Priority | Condition | Final Decision | Effect |
| -------- | --------- | -------------- | ------ |
| 1 (highest) | ALL critics return `ERROR` (LLM unavailable) | `APPROVE` (fail-open) | Trade continues through OPA only; mirrors SLM sidecar handling |
| 2 | ALL critics vote `REJECT` | `REJECT` | Trade blocked; `GovernanceError` raised |
| 3 | Split `APPROVE` + `REJECT` | `ESCALATE` | Consensus unclear; routes to human review |
| 4 | Any critic votes `ESCALATE` | `ESCALATE` | Trade escalated to human review; `GovernanceError` raised |
| 5 | ALL critics vote `APPROVE` | `APPROVE` | Unanimous approval — trade proceeds |

> **Fail-Open on Total LLM Unavailability:** If both LLM critics return `ERROR` (e.g., vLLM backend down), the consensus engine defaults to `APPROVE` with the reason `"Consensus skipped — all LLM critics unavailable (fail-open)."`. This design mirrors the SLM sidecar graceful degradation (Phase 4.3) — the consensus layer is supplementary to the deterministic OPA/CBF/STPA tiers, which remain the primary enforcement gates.

### 7.4 Background Audit Queue (Phase 4.4)

All consensus results — including `SKIPPED` decisions — are pushed to a non-blocking `asyncio.Queue(maxsize=1000)` for post-execution background logging:

- **`_AUDIT_QUEUE`**: Module-level `asyncio.Queue` with a 1000-record cap
- **`_background_audit_worker()`**: Long-lived coroutine started at gateway startup via `asyncio.create_task()`. Drains the queue and logs completed consensus records with action, symbol, amount, decision, and votes
- **Non-blocking guarantee**: `put_nowait()` is used to enqueue — if the queue is full, the audit record is dropped with a warning log rather than blocking the governance hot-path
- **Hot-path impact**: **0ms** — audit I/O is fully off the critical path

### 7.5 OTel Evidence Stamping

Every consensus check emits OpenTelemetry span attributes for the audit trail:

| Span Attribute | Value |
| -------------- | ----- |
| `langfuse.trace.metadata.iso.control_id` | `A.8.4` (AI System Impact Assessment) |
| `langfuse.trace.metadata.consensus.decision` | `APPROVE` / `REJECT` / `ESCALATE` |
| `langfuse.trace.metadata.consensus.votes` | Stringified list of critic votes |
| `langfuse.trace.metadata.iso.control_id_secondary` | `A.4.2` (Risk Management) — added on `ESCALATE` decisions |

---

## 7a. DEFER State Machine — Confidence-Starvation Bypass (v2.0.0)

Source: [`src/gateway/governance/defer_queue.py`](../../src/gateway/governance/defer_queue.py)

CAGE v2.0.0 extends the governance tri-state decision (`ALLOW | DENY | MANUAL_REVIEW`) to **four states** by introducing `DEFER`. This satisfies the CSA AARM specification's **Deferral Service** mandate — providing a formal state for situational ambiguity that avoids forcing a brittle binary allow/deny choice.

### Confidence-Starvation Boundary

The DEFER state machine implements a **three-zone confidence model**:

| Confidence Score | Decision | Routing |
| ---------------- | -------- | ------- |
| ≥ 0.95           | `ALLOW` / `DENY` | Autonomous Clearance via `system_authz.rego` |
| 0.70 – 0.95      | **`DEFER`** | Automated data-hydration loop — token parked in Redis db=1 with 4-hour TTL; resolved via `POST /v1/defer/{id}/inject` (automated) or `POST /v1/defer/{id}/escalate` (HITL) |
| < 0.70           | `DENY` | Confidence-Starvation Boundary — context fundamentally corrupted or missing |

### DeferToken Redis Architecture

- **Redis database**: `db=1` (isolated from LangGraph checkpointer at `db=0`)
- **Memory policy**: `maxmemory-policy noeviction` — fail-safe, blocks on OOM rather than silently dropping execution contexts
- **Data structures**:
  - `DEFER:{defer_id}` — Redis Hash containing the full `DeferToken` JSON
  - `DEFER:expiry_index` — Redis ZSet with `member=defer_id, score=expiry_unix_ts`
- **Default TTL**: 4 hours before stale escalation

### DeferReason Taxonomy

| Reason | AARM Mapping | Description |
| ------ | ------------ | ----------- |
| `INSUFFICIENT_CONTEXT` | AARM-V7 | OPA input snapshot missing required fields |
| `AMBIGUOUS_SEMANTIC_DISTANCE` | AARM-V7 | SLM similarity score in ambiguity band (0.40–0.60) |
| `DATA_STARVATION` | AARM-V7 | Langfuse telemetry evidence window below minimum sample |
| `CONFIDENCE_BELOW_THRESHOLD` | AARM-V7 | Model confidence < 0.70 |
| `EXTERNAL_VALIDATION` | SA-9 | Consensus score in ambiguous zone (0.70–0.95); awaiting external FRIA gate from normative provider (v2.1.0, §2.5) |

### Resolution Paths

Pending tokens are resolved by:
1. **Human-in-the-loop step-up**: `POST /v1/defer/{id}/escalate` → resolves as `ESCALATED`
2. **Automated data injection**: `POST /v1/defer/{id}/inject` → resolves as `INJECTED` with supplementary data payload
3. **TTL expiry**: Background `expire_stale()` sweep marks tokens as `EXPIRED` and auto-escalates

### Compliance Mapping

| Standard | Control | Mapping |
| -------- | ------- | ------- |
| ISO 42001 | A.8.4 | AI System Operation Controls — formal pause prevents unsafe execution under ambiguous context |
| CSA AARM | V7 | Context Window Overflow neutralization |
| STPA | UCA-7 | Agent proceeds with ambiguous context instead of parking for data injection |

---

## 8. DoWhy Causal Gatekeeper — Tier 6 (v2.0.0)

The **DoWhy Causal Gatekeeper** ([`src/gateway/governance/causal_gatekeeper.py`](../../src/gateway/governance/causal_gatekeeper.py)) serves as CAGE's final mathematical validation layer—the "Lock" on the CAGE. It utilizes **Microsoft DoWhy** causal inference and placebo simulation to confirm that the system's world-model is structurally sound before high-stakes trade actions.

> **Implementation note (2026-06-03):** `generate_mock_telemetry()` was updated to include a `timestamp` column (4 columns total: `trade_amount`, `risk_score`, `market_volatility`, `timestamp`). The freshness check in `causal_safety_check()` requires this column to validate that telemetry data is not stale. The fail-closed behavior is preserved — genuinely stale telemetry still blocks. The fix ensures synthetic/mock data passes the freshness check without bypassing the production guard.

### 8.1 Dual-Lifecycle Validation
The gatekeeper enforces two complementary validation phases:
1. **Phase 1: Statistical Kernel (CTRL_MRM_004)** — Fits a linear regression model over historical telemetry to estimate the marginal causal effect of `trade_amount` on `risk_score`, adjusting for the confounder `market_volatility`. Satisfies Model Risk Management standards.
2. **Phase 2: Operational Simulation (CTRL_TEL_003)** — Executes **50 placebo simulations** in real time against live Langfuse telemetry. If replacing the real treatment with random noise produces a statistically significant effect (`p_value < 0.05` or `placebo_effect > 0.2`), the causal graph assumptions are flagged as corrupted (Memory Poisoning / context manipulation), triggering an immediate `GovernanceError` fail-closed.

---

## 8.2 FiscalLimitGuard Concurrency Control

To prevent race conditions where multiple parallel agent execution threads concurrently read the same daily OPA limit and execute trades that in aggregate exceed the limit ("race to the rail"), CAGE v2.0.0 introduces the **FiscalLimitGuard** (`src/gateway/governance/fiscal_limit_guard.py`).
*   **Redis Atomic Transactions:** Uses Redis `WATCH/MULTI/EXEC` optimistic locking. If another thread updates the cap during OPA validation, the current pipeline commits are rejected, retrying with exponential backoff and jitter.
*   **Headroom Pre-Reservation (Step 3):** Headroom is reserved in Redis *after* concurrent CBF+OPA (Steps 2+4), closing the TOCTOU race. Default daily cap: **$500,000 USD** (`FISCAL_DAILY_CAP_USD` env var). Cap stored in **cents** for integer precision. Fail-closed: if Redis is unavailable, the trade is blocked.
*   **Release & Expiry:** Unused limits are dynamically returned to Redis via `release(token)` by the Saga engine on transaction rollback, while a **300s TTL** reclaims limits from crashed nodes.

---

## 9. Governance Signing: Cloud KMS HSM (Primary) + HMAC-SHA256 (Fallback)

CAGE v2.0.0 promotes **Cloud KMS HSM-backed asymmetric signing** as the primary governance signing mechanism, replacing HMAC-SHA256 as the primary. HMAC-SHA256 is retained as a fallback for development and CI environments only.

### Cloud KMS HSM Signing (Primary — Production)

- **Algorithm**: RSA-PKCS1-4096-SHA256 — asymmetric; private key never leaves the HSM
- **Key**: `CAGE_KMS_KEY_NAME` environment variable (e.g., `projects/{proj}/locations/global/keyRings/cage-governance/cryptoKeyVersions/1`)
- **Signing**: `KMSSigner.sign(payload)` — executed inside Google Cloud HSM; non-exportable private key
- **Verification**: `KMSSigner.verify(payload, signature)` — sub-millisecond local RSA verification using embedded public key PEM
- **Non-repudiation**: Google Cloud Audit Logs provide an immutable, externally attested record of every `cloudkms.cryptoKeyVersions.useToSign` operation
- **Compliance**: Satisfies **ISO 42001 §A.7.5** (records integrity), **NIST AU-10** (non-repudiation), **FINRA Rule 4511** (tamper-evident records)
- **Fallback**: If `CAGE_KMS_KEY_NAME` is unset, the signer falls back to HMAC-SHA256 with a `[KMSSigner] Falling back to HMAC` warning log — **prohibited in production**

### HMAC-SHA256 Routing Seal (Fallback / Dev-CI)

- Applied to **every** `/tools/execute` call as the routing integrity seal
- HMAC-SHA256 computed over raw request body bytes
- Secret: `CAGE_ROUTING_SEAL_SECRET` environment variable
- Enforced by [`src/gateway/server/governance_middleware.py`](../../src/gateway/server/governance_middleware.py); missing or invalid seal → reject (fail-closed)
- **FIND-010** (routing seal bypass): **RESOLVED** — POAM-012 closed

### Governance Signature (Agent State)

- HMAC-SHA256 computed over the `execution_plan_output` field in `AgentState`
- The Evaluator agent signs the plan and stores the result as `governance_signature` in state
- [`check_safety_signature(state)`](../../src/governed_financial_advisor/graph/graph.py) in the `safety_node` validates the signature before the `governed_trader` node executes
- Prevents state tampering between the evaluator and trader nodes in the LangGraph pipeline

### AnchorageGrpcLedgerProvider (Externally Reconciled CBF)

> **Status (POAM-023):** The `AnchorageGrpcLedgerProvider` for externally reconciled CBF balance anchoring is referenced in the architecture but has not yet been implemented. The current implementation uses the Redis `WATCH/MULTI/EXEC` optimistic locking pattern for CBF enforcement. The "Stale Ground Truth" threat (balance staleness) is addressed by the TTL-gated staleness check in the DEFER state machine (AARM-V7) and the `post_hitl_revalidate_node` execution-time re-sampling.

When implemented, `AnchorageGrpcLedgerProvider` will provide an externally reconciled cash balance anchor via gRPC, ensuring that the CBF invariant `h(x) = cash_balance - min_cash_balance ≥ 0` is validated against an authoritative external ledger rather than a Redis-cached balance — eliminating the residual "Stale Ground Truth" risk for high-value trades.

---

## 10. Threshold Management

**Single source of truth:** [`config/governance_thresholds.json`](../../config/governance_thresholds.json)

[`GovernanceThresholds`](../../src/gateway/governance/schemas/thresholds.py) Pydantic model (line 91):

- `@lru_cache(maxsize=1)` singleton — loaded once at startup
- [`load_and_validate_thresholds()`](../../src/gateway/governance/schemas/thresholds.py) at line 115: calls `sys.exit(1)` on validation failure — **fail-fast startup**
- NeMo actions hot-reload with 60-second TTL
- **v2.0.0-rc.1:** `max_slippage_pct` is now operator-adjustable at runtime via `POST /api/governance/thresholds` from the AgentSight KernelDashboard slider (0–10%, step 0.1); persisted to the running threshold store without service restart

**22 tracked thresholds** with full regulatory traceability (see [`compliance/risk_acceptance/THRESHOLD_TRACEABILITY_MATRIX.md`](../../compliance/risk_acceptance/THRESHOLD_TRACEABILITY_MATRIX.md)):

| Threshold Key                         | Value      | Controls Linked  |
| ------------------------------------- | ---------- | ---------------- |
| `cbf.min_cash_balance`                | 1000.0     | CBF, FIN-1       |
| `cbf.gamma`                           | 0.5        | CBF              |
| `drawdown.limit`                      | 0.05       | UCA-5            |
| `stpa.uca5_drawdown_threshold_pct`    | 4.5%       | UCA-5, FIND-008  |
| `stpa.uca6_max_order_volume_fraction` | 0.01       | UCA-6            |
| `stpa.max_sell_portfolio_fraction`    | 0.10       | FIN-1            |
| `stpa.max_latency_ms`                 | 200.0      | FIN-2, ISO-20022 |
| `confidence.min_trade_confidence`     | 0.95       | SR 26-2 §IV.B, IA-5 — **DEPRECATED**: `OPA system_authz.rego` is now authoritative for confidence enforcement |
| `consensus.threshold_usd`             | 10000.0    | CA-7             |
| `tier1_keywords`                      | 14 entries | SI-3             |

---

## 11. ISO Control Stamping

[`stamp_iso_control()`](../../src/gateway/governance/iso_control.py) (line 64) stamps **6 mandatory OpenTelemetry span attributes** on every governance action, creating an auditable evidence chain:

| Attribute                  | Example Value            | Purpose                                 |
| -------------------------- | ------------------------ | --------------------------------------- |
| `iso42001.control`         | `"A.9.2"`                | ISO 42001 Annex A control identifier    |
| `iso42001.tier`            | `2`                      | Governance tier number                  |
| `iso42001.outcome`         | `"PASSED"`               | Tier result                             |
| `iso42001.timestamp`       | `"2026-03-07T05:00:00Z"` | ISO 8601 event timestamp                |
| `iso42001.gateway_version` | `"1.4.2"`                | Gateway version for evidence provenance |
| `iso42001.evidence_chain`  | `"chain-ref-abc123"`     | Chain of custody reference              |

### ISO_CONTROL_MAP

The `ISO_CONTROL_MAP` exists in **two locations** — [`langfuse_utils.py:46`](../../src/governed_financial_advisor/utils/langfuse_utils.py) and [`compliance_bridge/types.py:133`](../../src/compliance_bridge/types.py) — which is documented technical debt requiring consolidation:

| Control Key        | ISO 42001 Annex A            | Scope                        |
| ------------------ | ---------------------------- | ---------------------------- |
| `nemo_input_scan`  | A.9.2 — Data Privacy / PII   | NeMo input guardrail scan    |
| `nemo_output_rail` | A.5.2 — Social Impact        | NeMo output safety rail      |
| `opa_policy_check` | SC-4 — Fiscal / RBAC         | OPA Rego policy evaluation   |
| `otel_trace`       | A.5.3 — Logging / Monitoring | OpenTelemetry trace emission |

---

## 12. Policy Transpiler & STPA-to-Policy Compiler

### 12.1 PolicyTranspiler (Runtime)

[`PolicyTranspiler`](../../src/governed_financial_advisor/governance/transpiler.py) automates the derivation of enforceable policies from regulatory requirements — implementing the **Automated Policy Derivation** governance pattern.

**Input:** A `ProposedUCA` — a Pydantic `ConstraintLogic` model produced by the `RiskAnalystAgent` from its analysis of regulatory text.

**Process:**

1. LLM generates a candidate NeMo action stub and an OPA Rego policy fragment
2. [`JudgeAgent.verify()`](../../src/governed_financial_advisor/governance/transpiler.py) validates the output by checking for required markers: `def `, `decision`, `package`
3. If judge validation fails, a deterministic template fallback is used to guarantee output

**Output:** A deployable NeMo action stub + OPA Rego fragment, ready for review and deployment.

**Supporting tool:** [`scripts/deontic_policy_extractor.py`](../../scripts/deontic_policy_extractor.py) — extracts deontic logic (obligations, permissions, prohibitions) from raw regulatory text as structured input to the transpiler.

```
Regulatory Text
      │
      ▼
deontic_policy_extractor.py
      │  (obligations / permissions / prohibitions)
      ▼
RiskAnalystAgent → ProposedUCA (ConstraintLogic)
      │
      ▼
PolicyTranspiler
      ├─ LLM generates NeMo stub + Rego fragment
      ├─ JudgeAgent.verify() validates
      └─ Fallback template (deterministic) on failure
      │
      ▼
Deployable NeMo Action + OPA Rego Policy
```

### 12.2 STPA-to-Policy Compiler (Build-Time CLI)

[`src/gateway/governance/stpa_compiler.py`](../../src/gateway/governance/stpa_compiler.py) is a CLI tool that compiles the STPA control structure definition ([`config/stpa_control_structure.yaml`](../../config/stpa_control_structure.yaml)) into four enforcement artifact types:

| Output Target | Generated File | Purpose |
| ------------- | -------------- | ------- |
| **OPA Rego rules** | `deployment/system_authz.rego` extensions | Deterministic policy checks for each UCA |
| **NeMo Colang rails** | Colang 2.x flow definitions | Guardrail content-safety rules for each UCA |
| **Python validator** | `src/gateway/governance/generated_stpa_validator.py` | Runtime `STPAValidator` class with per-UCA check methods |
| **LangGraph Saga nodes** | `src/gateway/governance/generated_saga_nodes.py` | WAL ledger entries, forward nodes, LIFO rollback, idempotent compensating nodes, and ghost-state recovery sub-graphs |

The compiler reads UCA definitions (UCA-1 through UCA-9), their associated hazards, detection patterns, and enforcement targets from YAML and emits deterministic, production-ready code — no LLM is involved in the compilation step.

---

## 13. Formal Risk Acceptances

The following governance-related risk acceptances are documented in [`compliance/risk_acceptance/THRESHOLD_TRACEABILITY_MATRIX.md`](../../compliance/risk_acceptance/THRESHOLD_TRACEABILITY_MATRIX.md):

| ID     | Risk Accepted                                                           | Compensating Control                                                                                                             |
| ------ | ----------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| RA-001 | 1% OTel sampling rate (performance tradeoff)                            | 100% governance logging maintained independently of trace sampling                                                               |
| RA-002 | Trades below $10k threshold processed by single agent without consensus | Consensus threshold is calibrated to organizational risk tolerance; single-agent decisions remain within STPA + OPA + CBF bounds |
| RA-004 | Single OPA node deployment with 5-failure circuit breaker               | Circuit breaker defaults to DENY-on-open, preserving fail-closed posture even during OPA availability events                     |

---

## Summary

The CAGE AI Governance & Policy Engine enforces a **neuro-symbolic, defense-in-depth** governance model across 6 active sequential tiers (0–6, plus tier 6b adaptive FRIA gate, with Tier 3 SLM deprecated), plus an optional 8th step for EU deployments. Every trade request must survive STPA semantic safety checks, confidence thresholds, a Redis-atomic Control Barrier Function, OPA Rego role-based authorization, multi-agent LLM consensus voting (two concurrent critic personas with a strict priority ladder), DoWhy causal gatekeeping, and adaptive external normative validation (§2.5) before execution is approved. All active tiers are fail-closed. The DEFER State Machine (v2.0.0) extends the decision space to four states (`ALLOW | DENY | MANUAL_REVIEW | DEFER`), now including `EXTERNAL_VALIDATION` (v2.1.0) for parking transactions in the ambiguous confidence zone while awaiting external FRIA gate responses. All thresholds are centrally managed with regulatory traceability and region-specific calibration. ISO 42001 control stamps create an auditable evidence chain on every governance event. The Policy Transpiler and STPA-to-Policy Compiler close the loop by converting regulatory requirements and STPA hazard definitions into deployable enforcement artifacts automatically.
