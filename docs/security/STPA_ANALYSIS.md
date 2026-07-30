# System-Theoretic Process Analysis (STPA) Implementation — v0.1.0

## Overview

This document details the STPA analysis applied to the Financial Advisor system (Module 5) and its implementation in code.

**Primary Governance Framework:** SR 26-2 (Federal Reserve, April 17, 2026) — Agentic AI Model Risk Management. ISO/IEC 42001:2023 is the primary AI governance standard.

The STPA control structure is the **single source of truth** for all governance enforcement. The STPA Compiler (`src/gateway/governance/stpa_compiler.py`) ingests `config/stpa_control_structure.yaml` and auto-generates artifacts for four enforcement targets: OPA Rego policies, NeMo Colang rails, Python validator classes, and LangGraph Saga compensating sub-graphs.

---

## 1. System Control Structure

*   **Controller:** Financial AI Agent (Planner/Executor).
*   **Actuators:** Gateway Tools (`execute_trade`, `write_db`).
*   **Controlled Process:** Financial Markets / Banking Ledger.
*   **Sensors:** Market Data Feeds, OPA Policy Engine, Redis Fiscal Limit Counter.

---

## 2. Unsafe Control Actions (UCAs)

| ID | Category | Description | Enforcement | Implementation |
| :--- | :--- | :--- | :--- | :--- |
| **UCA-1** | Unsafe Action | Agent executes write operation without approval token. | `[opa, nemo, python]` | `GeneratedSTPAValidator._check_uca_1()` + OPA Rego rule. |
| **UCA-2** | Wrong Timing | Agent executes trade with stale market data (>200ms latency). | `[opa, nemo, python]` | `GeneratedSTPAValidator._check_uca_2()` + OPA Rego rule. |
| **UCA-3** | Unsafe Action | Agent outputs PII to user interface. | `[nemo]` | NeMo Guardrails `verify_content_safety` + Presidio PII egress filter. |
| **UCA-4** | Stopped Too Soon | Agent debits account but fails to credit asset (atomic failure). | `[nemo, langgraph]` | **Saga WAL Pattern** — see §4 below. |
| **UCA-5** | Unsafe Action | Agent executes buy when drawdown > 4.5%. | `[opa, nemo, python]` | `GeneratedSTPAValidator._check_uca_5()` (threshold: `THRESHOLDS.stpa.uca5_drawdown_threshold_pct`) + `ControlBarrierFunction` in `cbf.py` + OPA Rego rule. |
| **UCA-6** | Unsafe Action | Agent order volume fraction exceeds maximum (`uca6_max_order_volume_fraction=0.01`, i.e., 1% of portfolio). | `[opa, python]` | `GeneratedSTPAValidator._check_uca_6()`. |
| **UCA-7** | Unsafe Action | High prompt injection semantic score detected. | `[opa]` | OPA Rego rule. Semantic score threshold: 0.85. |
| **UCA-8** | Unsafe Action | Trade attempted before risk assessment completed. | `[opa, python]` | `GeneratedSTPAValidator._check_uca_8()`. |
| **UCA-9** | Unsafe Action | Trade attempted with compliance check bypassed. | `[opa, python]` | `GeneratedSTPAValidator._check_uca_9()`. |

---

## 3. STPA Compiler — Enforcement Target Matrix

The compiler (`python -m src.gateway.governance.stpa_compiler compile --targets <target>`) generates the following artifacts:

| Target | Generated File | Enforcement Mechanism |
| :--- | :--- | :--- |
| `opa` | `config/opa/generated_stpa_policy.rego` | OPA Rego policy; fail-closed circuit breaker in `core/policy.py` |
| `nemo` | `config/rails/generated_stpa_rails.co` | NeMo Colang 2.x flow; enforced by `nemo/manager.py` |
| `python` | `src/gateway/governance/generated_stpa_validator.py` | `GeneratedSTPAValidator` Python class; invoked by `SymbolicGovernor` |
| `langgraph` | `src/gateway/governance/generated_saga_nodes.py` | LangGraph WAL forward + compensating nodes + centralized router |
| `all` | `opa` + `nemo` + `python` | Note: `langgraph` is **not** included in `all`; must be explicit |

---

## 4. UCA-4 — LangGraph Saga Pattern

UCA-4 represents an atomic transaction failure: the agent successfully debits an account but crashes before crediting the asset. This is a **ghost-state** problem that cannot be solved at the NeMo or OPA layer — it requires stateful orchestration.

### 4.1 Write-Ahead Log (WAL) Pattern

Every `execute_trade` call managed by the Saga follows a 3-step WAL protocol:

```
Step 1: Write PENDING intent to LangGraph checkpointer (Redis)
                ↓
Step 2: Execute external API call (debit)
                ↓
Step 3: Write COMPLETED confirmation with idempotency_key
```

If the agent crashes between Step 1 and Step 3, the `PENDING` entry persists in the Redis checkpointer. On the next execution, `saga_router_node` detects the dangling `PENDING` entry and escalates to `human_review`.

### 4.2 Ledger Schema (`AgentState.completed_transactions`)

```python
LedgerEntry = TypedDict("LedgerEntry", {
    "sequence_id":     int,              # LIFO ordering key
    "timestamp":       str,              # ISO 8601 UTC
    "uca_ref":         str,              # e.g. "UCA-4"
    "action":          str,              # e.g. "execute_trade"
    "idempotency_key": str,              # SHA-256(tx_id + action)[:32]
    "status":          LedgerEntryStatus,# PENDING | COMPLETED | ROLLED_BACK | PARTIAL_FAILURE
    "context_data":    dict,             # forward action result (tx_id, amount, account_id)
})
```

The ledger uses `Annotated[list[LedgerEntry], add]` — an append-only reducer — ensuring thread-safe writes across concurrent LangGraph nodes.

### 4.3 Centralized Saga Router Node

`saga_router_node` (generated) implements deterministic LIFO rollback:

1. **Ghost-state check:** If any `PENDING` entries exist → `ESCALATED + human_review`
2. **LIFO traversal:** Sort `COMPLETED` entries by `sequence_id` descending → delegate to compensating node
3. **Unhandled UCA:** If no compensating node registered → `ESCALATED + human_review`

### 4.4 Idempotent Compensating Node

`compensate_reverse_trade_node_uca_4` (generated):

- Reads the most recent `COMPLETED` entry for `UCA-4 / execute_trade`
- Extracts parameters via `parameter_mapping` defined in the YAML
- Derives `idempotency_key = SHA-256(transaction_id + "reverse_trade")[:32]`
- Passes the key to the reversal API — preventing double-refunds across retries
- On success: transitions ledger to `ROLLED_BACK`, returns `safety_status=BLOCKED`
- On failure: transitions to `PARTIAL_FAILURE`, escalates to `human_review` (bankruptcy protocol)

### 4.5 YAML Configuration (`config/stpa_control_structure.yaml`)

```yaml
- id: UCA-4
  action: execute_trade
  uca_type: stopped_too_soon
  enforcement: [nemo, langgraph]
  nemo_rail:
    flow_name: block_partial_transaction
    message: "Transaction integrity check failed."
  langgraph_saga:
    forward_action: execute_trade
    compensating_action: reverse_trade
    parameter_mapping:
      forward.transaction_id: compensating.target_tx_id
      forward.amount: compensating.refund_amount
      forward.account_id: compensating.account_id
```

### 4.6 ISO 42001 Telemetry

`SagaCallbackHandler` (in `langfuse_utils.py`) fires `on_chain_end` immediately when any Saga node completes, emitting an OTel span tagged with `iso42001.control_id=A.8.4`. This ensures rollback evidence is recorded even if the graph crashes before reaching the `END` node. The `saga_rollback` event is registered in `ISO_CONTROL_MAP` → `A.8.4` (AI System Operation Controls).

---

## 5. Multi-Agent Collision Prevention — FiscalLimitGuard

### Problem: Race to the Rail

When multiple agents (trading, hedging, liquidity) evaluate OPA fiscal limits concurrently, a TOCTOU race can allow combined spend to exceed the daily cap:

```
Agent A: GET remaining=$200k → OPA: ALLOW → executes $200k  ✓
Agent B: GET remaining=$200k → OPA: ALLOW → executes $200k  ✓ (but cap is now exceeded)
```

### Solution: Pre-Reservation

`FiscalLimitGuard` (`src/gateway/governance/fiscal_limit_guard.py`) atomically reserves a spend slice in Redis **before** OPA evaluation using `WATCH/MULTI/EXEC` optimistic locking:

```
Agent A: reserve($200k) → ATOMIC: OK, remaining=$0
Agent B: reserve($200k) → ATOMIC: REJECTED (would exceed cap)
```

OPA evaluates the **post-reservation** balance — it is responsible for policy semantics, not concurrency control.

### Implementation Details

| Property | Value |
| :--- | :--- |
| Redis key | `fiscal:daily_limit:{YYYY-MM-DD}` (UTC daily window) |
| Storage format | Cents (integer) — avoids float precision issues |
| Default cap | $500,000 USD (env: `FISCAL_DAILY_CAP_USD`) |
| Reservation TTL | 300 seconds (ghost-state auto-expiry) |
| Fail mode | **Fail-closed** — Redis error → rejected token (never fail-open) |

| Method | Description |
| :--- | :--- |
| `reserve(agent_id, amount_usd)` | Atomic check-and-increment; returns `ReservationToken` |
| `release(token)` | Atomic decrement on Saga rollback; idempotent, never raises |
| `confirm(token)` | Semantic hook for audit; reservation is already permanent (`confirm()` does NOT modify the counter — it was already incremented at reservation time) |
| `current_spend_usd()` | Current total reserved + confirmed spend |
| `remaining_usd()` | Remaining daily headroom |

**Fail-closed:** Redis unreachability during `reserve()` returns a rejected token.

**Integration with Saga:** The `release(token)` call belongs in the compensating node (`compensate_reverse_trade_node_uca_4`) when the Saga rolls back a trade — restoring fiscal capacity atomically alongside the ledger update.

---

## 6. Implementation Files

| File | Purpose |
| :--- | :--- |
| `config/stpa_control_structure.yaml` | Single source of truth for all UCA definitions, conditions, and enforcement targets |
| `src/gateway/governance/stpa_compiler.py` | Compiler CLI; ingests YAML; emits OPA/NeMo/Python/LangGraph artifacts |
| `src/gateway/governance/generated_stpa_validator.py` | **Primary** auto-generated Python validator — `GeneratedSTPAValidator` with `validate()` entry-point and `_check_uca_*()` per-UCA methods (do not edit; re-run compiler to regenerate) |
| `src/gateway/governance/stpa_validator.py` | **Deprecated shim** — re-exports `GeneratedSTPAValidator` as `STPAValidator`; emits `DeprecationWarning` on import; will be removed in the next major version. `symbolic_governor.py` now imports `GeneratedSTPAValidator` directly. |
| `config/opa/generated_stpa_policy.rego` | Auto-generated OPA Rego rules (do not edit) |
| `config/rails/generated_stpa_rails.co` | Auto-generated NeMo Colang rails (do not edit) |
| `src/gateway/governance/generated_saga_nodes.py` | Auto-generated LangGraph Saga nodes (do not edit) |
| `src/gateway/governance/fiscal_limit_guard.py` | Multi-agent pre-reservation guard (Redis WATCH/MULTI/EXEC) |
| `src/governed_financial_advisor/graph/state.py` | `AgentState` with WAL ledger (`completed_transactions`) |
| `src/governed_financial_advisor/utils/langfuse_utils.py` | `SagaCallbackHandler` OTel interceptor |
| `src/gateway/governance/ontology.py` | Trading Knowledge Graph; `ISO_CONTROL_MAP` short-form alias |
| `src/compliance_bridge/types.py` | Canonical `ISO_CONTROL_MAP` including `saga_rollback → A.8.4` |
| `tests/test_stpa_compiler.py` | 33 compiler tests (schema validation, code gen, fail-closed) |
| `tests/test_fiscal_limit_guard.py` | 16 multi-agent collision tests (fakeredis, no live Redis required) |
| `examples/chaos_agent_playground.py` | Scenarios A–E: adversarial governance demo + Saga chaos tests |

---

## 7. UCA Mathematical Formalization

The UCAs defined in §2 are grounded in formal predicates drawn from the Trading Knowledge Graph in [`src/gateway/governance/ontology.py`](../../src/gateway/governance/ontology.py). Each predicate defines the precise boundary between safe and unsafe control actions.

### 7.1 Financial Position UCAs

| UCA ID | Formal Predicate | Interpretation |
| :----- | :--------------- | :------------- |
| **FIN-1** | `trade_value > position_limit` | Trade value exceeds the configured position limit → **unsafe** |
| **FIN-2** | `portfolio_concentration > 0.25` | Single-asset concentration exceeds 25% of portfolio → **unsafe** |

These predicates are evaluated by `GeneratedSTPAValidator` on every `execute_trade` call. A `True` result for either predicate produces a `DENY` decision with UCA reference logged to the UCA audit trail.

### 7.2 Order Volume UCAs

| UCA ID | Formal Predicate | Interpretation |
| :----- | :--------------- | :------------- |
| **UCA-5** | `order_size > 0.1 × daily_volume` | Order exceeds 10% of daily market volume → **unsafe** (market impact threshold) |
| **UCA-6** | `order_size > fraction × daily_vol` | Order volume fraction exceeds `uca6_max_order_volume_fraction` (default: 0.01, i.e., 1%) → **STPA Violation** |

Note that UCA-5 and UCA-6 enforce complementary constraints at different granularities: UCA-5 guards against market-impact events (absolute 10% threshold), while UCA-6 enforces the portfolio-relative volume fraction configured in `config/thresholds/`.

### 7.3 Enforcement Chain

```
ontology.py (predicate definition)
    ↓
stpa_compiler.py (code generation)
    ↓
generated_stpa_validator.py (_check_uca_5(), _check_uca_6(), FIN-1, FIN-2)
    ↓
symbolic_governor.py (Tier 0 — STPA UCA validation runs first, sequentially, before Tiers 2/4 CBF + OPA)
    ↓
uca_logger.py (WORM audit record, KMS-signed)
```

All four predicates are also expressed as OPA Rego rules in `config/opa/generated_stpa_policy.rego` (auto-generated by the STPA Compiler), providing a second independent enforcement layer.

---

## 8. CBF Safety Guarantee

The Control Barrier Function (CBF) in [`src/gateway/governance/cbf.py`](../../src/gateway/governance/cbf.py) provides a **formal mathematical safety guarantee** for the STPA control structure: it proves that the system state can never leave the safe set `S` as long as the CBF condition holds at every time step.

### 8.1 Safe Set

```
S = {x ∈ ℝⁿ : h(x) ≥ 0}
```

where the state vector `x` includes cash balance, position sizes, drawdown, and exposure metrics. The barrier function `h` is:

```
h(x) = cash_balance − min_cash_balance
```

`h(x) ≥ 0` is the necessary and sufficient condition for the system to be in the safe set. When `h(x) < 0`, the system has violated the minimum cash balance constraint — a state that must never be reached.

### 8.2 Discrete-Time CBF Condition

For the STPA control structure, the CBF enforces **forward invariance** of `S` across discrete time steps:

```
h(S(t+1)) ≥ (1−γ) · h(S(t))     where γ ∈ (0,1)
```

This condition guarantees that if the system is in `S` at time `t` (i.e., `h(S(t)) ≥ 0`), it will remain in `S` at time `t+1`. The parameter `γ` controls the rate of allowed decay:
- `γ → 0`: the barrier value must be nearly preserved (tight safety margin)
- `γ → 1`: the barrier value may decay to zero in one step (loose safety margin)

### 8.3 Relationship to STPA UCAs

The CBF condition directly enforces the STPA safe set against the financial UCAs:

| STPA UCA | CBF Enforcement Mechanism |
| :------- | :------------------------ |
| UCA-5 (drawdown > 4.5%) | `h(x)` incorporates drawdown; CBF condition violated when drawdown approaches threshold |
| FIN-1 (trade_value > position_limit) | Proposed trade is evaluated against `h(S(t+1))` before execution |
| FIN-2 (concentration > 0.25) | Post-trade concentration is projected into `h(S(t+1))` |

### 8.4 Atomic Redis Implementation

The CBF state reads are performed atomically to prevent race conditions (finding H-07):

```
WATCH fiscal:state:{session_id}
MULTI
  GET cash_balance
  GET position_sizes
  GET drawdown
EXEC
```

`_MAX_RETRIES=5` with exponential backoff. If all retries fail (Redis unavailable), the CBF returns `DENY` (fail-closed) — never `ALLOW`. This is the corrected behaviour for finding C-02.
