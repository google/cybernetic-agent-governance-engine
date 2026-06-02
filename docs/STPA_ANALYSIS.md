# System-Theoretic Process Analysis (STPA) Implementation — v2.0.0

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
| **UCA-1** | Unsafe Action | Agent executes write operation without approval token. | `[opa, nemo, python]` | `GeneratedSTPAValidator.check_uca1()` + OPA Rego rule. |
| **UCA-2** | Wrong Timing | Agent executes trade with stale market data (>200ms latency). | `[opa, nemo, python]` | `GeneratedSTPAValidator.check_uca2()` + OPA Rego rule. |
| **UCA-3** | Unsafe Action | Agent outputs PII to user interface. | `[nemo]` | NeMo Guardrails `verify_content_safety` + Presidio PII egress filter. |
| **UCA-4** | Stopped Too Soon | Agent debits account but fails to credit asset (atomic failure). | `[nemo, langgraph]` | **Saga WAL Pattern** — see §4 below. |
| **UCA-5** | Unsafe Action | Agent executes buy when drawdown > 4.5%. | `[opa, nemo, python]` | `SafetyFilter` (CBF) in `SymbolicGovernor` + OPA Rego rule. |
| **UCA-6** | Unsafe Action | Agent order volume fraction exceeds maximum (`uca6_max_order_volume_fraction=0.01`, i.e., 1% of portfolio). | `[opa, python]` | `GeneratedSTPAValidator.check_uca6()`. |
| **UCA-7** | Unsafe Action | High prompt injection semantic score detected. | `[opa]` | OPA Rego rule. Semantic score threshold: 0.85. |
| **UCA-8** | Unsafe Action | Trade attempted before risk assessment completed. | `[opa, python]` | `GeneratedSTPAValidator.check_uca8()`. |
| **UCA-9** | Unsafe Action | Trade attempted with compliance check bypassed. | `[opa, python]` | `GeneratedSTPAValidator.check_uca9()`. |

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

| Method | Description |
| :--- | :--- |
| `reserve(agent_id, amount_usd)` | Atomic check-and-increment; returns `ReservationToken` |
| `release(token)` | Atomic decrement on Saga rollback; idempotent, never raises |
| `confirm(token)` | Semantic hook for audit; reservation is already permanent |
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
| `src/gateway/governance/stpa_validator.py` | Hand-authored base validator (legacy) |
| `src/gateway/governance/generated_stpa_validator.py` | Auto-generated Python validator (do not edit) |
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
