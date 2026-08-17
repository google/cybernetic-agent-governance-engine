# The Cybernetic Governance of Agentic AI: A Systems-Theoretic Analysis of ISO/IEC 42001 and the Cybernetic Agent Governance Engine (CAGE) Architecture

> **Jurisdiction separation principle:** **ISO/IEC 42001:2023 is the sole universal governance baseline** for CAGE. All VSM mappings, clause references, and control IDs in this document apply to every deployment region. Jurisdiction-specific frameworks (SR 26-2, NIST AI 600-1 — US_FED; EU AI Act, GDPR, DORA — EU_ECB; MAS FEAT, MAS Notice 655 — APAC_MAS) are additive layers activated by `CAGE_DEPLOYMENT_REGION` and impose no obligations on other regions.

## 1. Introduction: The Epistemological Crisis of Autonomous Agents

The transition to Agentic AI represents a shift from deterministic software to probabilistic, goal-oriented autonomy. Systems like **CAGE** (Cybernetic Agent Governance Engine) act within open-ended environments, precipitating a crisis for traditional "First-Order" governance.

**ISO/IEC 42001:2023** provides the framework for this new era. By mapping it to **Cybernetics** (specifically Stafford Beer’s Viable System Model), we construct a governance architecture capable of containing the "wildness" of agents via "Requisite Variety".

## 2. The Cybernetic Ontology

### 2.1. First-Order vs. Second-Order

- **First-Order:** Standard compliance (Checklists). Assumes a static subject.
- **Second-Order:** "Observing Systems" (Reflexivity). The **Evaluator Agent** in our system implements this by observing and critiquing the Planner's output before it acts.

### 2.2. The Law of Requisite Variety

- "Only variety can destroy variety."
- A manual audit team (Low Variety) cannot regulate an autonomous agent (High Variety).
- **Solution:** We use **Computational Governance** (The Evaluator Agent) to match the variety of the system.

## 3. CAGE Architecture & VSM Mapping

**v2.0.0 System State (GO: 2026-06-08):** CAGE implements an **8-tier governance pipeline** (FTRA pre-pipeline boundary gate at Tier 0.5 plus 7 in-pipeline tiers: Tiers 0–6, plus Tier 6b adaptive FRIA gate: STPA → Agentic Confidence → CBF + OPA [concurrent] → Fiscal Limit Pre-Reservation → Consensus → CausalGatekeeper → FRIA) with a 10-node LangGraph StateGraph. The legacy SLM sidecar has been fully retired with a permanent `slm_available=False` sentinel; OPA Policy Evaluation runs concurrently with the CBF check. NeMo Guardrails (including the Aho-Corasick keyword scan) runs as a pre-pipeline screening layer, integrated into the gateway process (not a standalone sidecar). Sensitive data detection covers **15 PII entity types** via Presidio/spaCy. Implemented v2.0.0 controls include: **Token Quota Proxy** (`token_quota_proxy.py`), **PII Sanitizer** (`pii_sanitizer.py`), and **UCA Logger** (`uca_logger.py`). All controls are ISO 42001 obligations active in every region; SR 26-2 MRM scope (CBF + DoWhy Phase 1) applies **US_FED only**.

> **FUTURE STATE — AnchorageGrpcLedgerProvider (POAM-023, target 2026-09-08):** External CBF ledger reconciliation via `AnchorageGrpcLedgerProvider` is **not yet implemented**. The Control Barrier Function currently uses Redis-only state. gRPC-based external ledger integration is tracked as POAM-023.

We map the components of our Governance Graph to the **Viable System Model (VSM)**:

| VSM System   | Function           | Our Component                     | ISO 42001 Clause           |
| :----------- | :----------------- | :-------------------------------- | :------------------------- |
| **System 5** | **Policy**         | **System Prompts / Constitution** | Clause 5.2 (Policy)        |
| **System 4** | **Intelligence**   | **Planner (Execution Analyst)**   | Clause 6.1 (Risk Planning) |
| **System 3** | **Control**        | **Evaluator Agent**               | Clause 9.1 (Monitoring)    |
| **System 2** | **Coordination**   | **Graph State / Schema**          | Clause 8 (Operation)       |
| **System 2** | **Coordination**   | **Graph State / Schema**          | Clause 8 (Operation)       |
| **System 1** | **Implementation** | **Executor (Governed Trader)**    | Clause 8 (Operation)       |

### 3.1. Technical Control Mappings (Telemetry)

The system emits specific ISO Control IDs in its OpenTelemetry spans to prove compliance during audits:

| Control ID | Requirement                   | Implementation Component              | Telemetry Attribute                                |
| :--------- | :---------------------------- | :------------------------------------ | :------------------------------------------------- |
| **A.10.1** | Transparency & Explainability | **Governance Client** (`client.py`)   | `langfuse.trace.metadata.iso.control_id`           |
| **A.8.4**  | AI System Impact Assessment   | **Consensus Engine** (`consensus.py`) | `langfuse.trace.metadata.iso.control_id`           |
| **A.4.2**  | Risk Management               | **Consensus Engine** (Escalation)     | `langfuse.trace.metadata.iso.control_id_secondary` |

## 4. Governance Mechanisms

### 4.1. Feedforward Planning (System 4)

The **Planner** does not just act; it simulates. This is **Feedforward Control**. It anticipates errors (e.g., "Market Closed") before they occur.

### 4.2. The Simulation Loop (System 3)

The **Evaluator** performs a "Dry Run":

1.  **Feasibility:** Checks environment state.
2.  **Legality:** Checks OPA Policy.
3.  **Safety:** Checks NeMo Rails.

### 4.3. Faithfulness (System 3 Monitoring)

The **Explainer** ensures the output is grounded in reality, addressing the "Black Box" problem and "Post-Hoc Rationalization".

### 4.4. 8-Tier Governance Pipeline

The [`SymbolicGovernor`](../../../src/gateway/governance/symbolic_governor.py) implements an 8-tier pipeline (FTRA pre-pipeline boundary gate plus 7 in-pipeline tiers via `_run_checks()`) that every `execute_trade` action must traverse before a routing seal is issued. Each tier is a distinct safety layer with formal properties; Tiers 2 and 4 execute concurrently:

| Tier | Name | Mechanism | Formal Property |
| :--- | :--- | :-------- | :-------------- |
| **Tier 0** | STPA/STAMP UCA validation | `GeneratedSTPAValidator.validate()` | Bright-line block on unsafe control actions — no override |
| **Tier 1** | Agent confidence pre-check | Fast-fail local check against `AGENT_CONFIDENCE_THRESHOLD` | Avoids unneeded CBF/OPA round-trips |
| **Tier 2** | Control Barrier Function | Redis-backed cash balance invariant; concurrent with Tier 4 | Fail-closed on Redis unavailability |
| **Tier 3** | Fiscal Limit Pre-Reservation | `FiscalLimitGuard.reserve()` (Redis WATCH/MULTI/EXEC) | Closes TOCTOU race on daily fiscal cap |
| **Tier 4** | OPA policy evaluation | `asyncio.gather()`; concurrent with Tier 2 | Fail-closed on OPA unavailability |
| **Tier 5** | Consensus | ≥$10k trades, 30s timeout | Multi-critic unanimity |
| **Tier 6** | Causal gatekeeper | SCM + `PlaceboTreatmentRefuter` | World-model consistency |
| **Tier 6b** | FRIA zones | `FRIA_ZONE_ALLOW=0.95`, `FRIA_ZONE_DEFER=0.70` | Human oversight gate |

> PII sanitization (`pii_sanitizer.py`) and confabulation scoring (`confabulation_scorer.py`) are standalone modules, not sequential tiers of `_run_checks()`. PII sanitization runs inside `uca_logger.py` immediately before a UCA audit record is written to the WORM ledger; confabulation scoring is a standalone Langfuse observability metric.

## 5. Mathematical Safety Controls

This section documents the formal mathematical invariants enforced by the CAGE governance kernel. All formulas are implemented in the source files referenced below.

### 5.1. Control Barrier Functions (CBF)

**Source:** [`src/gateway/governance/cbf.py`](../../../src/gateway/governance/cbf.py)

The CBF enforces fiscal safety as a forward-invariance condition on the system state space.

- **Safe set:** `S = {x ∈ ℝⁿ : h(x) ≥ 0}`
- **Barrier function:** `h(x) = cash_balance − min_cash_balance`
- **Discrete-time CBF condition:** `h(S(t+1)) ≥ (1−γ)·h(S(t))` where `γ ∈ (0,1)`

The CBF condition guarantees that the system cannot transition from a safe state to an unsafe state in a single step. The decay parameter `γ` controls the rate at which the safety margin is permitted to shrink. CBF state is read atomically via a Redis pipeline (fail-closed on unavailability).

### 5.2. FRIA Zone Thresholds

**Source:** [`src/gateway/governance/symbolic_governor.py`](../../../src/gateway/governance/symbolic_governor.py)

The Fundamental Rights Impact Assessment (FRIA) zone thresholds determine the disposition of each governance decision at Tier 6b:

| Score Range | Zone | Action |
| :---------- | :--- | :----- |
| score ≥ `FRIA_ZONE_ALLOW` (0.95) | ALLOW | Async attestation — automated |
| `FRIA_ZONE_DEFER` (0.70) ≤ score < 0.95 | DEFER | Synchronous blocking gate — human review required |
| score < `FRIA_ZONE_DEFER` (0.70) | BLOCK | Hard block — human required |

Named constants: `FRIA_ZONE_ALLOW = 0.95`, `FRIA_ZONE_DEFER = 0.70`

### 5.3. Confabulation Risk Score

**Source:** [`src/gateway/governance/confabulation_scorer.py`](../../../src/gateway/governance/confabulation_scorer.py)

The confabulation (hallucination) risk score is computed as the complement of the model's self-reported confidence:

```
risk_score = 1.0 − confidence
```

A `risk_score` approaching 1.0 indicates high hallucination risk. Confabulation scoring is a standalone Langfuse observability metric computed independently of the FRIA zone classification (Tier 6b).

### 5.4. Causal Marginal Risk Boundary

**Source:** [`src/gateway/governance/causal_gatekeeper.py`](../../../src/gateway/governance/causal_gatekeeper.py)

The causal gatekeeper applies a marginal risk boundary to prevent trades whose causal effect estimate pushes the system into an unsafe region:

```
(0.5 + estimate.value × amount) > CAUSAL_LOCK_RISK_BOUNDARY
```

Named constants:
- `CAUSAL_LOCK_RISK_BOUNDARY = 0.95`
- `CAUSAL_LOCK_P_VALUE_THRESHOLD = 0.05`
- `CAUSAL_LOCK_PLACEBO_EFFECT_MAGNITUDE = 0.2`

The `PlaceboTreatmentRefuter` runs 50 simulations; a refutation is triggered when `p < 0.05` and `|effect| > 0.2`, indicating the causal estimate is not robust to placebo treatment.

### 5.5. Routing Seal Integrity

**Source:** [`src/gateway/governance/routing_seal.py`](../../../src/governed_financial_advisor/utils/routing_seal.py)

Every request traversing the governance gateway must carry a valid HMAC-SHA256 routing seal. The seal format is:

```
<expire_ts_hex>.<action_slug>.<hmac_hex>
```

- **Algorithm:** HMAC-SHA256 keyed on `GOVERNANCE_SALT` (≥64 chars, fail-fast at startup)
- **TTL:** 30 seconds (`expire_ts_hex` encodes the expiry Unix timestamp)
- **Enforcement:** `CAGE_SEAL_ENFORCEMENT=enforce` required in production; `log` mode is prohibited

### 5.6. Fiscal Limit Guard Parameters

**Source:** [`src/gateway/governance/fiscal_limit_guard.py`](../../../src/gateway/governance/fiscal_limit_guard.py)

The `FiscalLimitGuard` enforces a hard daily spending cap using Redis atomic operations:

| Parameter | Value | Description |
| :-------- | :---- | :---------- |
| Daily cap | $500,000 USD | Stored as integer cents in Redis |
| Window | 86,400 seconds | Rolling 24-hour window |
| Retry backoff | `_RETRY_BASE_MS × 2^attempt` | Exponential backoff on Redis contention |

State is managed via Redis `WATCH`/`MULTI`/`EXEC` atomic transactions. The guard is fail-closed: Redis unavailability blocks the trade.

## 6. STPA Unsafe Control Actions

**Source:** [`src/gateway/governance/ontology.py`](../../../src/gateway/governance/ontology.py)

System-Theoretic Process Analysis (STPA) identifies the following Unsafe Control Actions (UCAs) that the governance kernel is designed to prevent. These are enforced by the `GeneratedSTPAValidator` and logged by the `UCALogger`.

| UCA ID | Condition | Description |
| :----- | :-------- | :---------- |
| **FIN-1** | `trade_value > position_limit` | Trade value exceeds the position limit — concentration risk |
| **FIN-2** | `portfolio_concentration > 0.25` | Portfolio concentration exceeds 25% in a single asset |
| **UCA-5** | `order_size > 0.1 × daily_volume` | Order size exceeds 10% of daily volume — market impact risk |
| **UCA-6** | `order_size > fraction × daily_vol` | Order size exceeds the parameterised fraction of daily volume |

All UCA violations are recorded as 16-field compliance records, signed with KMS (HMAC-SHA256), and written to the region-gated WORM bucket (`CAGE_DEPLOYMENT_REGION`).

## 7. Conclusion

By implementing CAGE, we move from "Rule-Based Guardrails" to **"Agentic Governance"**. The Evaluator Agent acts as a cybernetic regulator, ensuring that the system remains viable and compliant within the high-stakes environment of Corporate Finance. The 8-tier governance pipeline (FTRA + 7 in-pipeline tiers), grounded in Control Barrier Function theory and causal inference, provides mathematically verifiable safety guarantees that satisfy ISO/IEC 42001:2023 Annex A obligations across all deployment regions.
