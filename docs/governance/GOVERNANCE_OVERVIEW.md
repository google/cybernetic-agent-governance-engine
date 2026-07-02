# Cybernetic Governance of Agentic AI

**Last Updated:** 2026-06-15 | **System Version:** v2.0.0 (stable, released 2026-06-08)

> **Jurisdiction separation principle:** **ISO/IEC 42001:2023** is the **sole universal governance baseline** — every control, pipeline step, and audit artifact in this document applies to all deployment regions (`US_FED`, `EU_ECB`, `APAC_MAS`). All other regulatory frameworks are **additive, jurisdiction-specific layers** activated exclusively by the `CAGE_DEPLOYMENT_REGION` environment variable:
> - **US_FED only:** SR 26-2 (Federal Reserve), NIST AI 600-1, NIST SP 800-53, NIST AI RMF
> - **EU_ECB only:** EU AI Act, GDPR Art. 22, DORA
> - **APAC_MAS only:** MAS FEAT Principles, MAS Notice 655, MAS TRM
>
> Controls marked *(All Regions)* are ISO 42001 obligations. Controls marked with a specific region are additive obligations for that jurisdiction only.

> **Jurisdiction separation principle:** **ISO/IEC 42001:2023** is the **sole universal governance baseline** — every control, pipeline step, and audit artifact in this document applies to all deployment regions (`US_FED`, `EU_ECB`, `APAC_MAS`). All other regulatory frameworks are **additive, jurisdiction-specific layers** activated exclusively by the `CAGE_DEPLOYMENT_REGION` environment variable:
> - **US_FED only:** SR 26-2 (Federal Reserve), NIST AI 600-1, NIST SP 800-53, NIST AI RMF
> - **EU_ECB only:** EU AI Act, GDPR Art. 22, DORA
> - **APAC_MAS only:** MAS FEAT Principles, MAS Notice 655, MAS TRM
>
> Controls marked *(All Regions)* are ISO 42001 obligations. Controls marked with a specific region are additive obligations for that jurisdiction only.

> **v0.1.0 Release Note:** This document reflects the v0.1.0 stable release. Key changes since rc.3: Token Quota Proxy (`CTRL_TQP_007`) active; PII Sanitizer active; UCA Logger active; SLM sidecar permanently deprecated (`slm_available=false`); OPA confidence threshold 0.97 unconditional; vLLM reasoning model (`DeepSeek-R1-Distill-Llama-8B`) deployed; `outlines` library removed (CVE-2025-69872). See [`docs/V2_ROADMAP.md`](../project/V2_ROADMAP.md) for the full v0.1.0 delivery summary.

This document describes the **Cybernetic Governance** framework that transforms the Financial Advisor agent from a probabilistic LLM application into a deterministic, engineering-controlled system. For the full architectural detail, see [`ARCHITECTURE.md`](ARCHITECTURE.md).

## 1. Theoretical Framework: Hybrid Reasoning Architecture & STPA

We utilize a **Hybrid Reasoning Architecture** to solve the "Recursive Paradox" of agent safety (High Variety vs. Low Safety). This architecture combines **deterministic workflow control** (LangGraph) with **LLM-powered reasoning** (native LangChain Runnables).

We also employ **Systems-Theoretic Process Analysis (STPA)** to identify and mitigate Unsafe Control Actions (UCAs). See [`docs/STPA_ANALYSIS.md`](../security/STPA_ANALYSIS.md) for the detailed hazard analysis.

- **Variety Attenuation:** Ashby's Law ($V_R \ge V_A$) is used to constrain the agent's infinite action space ($V_A$) into a manageable set of states verified by the governance stack ($V_R$).
- **Explicit Routing (LangGraph):** Unlike standard "tool-use" agents that probabilistically choose tools, the **Supervisor Agent** (implemented in **LangGraph**) uses a deterministic `StateGraph` to transition between states. This forms the "hard logic" cage around the probabilistic "soft logic" of the LLM.

### 2. The Dynamic Risk-Adaptive Stack

The architecture enforces "Defense in Depth" through a **7-step `SymbolicGovernor` pipeline** (`_run_checks()`) backed by supporting infrastructure layers and the broader **15 security & governance control points** wrapping the entire system.

> **See also:** [`docs/NEURO_SYMBOLIC_GOVERNANCE.md`](NEURO_SYMBOLIC_GOVERNANCE.md) for the full neuro-symbolic architecture detail.

#### Pre-Pipeline: NeMo Guardrails (Layer 0)

**Goal:** Input/Output safety, topical control, and **PII filtering**.

NeMo Guardrails runs **before** `_run_checks()` is invoked. It is integrated into the gateway process (not a standalone sidecar service). The `nemo-service` pod in the `governance-stack` namespace hosts the standalone Colang runtime for external callers, but the production inference path uses the in-process singleton in `src/gateway/governance/nemo/manager.py`. NeMo delegates all LLM inference to the vLLM endpoint via the `vllm_llama` engine in `config/rails/config.yml`.

- **PII Filtering:** **Microsoft Presidio** (15 entity types) detects and masks PII in both user input and agent output. Spacy `en_core_web_sm` provides entity recognition.
- **Implementation:** `src/gateway/governance/nemo/manager.py` & `config/rails/`
- **Context Injection:** NeMo actions receive pre-computed STPA and CBF results via context injection (injected by `pre_check()` before the guardrail fires). This eliminates the re-entrant loop where NeMo actions previously called back into `SymbolicGovernor` sub-components, causing each check to run twice per request.
- **Observability (ISO 42001):** A custom `NeMoOTelCallback` intercepts every guardrail intervention and emits an OpenTelemetry span with `langfuse.trace.metadata.guardrail.outcome` and `langfuse.trace.metadata.iso.control_id="A.6.2.8"`.

#### The 7-Step Governance Pipeline (`SymbolicGovernor._run_checks()`)

The `SymbolicGovernor` in `src/gateway/governance/symbolic_governor.py` is the central enforcement engine. Every tool execution request passes through the following steps in order:

| Step | Name | Implementation | Notes |
|------|------|---------------|-------|
| **0** | STPA UCA Constraint Check | `stpa_validator.validate()` | Aho-Corasick keyword scan feeds this; checks for Unsafe Control Actions defined in the ontology |
| **1** | Agentic Confidence Gate | OPA `system_authz.rego` | **OPA is the sole enforcer** of the confidence threshold (0.95 normal; 0.97 for EU_ECB region). The Python-side confidence check has been removed. SLM sidecar is permanently deprecated (`slm_available=false`). |
| **2** | Control Barrier Function | `ControlBarrierFunction.verify_action()` (`cbf.py`) | Redis-backed cash balance invariant `h(x) = cash_balance − min_cash_balance ≥ 0` |
| **2b** | OPA Policy Evaluation | `OPAClient.evaluate_policy()` | Runs **concurrently** with CBF via `asyncio.gather` — combined latency is `max(CBF_ms, OPA_ms)` |
| **3** | Fiscal Limit Pre-Reservation | `FiscalLimitGuard.reserve()` | Atomically reserves the requested USD amount against the daily cap in Redis (WATCH/MULTI/EXEC) **before** the consensus gate, closing the TOCTOU race between the CBF balance check and actual trade execution. Released on any subsequent failure. |
| **4** | Multi-Agent Consensus | `consensus_engine.check_consensus()` | For trades exceeding $10,000: two concurrent LLM critics ("Risk Manager" and "Compliance Officer") must reach unanimity. Any dissent blocks the trade. |
| **5** | DoWhy Causal Gatekeeper | `causal_safety_check()` | Constructs a `CausalModel` (market_volatility → trade_amount → risk_score), estimates causal effect via backdoor linear regression, then applies a **Placebo Treatment Refuter** (50 simulations, p < 0.05). Fail-safe: blocks on any exception. |
| **6** | FRIA Normative Boundary + Attestation | `enforce_fria_boundary()` + OTel stamp | **Merged step:** adaptive FRIA enforcement (ALLOW/DEFER/DENY based on consensus score) combined with EU AI Act Art. 29a OTel attestation. Runs only when `CAGE_NORMATIVE_PROVIDER != "static"` for enforcement; attestation stamp always applied for EU_ECB deployments. |

**Routing Seal timing:** The KMS-backed routing seal (`generate_seal()`) is issued **only after all 7 pipeline steps complete successfully**. Previously `validate_action()` issued the seal after only CBF + OPA (Steps 2/2b), implying full governance approval that was never actually granted. That gap is now closed.

**HITL (Human-in-the-Loop):** Handled by `defer_queue.py`, triggered by pipeline decisions (e.g., `MANUAL_REVIEW` from OPA or confidence starvation). LangGraph's `interrupt_before=["governed_trader"]` enforces a physical pause before every trade execution; the full pipeline is re-run after human approval via `post_hitl_revalidate`.

#### Supporting Infrastructure (Not Pipeline Steps)

The following components are essential infrastructure but are **not** numbered governance pipeline steps:

| Component | Role | Notes |
|-----------|------|-------|
| **Redis Session Persistence** | Stateful sessions on stateless compute | `AsyncRedisSaver` checkpoints graph state after each node transition; `MemorySaver` fallback emits OTel alert. Implementation: `src/governed_financial_advisor/graph/checkpointer.py` |
| **Pydantic Schema Validation** | Structural integrity at the request boundary | Strict Pydantic v2 models validate every tool call before it reaches the pipeline. UUID v4, ticker regex `^[A-Z]{1,5}$`, and `trader_role` enforced here. Implementation: `src/governed_financial_advisor/tools/trades.py` |
| **KMS Routing Seal** | Cryptographic authorization between agent nodes | Issued after full pipeline approval (see above). GCP KMS asymmetric signing (primary); HMAC-SHA256 fallback for dev/CI only. Implementation: `src/gateway/governance/kms_signer.py` |

**OPA RBAC thresholds** (enforced in Step 2b):

| Role     | ALLOW up to | MANUAL_REVIEW         | DENY         |
| -------- | ----------- | --------------------- | ------------ |
| `junior` | $5,000      | $5,001 – $10,000      | > $10,000    |
| `senior` | $500,000    | $500,001 – $1,000,000 | > $1,000,000 |

- **Canonical policy:** `src/governed_financial_advisor/governance/policy/trade_governance.rego` (package `trade.governance`).
- **System authorization:** `deployment/system_authz.rego` — enforces SR 26-2 §IV.B `confidence_sufficient ≥ 0.95` for agentic trade execution (OPA is sole enforcer; Python check removed).
- **Infrastructure:** OPA runs as a standalone service in the `default` namespace (see [`deployment/k8s/NAMESPACE-GUIDE.md`](deployment/k8s/NAMESPACE-GUIDE.md)); the gateway calls it via the `OPAClient` with a `CircuitBreaker` (5 failures → 30s open-circuit; DENY-on-open).

---

## Symbolic Governor Pipeline

> **Source:** [`src/gateway/governance/symbolic_governor.py`](../../src/gateway/governance/symbolic_governor.py)

The `SymbolicGovernor._run_checks()` method implements a strict **7-tier sequential pipeline**. Every tool execution request must pass all applicable tiers before a routing seal is issued. The tiers below use 1-based numbering aligned to the source implementation; the existing Step 0–6 table in §2 uses 0-based numbering for historical reasons — both refer to the same pipeline.

### 7-Tier Pipeline

| Tier | Name | Key Invariant / Action | Source Module |
|------|------|------------------------|---------------|
| **1** | NoDirectBind invariant check | No LLM output may bind directly to an executable action without passing the full governance pipeline | `symbolic_governor.py` |
| **2** | PII sanitization | Microsoft Presidio (15 entity types) masks PII in request payload before any downstream evaluation | `nemo/manager.py`, `privacy.py` |
| **3** | CBF + OPA concurrent evaluation | `asyncio.gather(cbf_check, opa_check)` — combined latency = `max(CBF_ms, OPA_ms)` | `cbf.py`, OPA `system_authz.rego` |
| **4** | Causal gatekeeper | DoWhy `CausalModel` + Placebo Treatment Refuter (50 sims, p < 0.05, \|eff\| > 0.2) | `causal_gatekeeper.py` |
| **5** | Confabulation scoring | `risk_score = 1.0 − confidence`; score ≥ 0.95 → BLOCK | `confabulation_scorer.py` |
| **6** | Consensus (high-value trades) | Boolean unanimity via `asyncio.gather`; threshold $10,000 USD; 30 s timeout | `consensus.py` |
| **7** | FRIA zone classification | Fundamental Rights Impact Assessment — score-based zone assignment (ALLOW / DEFER / BLOCK) | `symbolic_governor.py` |

### NoDirectBind Invariant

The **NoDirectBind invariant** is the foundational safety property of the pipeline:

> *No output produced by an LLM may be bound directly to an executable action (trade, API call, state mutation) without first passing through the full `SymbolicGovernor._run_checks()` pipeline.*

This invariant is enforced structurally: the `@governed_tool` decorator intercepts every tool call at the gateway boundary and invokes `_run_checks()` before any execution occurs. A routing seal (`X-CAGE-Routing-Seal`) is issued **only** after all 7 tiers complete successfully.

### Tier 3 — Concurrent CBF + OPA Evaluation

Tier 3 runs the Control Barrier Function check and the OPA policy evaluation **concurrently** using `asyncio.gather`:

```python
cbf_result, opa_result = await asyncio.gather(cbf_check(), opa_check())
```

Both checks must pass. The combined latency is `max(CBF_ms, OPA_ms)` rather than the sum, reducing p99 pipeline latency.

### FRIA Zone Decision Semantics (Tier 7)

The Fundamental Rights Impact Assessment (FRIA) at Tier 7 classifies each request into one of three zones based on a composite governance score:

| Zone | Score Condition | Decision | Mechanism |
|------|----------------|----------|-----------|
| **ALLOW** | score ≥ `FRIA_ZONE_ALLOW` (0.95) | Proceed; async attestation emitted | OTel span stamped with EU AI Act Art. 29a attestation |
| **DEFER** | 0.70 ≤ score < 0.95 (`FRIA_ZONE_DEFER`) | Synchronous blocking gate | Request held; pushed to DEFER queue (Redis db=1, 4 h TTL) for human review |
| **BLOCK** | score < 0.70 | Hard deny | Request rejected; violation logged with `[CTRL_FRIA_006]` prefix |

Constants: `FRIA_ZONE_ALLOW = 0.95`, `FRIA_ZONE_DEFER = 0.70` (defined in [`src/gateway/governance/symbolic_governor.py`](../../src/gateway/governance/symbolic_governor.py)).

---

## Mathematical Governance Invariants

The following formal conditions are evaluated at runtime. A violation of any invariant causes the pipeline to halt and the request to be denied.

### Control Barrier Function (CBF) — Tier 3

**Barrier function:** `h(x) = cash_balance − min_cash_balance`

**Discrete-time CBF condition** (must hold at every time step):

```
h(S(t+1)) ≥ (1−γ) · h(S(t))
```

where γ ∈ (0, 1] is the decay parameter (default γ = 0.5). If `h(S(t)) ≥ 0` and the condition holds for all t, then `h(S(t)) ≥ 0` for all t ≥ 0 — the cash balance never falls below `min_cash_balance`.

> **Source:** [`src/gateway/governance/cbf.py`](../../src/gateway/governance/cbf.py)

### Confabulation Risk Score — Tier 5

```
risk_score = 1.0 − confidence
```

**Decision rule:** if `risk_score ≥ 0.95` (equivalently, `confidence ≤ 0.05`) → **BLOCK**. The threshold guards against LLM outputs with near-zero grounding confidence being passed to execution.

> **Source:** [`src/gateway/governance/confabulation_scorer.py`](../../src/gateway/governance/confabulation_scorer.py)

### Causal Marginal Risk Boundary — Tier 4

The causal gatekeeper blocks a trade when the estimated marginal effect of `trade_amount` on `risk_score` pushes the predicted risk above the safety boundary:

```
(0.5 + estimate.value × amount) > 0.95  →  LOCK (trade blocked)
```

Additionally, the Placebo Treatment Refuter (50 simulations) must confirm the world-model is trustworthy: if the placebo still detects a significant effect (p < 0.05 **or** |effect| > 0.2), the model is deemed unreliable and the trade is blocked.

> **Source:** [`src/gateway/governance/causal_gatekeeper.py`](../../src/gateway/governance/causal_gatekeeper.py)

### FRIA Zone Boundaries — Tier 7

```
score ≥ 0.95              →  ALLOW  (async attestation)
0.70 ≤ score < 0.95       →  DEFER  (synchronous blocking gate)
score < 0.70              →  BLOCK  (hard deny)
```

> **Source:** [`src/gateway/governance/symbolic_governor.py`](../../src/gateway/governance/symbolic_governor.py)

---

## STPA Unsafe Control Actions

> **Source:** [`src/gateway/governance/ontology.py`](../../src/gateway/governance/ontology.py)

The STPA (Systems-Theoretic Process Analysis) ontology defines Unsafe Control Actions (UCAs) as formal inequalities. The `GeneratedSTPAValidator` evaluates these constraints on every request; any violation halts the pipeline at Tier 1 (Step 0 in the 0-based table).

### Financial UCAs (FIN-*)

| UCA ID | Inequality Condition | Hazard Description |
|--------|---------------------|--------------------|
| **FIN-1** | `trade_value > position_limit` | Trade value exceeds the authorised position limit — unsafe control action |
| **FIN-2** | `portfolio_concentration > 0.25` | Single-asset concentration exceeds 25% of portfolio — unsafe control action |

### General UCAs (UCA-*)

| UCA ID | Inequality Condition | Hazard Description |
|--------|---------------------|--------------------|
| **UCA-2** | `risk_score > 0.8` (missing action) | Required risk-mitigation action is absent when risk score exceeds 0.8 |
| **UCA-5** | `order_size > 0.1 × daily_volume` | Order size exceeds 10% of daily volume — market-impact unsafe action |
| **UCA-6** | `order_size > fraction × daily_vol` | Order size exceeds the permitted fraction of daily volume — STPA Violation |
| **UCA-7** | `market_volatility > threshold` | Action taken during excessive market volatility — timing unsafe control action |

### Regional Control Maps

The ontology defines three regional control maps activated by `CAGE_DEPLOYMENT_REGION`:

| Region | Activated By | Additive Obligations |
|--------|-------------|----------------------|
| **US_FED** | `CAGE_DEPLOYMENT_REGION=US_FED` | NIST SP 800-53, SR 26-2 §IV, NIST AI RMF |
| **EU_ECB** | `CAGE_DEPLOYMENT_REGION=EU_ECB` | EU AI Act Art. 29a, GDPR Art. 22, DORA Art. 12 |
| **APAC_MAS** | `CAGE_DEPLOYMENT_REGION=APAC_MAS` | MAS FEAT Principles, MAS Notice 655, MAS TRM §4.2 |

All UCAs above are evaluated in **all regions** as part of the ISO 42001 universal baseline. Regional control maps add jurisdiction-specific thresholds and reporting obligations on top of the universal UCA set.

---

## Decoupled Governance Abstraction (Option 3 & Multi-Region Productization)

All hardcoded regulatory citation strings (`SR 26-2 §IV.B`, `ISO 42001 §A.5.2`, etc.) have been removed from Python business logic. The system now uses a multi-region two-layer abstraction layer that dynamically adapts depending on the `CAGE_DEPLOYMENT_REGION` environment variable (`US_FED`, `EU_ECB`, `APAC_MAS`):

| Layer | Location | Purpose |
|---|---|---|
| **Stable Control IDs** | `src/gateway/governance/constants.py` — `GovernanceControl` enum | Internal IDs (`CTRL_AGT_001`…) that never change regardless of which frameworks or regions are active |
| **Regulatory Registry** | `config/compliance/{REGION}_BASELINE.json` *(fallback to `control_mappings.json`)* | Single source of truth mapping `CTRL_*` IDs to external frameworks in a region-specific baseline profile — no Python changes required |
| **OSCAL Framework Router** | `config/oscal/framework_mappings/*.json` — loaded by `FrameworkRouter` in `oscal_ssp_exporter.py` | UCA-to-control cross-walk tables for NIST SP 800-53, ISO 42001, EU AI Act, and MAS FEAT — adding a new jurisdiction is a JSON-only operation |

### GovernanceControl → Framework Mapping

| Control ID | Internal ID | Primary Framework | Scope | Governing Module / Active Regions |
|---|---|---|---|---|
| `CTRL_AGT_001` | THR-CONF-001 | ISO 42001 §A.5.2 | Agentic | `symbolic_governor.py` — confidence check *(All Regions)* |
| `CTRL_WAL_002` | THR-WAL-002 | ISO 42001 §A.8.4 | Agentic | `generated_saga_nodes.py` — WAL SAGA *(All Regions)* · DORA Art. 12 addendum *(EU_ECB only)* |
| `CTRL_TEL_003` | THR-TEL-003 | ISO 42001 §A.9.4 | Agentic | `telemetry_provider.py`, `causal_gatekeeper.py` *(All Regions)* · telemetry suppressed in EU_ECB per SR 26-2 "no legal force" sentinel |
| `CTRL_MRM_004` | THR-MRM-004 | SR 26-2 §IV — Model Risk Management | Traditional ML | `safety.py` (CBF), `causal_gatekeeper.py` — **US_FED only**; ISO 42001 §A.9.4 is the universal equivalent |
| `CTRL_OPA_005` | THR-OPA-005 | ISO 42001 §A.6.1 | Agentic | `symbolic_governor.py` — OPA policy check *(All Regions)* |
| `CTRL_FRIA_006` | THR-FRIA-006 | EU AI Act Art. 29a | Agentic | `symbolic_governor.py` — Step 6 FRIA normative boundary + attestation — **EU_ECB only** |
| `CTRL_CTX_007` | THR-CTX-007 | CSA AARM-V1 / ISO 42001 §A.5.3 | AARM Primitive | `src/compliance_bridge/context_accumulator.py` *(All Regions)* |
| `CTRL_DFR_008` | THR-DFR-008 | CSA AARM-V7 / ISO 42001 §A.8.4 | AARM Primitive | `src/gateway/governance/defer_queue.py` — DEFER State Machine *(All Regions)* |
| `CTRL_AARM_009` | THR-AARM-009 | CSA AARM v1.0 | AARM Primitive | `src/compliance_bridge/aarm_mapper.py` — Threat Ledger *(All Regions)* |

Legacy citations (e.g. `SR 26-2 §IV.B`) are preserved as `legacy_citation` fields inside baseline profiles so SIEM consumers retain backward-compatible alert matching.

### ControlRegistry API & Multi-Region Execution

The `ControlRegistry` is a thread-safe, lock-guaranteed singleton that loads regulatory definitions dynamically at startup:

1. **Activation Pattern:**
   ```bash
   export CAGE_DEPLOYMENT_REGION=EU_ECB  # Options: US_FED (default), EU_ECB, APAC_MAS
   ```
2. **Properties and Methods:**
   - `registry.active_region`: Returns the active region identifier string (`"US_FED"`, `"EU_ECB"`, `"APAC_MAS"`, or `"LEGACY"`).
   - `registry.get_mapping_safe(control)`: Attempts to resolve a control ID. Unlike `get_mapping()`, this returns `None` instead of throwing `KeyError` if a control is absent from the active region's baseline, enabling graceful handling of region-specific controls like `CTRL_FRIA_006`.
   - `ControlRegistry.reconfigure(region)`: Triggers runtime reloading of the baseline profile for operational testing and hot reconfiguration.

---

## SR 26-2 Compliance — US_FED Only (`CAGE_DEPLOYMENT_REGION=US_FED`)

> **Scope:** The Federal Reserve's SR 26-2 (April 17, 2026) applies **exclusively** to `CAGE_DEPLOYMENT_REGION=US_FED` deployments. EU_ECB and APAC_MAS deployments satisfy equivalent obligations via ISO 42001 and their respective jurisdiction-specific frameworks. No SR 26-2 obligation is imposed on non-US_FED deployments.

The Federal Reserve's SR 26-2 explicitly scopes generative and agentic AI systems *outside* SR 11-7's prescriptive framework, directing institutions to apply rigorous internal risk controls. CAGE addresses all four SR 26-2 examination dimensions:

| SR 26-2 Dimension | CAGE Implementation | Source File |
|---|---|---|
| **Agentic Bounding** | Confidence threshold — `CTRL_AGT_001` (ISO 42001 §A.5.2) | `symbolic_governor.py`, `control_mappings.json` |
| **Non-Determinism Containment** | WAL + LIFO rollback SAGA — `CTRL_WAL_002` (ISO 42001 §A.8.4) | `generated_saga_nodes.py` |
| **World-Model Validation** | DoWhy `CausalGatekeeper` Phase 2 — `CTRL_TEL_003` (ISO 42001 §A.9.4) on live Langfuse telemetry | `causal_gatekeeper.py`, `telemetry_provider.py` |
| **Traditional MRM (non-agentic)** | CBF formula + DoWhy coefficient validation — `CTRL_MRM_004` (SR 26-2 §IV, US_FED only) | `safety.py`, `causal_gatekeeper.py` (Phase 1) |

### Agent Scope Declaration (`config/agent_scope.yaml`)

SR 26-2 requires a formal, machine-readable declaration of permitted agent boundaries. `config/agent_scope.yaml` is that declaration:

- Parsed by OPA as `data.agent_scope` — allowed MCP tools, fiscal limits, and prohibited actions become enforceable policy
- Referenced by OSCAL SSP as the authoritative scope boundary artifact
- Validated by Lula 6h CronJob against `lula-validation-*.yaml` targets
- All scope changes are source-controlled at this YAML level and propagate deterministically to all generated artifacts

### Four Governance Gap Closures

These were the four original SR 26-2 examination gaps; all are now closed and decoupled from hardcoded regulatory strings via the `GovernanceControl` registry:

| Gap | Closure | Files |
|---|---|---|
| Gap 1 (Live Telemetry) | `LangfuseTelemetryProvider` + `CTRL_TEL_003` OTel spans | `telemetry_provider.py`, `causal_gatekeeper.py` |
| Gap 2 (WAL Atomicity) | MCP tool WAL nodes + `CTRL_WAL_002` annotations | `generated_saga_nodes.py` (re-compiled from `stpa_compiler.py`) |
| Gap 3 (Terminology) | All audit logs now lead with `[CTRL_*]` IDs; `legacy_citation` in regional profile for SIEM back-compat | `symbolic_governor.py`, `safety.py`, `config/compliance/*_BASELINE.json` |
| Gap 4 (Scope) | `config/agent_scope.yaml` retains authoritative SR 26-2 scope block; `CTRL_*` IDs added as stable aliases | `agent_scope.yaml` |

## 3. Tiered Observability: The Cost of Transparency

The architecture implements a **Risk-Based Tiered Strategy** balancing operational visibility against cost.

| Tier     | Destination              | Content                  | Sampling Logic                | Purpose                       |
| -------- | ------------------------ | ------------------------ | ----------------------------- | ----------------------------- |
| **Hot**  | OpenTelemetry → Langfuse | Governance spans (100%)  | 100% for governance decisions | Audit evidence, compliance    |
| **Hot**  | OpenTelemetry → Langfuse | General inference spans  | 1% sampling (RA-001)          | Operational health            |
| **Cold** | GCS artifact bucket      | OSCAL Assessment Results | Per Lula 6h CronJob run       | Regulatory compliance records |

**Dual Langfuse projects:**

- **Application project** — inference latency, token counts, model quality metrics
- **Compliance project** — governance verdicts, OPA results, ISO 42001 control evidence

## 4. Implementation Details

### The Deterministic Router (LangGraph)

The canonical agent graph is assembled by `create_graph(redis_url)` in `src/governed_financial_advisor/graph/graph.py`. The graph compiles with:

- **10 nodes:** `nemo_guardrail → thinker_node → doer_node → data_analyst / execution_analyst → evaluator → safety_check → governed_trader → explainer → nemo_output_rail`
- **`interrupt_before=["governed_trader"]`** — mandatory HITL pause before any trade execution
- **`AsyncRedisSaver`** — durable checkpoint persistence; `MemorySaver` fallback emits ERROR log + OTel alert span

All agent transitions are explicitly managed by routing functions (`route_supervisor`, `check_safety_signature`, `route_after_safety`). Agents return structured state fields; the graph decides the next node deterministically based on those fields.

### Governance Decorator

The `@governed_tool` decorator (gateway-side) intercepts all tool executions:

1. Validates Pydantic schema (infrastructure boundary — not a pipeline step).
2. Checks HMAC `X-CAGE-Routing-Seal` header (issued only after full pipeline approval).
3. Invokes the full `SymbolicGovernor._run_checks()` pipeline: STPA (Step 0) → Confidence/OPA (Steps 1/2b) → CBF (Step 2) → Fiscal Limit Pre-Reservation (Step 3) → Consensus (Step 4) → Causal Gatekeeper (Step 5) → FRIA (Step 6).
4. Wraps execution in ISO 42001-stamped OpenTelemetry spans.

## 5. Local Development

### Prerequisites

- [Open Policy Agent (OPA)](https://www.openpolicyagent.org/docs/latest/#running-opa) installed
- Python ≥ 3.11; `uv` or `pip`

### Running the Stack

1. **Start OPA Server:**
   ```bash
   opa run -s deployment/system_authz.rego --addr :8181
   ```
2. **Install dependencies:**
   ```bash
   uv sync --all-groups --all-extras
   ```
3. **Run Tests:**
   ```bash
   pytest tests/ -v --timeout=60
   ```

## 6. Deployment (Sovereign vLLM on GKE)

The architecture is designed for **Google Kubernetes Engine (GKE)** using the **Sovereign vLLM** pattern — all LLM inference runs within the cluster boundary; no requests are sent to external LLM APIs.

- **Infrastructure:** GKE Standard Cluster with NVIDIA L4 GPU Spot node pools.
- **Reasoning Node:** vLLM serving `DeepSeek-R1-Distill-Llama-8B` (AWQ 4-bit, 32K context, `gpu_memory_utilization=0.9`).
- **Fast Node:** vLLM serving `Meta-Llama-3.1-8B-Instruct` (standard precision, Spot instances).
- **Governance:** OPA in `default` namespace; NeMo Guardrails in `governance-stack` namespace; both accessed over intra-cluster DNS.
- **Communication:** Intra-cluster HTTP/REST and gRPC.

For detailed deployment instructions, see **[deployment/README.md](deployment/README.md)** and the [Technical Report — Deployment & Infrastructure](docs/technical-report/08-DEPLOYMENT-INFRASTRUCTURE.md).
