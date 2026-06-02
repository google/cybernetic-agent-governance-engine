# Cybernetic Governance of Agentic AI

This document describes the **Cybernetic Governance** framework that transforms the Financial Advisor agent from a probabilistic LLM application into a deterministic, engineering-controlled system. For the full architectural detail, see [`ARCHITECTURE.md`](ARCHITECTURE.md).

## 1. Theoretical Framework: Hybrid Reasoning Architecture & STPA

We utilize a **Hybrid Reasoning Architecture** to solve the "Recursive Paradox" of agent safety (High Variety vs. Low Safety). This architecture combines **deterministic workflow control** (LangGraph) with **LLM-powered reasoning** (native LangChain Runnables).

We also employ **Systems-Theoretic Process Analysis (STPA)** to identify and mitigate Unsafe Control Actions (UCAs). See [`docs/STPA_ANALYSIS.md`](docs/STPA_ANALYSIS.md) for the detailed hazard analysis.

- **Variety Attenuation:** Ashby's Law ($V_R \ge V_A$) is used to constrain the agent's infinite action space ($V_A$) into a manageable set of states verified by the governance stack ($V_R$).
- **Explicit Routing (LangGraph):** Unlike standard "tool-use" agents that probabilistically choose tools, the **Supervisor Agent** (implemented in **LangGraph**) uses a deterministic `StateGraph` to transition between states. This forms the "hard logic" cage around the probabilistic "soft logic" of the LLM.

### 2. The Dynamic Risk-Adaptive Stack

The architecture enforces "Defense in Depth" through eight distinct runtime layers (0–7) in the StateGraph harness. These work in tandem with the **7-tier Symbolic Governor code pipeline (Tiers 0–6) + Step 8 FRIA** and the broader **15 security & governance control points** wrapping the entire system:

### Layer 0: Conversational Guardrails (NeMo)

**Goal:** Input/Output safety, topical control, and **PII filtering**.

NeMo Guardrails is deployed as a **standalone pod** (`nemo-service`) in the `governance-stack` Kubernetes namespace. It is **not** an in-process sidecar. NeMo delegates all LLM inference to the vLLM endpoint via the `vllm_llama` engine in `config/rails/config.yml`.

- **PII Filtering:** **Microsoft Presidio** (20 entity types) detects and masks PII in both user input and agent output. Spacy `en_core_web_sm` provides entity recognition.
- **Implementation:** `src/gateway/governance/nemo/manager.py` & `config/rails/`
- **Observability (ISO 42001):** A custom `NeMoOTelCallback` intercepts every guardrail intervention and emits an OpenTelemetry span with `langfuse.trace.metadata.guardrail.outcome` and `langfuse.trace.metadata.iso.control_id="A.6.2.8"`.

### Layer 1: Session Persistence (Redis)

**Goal:** Stateful sessions on stateless compute.

The Agentic Gateway runs on GKE behind a global load balancer. Session state is checkpointed to Redis after each graph node transition via LangGraph's `AsyncRedisSaver`.

- **Implementation:** `src/governed_financial_advisor/graph/checkpointer.py` — `AsyncRedisSaver` (primary); `MemorySaver` (fallback with OTel alert).
- **Safety:** Graph state survives pod restarts. HITL pending approval threads persist across server restarts.

### Layer 2: The Syntax Trapdoor (Schema)

**Goal:** Structural integrity.

Strict **Pydantic v2** models validate every tool call _before_ it reaches the policy engine.

- **Implementation:** `src/governed_financial_advisor/tools/trades.py`
- **Features:**
  - **UUID Validation:** `transaction_id` must be a valid UUID v4.
  - **Regex Validation:** Ticker symbols must match `^[A-Z]{1,5}$`.
  - **Role Context:** `trader_role` (junior/senior) is enforced in the schema and downstream OPA policy.

### Layer 3: The Policy Engine (RBAC & OPA)

**Goal:** Authorization and business logic enforcement.

**Open Policy Agent (OPA)** and **Rego** decouple policy from code. The system implements a **Tri-State Decision**:

1.  **ALLOW** — Action proceeds to the next layer.
2.  **DENY** — Action is hard-blocked immediately.
3.  **MANUAL_REVIEW** — Action is suspended pending human intervention.

**Role-Based Access Control (RBAC):**

| Role     | ALLOW up to | MANUAL_REVIEW         | DENY         |
| -------- | ----------- | --------------------- | ------------ |
| `junior` | $5,000      | $5,001 – $10,000      | > $10,000    |
| `senior` | $500,000    | $500,001 – $1,000,000 | > $1,000,000 |

- **Canonical policy:** `src/governed_financial_advisor/governance/policy/trade_governance.rego` (package `trade.governance`).
- **System authorization:** `deployment/system_authz.rego` — enforces SR 26-2 §IV.B `confidence_sufficient ≥ 0.95` for agentic trade execution.
- **Infrastructure:** OPA runs as a standalone service in the `default` namespace (see [`deployment/k8s/NAMESPACE-GUIDE.md`](deployment/k8s/NAMESPACE-GUIDE.md)); the gateway calls it via the `OPAClient` with a `CircuitBreaker` (5 failures → 30s open-circuit; DENY-on-open).

**State Management (CBF):**

The `ControlBarrierFunction` in `src/gateway/governance/safety.py` enforces the cash balance invariant `h(x) = cash_balance − min_cash_balance ≥ 0` using Redis `WATCH`/`MULTI`/`EXEC` atomic transactions.

### Layer 4: The Signed Handshake (Integrity)

**Goal:** Cryptographic authorization between agent nodes.

A **Signed Handshake** pattern gates the transition from evaluator to executor:

1.  **Evaluator Agent:** Verifies the proposal against OPA and NeMo. If safe, it signs the plan using an HMAC-SHA256 `governance_signature` over `execution_plan_output`.
2.  **State Gating:** The LangGraph `StateGraph` uses a conditional edge (`check_safety_signature`) that routes to `explainer` if the signature is missing or invalid — trade never executes.
3.  **Executor Agent:** Validates `governance_signature` independently before issuing any trade instruction.

- **Implementation:** `src/governed_financial_advisor/graph/nodes/evaluator_node.py`

### Layer 5: The Consensus Engine (Adaptive Compute)

**Goal:** High-stakes semantic validation.

For trades exceeding **$10,000**, the `ConsensusEngine` triggers a multi-agent debate:

- **Mechanism:** Two concurrent LLM critics ("Risk Manager" and "Compliance Officer" personas) independently evaluate the trade via `asyncio.gather`. **Unanimity required** — any dissent blocks the trade.
- **Below threshold:** Single-agent judgment is accepted (documented risk acceptance RA-002).
- **Implementation:** `src/gateway/governance/consensus.py`

### Layer 6: Human-in-the-Loop (Constructive Friction)

**Goal:** Final mandatory human oversight before trade execution.

LangGraph's `interrupt_before=["governed_trader"]` enforces a physical pause before every trade:

- **Mechanism:** The graph halts at `governed_trader`, persists full `AgentState` to Redis via `AsyncRedisSaver`.
- **Resume:** A human operator calls `POST /v1/approvals/{thread_id}/resume` with an `APPROVED` or `REJECTED` decision, which reloads the checkpoint and resumes the graph.
- **Concept:** Policy-as-Code with a Human Safety Switch — no trade executes without a human decision record.

### Layer 7: The Causal Gatekeeper (DoWhy)

**Goal:** World-model integrity validation via causal inference.

The **DoWhy Causal Gatekeeper** (`src/gateway/governance/causal_gatekeeper.py`) acts as the "Lock on the CAGE" — a final causal inference check that validates whether the system's understanding of market dynamics is trustworthy enough to execute a trade.

- **Mechanism:** Constructs a `CausalModel` (market_volatility → trade_amount → risk_score), estimates the causal effect via backdoor linear regression, then applies a **Placebo Treatment Refuter**. If replacing the real treatment with random noise still produces a significant effect (p < 0.05 or |effect| > 0.2), the world-model is deemed untrustworthy and the trade is blocked.
- **Fail-Safe:** Returns `False` (blocks) on any exception — if causal validity cannot be proven, the action is denied.
- **Integration:** Injected as Step 6 in `SymbolicGovernor._run_checks()`, runs only for `execute_trade` actions.
- **Telemetry Provider ([CTRL_TEL_003]):** `LangfuseTelemetryProvider` (`src/gateway/governance/telemetry_provider.py`) fetches live governance spans from Langfuse — replacing `generate_mock_telemetry()`. Falls back to `MockTelemetryProvider` when `< CAUSAL_MIN_LIVE_SAMPLES` (default: 50) live records exist, emitting an audit-visible WARNING.
  DoWhy now emits **dual OTel spans**: `causal_gatekeeper.statistical_kernel` (tagged `CTRL_MRM_004` / SR 26-2 MRM) for the regression coefficient phase, and `causal_gatekeeper.placebo_refutation` (tagged `CTRL_TEL_003` / ISO 42001 §A.9.4) for the live simulation phase.

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
| `CTRL_WAL_002` | THR-WAL-002 | ISO 42001 §A.8.4 / DORA Art. 12 | Agentic | `generated_saga_nodes.py` — WAL SAGA *(All Regions)* |
| `CTRL_TEL_003` | THR-TEL-003 | ISO 42001 §A.9.4 | Agentic | `telemetry_provider.py`, `causal_gatekeeper.py` *(All Regions)* |
| `CTRL_MRM_004` | THR-MRM-004 | SR 26-2 §IV — Model Risk Management | Traditional ML | `safety.py` (CBF), `causal_gatekeeper.py` *(All Regions, telemetry suppressed in EU_ECB)* |
| `CTRL_OPA_005` | THR-OPA-005 | ISO 42001 §A.6.1 | Agentic | `symbolic_governor.py` — OPA policy check *(All Regions)* |
| `CTRL_FRIA_006` | THR-FRIA-006 | EU AI Act Art. 29a | Agentic | `symbolic_governor.py` — Step 7 FRIA attestation *(EU_ECB only)* |
| `CTRL_CTX_007` | THR-CTX-007 | CSA AARM-V1 / ISO 42001 §A.5.3 | AARM Primitive | `src/compliance_bridge/context_accumulator.py` *(All Regions)* |
| `CTRL_DFR_008` | THR-DFR-008 | CSA AARM-V7 / ISO 42001 §A.8.4 | AARM Primitive | `src/gateway/governance/defer_queue.py` — DEFER State Machine *(All Regions)* |
| `CTRL_AARM_009` | THR-AARM-009 | CSA AARM v1.0 | AARM Primitive | `src/compliance_bridge/aarm_mapper.py` — Threat Ledger *(All Regions)* |

Legacy citations (e.g. `SR 26-2 §IV.B`) are preserved as `legacy_citation` fields inside baseline profiles so SIEM consumers retain backward-compatible alert matching.ne profiles so SIEM consumers retain backward-compatible alert matching.

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

## SR 26-2 Compliance (April 2026)

The Federal Reserve's SR 26-2 explicitly scopes generative and agentic AI systems *outside* SR 11-7's prescriptive framework, directing institutions to apply rigorous internal risk controls. CAGE addresses all four SR 26-2 examination dimensions:

| SR 26-2 Dimension | CAGE Implementation | Source File |
|---|---|---|
| **Agentic Bounding** | Confidence threshold — `CTRL_AGT_001` (ISO 42001 §A.5.2) | `symbolic_governor.py`, `control_mappings.json` |
| **Non-Determinism Containment** | WAL + LIFO rollback SAGA — `CTRL_WAL_002` (ISO 42001 §A.8.4) | `generated_saga_nodes.py` |
| **World-Model Validation** | DoWhy `CausalGatekeeper` Phase 2 — `CTRL_TEL_003` (ISO 42001 §A.9.4) on live Langfuse telemetry | `causal_gatekeeper.py`, `telemetry_provider.py` |
| **Traditional MRM (non-agentic)** | CBF formula + DoWhy coefficient validation — `CTRL_MRM_004` (SR 26-2 §IV) | `safety.py`, `causal_gatekeeper.py` (Phase 1) |

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

- **8 nodes:** `thinker_node → doer_node → data_analyst / execution_analyst → evaluator → safety_check → governed_trader → explainer`
- **`interrupt_before=["governed_trader"]`** — mandatory HITL pause before any trade execution
- **`AsyncRedisSaver`** — durable checkpoint persistence; `MemorySaver` fallback emits ERROR log + OTel alert span

All agent transitions are explicitly managed by routing functions (`route_supervisor`, `check_safety_signature`, `route_after_safety`). Agents return structured state fields; the graph decides the next node deterministically based on those fields.

### Governance Decorator

The `@governed_tool` decorator (gateway-side) intercepts all tool executions:

1. Validates Pydantic schema.
2. Checks HMAC `X-CAGE-Routing-Seal` header.
3. Queries OPA via `OPAClient` (Tier 4 of the SymbolicGovernor).
4. Triggers `ConsensusEngine` if trade exceeds `consensus.threshold_usd = $10,000` (Tier 5).
5. Runs DoWhy Causal Gatekeeper refutation (Tier 7).
6. Wraps execution in ISO 42001-stamped OpenTelemetry spans.

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
