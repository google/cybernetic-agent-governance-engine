# CAGE Architecture — Cybernetic Governance Engine

> **Architecture:** 10-node governance graph with integrated safety checks, STPA-compiled policy enforcement, LangGraph Saga WAL pattern, Zero-Trust Network cluster hardening (Z3N), DoWhy causal inference validation, Redis-backed multi-agent FiscalLimitGuard, and exhaustively verified NoDirectBind safety invariant (v2.0.0-rc.2).


---

## System Overview

The Cybernetic Governance Engine (CAGE) is a Python-first backend platform that orchestrates a governed financial advisory workflow under ISO/IEC 42001, SR 26-2, FedRAMP HIGH, the EU AI Act, and MAS FEAT. Through its multi-region compliance profile system (activated via `CAGE_DEPLOYMENT_REGION`), CAGE dynamically adapts its active controls, compliance mappings, and numeric thresholds for US Fed (`US_FED`), EU ECB (`EU_ECB`), and APAC MAS (`APAC_MAS`) environments. The canonical reasoning path is a LangGraph multi-agent `StateGraph` (`src/governed_financial_advisor/graph/graph.py`) with **10 nodes** — including the mandatory, fail-closed `nemo_guardrail` input node, `nemo_output_rail` output node — nemo_guardrail → thinker_node → doer_node → data_analyst / execution_analyst → evaluator → **safety_check** → governed_trader → explainer → nemo_output_rail. Each LLM call and tool invocation traverses a 7-tier gateway governance pipeline (Aho-Corasick keyword scan → NeMo Guardrails → STPA validator → OPA policy engine → Control Barrier Function → consensus engine → DoWhy causal gatekeeper). The `safety_check_node` was added in Rev8 as an explicit OPA policy gate between the evaluator and the governed trader — BLOCKED/ESCALATED results route to the explainer without executing a trade. A parallel KFP v2 Cybernetic Governance Loop (`src/governed_financial_advisor/pipelines/green_stack_pipeline.py`) provides continuous governance evaluation by fetching compliance metrics from the compliance bridge, evaluating against ISO 42001 thresholds, and hot-reloading NeMo Guardrails configurations in-process via `POST /v1/nemo/apply-refinement` when thresholds are breached. The pipeline is programmatically submitted via `POST /v1/refinement/trigger` or automatically triggered reactively by a Langfuse webhook receiver (`POST /v1/webhooks/langfuse`) equipped with a 5-minute cooldown gate and a 10-sample minimum to prevent policy flapping during noisy bursts. A legacy namespace shim (`src/graph/graph.py`) exposes an optimistic-execution subgraph used only by the legacy test suite; it now emits a `DeprecationWarning` on import. The compliance bridge ingests Lula OSCAL audit findings into Langfuse and broadcasts real-time governance and remediation events via SSE (including dynamic patch advisories on the Kernel Dashboard). All in-flight approval state is checkpointed to Redis via LangGraph's `AsyncRedisSaver` — the fallback `MemorySaver` now emits an ERROR log and OTel attributes on activation. The system deploys on GKE with NVIDIA L4 Spot GPU nodes for two vLLM inference pools routed through a cloud-agnostic NGINX Inference Gateway.

---

## Component Map

```mermaid
graph TB
    subgraph Frontend
        UI[agentsight-ui\nReact/Vite/TypeScript]
    end

    subgraph governed-financial-advisor\nPython + LangGraph + FastAPI
        FA[server.py\nNeMo input/output guardrails]
        GRAPH[graph.py CANONICAL\n10 nodes + HITL interrupt]
        CHECKPT[checkpointer.py\nAsyncRedisSaver / MemorySaver]
        STATE[state.py\nAgentState TypedDict 25 fields]
        NODES[graph/nodes/\nagent_nodes, evaluator, explainer\nsupervisor, approval, safety]
        SUBS[graph/subgraphs/\ndata_analyst_graph\ngoverned_trader_graph]
        GOV[governance/\nclient, structs, policy_loader\ntranspiler, nemo_actions]
    end


    subgraph green-stack-pipeline\nKFP v2 Kubeflow Pipelines
        GSP[green_stack_pipeline.py\nGovernance evaluation loop]
        FC[fetch_compliance_metrics\nPOLL compliance-bridge]
        EG[evaluate_governance_metrics\nISO 42001 safety_rate threshold]
        TN[trigger_nemo_refinement\nPOST /v1/nemo/apply-refinement]
    end

    subgraph gateway\nPython + FastAPI + FastMCP
        GW[hybrid_server.py\nMCP server + OPA + NeMo proxy]
        AC[text_filter.py\nAho-Corasick Tier-1]
        NEMO[nemo/manager.py\nColang 2.x + Presidio PII]
        STPA[generated_stpa_validator.py\nGeneratedSTPAValidator\nUCA-1/2/5/6/8/9 checks]
        OPA_C[core/policy.py\nOPAClient circuit breaker]
        SYMGOV[symbolic_governor.py\nGovernanceControl Registry\n(CTRL_AGT_001 · CTRL_OPA_005)]
        CBF[cbf.py ControlBarrierFunction\nRedis-backed cash/drawdown]
        CAUSAL[causal_gatekeeper.py\nDoWhy refutation lock]
        FLG[fiscal_limit_guard.py\nRedis pre-reservation]
        TQP[token_quota_proxy.py\nCTRL_TQP_007 step+token quota]
        PIISAN[pii_sanitizer.py\nISO 42001 A.6 pre-ledger redaction]
        UCALOG[uca_logger.py\nISO 42001 Clause 6.1 WORM records]
        SAGA[generated_saga_nodes.py\nsaga_router + compensating nodes]
    end

    subgraph compliance-bridge\nPython + FastAPI + SSE
        CB[main.py\nSSE + metrics + audit ingest]
        AW[audit_workflow.py\n6-step OSCAL pipeline]
        SSE_BUS[sse_events.py\nGovernanceEventBus asyncio.Queue]
        OP[oscal_parser.py\nYAML → OscalFinding]
        TYPES[types.py\nPydantic models + SUPPORTED_CONTROLS]
    end

    subgraph Infrastructure
        REDIS[(Redis\nLangGraph Checkpointer + CBF state)]
        OPA_SERVER[OPA Server\ntrade_governance.rego]
        NEMO_SERVER[NeMo Guardrails\nColang 2.x runtime]
        GWI[NGINX Inference Gateway\ngateway.networking.k8s.io/v1beta1]
        VLLM_R[vLLM Brain\nDeepSeek-R1-Distill-Llama-8B\nSpot GPU pool]
        VLLM_F[vLLM Police\nMeta-Llama-3.1-8B-Instruct\nSpot GPU pool]
        LF[Langfuse self-hosted\nObservability + Prompt registry]
        S3[(MinIO/GCS\nOSCAL Artifacts + Model Weights)]
        LULA[Lula CronJob\nevery 6h OSCAL validation]
        KFP[Kubeflow Pipelines\nGreen-Stack scheduler]
    end

    UI -- REST + SSE\n/v1/events/stream --> CB
    UI -- gRPC protos --> GW

    FA -- MCP SSE\nW3C traceparent --> GW
    FA --> GRAPH --> STATE
    GRAPH --> NODES --> SUBS --> GW
    GRAPH --> CHECKPT --> REDIS

    GW --> TQP --> AC --> NEMO --> STPA --> OPA_C --> SYMGOV --> CBF --> CAUSAL --> FLG
    TQP --> PIISAN --> UCALOG
    UCALOG --> S3
    FLG --> SAGA
    CBF --> REDIS
    FLG --> REDIS
    SAGA --> REDIS
    OPA_C --> OPA_SERVER
    NEMO --> NEMO_SERVER
    GW -- HTTP --> GWI --> VLLM_R & VLLM_F

    CB --> AW --> SSE_BUS --> UI
    CB -- Langfuse SDK --> LF
    CB -- boto3 --> S3
    LULA -- POST /v1/audit/ingest --> CB

    KFP --> GSP --> FC --> EG --> TN
    FC -- GET /v1/metrics --> CB
    TN -- POST /v1/nemo/apply-refinement --> FA
    LF -- Webhook /v1/webhooks/langfuse --> FA
    FA -- POST /v1/refinement/trigger --> KFP

    SG --> ON
    FA -- OTel OTLP/HTTP --> LF
    GW -- OTel OTLP/HTTP --> LF
```

---

## Green-Stack Pipeline

[`src/governed_financial_advisor/pipelines/green_stack_pipeline.py`](src/governed_financial_advisor/pipelines/green_stack_pipeline.py) is a **Kubeflow Pipelines v2 (KFP v2)** pipeline that implements the cybernetic governance **feedback loop** (also referred to as the "Cybernetic Governance Loop"):

```
Compliance Bridge → ISO 42001 Evaluation → NeMo In-Process Hot-Reload
```

Three KFP components:

| Component                     | Function                                                      | Key Parameter                              |
| ----------------------------- | ------------------------------------------------------------- | ------------------------------------------ |
| `fetch_compliance_metrics`    | `GET {compliance_bridge_url}/v1/metrics/{control_id}`         | `control_id` (default: `A.5.2`)            |
| `evaluate_governance_metrics` | Compare `safety_rate` to threshold                            | `safety_threshold` (default: `0.95`)       |
| `trigger_nemo_refinement`     | `POST {backend_url}/v1/nemo/apply-refinement` if FAIL          | `backend_url` (governed-financial-advisor) |

The pipeline is named "green-stack" because it operates as the "self-healing" layer of the governance stack — when the compliance bridge reports degraded safety rates, the pipeline automatically triggers NeMo Guardrails policy hot-reloading in-process without human intervention. This is the **cybernetic feedback** component of CAGE.

**Current status:** Fully implemented and validated. The `POST /v1/refinement/trigger` endpoint enqueues a Kubeflow Pipelines (KFP) refinement run. A reactive `POST /v1/webhooks/langfuse` webhook receiver automatically triggers KFP runs when the safety score drops below the 0.95 threshold, utilizing a 5-minute cooldown gate (`REFINEMENT_COOLDOWN_SECONDS=300`) and a 10-sample minimum (`REFINEMENT_MIN_SAMPLES=10`) to prevent policy flapping during noisy bursts. The final step of the KFP pipeline calls the hot-reload `POST /v1/nemo/apply-refinement` endpoint on the backend to apply and reload new guardrails in-process without pod restarts. **v2.0.0 note:** All NeMo config refinements require explicit human approval via `POST /v1/nemo/propose-refinement` before the apply step executes — the autonomous hot-reload loop is human-gated.

---

## Infrastructure Layer (`src/governed_financial_advisor/infrastructure/`)

The infrastructure layer is **fully populated**. It provides all cross-cutting clients and configuration abstractions for the governed financial advisor service.

### Client Differentiation

Three purpose-distinct HTTP clients exist. They are **not aliases** — each targets a different surface of the gateway stack:

| Client             | File                                                                                         | Target Endpoint                          | Protocol                          | Purpose                                                                                             |
| ------------------ | -------------------------------------------------------------------------------------------- | ---------------------------------------- | --------------------------------- | --------------------------------------------------------------------------------------------------- |
| `GatewayClient`    | [`gateway_client.py`](src/governed_financial_advisor/infrastructure/gateway_client.py)       | `GATEWAY_URL` (`/v1/chat/completions`)   | HTTP/JSON                         | Freeform chat inference through the governed gateway; lazy singleton httpx client                   |
| `GovernanceClient` | [`governance_client.py`](src/governed_financial_advisor/infrastructure/governance_client.py) | `GATEWAY_API_BASE` (`/chat/completions`) | HTTP/JSON with vLLM `guided_json` | Schema-constrained structured generation via FSM logit processor; sync + async variants             |
| `GatewayMCPClient` | [`mcp_client.py`](src/governed_financial_advisor/infrastructure/mcp_client.py)               | `MCP_SERVER_SSE_URL`                     | SSE/MCP protocol                  | Tool dispatch via Model Context Protocol; W3C traceparent injected via `ClientSession` monkey-patch |

**When to use each:**

- Use `GatewayClient` for conversational LLM calls that go through the full NeMo/OPA gateway
- Use `GovernanceClient` for schema-critical structured outputs (risk reports, UCA analysis) where FSM-constrained generation is required
- Use `GatewayMCPClient` to invoke gateway tools (`execute_trade_action`, `evaluate_policy`, `check_safety_constraints`, etc.)

### Configuration Hierarchy

[`config_manager.py`](src/governed_financial_advisor/infrastructure/config_manager.py) implements a two-tier lookup:

1. **Environment variables** — fastest; K8s Secrets injected as env vars follow this path
2. **Default fallback** — returned when no env var is set

`ConfigManager` sits above `config/settings.py::Config`. All secret resolution uses `os.getenv()` or `config_manager.get()` — there is no Google Secret Manager dependency at runtime.

### Redis Client (`redis_client.py`)

[`AsyncRedisClient`](src/governed_financial_advisor/infrastructure/redis_client.py) is a full-featured production client:

- **OTel-traced** — every `get`/`set`/`delete` creates a span with `redis.key` attribute
- **Fail-fast** — raises `ConnectionError` on connect failure (no silent memory fallback)
- **Kubernetes-aware** — strips `tcp://host:port` prefix from `REDIS_PORT` env var (GKE auto-injection)
- **Test-compatible** — `RedisClient = AsyncRedisClient` alias at line 164 preserves existing test imports
- Global singleton `redis_client` exported at line 168 (the P0 import target from `safety.py:141`)

### NeMo Telemetry Exporter (`telemetry/nemo_exporter.py`)

[`NeMoOTelCallback`](src/governed_financial_advisor/infrastructure/telemetry/nemo_exporter.py) is a `StreamingHandler` subclass (NeMo internal event hook) that creates OTel spans for every guardrail action matching `"check"`, `"guard"`, or `"detect"`. Each span is tagged:

- `langfuse.trace.metadata.iso.control_id = "A.6.2.8"` (ISO 42001 Event Logging)
- `langfuse.trace.metadata.guardrail.outcome = "ALLOWED" | "BLOCKED"`

Spans flow: NeMo runtime → Langfuse OTLP/HTTP ingestion (direct). This is **span/trace telemetry**, not Langfuse score events.

**Known issue (R-21):** `self.current_span` is an instance variable. Concurrent async guardrail actions will overwrite it, leaking the earlier span open.

---

## Request Path — Governed Financial Advisory Request

A typical governed trade advisory request flows as follows:

1. **User sends request** → `POST /agent/query` to [`server.py`](src/governed_financial_advisor/server.py)
2. **NeMo input safety** → `validate_with_nemo(prompt, rails)` — Colang 2.x + 15-entity Presidio PII scan; unsafe input returns early
3. **Graph invocation** → `graph.ainvoke({"messages": [...], "user_id": ...}, {"thread_id": ...})`
4. **Thinker node** (DeepSeek-R1) → classifies intent (`DATA_ANALYST / EXECUTION_ANALYST / STRATEGY_ADVISOR / HUMAN_REVIEW`); extracts risk profile and investment period into `AgentState`
5. **Doer node** (Llama 3.1) → formats `RouteRequest` tool call; sets `next_step` field in state (avoids fragile keyword scanning — ARCH-03 fix)
6. **Supervisor routing** → `route_supervisor()` reads `next_step`; maps `"FINISH"` → LangGraph `END` sentinel
7. **Data Analyst path** (if market data requested) → `data_analyst_graph` subgraph: thinker→doer→execute_tool→reporter; every MCP call traverses 7-layer gateway governance
8. **Execution Analyst node** → Llama structured plan generation (Pydantic output); market context injected; `loop_count` incremented unconditionally
9. **Evaluator node** → `check_safety_constraints()` calls OPA `evaluate_policy` via MCP; HMAC-SHA256 `governance_signature` generated on `APPROVED`
10. **Signature gate** (`check_safety_signature`) → if `APPROVED + sig`: proceed to `safety_check_node`; if `loop_count >= 3`: escape to `explainer` (recursion guard); else: loop back to `execution_analyst`
11. **Safety Check node** _(NEW Rev8 — R-11 FIXED)_ → calls OPA policy gate directly; `route_safety()` routes: `APPROVED/SKIPPED → governed_trader`, `BLOCKED/ESCALATED → explainer` without executing trade
12. **LangGraph interrupt** (`interrupt_before=["governed_trader"]`) → graph pauses; checkpoint saved to Redis; approval required if trade > $10k or risk_score > 0.7
13. **Human review** → reviewer calls `POST /v1/approvals/{thread_id}/resume` → `Command(resume=...)` resumes graph
14. **Governed Trader subgraph** → approval gate (for high-value trades) → executor calls MCP `execute_trade_action` → gateway enforces full governance pipeline including CBF + STPA + Consensus
15. **Explainer node** → final narrative for user
16. **NeMo output masking** → `verify_and_mask_output(rails, response)` — Presidio PII egress filter
17. **OTel spans** emitted throughout → Langfuse receives W3C traceparent-linked trace waterfall

---

## Governance Stack

All governance enforcement layers are Python-only:

| Tier | Component                   | File                                                                                | Mechanism                                                                                          | When Applied                             |
| ---- | --------------------------- | ----------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- | ---------------------------------------- |
| 1    | Aho-Corasick keyword scan   | [`safety.py:51`](src/gateway/governance/safety.py)                                  | O(n) forbidden keyword detection, 14+ patterns                                                     | Every `/agent/query` request             |
| 2    | NeMo Guardrails input       | [`nemo/manager.py`](src/gateway/governance/nemo/manager.py)                         | Colang 2.x + bypass pattern check + Presidio                                                       | Every `/agent/query` request             |
| 3    | STPA Validator              | [`stpa_validator.py`](src/gateway/governance/stpa_validator.py) / `generated_stpa_validator.py` | UCA-1/2/5/6/8/9 deterministic checks; compiled from `stpa_control_structure.yaml` | Every `execute_trade_action` MCP call    |
| 4    | OPA Policy Engine           | [`core/policy.py`](src/gateway/core/policy.py)                                      | `trade_governance.rego` + `generated_stpa_policy.rego` RBAC; circuit breaker                      | Every tool call via Symbolic Governor    |
| 5    | Control Barrier Function    | [`safety.py ControlBarrierFunction`](src/gateway/governance/safety.py)              | Discrete-time CBF; Redis-backed cumulative cash state                                              | Every `execute_trade` call               |
| 6    | Consensus Engine            | [`consensus.py`](src/gateway/governance/consensus.py)                               | Multi-agent debate for high-stakes trades                                                          | Every `execute_trade_action` > threshold |
| 7    | DoWhy Causal Gatekeeper     | [`causal_gatekeeper.py`](src/gateway/governance/causal_gatekeeper.py)               | Placebo refutation (DoWhy); validates world-model integrity pre-trade                              | `execute_trade` calls only          |
| 8    | NeMo output masking         | [`nemo/manager.py`](src/gateway/governance/nemo/manager.py)                         | Presidio PII egress filter (15 entity types)                                                       | Every LLM response; PII-004 FIXED        |
| 9    | HMAC signature gate         | [`evaluator_node.py`](src/governed_financial_advisor/graph/nodes/evaluator_node.py) | HMAC-SHA256 governance_signature; required before governed_trader                                  | Evaluator → governed_trader edge         |
| 10   | LangGraph interrupt         | [`graph.py:100`](src/governed_financial_advisor/graph/graph.py)                     | `interrupt_before=["governed_trader"]`                                                             | Before every governed_trader execution   |
| 11   | Human approval gate         | [`approval_node.py`](src/governed_financial_advisor/graph/nodes/approval_node.py)   | `interrupt()` / `Command(resume=...)` via `/v1/approvals/{thread_id}/resume`                       | Trades > $10k or risk_score > 0.7        |
| 12   | Recursion guard             | [`graph.py:82`](src/governed_financial_advisor/graph/graph.py)                      | `loop_count >= 3 → explainer` escape hatch                                                         | evaluator→execution_analyst loop         |
| 13   | Linkerd mTLS                | [`linkerd-mtls-policy.yaml`](deployment/k8s/linkerd-mtls-policy.yaml)               | SPIFFE/SVID identity; `Server`/`AuthorizationPolicy`/`MeshTLSAuthentication` v1beta2               | All intra-cluster service communication  |
| 14   | Cilium L7 egress            | [`cilium-egress-lockdown.yaml`](deployment/k8s/cilium-egress-lockdown.yaml)          | FQDN allowlist (gateway); internal-only lockdown (sovereign-agent pods); default-deny              | All outbound network traffic             |
| 15   | FiscalLimitGuard            | [`fiscal_limit_guard.py`](src/gateway/governance/fiscal_limit_guard.py)              | Redis `WATCH/MULTI/EXEC` atomic pre-reservation; prevents multi-agent TOCTOU on OPA fiscal limits  | Every `execute_trade` call, pre-OPA      |
| 16   | Token Quota Proxy           | [`token_quota_proxy.py`](src/gateway/governance/token_quota_proxy.py)                | Redis atomic Lua counters; step-count ≤12 and token ≤100k per session; fail-CLOSED on Redis error; two-phase commit (reserve → reconcile); rollback on downstream failure. ISO 42001 Annex A.4. `CTRL_TQP_007`. | Every inference proxy request (Step 2 in `inference_proxy.py`) |

> **CTRL_TQP_007 — Token Quota Proxy:** Implements ISO 42001 Annex A.4 (Resource Management). Every blocked execution produces a KMS-signed UCA record persisted to the region-gated WORM ledger via [`uca_logger.py`](src/gateway/governance/uca_logger.py). Pre-ledger PII sanitization applied by [`pii_sanitizer.py`](src/gateway/governance/pii_sanitizer.py) (ISO 42001 Annex A.6). OPA `quota_within_limits` and `token_quota_within_limits` rules in `deployment/system_authz.rego` provide secondary declarative evidence; Python `TokenQuotaProxy` is the primary enforcer.

### Multi-Jurisdiction Regional Compliance Profiles

CAGE supports multi-jurisdiction productization by separating the technical engine from the regional regulatory frameworks. Using the `CAGE_DEPLOYMENT_REGION` environment variable, the system dynamically configures active compliance rules, telemetry models, and operational safety thresholds:

| Region Code | Target Jurisdiction | Compliance Profile | Active Controls & Frameworks | Key Operational Thresholds |
|---|---|---|---|---|
| `US_FED` *(Default)* | United States | `US_FED_BASELINE.json` | SR 26-2, NIST RMF, ISO 42001 | Confidence: `0.95`, Drawdown: `5%`, SLA: `200ms`, Consensus Threshold: `$10,000` |
| `EU_ECB` | European Union | `EU_ECB_BASELINE.json` | EU AI Act, DORA, GDPR Art. 22 | Confidence: `0.97`, Drawdown: `4%`, SLA: `150ms`, Consensus Threshold: `$7,500` |
| `APAC_MAS` | Singapore / APAC | `APAC_MAS_BASELINE.json` | MAS FEAT Principles | Confidence: `0.95`, Drawdown: `5%`, SLA: `100ms`, Consensus Threshold: `$5,000` |

#### Key Regional Behaviors:
1. **EU_ECB Regional Profile:**
   - **Step 7 FRIA Attestation:** Generates a pre-market Fundamental Rights Impact Assessment (FRIA) attestation for EU AI Act Article 29a compliance, injecting OTel span attributes (`governance.fria.control_id`, `governance.fria.framework`, `governance.fria.scope`) to satisfy logging obligations.
   - **Data-Driven SR 26-2 Telemetry Suppression:** The `causal_gatekeeper` reads the `"no legal force"` sentinel embedded in each regional profile's `legacy_citation` field. When present, it emits `primary_framework` (the jurisdiction-correct citation, e.g. `EBA/GL/2023/02`) on OTel spans instead of the US-specific SR 26-2 string. This is fully data-driven — adding a new region requires only a JSON profile update, never a Python change.
2. **ControlRegistry Singleton:**
   - A thread-safe, lock-guaranteed registry loaded dynamically from `/config/compliance/{REGION}_BASELINE.json` with a legacy fallback to `control_mappings.json`.
   - Offers `get_mapping_safe()` to prevent system-wide `KeyError` exceptions when checking region-specific controls (e.g. `CTRL_FRIA_006` in non-EU environments).
   - Allows runtime lifecycle reconfiguration via `ControlRegistry.reconfigure("REGION")` for testing and updates.

---

## Testing Coverage Map

| Test File                                                                                              | What It Tests                                                                                   | Source Under Test                                               |
| ------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------- | --------------------------------------------------------------- |
| [`test_cage_graph.py`](tests/test_cage_graph.py)                                                       | Canonical CAGE graph compilation and node structure                                     | `src/governed_financial_advisor/graph/graph.py::create_graph()` |
| [`test_stpa_compiler.py`](tests/test_stpa_compiler.py)                                                 | STPA compiler schema validation, code generation, fail-closed semantics (33 tests)      | `src/gateway/governance/stpa_compiler.py`                       |
| [`test_causal_gatekeeper.py`](tests/test_causal_gatekeeper.py)                                         | DoWhy causal gatekeeper: refutation logic, fail-open on missing dep, integration with SymbolicGovernor | `src/gateway/governance/causal_gatekeeper.py`      |
| [`test_fiscal_limit_guard.py`](tests/test_fiscal_limit_guard.py)                                       | Multi-agent race condition, Saga rollback release, Redis fail-closed, idempotency (16 tests) | `src/gateway/governance/fiscal_limit_guard.py`           |
| [`test_playground_telemetry.py`](tests/test_playground_telemetry.py)                                   | Evidence chain hash integrity, tamper detection, PII redaction, view-access log (27 tests) | `examples/telemetry.py`                                       |
| [`test_hitl_rationale.py`](tests/test_hitl_rationale.py)                                               | Mandatory rationale validation, Saga payload propagation, and cryptographic evidence chain | `src/governed_financial_advisor/server.py`                    |
| [`test_optimistic_execution.py`](tests/test_optimistic_execution.py)                                   | Optimistic concurrency interruption                                                     | `src/gateway/core/tools::execute_trade()`                       |
| [`test_compliance_bridge.py`](tests/test_compliance_bridge.py)                                         | OSCAL YAML parsing, Pydantic validation, FastAPI endpoints                              | `src/compliance_bridge/` package                                |
| [`test_symbolic_governor.py`](tests/test_symbolic_governor.py)                                         | SymbolicGovernor OPA + CBF + STPA integration                                           | `src/gateway/governance/symbolic_governor.py`                   |
| [`test_opa_client.py`](tests/test_opa_client.py)                                                       | OPA circuit breaker behavior                                                            | `src/gateway/core/policy.py`                                    |
| [`test_pii_integration.py`](tests/test_pii_integration.py)                                             | Presidio PII detection (PII-004 regression guard)                                       | `src/gateway/governance/nemo/manager.py`                        |
| [`test_governance_architecture.py`](tests/test_governance_architecture.py)                             | Permanent CI guardrail: no hardcoded regulatory strings, regional profile parity, enum/registry parity, SIEM legacy citation, orphaned-control detection (5 tests) | `src/gateway/governance/`, `config/compliance/`     |
| [`test_framework_router.py`](tests/test_framework_router.py)                                           | FrameworkRouter matrix: JSON schema integrity, cache identity/isolation, UCA coverage, description completeness, narrative rendering, deduplication, sentinel suppression (41 tests) | `oscal_ssp_exporter.py`, `config/oscal/framework_mappings/` |

---

## Deployment — Kubernetes/GKE Topology

```
GKE Cluster (governance-stack namespace)
├── governed-financial-advisor   (1 pod, 2 CPU / 2Gi, REDIS_URL configured)
│     └── deployment/k8s/financial-advisor.yaml
├── gateway                      (deployment/k8s/backend-deployment.yaml)
├── compliance-bridge            (deployment/service.yaml)

├── vllm-brain                   (DeepSeek-R1-Distill-Llama-8B, NVIDIA L4 Spot)
├── vllm-police                  (Meta-Llama-3.1-8B-Instruct, NVIDIA L4 Spot)
├── redis                        (db=0: checkpointer + CBF; db=1: DEFER state, noeviction)
├── opa                          (trade_governance.rego + generated_stpa_policy.rego)
├── langfuse                     (self-hosted: ClickHouse + MinIO + Worker)
├── minio                        (model weights + OSCAL artifacts)
├── agentsight                   (eBPF kernel sidecar — deployment/agentsight/)
├── lula-cron                    (CronJob every 6h — 15 active OSCAL validation manifests)
├── inference-gateway            (NGINX Gateway API — cloud-agnostic)
├── linkerd control plane        (Z3N: mTLS proxy injection on governance-stack namespace)
│     ├── deployment/k8s/linkerd-mtls-policy.yaml  — Server + AuthorizationPolicy + MeshTLSAuthentication
│     └── SPIFFE/SVID identity: gateway↔opa, gateway↔nemo
└── cilium CNI                   (Z3N: L7 FQDN egress lockdown)
      ├── deployment/k8s/cilium-egress-lockdown.yaml  — CiliumNetworkPolicy
      ├── gateway pod: approved FQDN allowlist (api.openai.com, cloud.langfuse.com, etc.)
      └── sovereign-agent pods: internal-only (opa, gateway, langfuse)
```

**Model loading:** vLLM pods load serialized TensorSerializer shards from MinIO (`vllm-models` bucket). Cold-start ~60–90s vs ~20 min HuggingFace download. No GKE-proprietary GCS Fuse CSI driver required.

**Workload Identity:** GKE Workload Identity Federation (OIDC) exclusively. Zero hardcoded `service-account-key.json` files (verified in `infra/modules/gateway/main.tf`). `roles/iam.workloadIdentityUser` binding to `financial-advisor-sa`.

**Cost optimization:** vLLM pods bound to `cloud.google.com/gke-spot=true` nodes → ~60% compute savings. Gateway runs on On-Demand instances.

---

## Key Files Reference

| Component                    | Entry Point                                                            | Key File(s)                                                                                               |
| ---------------------------- | ---------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| Financial Advisor server     | `src/governed_financial_advisor/server.py`                             | `graph/graph.py`, `graph/checkpointer.py`                                                                 |
| Canonical CAGE graph         | `graph/graph.py::create_graph()`                                       | 10 nodes (including mandatory NeMo input/output rails): nemo_guardrail → thinker → doer → data_analyst / execution_analyst → evaluator → safety_check → governed_trader → explainer → nemo_output_rail |
| Legacy optimistic graph shim | `src/governed_financial_advisor/graph/graph.py` (legacy shim)          | For `test_optimistic_graph.py` ONLY — do not use in production                                            |
| Agent state schema           | `graph/state.py::AgentState`                                           | 25 fields: messages, next_step, safety_status, governance_signature, approval_required, approval_decision, hitl_expires_at, **completed_transactions** (WAL ledger) |
| WAL Ledger entries           | `graph/state.py::LedgerEntry`                                          | sequence_id, uca_ref, idempotency_key, status (PENDING/COMPLETED/ROLLED_BACK/PARTIAL_FAILURE), context_data |
| Saga router + nodes          | `src/gateway/governance/generated_saga_nodes.py`                       | saga_router_node (LIFO + ghost-state), compensate_reverse_trade_node_uca_4 (DO NOT EDIT)                  |
| Fiscal limit guard           | `src/gateway/governance/fiscal_limit_guard.py`                         | Redis WATCH/MULTI/EXEC atomic pre-reservation; prevent multi-agent OPA limit collision                   |
| Saga telemetry               | `src/governed_financial_advisor/utils/langfuse_utils.py::SagaCallbackHandler` | on_chain_end interceptor; emits OTel span iso42001.control_id=A.8.4 per Saga node                  |
| Optimistic nodes             | `src/governed_financial_advisor/graph/nodes/` (legacy test path)       | safety_check_node, trader_prep_node, optimistic_execution_node, route_optimistic_execution                |
| Green-Stack KFP pipeline     | `src/governed_financial_advisor/pipelines/green_stack_pipeline.py::governance_pipeline` | fetch_compliance_metrics → evaluate → trigger_nemo_refinement                          |
| Approval API                 | `server.py POST /v1/approvals/{thread_id}/resume`                      | `graph/nodes/approval_node.py`                                                                            |
| Data analyst subgraph        | `graph/subgraphs/data_analyst_graph.py`                                | 4-node: thinker→doer→execute_tool→reporter                                                                |
| Governed trader subgraph     | `graph/subgraphs/governed_trader_graph.py`                             | 4-node: approval→executor→tools→rejection                                                                 |
| Evaluator (HMAC + OPA)       | `graph/nodes/evaluator_node.py`                                        | `agents/evaluator/agent.py::check_safety_constraints()`                                                   |
| Gateway server               | `src/gateway/server/hybrid_server.py`                                  | `/agent/query`, `/api/chat`, MCP tools                                                                    |
| Governance pipeline          | `src/gateway/governance/symbolic_governor.py`                          | OPA + CBF + STPA + Consensus + FRIA; emits structured `GovernanceControl` violation payloads via `ControlRegistry` (`config/compliance/{REGION}_BASELINE.json` or fallback `config/control_mappings.json`) |
| OSCAL SSP exporter           | `src/gateway/governance/oscal_ssp_exporter.py`                        | `FrameworkRouter` loads `config/oscal/framework_mappings/*.json` at runtime; `--framework` CLI flag selects NIST, ISO42001, EU_AI_ACT, or MAS_FEAT cross-walk |
| Framework routing tables     | `config/oscal/framework_mappings/`                                     | `NIST_SP800_53.json`, `ISO_42001.json`, `EU_AI_ACT.json`, `MAS_FEAT.json` — adding a new jurisdiction is a JSON-only operation |
| Keyword scanner              | `src/gateway/governance/safety.py`                                     | Aho-Corasick automaton, 14+ default patterns                                                              |
| OPA client                   | `src/gateway/core/policy.py`                                           | Circuit breaker, UDS transport                                                                            |
| OPA policy                   | `src/governed_financial_advisor/governance/policy/trade_governance.rego` | Package `trade.governance`; RBAC-based thresholds                                                       |
| NeMo config                  | `config/rails/config.yml`                                              | Colang 2.x, vllm_llama engine, Presidio 15 entities                                                       |
| Compliance bridge            | `src/compliance_bridge/main.py`                                        | SSE stream, audit ingest, metrics, prompt proxy                                                           |
| Audit pipeline               | `src/compliance_bridge/audit_workflow.py`                              | 6-step: persist→parse→ingest→alert→remediate→conformance_report                                           |
| OSCAL parser                 | `src/compliance_bridge/oscal_parser.py`                                | YAML → `OscalFinding` Pydantic model                                                                      |
| SSE event bus                | `src/compliance_bridge/sse_events.py`                                  | `GovernanceEventBus` asyncio.Queue per subscriber                                                         |

---

## NeMo Guardrails Deployment

**Pattern: Standalone pod in `governance-stack` namespace** (not a gateway sidecar).

[`deployment/k8s/nemo.yaml`](deployment/k8s/nemo.yaml) — `kind: Deployment`, `name: nemo-service`, ClusterIP `Service` on port 8000.

- **Engine:** CPU-only. Delegates LLM inference to vLLM endpoint via `vllm_llama` engine in [`config/rails/config.yml`](config/rails/config.yml).
- **OTel:** Exports directly to Langfuse integrated OTLP endpoint (`langfuse-web.governance-stack:3000/api/public/otel/v1/traces`) as `nemo-guardrails` service name. (Standalone `otel-collector` deprecated 2026-05-31.)
- **Resources:** 500m–1 CPU, 1–2 GiB RAM.

### NeMo Guardrails Configuration (`config/rails/`)

| File                                                         | Purpose                                                                                                                                         |
| ------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| [`config/rails/config.yml`](config/rails/config.yml)         | Colang 2.x, `vllm_llama` engine, 15 Presidio PII entities (input + output rails), GUARDRAILS_MODEL_NAME env override                            |
| [`config/rails/main_logic.co`](config/rails/main_logic.co)   | 6 flows: main (activates self-check + 3 safety checks), financial_analysis, catch_all, check_authorization, check_latency, check_financial_risk |
| [`config/rails/definitions.co`](config/rails/definitions.co) | 1 active action declaration (`invoke_vllm_fallback`); financial safety actions **commented out** — see R-22                                     |
| [`config/rails/actions.py`](config/rails/actions.py)         | `RetrieveKnowledgeAction` only (knowledge base retrieval); NOT the financial safety actions                                                     |
| [`config/rails/prompts.yml`](config/rails/prompts.yml)       | Fallback `self_check_input` / `self_check_output` prompts (Langfuse is primary)                                                                 |

**✅ R-22 (Mitigated → Low):** `main_logic.co` previously invoked `CheckApprovalTokenAction`, `CheckDataLatencyAction`, `CheckDrawdownLimitAction`, `CheckSlippageRiskAction`. On 2026-03-10 these financial Colang flows were permanently removed; financial policy enforcement was transferred to the `safety_check_node → OPA` path. Pass-through stubs for all six financial actions (`check_approval_token_action`, `check_data_latency_action`, `check_drawdown_limit_action`, `check_slippage_risk_action`, `check_atomic_execution_action`, `log_safety_audit_action`) were added to [`config/rails/actions.py`](config/rails/actions.py) to eliminate the `ImportError` fallback path in `nemo_action_registry.get_all_actions()`. The standalone `nemo-service` pod now resolves its full action registry on Priority 1 (no silent sync fallback). Each stub emits an OTel span stamped `PASS_THROUGH_OPA_AUTHORITATIVE` for audit visibility. The standalone pod is not in the production inference critical path (graph nodes use the in-process singleton in `manager.py`).

---

## OPA Deployment

**Pattern: Standalone service in the `default` namespace** (not `governance-stack`; not a sidecar).

[`deployment/k8s/opa.yaml`](deployment/k8s/opa.yaml) — `namespace: default`, ports 8181 (HTTP) + 8282 (diagnostics), ClusterIP Service.

- **Policy loading:** ConfigMap volume mount at `/policies` (static bundle — no remote bundle server)
- **Config:** Separate ConfigMap `opa-runtime-config` mounted as `/config/opa_config.yaml`
- **No TLS, no API auth** — network-level isolation assumed (K8s NetworkPolicy)
- **Compliance labels:** `compliance.iso42001/controls: "A.5.3,SC-4,A.9.2,A.5.2"` on Deployment + Pod — these are the structural labels queried by `lula-validation-sc4.yaml`
- **Lula RBAC cross-namespace access:** `lula-rbac.yaml` ClusterRole grants `lula-auditor` read access to `opa-compliance-status` and `opa-policies` ConfigMaps in `default` namespace — see R-24

---

For architectural decisions, see [`docs/DEPLOYMENT_DECISION_RECORD.md`](docs/DEPLOYMENT_DECISION_RECORD.md).

---

## Technical Report Series

Full engineering and compliance documentation for CAGE is maintained in the [Technical Report Series](docs/technical-report/README.md). Each document addresses a distinct architectural or compliance domain.

| #   | Document                                                                                       | Title                             |
| --- | ---------------------------------------------------------------------------------------------- | --------------------------------- |
| 01  | [`01-SYSTEM-OVERVIEW.md`](docs/technical-report/01-SYSTEM-OVERVIEW.md)                         | System Overview                   |
| 02  | [`02-ARCHITECTURE.md`](docs/technical-report/02-ARCHITECTURE.md)                               | System Architecture (detailed)    |
| 03  | [`03-TECHNOLOGY-STACK.md`](docs/technical-report/03-TECHNOLOGY-STACK.md)                       | Technology Stack                  |
| 04  | [`04-AGENT-SYSTEM.md`](docs/technical-report/04-AGENT-SYSTEM.md)                               | Multi-Agent System Design         |
| 05  | [`05-AI-GOVERNANCE-POLICY-ENGINE.md`](docs/technical-report/05-AI-GOVERNANCE-POLICY-ENGINE.md) | AI Governance & Policy Engine     |
| 06  | [`06-COMPLIANCE-STANDARDS.md`](docs/technical-report/06-COMPLIANCE-STANDARDS.md)               | Compliance & Regulatory Standards |
| 07  | [`07-SECURITY-INFRASTRUCTURE.md`](docs/technical-report/07-SECURITY-INFRASTRUCTURE.md)         | Security Infrastructure           |
| 08  | [`08-DEPLOYMENT-INFRASTRUCTURE.md`](docs/technical-report/08-DEPLOYMENT-INFRASTRUCTURE.md)     | Deployment & Infrastructure       |
| 09  | [`09-OPERATIONAL-RUNBOOK.md`](docs/technical-report/09-OPERATIONAL-RUNBOOK.md)                 | Operational Runbook               |
| 10  | [`10-FORMAL-VERIFICATION.md`](docs/technical-report/10-FORMAL-VERIFICATION.md)                 | Formal Verification & Completeness Proof |

---

_Architecture current as of 2026-06-08. Canonical graph: 10 nodes including mandatory NeMo input/output rails. Governance tiers: **7** (SymbolicGovernor tiers 0–6) + FiscalLimitGuard pre-reservation + Token Quota Proxy (CTRL_TQP_007) + LangGraph Saga WAL. STPA compiler active: UCAs compiled from `config/stpa_control_structure.yaml`; LangGraph Saga target added (UCA-4 fully enforced via WAL + LIFO rollback + idempotent compensating nodes). Z3N: Linkerd + Cilium deployed. POAM-007 (IA-3), POAM-010 (RA-5), POAM-016 (SI-2), POAM-020 (CM-3), POAM-021 (SI-4) closed. POAM-023 (SI-2 CVE-2025-13462) opened 2026-06-08. POAM-011 (SC-8) and POAM-012 (SC-12) remain Open. Vendor integrations isolated in `src/integrations/{vendor}/` (NexArt, TrustLayers). Redis db=1 hardened with `noeviction` + Guaranteed QoS. Lula coverage: 15 validation manifests (4 Active, 11 Stub). FiscalLimitGuard: Redis WATCH/MULTI/EXEC atomic pre-reservation prevents multi-agent OPA limit collision. Token Quota Proxy: Redis Lua atomic step/token counters; fail-CLOSED; ISO 42001 A.4. NoDirectBind safety invariant machine-verified over 19 reachable states (v2.0.0-rc.2). Test suite: **796 passing, 0 failed** (Track D — 2026-06-08). For architectural decisions, see [`docs/DEPLOYMENT_DECISION_RECORD.md`](docs/DEPLOYMENT_DECISION_RECORD.md)._
