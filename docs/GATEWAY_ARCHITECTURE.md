# Gateway Architecture: Sovereign Edition — v2.0.0

## Overview

The Gateway acts as the central orchestrator and compliance enforcement point for the AI financial advisor. It implements a **Kubernetes Inference Gateway** architecture, abstracting a "Split-Brain" topology that routes tasks between a high-capacity Reasoning Model (`DeepSeek-R1-Distill-Llama-8B`) and a low-latency Governance Model (`Meta-Llama-3.1-8B-Instruct`). Both models are hosted on cost-optimized **Spot/preemptible GPU nodes** (NVIDIA L4). (GKE is the reference deployment; other Kubernetes distributions are supported)

**Version:** v2.0.0-rc.3 (promoted 2026-06-07)
**Primary Compliance Framework:** ISO/IEC 42001:2023 · SR 26-2 (Federal Reserve, April 17, 2026) · CSA AARM v1.0

## Core Components

1.  **Hybrid Gateway Service (FastAPI + FastMCP):**
    - Exposes a unified HTTP/MCP interface.
    - Handles tool execution requests (`execute_trade`, `search_market`).
    - Enforces neuro-symbolic policies via OPA and the Symbolic Governor.
    - **Reusable LangGraph Governance Harness:** Provides factory functions (`create_opa_safety_node`, `create_nemo_guardrail_node`) so any agent graph can implement standardized governance with domain-specific context extractors.
    - **NeMo Guardrails (PII & Semantic):** Enforces topical safety and masks PII (Presidio) on input/output directly within the service graph via the harness.

2.  **Sovereign vLLM Cluster:**
    - **Node A (Reasoning):** Handles planning, complex analysis, and chain-of-thought generation. Model: `deepseek-ai/DeepSeek-R1-Distill-Llama-8B` (NVIDIA L4 GPU, 16Gi). Note: `Qwen/Qwen2.5-7B-Instruct` is the undeployed aspirational governance backend (`vllm-governance.yaml`, marked NOT CURRENTLY DEPLOYED).
    - **Node B (Governance):** Handles rapid policy checks, safety filtering, and content moderation. Model: `Qwen/Qwen2.5-1.5B-Instruct`.
    - **Deep Reasoning:** `deepseek-ai/DeepSeek-R1-Distill-Llama-8B` for complex multi-step analysis.

3.  **Observability Layer (Direct Langfuse OTLP):**
    - **Application Tracing (Langfuse via OpenTelemetry):** Captures the execution graph, prompt templates, and tool inputs/outputs using OpenTelemetry GenAI Semantic Conventions (v1.36.0+). Generic application spans are natively mapped to Langfuse schemas via `langfuse.observation.*` and `langfuse.trace.metadata.*`. **Direct OTLP ingestion** to Langfuse endpoint `http://langfuse-web:3000/api/public/otel/v1/traces` — the OTel Collector sidecar was **deprecated 2026-05-31**.
    - **Distributed MCP Tracing:** W3C `traceparent` is injected into MCP tool call arguments (`_otel_carrier`) by the client and extracted at the `ToolManager.call_tool()` level on the server. This bridges the SSE transport gap and produces parent-child spans across the protocol boundary.
    - **Scanner-Noise Filtering:** The `server_request_hook` uses an HTTP method allowlist (`GET`/`POST` only) and a path blocklist to silently drop vulnerability scanner probes from traces.
    - **System Monitoring (AgentSight UI):** A React/Vite frontend backed by an eBPF DaemonSet providing kernel-level observability. Phase 1 features: `KernelDashboard` with slippage slider, price drift badges, and HITL TTL countdown. The eBPF daemon intercepts:
      - **Encrypted Traffic (OpenSSL):** Captures raw LLM payloads at the network boundary.
      - **System Calls (Kernel):** Monitors process creation (`execve`), file access (`openat`), and network connections (`connect`).
    - **Correlation:** The Gateway injects the OpenTelemetry `trace_id` as an `X-Trace-Id` HTTP header into every LLM request. AgentSight uses this header to link high-level intent (Langfuse trace) with low-level system actions.

4.  **DEFER Queue (AARM-V7 — Confidence-Starved Context Handling):**
    - Redis `db=1` with `noeviction` policy stores contexts that fall in the DEFER zone of the three-zone confidence model: ALLOW ≥ 0.95, DEFER 0.70–0.95, DENY < 0.70 (`DEFER_CONFIDENCE_THRESHOLD = 0.70`). Contexts in the DEFER zone are not outright denied.
    - DEFER tokens are parked with a 4-hour TTL and resolved via `POST /v1/defer/{id}/inject` (automated data injection) or `POST /v1/defer/{id}/escalate` (HITL manual review escalation).
    - Implements AARM vector V7 (Context Window Overflow) from the CSA AARM v1.0 11-vector threat model.
    - See `src/gateway/governance/defer_queue.py`.

5.  **External Normative Provider with Adaptive FRIA Gating:**
    - `src/gateway/governance/normative_provider.py` supplies jurisdiction-specific normative constraints at runtime.
    - For `EU_ECB` deployments: activates Adaptive FRIA (Fundamental Rights Impact Assessment) gating per EU AI Act Art. 29a, with 24-hour PII retention limits.
    - Normative constraints are loaded without redeployment via the `CAGE_DEPLOYMENT_REGION` environment variable.

6.  **ConsensusModelRegistry (Heterogeneous Multi-Model Consensus):**
    - `src/gateway/governance/consensus.py` manages a registry of heterogeneous models for multi-model consensus evaluation.
    - Activated for trades ≥ $10,000 USD (consensus_threshold_usd).
    - Prevents single-model capture by requiring agreement across model families.

7.  **AnchorageGrpcLedgerProvider (Externally Reconciled CBF — FUTURE STATE / POAM-023):**
    - **Status:** Not yet implemented. Referenced in architecture as a planned enhancement.
    - When implemented, the Control Barrier Function (CBF) cash-balance barrier (γ=0.5, min=$1,000) will be reconciled against an external ledger via gRPC, eliminating reliance on Redis-cached balances for safety-critical checks.
    - The current implementation uses Redis `WATCH/MULTI/EXEC` optimistic locking for CBF enforcement. The "Stale Ground Truth" risk is mitigated by the TTL-gated staleness check in the DEFER state machine (AARM-V7) and the `post_hitl_revalidate_node` execution-time re-sampling.
    - See POAM-023 for tracking status.

## Data Flow

1.  **User Request:** Incoming HTTP/gRPC request to the Gateway.
2.  **Noise Filtering:** OTel `server_request_hook` drops scanner probes (non-GET/POST methods, known probe paths).
3.  **Policy Check (Pre-Execution):** OPA validates the request against regulatory policies.
4.  **Routing:** GatewayClient connects to the Kubernetes Inference Gateway, which routes to the target model (Reasoning vs. Governance).
5.  **Header Injection:** The client generates a trace ID and injects `X-Trace-Id`.
6.  **LLM Call:** Request is sent to vLLM. AgentSight intercepts this call.
7.  **MCP Tool Execution:** If the model requests a tool via MCP, the client injects `traceparent` and calls the Gateway. The Gateway extracts the context, creates a child span, and executes the tool.
8.  **HITL Gate (TOCTOU Remediation):** For trades >$10,000 USD or risk_score >0.7, the `hitl_gate` node interrupts the graph. On human approval, `post_hitl_rehydrate` fetches a live market quote and computes price drift, then `post_hitl_revalidate` re-runs **Tier 2 (CBF)** and **Tier 4 (OPA)** only with fresh market data before proceeding (or blocking on drift/governance violation).
9.  **DEFER Queue:** Contexts in the DEFER zone (confidence 0.70–0.95) are pushed to Redis `db=1` (noeviction, 4-hour TTL) for deferred resolution. Three-zone model: ALLOW ≥ 0.95, DEFER 0.70–0.95, DENY < 0.70. Resolved via `POST /v1/defer/{id}/inject` (automated) or `POST /v1/defer/{id}/escalate` (HITL). (AARM-V7)
10. **Logging:**
    - Application metadata is sent **directly** via OTLP to Langfuse (`http://langfuse-web:3000/api/public/otel/v1/traces`). The OTel Collector is **deprecated** as of 2026-05-31.
    - System events are displayed in the AgentSight Dashboard (React/Vite, port 5173).

## Deployment Topology

- **Production (Kubernetes):** Gateway runs as a service behind an Ingress in the `governance-stack` namespace. AgentSight runs as a DaemonSet for kernel-level eBPF observability. Linkerd mTLS + Cilium L7 egress lockdown are deployed (POAM-007 closed 2026-05-17). (GKE is the reference deployment; other Kubernetes distributions are supported)
- **Local (Docker Compose):** All components run in a shared network. See `deployment/agentsight/docker-compose.agentsight.yaml`.

## Security Architecture

### Network Security
- **Linkerd mTLS:** All service-to-service communication is encrypted via mutual TLS (POAM-007 closed 2026-05-17).
- **Cilium L7 Egress Lockdown:** Approved FQDN egress allowlist enforced at the kernel level:
  - `api.openai.com`, `api.anthropic.com`, `generativelanguage.googleapis.com`, `*.googleapis.com`
  - `metadata.google.internal`, `us.i.posthog.com`, `cloud.langfuse.com`
  - `api.trade.gov`, `www.treasury.gov`

### CSA AARM v1.0 — 11-Vector Threat Coverage

| Vector | Threat | Mitigation |
|--------|--------|------------|
| AARM-V1 | Memory Poisoning | SHA-256 hash-chained context accumulator (`src/compliance_bridge/context_accumulator.py`) |
| AARM-V2 | Goal Hijacking | NeMo Guardrails input rail + OPA semantic score threshold (0.85) |
| AARM-V3 | Confused Deputy | HMAC-SHA256 routing seal + Cloud KMS HSM asymmetric signing; all execution paths cryptographically attested |
| AARM-V4 | Cross-Agent Propagation | SBOM generation (`scripts/generate_sbom.py`); `outlines` package removed (CVE-2025-69872) |
| AARM-V5 | Prompt Injection | Aho-Corasick keyword scan (Tier 1) + NeMo Guardrails Colang 2.x input rail (Tier 3) |
| AARM-V6 | Reward Hacking | OPA RBAC policy (Tier 4); Linkerd mTLS workload identity |
| AARM-V7 | Context Window Overflow | DEFER queue (Redis db=1 noeviction, 4h TTL); three-zone model (ALLOW≥0.95, DEFER 0.70–0.95, DENY<0.70) |
| AARM-V8 | Temporal Deception | LangGraph Saga WAL + LIFO rollback; idempotency keys |
| AARM-V9 | Privilege Escalation | ConsensusModelRegistry heterogeneous multi-model consensus (DeepSeek-R1 + Llama 3.1) |
| AARM-V10 | Data Exfiltration | NeMo output rail + Presidio PII egress scan (15 entity types) |
| AARM-V11 | Model Substitution | OSCAL v1.0.4 artifact persistence to GCS; Cloud KMS HSM signing (PARTIAL — POAM-022) |

### Cloud KMS HSM-Backed Asymmetric Governance Signing

Cloud KMS asymmetric signing is the **primary** governance signing mechanism (replaces HMAC-SHA256 as primary). HMAC-SHA256 is retained as a **fallback for dev/CI only**.

- **Primary:** Google Cloud KMS HSM — private key never leaves the HSM; Cloud Audit Logs provide immutable external attestation.
- **Fallback:** HMAC-SHA256 using `GOVERNANCE_SALT` (dev/CI only; compliance bridge flags this as a gap).
- See `src/gateway/governance/kms_signer.py`.

## Repository Structure (OSS)

```text
cybernetic-governance-engine/
├── .agent/                 # Agent Personas, Rules, and Policies
├── config/                 # Global Settings & Model Mappings
├── data/                   # Sample Datasets & Symbolic Stamps
├── deployment/             # GKE Deployment Orchestration
│   ├── agentsight/         # AgentSight eBPF daemon config
│   ├── docker/             # vLLM & Gateway Dockerfiles
│   ├── k8s/                # Kubernetes Manifests (TPLs)
│   └── scripts/            # Management & Secret Mirroring
├── infra/                  # Infrastructure-as-Code (Terraform modular monorepo)
│   ├── modules/            # Reusable Terraform modules (gateway, redis_cache, etc.)
│   └── targets/            # Deployment targets (gcp-gke)
├── docs/                   # Engineering & Governance Docs
├── scripts/                # Development & Diagnostic Utilities
├── src/                    # Core Implementation
│   ├── agentsight-ui/      # React Frontend
│   ├── compliance_bridge/  # OSCAL compliance audit pipeline
│   ├── gateway/            # Hybrid inference gateway + reusable LangGraph governance harness
│   │   └── observability/  # Distributed MCP tracing (W3C traceparent extraction)
│   └── governed_financial_advisor/ # LangGraph Agent Plane
└── setup_test_env.sh       # OSS Environment Initializer
```

## Key Source Files

| File                                                          | Purpose                                                    |
| :------------------------------------------------------------ | :--------------------------------------------------------- |
| `src/gateway/server/hybrid_server.py`                         | FastAPI + FastMCP gateway with OTel instrumentation        |
| `src/gateway/observability/mcp_tracing.py`                    | W3C trace context extraction and distributed span creation |
| `src/governed_financial_advisor/infrastructure/mcp_client.py` | MCP client with traceparent injection                      |
| `src/gateway/governance/langgraph_harness/`                   | Reusable Factory/Builder nodes for NeMo and OPA            |
| `src/gateway/governance/symbolic_governor.py`                 | Neuro-symbolic governance engine                           |
| `src/gateway/governance/nemo/manager.py`                      | NeMo Guardrails integration                                |

## Governance Endpoints

### `POST /governance/validate-action`

Served by [`src/gateway/server/governance_middleware.py`](src/gateway/server/governance_middleware.py) and mounted under the `governance_app` FastAPI sub-application.

This is the **Single Choke Point** for all tool-level governance decisions — the Unified Gateway Governance path (Option 2). It is called by the GFA service and any future tool actuators instead of invoking OPA directly.

**Request body** (`ValidateActionRequest`):
```json
{
  "action": "execute_trade",
  "params": {
    "symbol": "AAPL",
    "amount": 5000.0,
    "confidence": 0.98,
    "trader_role": "analyst"
  }
}
```

**Governance tiers executed** (via [`SymbolicGovernor.validate_action()`](src/gateway/governance/symbolic_governor.py)) — full 7-tier pipeline via `_run_checks()`:

- **Tier 0 — STPA/STAMP UCA validation:** Runs for all tool names when `stpa_validator` is injected. Checks unsafe control actions (UCA-1 through UCA-6) against `governance_thresholds.json`.
- **Tier 1 — Agent confidence threshold pre-check:** `execute_trade` only. Fast-fails if `confidence < AGENT_CONFIDENCE_THRESHOLD` (default 0.95, env-overridable). Skips CBF/OPA round-trips when confidence is obviously below threshold.
- **Tier 2 — Control Barrier Function (CBF):** `execute_trade` only. Mathematical safety bounds check via Redis-backed cash balance verification (γ=0.5, min=$1,000) implemented in [`cbf.py`](src/gateway/governance/cbf.py). External ledger reconciliation via `AnchorageGrpcLedgerProvider` is a planned future enhancement (POAM-023); the current implementation uses Redis `WATCH/MULTI/EXEC` optimistic locking. `verify_action()` is **read-only** — it does not modify Redis state.
- **Tier 3 — OPA Rego policy evaluation:** All tool names. Declarative rule enforcement against the active regional compliance profile (`CAGE_DEPLOYMENT_REGION`). OPA circuit breaker: 5 failures → OPEN, 30s recovery, 3000ms hard latency budget. Redis decision cache: 10s TTL, SHA-256 keyed (`cage:opa:decision:{sha256_prefix}`), `OPA_CACHE_ENABLED` env var (default true). Cache is checked **before** the HTTP call; a hit short-circuits the entire round-trip. For `execute_trade`, CBF (Tier 2) and OPA (Tier 3) run **concurrently** via `asyncio.gather` to minimize latency.
- **Tier 4 — Fiscal Limit Pre-Reservation:** `execute_trade` only, when `fiscal_limit_guard` is injected and no prior violations exist. Atomically reserves the requested USD amount against the daily fiscal cap in Redis (`WATCH/MULTI/EXEC`) before the consensus gate. Closes the TOCTOU race between the CBF balance check and actual trade execution. Released immediately if any subsequent tier produces a violation.
- **Tier 5 — Multi-agent Consensus (ISO 42001 A.8.4):** `execute_trade` only, **conditional on amount ≥ $10,000 USD** (`consensus.threshold_usd` in `governance_thresholds.json`). Trades below $10,000 receive an immediate `SKIPPED` result with zero LLM calls. Above threshold: two critic personas (Risk Manager → DeepSeek-R1, Compliance Officer → Llama 3.1) are queried concurrently via `asyncio.gather`. Consensus rules: unanimous `APPROVE` → pass; unanimous `REJECT` → block; split vote or any `ESCALATE` → escalate for human review; unanimous `ERROR` → escalate (fail-closed, DoS bypass prevention). Results are pushed to a background audit queue (`_AUDIT_QUEUE`) for post-execution logging.
- **Tier 6 — DoWhy Causal Gatekeeper:** `execute_trade` only. Redis-cached by `(action_type, market_regime)` with a 60-second TTL (`CAUSAL_CACHE_TTL_SECONDS`); cache hits skip both phases entirely. On cache miss: Phase 1 runs DoWhy causal model + linear regression (SR 26-2 MRM scope); Phase 2 runs 50-simulation placebo refutation against live telemetry (ISO 42001 §A.9.4). Fails closed if telemetry is stale (> `TELEMETRY_MAX_STALENESS_SECONDS`, default 300s) or if `dowhy` is not installed (production startup raises `RuntimeError` if `dowhy` is absent).
- **Tier 6b — Adaptive FRIA Enforcement:** `execute_trade` only, when `CAGE_NORMATIVE_PROVIDER != "static"` and no prior violations exist. Confidence-score-gated: ≥ 0.95 → async attestation; 0.70–0.95 → synchronous blocking DEFER gate; < 0.70 → hard DENY. EU_ECB deployments additionally stamp FRIA attestation on every OTel span (EU AI Act Art. 29a / DORA Art. 10 logging obligation).

**Semantic similarity SLM (Tier 3 in legacy docs):** **DEPRECATED** — `slm_available=False` permanent sentinel; SLM sidecar retired. OPA Rego policy now handles semantic score thresholds.

**Tools exempt from all governance overhead:** `check_market_status` and `verify_content_safety` return an empty seal immediately in `enforce_governance()` without entering `_run_checks()`.

**Response** (on approval):
```json
{
  "verdict": "APPROVED",
  "violations": [],
  "seal": "<kms-asymmetric-routing-seal-hex>",
  "latency_ms": 12.4
}
```

**Response** (on denial — HTTP 403):
```json
{
  "verdict": "DENIED",
  "violations": ["OPA: policy denied 'execute_trade'"],
  "seal": "",
  "latency_ms": 0
}
```

**W3C Trace Context:** The GFA injects a `traceparent` header via `opentelemetry.propagate.inject(headers)`. This endpoint extracts it and attaches the incoming span context so that all `cage.validate_action` child spans are connected to the GFA's `cage.tool_execute` root span in Langfuse, producing a unified trace tree across the service boundary.

**Routing seal:** On approval, a short-lived `routing_seal` is returned — signed by Cloud KMS HSM (primary) or HMAC-SHA256 (dev/CI fallback). The downstream actuator **must** verify this seal before firing — ensuring execution cannot proceed by simply ignoring the HTTP response.

## Compliance Framework References

| Framework | Scope | Status |
|-----------|-------|--------|
| ISO/IEC 42001:2023 | Primary AI governance framework | Active |
| SR 26-2 (Federal Reserve, April 17, 2026) | Agentic AI model risk management | Active (default: US_FED) |
| EU AI Act Art. 29a | FRIA gating, 24h PII retention | Active (EU_ECB region) |
| GDPR Art. 22 | Automated decision-making | Active (EU_ECB region) |
| MAS FEAT Principles | Singapore-specific controls | Active (APAC_MAS region) |
| CSA AARM v1.0 | 11-vector AI agent threat model | Active |
| NIST SP 800-53 Rev 5 HIGH | 24% readiness; FedRAMP in progress | In Progress |
| OSCAL v1.0.4 | Artifact persistence to GCS | Active |
| Lula | 15 Lula validation manifests (4 Active, 11 Stub — see [`compliance/lula/README.md`](../compliance/lula/README.md)) | Active (4 of 15) |
