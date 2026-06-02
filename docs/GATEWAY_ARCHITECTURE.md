# Gateway Architecture: Sovereign Edition

## Overview

The Gateway acts as the central orchestrator and compliance enforcement point for the AI financial advisor. It implements a **Kubernetes Inference Gateway** architecture, abstracting a "Split-Brain" topology that routes tasks between a high-capacity Reasoning Model (`DeepSeek-R1-Distill-Llama-8B`) and a low-latency Governance Model (`Meta-Llama-3.1-8B-Instruct`). Both models are hosted on cost-optimized **Spot/preemptible GPU nodes** (NVIDIA L4). (GKE is the reference deployment; other Kubernetes distributions are supported)

## Core Components

1.  **Hybrid Gateway Service (FastAPI + FastMCP):**
    - Exposes a unified HTTP/MCP interface.
    - Handles tool execution requests (`execute_trade`, `search_market`).
    - Enforces neuro-symbolic policies via OPA and the Symbolic Governor.
    - **Reusable LangGraph Governance Harness:** Provides factory functions (`create_opa_safety_node`, `create_nemo_guardrail_node`) so any agent graph can implement standardized governance with domain-specific context extractors.
    - **NeMo Guardrails (PII & Semantic):** Enforces topical safety and masks PII (Presidio) on input/output directly within the service graph via the harness.

2.  **Sovereign vLLM Cluster:**
    - **Node A (Reasoning):** Handles planning, complex analysis, and chain-of-thought generation.
    - **Node B (Governance):** Handles rapid policy checks, safety filtering, and content moderation.

3.  **Observability Layer (Hybrid):**
    - **Application Tracing (Langfuse via OpenTelemetry):** Captures the execution graph, prompt templates, and tool inputs/outputs using OpenTelemetry GenAI Semantic Conventions (v1.36.0+). Generic application spans are natively mapped to Langfuse schemas via `langfuse.observation.*` and `langfuse.trace.metadata.*`. Uses an asynchronous OTLP Collector to minimize latency.
    - **Distributed MCP Tracing:** W3C `traceparent` is injected into MCP tool call arguments (`_otel_carrier`) by the client and extracted at the `ToolManager.call_tool()` level on the server. This bridges the SSE transport gap and produces parent-child spans across the protocol boundary.
    - **Scanner-Noise Filtering:** The `server_request_hook` uses an HTTP method allowlist (`GET`/`POST` only) and a path blocklist to silently drop vulnerability scanner probes from traces.
    - **System Monitoring (AgentSight):** An eBPF sidecar daemon that intercepts:
      - **Encrypted Traffic (OpenSSL):** Captures raw LLM payloads at the network boundary.
      - **System Calls (Kernel):** Monitors process creation (`execve`), file access (`openat`), and network connections (`connect`).
    - **Correlation:** The Gateway injects the OpenTelemetry `trace_id` as an `X-Trace-Id` HTTP header into every LLM request. AgentSight uses this header to link high-level intent (Langfuse trace) with low-level system actions.

## Data Flow

1.  **User Request:** Incoming HTTP/gRPC request to the Gateway.
2.  **Noise Filtering:** OTel `server_request_hook` drops scanner probes (non-GET/POST methods, known probe paths).
3.  **Policy Check (Pre-Execution):** OPA validates the request against regulatory policies.
4.  **Routing:** GatewayClient connects to the Kubernetes Inference Gateway, which routes to the target model (Reasoning vs. Governance).
5.  **Header Injection:** The client generates a trace ID and injects `X-Trace-Id`.
6.  **LLM Call:** Request is sent to vLLM. AgentSight intercepts this call.
7.  **MCP Tool Execution:** If the model requests a tool via MCP, the client injects `traceparent` and calls the Gateway. The Gateway extracts the context, creates a child span, and executes the tool.
8.  **Logging:**
    - Application metadata is sent asynchronously via OTLP to Langfuse.
    - System events are displayed in the AgentSight Dashboard.

## Deployment Topology

- **Production (Kubernetes):** Gateway runs as a service behind an Ingress. AgentSight runs as a DaemonSet or sidecar container in the same pod. (GKE is the reference deployment; other Kubernetes distributions are supported)
- **Local (Docker Compose):** All components run in a shared network. See `deployment/agentsight/docker-compose.agentsight.yaml`.

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
│   └── governed_financial_advisor/ # LangGraph Agent Plane
└── setup_dev.sh            # OSS Environment Initializer
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
