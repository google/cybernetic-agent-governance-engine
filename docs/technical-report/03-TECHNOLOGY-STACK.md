# 03 — Technology Stack

| Field                | Value                                                                    |
| -------------------- | ------------------------------------------------------------------------ |
| **Document Version** | 2.0                                                                      |
| **Date**             | 2026-06-01                                                               |
| **Classification**   | INTERNAL                                                                 |
| **Document Series**  | CAGE Technical Report                                                    |
| **Status**           | DRAFT — Pending AO Approval (GKE deployment verified 2026-06-03; 853 tests passing) |
| **Reference**        | `docs/GATEWAY_ARCHITECTURE.md`, `docs/INFERENCE_GATEWAY_ARCHITECTURE.md` |

---

## 1. Programming Languages

| Language                      | Version             | Role                                                                           | Primary Locations                                                                  |
| ----------------------------- | ------------------- | ------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------- |
| **Python**                    | ≥ 3.10, < 3.13      | Primary backend language; all agents, inference gateway, compliance bridge     | `src/gateway/`, `src/compliance_bridge/`, `src/governed_financial_advisor/agents/`  |
| **TypeScript / React**        | React 18 / TS 5.x   | AgentSight UI frontend                                                         | `src/agentsight-ui/`                                                               |
| **Rego**                      | OPA built-in        | Policy-as-code; symbolic governance enforcement                                | `trade.governance` package; `system.authz` package; `deployment/system_authz.rego` |
| **Colang 2.x**                | NeMo Guardrails 2.x | Dialog-flow safety rails and guardrail definitions                             | `config/rails/definitions.co`, `config/rails/main_logic.co`                        |
| **HCL (Terraform)**           | ≥ 1.5               | Infrastructure-as-code; GKE, IAM, secrets, storage provisioning                | `infra/modules/`, `infra/targets/`                                                 |
| **YAML**                      | —                   | Kubernetes manifests, OSCAL artifacts, Lula validations, Cloud Build pipelines | `deployment/k8s/`, `compliance/`                                                   |
| **Protocol Buffers (proto3)** | proto3              | gRPC interface definitions for gateway and NeMo communication                  | `src/agentsight-ui/gateway_protos/gateway.proto`, `src/gateway/protos/nemo.proto`                     |

---

## 2. Core Frameworks & Agent Orchestration

| Framework                   | Role                                   | Key Details                                                                                       |
| --------------------------- | -------------------------------------- | ------------------------------------------------------------------------------------------------- |
| **LangGraph**               | Multi-agent `StateGraph` orchestration | 10-node pipeline (including mandatory NeMo input/output rails); `interrupt_before=["governed_trader"]`; `AsyncRedisSaver` checkpointing |
| **FastAPI**                 | HTTP API server                        | Agent server `:8000`; Compliance Bridge `:3001`                                                   |
| **FastMCP**                 | MCP tool server over SSE               | 6 registered tools; `patch_mcp_tools()` injects W3C `traceparent` headers                         |
| **NeMo Guardrails**         | AI safety rails                        | Colang 2.x dialect; 15 Presidio PII entity types (input + output rails); model configurable via `GUARDRAILS_MODEL_NAME` |
| **Open Policy Agent (OPA)** | Rego policy enforcement                | `trade.governance` package; fail-closed posture; `CircuitBreaker` (5 failures, 30 s recovery)     |
| **LangChain**               | Agent tool-calling framework           | `create_tool_calling_agent`; LangChain OpenAI integration for model binding                       |

---

## 3. LLM Infrastructure

| Component               | Model                          | Details                                                                                |
| ----------------------- | ------------------------------ | -------------------------------------------------------------------------------------- |
| **vLLM Reasoning Node** | `DeepSeek-R1-Distill-Llama-8B` | AWQ quantization; `max_model_len=32768`; `gpu_memory_utilization=0.9`; NVIDIA L4 24 GB; active Risk Manager in ConsensusEngine |
| **vLLM Fast Node**      | `Meta-Llama-3.1-8B-Instruct`   | OpenAI-compatible endpoint; spot instances; low-latency path; active Compliance Officer in ConsensusEngine |
| **vLLM Governance**     | `Qwen/Qwen2.5-7B-Instruct`     | **NOT CURRENTLY DEPLOYED** — aspirational governance backend (`vllm-governance.yaml` explicitly marked undeployed) |
| **liteLLM**             | LLM router                     | `MODEL_REASONING` and `MODEL_FAST` aliasing; unified API surface                       |
| **vLLM Tensorizer**     | Cold-start optimization        | Model weight streaming from MinIO; eliminates cold-boot latency                        |
| **Guided JSON (FSM)**   | Structured output              | Enforced at vLLM level for `ExecutionPlan` schema compliance                           |

---

## 4. Python Library Dependencies

### Agent / AI

| Library            | Purpose                                       |
| ------------------ | --------------------------------------------- |
| `langchain-openai` | LangChain OpenAI provider binding             |
| `langgraph`        | StateGraph multi-agent orchestration          |
| `langfuse`         | LLM observability; audit trace ingestion      |
| `nemoguardrails`   | NeMo Guardrails runtime                       |
| `openai`           | OpenAI-compatible REST client (vLLM endpoint) |
| `google-adk`       | Google Agent Development Kit (≥1.28.1); advisor extras |

### Privacy / Safety

| Library               | Purpose                                                                  |
| --------------------- | ------------------------------------------------------------------------ |
| `presidio-analyzer`   | Microsoft Presidio PII detection; **15 entity types**; `score_threshold=0.3` |
| `presidio-anonymizer` | PII anonymization and redaction before LLM submission                    |

### Policy

| Library             | Purpose                                               |
| ------------------- | ----------------------------------------------------- |
| `opa-python-client` | Programmatic OPA policy evaluation from Python agents |

### Observability

| Library                                   | Purpose                                                                 |
| ----------------------------------------- | ----------------------------------------------------------------------- |
| `opentelemetry-sdk`                       | Core OpenTelemetry trace and span API                                   |
| `opentelemetry-exporter-otlp-proto-grpc`  | OTLP gRPC/HTTP export directly to Langfuse (collector deprecated)       |
| `opentelemetry-instrumentation-fastapi`   | Auto-instrumentation for FastAPI endpoints                              |
| `opentelemetry-instrumentation-langchain` | Auto-instrumentation for LangChain agent calls                          |

### Data Validation

| Library       | Purpose                                                                     |
| ------------- | --------------------------------------------------------------------------- |
| `pydantic` v2 | Schema validation; all domain models use `BaseModel` with `field_validator` |

### State / Cache

| Library              | Purpose                                                                      |
| -------------------- | ---------------------------------------------------------------------------- |
| `aioredis` / `redis` | Async Redis client; `AsyncRedisSaver` for LangGraph checkpoints              |
| `cachetools`         | `TTLCache(maxsize=32, ttl=300)` — 5-minute compliance metric cache in bridge |

### HTTP

| Library     | Purpose                                                            |
| ----------- | ------------------------------------------------------------------ |
| `httpx`     | Pooled async HTTP client; `max_connections=50`, `max_keepalive=20` |
| `httpx-sse` | SSE client for MCP transport over HTTP                             |

### Market Data

| Library    | Purpose                                                                |
| ---------- | ---------------------------------------------------------------------- |
| `yfinance` | 1-month price history; latest close price; top 3 news items per symbol |

### Pipeline / Orchestration

| Library | Purpose                                                  |
| ------- | -------------------------------------------------------- |
| `kfp`   | Kubeflow Pipelines SDK; `governance_pipeline` definition |

### Pattern Matching

| Library         | Purpose                                                |
| --------------- | ------------------------------------------------------ |
| `pyahocorasick` | Aho-Corasick Tier-1 keyword scan; 14 governed keywords |

### Cryptography

| Library              | Purpose                                                                                   |
| -------------------- | ----------------------------------------------------------------------------------------- |
| `google-cloud-kms`   | **Primary** governance signing — Cloud KMS HSM-backed asymmetric RSA-4096 signatures; non-repudiation for all governance decisions |
| `hmac`               | **Fallback** HMAC-SHA256 routing seal (`X-CAGE-Routing-Seal`) and governance signature; used when `CAGE_KMS_KEY_NAME` is unset (dev/CI only) |
| `hashlib`            | Digest backend for HMAC and SHA-256 hash-chain operations                                 |

### gRPC

| Library        | Purpose                                     |
| -------------- | ------------------------------------------- |
| `grpcio`       | gRPC runtime for gateway ↔ UI communication |
| `grpcio-tools` | Proto compilation toolchain                 |
| `protobuf`     | Protocol Buffers serialization runtime      |

### Removed / Deprecated Libraries

| Library        | Status                                                                                                   |
| -------------- | -------------------------------------------------------------------------------------------------------- |
| ~~`outlines`~~ | **REMOVED** — CVE-2025-69872 (critical vulnerability). Structured output now enforced via vLLM FSM natively. |
| ~~SLM sidecar~~| **DEPRECATED** — `slm_available=False` permanent sentinel injected into OPA payload; 0ms overhead; Tier 3 bypassed to optimize latency budget. |

### Known Environment Issues

| Issue | Resolution |
| ----- | ---------- |
| `typer` corrupted namespace stub (`No module named typer.main`) | **Resolved 2026-06-03** — Reinstall `typer>=0.9.0` via `pip install --force-reinstall "typer>=0.9.0"`. The corrupted stub caused `presidio_analyzer` import failure and `OperatorConfig NameError` in NeMo SDD actions, blocking `test_pii_integration.py`. |

---

## 5. Vendor Integrations (`src/integrations/`)

Third-party compliance provider adapters are architecturally isolated in `src/integrations/{vendor}/` to prevent vendor SDK code from leaking into the governance kernel. Each adapter implements the `NormativeProvider` interface defined in `src/gateway/governance/normative_provider.py`.

| Integration          | Root Path                        | Purpose                                                                                                   | Status                  |
| -------------------- | -------------------------------- | --------------------------------------------------------------------------------------------------------- | ----------------------- |
| **TrustLayers**      | `src/integrations/trustlayers/`  | Production normative provider; `TrustLayersProvider` implements 3-endpoint external validation API; activated via `CAGE_NORMATIVE_PROVIDER=trustlayers` | Implemented (POAM-022 In Progress — awaiting API credentials) |
| **NexArt**           | `src/integrations/nexart/`       | CER (Compliance Evidence Record) attestation provider; `NexArtClient` + `NexArtAttestationCallback` (LangGraph callback handler) in `adapter.py`; `NexArtProvider` (NormativeProvider interface) in `provider.py` | Implemented             |

> **Vendor Isolation Design:** Infrastructure invariants (Cloud KMS, Redis, OPA) remain in `src/gateway/governance/`. Vendor adapters are lazy-loaded and never imported by the governance kernel directly — they are registered via the `normative_provider` factory at startup based on `CAGE_NORMATIVE_PROVIDER` environment variable.

---

## 6. Frontend Stack (AgentSight UI)

| Technology            | Role                  | Details                                                                            |
| --------------------- | --------------------- | ---------------------------------------------------------------------------------- |
| **React 18**          | UI framework          | TypeScript; functional components; hooks-based state management                    |
| **Vite**              | Build tool            | Dev server `:5173`; configuration in `src/agentsight-ui/vite.config.ts`                              |
| **TypeScript**        | Type safety           | Strict mode enabled; `src/agentsight-ui/tsconfig.app.json`                                           |
| **Zod**               | Schema validation     | `GovernanceCode` schema validation at runtime boundary                             |
| **SSE (EventSource)** | Real-time events      | Consumes `{BACKEND_URL}/v1/events/stream`; 5 s polling fallback on connection loss |
| **protobuf-js**       | Proto deserialization | `src/protos/gateway.js`, `src/agentsight-ui/src/protos/gateway.ts`                                   |

**Phase 1 additions (v2.0.0-rc.1):** [`KernelDashboard.tsx`](../../src/agentsight-ui/src/KernelDashboard.tsx) adds `useCallback` for `saveSlippage` (POSTs to `/api/governance/thresholds`), a 1-second `setInterval` tick for HITL TTL countdown, `formatCountdown()` and `priceDrift()` helper functions, and extended `TelemetryItem` / `GovernanceEvent` interfaces with `hitl_expires_at`, `price_fresh`, `price_stale` fields. [`KernelDashboard.css`](../../src/agentsight-ui/src/KernelDashboard.css) adds `.slippage-control`, `.drift-badge` (with `drift-pulse` animation), `.hitl-ttl`, and `.hitl-ttl-expired` styles.

---

## 7. Infrastructure & Platform

| Technology                          | Role                   | Details                                                                                               |
| ----------------------------------- | ---------------------- | ----------------------------------------------------------------------------------------------------- |
| **Google Kubernetes Engine (GKE)**  | Runtime platform       | `governance-stack` namespace; 9 `NetworkPolicy` objects; default-deny posture                         |
| **Terraform**                       | Infrastructure-as-code | `infra/modules/` (16 shared modules) + `infra/targets/` (`agnostic/`, `gcp-gke/`)                     |
| **Docker**                          | Containerization       | Multi-stage builds; `Dockerfile`, `Dockerfile.vllm`, `Dockerfile.lula-*`                              |
| **Google Cloud Build**              | CI/CD                  | `cloudbuild_gateway.yaml`, `cloudbuild.vllm.yaml`, `cloudbuild.lula.yaml`                             |
| **uv / uv_build**                   | Build system           | `uv_build>=0.8.14`; fast Python package installer and build backend                                   |
| **Kubernetes Secrets**              | Secret storage         | Kubernetes-native `Secret` objects provisioned via Terraform (`infra/modules/app_secrets/`); no runtime GCP Secret Manager dependency |
| **Google Cloud Storage (GCS)**      | Artifact storage       | **Primary** storage SDK (`google-cloud-storage>=2.0.0`); OSCAL assessment results; model artifacts; configurable via `STORAGE_BACKEND` |
| **MinIO / boto3**                   | S3-compatible storage  | `boto3>=1.35.0` S3-compat fallback; source for vLLM Tensorizer cold-start weight streaming            |
| **NVIDIA L4 GPU**                   | GPU compute            | 24 GB VRAM; AWQ quantization; spot instances for cost optimisation                                    |
| **Kubernetes Inference Gateway**    | LLM routing            | nginx `GatewayClass`; see ADR-002 for migration from GKE GCE load balancer                            |

---

## 8. Data Stores

| Store                   | Technology                     | Purpose                                                                    |
| ----------------------- | ------------------------------ | -------------------------------------------------------------------------- |
| **State / Checkpoints** | Redis (`AsyncRedisSaver`)      | LangGraph graph checkpoints; HITL interrupt state persistence              |
| **CBF Cash Balance**    | Redis (`WATCH`/`MULTI`/`EXEC`) | Atomic Control Barrier Function enforcement; prevents balance overrun      |
| **Compliance Cache**    | `TTLCache` (in-memory)         | 5-minute TTL per compliance control metric; reduces OPA round-trips        |
| **Audit Logs**          | Langfuse (self-hosted v3, ClickHouse + MinIO) | 7-year retention policy; OTLP gRPC ingestion; dual-project configuration; standalone OTel Collector deprecated 2026-05-31 |
| **OSCAL Results**       | GCS / local / S3               | OSCAL Assessment Results artifacts; backend selected via `STORAGE_BACKEND` |
| **Market Data**         | `yfinance` (real-time)         | 1-month price history on demand; no persistent store                       |

---

## 9. Observability Stack

| Component               | Technology                                | Details                                                                                                                    |
| ----------------------- | ----------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| **Distributed Tracing** | OpenTelemetry SDK                         | OTLP/HTTP export direct to Langfuse OTLP endpoint (`http://langfuse-web:3000/api/public/otel/v1/traces`); `FastAPIInstrumentor`, `LangchainInstrumentor` auto-instrumentation |
| ~~**Trace Collector**~~ | ~~`opentelemetry-collector-contrib`~~     | **Deprecated 2026-05-31.** Services now export OTLP directly to Langfuse integrated OTLP ingestion; standalone collector removed from deployment. |
| **Compliance Metrics**  | Langfuse                                  | Dual-project setup; `TTLCache(maxsize=32, ttl=300)` for metric caching                                                    |
| **Real-time Events**    | Server-Sent Events (SSE)                  | `GovernanceEventBus`; `asyncio.Queue(maxsize=128)` back-pressure                                                          |
| **Kernel Monitoring**   | eBPF DaemonSet (AgentSight)               | OpenSSL uprobes; syscall interception; `python3` process targeting                                                         |
| **Sampling**            | 1% general / 100% governance              | Per RA-001 risk acceptance; all governance decisions sampled at 100%                                                       |

---

## 10. Compliance & Standards Tooling

| Tool                                      | Purpose                           | Details                                                                               |
| ----------------------------------------- | --------------------------------- | ------------------------------------------------------------------------------------- |
| **Lula**                                  | OSCAL automated validation        | `CronJob` every 6 h; Kubernetes domain checks; writes OSCAL Assessment Results to GCS |
| **OSCAL v1.0.4**                          | Machine-readable compliance       | `component-definition.yaml`; System Security Plan (SSP); profile overlay              |
| **Kubeflow Pipelines (KFP)**              | Governance pipeline orchestration | `governance_pipeline`; triggered via `POST /v1/refinement/trigger` or `POST /v1/webhooks/langfuse`, applies hot-reloads via `POST /v1/nemo/apply-refinement` |
| **`scripts/generate_sbom.py`**            | SBOM generation                   | Daily CronJob; RA-003 risk acceptance for per-build frequency                         |
| **`scripts/deontic_policy_extractor.py`** | Policy derivation                 | Automated law → Rego / NeMo transpilation input pipeline                              |

---

## 11. Protocols & Standards

| Protocol / Standard            | Usage                                                                             |
| ------------------------------ | --------------------------------------------------------------------------------- |
| **gRPC (proto3)**              | Gateway ↔ AgentSight UI; `Chat` and `ExecuteTool` RPCs defined in `src/gateway/protos/gateway.proto` |
| **OpenAI-compatible REST API** | vLLM endpoint; `POST /v1/chat/completions` used by all model consumers            |
| **Server-Sent Events (SSE)**   | MCP transport (`FastMCP`); compliance event streaming from `GovernanceEventBus`   |
| **W3C Traceparent**            | Distributed trace propagation across the MCP SSE boundary via `patch_mcp_tools()` |
| **Cloud KMS (RSA-4096-SHA256)**| **Primary** governance signing — HSM-backed asymmetric signatures; non-repudiation for all governance decisions |
| **HMAC-SHA256**                | **Fallback** routing seal (`X-CAGE-Routing-Seal` header); governance signature on `AgentState` (dev/CI only when KMS unavailable) |
| **OTLP (gRPC)**                | OpenTelemetry → Langfuse ingestion; all trace and span export                     |
| **ISO-20022**                  | Banking payments standard; drives the 200 ms end-to-end latency SLA               |
| **OSCAL v1.0.4**               | NIST-standard machine-readable compliance artifact format                         |
