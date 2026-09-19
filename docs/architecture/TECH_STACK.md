# Technology Stack & Bill of Materials

| Field                | Value                                                                    |
| -------------------- | ------------------------------------------------------------------------ |
| **Document Version** | 3.0.1                                                                    |
| **Date**             | 2026-09-09                                                               |
| **Classification**   | INTERNAL                                                                 |
| **Document Series**  | CAGE Architecture Specification                                          |
| **Status**           | ACTIVE — v3.0.1 stable (GKE deployment verified; baseline: 2,553 passing core unit tests; 4,148 tests collected / 3,921 passed, 0 failed) |
| **Canonical Path**   | `docs/architecture/TECH_STACK.md`                                        |
| **References**       | [`GATEWAY_ARCHITECTURE.md`](GATEWAY_ARCHITECTURE.md), [`AGENT_SYSTEM_ARCHITECTURE.md`](AGENT_SYSTEM_ARCHITECTURE.md) |

---

## 1. Programming Languages

| Language                      | Version             | License        | Role                                                                           | Governance Justification & Primary Locations                                       |
| ----------------------------- | ------------------- | -------------- | ------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------- |
| **Python**                    | $\ge 3.10, < 3.13$  | PSF License    | Primary backend language; all agents, inference gateway, compliance bridge     | Broad ecosystem for agent orchestration, typing, async I/O; `src/gateway/`, `src/compliance_bridge/`, `src/governed_financial_advisor/` |
| **TypeScript / React**        | React 18 / TS 5.x   | MIT            | AgentSight UI frontend                                                         | Strict type safety for governance dashboard state; `src/agentsight-ui/`            |
| **Rego**                      | OPA built-in        | Apache-2.0     | Policy-as-code; symbolic governance enforcement                                | Declarative, side-effect-free policy evaluation; `trade.governance` package; `deployment/system_authz.rego` |
| **Colang 2.x**                | NeMo Guardrails 2.x | Apache-2.0     | Dialog-flow safety rails and guardrail definitions                             | Event-driven conversational safety rails; `config/rails/definitions.co`, `config/rails/main_logic.co` |
| **HCL (Terraform)**           | $\ge 1.5$           | MPL-2.0 / BSL  | Infrastructure-as-code; GKE, IAM, secrets, storage provisioning                | Reproducible, auditable cloud topology; `infra/modules/`, `infra/targets/`         |
| **YAML**                      | —                   | —              | Kubernetes manifests, OSCAL artifacts, Lula validations, Cloud Build pipelines | Industry standard declarative configuration; `deployment/k8s/`, `compliance/`      |
| **Protocol Buffers (proto3)** | proto3              | BSD-3-Clause   | gRPC interface definitions for gateway and NeMo communication                  | Strongly typed, backward-compatible cross-process communication; [`src/gateway/protos/gateway.proto`](../../src/gateway/protos/gateway.proto) |

---

## 2. Core Frameworks & Agent Orchestration

| Framework                   | License    | Role                                   | Governance Justification & Key Details                                                                                       |
| --------------------------- | ---------- | -------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| **LangGraph**               | MIT        | Multi-agent `StateGraph` orchestration | Deterministic cyclic state machine; supports `interrupt_before` for HITL and `AsyncRedisSaver` checkpoint persistence         |
| **FastAPI**                 | MIT        | HTTP API server                        | High-performance ASGI server with OpenAPI schema generation; agent server `:8081/:80`, compliance bridge `:3001/:3002`       |
| **FastMCP**                 | MIT        | MCP tool server over SSE               | Model Context Protocol implementation with W3C `traceparent` distributed trace propagation                                    |
| **NeMo Guardrails**         | Apache-2.0 | AI safety rails                        | Programmable conversational safety rails; 10 Presidio PII entity types; configurable via `GUARDRAILS_MODEL_NAME`             |
| **Open Policy Agent (OPA)** | Apache-2.0 | Rego policy enforcement                | Deterministic, sub-millisecond RBAC and deontic constraints; fail-closed `CircuitBreaker` (5 failures, 30s recovery)         |
| **LangChain**               | MIT        | Agent tool-calling framework           | Standardized tool binding and schema translation for heterogeneous models                                                    |

---

## 3. LLM Infrastructure (Sovereign Local Stack)

CAGE operates a sovereign, local LLM serving topology using containerized vLLM instances to maintain jurisdictional data residency and eliminate vendor data leakage:

| Component               | Model                          | Quantization / Sizing                   | Role & Governance Justification                                                                |
| ----------------------- | ------------------------------ | --------------------------------------- | ---------------------------------------------------------------------------------------------- |
| **vLLM Reasoning Node** | `DeepSeek-R1-Distill-Llama-8B` | AWQ; `max_model_len=32768`; NVIDIA L4   | Deep reasoning for complex investment theses; active Risk Manager in `ConsensusEngine`         |
| **vLLM Fast Node**      | `Meta-Llama-3.1-8B-Instruct`   | Unquantized / FP16; spot L4 instances  | Low-latency instruction decomposition and reporting; active Compliance Officer in ConsensusEngine |
| **vLLM Governance**     | `Qwen/Qwen2.5-1.5B-Instruct`   | Reference profile (undeployed)          | Compact model for dedicated classification tasks (`vllm-governance.yaml`)                      |
| **liteLLM**             | LLM Router                     | In-memory proxy                         | Abstract routing between `MODEL_REASONING` and `MODEL_FAST` endpoints                          |
| **vLLM Tensorizer**     | Cold-Start Streaming           | MinIO weight streaming                  | Sub-minute cold-start container initialization without baked-in model weights                  |
| **Guided JSON (FSM)**   | Structured Output Engine       | vLLM native regex/schema FSM            | Eliminates JSON syntax errors at generation time, replacing deprecated `outlines` library      |

---

## 4. Python Library Dependencies

### 4.1 Agent / AI

| Library            | License    | Purpose & Governance Justification                                    |
| ------------------ | ---------- | --------------------------------------------------------------------- |
| `langchain-openai` | MIT        | Provider binding for OpenAI-compatible vLLM endpoints                 |
| `langgraph`        | MIT        | Cyclic graph orchestration and durable execution checkpointing        |
| `langfuse`         | MIT        | Sovereign LLM observability, audit trace ingestion, score tracking   |
| `nemoguardrails`   | Apache-2.0 | Dialog safety rails, programmable topic blocking, and jailbreak guard |
| `openai`           | Apache-2.0 | Async client for local vLLM OpenAI-compatible endpoints               |
| `google-adk`       | Apache-2.0 | Google Agent Development Kit ($\ge 1.28.1$); advisor tooling extras    |

### 4.2 Privacy / Safety

| Library               | License    | Purpose & Governance Justification                                                                  |
| --------------------- | ---------- | --------------------------------------------------------------------------------------------------- |
| `presidio-analyzer`   | MIT        | Microsoft Presidio PII detection; 10 entity types configured in `config/rails/config.yml`           |
| `presidio-anonymizer` | MIT        | PII anonymization and masking before LLM submission and after response generation                  |

### 4.3 Policy & Causal

| Library             | License    | Purpose & Governance Justification                                                                   |
| ------------------- | ---------- | ---------------------------------------------------------------------------------------------------- |
| `opa-python-client` | Apache-2.0 | Programmatic OPA evaluation from Python agents                                                       |
| `dowhy`             | MIT        | Causal inference engine for Tier 6 causal gatekeeper (counterfactual refutation & slope invariance) |

### 4.4 Observability

| Library                                   | License    | Purpose & Governance Justification                                    |
| ----------------------------------------- | ---------- | --------------------------------------------------------------------- |
| `opentelemetry-sdk`                       | Apache-2.0 | Core OpenTelemetry trace and span creation                            |
| `opentelemetry-exporter-otlp-proto-grpc`  | Apache-2.0 | Direct OTLP export to Langfuse (collector deprecated 2026-05-31)      |
| `opentelemetry-instrumentation-fastapi`   | Apache-2.0 | Automatic HTTP span generation for inbound gateway requests           |
| `opentelemetry-instrumentation-langchain` | Apache-2.0 | Automatic trace propagation across LangChain and LangGraph executions |

### 4.5 Data Validation & Serialization

| Library       | License    | Purpose & Governance Justification                                                   |
| ------------- | ---------- | ------------------------------------------------------------------------------------ |
| `pydantic` v2 | MIT        | Strict runtime type validation and JSON schema export across all domain models       |
| `canonicaljson` / RFC 8785 | Apache-2.0 | Deterministic JSON Canonicalization Scheme (JCS) for tamper-evident hash calculation |

### 4.6 State, Caching & Concurrency

| Library              | License    | Purpose & Governance Justification                                                |
| -------------------- | ---------- | --------------------------------------------------------------------------------- |
| `aioredis` / `redis` | MIT        | Async Redis client; `AsyncRedisSaver`, Lua atomic CBF, and FiscalLimitGuard locks |
| `cachetools`         | MIT        | `TTLCache(maxsize=32, ttl=300)` — 5-minute compliance metric cache in bridge      |

### 4.7 HTTP & Networking

| Library     | License    | Purpose & Governance Justification                                  |
| ----------- | ---------- | ------------------------------------------------------------------- |
| `httpx`     | BSD-3-Clause | Pooled async HTTP client; `max_connections=50`, `max_keepalive=20` |
| `httpx-sse` | MIT        | Server-Sent Events client for FastMCP streaming transport           |

### 4.8 Market Data

| Library    | License    | Purpose & Governance Justification                                              |
| ---------- | ---------- | ------------------------------------------------------------------------------- |
| `yfinance` | Apache-2.0 | 1-month historical OHLCV and real-time market quotes for financial domain agent |

### 4.9 Pipeline & Pattern Matching

| Library         | License    | Purpose & Governance Justification                                    |
| --------------- | ---------- | --------------------------------------------------------------------- |
| `kfp`           | Apache-2.0 | Kubeflow Pipelines SDK; `governance_pipeline` definition              |
| `pyahocorasick` | BSD-3-Clause | Fast multi-keyword string matching for Tier 1 Aho-Corasick safety scan |

### 4.10 Cryptography & KMS Providers

| Library               | License    | Purpose & Governance Justification                                                   |
| --------------------- | ---------- | ------------------------------------------------------------------------------------ |
| `google-cloud-kms`    | Apache-2.0 | **GCP** governance signing — Cloud KMS HSM-backed RSA-4096 (`GCPKMSProvider`)        |
| `boto3`               | Apache-2.0 | **AWS** governance signing — AWS KMS HSM provider (`AWSKMSProvider`)                  |
| `azure-keyvault-keys` | MIT        | **Azure** governance signing — Azure Key Vault Managed HSM provider (`AzureKMSProvider`) |
| `cryptography`        | Apache-2.0 / BSD | Low-level cryptographic primitives (Ed25519 CER verification, RSA verify)       |
| `hashlib` / `hmac`    | PSF        | Standard library digest implementations for SHA-256 hash chains and dev-mode HMAC    |

### 4.11 gRPC Toolchain

| Library        | License      | Purpose & Governance Justification                          |
| -------------- | ------------ | ----------------------------------------------------------- |
| `grpcio`       | Apache-2.0   | High-performance gRPC runtime for gateway inter-service IPC |
| `grpcio-tools` | Apache-2.0   | Protocol buffer compiler for Python stubs                   |
| `protobuf`     | BSD-3-Clause | Google Protocol Buffers runtime                             |

### 4.12 Removed & Deprecated Libraries

| Component / Library | Status         | Rationale & Mitigation                                                                    |
| ------------------- | -------------- | ----------------------------------------------------------------------------------------- |
| ~~`outlines`~~      | **REMOVED**    | Critical CVE-2025-69872. Replaced with native vLLM FSM guided decoding.                   |
| ~~OTel Collector~~  | **DEPRECATED** | Removed in favor of direct OTLP gRPC export from application pods to Langfuse web service.|

---

## 5. Vendor & Partner Integrations (`src/integrations/`)

Third-party compliance, attestation, and actuator provider adapters live in `src/integrations/{provider_id}/`. They are strictly isolated from the Layer 1 governance kernel.

| Integration     | Root Path                       | Purpose                                                                                                   | Status      |
| --------------- | ------------------------------- | --------------------------------------------------------------------------------------------------------- | ----------- |
| **Provider 01** | `src/integrations/provider_01/` | Production normative provider; implements 3-endpoint normative validation API via `Provider01NormativeProvider` | Implemented (POAM-022 awaiting credentials) |
| **Provider 02** | `src/integrations/provider_02/` | CER (Compliance Evidence Record) attestation provider; `Provider02Client` + `Provider02AttestationCallback` | Implemented |
| **Provider 03** | `src/integrations/provider_03/` | JCS (RFC 8785) evidence normalization and decision governance adapter                                     | Implemented |
| **Provider 05** | `src/integrations/provider_05/` | Verifiable Execution Evidence Pack; RFC-3161 cryptographic evidence packages with 3 axioms               | Implemented |
| **Provider 06** | `src/integrations/provider_06/` | Tri-state deterministic verifier adapter (`PASS`/`REVIEW`/`BLOCKED`) with DeferQueue parking integration | Implemented |
| **Actuator 01** | `src/integrations/actuator_01/` | Actuator-side vendor adapter; envelope builder and signature verification for sealed execution            | Implemented |
| **Storage GCS** | `src/integrations/storage_gcs/` | Google Cloud Storage cold-store backend for evidence archives                                             | Implemented |
| **Storage S3**  | `src/integrations/storage_s3/`  | AWS S3 / MinIO cold-store backend for evidence archives                                                   | Implemented |

### 5.1 Vendor Adapter Architecture Standards
1. **Vendor Isolation**: Vendor code must never import into `src/gateway/`.
2. **Seam Implementation**: Synchronous gate adapters implement `NormativeProvider` (`fetch_baseline`, `validate_fria`, `submit_evidence`).
3. **Universal Protocol Conformance**: Parameterized conformance suite in `tests/test_normative_provider_conformance.py` verifies contract adherence.
4. **Tri-State / Review Mapping**: Upstream non-binary verdicts (`REVIEW`, `ESCALATE`) map to `ValidationResult(admitted=False, findings=[{"needs_human_review": True, ...}])` for parking in `DeferQueue`.
5. **Fail-Closed Semantics**: Network timeouts, parsing failures, and HTTP errors always fail closed.
6. **Sidecar & UDS Architecture**: Production high-throughput adapters run as sidecar containers over Unix Domain Sockets (UDS) for sub-millisecond latency.
7. **Hermetic Testing**: All unit tests run against mock clients (`respx`); no live external API calls in PR CI.

---

## 6. Frontend Stack (AgentSight UI)

| Technology            | License | Role                  | Details                                                                            |
| --------------------- | ------- | --------------------- | ---------------------------------------------------------------------------------- |
| **React 18**          | MIT     | UI framework          | TypeScript; functional components; hooks-based state management                    |
| **Vite**              | MIT     | Build tool            | Dev server `:5173`; config in `src/agentsight-ui/vite.config.ts`                   |
| **TypeScript**        | Apache-2.0 | Type safety        | Strict mode enabled; `src/agentsight-ui/tsconfig.app.json`                         |
| **Zod**               | MIT     | Schema validation     | Runtime boundary validation for `GovernanceCode` and API payloads                  |
| **SSE (EventSource)** | Web Std | Real-time events      | Consumes `{BACKEND_URL}/v1/events/stream` with 5s polling fallback                  |
| **protobuf-js**       | BSD-3-Clause | Proto deserialization | Deserialization of binary governance protobuf events in browser                    |

---

## 7. Infrastructure & Platform

| Technology                          | Role                   | Details                                                                                               |
| ----------------------------------- | ---------------------- | ----------------------------------------------------------------------------------------------------- |
| **Google Kubernetes Engine (GKE)**  | Runtime platform       | `governance-stack` namespace; 9 `NetworkPolicy` objects; default-deny posture                         |
| **Cilium / GKE Dataplane V2**       | L7 network policy CNI  | `CiliumNetworkPolicy` in `deployment/k8s/cilium/`; FQDN allowlist enforcement via eBPF DNS proxy       |
| **Terraform**                       | Infrastructure-as-code | `infra/modules/` (16 shared modules) + `infra/targets/` (`agnostic/`, `gcp-gke/`)                     |
| **Docker**                          | Containerization       | Multi-stage builds; `Dockerfile`, `Dockerfile.vllm`, `Dockerfile.lula-*`                              |
| **Google Cloud Build**              | CI/CD                  | Dot notation: `cloudbuild.gateway.yaml`, `cloudbuild.vllm.yaml`, `cloudbuild.lula.yaml`              |
| **uv / uv_build**                   | Build system           | Fast Python package installer, lockfile resolver, and build backend                                  |
| **Kubernetes Secrets**              | Secret storage         | Kubernetes-native `Secret` objects provisioned via Terraform; no runtime secret manager dependency    |
| **Google Cloud Storage (GCS)**      | Artifact storage       | Primary storage SDK (`google-cloud-storage`); OSCAL assessment results and WORM audit records         |
| **MinIO / boto3**                   | S3-compatible storage  | S3-compatible fallback; source for vLLM Tensorizer cold-start weight streaming                        |
| **NVIDIA L4 GPU**                   | GPU compute            | 24 GB VRAM; AWQ quantization; spot instances for cost optimization                                    |
| **Kubernetes Inference Gateway**    | LLM routing            | Nginx `GatewayClass` with load balancing and path routing                                             |

---

## 8. Data Stores

| Store                   | Technology                     | Purpose & Invariants                                                       |
| ----------------------- | ------------------------------ | -------------------------------------------------------------------------- |
| **State / Checkpoints** | Redis (`AsyncRedisSaver`)      | LangGraph graph checkpoints; HITL interrupt state persistence              |
| **CBF Cash Balance**    | Redis (Lua script check+commit)| Atomic Control Barrier Function enforcement (`atomic_verify_and_commit.lua`) |
| **Compliance Cache**    | `TTLCache` (in-memory)         | 5-minute TTL per compliance control metric; reduces OPA round-trips        |
| **Audit Logs**          | Langfuse (ClickHouse + MinIO)  | 7-year retention policy; OTLP gRPC ingestion; dual-project sovereign telemetry|
| **OSCAL Results**       | GCS / S3 / local               | OSCAL Assessment Results artifacts; backend selected via `STORAGE_BACKEND` |
| **Market Data**         | `yfinance` (real-time)         | 1-month price history on demand; no persistent database storage            |

---

## 9. Observability Stack

| Component               | Technology                   | Details                                                                                                                    |
| ----------------------- | ---------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| **Distributed Tracing** | OpenTelemetry SDK            | Direct OTLP/HTTP export to Langfuse (`http://langfuse-web:3000/api/public/otel/v1/traces`); auto-instrumentation          |
| **Compliance Metrics**  | Langfuse                     | Dual-project setup; sovereign regional telemetry instances (`us-central1`, `europe-west1`, `asia-southeast1`)               |
| **Real-time Events**    | Server-Sent Events (SSE)     | `GovernanceEventBus`; `asyncio.Queue(maxsize=128)` back-pressure                                                          |
| **Kernel Monitoring**   | eBPF DaemonSet (AgentSight)  | OpenSSL uprobes; syscall interception; `python3` process targeting                                                         |
| **Sampling**            | 1% general / 100% governance | All governance decisions sampled at 100%; general traces sampled at 1%                                                     |

---

## 10. Compliance & Standards Tooling

| Tool                                      | Purpose                           | Details                                                                               |
| ----------------------------------------- | --------------------------------- | ------------------------------------------------------------------------------------- |
| **Lula**                                  | OSCAL automated validation        | `CronJob` every 6 h; Kubernetes domain checks; writes OSCAL Assessment Results to GCS |
| **OSCAL v1.0.4**                          | Machine-readable compliance       | `component-definition.yaml`; System Security Plan (SSP); profile overlay              |
| **Kubeflow Pipelines (KFP)**              | Governance pipeline orchestration | `governance_pipeline`; automated retraining and hot-reloads via NeMo endpoints        |
| **`scripts/generate_sbom.py`**            | SBOM generation                   | Automated CycloneDX/SPDX SBOM generation script                                       |
| **`scripts/deontic_policy_extractor.py`** | Policy derivation                 | Automated regulatory text $\to$ Rego / NeMo policy compilation pipeline               |

---

## 11. Protocols & Standards

| Protocol / Standard            | Usage                                                                             |
| ------------------------------ | --------------------------------------------------------------------------------- |
| **gRPC (proto3)**              | Gateway $\leftrightarrow$ AgentSight UI; `Chat` and `ExecuteTool` RPCs defined in `src/gateway/protos/gateway.proto` |
| **OpenAI-compatible REST API** | Local vLLM endpoint; `POST /v1/chat/completions` used by all model consumers      |
| **Server-Sent Events (SSE)**   | MCP transport (`FastMCP`); compliance event streaming from `GovernanceEventBus`   |
| **W3C Traceparent**            | Distributed trace propagation across the MCP SSE boundary via `patch_mcp_tools()` |
| **Cloud KMS (RSA-4096-SHA256)**| **Primary** governance signing — HSM-backed asymmetric signatures for non-repudiation |
| **HMAC-SHA256**                | **Fallback** routing seal (`X-CAGE-Routing-Seal` header) in dev/test environments |
| **OTLP (gRPC / HTTP)**         | OpenTelemetry $\to$ Langfuse ingestion; all trace and span export                 |
| **ISO-20022**                  | Banking payments standard; message format reference for transaction fields        |
| **OSCAL v1.0.4**               | NIST-standard machine-readable compliance artifact format                         |
| **RFC 8785 (JCS)**             | JSON Canonicalization Scheme for cryptographic digest stability                   |
