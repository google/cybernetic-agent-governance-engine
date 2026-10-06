# Technology Stack & Bill of Materials

| Field                | Value                                                                    |
| -------------------- | ------------------------------------------------------------------------ |
| **Document Version** | 3.0.1                                                                    |
| **Date**             | 2026-09-29                                                               |
| **Classification**   | INTERNAL                                                                 |
| **Document Series**  | CAGE Architecture Specification                                          |
| **Status**           | ACTIVE — v3.0.1 stable; `infra/targets/gcp-gke` is the sole cloud reference deployment |
| **Canonical Path**   | `docs/architecture/TECH_STACK.md`                                        |
| **References**       | [`GATEWAY_ARCHITECTURE.md`](GATEWAY_ARCHITECTURE.md), [`AGENT_SYSTEM_ARCHITECTURE.md`](AGENT_SYSTEM_ARCHITECTURE.md) |

**Last Updated:** 2026-09-29

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
| **LangGraph**               | MIT        | Multi-agent `StateGraph` orchestration | Deterministic cyclic state machine ($\ge 1.1.0$); dynamic `interrupt()` primitive for HITL and `AsyncRedisSaver` checkpoint persistence |
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
| **vLLM Reasoning Node** | `deepseek-ai/DeepSeek-R1-Distill-Llama-8B` | `--max-model-len 16384`; NVIDIA L4 on `g2-standard-8`, non-Spot | Deep reasoning for complex investment theses (`module.vllm_reasoning`, service `vllm-reasoning`) |
| **vLLM Fast Node**      | `Qwen/Qwen2.5-1.5B-Instruct`   | `--enable-auto-tool-choice --tool-call-parser hermes`; NVIDIA L4, non-Spot | Low-latency tool calling, NeMo rail evaluation, and compliance-bridge remediation (`module.vllm`, service `vllm-service`) |
| **liteLLM**             | Model registry                 | In-process library (advisor)            | Registers `MODEL_REASONING` / `MODEL_FAST` limits in [`infrastructure/llm/config.py`](../../src/governed_financial_advisor/infrastructure/llm/config.py); not declared in `pyproject.toml` |
| **Run:ai Model Streamer** | Cold-Start Streaming         | `--load-format runai_streamer` from the GCS model bucket | Weights stream from `gs://<project>-models/` (Workload Identity, `HF_HUB_OFFLINE=1`); no HF token or weights baked into the image. GKE image streaming (`gcfs_config`) is enabled on the GPU pool |
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
| `httpx` (direct)    | BSD-3-Clause | OPA is evaluated over the REST Data API with a hand-rolled async client in [`src/gateway/core/policy.py`](../../src/gateway/core/policy.py) — no third-party OPA SDK is declared |
| `dowhy`             | MIT        | Causal inference engine for Tier 6 causal gatekeeper (counterfactual refutation & slope invariance); `compliance` extra |

### 4.4 Observability

| Library                                   | License    | Purpose & Governance Justification                                    |
| ----------------------------------------- | ---------- | --------------------------------------------------------------------- |
| `opentelemetry-sdk`                       | Apache-2.0 | Core OpenTelemetry trace and span creation                            |
| `opentelemetry-exporter-otlp-proto-grpc`  | Apache-2.0 | Direct OTLP export to Langfuse (collector deprecated 2026-05-31)      |
| `opentelemetry-instrumentation-fastapi`   | Apache-2.0 | Automatic HTTP span generation for inbound gateway requests           |
| `opentelemetry-instrumentation-langchain` | Apache-2.0 | Automatic trace propagation across LangChain and LangGraph executions |
| `prometheus-client`                       | Apache-2.0 | Operational, CBF safety-gate, FTRA, rate-limiter, and evidence-pipeline Prometheus collectors (gracefully degrades to no-op when absent) |

### 4.5 Data Validation & Serialization

| Library       | License    | Purpose & Governance Justification                                                   |
| ------------- | ---------- | ------------------------------------------------------------------------------------ |
| `pydantic` v2 | MIT        | Strict runtime type validation and JSON schema export across all domain models       |
| `jsonschema`  | MIT        | Draft 2020-12 validation of LangGraph node output against the AgentState contract ([`state_contract.py`](../../src/gateway/governance/state_contract.py)) |
| Vendored JCS (RFC 8785) | Apache-2.0 | Deterministic JSON Canonicalization Scheme for tamper-evident hash calculation. Vendored in-tree at [`src/gateway/governance/vendor/jcs`](../../src/gateway/governance/vendor/jcs) and wrapped by [`jcs_canonicalizer.py`](../../src/gateway/governance/jcs_canonicalizer.py) — no external `canonicaljson` dependency |

### 4.6 State, Caching & Concurrency

| Library              | License    | Purpose & Governance Justification                                                |
| -------------------- | ---------- | --------------------------------------------------------------------------------- |
| `redis`              | MIT        | Async Redis client ($\ge 5.0.0$, native `redis.asyncio`); `AsyncRedisSaver`, Lua atomic CBF, and FiscalLimitGuard locks. `aioredis` is **not** a dependency — it was absorbed into `redis-py` 4.2+ |
| `clickhouse-connect` | Apache-2.0 | ClickHouse driver for the durable evidence sink; `clickhouse` extra                |
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
| `google-cloud-kms`    | Apache-2.0 | **GCP** governance signing — Cloud KMS HSM-backed asymmetric keys (`GCPKMSProvider` in [`src/integrations/gcp/kms_provider.py`](../../src/integrations/gcp/kms_provider.py)); the GKE target provisions per-workload `EC_SIGN_P256_SHA256` keys on the `cage-signing-<env>` keyring. Declared in the `gateway` extra |
| `boto3`               | Apache-2.0 | **AWS** governance signing — AWS KMS HSM provider (`AWSKMSProvider` in [`src/integrations/aws/kms_provider.py`](../../src/integrations/aws/kms_provider.py)); declared in the `s3` extra              |
| `azure-keyvault-keys` | MIT        | **Azure** governance signing — Azure Key Vault Managed HSM provider (`AzureKMSProvider` in [`src/integrations/azure/kms_provider.py`](../../src/integrations/azure/kms_provider.py)). **Not declared** in `pyproject.toml`: imported lazily, and `AzureKMSProvider` raises an install hint when absent |
| `cryptography`        | Apache-2.0 / BSD | Low-level cryptographic primitives (Ed25519 CER verification, `SoftwareEd25519Provider` dev/CI signing, ECDSA/RSA verify) |
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
| ~~SLM verifier tier~~ | **REMOVED** (`7ab1acd`) | The Small Language Model semantic-similarity sidecar was deleted along with its `[slm]` extra (`flask`, `sentence-transformers`, `torch` and the transitive `nvidia-*` suite) and its Dockerfile and Terraform module. No SLM package remains in the tree. Active backing verifiers are OPA, CBF, multi-agent consensus, and the TLA+ formal models. |
| ~~`sentence-transformers`~~ | **REMOVED** (`7ab1acd`) | Backed the former Stage 2.5 embedding-based semantic injection scorer (~2 GB transitive footprint). Stage 2 pure-regex detection is retained. Adopters needing semantic detection implement it as a Layer 3 adapter — see [`ADR-2026-09-19-001`](../adr/ADR-2026-09-19-001-remove-sentence-transformers-from-core.md). |

---

## 5. Vendor & Partner Integrations (`src/integrations/`)

Third-party compliance, attestation, and actuator provider adapters live in `src/integrations/{provider_id}/`. They are strictly isolated from the Layer 1 governance kernel.

| Integration     | Root Path                       | Purpose                                                                                                   | Status      |
| --------------- | ------------------------------- | --------------------------------------------------------------------------------------------------------- | ----------- |
| **Provider 01** | `src/integrations/provider_01/` | Production normative provider; implements 3-endpoint normative validation API via `Provider01NormativeProvider` | Implemented (POAM-022 awaiting credentials) |
| **Provider 02** | `src/integrations/provider_02/` | CER (Compliance Evidence Record) attestation provider; `Provider02Client` + `Provider02AttestationCallback` | Implemented |
| **Provider 03** | `src/integrations/provider_03/` | JCS (RFC 8785) evidence normalization and decision governance adapter                                     | Implemented |
| **Provider 05** | `src/integrations/provider_05/` | Veraxis Execution Integrity Protocol (VEIP); three `AttestationProvider` axioms (Blueprint / Key / Physics) plus execution-warrant verification | Seeded (HTTP path unimplemented) |
| **Provider 06** | `src/integrations/provider_06/` | Tri-state deterministic verifier adapter (`PASS`/`REVIEW`/`BLOCKED`) with DeferQueue parking integration | Implemented |
| **Provider 07** | `src/integrations/provider_07/` | Bayesian causal suitability adapter; `Provider07NormativeProvider` + `Provider07JwksClient` with `kid`-resolved signature verification | Implemented |
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
7. **Hermetic Unit Testing**: Adapter *unit* tests run against mocked transports (`respx`). Tests marked `partner_integration` / `live_external` are excluded from hermetic runs and must execute over the wire against live partner sandboxes.

### 5.2 Distributable Client SDK (`packages/cage-client/`)

The policy-enforcement-point client is shipped as a standalone, independently installable package so that adopters can govern their own LangGraph applications without vendoring the CAGE kernel.

| Attribute | Value |
| --------- | ----- |
| **Distribution name** | `cage-client` v0.2.0 (Apache-2.0) |
| **Source root** | [`packages/cage-client/src/cage_client/`](../../packages/cage-client/src/cage_client) |
| **Runtime dependencies** | `httpx>=0.27.0`, `pydantic>=2.0.0`, `cryptography>=41.0.0` — three packages only |
| **Optional extras** | `langgraph` (`langgraph`, `langchain-core`), `http2` (`h2`), `all` |
| **Python floor** | $\ge 3.10$ |
| **Build command** | `make build-client-sdk` (`cd packages/cage-client && uv build`) |

Modules, all rooted at [`packages/cage-client/src/cage_client/`](../../packages/cage-client/src/cage_client): `core.py` exposes `CageClient.validate_action()`; `transport.py` and `envelope.py` carry the wire layer; `crypto.py` generates W3C `traceparent` headers (`generate_w3c_traceparent()`); `exceptions.py` defines `PolicyViolationException`, `DeferralPending`, `RoutingSealVerificationError` and the `CageGatewayError` base; and the `adapters` subpackage provides the `@cage_guard` LangGraph decorator.

> [!NOTE]
> An in-tree mirror of the same client lives at [`src/gateway/client/`](../../src/gateway/client) and is what the reference advisor imports (`from src.gateway.client.adapters.langgraph import cage_guard`). The two trees are near-identical but not byte-identical; `packages/cage-client/` is the published artifact.

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
| **Google Kubernetes Engine (GKE)**  | Runtime platform       | `governance-stack` namespace; regional cluster in prod, zonal in dev/staging; four node pools (`general`, `general-spot`, `gpu-l4`, local-SSD `clickhouse`) |
| **GKE Dataplane V2 + FQDNNetworkPolicy** | Network policy     | Default-deny L3/L4 `NetworkPolicy` plus `FQDNNetworkPolicy` (`networking.gke.io/v1alpha1`) egress allowlists in [`network_policy.tf`](../../infra/targets/gcp-gke/network_policy.tf); DNS egress limited to kube-dns and Cloud DNS |
| **Linkerd + Google CAS**            | Service mesh           | mTLS workload identity for all pods in the namespace; trust anchor in Google CAS ([`service_mesh`](../../infra/modules/service_mesh)) |
| **Terraform**                       | Infrastructure-as-code | `infra/modules/` (22 shared modules) + `infra/targets/` (`agnostic/`, `gcp-gke/`); `hashicorp/google ~> 6.43` |
| **Perimeter**                       | Supply chain & edge    | Binary Authorization (`REQUIRE_ATTESTATION`, KMS-backed attestor), VPC Service Controls, Cloud Armor and Cloud DNS in [`perimeter.tf`](../../infra/targets/gcp-gke/perimeter.tf); images pinned by `@sha256:` via `var.image_digests` |
| **Docker**                          | Containerization       | Multi-stage builds; root `Dockerfile`, `src/gateway/Dockerfile`, and `deployment/docker/Dockerfile.{vllm,nemo,opa,lula-*}` |
| **Google Cloud Build**              | CI/CD                  | [`deployment/docker/cloudbuild.image.yaml`](../../deployment/docker/cloudbuild.image.yaml) (`gateway`, `governed-financial-advisor`, `compliance-bridge`, `nemo-guardrails`, `agentsight-ui`, `cage-opa`), [`cloudbuild.vllm.yaml`](../../deployment/docker/cloudbuild.vllm.yaml), and [`cloudbuild.lula.yaml`](../../deployment/docker/cloudbuild.lula.yaml) running as `cage-cloudbuild-<env>` and signing Binary Authorization attestations via [`scripts/attest_image.sh`](../../scripts/attest_image.sh) |
| **uv / uv_build**                   | Build system           | Fast Python package installer, lockfile resolver, and build backend                                  |
| **Kubernetes Secrets**              | Secret storage         | Kubernetes-native `Secret` objects provisioned via Terraform; no runtime secret manager dependency    |
| **Google Cloud Storage (GCS)**      | Artifact storage       | Primary storage SDK (`google-cloud-storage`); retention-locked, CMEK-encrypted evidence WORM bucket ([`worm_bucket`](../../infra/modules/worm_bucket)) for OSCAL results and evidence archives; model-weight bucket for vLLM |
| **Cloud KMS**                       | Keys                   | Symmetric CMEK keyring ([`kms`](../../infra/modules/kms)) kept separate from the asymmetric `cage-signing-<env>` keyring ([`kms_signing.tf`](../../infra/targets/gcp-gke/kms_signing.tf)) |
| **MinIO / boto3**                   | S3-compatible storage  | S3-compatible storage for the `agnostic` target ([`minio_storage`](../../infra/modules/minio_storage)); not used by the GKE target |
| **NVIDIA L4 GPU**                   | GPU compute            | 24 GB VRAM on `g2-standard-8`; the GPU pool never uses Spot VMs                                       |
| **Kubernetes Inference Gateway**    | LLM routing            | Nginx `GatewayClass` with load balancing and path routing                                             |

---

## 8. Data Stores

| Store                   | Technology                     | Purpose & Invariants                                                       |
| ----------------------- | ------------------------------ | -------------------------------------------------------------------------- |
| **State / Checkpoints** | Redis (`AsyncRedisSaver`)      | LangGraph graph checkpoints; HITL interrupt state persistence. On GKE: app Memorystore for Valkey instance (`module.memorystore_app`, shared with Langfuse) |
| **CBF Cash Balance**    | Redis (Lua script check+commit)| Atomic Control Barrier Function enforcement (`atomic_verify_and_commit.lua`). On GKE: dedicated governance Memorystore for Valkey instance (`module.memorystore_governance`, IAM auth, `noeviction`) |
| **Compliance Cache**    | `TTLCache` (in-memory)         | 5-minute TTL per compliance control metric; reduces OPA round-trips        |
| **Audit Logs**          | Langfuse (ClickHouse + GCS blob storage + Cloud SQL PostgreSQL) | OTLP ingestion; dual-project telemetry. On GKE, Langfuse metadata lives in Cloud SQL PostgreSQL 15 reached through the Cloud SQL Auth Proxy with IAM database auth |
| **Evidence Query Plane** | ClickHouse ([`clickhouse_operator`](../../infra/modules/clickhouse_operator)) | Analytical mirror of evidence; the GCS WORM bucket is the system of record |
| **OSCAL Results**       | GCS / S3 / local               | OSCAL Assessment Results artifacts; backend selected via `STORAGE_BACKEND` |
| **Market Data**         | `yfinance` (real-time)         | 1-month price history on demand; no persistent database storage            |

---

## 9. Observability Stack

| Component               | Technology                   | Details                                                                                                                    |
| ----------------------- | ---------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| **Distributed Tracing** | OpenTelemetry SDK            | Direct OTLP/HTTP export to Langfuse (`http://langfuse-web:3000/api/public/otel/v1/traces`); auto-instrumentation          |
| **Compliance Metrics**  | Langfuse                     | Dual-project setup; sovereign regional telemetry instances (`us-central1`, `europe-west1`, `asia-southeast1`)               |
| **Operational & Safety Metrics** | Prometheus / GKE Managed Prometheus (GMP) | NIST SP 800-53 AU-12 (`monitoring_config.managed_prometheus` in [`infra/modules/gcp_gke_cluster/main.tf`](../../infra/modules/gcp_gke_cluster/main.tf)); `/metrics` scrape via [`deployment/k8s/gateway-servicemonitor.yaml`](../../deployment/k8s/gateway-servicemonitor.yaml) validated by [`compliance/lula/lula-validation-metrics.yaml`](../../compliance/lula/lula-validation-metrics.yaml); covers CBF safety/replication, FTRA boundary checks, MCP rate limiting, evidence stream/custody/verification, and ClickHouse `cage_evidence.v_prometheus_metrics` (2-year operational TTL) |
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
| **Cloud KMS (asymmetric)**     | **Primary** governance signing — HSM-backed asymmetric signatures for non-repudiation (`EC_SIGN_P256_SHA256` keys in the GKE target) |
| **HMAC-SHA256**                | **Fallback** signing for the governor's routing seal (`routing_seal.py`, keyed by `GOVERNANCE_SALT`) in dev/test environments |
| **OTLP (gRPC / HTTP)**         | OpenTelemetry $\to$ Langfuse ingestion; all trace and span export                 |
| **ISO-20022**                  | Banking payments standard; message format reference for transaction fields        |
| **OSCAL v1.0.4**               | NIST-standard machine-readable compliance artifact format                         |
| **RFC 8785 (JCS)**             | JSON Canonicalization Scheme for cryptographic digest stability                   |
