---
title: "Cybernetic Governance Engine (CAGE) — Deployment & Infrastructure"
document: "08-DEPLOYMENT-INFRASTRUCTURE"
version: "1.1"
date: "2026-05-31"
classification: "INTERNAL"
---

# 08 — Deployment & Infrastructure

## Infrastructure Overview

CAGE runs on Google Kubernetes Engine (GKE) in the `governance-stack` namespace. All infrastructure is defined as code via Terraform, containerised with Docker, and deployed through Google Cloud Build pipelines. GPU compute uses NVIDIA L4 24 GB Spot instances with AWQ quantization to balance cost and the 200 ms ISO-20022 latency SLA.

**Platform Summary**

| Component          | Technology             | Details                          |
| ------------------ | ---------------------- | -------------------------------- |
| Container Platform | GKE                    | `governance-stack` namespace     |
| IaC                | Terraform              | `infra/modules/` + `infra/targets/`  |
| Container Registry | GCR / AR               | Cloud Build → push               |
| CI/CD              | Google Cloud Build     | YAML-defined pipelines           |
| GPU Compute        | NVIDIA L4 24 GB        | Spot instances; AWQ quantization |
| Secret Store       | Kubernetes Secrets     | Terraform-provisioned; no runtime GSM dependency |
| Object Storage     | GCS + MinIO            | OSCAL artifacts + model weights  |
| Database           | Cloud SQL (PostgreSQL) | Langfuse backend                 |

---

## Kubernetes Service Topology

All services run in the `governance-stack` namespace. Full manifest inventory lives under `deployment/k8s/`.

| Service                    | Manifest                       | Port | Purpose                      |
| -------------------------- | ------------------------------ | ---- | ---------------------------- |
| Governed Financial Advisor | `deployment/k8s/financial-advisor.yaml`       | 8000 | FastAPI agent server         |
| Hybrid Gateway             | `deployment/k8s/backend-deployment.yaml`      | —    | MCP + Inference + Governance |
| Compliance Bridge          | `deployment/k8s/compliance-bridge.yaml`       | 3001 | OSCAL audit + SSE events     |
| AgentSight UI              | `frontend-deployment.yaml.tpl` | 5173 | React dashboard              |
| vLLM Reasoning             | `vllm-reasoning.yaml.tpl`      | —    | DeepSeek-R1-Distill-Llama-8B |
| vLLM Fast                  | `vllm-fast.yaml.tpl`           | —    | Meta-Llama-3.1-8B-Instruct   |
| OPA                        | `deployment/k8s/opa.yaml`                     | —    | Policy engine                |
| Redis                      | `deployment/k8s/redis-statefulset.yaml`       | 6379 | Checkpointing (db=0) + DEFER (db=1, noeviction) |
| NeMo                       | `deployment/k8s/nemo.yaml`                    | —    | Guardrails server            |
| MinIO                      | `deployment/k8s/minio.yaml`                   | —    | Model weight storage         |
| Langfuse Web               | `deployment/k8s/langfuse-web.yaml`            | —    | Observability UI             |
| Langfuse DB                | `deployment/k8s/langfuse-db.yaml`             | —    | PostgreSQL                   |
| Lula CronJob               | `deployment/k8s/lula-cron.yaml`               | —    | OSCAL validation every 6 h   |
| SBOM CronJob               | `deployment/k8s/sbom-cronjob.yaml`            | —    | Daily SBOM generation        |
| AgentSight DaemonSet       | `deployment/k8s/agentsight-daemon.yaml`       | —    | eBPF kernel monitoring       |

**Supporting Manifests**

- `deployment/k8s/vllm-pdb.yaml` — Pod Disruption Budget; ensures vLLM availability during rolling updates
- `deployment/k8s/model-pvc.yaml` — Persistent Volume Claim for model weights
- `deployment/k8s/service-account.yaml` — Workload Identity binding for GCP APIs
- `deployment/k8s/tensorize-job.yaml` — Kubernetes Job converting model weights to Tensorizer format on MinIO
- `deployment/k8s/redis-config.yaml` — Redis ConfigMap enforcing `maxmemory-policy noeviction` for db=1 DEFER state safety

**Vendor Integration Package (`src/integrations/`)**

Third-party compliance and attestation adapters are deployed as part of the Hybrid Gateway image but are isolated in their own package tree. They are **not** separate Kubernetes services — they run in-process within the gateway pod and are activated only when the corresponding environment variables are set:

| Adapter          | Env Var Required          | Activated In         |
| ---------------- | ------------------------- | -------------------- |
| TrustLayers      | `TRUSTLAYERS_API_KEY`     | Hybrid Gateway pod   |
| NexArt           | `NEXART_API_KEY`          | Hybrid Gateway pod   |

See [`EXTENSIBILITY_ARCHITECTURE.md §2.6`](../../docs/architecture/EXTENSIBILITY_ARCHITECTURE.md) for the full vendor isolation architecture.

### Redis Deployment Hardening (v2.1.0)

Source: `deployment/k8s/redis-config.yaml`, `deployment/k8s/redis-statefulset.yaml`, `deployment/k8s/NAMESPACE-GUIDE.md`

The Redis StatefulSet has been hardened to support the DEFER state machine's fail-closed requirement. When CAGE enters an ambiguous gating state ($0.70 \le \text{Score} < 0.95$), the transaction token parked in Redis `db=1` must **never** be silently evicted.

| Configuration                   | Value                        | Purpose                                                          |
| ------------------------------- | ---------------------------- | ---------------------------------------------------------------- |
| `maxmemory-policy`              | `noeviction`                 | Redis refuses new writes under memory pressure instead of evicting active DEFER tokens |
| `appendonly`                     | `yes`                        | AOF persistence for crash recovery of in-flight DEFER tokens     |
| `rename-command FLUSHALL`        | `""`                         | Disables FLUSHALL to prevent accidental state wipe               |
| `rename-command FLUSHDB`         | `""`                         | Disables FLUSHDB to prevent accidental state wipe                |
| Container QoS                   | Guaranteed (`requests == limits`) | Prevents OOM-kill under memory pressure; resources: 256Mi / 500m |
| Image                           | `redis/redis-stack-server:latest` | Includes RedisJSON module for structured DEFER token storage    |
| `db=0`                          | LangGraph checkpoints         | Standard caching namespace                                       |
| `db=1`                          | DEFER state machine tokens    | High-assurance namespace — noeviction enforced                   |

---

## Kubernetes Inference Gateway

Source: `deployment/k8s/inference-gateway/`

ADR-002 records the decision to migrate from the GKE GCE GatewayClass to the nginx GatewayClass for the Kubernetes Inference Gateway, providing better load balancing, inference pool routing, and cross-namespace reference grant support.

| Manifest               | Purpose                               |
| ---------------------- | ------------------------------------- |
| `deployment/k8s/inference-gateway/gateway.yaml`         | nginx GatewayClass definition         |
| `deployment/k8s/inference-gateway/http-route.yaml`      | HTTP routing rules to inference pools |
| `deployment/k8s/inference-gateway/inference-pool.yaml`  | vLLM inference backend pool           |
| `deployment/k8s/inference-gateway/reference-grant.yaml` | Cross-namespace reference grant       |

---

## Docker Image Inventory

Source: `deployment/docker/`

| Image             | Dockerfile                                     | Base                      | Key Contents                                                                           |
| ----------------- | ---------------------------------------------- | ------------------------- | -------------------------------------------------------------------------------------- |
| Gateway           | `src/gateway/Dockerfile`                       | Python 3.11-slim          | FastAPI, NeMo, OPA client, all governance deps                                         |
| Compliance Bridge | `src/compliance_bridge/Dockerfile`             | Python 3.11-slim          | OSCAL parser, Langfuse, SSE                                                            |
| AgentSight UI     | `src/agentsight-ui/Dockerfile`                 | Node 18 → nginx           | React build; nginx serve                                                               |
| vLLM              | `deployment/docker/Dockerfile.vllm`            | `vllm/vllm-openai:latest` | `vllm[runai]`, `runai-model-streamer`, `huggingface_hub`; ARG `HUGGING_FACE_HUB_TOKEN` |
| Lula Runtime      | `deployment/docker/Dockerfile.lula-runtime`    | `alpine:3.19`             | Lula binary only                                                                       |
| Lula Multi-stage  | `deployment/docker/Dockerfile.lula-multistage` | Multi-stage build         | Build + runtime separation                                                             |
| NeMo              | `Dockerfile.nemo`                              | NeMo base                 | Guardrails server                                                                      |
| Main              | `Dockerfile`                                   | Python 3.11-slim          | Governed Financial Advisor                                                             |

**Root-Level Compose Files**

- `docker-compose.yml` — production compose stack
- `docker-compose.dev.yml` — development overrides with hot-reload volumes

---

## Cloud Build CI/CD Pipelines

Source: `deployment/docker/`

| Pipeline | Config                                                | Builds                          |
| -------- | ----------------------------------------------------- | ------------------------------- |
| Gateway  | `deployment/docker/cloudbuild_gateway.yaml` / `deployment/docker/cloudbuild.gateway.yaml` | Hybrid Gateway image            |
| vLLM     | `deployment/docker/cloudbuild.vllm.yaml`                                | vLLM inference image            |
| Lula     | `deployment/docker/cloudbuild.lula.yaml`                                | Lula compliance validator image |

**Build flow**: Cloud Build trigger → Docker build → push to GCR/AR → update Kubernetes Deployment via `kubectl rollout`.

---

## Terraform Infrastructure-as-Code

The Terraform code is organised as a **modular monorepo** under `infra/` with reusable shared modules and explicit deployment targets. The old monolithic `deployment/terraform/` directory is superseded by this structure.

### Shared Modules (`infra/modules/`)

| Module               | Path                             | Purpose                                          |
| -------------------- | -------------------------------- | ------------------------------------------------ |
| `k8s_namespace`      | `infra/modules/k8s_namespace/`   | Kubernetes namespace + RBAC                      |
| `gcp_gke_cluster`    | `infra/modules/gcp_gke_cluster/` | GKE cluster provisioning (GCP-specific)          |
| `vllm_inference`     | `infra/modules/vllm_inference/`  | vLLM deployment (generic or GCP GCS Fuse)        |
| `slm_inference`      | `infra/modules/slm_inference/`   | SLM sidecar deployment (Deprecated/Retired)      |
| `nemo_guardrails`    | `infra/modules/nemo_guardrails/` | NeMo Guardrails server deployment                |
| `opa_policy`         | `infra/modules/opa_policy/`      | OPA engine + Rego bundle                         |
| `redis_cache`        | `infra/modules/redis_cache/`     | Redis StatefulSet                                |
| `postgres_db`        | `infra/modules/postgres_db/`     | PostgreSQL (Helm chart wrapper)                  |
| `langfuse_stack`     | `infra/modules/langfuse_stack/`  | Langfuse web + worker + ClickHouse               |
| `clickhouse`         | `infra/modules/clickhouse/`      | ClickHouse StatefulSet for Langfuse              |
| `minio_storage`      | `infra/modules/minio_storage/`   | MinIO StatefulSet (S3-compatible, cloud-agnostic)|
| `compliance_bridge`  | `infra/modules/compliance_bridge/` | Compliance Bridge service                      |

### Deployment Targets (`infra/targets/`)

| Target     | Path                      | Purpose                                                              |
| ---------- | ------------------------- | -------------------------------------------------------------------- |
| `agnostic` | `infra/targets/agnostic/` | Cloud-agnostic K8s deployment (k3s, EKS, AKS, GKE via kubeconfig)   |
| `gcp-gke`  | `infra/targets/gcp-gke/`  | GCP GKE deployment — provisions cluster + all services via modules   |

Each target contains `dev.tfvars` and `prod.tfvars` for environment-specific overrides. The `gcp-gke` target uses a GCS backend for Terraform state; the `agnostic` target uses a Kubernetes secret backend.

### Deployment Entry Point

All deployments go through `deploy_all.sh` using the `--target` and `--env` flags:

```bash
# Deploy to GCP GKE (development)
./deploy_all.sh --target gcp-gke --env dev --auto-approve

# Deploy to GCP GKE (production)
./deploy_all.sh --target gcp-gke --env prod

# Deploy to local k3s / any K8s cluster (agnostic)
./deploy_all.sh --target agnostic --env dev

# Override individual Terraform variables
./deploy_all.sh --target gcp-gke --env dev \
  --var project_id=my-test-project \
  --var gpu_type=nvidia-t4
```

The script auto-detects the project from `.env` and performs a pre-build step (Cloud Build) before running `terraform apply` for the `gcp-gke` target.

> **Note:** The legacy monolithic `deployment/terraform/` directory remains in the repository as a historical reference but is no longer the primary IaC path. All new infrastructure changes should be made in `infra/targets/` or `infra/modules/`.

---

## vLLM Deployment Configuration

Source: `generate_reasoning_manifest.py`, `deployment/k8s/vllm-inference-spot.yaml`

### Reasoning Node — DeepSeek-R1-Distill-Llama-8B

| Parameter              | Value                                    |
| ---------------------- | ---------------------------------------- |
| Quantization           | AWQ 4-bit                                |
| Context length         | `max_model_len = 32768` (32 K tokens)    |
| GPU memory utilization | `gpu_memory_utilization = 0.9`           |
| GPU                    | NVIDIA L4 24 GB VRAM                     |
| Instance type          | Spot (cost-optimized)                    |
| Prefix caching         | Enabled — governance system prompt reuse |

### Fast Node — Meta-Llama-3.1-8B-Instruct

| Parameter         | Value                      |
| ----------------- | -------------------------- |
| Precision         | Standard (non-quantized)   |
| Instance type     | Spot                       |
| API compatibility | OpenAI-compatible endpoint |

### Cold-Start Acceleration

vLLM Tensorizer streams model weights directly from MinIO at pod startup. `deployment/k8s/tensorize-job.yaml` pre-converts weights to Tensorizer format. This eliminates the HuggingFace Hub download step from the critical path and reduces cold-start time significantly (documented in `docs/LATENCY_STRATEGY.md` as "The Enforcer" strategy on NVIDIA L4).

**Additional vLLM manifests**:

- `deployment/k8s/vllm-streaming.yaml` — streaming inference configuration
- `deployment/k8s/vllm-governance.yaml` — governance-specific vLLM configuration

---

## vLLM Model Manifest Generation

`generate_reasoning_manifest.py` (root-level script) programmatically produces Kubernetes Deployment manifests for reasoning nodes, configuring the `MODEL_REASONING` environment variable, AWQ quantization, `max_model_len=32768`, and `gpu_memory_utilization=0.9`. Output templates are written to `deployment/k8s_rendered/vllm-reasoning.yaml.tpl` and related paths.

Model weight mirroring is handled by `deployment/scripts/mirror_models.py`, which syncs weights from HuggingFace Hub to MinIO. `deployment/k8s/model-downloader.yaml.tpl` defines the Kubernetes Job used for model download initialisation at cluster bootstrap.

---

## Langfuse Deployment

Source: `deployment/langfuse/README.md`, `deployment/langfuse/service.yaml`, `infra/modules/langfuse_stack/`

Langfuse is self-hosted on GKE backed by Cloud SQL PostgreSQL, giving CAGE full control over LLM trace data. Components:

| Resource                         | File                                      |
| -------------------------------- | ----------------------------------------- |
| Web service manifest             | `deployment/k8s/langfuse-web.yaml`        |
| Worker Horizontal Pod Autoscaler | `deployment/k8s/langfuse-worker-hpa.yaml` |
| Database manifest                | `deployment/k8s/langfuse-db.yaml`         |
| Service definition               | `deployment/langfuse/service.yaml`        |
| Terraform resources              | `infra/modules/langfuse_stack/`           |
| PostgreSQL                       | `infra/modules/postgres_db/`              |

The worker HPA scales Langfuse worker pods automatically under trace ingestion bursts, ensuring observability data is not dropped during high-throughput governance events.

---

## Storage Architecture

Three configurable storage backends are controlled by the `STORAGE_BACKEND` environment variable:

| Backend | Technology            | Use Case                                 |
| ------- | --------------------- | ---------------------------------------- |
| `gcs`   | Google Cloud Storage  | Production; Workload Identity Federation |
| `s3`    | MinIO (S3-compatible) | Model weights; development               |
| `local` | Local filesystem      | Testing; development only                |

**Provisioning**:

- GCS bucket provisioning is managed via Terraform modules in `infra/`
- `deployment/k8s/model-pvc.yaml` / `model-pvc.yaml.tpl` — Persistent Volume Claims for model weights
- `deployment/scripts/upload_to_gcs.py` — artifact upload utility for OSCAL documents and audit outputs

---

## Network Policies and Security Context

Source: `deployment/k8s/network-policy.yaml`, `deployment/k8s/network-policy-hardening.yaml`

Nine `NetworkPolicy` objects are applied within the `governance-stack` namespace. The default posture is deny-all for both ingress and egress, with explicit allow rules for service-to-service communication:

- Agent → Gateway
- Gateway → OPA
- Gateway → Redis
- Gateway → vLLM services

**Pod-level security controls**:

| Resource               | File                                         | Purpose                             |
| ---------------------- | -------------------------------------------- | ----------------------------------- |
| Pod Security Admission | `deployment/k8s/pod-security-admission.yaml` | Enforces `restricted` profile       |
| Security context patch | `deployment/k8s/security-context-patch.yaml` | Non-root user; read-only filesystem |
| Ingress                | `deployment/k8s/ingress.yaml`                | External traffic routing            |

---

## Latency Strategy

Source: [`docs/LATENCY_STRATEGY.md`](../../docs/LATENCY_STRATEGY.md)

### 10.1 Latency as Currency Philosophy
Every secure generation node in a multi-agent system incurs a "Governance Tax" (overhead):
1. **Semantic Guardrails (NeMo):** ~150-300ms (Input/Output checks).
2. **Policy Evaluation (OPA):** ~10-50ms (Sidecar network hop + Rego eval).
3. **Syntactic Enforcement (vLLM FSM):** ~50ms (with Prefix Caching).

To maintain an end-to-end transaction latency **< 200ms** (mandated by the ISO-20022 banking SLA and enforced by STPA threshold `stpa.max_latency_ms = 200.0` for US / `150.0` for EU), CAGE treats latency as a currency. We optimize our inference and networking layers to generate tokens fast enough to "pay for" these security checks.

### 10.2 Layered Latency Mitigation Controls

The 200 ms SLA is enforced through 14 hardware, network, and software mitigations organized across four categories:

#### Infrastructure-Level Mitigations

| # | Mechanism | Source | Detail | Latency Impact |
| - | --------- | ------ | ------ | -------------- |
| 1 | **NVIDIA L4 GPU** | [`vllm-inference-spot.yaml`](../../deployment/k8s/vllm-inference-spot.yaml) | Primary reasoning node accelerator ("The Enforcer"); optimizes cost and throughput for <20B models | Baseline speed |
| 2 | **vLLM Prefix Caching** | `--enable-prefix-caching` | Stores attention KV cache of the shared governance system prompt in GPU memory | TTFT: 200ms → **<50ms** |
| 3 | **vLLM Tensorizer** | [`tensorize-job.yaml`](../../deployment/k8s/tensorize-job.yaml) | Streams serialized tensor weights directly from in-cluster MinIO via S3 API | Cold Start: 20m → **~60s** |
| 4 | **httpx Pooled Connections** | [`inference_proxy.py`](../../src/gateway/server/inference_proxy.py) | `max_connections=50`, `max_keepalive=20`, `keepalive_expiry=30s` in the shared `httpx.AsyncClient` singleton | Network RTT: **<10ms** |
| 5 | **Spot Instances** | GKE Spot GPU node pools | Reduces infrastructure costs by ~60% without SLA compromise | Resource cost |

#### Governance Pipeline Mitigations

| # | Mechanism | Source | Detail | Latency Impact |
| - | --------- | ------ | ------ | -------------- |
| 6 | **Aho-Corasick O(n) Keyword Scan** | [`safety.py`](../../src/gateway/governance/safety.py) | Tier-1 keyword detection uses a pre-built `pyahocorasick` automaton for single-pass O(n) scanning of all 14+ forbidden keywords, replacing the naïve O(n×m) `any()` loop. Automaton is built lazily on first invocation and cached for process lifetime. | Scan: **O(n)** vs O(n×m) |
| 7 | **OPA Circuit Breaker** | [`policy.py`](../../src/gateway/core/policy.py) | Three-tier latency defense: (a) **Hard timeout**: 1.0s per OPA request; (b) **Soft ceiling warning**: cumulative `>2000ms` emits latency inflation warning; (c) **Bankruptcy protocol**: cumulative `>3000ms` → immediate DENY, bypassing remaining OPA evaluation | Hard cap: **3000ms** |
| 8 | **SLM Sidecar Bypassed** | [`symbolic_governor.py`](../../src/gateway/governance/symbolic_governor.py) | SLM similarity sidecar has been permanently deprecated and bypassed (0ms added). Bypassing is enforced by hardcoding the `"slm_available": false` sentinel, forcing OPA Rego policies to apply the elevated confidence threshold (`0.97` vs `0.95` default) | Bypassed: **0ms** (0ms added) |
| 9 | **Consensus Parallel Critics** | [`consensus.py`](../../src/gateway/governance/consensus.py) (Phase 4.4) | Two LLM critic votes (Risk Manager + Compliance Officer) dispatched via `asyncio.gather()` — **parallel**, not sequential. Replaces the original sequential `await` chain | 2 calls: **max(A,B)** not A+B |
| 10 | **Consensus Background Audit Queue** | [`consensus.py`](../../src/gateway/governance/consensus.py) (Phase 4.4) | Post-execution audit logging pushed to a non-blocking `asyncio.Queue(maxsize=1000)` drained by `_background_audit_worker()`. Audit I/O never blocks the governance hot-path | Audit: **0ms** on hot-path |
| 11 | **DEFER Queue Confidence-Starvation Bypass** | [`defer_queue.py`](../../src/gateway/governance/defer_queue.py) | Requests with confidence < 0.70 ("Confidence-Starvation Boundary") are routed to DEFER → Redis parking instead of MANUAL_REVIEW, preventing operational fatigue from low-confidence requests clogging the human review queue | HITL: **avoided** for junk |

#### Data Loading & Caching Mitigations

| # | Mechanism | Source | Detail | Latency Impact |
| - | --------- | ------ | ------ | -------------- |
| 12 | **Threshold Singleton `@lru_cache`** | [`thresholds.py`](../../src/gateway/governance/schemas/thresholds.py) | `GovernanceThresholds` Pydantic model loaded once at startup via `@lru_cache(maxsize=1)` — JSON parse + Pydantic validation cost paid exactly once; all subsequent access is a dict lookup | Config: **0ms** per request |
| 13 | **NeMo Action 60s TTL Hot-Reload** | [`nemo/vllm_client.py`](../../src/gateway/governance/nemo/vllm_client.py) | NeMo Colang action classes hot-reload threshold values with a 60-second TTL. This picks up `governance_thresholds.json` changes without service restart while amortising the reload cost across 60 seconds of traffic | Reload: **amortised** |

#### Event Streaming Mitigations

| # | Mechanism | Source | Detail | Latency Impact |
| - | --------- | ------ | ------ | -------------- |
| 14 | **GovernanceEventBus Backpressure** | [`sse_events.py`](../../src/compliance_bridge/sse_events.py) | Per-subscriber `asyncio.Queue(maxsize=128)` with `put_nowait()` — slow SSE clients have events dropped rather than blocking the publisher coroutine. Dead queues are auto-removed | Publish: **non-blocking** |

### 10.3 Latency Budget Breakdown

The following table documents the typical per-request latency budget for a governed `execute_trade` action on the hot-path:

| Phase | Component | Typical | Max | Mitigation |
| ----- | --------- | ------- | --- | ---------- |
| **Tier 0** | STPA/UCA Validation | <1ms | 5ms | Pure Python dict checks |
| **Tier 1** | Agentic Confidence Check | <1ms | 1ms | Float comparison |
| **Tier 2** | Control Barrier Function | ~5ms | 15ms | Redis `WATCH`/`MULTI`/`EXEC` — single round-trip |
| **Tier 3** | SLM Sidecar Query (Deprecated) | 0ms | **0ms (Bypassed)** | Bypassed permanently; evaluates under `slm_available = False` |
| **Tier 4** | OPA Policy Evaluation | ~10-50ms | **1000ms timeout** | Circuit breaker; bankruptcy at 3000ms cumulative |
| **Tier 5** | Multi-Agent Consensus | ~200ms | ~3000ms | Parallel `asyncio.gather`; skip if < $10k threshold |
| **Tier 6** | DoWhy Causal Gatekeeper | ~100ms | 500ms | 50 simulations; fail-open on import error |
| **Step 8** | FRIA Attestation (EU only) | <1ms | 1ms | Non-blocking span attribute stamp |
| **Network** | Inference Proxy → vLLM | <10ms | 50ms | httpx connection pooling; keep-alive |
| **Inference** | vLLM TTFT (Prefix-Cached) | ~40ms | 200ms | Prefix caching; governance prompt reuse |
| **Total** | End-to-end governance overhead | ~200ms | ~3000ms (bankruptcy) | Layered mitigations keep typical well under SLA |

### 10.4 vLLM Prefix Caching Mechanics
Since every governance check shares the same massive system prompt and JSON schema definition, vLLM hashes this prompt prefix and stores the KV attention states. Subsequent requests matching the prefix skip attention computation entirely. This drops the Time-To-First-Token (TTFT) from ~200ms to **<50ms**, preserving the bulk of the 200ms SLA budget for downstream agent reasoning.

### 10.5 Cold-Start Latency Mitigation Analysis
Pod startup and model weight loading represent a critical secondary latency factor. CAGE compares three distinct strategies to optimize recovery speed:

| Cold-Start Strategy | Recovery Time | Cloud-Agnostic | Engineering Implications |
| ------------------- | ------------- | -------------- | ------------------------ |
| **Full HuggingFace Download** | ~20 minutes | Yes | High network latency; prone to rate-limiting and external gateway failures. |
| **GCS Fuse Image Streaming**  | ~2–5 minutes | No (GKE-only) | Lazy-pulling via GCS CSI driver; high runtime overhead and GKE proprietary lock-in. |
| **MinIO + vLLM Tensorizer**   | **60–90 seconds** | **Yes** | **(Active)** Streams serialized shards from in-cluster S3-compatible MinIO; no POSIX mounting overhead. |

Model weights are pre-serialized to TensorSerializer format via a one-time GKE Job ([`deployment/k8s/tensorize-job.yaml`](../../deployment/k8s/tensorize-job.yaml)) and stored in the local `vllm-models` MinIO bucket. At pod startup, vLLM streams individual tensor shards on demand using `--load-format tensorizer`—completely eliminating posix file system locks and GKE CSI driver dependencies.


## Deployment Decision Record

Source: `docs/DEPLOYMENT_DECISION_RECORD.md`

**ADR-002 — nginx GatewayClass for Kubernetes Inference Gateway**

| Attribute | Detail                                                                                      |
| --------- | ------------------------------------------------------------------------------------------- |
| Decision  | Migrate from GKE GCE GatewayClass to nginx GatewayClass                                     |
| Rationale | Better load balancing; inference pool routing; cross-namespace reference grant support      |
| Impact    | Inference traffic now routed through `deployment/k8s/inference-gateway/gateway.yaml` and `deployment/k8s/inference-gateway/http-route.yaml` |

---

## Operational Scripts and Runbooks

### Deployment Operations

| Script                    | Purpose                                                              |
| ------------------------- | -------------------------------------------------------------------- |
| `deploy_all.sh`           | Unified deployment entry point — `--target TARGET --env ENV`         |
| `scripts/deploy_sw.py` | Software deployment orchestrator — accepts `--target` and `--env`    |
| `deployment/teardown.py`  | Graceful stack teardown                                              |

### Secret Management

| Script                                       | Purpose                                   |
| -------------------------------------------- | ----------------------------------------- |
| `deployment/update_langfuse_secret.py`       | Langfuse credential rotation (Kubernetes Secret update) |

> **Note:** GCP Secret Manager was removed as a runtime dependency (v1.0.0 ADR). All secrets are now managed as Kubernetes `Secret` objects. The legacy `create_secret_manual.py` script (GCP Secret Manager) is no longer applicable.

### Model Management

| Script                                  | Purpose                               |
| --------------------------------------- | ------------------------------------- |
| `deployment/scripts/mirror_models.py`   | HuggingFace Hub → MinIO weight mirror |
| `deployment/scripts/rebuild_backend.py` | Backend image rebuild and redeploy    |

### Operational Utilities

| Script / Manifest                          | Purpose                    |
| ------------------------------------------ | -------------------------- |
| `scripts/proxy_backend.sh` / `scripts/proxy_ui.sh` | Local proxy for debugging  |
| `deployment/k8s/db-reset.yaml`             | Database reset Job         |
| `deployment/scripts/upload_to_gcs.py`      | GCS artifact upload        |
| `fetch_langfuse_metrics.py`                | Langfuse metrics retrieval |
| `deployment/k8s/generated/debug-downloader.yaml`     | Debug download utility     |
| `deployment/k8s/generated/debug-downloader-fix.yaml` | Debug download fix variant |

**Decommission checklist**: `docs/TECHNICAL_DECOMMISSION_GUIDELINES.md`  
**Sensitive data removal**: `docs/GIT_HISTORY_SCRUBBING.md` — procedures for scrubbing secrets from Git history
