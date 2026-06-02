# Latency as Currency: Funding Governance with Inference Speed

> **Last verified:** 2026-06-02

This document outlines the performance strategy for the Cybernetic Governance Engine. The core philosophy is **"Latency as Currency"**: we must generate tokens fast enough to "pay for" the overhead of strict governance checks (NeMo, OPA, JSON Enforcement).

## The Governance Tax

Every safe generation incurs a latency penalty:

1.  **Semantic Guardrails (NeMo):** ~150-300ms (Input/Output checks).
2.  **Policy Evaluation (OPA):** ~10-50ms warm (sidecar network hop + Rego eval); up to ~20s on first evaluation after a pod rollout (cold-start). Mitigated by the OPA Decision Cache (see below).
3.  **Syntactic Enforcement (vLLM Guided Decoding):** ~50ms (with `--guided-decoding-backend outlines`).

To maintain a responsive user experience (Total Response Time < 2s for simple queries), the underlying inference engine must be exceptionally fast. The [`CircuitBreaker`](../src/gateway/core/policy.py:89) in [`OPAClient`](../src/gateway/core/policy.py:131) enforces a hard latency budget of **3000ms** and emits a soft-ceiling warning at **2000ms**.

## The Solution: "The Enforcer" on NVIDIA L4

We utilize a dedicated, self-hosted inference node for structure enforcement, optimized for speed and cost.

### Hardware: NVIDIA L4 (24GB VRAM) on Spot Instances

- **Why:** The L4 is the most cost-effective GPU for models < 20B parameters, and using Spot/preemptible GPU instances (e.g., GKE Spot, AWS Spot, Azure Spot) reduces costs by ~60%.
- **Capacity:** A single L4 can comfortably host `Qwen/Qwen2.5-7B-Instruct` (~14GB VRAM in float16) with room for KV cache.
- **Throughput:** Capable of high token-per-second generation for JSON structures.

### Software: vLLM + Guided Decoding

We use **vLLM** with **guided decoding** enabled via `--guided-decoding-backend outlines` (see [`deployment/k8s/vllm-governance.yaml`](../deployment/k8s/vllm-governance.yaml:48)).

> **Note on Prefix Caching:** Enabling `--enable-prefix-caching` on the governance node is a planned optimization that would reduce TTFT for repeated schema prefixes from ~200ms to <50ms. It is **not yet present** in the current `vllm-governance.yaml` deployment manifest and should be treated as aspirational until added.

#### How Guided Decoding Works

1.  **The Pattern:** Every governance request shares the same massive system prompt: "You are a governance engine. Output JSON matching this schema: { ... complex schema ... }".
2.  **The Constraint:** vLLM's `outlines` backend enforces a Finite State Machine (FSM) over the token vocabulary, guaranteeing structurally valid JSON output.
3.  **The Result:** Structurally guaranteed, compliant JSON responses with no post-processing parse failures.

> **Note on `outlines` client-side dependency:** The `outlines` Python package has been removed from CAGE's client-side dependencies ([`pyproject.toml`](../pyproject.toml:56)) due to CVE-2025-69872 (diskcache pickle RCE). The guided JSON FSM decoder runs **server-side inside vLLM**, which bundles its own copy. CAGE never imports `outlines` directly.

### Architecture Alignment

| Component      | Model                              | Hosted On            | Optimization                        |
| -------------- | ---------------------------------- | -------------------- | ----------------------------------- |
| **Reasoning**  | `deepseek-ai/DeepSeek-R1-Distill-Llama-8B` | Spot GPU (NVIDIA L4) | Deep semantic understanding.        |
| **Governance** | `Qwen/Qwen2.5-7B-Instruct` *(NOT CURRENTLY DEPLOYED — aspirational)* | Spot GPU (NVIDIA L4) | Guided JSON (`outlines` backend).   |
| **Guardrails** | NeMo Guardrails service            | CPU pod (0.5–1 vCPU, 1–2Gi RAM) | In-cluster, no GPU required.  |

The reasoning model name (`deepseek-ai/DeepSeek-R1-Distill-Llama-8B`) is the default resolved by [`create_nemo_manager()`](../src/gateway/governance/nemo/manager.py:201) via the `GUARDRAILS_MODEL_NAME` / `MODEL_FAST` env vars. The governance model (`Qwen/Qwen2.5-7B-Instruct`) is declared in [`deployment/k8s/vllm-governance.yaml`](../deployment/k8s/vllm-governance.yaml:50) but is **NOT CURRENTLY DEPLOYED** — it is the aspirational governance backend.

## Latency Budget Example

**Scenario:** Risk Analyst generates a formal assessment.

1.  **Agent Reasoning (DeepSeek-R1-Distill-Llama-8B):** 3.0s (Thinking time)
2.  **Tool Call (Governance Client):**
    - Network RTT: 10ms
    - **vLLM TTFT (Warm):** 40ms (cold-start up to 20s; mitigated by OPA Decision Cache and gateway pre-warming)
    - Generation (100 tokens): 150ms
3.  **Total Governance Overhead:** ~200ms

**Result:** The user gets a structurally guaranteed, compliant response with minimal added delay compared to a raw LLM call.

## Latency Reduction Mechanisms

The following mechanisms are implemented in code and actively reduce governance overhead:

### 1. OPA Decision Cache (Redis, 10s TTL)

[`src/gateway/core/policy.py`](../src/gateway/core/policy.py) implements a short-TTL Redis cache for OPA decisions. Identical OPA inputs (same action + symbol + amount + slm_available) within a **10-second window** return the cached decision without an HTTP round-trip.

- **Key prefix:** `cage:opa:decision:` (SHA-256 of canonical JSON input, first 24 hex chars)
- **TTL:** `_OPA_CACHE_TTL_SECONDS = 10` — intentionally short to avoid stale decisions under fast market moves
- **Toggle:** `OPA_CACHE_ENABLED` env var (default: `"true"`); set to `"false"` to disable in unit test environments
- **Failure mode:** Cache write/read failures are silent — the OPA HTTP path remains authoritative

### 2. Circuit Breaker (Fail-Fast, Latency Budget Enforcement)

[`CircuitBreaker`](../src/gateway/core/policy.py:89) in `policy.py` protects the governance path from cascading failures:

- **Failure threshold:** 5 consecutive failures → circuit OPEN
- **Recovery timeout:** 30 seconds before attempting half-open probe
- **Hard latency budget:** 3000ms (`max_latency_budget`) — requests exceeding this are fast-failed with `DENY` ("Bankruptcy Protocol")
- **Soft ceiling:** 2000ms — emits a `Latency Inflation Warning` log but does not block

### 3. Gateway Boot-Time Pre-Warming

[`hybrid_server.py`](../src/gateway/server/hybrid_server.py) pre-warms both NeMo Rails and OPA at pod startup via the `_gateway_lifespan` async context manager:

- **NeMo Rails:** [`initialize_rails()`](../src/gateway/governance/nemo/manager.py:397) is called once at boot; the resulting `LLMRails` instance is shared across all sub-apps (`inference_app`, `mcp_app`) via `app.state.nemo_rails`, eliminating per-request JIT compilation overhead.
- **OPA:** A synthetic `execute_trade` evaluation is fired at startup to warm the Rego schema and HTTP connection pool.

### 4. Pooled HTTP Connections

Two separate pooled `httpx.AsyncClient` instances eliminate TCP handshake overhead on the hot governance path:

**Inference Proxy → vLLM** ([`inference_proxy.py`](../src/gateway/server/inference_proxy.py:64)):
- `max_connections=50`, `max_keepalive_connections=20`, `keepalive_expiry=30s`
- Timeouts: `connect=5.0s`, `read=120.0s`, `write=30.0s`, `pool=5.0s`
- Lazy singleton; closed on app shutdown

**GFA → Governance Infrastructure** ([`http_pool.py`](../src/governed_financial_advisor/infrastructure/http_pool.py:34)):
- `max_connections=50`, `max_keepalive_connections=20`, timeout=30s
- Exponential back-off retry for HTTP 429 / 503 (3 attempts, base delay 1.0s)

### 5. Query Cache (Redis, 1-Hour TTL)

[`QueryCache`](../src/governed_financial_advisor/infrastructure/query_cache.py:40) in the GFA service caches responses for deterministic educational and regulatory queries only. Market data, personalized advice, and trading actions are **never cached**.

- **TTL:** 3600s (1 hour, configurable via `QUERY_CACHE_TTL` env var)
- **Toggle:** `ENABLE_QUERY_CACHE` env var (default: `"true"`)
- **Backend:** Redis primary, in-process dict fallback when Redis is unavailable
- **Expected hit rate:** 20–30% (educational queries)
- **Cache key:** `query_cache:<sha256[:16]>` of normalized (lowercased, whitespace-collapsed) query

### 6. Redis Client Timeouts

Both Redis clients enforce strict connection timeouts to prevent governance hangs:

**Gateway Redis** ([`src/gateway/infrastructure/redis_client.py`](../src/gateway/infrastructure/redis_client.py:70)):
- `socket_connect_timeout=3.0s`, `socket_timeout=3.0s`
- Used by: OPA Decision Cache, `ControlBarrierFunction`

**GFA Redis** ([`src/governed_financial_advisor/infrastructure/redis_client.py`](../src/governed_financial_advisor/infrastructure/redis_client.py:84)):
- `socket_connect_timeout=2.0s`, `socket_timeout=5.0s`, `max_connections=100`
- Supports Redis Sentinel (auto-detected via port 26379 probe) for HA deployments
- Used by: LangGraph checkpointer (db=0), `QueryCache`

### 7. DEFER Queue (4-Hour Park Window)

[`DeferQueue`](../src/gateway/governance/defer_queue.py:142) implements a fourth decision state (ALLOW | DENY | MANUAL_REVIEW | **DEFER**) that prevents operational fatigue from forcing binary decisions under fundamentally incomplete context:

- **Confidence-Starvation Boundary:** `DEFER_CONFIDENCE_THRESHOLD = 0.70` — execution contexts with confidence below this route to DEFER rather than MANUAL_REVIEW
- **Park TTL:** `_DEFAULT_TTL = 14400s` (4 hours) before auto-escalation to MANUAL_REVIEW
- **Redis isolation:** `db=1` with `noeviction` maxmemory policy (separate from LangGraph checkpointer at `db=0`)
- **Data structures:** Redis Hash `DEFER:{defer_id}` + ZSet `DEFER:expiry_index` (scored by expiry timestamp)

## Model Weight Loading — Cold-Start Latency

vLLM cold-start time is a critical secondary latency factor. The table below compares the three viable strategies:

| Strategy                                    | Cold-Start Time    | Cloud-Agnostic | Notes                                                                                   |
| ------------------------------------------- | ------------------ | -------------- | --------------------------------------------------------------------------------------- |
| **Full HuggingFace Download** (baseline)    | ~20 minutes        | ✅             | Downloads all shards; blocked by HF rate limits                                         |
| **GCS Fuse GCFS Image Streaming** (removed) | ~2–5 minutes       | ❌ GKE-only    | Lazy-pull from GCS via GKE-proprietary CSI driver; no longer used                       |
| **MinIO + vLLM Tensorizer** (current)       | **~60–90 seconds** | ✅             | vLLM native `--load-format tensorizer`; streams serialized shards from in-cluster MinIO |

### Current Approach: vLLM Native Tensorizer from MinIO

Model weights are pre-serialized to TensorSerializer format via a one-time GPU Job ([`deployment/k8s/tensorize-job.yaml`](../deployment/k8s/tensorize-job.yaml)) and stored in a MinIO bucket (S3-compatible, already deployed in the cluster). The bucket name is parameterized via `${MINIO_BUCKET}` at apply time.

At pod startup, vLLM streams individual tensor shards on demand via the S3 API — no POSIX filesystem mount, no GKE-proprietary CSI sidecar injector required.

The tensorize job ([`deployment/k8s/tensorize-job.yaml`](../deployment/k8s/tensorize-job.yaml)):
- Runs on an NVIDIA L4 GPU node (same node class as inference pods)
- Downloads from HuggingFace Hub → serializes via `TensorSerializer` → uploads to MinIO at `s3://${MINIO_BUCKET}/${MODEL_NAME_SANITIZED}/model.tensors`
- MinIO endpoint: `http://minio.governance-stack.svc.cluster.local:9000`
- Auto-cleans up 1 hour after completion (`ttlSecondsAfterFinished: 3600`)

**Why this is preferable to GCS Fuse:**

- **~60–90s vs ~2–5min** cold-start vs GCFS (shards are serialized and compact — no per-shard conversion overhead at runtime).
- **Cloud-agnostic:** MinIO works on EKS, AKS, bare-metal, or any Kubernetes distribution.
- **Eliminates** the `gcsfuse.csi.storage.gke.io` CSI driver and `gke-gcsfuse/volumes: "true"` annotation dependency.
- **No extra pip packages:** `--load-format tensorizer` is vLLM native.

## SymbolicGovernor CBF+OPA Concurrency

Within the `SymbolicGovernor._run_checks()` pipeline, **CBF (`verify_action()`) and OPA run concurrently** via `asyncio.gather` (Steps 2+4). Combined latency is `max(CBF_ms, OPA_ms)` rather than `CBF_ms + OPA_ms`. This is intentional design:

- `ControlBarrierFunction.verify_action()` is **read-only** — it reads `safety:current_cash` from Redis but does not modify state.
- The TOCTOU race between the CBF balance check and actual trade execution is closed by **FiscalLimitGuard** (Step 3) using atomic `WATCH/MULTI/EXEC` pre-reservation against `fiscal:daily_limit:{YYYY-MM-DD}`, **not** by making CBF+OPA sequential.

## Governance Pipeline Ordering (Inference Proxy)

The [`/inference/v1/chat/completions`](../src/gateway/server/inference_proxy.py:165) endpoint applies governance checks in this fixed order:

1. **Tier-1 Aho-Corasick keyword scan** — synchronous, sub-millisecond; blocks on keyword match before any network call
2. **NeMo Guardrails input verification** ([`verify_input()`](../src/gateway/governance/nemo/manager.py:614)) — semantic input rail; ~150–300ms
3. **Forward to vLLM backend** — pooled `httpx.AsyncClient`; supports streaming SSE (`stream=True`) with per-chunk TTFT capture on OTel spans (`gen_ai.ttft_ms`)
4. **NeMo output verification + PII masking** ([`verify_and_mask_output()`](../src/gateway/governance/nemo/manager.py:679)) — Presidio-backed; skipped in `CAGE_SEAL_ENFORCEMENT != enforce` (dev) mode

Backend routing is model-aware: requests with `"deepseek"` or `"reasoning"` in the model ID route to `VLLM_REASONING_API_BASE`; all others route to `VLLM_FAST_API_BASE` (see [`_resolve_backend_url()`](../src/gateway/server/inference_proxy.py:137)).

## SLM Semantic Similarity Sidecar (Deprecated)

> **Deprecated as of v2.0.x.** The SLM sidecar has been **completely deprecated to optimize latency**. [`symbolic_governor.py`](../src/gateway/governance/symbolic_governor.py:47) hardcodes `slm_available = False` and injects an `"slm_available": false` sentinel into every OPA payload. The Tier-2 semantic similarity check no longer executes at runtime.

The sidecar code ([`src/gateway/slm/slm_server.py`](../src/gateway/slm/slm_server.py)) and the `slm` service in [`docker-compose.yml`](../docker-compose.yml:42) remain in the repository for reference but are not active in the governance pipeline. The `slm` optional dependency group in [`pyproject.toml`](../pyproject.toml:98) (`flask`, `sentence-transformers`) is similarly retained but not installed in production images.
