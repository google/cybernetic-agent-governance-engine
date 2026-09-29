# Latency as Currency: Funding Governance with Inference Speed

**Last Updated:** 2026-09-29

> **Universal Baseline:** Audit logging latency requirements are governed by **ISO 42001 §A.9.2** (evidence integrity) universally across all `CAGE_DEPLOYMENT_REGION` values. Jurisdiction-specific SLA authorities are listed in the table below.
>
> | Jurisdiction | Audit Logging SLA Authority | Max Governance Overhead |
> |-------------|----------------------------|------------------------|
> | **Universal** | ISO 42001 §A.9.2 | < 2s total response time |
> | **US_FED** | NIST SP 800-53 AU-12 (additionally) | 200ms governance overhead |
> | **EU_ECB** | DORA Art. 10 (additionally) | 200ms governance overhead |
> | **APAC_MAS** | MAS Notice 655 (additionally) | 200ms governance overhead |

This document outlines the performance strategy for the Cybernetic Governance Engine. The core philosophy is **"Latency as Currency"**: we must generate tokens fast enough to "pay for" the overhead of strict governance checks (NeMo, OPA, JSON Enforcement).

## The Governance Tax

Every safe generation incurs a latency penalty:

1.  **Semantic Guardrails (NeMo):** ~150-300ms (Input/Output checks).
2.  **Policy Evaluation (OPA):** ~10-50ms warm (sidecar network hop + Rego eval); up to ~20s on first evaluation after a pod rollout (cold-start). Mitigated by the OPA Decision Cache (see below).
3.  **Syntactic Enforcement (vLLM Native JSON-mode API):** ~50ms. The `outlines` library was removed from CAGE's client-side dependencies due to CVE-2025-69872 (diskcache pickle RCE); vLLM's native JSON-mode API is used instead.

To maintain a responsive user experience (Total Response Time < 2s for simple queries), the underlying inference engine must be exceptionally fast. The `CircuitBreaker` in `OPAClient` enforces a hard latency budget of **3000ms** and emits a soft-ceiling warning at **2000ms**.

## The Solution: "The Enforcer" on NVIDIA L4

We utilize a dedicated, self-hosted inference node for structure enforcement, optimized for speed and cost.

### Hardware: NVIDIA L4 (24GB VRAM) on On-Demand `g2-standard-8`

- **Why:** The L4 is the most cost-effective GPU for models < 20B parameters. The `gcp-gke` target runs the `gpu-l4` pool on on-demand `g2-standard-8` nodes (1× L4) — Spot is not used for inference — and saves cost by scaling the pool to zero when idle (0–2 nodes by default).
- **Capacity:** A single L4 comfortably hosts the default fast model `Qwen/Qwen2.5-1.5B-Instruct` (`served_model_fast`), and has room for models up to ~7B in float16 with KV cache.
- **Throughput:** Capable of high token-per-second generation for JSON structures.

### Software: vLLM + Guided Decoding

We use **vLLM** with its **native JSON-mode API** for structured output enforcement. The `--guided-decoding-backend outlines` flag and the `outlines` Python package have been **removed** due to CVE-2025-69872 (diskcache pickle RCE); vLLM's built-in JSON-mode decoder is used instead (provisioned via [`infra/modules/vllm_inference/main.tf`](../../infra/modules/vllm_inference/main.tf)).

> **Note on Prefix Caching:** Enabling `--enable-prefix-caching` on the vLLM inference deployment (`infra/modules/vllm_inference/main.tf`) is a planned optimization that would reduce TTFT for repeated schema prefixes from ~200ms to <50ms. It is **not yet enabled** in the Terraform module and should be treated as aspirational until added.

#### How vLLM Native JSON-Mode Works

1.  **The Pattern:** Every governance request shares the same massive system prompt: "You are a governance engine. Output JSON matching this schema: { ... complex schema ... }".
2.  **The Constraint:** vLLM's native JSON-mode API enforces structured output over the token vocabulary, guaranteeing structurally valid JSON output without requiring the `outlines` package.
3.  **The Result:** Structurally guaranteed, compliant JSON responses with no post-processing parse failures.

> **Note on `outlines` removal:** The `outlines` Python package has been **removed** from CAGE's dependencies (`pyproject.toml`) due to CVE-2025-69872 (diskcache pickle RCE). vLLM's native JSON-mode API is used for all structured output enforcement. CAGE does not import or depend on `outlines`.

### Architecture Alignment

| Component      | Model                              | Hosted On            | Optimization                        |
| -------------- | ---------------------------------- | -------------------- | ----------------------------------- |
| **Reasoning**  | `deepseek-ai/DeepSeek-R1-Distill-Llama-8B` | GPU (NVIDIA L4) | Deep semantic understanding.        |
| **Fast / Governance** | `Qwen/Qwen2.5-1.5B-Instruct` (default `served_model_fast`) | GPU (NVIDIA L4) | Structured JSON (vLLM native JSON-mode API). |
| **Guardrails** | NeMo Guardrails service            | CPU pod (0.5–1 vCPU, 1–2Gi RAM) | In-cluster, no GPU required.  |

The reasoning model name (`deepseek-ai/DeepSeek-R1-Distill-Llama-8B`) is the default resolved by `create_nemo_manager()` via the `GUARDRAILS_MODEL_NAME` / `MODEL_FAST` env vars. Both fast and reasoning vLLM deployments are provisioned via Terraform ([`infra/modules/vllm_inference/main.tf`](../../infra/modules/vllm_inference/main.tf)); the served model IDs default to `served_model_fast` / `served_model_reasoning` in `infra/targets/gcp-gke/variables.tf`. Raw static vLLM manifests under `deployment/k8s/` have been retired.

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

[`src/gateway/core/policy.py`](../../src/gateway/core/policy.py) implements a short-TTL Redis cache for OPA decisions. Identical OPA inputs (same action + symbol + amount) within a **10-second window** return the cached decision without an HTTP round-trip.

- **Key prefix:** `cage:opa:decision:` (SHA-256 of canonical JSON input, first 24 hex chars)
- **TTL:** `_OPA_CACHE_TTL_SECONDS = 10` — intentionally short to avoid stale decisions under fast market moves
- **Toggle:** `OPA_CACHE_ENABLED` env var (default: `"true"`); set to `"false"` to disable in unit test environments
- **Failure mode:** Cache write/read failures are silent — the OPA HTTP path remains authoritative

### 2. Circuit Breaker (Fail-Fast, Latency Budget Enforcement)

`CircuitBreaker` in `policy.py` protects the governance path from cascading failures:

- **Failure threshold:** 5 consecutive failures → circuit OPEN
- **Recovery timeout:** 30 seconds before attempting half-open probe
- **Hard latency budget:** 3000ms (`max_latency_budget`) — requests exceeding this are fast-failed with `DENY` ("Bankruptcy Protocol")
- **Soft ceiling:** 2000ms — emits a `Latency Inflation Warning` log but does not block

### 3. Gateway Boot-Time Pre-Warming

[`hybrid_server.py`](../../src/gateway/server/hybrid_server.py) pre-warms both NeMo Rails and OPA at pod startup via the `_gateway_lifespan` async context manager:

- **NeMo Rails:** `initialize_rails()` is called once at boot; the resulting `LLMRails` instance is shared across all sub-apps (`inference_app`, `mcp_app`) via `app.state.nemo_rails`, eliminating per-request JIT compilation overhead.
- **OPA:** After `_activate_domain()` builds the governor (including the OPA package/rule handshake), a synthetic dry-run `system_warmup_test` evaluation is fired through `governor.components.opa` to warm the Rego schema and HTTP connection pool.

### 4. Pooled HTTP Connections

Two separate pooled `httpx.AsyncClient` instances eliminate TCP handshake overhead on the hot governance path:

**Inference Proxy → vLLM** (`inference_proxy.py`):
- `max_connections=50`, `max_keepalive_connections=20`, `keepalive_expiry=30s`
- Timeouts: `connect=5.0s`, `read=120.0s`, `write=30.0s`, `pool=5.0s`
- Lazy singleton; closed on app shutdown

**GFA → Governance Infrastructure** (`http_pool.py`):
- `max_connections=50`, `max_keepalive_connections=20`, timeout=30s
- Exponential back-off retry for HTTP 429 / 503 (3 attempts, base delay 1.0s)

### 5. Query Cache (Redis, 1-Hour TTL)

`QueryCache` in the GFA service caches responses for deterministic educational and regulatory queries only. Market data, personalized advice, and trading actions are **never cached**.

- **TTL:** 3600s (1 hour, configurable via `QUERY_CACHE_TTL` env var)
- **Toggle:** `ENABLE_QUERY_CACHE` env var (default: `"true"`)
- **Backend:** Redis primary, in-process dict fallback when Redis is unavailable
- **Expected hit rate:** 20–30% (educational queries)
- **Cache key:** `query_cache:<sha256[:16]>` of normalized (lowercased, whitespace-collapsed) query

### 6. Redis Client Timeouts

Both Redis clients enforce strict connection timeouts to prevent governance hangs:

**Gateway Redis** (`src/gateway/infrastructure/redis_client.py`):
- `socket_connect_timeout=3.0s`, `socket_timeout=3.0s`
- Used by: OPA Decision Cache, `ControlBarrierFunction`

**GFA Redis** (`src/governed_financial_advisor/infrastructure/redis_client.py`):
- `socket_connect_timeout=2.0s`, `socket_timeout=5.0s`, `max_connections=100`
- Supports Redis Sentinel (auto-detected via port 26379 probe) for HA deployments
- Used by: LangGraph checkpointer (db=0), `QueryCache`

### 7. DEFER Queue (4-Hour Park Window)

`DeferQueue` implements a fourth decision state (ALLOW | DENY | REQUIRE_APPROVAL | **DEFER**) that prevents operational fatigue from forcing binary decisions under fundamentally incomplete context:

- **Confidence-Starvation Boundary:** `DEFER_CONFIDENCE_THRESHOLD = 0.70` — execution contexts with confidence below this route to DEFER rather than REQUIRE_APPROVAL
- **Park TTL:** `_DEFAULT_TTL = 14400s` (4 hours) before auto-escalation to MANUAL_REVIEW
- **Redis isolation:** `db=1` with `noeviction` maxmemory policy (separate from LangGraph checkpointer at `db=0`)
- **Data structures:** Redis Hash `DEFER:{defer_id}` + ZSet `DEFER:expiry_index` (scored by expiry timestamp)

## Model Weight Loading — Cold-Start Latency

vLLM cold-start time is a critical secondary latency factor, especially because the `gpu-l4` pool scales to zero when idle. The `gcp-gke` target combines three mechanisms:

| Mechanism | Where | Effect |
| --------- | ----- | ------ |
| **GCS weight streaming** (`runai_streamer`) | `module.vllm` / `module.vllm_reasoning` in [`infra/targets/gcp-gke/main.tf`](../../infra/targets/gcp-gke/main.tf) | When `model_fast` / `model_reasoning` is a `gs://` path, vLLM runs with `--load-format runai_streamer` and streams weights from the project's model bucket (`${project_id}-models` by default); no Hugging Face download at startup |
| **GKE image streaming** (`gcfs_config`) | `gpu-l4` node pool in [`infra/modules/gcp_gke_cluster/main.tf`](../../infra/modules/gcp_gke_cluster/main.tf) | Lazy-pulls the large `vllm-streamer` container image so the pod starts before the full image is downloaded |
| **Non-blocking rollout** (`wait_for_rollout = false`) | [`infra/modules/vllm_inference/main.tf`](../../infra/modules/vllm_inference/main.tf) | `terraform apply` does not block on a GPU node scaling up from zero; the autoscaler uses `location_policy = "ANY"` to find L4 capacity in any zone |

### Weight Source and Egress

- Weights are staged once in the model bucket; the vLLM workload identity holds only bucket-scoped `roles/storage.objectViewer` and `roles/storage.legacyBucketReader` (the latter for `storage.buckets.get`, required by `runai_model_streamer_gcs`), defined in [`infra/targets/gcp-gke/iam.tf`](../../infra/targets/gcp-gke/iam.tf).
- `HF_HUB_OFFLINE=1` and `TRANSFORMERS_OFFLINE=1` forbid runtime egress to `huggingface.co`, and no Hugging Face token is baked into the vLLM image or passed to the pods.
- A non-`gs://` model path falls back to vLLM's `auto` load format (used by the `agnostic` target via `var.vllm_model_path`).

> [!NOTE]
> The older MinIO + Tensorizer path ([`deployment/k8s/tensorize-job.yaml`](../../deployment/k8s/tensorize-job.yaml)) is not wired into either Terraform target; the `gcp-gke` target streams from GCS as described above.

## Governor Pipeline Ordering (Two-Phase)

`run_pipeline()` ([`src/gateway/governance/governor/pipeline.py`](../../src/gateway/governance/governor/pipeline.py)) runs stages **sequentially**, not concurrently, so governance latency is the sum of the stages that actually run:

- **Phase 1 (read-only):** `ftra` → `stpa` → `opa` → `confidence` → read-only domain tiers, stopping at the first HARD violation. Ungoverned actions (no domain tier claims them) run only `ftra`, `stpa` and `opa`.
- **Phase 2 (mutating):** runs only if Phase 1 produced zero violations. Commits (e.g. the CBF debit and the finance plugin's fiscal reservation) go through a `ReservationScope` and are rolled back LIFO if the pipeline or seal issuance fails, which is what closes the TOCTOU window between check and commit. The `DRY_RUN` profile calls each mutating stage's side-effect-free `preview()` instead.

## Governance Pipeline Ordering (Inference Proxy)

The `/inference/v1/chat/completions` endpoint applies governance checks in this fixed order:

1. **Tier-1 Aho-Corasick keyword scan** — synchronous, sub-millisecond; applied to all messages; blocks on keyword match before any network call
2. **Caller identity** — `extract_client_identity()` reads the Linkerd `l5d-client-id`; failure returns HTTP 401
3. **Token/step quota** — `check_and_increment()` on the token quota proxy; exceeding it returns HTTP 429
4. **NeMo Guardrails input verification** (`verify_input()`) — semantic input rail; ~150–300ms; any downstream failure rolls back the quota step
5. **Forward to vLLM backend** — pooled `httpx.AsyncClient`; supports streaming SSE (`stream=True`) with per-chunk TTFT capture on OTel spans (`gen_ai.ttft_ms`)
6. **NeMo output verification + PII masking** (`verify_and_mask_output()`) — Presidio-backed; applied to message content and tool-call arguments in every environment (NeMo rails always fail closed)

Backend routing is model-aware: requests with `"deepseek"` or `"reasoning"` in the model ID route to `VLLM_REASONING_API_BASE`; all others route to `VLLM_FAST_API_BASE` (see `_resolve_backend_url()`).

