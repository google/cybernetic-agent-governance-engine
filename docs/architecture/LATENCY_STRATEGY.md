# Latency as Currency: Funding Governance with Inference Speed

**Last Updated:** 2026-10-22

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
2.  **Policy Evaluation (OPA):** ~10-50ms warm (sidecar network hop + Rego eval); up to ~20s on first evaluation after a pod rollout (cold-start). Mitigated by gateway boot-time pre-warming (see below).
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
    - **vLLM TTFT (Warm):** 40ms (cold-start up to 20s; mitigated by gateway pre-warming)
    - Generation (100 tokens): 150ms
3.  **Total Governance Overhead:** ~200ms

**Result:** The user gets a structurally guaranteed, compliant response with minimal added delay compared to a raw LLM call.

## Latency Reduction Mechanisms

The following mechanisms are implemented in code and actively reduce governance overhead:

### 1. No OPA Decision Cache

[`OPAClient.evaluate_policy()`](../../src/gateway/core/policy.py) sends every decision to OPA, so a policy or data change takes effect on the next request. The Redis decision cache it used to consult (10 s TTL) almost never hit on the trade path, where each `execute_trade` carries a fresh `transaction_id`, so those checks paid a Redis read and write for nothing. Where inputs did repeat (read-only actions, and the repeated-input benchmark recorded in [`PROVENANCE.md`](../paper/measurements/2026-10-03-c0e3b14e/PROVENANCE.md)), it hid OPA latency and could serve a decision for up to 10 s after a policy or data change.

### 2. Circuit Breaker (Fail-Fast, Latency Budget Enforcement)

`CircuitBreaker` in `policy.py` protects the governance path from cascading failures:

- **Failure threshold:** 5 consecutive upstream failures (connect, read or protocol errors, HTTP 5xx, or 408/429 from a proxy) → circuit OPEN, and every check fails fast with `DENY`. A healthy answer resets the count, so the rule does not depend on traffic volume: a dead OPA trips it at any request rate, and rare errors between healthy answers never do.
- **Not counted:** HTTP 4xx answers (OPA is up but rejected the query), local connection-pool saturation (`httpx.PoolTimeout`), and local misconfiguration (an unusable `OPA_URL`, an illegal header value); each denies that request without tripping the breaker
- **Recovery:** after 30 seconds the next call is the single HALF_OPEN probe; a healthy answer closes the circuit, an upstream failure reopens it, and other callers keep failing fast until the probe finishes
- **Hard latency budget:** 3000ms (`max_latency_budget`) — a caller that passes its elapsed governance time as `current_latency_ms` gets `DENY` once it exceeds this ("Bankruptcy Protocol"). No in-repo caller passes it yet (`OpaStage`, the MCP tool server and the warm-up use the default of 0), so the budget is not enforced in production today.
- **Soft ceiling:** 2000ms — emits a `Latency Inflation Warning` log but does not block (same `current_latency_ms` caveat)

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

### 6. Pooled Async Redis Clients & Process-Scoped `DeferQueue`

Both Redis clients enforce strict connection timeouts and connection pooling to prevent governance hangs and per-request TCP/TLS handshake churn:

**Gateway Redis** ([`src/gateway/infrastructure/redis_client.py`](../../src/gateway/infrastructure/redis_client.py)):
- `BlockingConnectionPool` (`REDIS_MAX_CONNECTIONS=50`, `REDIS_POOL_TIMEOUT=3.0s`), `socket_connect_timeout=3.0s`, `socket_timeout=3.0s`, `health_check_interval=30s`, and bounded exponential-backoff `Retry` on transient connection errors
- Process-scoped [`DeferQueue`](../../src/gateway/governance/defer_queue.py) singleton (`get_shared_defer_queue()`, pre-warmed at gateway boot with pre-loaded Lua script SHAs via `ensure_scripts_loaded()`)
- Proactive background GCP IAM token refresh (`GcpRedisIamCredentialProvider` in [`redis_credential_provider.py`](../../src/integrations/gcp/redis_credential_provider.py)) inside the 600s pre-expiry window

**GFA Redis** (`src/governed_financial_advisor/infrastructure/redis_client.py`):
- `socket_connect_timeout=2.0s`, `socket_timeout=5.0s`, `max_connections=100`
- Supports Redis Sentinel (auto-detected via port 26379 probe) for HA deployments
- Used by: LangGraph checkpointer (db=0), `QueryCache`

### 7. DEFER Queue (4-Hour Park Window)

`DeferQueue` implements a fourth decision state (ALLOW | DENY | REQUIRE_APPROVAL | **DEFER**) that prevents operational fatigue from forcing binary decisions under fundamentally incomplete context:

- **Confidence-Starvation Boundary:** `confidence.defer_floor = 0.70` (`get_confidence_defer_floor()`) — execution contexts with confidence below this route to DEFER rather than REQUIRE_APPROVAL
- **Park TTL:** `_DEFAULT_TTL = 14400s` (4 hours) before auto-escalation to MANUAL_REVIEW
- **Redis isolation:** `db=1` with `noeviction` maxmemory policy (separate from LangGraph checkpointer at `db=0`)
- **Data structures:** Redis Hash `DEFER:{defer_id}` + ZSet `DEFER:expiry_index` (scored by expiry timestamp)

### 8. Background DoWhy Causal World-Model Refresher (Zero Hot-Path Refutation)

[`WorldModelRefresher`](../../src/gateway/governance/causal/world_model_refresher.py) moves CPU-intensive DoWhy `CausalModel` construction, backdoor linear-regression estimation, and 100-simulation placebo refutation completely off the request thread into a background daemon loop (`CAUSAL_REFRESH_INTERVAL_SECONDS=30`, `CAUSAL_WORLD_MODEL_TTL_SECONDS=90`). Request-path [`CausalGatekeeper.verify_action_causality()`](../../src/gateway/governance/causal/gatekeeper.py) performs a single Redis read (`causal:v1:{domain}:{action_type}:{regime}`) in $<1\text{ ms}$ and fails closed (`CAUSAL_WORLD_MODEL_STALE`) on a cache miss without blocking the asyncio event loop.

### 9. Async KMS Signing & Cached Key Metadata

[`KMSGovernanceSigner`](../../src/gateway/governance/kms_signer.py) (`sign_async`, `sign_decision_async`) offloads Cloud KMS HSM signing to a dedicated `ThreadPoolExecutor` (`cage-kms`) bounded by `asyncio.Semaphore` (`CAGE_KMS_MAX_CONCURRENCY=16`) and `CAGE_KMS_SIGN_TIMEOUT_SECONDS=5.0`. [`GCPKMSProvider`](../../src/integrations/gcp/kms_provider.py) caches key algorithm metadata (`digest_algorithm`, `jose_alg`, `uses_rsa_pss`) at initialization/readiness and `KMSGovernanceSigner.public_jwk` caches the parsed public JWK, eliminating per-seal `GetCryptoKeyVersion` RPCs and PEM parsing.

### 10. Evidence Stream Group-Commit Micro-Batching

[`EvidenceStreamSink`](../../src/gateway/governance/evidence/stream.py) runs a single background group-commit appender per gateway process fed by a bounded `asyncio.Queue` (`EVIDENCE_GROUP_COMMIT_QUEUE_SIZE=1024`). The appender coalesces up to `EVIDENCE_GROUP_COMMIT_MAX_BATCH=64` JCS-normalized records within `EVIDENCE_GROUP_COMMIT_MAX_WAIT_MS=2.0` ms, chains the batch locally, and commits all `k` records atomically via `_APPEND_BATCH_SCRIPT` (`EVALSHA`), re-chaining automatically on multi-replica head contention while preserving per-record `(msg_id, record_hash, sequence)` routing-seal binding (`B2`).

### 11. Single-Evaluation Trade Preview Reuse (`routing_verdict_cache`)

In the Governed Financial Advisor graph, [`evaluator_node`](../../src/governed_financial_advisor/graph/nodes/evaluator_node.py) and [`safety_check_node`](../../src/governed_financial_advisor/graph/nodes/safety_node.py) record the `ALLOW` preview verdict of a single-trade plan in `AgentState["routing_verdict_cache"]`, bound to the SHA-256 digest of the full canonical `execute_trade` payload, including `confidence` ([`canonical_trade_digest()`](../../src/governed_financial_advisor/graph/nodes/trade_contract.py), `30s` TTL). When `governed_trader` immediately invokes [`gateway_tool_guard("execute_trade")`](../../src/governed_financial_advisor/graph/governance/tool_guard.py) with a single tool call for the same order, the guard reuses the cached preview once ([`reusable_allow_verdict()`](../../src/governed_financial_advisor/graph/nodes/trade_contract.py)) and clears it, avoiding a duplicate 8-tier preview round-trip before the committing `POST /tools/execute` (`execute_trade_action`) dispatch. A tool call carrying any field outside the canonical payload (for example `limit_price`, `account_id` or `transaction_id`) always gets a fresh preview, and a multi-step plan is never cached.

### 12. Stateless MCP Streamable HTTP, 300s Tool Cache & `uvloop`/`httptools`

The gateway runs Uvicorn with `loop="uvloop"` and `http="httptools"` ([`hybrid_server.py`](../../src/gateway/server/hybrid_server.py)) and serves FastMCP over stateless Streamable HTTP (`/mcp/`, [`mcp_tool_server.py`](../../src/gateway/server/mcp_tool_server.py)). [`GatewayMCPClient`](../../src/gateway/infrastructure/mcp_client.py) reuses a persistent pooled `httpx.AsyncClient` and caches `list_tools()` / `get_tools()` for `300s` (`CAGE_MCP_TOOLS_CACHE_TTL_S`).

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
5. **Forward to vLLM backend** — pooled `httpx.AsyncClient`. With `stream=True` the proxy reads the whole upstream SSE stream before step 6 and only then replays it, so the client's time to first token equals the full generation time; `gen_ai.ttft_ms` on the OTel span measures the *upstream* first token, not what the client sees (see [GATEWAY_ARCHITECTURE.md §5.5](GATEWAY_ARCHITECTURE.md#55-content-rails-and-streaming-egress))
6. **NeMo output verification + PII masking** (`verify_and_mask_output()`) — Presidio-backed; applied to message content and tool-call arguments in every environment (NeMo rails always fail closed)

Backend routing is model-aware: requests with `"deepseek"` or `"reasoning"` in the model ID route to `VLLM_REASONING_API_BASE`; all others route to `VLLM_FAST_API_BASE` (see `_resolve_backend_url()`).

