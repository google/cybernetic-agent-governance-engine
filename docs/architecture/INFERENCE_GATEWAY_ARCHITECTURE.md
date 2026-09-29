# Inference Gateway Architecture — v3.0.1

## Executive Summary

This document analyzes the feasibility and impact of migrating the current "Sovereign" AI architecture (Split-Brain: Reasoning vs. Governance) to use a Kubernetes Inference Gateway.

> **Universal Baseline:** The primary architectural driver for CAGE governance is **ISO/IEC 42001:2023** — applicable to all `CAGE_DEPLOYMENT_REGION` values (US_FED, EU_ECB, APAC_MAS). The Inference Gateway's priority handling ensures governance checks are never starved of capacity, satisfying ISO 42001 §A.8.4 (AI system operation controls) universally.

> **US_FED Only:** SR 26-2 (Federal Reserve supervisory guidance, April 17, 2026) applies exclusively to `CAGE_DEPLOYMENT_REGION=US_FED` deployments. SR 26-2 has no legal force outside the US Federal Reserve system (see `.roo/rules` §12.4). References to SR 26-2 in this document are scoped to US_FED deployments only.

The `GatewayClient` (`src/gateway/core/llm.py`) supports routing traffic through the **Inference Gateway** (nginx GatewayClass) at the infrastructure layer when `VLLM_GATEWAY_URL` is set, enabling advanced traffic management, autoscaling, and priority handling critical for regulatory compliance. When it is unset — the default in the `gcp-gke` Terraform target (`vllm_gateway_url = ""`) — the client connects directly to the two vLLM Services.

**Status:** **OPTIONAL** — client-side Gateway Mode implemented; the `deployment/k8s/inference-gateway/` manifests are applied manually and are not provisioned by the `gcp-gke` Terraform target, which runs **DIRECT** mode by default
**Version:** v3.0.1
**Last Updated:** 2026-09-29

> **Update 2026-03-03:** The GatewayClass has been migrated from the GKE-proprietary `gke-l7-gxlb` to the portable `nginx` GatewayClass (see `deployment/k8s/inference-gateway/gateway.yaml`). Gateway API CRDs are now installed via Helm rather than the GKE-managed `gateway_api_config.channel`. This eliminates the hard GKE dependency while preserving all routing, priority, and autoscaling capabilities.

> **Update 2026-05-31:** The OTel Collector sidecar has been **deprecated**. All telemetry now flows via direct Langfuse OTLP ingestion; the gateway manifests set `OTEL_EXPORTER_OTLP_ENDPOINT` to `http://langfuse-web.governance-stack.svc.cluster.local:3000/api/public/otel/v1/traces`. Remove any `OTEL_EXPORTER_OTLP_ENDPOINT` references pointing to a collector.

> **Update (BREAKING, #300):** Caller identity at the gateway edge is derived exclusively from the Linkerd mTLS workload identity (`l5d-client-id`) matched against `CAGE_TRUSTED_CLIENT_IDENTITIES`. The `X-Agent-ID` header, any body-supplied `agent_id`, SPIFFE-style headers and the anonymous fallback have been removed; unauthenticated requests are refused. See [§6](#6-agent-identity-at-the-inference-edge-linkerd-mtls-workload-identity) and the canonical [`AGENT_IDENTITY_BINDING_SPEC.md`](AGENT_IDENTITY_BINDING_SPEC.md).


---

## 1. Current Architecture vs. Proposed Architecture

### Current State (Application-Side Routing)

- **Logic:** `src/gateway/core/llm.py` (`GatewayClient`) contains if/else logic to select the backend based on `mode` (e.g., `planner` -> `vllm-reasoning`, `fast` -> `vllm-service`).
- **Infrastructure:** Two separate Kubernetes Services (`vllm-reasoning`, `vllm-service`) provisioned via `infra/modules/vllm_inference/main.tf` (instantiated as `module.vllm` and `module.vllm_reasoning` in `infra/targets/gcp-gke/main.tf`).
  - **Weights:** Loaded from the GCS model bucket with vLLM's `runai_streamer` load format when the model path is `gs://…`; `HF_HUB_OFFLINE=1` / `TRANSFORMERS_OFFLINE=1` forbid runtime egress to Hugging Face, and no HF token is baked into images.
  - **Nodes:** The `gpu-l4` pool (`g2-standard-8`, 1× NVIDIA L4, on-demand — no Spot) scales 0–2 by default with image streaming (`gcfs_config`) enabled and autoscaler `location_policy = "ANY"`; vLLM CPU/memory defaults are sized to `g2-standard-8` allocatable. Terraform does not wait for vLLM rollout (`wait_for_rollout = false`), so GPU cold starts do not block `terraform apply`.
  - **Images:** The `vllm-streamer` image is referenced by digest from `var.image_digests`.
- **Scaling:** No vLLM HPA; each deployment runs `var.vllm_replicas` (default `1`) and GPU capacity comes from cluster-autoscaler on the `gpu-l4` pool (reactive).

### Proposed State (Kubernetes Inference Gateway)

- **Logic:** `GatewayClient` points to a single endpoint (the Inference Gateway). It specifies a `model` name (e.g., `llama-3.1-8b-instruct`, `deepseek-r1-distill-llama-8b`).
- **Infrastructure:**
  - **Gateway:** A unified Kubernetes Gateway resource.
  - **InferencePools:** Custom resources defining the backend pools (`vllm-reasoning`, `vllm-service`).
  - **HTTPRoutes:** Rules mapping `model` names or headers to specific pools.
- **Scaling:** Metric-based HPA (Queue Depth, KV Cache Usage) managed by the Gateway controller (proactive).

---

## 2. Cost/Benefit Analysis

### Pros (Benefits)

1.  **Criticality & Priority Handling (Governance)**
     - **Feature:** The Inference Gateway supports **Priority** classes.
     - **Impact:** We can assign higher priority to "Governance" traffic (System 2 checks). Even if the "Reasoning" (System 1) pool is saturated with complex queries, the Governance checks (which block trade execution) will be prioritized or routed to reserved capacity. This satisfies **ISO 42001 §A.8.4** (AI system operation controls — universal, all regions) — safety checks must never fail due to congestion. The 200ms max latency SLA (ISO-20022) is enforced at the gateway layer. > **US_FED Only:** This also satisfies **SR 26-2 Model Risk Management** requirements for `CAGE_DEPLOYMENT_REGION=US_FED` deployments.

2.  **Optimized Autoscaling**
    - **Feature:** Uses custom metrics like **Queue Length** and **KV Cache Usage** (Time-to-First-Token optimization).
    - **Impact:** Scale up `vllm-reasoning` nodes _before_ latency spikes, ensuring consistent performance for the Planner Agent. Standard CPU scaling is often too slow for LLM inference bursts.

3.  **Simplified Client Code**
    - **Feature:** Single endpoint URL.
    - **Impact:** `GatewayClient` becomes a standard OpenAI client. We remove the custom "Dual-Client" logic, reducing coupling and making it easier to swap underlying models without code changes.

4.  **LoRA Adapter Support**
    - **Feature:** Efficiently serves multiple fine-tuned adapters on a shared base model.
    - **Impact:** Future-proofing. If we train specific LoRA adapters for "Risk Analysis" or "Compliance," we can serve them on the existing `vllm-reasoning` pool without deploying new heavy pods.

### Cons (Costs & Risks)

1.  **Environment Divergence (Local vs. Prod)**
    - **Risk:** The Inference Gateway does not exist in Docker Compose.
    - **Mitigation:** We must maintain the `GatewayClient`'s ability to support "Direct Mode" (current logic) for local development, while switching to "Gateway Mode" (single URL) in production via `Config`.

2.  **Infrastructure Complexity**
    - **Cost:** Requires installing Gateway API CRDs (via Helm) and managing new manifests (`InferencePool`, `InferenceGateway`).
    - **Mitigation:** Use Kustomize overlays to keep production-specific resources separate from base deployment manifests.

3.  **Vendor Lock-in** _(Mitigated)_
    - **Previous Risk:** The original `gke-l7-gxlb` GatewayClass was GKE-proprietary.
    - **Current State (2026-03-03):** Migrated to `nginx` GatewayClass. The implementation is now portable — switching providers requires only a GatewayClass name change.

---

## 3. Migration Strategy

To adopt this without disrupting the current workflow, we recommend a phased approach:

### Phase 1: Infrastructure Preparation (DevOps)

1.  Install Gateway API CRDs via Helm (`kubectl apply -f` or `helm install gateway-api`).
2.  Define `InferencePool` resources for `vllm-reasoning` and `vllm-service`.
3.  Deploy the `InferenceGateway` with `gatewayClassName: nginx`.

### Phase 2: Application Update (Code) — done

`src/gateway/core/llm.py` reads `VLLM_GATEWAY_URL` (`config/settings.py`):
- If `VLLM_GATEWAY_URL` is set: a single `AsyncOpenAI` client, routing by `model` name (`MODEL_REASONING` / `MODEL_FAST`).
- If not set (Local / default GKE): dual-client logic against `VLLM_REASONING_API_BASE` and `VLLM_FAST_API_BASE`.

### Phase 3: Traffic Cutover

1.  Deploy updated Gateway Service to Prod.
2.  Set `VLLM_GATEWAY_URL` to the internal IP of the Inference Gateway.
3.  Verify routing and priority handling.

> [!WARNING]
> The manifests in `deployment/k8s/inference-gateway/` have not been realigned with the Terraform-provisioned vLLM pools. `http-route.yaml` routes on an `x-model-id` header (which `GatewayClient` does not send) to model IDs (`deepseek-ai/DeepSeek-R1-Distill-Qwen-32B`, `Qwen/Qwen2.5-7B-Instruct`) and a `vllm-inference` Service that differ from the `gcp-gke` defaults (`served_model_reasoning`, `served_model_fast`, Service `vllm-service`), and the `pool-governance` InferencePool selects `app: vllm-governance`. Align them before cutover.

---

## 4. Final Recommendation

**Proceed with Inference Gateway (nginx GatewayClass) adoption for the Production environment.**

The **Priority Handling** feature alone justifies the complexity, as it directly supports the "Neuro-Cybernetic" safety mandate: _Governance must always be available to block unsafe actions._ Using standard CPU scaling for the governance model is a safety risk during high load; the Inference Gateway mitigates this. This directly satisfies SR 26-2 §IV Model Risk Management requirements for agentic AI systems.

## DEFER Queue & AARM Vector Coverage

The Inference Gateway works in conjunction with the DEFER queue (AARM-V7) to handle confidence-starved contexts:

- **DEFER Queue:** Redis `db=1` (noeviction policy) holds contexts that fail the `min_trade_confidence: 0.95` threshold but are not outright denied. These are queued for human review or re-evaluation.
- **Gateway Role:** The Inference Gateway's priority routing ensures that DEFER queue re-evaluation requests are processed with appropriate priority — preventing starvation of deferred contexts during peak load.
- **AARM Coverage:** The 11-vector CSA AARM v1.0 threat model is enforced across the gateway layer:
  - AARM-V1: SHA-256 hash-chained context accumulator prevents context poisoning across inference calls.
  - AARM-V7: DEFER queue (Redis db=1 noeviction) handles confidence starvation.
  - AARM-V10: ConsensusModelRegistry ensures heterogeneous multi-model consensus for trades ≥$10,000 USD.

**Next Steps:**

1.  Align `deployment/k8s/inference-gateway/` with the Terraform-provisioned Services and served model names (see the warning in §3).
2.  Provision the Gateway resources from the `gcp-gke` Terraform target instead of a manual `kubectl apply`.

## 5. Deployment & Configuration Guide

To deploy the Inference Gateway and configure the application:

### Step 1: Apply Kubernetes Manifests

Apply the manifests located in `deployment/k8s/inference-gateway/`. This will create the `Gateway`, `HTTPRoute`s, and `ReferenceGrant`.

```bash
kubectl apply -f deployment/k8s/inference-gateway/
```

### Step 2: Retrieve the Gateway IP Address

Wait for the Gateway controller to assign an IP address to the `llm-gateway`.

```bash
# Check the status of the Gateway
kubectl get gateway llm-gateway -n default

# Extract the IP address directly
export GATEWAY_IP=$(kubectl get gateway llm-gateway -n default -o jsonpath='{.status.addresses[0].value}')
echo "Gateway IP: $GATEWAY_IP"
```

_Note: Depending on your cluster configuration, this might be an internal IP (ClusterIP) or an external LoadBalancer IP._

### Step 3: Configure the Application

Update your `.env` file to set the `VLLM_GATEWAY_URL` environment variable using the retrieved IP. This ensures configuration is managed centrally and securely.

```bash
# In your .env file
VLLM_GATEWAY_URL=http://<GATEWAY_IP>/v1
```

Then, redeploy the application stack using the deployment script. `deploy_all.sh` reads `VLLM_GATEWAY_URL` from `.env` and passes it to Terraform (`vllm_gateway_url`), which injects it into the gateway and advisor containers.

```bash
./deploy_all.sh --target gcp-gke --env dev
```

Once this variable is set, `GatewayClient` automatically switches to **Gateway Mode**, routing all LLM requests through this single endpoint.

---

## 6. Agent Identity at the Inference Edge (Linkerd mTLS Workload Identity)

The Inference Gateway handles **routing, priority, and autoscaling**. It does not establish who the caller is. Under Linkerd mTLS, the Linkerd inbound proxy terminates TLS and sets `l5d-client-id` (`<sa>.<ns>.serviceaccount.identity.linkerd.<trust-domain>`). Gateway ingress authentication and caller identity extraction live in [`src/gateway/server/workload_identity.py`](../../src/gateway/server/workload_identity.py) (`WorkloadIdentityMiddleware` and `extract_client_identity(scope)`).

### 6.1 Extraction and fail-closed rejection

`WorkloadIdentityMiddleware` gates every non-open request against `CAGE_TRUSTED_CLIENT_IDENTITIES` (which is required in every environment), and [`src/gateway/server/inference_proxy.py`](../../src/gateway/server/inference_proxy.py) resolves the caller immediately after the Tier-1 keyword scan and before any quota or NeMo work:

- It calls `extract_client_identity(request.scope)` from [`src/gateway/server/workload_identity.py`](../../src/gateway/server/workload_identity.py), which returns the verified `l5d-client-id` matching `<sa>.<ns>.serviceaccount.identity.linkerd.<trust-domain>`.
- On any failure it stamps the SC-8 control as `BLOCK` on the span and returns **HTTP 401** with `{"error": "authentication_required", "message": ...}`.
- There is **no anonymous fallback** — the request never reaches quota enforcement, NeMo rails, or the model pools.
- The resulting workload identity is the `agent_id` used for per-session token/step quota accounting (the HTTP 429 quota path reports it verbatim).

### 6.2 Removed identity sources (breaking change, v3.1.0)

| Removed | Replacement |
|---|---|
| `X-Agent-ID` request header | Verified `l5d-client-id` from the Linkerd inbound mTLS proxy |
| Any `X-SPIFFE-ID`-style header | Verified `l5d-client-id` from the Linkerd inbound mTLS proxy |
| `agent_id` field in the JSON request body | Verified `l5d-client-id` from the Linkerd inbound mTLS proxy |
| Anonymous / unauthenticated fallback identity | HTTP 403/401 rejection |

Clients that previously identified themselves with a client-supplied header or body field now receive HTTP 403/401 unless they call through the Linkerd mesh with a trusted workload identity.

### 6.3 Deployment implication

Because extraction reads `l5d-client-id` set by the Linkerd inbound proxy, the caller must be meshed and listed in `CAGE_TRUSTED_CLIENT_IDENTITIES`. Unmeshed callers or callers whose identity is not in `CAGE_TRUSTED_CLIENT_IDENTITIES` are refused fail-closed.

The canonical identity specification — including the DPoP double-binding design and the OPA namespace-prefix authorization model — is [`AGENT_IDENTITY_BINDING_SPEC.md`](AGENT_IDENTITY_BINDING_SPEC.md).
