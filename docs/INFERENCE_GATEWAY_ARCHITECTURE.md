# Inference Gateway Architecture

## Executive Summary

This document analyzes the feasibility and impact of migrating the current "Sovereign" AI architecture (Split-Brain: Reasoning vs. Governance) to use a Kubernetes Inference Gateway.

Currently, the `GatewayService` routes traffic through the **Inference Gateway** (nginx GatewayClass) at the infrastructure layer, enabling advanced traffic management, autoscaling, and priority handling critical for regulatory compliance (SR 11-7).

**Status:** **IMPLEMENTED** (Production) / **DIRECT** (Local Dev)

> **Update 2026-03-03:** The GatewayClass has been migrated from the GKE-proprietary `gke-l7-gxlb` to the portable `nginx` GatewayClass (see `deployment/k8s/inference-gateway/gateway.yaml`). Gateway API CRDs are now installed via Helm rather than the GKE-managed `gateway_api_config.channel`. This eliminates the hard GKE dependency while preserving all routing, priority, and autoscaling capabilities.

---

## 1. Current Architecture vs. Proposed Architecture

### Current State (Application-Side Routing)

- **Logic:** `src/gateway/core/llm.py` (`GatewayClient`) contains if/else logic to select the backend based on `mode` (e.g., `planner` -> `vllm-reasoning`, `fast` -> `vllm-governance`).
- **Infrastructure:** Two separate Kubernetes Services (`vllm-reasoning`, `vllm-governance`).
- **Scaling:** Standard HPA based on CPU/Memory (reactive).

### Proposed State (Kubernetes Inference Gateway)

- **Logic:** `GatewayClient` points to a single endpoint (the Inference Gateway). It specifies a `model` name (e.g., `llama-3.1-8b-instruct`, `deepseek-r1-distill-llama-8b`).
- **Infrastructure:**
  - **Gateway:** A unified Kubernetes Gateway resource.
  - **InferencePools:** Custom resources defining the backend pools (`vllm-reasoning`, `vllm-governance`).
  - **HTTPRoutes:** Rules mapping `model` names or headers to specific pools.
- **Scaling:** Metric-based HPA (Queue Depth, KV Cache Usage) managed by the Gateway controller (proactive).

---

## 2. Cost/Benefit Analysis

### Pros (Benefits)

1.  **Criticality & Priority Handling (Governance)**
    - **Feature:** The Inference Gateway supports **Priority** classes.
    - **Impact:** We can assign higher priority to "Governance" traffic (System 2 checks). Even if the "Reasoning" (System 1) pool is saturated with complex queries, the Governance checks (which block trade execution) will be prioritized or routed to reserved capacity. This is vital for **SR 11-7 Model Risk Management**—safety checks must never fail due to congestion.

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
2.  Define `InferencePool` resources for `vllm-reasoning` and `vllm-governance`.
3.  Deploy the `InferenceGateway` with `gatewayClassName: nginx`.

### Phase 2: Application Update (Code)

1.  Update `src/gateway/core/llm.py`:
    - Introduce `VLLM_GATEWAY_URL` env var.
    - If `VLLM_GATEWAY_URL` is set: Use single client, routing by `model` name.
    - If not set (Local/Legacy): Use existing dual-client logic.

### Phase 3: Traffic Cutover

1.  Deploy updated Gateway Service to Prod.
2.  Set `VLLM_GATEWAY_URL` to the internal IP of the Inference Gateway.
3.  Verify routing and priority handling.

---

## 4. Final Recommendation

**Proceed with Inference Gateway (nginx GatewayClass) adoption for the Production environment.**

The **Priority Handling** feature alone justifies the complexity, as it directly supports the "Neuro-Cybernetic" safety mandate: _Governance must always be available to block unsafe actions._ Using standard CPU scaling for the governance model is a safety risk during high load; the Inference Gateway mitigates this.

**Next Steps:**

1.  Update `GatewayClient` to support a unified endpoint configuration.
2.  Create Kubernetes manifests (`infra/inference-gateway/`) for the new resources.

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

Then, redeploy the application stack using the deployment script. This will inject the new environment variable into the Gateway Service container.

```bash
python3 deployment/deploy_sw.py --project-id <YOUR_PROJECT_ID> --skip-build
```

> **Note:** The `--project-id` flag is GCP-specific and can be omitted for non-GCP Kubernetes deployments.

Once this variable is set, the `GatewayService` will automatically switch to **Gateway Mode**, routing all LLM requests through this single endpoint.
