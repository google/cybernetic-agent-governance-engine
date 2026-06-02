# Latency as Currency: Funding Governance with Inference Speed

This document outlines the performance strategy for the Cybernetic Governance Engine. The core philosophy is **"Latency as Currency"**: we must generate tokens fast enough to "pay for" the overhead of strict governance checks (NeMo, OPA, JSON Enforcement).

## The Governance Tax

Every safe generation incurs a latency penalty:

1.  **Semantic Guardrails (NeMo):** ~150-300ms (Input/Output checks).
2.  **Policy Evaluation (OPA):** ~10-50ms (Sidecar network hop + Rego eval).
3.  **Syntactic Enforcement (vLLM FSM):** ~50ms (with Prefix Caching).

To maintain a responsive user experience (Total Response Time < 2s for simple queries), the underlying inference engine must be exceptionally fast.

## The Solution: "The Enforcer" on NVIDIA L4

We utilize a dedicated, self-hosted inference node for structure enforcement, optimized for speed and cost.

### Hardware: NVIDIA L4 (24GB VRAM) on Spot Instances

- **Why:** The L4 is the most cost-effective GPU for models < 20B parameters, and using Spot/preemptible GPU instances (e.g., GKE Spot, AWS Spot, Azure Spot) reduces costs by ~60%.
- **Capacity:** A single L4 can comfortably host `Meta-Llama-3.1-8B-Instruct` (~16GB VRAM in float16) with room for KV cache.
- **Throughput:** Capable of high token-per-second generation for JSON structures.

### Software: vLLM + Prefix Caching

We use **vLLM** with **Prefix Caching** enabled (`--enable-prefix-caching`).

#### How Prefix Caching Works

1.  **The Pattern:** Every governance request shares the same massive system prompt: "You are a governance engine. Output JSON matching this schema: { ... complex schema ... }".
2.  **The Cache:** vLLM hashes this prompt prefix and stores the KV (Key-Value) attention states in GPU memory.
3.  **The Hit:** When a new request comes in (different user data, same schema), vLLM skips computing attention for the schema definition.
4.  **The Result:** The "Time-To-First-Token" (TTFT) for the governance check drops from ~200ms to **<50ms**.

### Architecture Alignment

| Component      | Model                          | Hosted On            | Optimization                  |
| -------------- | ------------------------------ | -------------------- | ----------------------------- |
| **Reasoning**  | `DeepSeek-R1-Distill-Llama-8B` | Spot GPU (NVIDIA L4) | Deep semantic understanding.  |
| **Governance** | `Meta-Llama-3.1-8B-Instruct`   | Spot GPU (NVIDIA L4) | Prefix Caching + Guided JSON. |

## Latency Budget Example

**Scenario:** Risk Analyst generates a formal assessment.

1.  **Agent Reasoning (DeepSeek-R1-Llama-8B):** 3.0s (Thinking time)
2.  **Tool Call (Governance Client):**
    - Network RTT: 10ms
    - **vLLM TTFT (Cached):** 40ms
    - Generation (100 tokens): 150ms
3.  **Total Governance Overhead:** ~200ms

**Result:** The user gets a structurally guaranteed, compliant response with minimal added delay compared to a raw LLM call.

## Model Weight Loading — Cold-Start Latency

vLLM cold-start time is a critical secondary latency factor. The table below compares the three viable strategies:

| Strategy                                    | Cold-Start Time    | Cloud-Agnostic | Notes                                                                                   |
| ------------------------------------------- | ------------------ | -------------- | --------------------------------------------------------------------------------------- |
| **Full HuggingFace Download** (baseline)    | ~20 minutes        | ✅             | Downloads all shards; blocked by HF rate limits                                         |
| **GCS Fuse GCFS Image Streaming** (removed) | ~2–5 minutes       | ❌ GKE-only    | Lazy-pull from GCS via GKE-proprietary CSI driver; no longer used                       |
| **MinIO + vLLM Tensorizer** (current)       | **~60–90 seconds** | ✅             | vLLM native `--load-format tensorizer`; streams serialized shards from in-cluster MinIO |

### Current Approach: vLLM Native Tensorizer from MinIO

Model weights are pre-serialized to TensorSerializer format via a one-time GPU Job ([`deployment/k8s/tensorize-job.yaml`](../deployment/k8s/tensorize-job.yaml)) and stored in the `vllm-models` MinIO bucket (S3-compatible, already deployed in the cluster).

At pod startup, vLLM streams individual tensor shards on demand via the S3 API — no POSIX filesystem mount, no GKE-proprietary CSI sidecar injector required.

**Why this is preferable to GCS Fuse:**

- **~60–90s vs ~2–5min** cold-start vs GCFS (shards are serialized and compact — no per-shard conversion overhead at runtime).
- **Cloud-agnostic:** MinIO works on EKS, AKS, bare-metal, or any Kubernetes distribution.
- **Eliminates** the `gcsfuse.csi.storage.gke.io` CSI driver and `gke-gcsfuse/volumes: "true"` annotation dependency.
- **No extra pip packages:** `--load-format tensorizer` is vLLM native.
