# Deployment Decision Record

## 1. Executive Summary

This document records key architectural decisions regarding the deployment of the Neuro-Cybernetic Governance system.

## 2. Infrastructure

- **Platform:** Kubernetes (GKE on Google Cloud is the reference deployment; EKS, AKS, and bare-metal are also supported).
  - **Reason:** Required for persistent GPU access (vLLM stateful sets) which is not supported by Cloud Run or Autopilot.
- **Region:** `northamerica-northeast2` (Toronto) / `us-central1` (Backup).

## 3. Configuration & Secrets Management (Updated 2026-01-27)

### Decision: No `.env` Files in Production

- **Problem:** Storing secrets in `.env` files is insecure and hard to rotate. It violates 12-factor app principles for secrets.
- **Solution:** A tiered configuration strategy managed by `ConfigManager` (`src/governed_financial_advisor/infrastructure/config_manager.py`).

### Strategy — Kubernetes-native Secret Injection

> **ADR**: Google Secret Manager was removed in favour of Kubernetes-native secret
> injection (env vars from `Secret` objects). No runtime dependency on
> `google-cloud-secret-manager`. Secrets are resolved via env var → default (two-tier) only.

We use Kubernetes `Secret` objects exclusively for resilient, cloud-agnostic secret management.

1.  **Kubernetes Secrets (Primary Path):**
    - Secrets are injected as Environment Variables via `envFrom` / `secretRef` in Deployment manifests.
    - Terraform manages `kubernetes_secret` resources in `deployment/terraform/secrets.tf`.
    - This is standard for high-performance, cloud-portable apps.

2.  **Local & OSS Development:**
    - `.env` files are supported locally and for OSS deployments (`--is-oss`).
    - No `GOOGLE_CLOUD_PROJECT` is required for secret resolution — only needed
      if GCP-specific infrastructure (Cloud SQL, GCS) is used directly.

## 4. Compute Decisions

- **vLLM:** Split into `vllm-fast` (Llama 3.1 8B) and `vllm-reasoning` (DeepSeek-R1-Distill-Llama-8B) on NVIDIA L4 Spot GPU nodes to optimize cost vs. latency.
- **Gateway:** Stateless gRPC service, horizontally scalable.

## 5. Observability Deployment (Updated 2026-02-21)

### Decision: Custom GKE Deployment over Official `Langfuse Terraform Module`

- **Problem:** Evaluating whether to update the Langfuse deployment to use the official Terraform module, which provisions a dedicated GKE cluster, Cloud SQL, and Redis.
- **Solution:** Decided **against** using the generic Terraform module. We will maintain our custom GKE manifest deployment strategy, co-locating Langfuse with our vLLM inference stack.
- **Reasoning:**
  - **Cost & Overhead:** Spinning up a dedicated GKE cluster just for observability introduces massive unnecessary costs, as we already have an optimized cluster.
  - **Latency & Egress:** Co-locating the OpenTelemetry Collector and Langfuse instances within the `governance-stack` namespace prevents cross-cluster network latency and cloud egress fees.
  - **Cohesion:** Our custom `deploy_sw.py` script dynamically orchestrates the entire Triple-Hybrid architecture. Using a generic Terraform module breaks this unified pipeline.

---

## ADR-001: Replace GCS Fuse CSI with MinIO Tensorizer for vLLM Weight Streaming

**Date**: 2026-03-03
**Status**: Accepted

**Context**: vLLM deployments previously mounted GCS buckets via the GCS Fuse CSI driver (`gcsfuse.csi.storage.gke.io`), a GKE-proprietary extension requiring the GCFS sidecar injector (`gke-gcsfuse/volumes: "true"` pod annotation). This created a hard dependency on GKE and GCS-native APIs, blocking deployment on EKS, AKS, or bare-metal Kubernetes clusters.

**Decision**: Replace GCS Fuse CSI with vLLM's native `--load-format tensorizer` pointed at MinIO, which is already deployed in the `governance-stack` namespace and exposes an S3-compatible API. A one-time GPU Job (`deployment/k8s/tensorize-job.yaml`) serializes HuggingFace model weights to TensorSerializer format and uploads them to the MinIO `vllm-models` bucket. `deploy_sw.py` bootstraps MinIO credentials and the bucket before the vLLM stack is applied.

**Consequences**:

- Cloud-agnostic: works on EKS, AKS, bare-metal, or any Kubernetes distribution
- No GKE-proprietary CSI driver or GCFS sidecar injector required
- One-time tensorization step needed per model (`deployment/k8s/tensorize-job.yaml`)
- Cold-start time ~60–90s vs ~20 minutes for a full HuggingFace download
- MinIO must be operational before vLLM pods start (enforced by `_ensure_minio_bucket()` in `deploy_sw.py`)

---

## ADR-002: Portability Improvements (Gateway & Node Selectors)

**Date**: 2026-03-03
**Status**: Accepted

**Context**: Several GKE-specific primitives were embedded in infrastructure manifests, preventing portability across cloud providers and creating dependency on GKE-managed controllers.

**Decision**: Replace proprietary extensions with portable equivalents:

- `gke-l7-gxlb` GatewayClass → `nginx` (Gateway API CRDs installed via Helm)
- `kubernetes.io/ingress.class: gce` → `nginx` in AgentSight ingress
- `cloud.google.com/gke-accelerator: nvidia-l4` node selectors → `nvidia.com/gpu.product: NVIDIA-L4` across all vLLM manifests
- Removed `gcfs_config`, `gateway_api_config.channel`, and `gpu_sharing_config` blocks from `deployment/terraform/gke.tf`

**Consequences**:

- Inference gateway and AgentSight ingress now portable across any Kubernetes distribution with nginx
- GPU node selection uses the standard NVIDIA device plugin label, compatible with any Kubernetes GPU operator
- `gateway_api_config.channel` removal means Gateway API CRDs must be installed out-of-band (Helm chart); this is documented in `deployment/terraform/README.md`
