# Deployment Decision Record

> **Reference architecture only.** CAGE demonstrates governance patterns for AI systems;
> it is not deployed to production. The decisions below are illustrative patterns for
> adopters, not operational obligations for this repository.

## 1. Executive Summary

This document records key architectural decisions regarding the deployment of the
Cybernetic AI Governance Engine (CAGE). The canonical deployment entry point is
[`deploy_all.sh`](../../deploy_all.sh). Active infrastructure-as-code lives under
[`infra/`](../../infra/); the historical `deployment/terraform/` directory was
removed on 2026-03-15.

---

## 2. Infrastructure Platform

- **Platform:** Kubernetes — GKE on Google Cloud is the reference deployment;
  k3s, EKS, AKS, and bare-metal Kubernetes are also supported via the `agnostic`
  target.
- **Reason:** Required for persistent GPU access (vLLM StatefulSets / Deployments)
  which Cloud Run and GKE Autopilot do not support for large model inference.
- **Regions (reference postures):**

| `CAGE_DEPLOYMENT_REGION` | GCP Region | Compliance Posture |
|--------------------------|------------|--------------------|
| `US_FED` | `us-central1` | ISO 42001 + NIST SP 800-53 |
| `EU_ECB` | `europe-west1` | ISO 42001 + EU AI Act / GDPR / DORA |
| `APAC_MAS` | `asia-southeast1` | ISO 42001 + MAS FEAT / Notice 655 / TRM |

---

## 3. Deployment Entry Point (Updated 2026-03-15)

### Decision: `deploy_all.sh` Replaces `deploy_sw.py`

- **Superseded:** `deployment/deploy_sw.py` and `deployment/terraform/` are no
  longer the deployment entry point. `deployment/terraform/` was removed
  2026-03-15; `deploy_sw.py` is retained for historical reference only.
- **Current entry point:** [`deploy_all.sh`](../../deploy_all.sh) at the
  repository root.

```bash
# Approved commands — see DEPLOYMENT_RULES.md for the full matrix
./deploy_all.sh --target agnostic --env dev
./deploy_all.sh --target gcp-gke --env dev --auto-approve
CAGE_DEPLOYMENT_REGION=US_FED ./deploy_all.sh --target gcp-gke --env prod \
  --var-file=infra/targets/gcp-gke/prod.tfvars
```

`deploy_all.sh` performs the following steps in order:
1. Loads `.env` via selective export (H-16 security pattern — no `allexport`)
2. Generates `infra/targets/gcp-gke/terraform.auto.tfvars` from `.env` via
   [`scripts/gen_tfvars.py`](../../scripts/gen_tfvars.py)
3. Runs `terraform init` and `terraform plan` in the target directory
4. Pre-builds all container images via Cloud Build (`scripts/build_images.sh`)
   before `terraform apply` to eliminate race conditions
5. Runs `terraform apply -parallelism=1` (serialised to avoid K8s API thrashing)
6. Prints `terraform output deployment_summary`

### Terraform State Backends

| Target | Backend | Location |
|--------|---------|----------|
| `gcp-gke` | GCS (optional; configured in `providers.tf`) | `YOUR_PROJECT-tfstate/cage/gcp-gke` |
| `agnostic` | Kubernetes Secret | `terraform-state` namespace |

---

## 4. Configuration & Secrets Management (Updated 2026-01-27)

### Decision: No Secrets in `.env` — Kubernetes-Native Injection

- **Problem:** Storing secrets in `.env` files is insecure and hard to rotate.
- **Solution:** A tiered strategy managed by `ConfigManager`
  (`src/governed_financial_advisor/infrastructure/config_manager.py`).

> **ADR:** Google Secret Manager was removed in favour of Kubernetes-native
> secret injection (env vars from `Secret` objects). No runtime dependency on
> `google-cloud-secret-manager`. Secrets are resolved via env var → default
> (two-tier) only.

**Kubernetes `Secret` objects (primary path):**
- Secrets are injected as environment variables via `envFrom` / `secretRef` in
  Deployment manifests.
- Terraform manages `kubernetes_secret` resources in `infra/targets/gcp-gke/`.
- K8s manifests must use `secretKeyRef` / `secretRef` — never `value: <secret>`.

**Local / OSS development:**
- `.env` files are supported locally and for OSS deployments.
- `deploy_all.sh` reads `.env` via `_read_env_var()` (H-16: no `allexport`)
  and maps values selectively to `TF_VAR_*` names.

---

## 5. Compute Decisions

- **vLLM split architecture:**
  - `vllm-inference` (`vllm-service`): Fast path — `Qwen/Qwen2.5-7B-Instruct`
    on NVIDIA L4 Spot GPU nodes
  - `vllm-reasoning`: Reasoning plane — `casperhansen/deepseek-r1-distill-qwen-14b-awq`
    on NVIDIA L4 Spot GPU nodes
- **GPU node selection:** Uses the portable NVIDIA device plugin label
  `nvidia.com/gpu.product: NVIDIA-L4` (ADR-002), not the GKE-proprietary
  `cloud.google.com/gke-accelerator`.
- **Gateway:** Stateless FastAPI/gRPC service (port 8080 HTTP, 50051 gRPC),
  horizontally scalable via `deployment/k8s/gateway-hpa.yaml`.

### Port-forward Map (Dev)

The [`scripts/port_forward_dev.sh`](../../scripts/port_forward_dev.sh) script
establishes auto-reconnecting port-forwards for all services. Default namespace:
`governance-stack` (override via `K8S_NAMESPACE` in `.env`).

| Service | Local port | Remote port |
|---------|-----------|-------------|
| OPA | 8181 | 8181 |
| Langfuse API | 3001 | 3000 |
| Langfuse UI | 3000 | 3000 |
| vLLM fast (primary) | 8001 | 8000 |
| vLLM fast (alt) | 18081 | 8000 |
| vLLM reasoning (primary) | 8000 | 8000 |
| vLLM reasoning (alt) | 18082 | 8000 |
| Gateway | 8080 | 8080 |
| Governed FA backend | 18080 | 80 |
| Redis | 6379 | 6379 |
| Compliance bridge | 3002 | 80 |

---

## 6. Observability Deployment (Updated 2026-05-31)

### Decision: Custom GKE Deployment over Official Langfuse Terraform Module

- **Against** using the generic Langfuse Terraform module (which provisions a
  dedicated GKE cluster, Cloud SQL, and Redis).
- **Reason:**
  - Co-locating Langfuse within the `governance-stack` namespace eliminates
    cross-cluster latency and GCP egress fees.
  - The standalone OpenTelemetry Collector sidecar was **deprecated 2026-05-31**.
    Telemetry now flows directly from the governed-advisor and gateway to
    Langfuse's native OTLP ingestion endpoint:
    `http://langfuse-web:3000/api/public/otel/v1/traces`
  - Unified `deploy_all.sh` pipeline orchestrates Langfuse alongside the
    inference stack.

---

## ADR-001: Replace GCS Fuse CSI with MinIO Tensorizer for vLLM Weight Streaming

**Date:** 2026-03-03  
**Status:** Accepted

**Context:** vLLM deployments previously mounted GCS buckets via the GCS Fuse
CSI driver (`gcsfuse.csi.storage.gke.io`), a GKE-proprietary extension requiring
the GCFS sidecar injector (`gke-gcsfuse/volumes: "true"` pod annotation). This
created a hard dependency on GKE and GCS-native APIs.

**Decision:** Replace GCS Fuse CSI with vLLM's native `--load-format tensorizer`
pointed at MinIO (in-cluster S3-compatible store, `governance-stack` namespace).
A one-time GPU Job ([`deployment/k8s/tensorize-job.yaml`](../k8s/tensorize-job.yaml))
serialises HuggingFace weights to TensorSerializer format and uploads them to the
MinIO `vllm-models` bucket.

```bash
# One-time tensorization
kubectl apply -f deployment/k8s/tensorize-job.yaml -n governance-stack
kubectl wait --for=condition=complete job/tensorize-weights \
  --timeout=30m -n governance-stack
```

**Consequences:**
- Cloud-agnostic: works on EKS, AKS, bare-metal, or any Kubernetes distribution
- No GKE-proprietary CSI driver or GCFS sidecar injector required
- One-time tensorization step per model
- Cold-start time ~60–90 s vs ~20 min for a full HuggingFace download
- MinIO must be operational before vLLM pods start

> **Note:** GCS (`gs://`) is the **primary** model artifact store for initial
> upload. See [`deployment/scripts/upload_to_gcs.py`](../scripts/upload_to_gcs.py)
> for artifact upload. MinIO is used for in-cluster vLLM streaming and
> Langfuse event storage.

---

## ADR-002: Portability Improvements (Gateway & Node Selectors)

**Date:** 2026-03-03  
**Status:** Accepted

**Context:** GKE-specific primitives in infrastructure manifests prevented
portability across cloud providers.

**Decision:** Replace proprietary extensions with portable equivalents:

- `gke-l7-gxlb` GatewayClass → `nginx`
  ([`deployment/k8s/inference-gateway/gateway.yaml`](../k8s/inference-gateway/gateway.yaml))
- `kubernetes.io/ingress.class: gce` → `nginx` in AgentSight ingress
- `cloud.google.com/gke-accelerator: nvidia-l4` node selectors →
  `nvidia.com/gpu.product: NVIDIA-L4` across all vLLM manifests
- `deployment/terraform/` removed 2026-03-15; active IaC is
  `infra/targets/gcp-gke/`

**Consequences:**
- Inference gateway and AgentSight ingress are portable across any Kubernetes
  distribution with nginx
- GPU node selection uses the standard NVIDIA device plugin label
- Gateway API CRDs must be installed out-of-band via Helm
  (`kubernetes/ingress-nginx` chart)

---

## ADR-003: Region-Gated Compliance Hardening via `CAGE_DEPLOYMENT_REGION`

**Date:** 2026-04-01  
**Status:** Accepted

**Context:** `enable_nist_compliance` was previously activated by `--env prod`
alone, causing EU_ECB and APAC_MAS prod deployments to incorrectly activate
NIST SP 800-53 hardening (SC-7, AC-3, deletion protection, Redis replication).

**Decision (DEP-01/R-2):** Gate `enable_nist_compliance=true` on
`CAGE_DEPLOYMENT_REGION == "US_FED"` in `deploy_all.sh`. ISO 42001 baseline
hardening is always active in prod regardless of region; NIST-specific
infrastructure hardening is US_FED only.

```bash
# US_FED prod — ISO 42001 + NIST SP 800-53
CAGE_DEPLOYMENT_REGION=US_FED ./deploy_all.sh --target gcp-gke --env prod \
  --var-file=infra/targets/gcp-gke/prod.tfvars

# EU_ECB prod — ISO 42001 + EU AI Act / GDPR / DORA (no NIST hardening)
CAGE_DEPLOYMENT_REGION=EU_ECB ./deploy_all.sh --target gcp-gke --env prod \
  --var-file=infra/targets/gcp-gke/eu-prod.tfvars
```

**Consequences:**
- `TF_VAR_cage_deployment_region` is derived from `CAGE_DEPLOYMENT_REGION` via
  `.env` / `_read_env_var()` (DEP-02 / DEP-22)
- `staging` environment is defined in the Terraform schema but not yet
  provisioned (POAM-024, target v2.1.0, 2026-12-31)
