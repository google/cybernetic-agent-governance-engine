# Infrastructure Deployment Status

This document describes the infrastructure components of the Cybernetic Governance Engine (CAGE) and their current deployment status.

## Architecture Overview

The CAGE infrastructure is organized as a set of composable Terraform modules deployed to one of two targets:

```
infra/
├── modules/              # Reusable Terraform components
│   ├── k8s_namespace/
│   ├── gcp_gke_cluster/
│   ├── minio_storage/
│   ├── postgres_db/
│   ├── redis_cache/
│   ├── vllm_inference/
│   ├── langfuse_stack/
│   ├── compliance_bridge/
│   └── opa_policy/
│
└── targets/              # Deployment endpoints
    ├── agnostic/         # Cloud-agnostic Kubernetes
    └── gcp-gke/          # GCP-optimized GKE
```

## Terraform Modules

All nine modules are fully implemented and validated.

| Module | Description | Status |
|--------|-------------|--------|
| `k8s_namespace` | Kubernetes namespace with Pod Security Standards (PSS/PSA) enforcement | ✅ Complete |
| `gcp_gke_cluster` | GKE cluster with NIST SP 800-53 compliance toggles, GPU node pools, and autoscaling | ✅ Complete |
| `minio_storage` | S3-compatible object storage via MinIO Helm chart | ✅ Complete |
| `postgres_db` | PostgreSQL database via Helm with automated init scripts | ✅ Complete |
| `redis_cache` | High-Availability Redis with Sentinel support via Helm | ✅ Complete |
| `vllm_inference` | vLLM inference server with dedicated Spot GPU node pools (NVIDIA L4, multi-zone) | ✅ Complete |
| `langfuse_stack` | Self-hosted Langfuse observability platform (UI, worker, database) | ✅ Complete |
| `compliance_bridge` | Langfuse-to-Lula compliance audit bridge with dynamic project key bootstrapping | ✅ Complete |
| `opa_policy` | Open Policy Agent engine for Rego-based governance policy enforcement | ✅ Complete |

## Deployment Targets

### `agnostic` — Cloud-Agnostic Kubernetes

Deploys the full governance stack to any Kubernetes cluster (k3s, minikube, kind, EKS, AKS, GKE).

**Provisions:**
- Kubernetes namespace (`governance-stack-<env>`)
- MinIO S3-compatible object storage
- Terraform state stored in-cluster (no cloud dependencies)

**Files:**
- `infra/targets/agnostic/main.tf` — all 9 modules integrated
- `infra/targets/agnostic/providers.tf` — Kubernetes backend
- `infra/targets/agnostic/variables.tf`
- `infra/targets/agnostic/outputs.tf`
- `infra/targets/agnostic/dev.tfvars`
- `infra/targets/agnostic/prod.tfvars`

### `gcp-gke` — GCP GKE

Provisions a complete GKE cluster and deploys the full governance stack.

**Provisions:**
- GKE cluster with CPU and GPU node pools
- Kubernetes namespace
- MinIO storage on GCP persistent disks
- GCS bucket for Langfuse events
- Cloud Router & NAT (when private cluster mode is enabled)

**Files:**
- `infra/targets/gcp-gke/main.tf` — GKE cluster + all modules
- `infra/targets/gcp-gke/providers.tf` — GCP + Kubernetes providers
- `infra/targets/gcp-gke/variables.tf` — security and compliance toggles
- `infra/targets/gcp-gke/outputs.tf`
- `infra/targets/gcp-gke/dev.tfvars` — cost-optimized configuration
- `infra/targets/gcp-gke/prod.tfvars` — NIST SP 800-53 HIGH baseline configuration

## Deployment Scripts

| Script | Description |
|--------|-------------|
| `deploy_all.sh` | Unified deployment script with `--target` and `--env` parameters |
| `deployment/deploy_sw.py` | Software deployment helper with target-aware image URI generation |

## Regional Deployment

CAGE implements a **boot contract** requiring `CAGE_DEPLOYMENT_REGION` to be declared in every container manifest. The `ControlRegistry` singleton reads this variable at startup and loads the corresponding compliance baseline profile.

| Value | Profile | Governing Frameworks |
|-------|---------|----------------------|
| `US_FED` | `config/compliance/US_FED_BASELINE.json` | SR 26-2 / NIST AI RMF / ISO 42001 |
| `EU_ECB` | `config/compliance/EU_ECB_BASELINE.json` | EU AI Act / DORA / GDPR / EBA/GL/2023/02 |
| `APAC_MAS` | `config/compliance/APAC_MAS_BASELINE.json` | MAS FEAT / MAS TRM Guidelines / ISO 42001 |

> **Important:** Omitting `CAGE_DEPLOYMENT_REGION` causes a silent fallback to `US_FED`, which is incorrect for EU or APAC deployments.

## Security Postures

### Development

- No resource limits enforced
- No Pod Security Standards
- Public cluster access (GCP target)
- Suitable for local iteration and testing

### Production (NIST SP 800-53 HIGH)

- Resource limits enforced on all containers
- Security contexts: `runAsNonRoot`, `readOnlyRootFilesystem`
- Pod Security Standards: `restricted`
- Private GKE cluster with authorized network access only
- Binary Authorization (signed images only)
- Comprehensive audit logging
- Customer-managed encryption keys (optional)

## Validation

After deployment, validate with:

```bash
# Run the validation script
./infra/validate_deployment.sh governance-stack-dev

# Manual checks
kubectl get ns
kubectl get pods -n governance-stack-dev
kubectl get svc -n governance-stack-dev
```

## See Also

- [Quick Start Guide](QUICK_START.md) — deploy in 5 minutes
- [Deployment Guide](DEPLOYMENT_GUIDE.md) — full deployment reference
- [Module Documentation](modules/) — individual module READMEs
