# Deployment Guide: Monorepo Infrastructure

## Overview

The Cybernetic Governance Engine now supports **target-based deployment**, allowing you to deploy to either a generic Kubernetes cluster or a GCP-optimized GKE cluster using the same application code.

## Architecture

```
infra/
├── modules/              # Reusable Terraform components
│   ├── k8s_namespace/   ✅ Complete
│   ├── minio_storage/   ✅ Complete
│   └── gcp_gke_cluster/ ✅ Complete
│
└── targets/              # Deployment endpoints
    ├── agnostic/        ✅ Complete - Deploy to any K8s cluster
    └── gcp-gke/         ✅ Complete - Provision GKE cluster
```

## Deployment Modes

### 1. Local Development (Docker Compose)

**Use case**: Laptop development, no Kubernetes required

```bash
# For local development (hot-reload volumes, dev overrides):
docker compose -f docker-compose.dev.yml up

# Or via the unified script:
./deploy_all.sh
```

**What runs**: Docker Compose stack with all services

> **Compose file distinction:** `docker-compose.yml` is the production compose file. `docker-compose.dev.yml` is for local development — it includes hot-reload volume mounts and development overrides. Use `docker-compose.dev.yml` for local iteration; use `docker-compose.yml` only for production-equivalent local testing.

### 2. Agnostic Kubernetes Target

**Use case**: Deploy to existing K8s cluster (k3s, EKS, AKS, minikube, etc.)

```bash
./deploy_all.sh --target agnostic --env dev --auto-approve
```

**What's provisioned**:
- Kubernetes namespace
- MinIO object storage
- Terraform state stored in cluster (no cloud dependencies)

### 3. GCP GKE Target

**Use case**: Provision complete GKE cluster with GPU support

```bash
./deploy_all.sh --target gcp-gke --env dev \
  --var project_id=YOUR_PROJECT \
  --var minio_root_password=SecurePass123 \
  --auto-approve
```

**What's provisioned**:
- Complete GKE cluster with autoscaling
- GPU node pool (NVIDIA L4 or T4)
- Kubernetes namespace
- MinIO storage on GCP persistent disks
- GCS bucket for Langfuse events
- Cloud Router & NAT (when private cluster enabled)

## Command Reference

### Basic Commands

```bash
# Show help
./deploy_all.sh --help

# Deploy to agnostic target (dev)
./deploy_all.sh --target agnostic --env dev --auto-approve

# Deploy to GCP target (dev)
./deploy_all.sh --target gcp-gke --env dev --auto-approve

# Deploy to GCP target (prod with NIST compliance)
./deploy_all.sh --target gcp-gke --env prod
```

### Advanced Options

```bash
# Use custom kubeconfig
./deploy_all.sh --target agnostic --env dev \
  --kubeconfig ~/.kube/my-cluster.yaml

# Override specific variables
./deploy_all.sh --target gcp-gke --env dev \
  --var project_id=test-project \
  --var gpu_type=nvidia-t4 \
  --var cluster_name=test-cluster

# Use additional var file
./deploy_all.sh --target gcp-gke --env dev \
  --var-file=custom-overrides.tfvars
```

### Manual Terraform Operations

```bash
# Navigate to target
cd infra/targets/gcp-gke

# Initialize
terraform init

# Plan
terraform plan -var-file=dev.tfvars

# Apply
terraform apply -var-file=dev.tfvars

# Destroy
terraform destroy -var-file=dev.tfvars
```

## Configuration Files

### Agnostic Target

Edit `infra/targets/agnostic/dev.tfvars`:

```hcl
# Update for your cluster
storage_class      = "local-path"  # k3s
# storage_class    = "gp3"         # EKS
# storage_class    = "managed-premium"  # AKS

minio_storage_size = "10Gi"

# Update for your registry
registry_url = "ghcr.io/your-org/cage"
```

### GCP-GKE Target

Edit `infra/targets/gcp-gke/dev.tfvars`:

```hcl
# REQUIRED: Your GCP project
project_id = "your-gcp-project-id"

# Optional: Cost optimization
gpu_node_pool_min_count = 0  # Scale to zero

# Optional: Security testing
enable_binary_authorization = true
```

### Regional Deployment Configurations

CAGE v2.0.0 implements a **boot contract** requiring `CAGE_DEPLOYMENT_REGION` to be explicitly declared in every container manifest. The `ControlRegistry` singleton reads this variable at first instantiation and loads the corresponding `config/compliance/*_BASELINE.json` profile. **Omitting this variable causes a silent fallback to `US_FED`**, which is unacceptable for EU or APAC production deployments.

**Supported Values:**

| Value | Profile File | Governing Frameworks |
|-------|-------------|----------------------|
| `US_FED` | `config/compliance/US_FED_BASELINE.json` | SR 26-2 / NIST AI RMF / ISO 42001 |
| `EU_ECB` | `config/compliance/EU_ECB_BASELINE.json` | EU AI Act / DORA / GDPR / EBA/GL/2023/02 |
| `APAC_MAS` | `config/compliance/APAC_MAS_BASELINE.json` | MAS FEAT / MAS TRM Guidelines / ISO 42001 |

**Already declared in all authoritative manifests:**
- `deployment/k8s/generated/gateway-deployment.yaml` — `value: "${CAGE_DEPLOYMENT_REGION:-US_FED}"`
- `docker-compose.yml` — gateway and app services
- `docker-compose.dev.yml` — gateway dev overlay

```bash
# Override at deploy time without editing YAML (recommended for multi-region clusters)
kubectl set env deployment/gateway CAGE_DEPLOYMENT_REGION=EU_ECB -n governance-stack

# Or export before docker compose:
export CAGE_DEPLOYMENT_REGION=EU_ECB
docker compose up

# Runtime swap (e.g., container init hook) — uses the thread-safe reconfigure() method:
# python -c "from src.gateway.governance.constants import ControlRegistry; ControlRegistry.reconfigure('EU_ECB')"
```

> [!CAUTION]
> Do **not** rely on the `US_FED` default in a production EU or APAC deployment. If `CAGE_DEPLOYMENT_REGION` is absent, `ControlRegistry` will load US Federal Reserve control mappings, causing AU/DORA/GDPR telemetry compliance failures and incorrect span annotations in DORA Art. 10 audit logs.


## Security Postures

### Dev (Fast Iteration)

```bash
# Agnostic dev
./deploy_all.sh --target agnostic --env dev
```

**Configuration**:
- No resource limits
- No security contexts
- No Pod Security Standards
- Public cluster access (GCP)

### Prod (NIST Compliance)

```bash
# GCP prod with all security controls
./deploy_all.sh --target gcp-gke --env prod
```

**Configuration**:
- Resource limits enforced
- Security contexts (runAsNonRoot, readOnlyRootFilesystem)
- Pod Security Standards: restricted
- Private cluster with VPN-only access
- Binary Authorization (signed images only)
- Comprehensive audit logging
- Customer-managed encryption keys (optional)

## Validation

After deployment, validate with:

```bash
# Run validation script
./infra/validate_deployment.sh governance-stack-dev

# Manual checks
kubectl get ns
kubectl get pods -n governance-stack-dev
kubectl get svc -n governance-stack-dev

# Access MinIO console
kubectl port-forward svc/minio 9001:9001 -n governance-stack-dev
# Open: http://localhost:9001
```

## Current Status

The monorepo infrastructure refactoring is now **100% complete**, and all modules are fully integrated across both agnostic and GCP GKE deployment targets.

### ✅ Fully Implemented Modules

1. **`k8s_namespace`** - Namespace provisioning with Pod Security Standards (PSS/PSA)
2. **`minio_storage`** - MinIO S3-compatible object storage
3. **`postgres_db`** - PostgreSQL database with automated init scripts
4. **`redis_cache`** - High-Availability Redis with Sentinel support
5. **`vllm_inference`** - vLLM deployments with dedicated Spot GPU node pools (sourcing NVIDIA L4 regional/multi-zone across `us-central1-a/b/c`)
6. **`langfuse_stack`** - Self-hosted Langfuse stack (observability, UI, database)
7. **`compliance_bridge`** - Langfuse-to-Lula compliance audit bridge with dynamic project key bootstrapping
8. **`opa_policy`** - Open Policy Agent engine


## Troubleshooting

### terraform init fails

```bash
# Agnostic: Ensure terraform-state namespace exists
kubectl create namespace terraform-state

# GCP: Ensure authenticated
gcloud auth application-default login
```

### Storage class not found

```bash
# List available storage classes
kubectl get storageclass

# Update .tfvars with correct value
```

### GKE provisioning fails

```bash
# Check GCP quotas
gcloud compute project-info describe --project=YOUR_PROJECT

# Enable required APIs
gcloud services enable container.googleapis.com
```

## Rollback

If issues occur, see [ROLLBACK_PROCEDURES.md](ROLLBACK_PROCEDURES.md).

Quick rollback:

```bash
# Restore original scripts
mv deploy_all.sh.backup deploy_all.sh
mv deployment/deploy_sw.py.backup deployment/deploy_sw.py

# Use active Terraform target
cd infra/targets/gcp-gke
terraform apply -var-file=dev.tfvars
```

## Next Steps

1. **Test minimal deployment** on both targets
2. **Test full stack** deployment end-to-end
3. **Run Lula validations** post-deployment (`compliance/lula/`)
4. **Verify CAGE_DEPLOYMENT_REGION** is set correctly for each region
5. **Monitor** governance pipeline metrics in Langfuse

## See Also

- [Quick Start Guide](QUICK_START.md) - 5-minute getting started
- [Implementation Status](IMPLEMENTATION_STATUS.md) - What's complete vs. pending
- [Rollback Procedures](ROLLBACK_PROCEDURES.md) - How to revert changes
- [Module Documentation](modules/) - Individual module READMEs
- [Planning Documents](../plans/) - Architecture and migration plans
