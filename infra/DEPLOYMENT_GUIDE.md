# Deployment Guide: CAGE Infrastructure

## Overview

The Cybernetic Governance Engine supports **target-based deployment**, allowing you to deploy to either a generic Kubernetes cluster or a GCP-optimized GKE cluster using the same application code and Terraform modules.

## Architecture

```
infra/
├── modules/              # Reusable Terraform components
│   ├── k8s_namespace/
│   ├── minio_storage/
│   ├── gcp_gke_cluster/
│   ├── postgres_db/
│   ├── redis_cache/
│   ├── vllm_inference/
│   ├── langfuse_stack/
│   ├── compliance_bridge/
│   └── opa_policy/
│
└── targets/              # Deployment endpoints
    ├── agnostic/         # Deploy to any Kubernetes cluster
    └── gcp-gke/          # Provision and deploy to GKE
```

## Deployment Modes

### 1. Local Development (Docker Compose)

**Use case:** Laptop development — no Kubernetes required.

```bash
# Development mode (hot-reload volumes, dev overrides)
docker compose -f docker-compose.dev.yml up

# Or via the unified script
./deploy_all.sh
```

> **Compose file distinction:** `docker-compose.yml` is the production-equivalent compose file. `docker-compose.dev.yml` includes hot-reload volume mounts and development overrides. Use `docker-compose.dev.yml` for local iteration.

### 2. Agnostic Kubernetes Target

**Use case:** Deploy to an existing Kubernetes cluster (k3s, EKS, AKS, minikube, GKE, etc.)

```bash
./deploy_all.sh --target agnostic --env dev --auto-approve
```

**What is provisioned:**
- Kubernetes namespace (`governance-stack-<env>`)
- MinIO S3-compatible object storage
- Terraform state stored in-cluster (no cloud dependencies)

### 3. GCP GKE Target

**Use case:** Provision a complete GKE cluster with GPU support.

```bash
./deploy_all.sh --target gcp-gke --env dev \
  --var project_id=<YOUR_GCP_PROJECT_ID> \
  --var minio_root_password=<YOUR_MINIO_PASSWORD> \
  --auto-approve
```

**What is provisioned:**
- GKE cluster with autoscaling CPU and GPU node pools (NVIDIA L4 or T4)
- Kubernetes namespace
- MinIO storage on GCP persistent disks
- GCS bucket for Langfuse events
- Cloud Router & NAT (when private cluster mode is enabled)

---

## Command Reference

### Basic Commands

```bash
# Show help
./deploy_all.sh --help

# Deploy to agnostic target (dev)
./deploy_all.sh --target agnostic --env dev --auto-approve

# Deploy to GCP target (dev)
./deploy_all.sh --target gcp-gke --env dev --auto-approve

# Deploy to GCP target (prod — NIST compliance enabled)
./deploy_all.sh --target gcp-gke --env prod
```

### Advanced Options

```bash
# Use a custom kubeconfig
./deploy_all.sh --target agnostic --env dev \
  --kubeconfig ~/.kube/my-cluster.yaml

# Override specific Terraform variables
./deploy_all.sh --target gcp-gke --env dev \
  --var project_id=<YOUR_GCP_PROJECT_ID> \
  --var gpu_type=nvidia-t4 \
  --var cluster_name=<YOUR_GKE_CLUSTER_NAME>

# Use an additional var file
./deploy_all.sh --target gcp-gke --env dev \
  --var-file=custom-overrides.tfvars
```

### Manual Terraform Operations

```bash
# Navigate to the target directory
cd infra/targets/gcp-gke

# Initialize
terraform init

# Plan (always run before apply)
terraform plan -var-file=dev.tfvars

# Apply
terraform apply -var-file=dev.tfvars

# Destroy
terraform destroy -var-file=dev.tfvars
```

---

## Configuration Files

### Agnostic Target

Edit `infra/targets/agnostic/dev.tfvars`:

```hcl
# Set the storage class for your cluster type
storage_class      = "local-path"       # k3s
# storage_class    = "gp3"              # EKS
# storage_class    = "managed-premium"  # AKS

minio_storage_size = "10Gi"

# Set your container registry
registry_url = "ghcr.io/<YOUR_ORG>/cage"
```

### GCP-GKE Target

Edit `infra/targets/gcp-gke/dev.tfvars`:

```hcl
# Required: your GCP project ID
project_id = "<YOUR_GCP_PROJECT_ID>"

# Optional: cost optimization
gpu_node_pool_min_count = 0  # Scale GPU nodes to zero when idle

# Optional: security controls
enable_binary_authorization = true
```

---

## Regional Deployment Configuration

CAGE implements a **boot contract** requiring `CAGE_DEPLOYMENT_REGION` to be explicitly declared in every container manifest. The `ControlRegistry` singleton reads this variable at first instantiation and loads the corresponding compliance baseline profile.

**Supported values:**

| Value | Profile File | Governing Frameworks |
|-------|-------------|----------------------|
| `US_FED` | `config/compliance/US_FED_BASELINE.json` | SR 26-2 / NIST AI RMF / ISO 42001 |
| `EU_ECB` | `config/compliance/EU_ECB_BASELINE.json` | EU AI Act / DORA / GDPR / EBA/GL/2023/02 |
| `APAC_MAS` | `config/compliance/APAC_MAS_BASELINE.json` | MAS FEAT / MAS TRM Guidelines / ISO 42001 |

**Already declared in all authoritative manifests:**
- `deployment/k8s/generated/gateway-deployment.yaml`
- `docker-compose.yml` — gateway and app services
- `docker-compose.dev.yml` — gateway dev overlay

```bash
# Override at deploy time without editing YAML (recommended for multi-region clusters)
kubectl set env deployment/gateway CAGE_DEPLOYMENT_REGION=EU_ECB -n governance-stack

# Or export before docker compose
export CAGE_DEPLOYMENT_REGION=EU_ECB
docker compose up
```

> [!CAUTION]
> Do **not** rely on the `US_FED` default in a production EU or APAC deployment. If `CAGE_DEPLOYMENT_REGION` is absent, `ControlRegistry` will load US Federal Reserve control mappings, causing incorrect span annotations in DORA Art. 10 audit logs and GDPR/MAS telemetry compliance failures.

---

## Security Postures

### Development

```bash
./deploy_all.sh --target agnostic --env dev
```

**Configuration:**
- No resource limits
- No security contexts
- No Pod Security Standards
- Public cluster access (GCP target)

### Production (NIST SP 800-53 HIGH)

```bash
./deploy_all.sh --target gcp-gke --env prod
```

**Configuration:**
- Resource limits enforced on all containers
- Security contexts: `runAsNonRoot`, `readOnlyRootFilesystem`
- Pod Security Standards: `restricted`
- Private GKE cluster with authorized network access only
- Binary Authorization (signed images only)
- Comprehensive audit logging
- Customer-managed encryption keys (optional)

---

## Implemented Modules

| Module | Description |
|--------|-------------|
| `k8s_namespace` | Namespace provisioning with Pod Security Standards (PSS/PSA) |
| `minio_storage` | MinIO S3-compatible object storage |
| `postgres_db` | PostgreSQL database with automated init scripts |
| `redis_cache` | High-Availability Redis with Sentinel support |
| `vllm_inference` | vLLM deployments with dedicated Spot GPU node pools (NVIDIA L4, multi-zone across `us-central1-a/b/c`) |
| `langfuse_stack` | Self-hosted Langfuse stack (observability, UI, database) |
| `compliance_bridge` | Langfuse-to-Lula compliance audit bridge with dynamic project key bootstrapping |
| `opa_policy` | Open Policy Agent engine |

---

## Validation

After deployment, validate with:

```bash
# Run the validation script
./infra/validate_deployment.sh governance-stack-dev

# Manual checks
kubectl get ns
kubectl get pods -n governance-stack-dev
kubectl get svc -n governance-stack-dev

# Access MinIO console
kubectl port-forward svc/minio 9001:9001 -n governance-stack-dev
# Open: http://localhost:9001
```

---

## Troubleshooting

### `terraform init` fails (Agnostic)

```bash
# Ensure the terraform-state namespace exists
kubectl create namespace terraform-state
```

### `terraform init` fails (GCP)

```bash
# Ensure you are authenticated
gcloud auth application-default login
```

### Storage class not found

```bash
# List available storage classes
kubectl get storageclass

# Update .tfvars with the correct value
```

### GKE provisioning fails

```bash
# Check GCP quotas
gcloud compute project-info describe --project=<YOUR_GCP_PROJECT_ID>

# Enable required APIs
gcloud services enable container.googleapis.com \
  compute.googleapis.com \
  storage.googleapis.com \
  --project=<YOUR_GCP_PROJECT_ID>
```

---

## Rollback


Quick rollback:

```bash
# Navigate to the active Terraform target
cd infra/targets/gcp-gke

# Re-apply the last known-good configuration
terraform apply -var-file=dev.tfvars
```

---

## Post-Deployment Checklist

1. Verify all pods are running: `kubectl get pods -n governance-stack-dev`
2. Run Lula compliance validations: `compliance/lula/`
3. Confirm `CAGE_DEPLOYMENT_REGION` is set correctly for your target region
4. Monitor governance pipeline metrics in Langfuse
5. Review open POAM items in `docs/POAM.md`

---

## See Also

- [Quick Start Guide](QUICK_START.md) — 5-minute getting started
- [Module Documentation](modules/) — individual module READMEs
