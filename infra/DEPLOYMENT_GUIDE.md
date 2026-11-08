# Deployment Guide: CAGE Infrastructure

## Overview

The Cybernetic Governance Engine supports local container development via [`docker-compose.yml`](../docker-compose.yml) and Kubernetes/Terraform deployment to Google Kubernetes Engine via [`infra/targets/gcp-gke/`](targets/gcp-gke/) (`POAM-2026-185`).

## Architecture

```
infra/
├── modules/              # Reusable Terraform components
│   ├── agentsight_ui/
│   ├── app_secrets/
│   ├── clickhouse_operator/
│   ├── cloudsql_postgres/
│   ├── compliance_bridge/
│   ├── deployment_config/
│   ├── gateway/
│   ├── gcp_gke_cluster/
│   ├── governed_advisor/
│   ├── k8s_namespace/
│   ├── kms/
│   ├── langfuse_stack/
│   ├── memorystore_redis/
│   ├── memorystore_valkey/
│   ├── nemo_guardrails/
│   ├── opa_policy/
│   ├── service_mesh/
│   ├── vllm_inference/
│   ├── vpc_network/
│   └── worm_bucket/
│
└── targets/              # Deployment endpoint
    └── gcp-gke/          # Provision and deploy to GKE (sole shipped target)
```

## Deployment Modes

### 1. Local Development (Docker Compose)

**Use case:** Laptop development — no Kubernetes or cloud account required.

```bash
# Development mode (hot-reload volumes, dev overrides)
docker compose -f docker-compose.dev.yml up

# Or full local stack
docker compose up --build
```

> **Compose file distinction:** `docker-compose.yml` is the production-equivalent compose file. `docker-compose.dev.yml` includes hot-reload volume mounts and development overrides. Use `docker-compose.dev.yml` for local iteration.

> **Model backend:** compose is the only place `CAGE_INFERENCE_BACKEND=external`, a model served by a third-party provider, is supported. The GKE target refuses it (see [the gcp-gke README](targets/gcp-gke/README.md#inference-backend)).

### 2. GCP GKE Target (`infra/targets/gcp-gke/`)

**Use case:** Provision a complete GKE cluster with GPU support, Linkerd mTLS, Cloud KMS signing, and WORM evidence storage.

```bash
./deploy_all.sh --target gcp-gke --env staging \
  --var project_id=<YOUR_GCP_PROJECT_ID> \
  --auto-approve
```

**What is provisioned:**
- GKE cluster with autoscaling CPU, ClickHouse, and GPU node pools (NVIDIA L4) running under a dedicated least-privilege node service account (`cage-gke-nodes-<env>`)
- Kubernetes namespaces (`governance-stack`, `vllm-inference`, `agentsight`)
- Retention-locked GCS WORM bucket for tamper-evident compliance evidence and Langfuse event upload bucket
- Cloud SQL PostgreSQL, Memorystore Redis/Valkey, and ClickHouse analytical query plane
- Cloud Router & NAT (when private cluster mode is enabled)
- vLLM and the advisor, only with `inference_backend = "vllm"`

**Model backend:** `inference_backend` decides what is deployed. `"none"`, the default and staging's setting, deploys no vLLM, no advisor and no NeMo server. `"vllm"` deploys vLLM on the GPU pool and the advisor. `"external"` is compose-only. The [gcp-gke README](targets/gcp-gke/README.md#inference-backend) has the details, including why the advisor calls its models directly and which zones have no L4.

---

## Command Reference

### Basic Commands

```bash
# Show help
./deploy_all.sh --help

# Deploy to GCP target (dev)
./deploy_all.sh --target gcp-gke --env dev --auto-approve

# Deploy to GCP target (staging — full enforcing posture at 1-replica scale)
./deploy_all.sh --target gcp-gke --env staging --var project_id=<YOUR_GCP_PROJECT_ID> --auto-approve

# Deploy to GCP target (prod — full compliance posture enabled)
./deploy_all.sh --target gcp-gke --env prod --var-file=infra/targets/gcp-gke/prod.tfvars
```

### Advanced Options

```bash
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
- `infra/modules/gateway/main.tf` (via `var.cage_deployment_region` / `CAGE_DEPLOYMENT_REGION`)
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
./deploy_all.sh --target gcp-gke --env dev
```

**Configuration:**
- Reduced replica counts for fast iteration
- Non-enforcing posture unless `enforce_in_dev = true`

### Production / Staging (`local.enforcing_posture = true`)

```bash
./deploy_all.sh --target gcp-gke --env prod --var-file=infra/targets/gcp-gke/prod.tfvars
```

**Configuration:**
- Resource limits enforced on all containers
- Security contexts: `runAsNonRoot`, `readOnlyRootFilesystem`
- Pod Security Standards: `restricted`
- GKE cluster with scoped `authorized_networks`
- Binary Authorization (signed images only)
- Comprehensive audit logging
- Customer-managed encryption keys (CMEK)

---

## Implemented Modules

| Module | Description |
|--------|-------------|
| `gcp_gke_cluster` | GKE cluster with dedicated node SA, CPU/ClickHouse/GPU node pools, and NIST controls |
| `vpc_network` | VPC network, subnetwork, Cloud Router, and Cloud NAT |
| `kms` | Cloud KMS keyring and CMEK keys |
| `worm_bucket` | Retention-locked GCS WORM evidence bucket |
| `cloudsql_postgres` | Cloud SQL PostgreSQL instance with private IP and PITR |
| `memorystore_redis` / `memorystore_valkey` | Managed Memorystore in-memory state backends |
| `clickhouse_operator` | ClickHouse analytical query plane |
| `k8s_namespace` | Namespace provisioning with Pod Security Standards (PSS/PSA) |
| `vllm_inference` | vLLM deployments with dedicated GPU node pools (`g2-standard-8`, NVIDIA L4) |
| `langfuse_stack` | Self-hosted Langfuse v3 stack |
| `compliance_bridge` | Langfuse-to-Lula compliance audit bridge |
| `opa_policy` | Read-only OPA Rego policy, `system.authz`, and console decision-log ConfigMaps mounted by the `gateway` UDS sidecar |
| `gateway` | CAGE Hybrid Inference & Governance Gateway |
| `governed_advisor` | Governed Financial Advisor (in-cluster GKE Deployment) |

---

## Validation

After deployment, validate with:

```bash
# Run the validation script
./infra/validate_deployment.sh governance-stack

# Manual checks
kubectl get ns
kubectl get pods -n governance-stack
kubectl get svc -n governance-stack
```

---

## Troubleshooting

### `terraform init` fails (GCP)

```bash
# Ensure you are authenticated
gcloud auth application-default login
```

### GKE provisioning fails

```bash
# Check GCP quotas
gcloud compute project-info describe --project=<YOUR_GCP_PROJECT_ID>

# Enable required APIs
gcloud services enable container.googleapis.com \
  compute.googleapis.com \
  storage.googleapis.com \
  artifactregistry.googleapis.com \
  containerfilesystem.googleapis.com \
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
