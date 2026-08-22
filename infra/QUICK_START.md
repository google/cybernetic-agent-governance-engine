# Quick Start Guide — CAGE Infrastructure

Deploy the Cybernetic Governance Engine infrastructure in 5–10 minutes.

---

## Prerequisites

### Required tools

| Tool | Minimum version |
|------|----------------|
| Terraform | ≥ 1.5.0 |
| kubectl | ≥ 1.24 |
| uv (Python package manager) | latest |
| Git | any |

### For the agnostic target

- A running Kubernetes cluster (k3s, minikube, kind, EKS, AKS, or GKE)
- `kubectl` configured with cluster access
- `terraform-state` namespace created in the cluster (one-time):
  ```bash
  kubectl create namespace terraform-state
  ```

### For the GCP-GKE target

- `gcloud` CLI authenticated:
  ```bash
  gcloud auth application-default login
  ```
- A GCP project with billing enabled
- Required APIs enabled (see step 3 below)
- IAM permissions: Kubernetes Engine Admin, Service Account Admin, Storage Admin, Cloud Build Editor

---

## Option A: Agnostic Kubernetes (~5 minutes)

Deploy to any existing Kubernetes cluster (k3s, EKS, AKS, GKE, etc.).

### 1. Set up a local cluster (if needed)

```bash
# Install k3s
curl -sfL https://get.k3s.io | sh -

# Verify
kubectl get nodes

# Create the Terraform state namespace
kubectl create namespace terraform-state
```

### 2. Configure your environment

```bash
cp .env.example .env
# Edit .env — at minimum set K8S_NAMESPACE
```

### 3. Deploy

```bash
# From the repository root
./deploy_all.sh --target agnostic --env dev --auto-approve
```

What this provisions:
1. `governance-stack-dev` Kubernetes namespace (with PSA labels)
2. MinIO S3-compatible object storage
3. Terraform state stored in-cluster as a Kubernetes Secret

### 4. Verify the deployment

```bash
# Check namespace
kubectl get ns governance-stack-dev

# Check pods
kubectl get pods -n governance-stack-dev

# Retrieve MinIO credentials
kubectl get secret minio-credentials -n governance-stack-dev \
  -o jsonpath='{.data.access-key}' | base64 -d && echo

# Access the MinIO console
kubectl port-forward svc/minio 9001:9001 -n governance-stack-dev
# Open: http://localhost:9001
```

### 5. Tear down

```bash
cd infra/targets/agnostic
terraform destroy -var-file=dev.tfvars -auto-approve
```

---

## Option B: GCP GKE (~10 minutes)

Provision a complete GKE cluster with GPU support and optional compliance posture.

### 1. Authenticate with GCP

```bash
gcloud auth application-default login
gcloud config set project <YOUR_GCP_PROJECT_ID>
```

### 2. Configure `.env`

```bash
cp .env.example .env
```

Set at minimum:

```bash
GOOGLE_CLOUD_PROJECT=<YOUR_GCP_PROJECT_ID>
GOOGLE_CLOUD_LOCATION=us-central1       # or your preferred region
CAGE_DEPLOYMENT_REGION=US_FED           # US_FED | EU_ECB | APAC_MAS
```

### 3. Enable required GCP APIs

```bash
gcloud services enable \
  container.googleapis.com \
  compute.googleapis.com \
  storage.googleapis.com \
  cloudbuild.googleapis.com \
  cloudkms.googleapis.com \
  --project=<YOUR_GCP_PROJECT_ID>
```

### 4. Deploy

```bash
# Dev (fast iteration — reduced security posture)
./deploy_all.sh --target gcp-gke --env dev --auto-approve

# US_FED production (ISO 42001 + NIST SP 800-53)
CAGE_DEPLOYMENT_REGION=US_FED ./deploy_all.sh --target gcp-gke --env prod \
  --var-file=infra/targets/gcp-gke/prod.tfvars

# EU_ECB production (ISO 42001 + EU AI Act / GDPR / DORA)
CAGE_DEPLOYMENT_REGION=EU_ECB ./deploy_all.sh --target gcp-gke --env prod \
  --var-file=infra/targets/gcp-gke/eu-prod.tfvars

# APAC_MAS production (ISO 42001 + MAS FEAT / Notice 655 / TRM)
CAGE_DEPLOYMENT_REGION=APAC_MAS ./deploy_all.sh --target gcp-gke --env prod \
  --var-file=infra/targets/gcp-gke/apac-prod.tfvars
```

**What this provisions:**
1. GKE cluster with CPU and GPU node pools (Spot VMs for GPU by default)
2. `governance-stack` Kubernetes namespace with PSA `restricted` labels
3. `vllm-inference` namespace with PSA `baseline` labels (GPU workloads)
4. MinIO storage on GCP persistent disks
5. GCS bucket for Langfuse event storage
6. Cloud Router & NAT (when `enable_private_nodes=true`)
7. All CAGE application workloads via Terraform `kubernetes_*` resources

**Estimated time:** 8–12 minutes (GKE cluster provisioning dominates)

### 5. Verify the deployment

```bash
# Configure kubectl for the new cluster
gcloud container clusters get-credentials <YOUR_GKE_CLUSTER_NAME> \
  --zone=us-central1-a \
  --project=<YOUR_GCP_PROJECT_ID>

# Check nodes
kubectl get nodes

# Check namespaces and pods
kubectl get pods -n governance-stack
kubectl get pods -n vllm-inference

# Port-forward all dev services (auto-reconnect)
bash scripts/port_forward_dev.sh

# Test gateway health
curl http://localhost:8080/health

# Test backend health
curl http://localhost:18080/health
```

### 6. Tear down

```bash
cd infra/targets/gcp-gke
terraform destroy -var-file=dev.tfvars -auto-approve
```

---

## Background Deployments (recommended for long-running applies)

`deploy_all.sh` can take 10–15 minutes for a full GKE provisioning. To avoid terminal/tool timeouts:

```bash
# Launch fully detached
make deploy-bg TARGET=gcp-gke ENV=dev EXTRA_ARGS="--auto-approve"

# Monitor
make deploy-status     # summary + last 20 lines
make deploy-logs       # live tail (Ctrl+C to stop)
make deploy-kill       # cancel

# Images only
make build-bg
```

---

## Manual Terraform Operations

### Initialize

```bash
# Agnostic target
cd infra/targets/agnostic
terraform init -backend-config="config_path=~/.kube/config"

# GCP target (GCS backend)
cd infra/targets/gcp-gke
terraform init \
  -backend-config="bucket=${GOOGLE_CLOUD_PROJECT}-tfstate"
```

### Plan

```bash
terraform plan -var-file=dev.tfvars

# Override specific variables
terraform plan -var-file=dev.tfvars \
  -var="enable_gpu_node_pool=false"
```

### Apply

```bash
# Interactive (prompts for confirmation)
terraform apply -var-file=dev.tfvars

# Non-interactive
terraform apply -var-file=dev.tfvars -auto-approve
```

### Destroy

```bash
terraform destroy -var-file=dev.tfvars -auto-approve
```

---

## Key Terraform Variables (GCP-GKE target)

| Variable | Description | Dev default | Prod default |
|----------|-------------|-------------|--------------|
| `project_id` | GCP project ID | — (required) | — (required) |
| `region` | GCP region | `us-central1` | `us-central1` |
| `zone` | GCP zone | `us-central1-a` | `us-central1-a` |
| `cluster_name` | GKE cluster name | `cage-dev` | `cage-governance` |
| `environment` | Deployment tier | `dev` | `prod` |
| `cage_deployment_region` | Compliance posture | `US_FED` | `US_FED` |
| `enable_nist_compliance` | NIST SP 800-53 hardening (US_FED only) | `false` | `true` |
| `enable_binary_authorization` | Signed images only | `false` | `true` |
| `enable_audit_logging` | Comprehensive logging | `false` | `true` |
| `enable_cmek` | Customer-managed KMS keys | `false` | `true` |
| `enable_gpu_node_pool` | GPU node pool | `true` | `true` |
| `gpu_type` | GPU type | `nvidia-l4` | `nvidia-l4` |
| `gpu_node_pool_spot` | Use Spot VMs for GPU nodes | `true` | `true` |
| `primary_node_pool_machine_type` | CPU node machine type | `e2-standard-4` | `e2-standard-8` |

---

## Environment Variable → Terraform Variable Mapping

`deploy_all.sh` maps `.env` variables to `TF_VAR_*` automatically (H-16 selective export — secrets go directly to `TF_VAR_*`, never as bare env vars):

| `.env` variable | `TF_VAR_*` variable |
|-----------------|---------------------|
| `GOOGLE_CLOUD_PROJECT` | `TF_VAR_project_id` |
| `GOOGLE_CLOUD_LOCATION` | `TF_VAR_region` |
| `CAGE_DEPLOYMENT_REGION` | `TF_VAR_cage_deployment_region` |
| `LANGFUSE_PUBLIC_KEY` | `TF_VAR_langfuse_public_key` |
| `LANGFUSE_SECRET_KEY` | `TF_VAR_langfuse_secret_key` |
| `CAGE_ROUTING_SEAL_SECRET` | `TF_VAR_routing_seal_secret` |
| `GOVERNANCE_SALT` | `TF_VAR_governance_salt` |
| `HUGGING_FACE_HUB_TOKEN` | `TF_VAR_hf_token` |
| `KMS_GOVERNANCE_KEY` | `TF_VAR_kms_governance_key` |

---

## Security Posture Testing

### Binary Authorization (GCP only)

```bash
cd infra/targets/gcp-gke
terraform apply -var-file=dev.tfvars \
  -var="enable_binary_authorization=true"
```

### Private cluster with authorized networks (GCP only, US_FED)

```bash
terraform apply -var-file=prod.tfvars \
  -var="enable_nist_compliance=true" \
  -var='authorized_networks=[{"cidr":"<YOUR_IP>/32","display_name":"My IP"}]'
```

### Pod Security Standards (both targets)

```bash
# Already enforced at namespace level by pod-security-admission.yaml
# For the Terraform namespace module:
terraform apply -var-file=dev.tfvars \
  -var="enable_pod_security_standards=true" \
  -var="pod_security_level=restricted"
```

---

## Troubleshooting

### `terraform-state namespace not found` (agnostic)

```bash
kubectl create namespace terraform-state
```

### `Storage class not found` (k3s)

```bash
kubectl get storageclass
# Update storage_class in dev.tfvars to match an available class (e.g. local-path)
```

### `Failed to create GKE cluster: quota exceeded`

```bash
gcloud compute project-info describe --project=<YOUR_GCP_PROJECT_ID>
# Request a quota increase in the Cloud Console if needed
```

### `GCP API not enabled`

```bash
gcloud services enable container.googleapis.com \
  compute.googleapis.com \
  storage.googleapis.com \
  cloudbuild.googleapis.com \
  --project=<YOUR_GCP_PROJECT_ID>
```

### `ImagePullBackOff` on GKE

Images must be built via Cloud Build before Terraform apply. `deploy_all.sh` handles this automatically; for manual builds:

```bash
export PROJECT_ID=<YOUR_GCP_PROJECT_ID>
bash scripts/build_images.sh
```

### Backend connection refused on port-forward

```bash
# Restart port-forwards (they auto-reconnect)
pkill -f "kubectl port-forward" || true
bash scripts/port_forward_dev.sh
```

---

## Port-Forward Reference (development)

Run `bash scripts/port_forward_dev.sh` to start all with auto-reconnect.

| Service | Local Port | K8s Service | Remote Port |
|---------|------------|-------------|-------------|
| OPA | 8181 | `opa` | 8181 |
| Langfuse API | 3001 | `langfuse-web` | 3000 |
| Langfuse UI | 3000 | `langfuse-web` | 3000 |
| vLLM fast | 8001 | `vllm-service` | 8000 |
| vLLM fast (alt) | 18081 | `vllm-service` | 8000 |
| vLLM reasoning | 8000 | `vllm-reasoning` | 8000 |
| vLLM reasoning (alt) | 18082 | `vllm-reasoning` | 8000 |
| Gateway | 8080 | `gateway` | 8080 |
| Governed FA backend | 18080 | `governed-financial-advisor` | 80 |
| Redis (write) | 6379 | `redis-master` | 6379 |
| Compliance Bridge | 3002 | `compliance-bridge` | 80 |

---

## Next Steps

After validating the minimal stack:

1. Review the [Deployment Guide](DEPLOYMENT_GUIDE.md) for production configuration
2. Run Lula compliance validations:
   ```bash
   lula validate -f compliance/lula/lula-validation-ac3.yaml
   ```
3. Set `CAGE_DEPLOYMENT_REGION` correctly for your jurisdiction (`US_FED`, `EU_ECB`, or `APAC_MAS`)
4. Monitor the governance pipeline in Langfuse (`http://localhost:3000` via port-forward)

---

## See Also

- [Deployment Guide](DEPLOYMENT_GUIDE.md) — full deployment reference
- [Module Documentation](modules/) — individual module READMEs
- [`deployment/README.md`](../deployment/README.md) — Kubernetes manifest reference
- [`deployment/k8s/NAMESPACE-GUIDE.md`](../deployment/k8s/NAMESPACE-GUIDE.md) — namespace topology
- [`docs/operations/DEPLOYMENT_RULES.md`](../docs/operations/DEPLOYMENT_RULES.md) — Cloud Build requirement for GKE
