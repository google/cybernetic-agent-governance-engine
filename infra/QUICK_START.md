# Quick Start Guide: CAGE Infrastructure

Deploy the Cybernetic Governance Engine infrastructure in 5–10 minutes.

## Prerequisites

### Required Tools

| Tool | Minimum Version |
|------|----------------|
| Terraform | >= 1.5.0 |
| kubectl | >= 1.24 |
| uv (Python package manager) | latest |
| Git | any |

### For the Agnostic Target

- A running Kubernetes cluster (k3s, minikube, kind, EKS, AKS, or GKE)
- `kubectl` configured with cluster access

### For the GCP-GKE Target

- `gcloud` CLI authenticated (`gcloud auth application-default login`)
- A GCP project with billing enabled
- IAM permissions: Kubernetes Engine Admin, Service Account Admin, Storage Admin

---

## Option A: Agnostic Kubernetes (5 minutes)

Deploy to any existing Kubernetes cluster.

### 1. Set up a local cluster (if needed)

```bash
# Install k3s
curl -sfL https://get.k3s.io | sh -

# Verify
kubectl get nodes

# Create the Terraform state namespace
kubectl create namespace terraform-state
```

### 2. Deploy the minimal governance stack

```bash
# From the repository root
./deploy_all.sh --target agnostic --env dev \
  --var minio_root_password=<YOUR_MINIO_PASSWORD> \
  --auto-approve
```

**What this provisions:**
1. `governance-stack-dev` Kubernetes namespace
2. MinIO S3-compatible object storage
3. Terraform state stored in-cluster

### 3. Verify the deployment

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

### 4. Tear down

```bash
cd infra/targets/agnostic
terraform destroy -var-file=dev.tfvars \
  -var="minio_root_password=<YOUR_MINIO_PASSWORD>" \
  -auto-approve
```

---

## Option B: GCP GKE (10 minutes)

Provision a complete GKE cluster with GPU support.

### 1. Authenticate with GCP

```bash
gcloud auth application-default login

# Set your project
gcloud config set project <YOUR_GCP_PROJECT_ID>
```

### 2. Configure variables

Edit `infra/targets/gcp-gke/dev.tfvars` and set your project ID:

```hcl
project_id = "<YOUR_GCP_PROJECT_ID>"
```

### 3. Enable required GCP APIs

```bash
gcloud services enable \
  container.googleapis.com \
  compute.googleapis.com \
  storage.googleapis.com \
  --project=<YOUR_GCP_PROJECT_ID>
```

### 4. Deploy to GCP

```bash
# From the repository root
./deploy_all.sh --target gcp-gke --env dev \
  --var minio_root_password=<YOUR_MINIO_PASSWORD> \
  --auto-approve
```

**What this provisions:**
1. GKE cluster with CPU and GPU node pools
2. `governance-stack-dev` Kubernetes namespace
3. MinIO storage on GCP persistent disks
4. GCS bucket for Langfuse events
5. Cloud Router & NAT (when private cluster mode is enabled)

**Estimated time:** 8–12 minutes (GKE cluster provisioning)

### 5. Verify the deployment

```bash
# Configure kubectl for your new cluster
gcloud container clusters get-credentials <YOUR_GKE_CLUSTER_NAME> \
  --zone=us-central1-a \
  --project=<YOUR_GCP_PROJECT_ID>

# Check nodes
kubectl get nodes

# Check namespace and pods
kubectl get ns governance-stack-dev
kubectl get pods -n governance-stack-dev
kubectl get svc -n governance-stack-dev

# Access MinIO console
kubectl port-forward svc/minio 9001:9001 -n governance-stack-dev
# Open: http://localhost:9001
```

### 6. Tear down

```bash
cd infra/targets/gcp-gke
terraform destroy -var-file=dev.tfvars \
  -var="minio_root_password=<YOUR_MINIO_PASSWORD>" \
  -auto-approve
```

---

## Manual Terraform Operations

### Initialize

```bash
# Agnostic target
cd infra/targets/agnostic
terraform init -backend-config="config_path=~/.kube/config"

# GCP target
cd infra/targets/gcp-gke
terraform init
```

### Plan

```bash
terraform plan -var-file=dev.tfvars

# Override specific variables
terraform plan -var-file=dev.tfvars \
  -var="minio_storage_size=5Gi"
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

## Environment Variables

### Agnostic Target

```bash
export KUBECONFIG=~/.kube/config
export TF_VAR_minio_root_password=<YOUR_MINIO_PASSWORD>
export REGISTRY_URL=ghcr.io/<YOUR_ORG>/cage
```

### GCP-GKE Target

```bash
export TF_VAR_project_id=<YOUR_GCP_PROJECT_ID>
export TF_VAR_minio_root_password=<YOUR_MINIO_PASSWORD>
```

---

## Security Posture Testing

### Binary Authorization (GCP only)

```bash
cd infra/targets/gcp-gke
terraform apply -var-file=dev.tfvars \
  -var="enable_binary_authorization=true"
```

### Private Cluster with Authorized Networks (GCP only)

```bash
terraform apply -var-file=dev.tfvars \
  -var="enable_nist_compliance=true" \
  -var='authorized_networks=[{cidr="<YOUR_IP>/32",display_name="My IP"}]'
```

### Pod Security Standards (both targets)

```bash
# Agnostic
terraform apply -var-file=dev.tfvars \
  -var="enable_pod_security_standards=true" \
  -var="pod_security_level=restricted"

# GCP-GKE
terraform apply -var-file=dev.tfvars \
  -var="enable_pod_security_standards=true"
```

---

## Troubleshooting

### "terraform-state namespace not found" (Agnostic)

```bash
kubectl create namespace terraform-state
```

### "Storage class not found" (k3s)

```bash
# List available storage classes
kubectl get storageclass

# Update dev.tfvars with the correct storage_class value
```

### "Failed to create GKE cluster: quota exceeded"

```bash
# Check your GCP quotas
gcloud compute project-info describe --project=<YOUR_GCP_PROJECT_ID>

# Request a quota increase in the Cloud Console if needed
```

### "GCP API not enabled"

```bash
gcloud services enable container.googleapis.com \
  compute.googleapis.com \
  storage.googleapis.com \
  --project=<YOUR_GCP_PROJECT_ID>
```

---

## Next Steps

After validating the minimal stack:

1. Review the [Deployment Guide](DEPLOYMENT_GUIDE.md) for production configuration
2. Run Lula compliance validations: `compliance/lula/`
3. Set `CAGE_DEPLOYMENT_REGION` correctly for your target region (`US_FED`, `EU_ECB`, or `APAC_MAS`)
4. Monitor governance pipeline metrics in Langfuse

## See Also

- [Implementation Status](IMPLEMENTATION_STATUS.md) — component reference
- [Deployment Guide](DEPLOYMENT_GUIDE.md) — full deployment reference
- [Module Documentation](modules/) — individual module READMEs
