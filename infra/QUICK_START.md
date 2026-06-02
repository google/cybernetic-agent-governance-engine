# Quick Start Guide: Monorepo Infrastructure

## Prerequisites

### Required Tools
- **Terraform** >= 1.5.0
- **kubectl** >= 1.24
- **uv** (Python package manager)
- **Git**

### For Agnostic Target
- **Kubernetes cluster** (k3s, minikube, kind, EKS, AKS, or GKE)
- **kubectl** configured with cluster access

### For GCP-GKE Target
- **gcloud CLI** authenticated
- **GCP project** with billing enabled
- **Appropriate IAM permissions** (Kubernetes Engine Admin, Service Account Admin)

## 5-Minute Test: Agnostic Target

### 1. Set up local k3s cluster

```bash
# Install k3s (if not already installed)
curl -sfL https://get.k3s.io | sh -

# Verify installation
kubectl get nodes

# Create terraform-state namespace
kubectl create namespace terraform-state
```

### 2. Deploy minimal stack

```bash
# From repository root
./deploy_all.sh --target agnostic --env dev \
  --var minio_root_password=TestPassword123 \
  --auto-approve
```

**What this does**:
1. Creates `governance-stack-dev` namespace
2. Deploys MinIO object storage
3. Stores Terraform state in the cluster

### 3. Verify deployment

```bash
# Check namespace
kubectl get ns governance-stack-dev

# Check MinIO pod
kubectl get pods -n governance-stack-dev

# Get MinIO credentials
kubectl get secret minio-credentials -n governance-stack-dev \
  -o jsonpath='{.data.access-key}' | base64 -d && echo

# Access MinIO console
kubectl port-forward svc/minio 9001:9001 -n governance-stack-dev
# Open: http://localhost:9001
```

### 4. Clean up

```bash
cd infra/targets/agnostic
terraform destroy -var-file=dev.tfvars \
  -var="minio_root_password=TestPassword123" \
  -auto-approve
```

## 10-Minute Test: GCP-GKE Target

### 1. Authenticate with GCP

```bash
# Login
gcloud auth application-default login

# Set project
export GOOG-REDACTED
```

### 2. Configure variables

Edit `infra/targets/gcp-gke/dev.tfvars`:

```hcl
project_id = "your-actual-project-id"  # CHANGE THIS
```

### 3. Deploy to GCP

```bash
# From repository root
./deploy_all.sh --target gcp-gke --env dev \
  --var minio_root_password=SecurePassword123 \
  --auto-approve
```

**What this does**:
1. Provisions GKE cluster with CPU and GPU node pools
2. Creates `governance-stack-dev` namespace
3. Deploys MinIO on pd-standard storage
4. Creates GCS bucket for Langfuse events
5. Sets up Cloud Router & NAT (if private cluster enabled)

**Estimated time**: 8-12 minutes (GKE cluster provisioning)

### 4. Verify deployment

```bash
# Configure kubectl
gcloud container clusters get-credentials cage-dev \
  --zone=us-central1-a \
  --project=YOUR_PROJECT

# Check nodes
kubectl get nodes

# Check namespace
kubectl get ns governance-stack-dev

# Check MinIO
kubectl get pods -n governance-stack-dev
kubectl get svc -n governance-stack-dev

# Access MinIO console
kubectl port-forward svc/minio 9001:9001 -n governance-stack-dev
```

### 5. Clean up

```bash
cd infra/targets/gcp-gke
terraform destroy -var-file=dev.tfvars \
  -var="minio_root_password=SecurePassword123" \
  -auto-approve
```

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
# With var file
terraform plan -var-file=dev.tfvars

# Override specific variables
terraform plan -var-file=dev.tfvars \
  -var="minio_storage_size=5Gi"
```

### Apply

```bash
# Interactive (prompts for confirmation)
terraform apply -var-file=dev.tfvars

# Auto-approve (careful!)
terraform apply -var-file=dev.tfvars -auto-approve
```

### Destroy

```bash
terraform destroy -var-file=dev.tfvars -auto-approve
```

## Common Issues

### Issue: "terraform-state namespace not found" (Agnostic)

```bash
kubectl create namespace terraform-state
```

### Issue: "Storage class 'local-path' not found" (k3s)

```bash
# Verify storage class exists
kubectl get storageclass

# Update dev.tfvars with correct storage_class value
```

### Issue: "Failed to create GKE cluster: quota exceeded"

```bash
# Check your GCP quotas
gcloud compute project-info describe --project=YOUR_PROJECT

# Request quota increase in Cloud Console
```

### Issue: "GCP API not enabled"

```bash
# Enable required APIs
gcloud services enable container.googleapis.com \
  compute.googleapis.com \
  storage.googleapis.com \
  --project=YOUR_PROJECT
```

## Environment Variable Reference

### Agnostic Target

```bash
export KUBECONFIG=~/.kube/config
export TF_VAR_minio_root_password=SecurePassword123
export REGISTRY_URL=ghcr.io/your-org/cage
```

### GCP-GKE Target

```bash
export GOOG-REDACTED
export TF_VAR_minio_root_password=SecurePassword123
export TF_VAR_project_id=your-project-id
```

## Security Posture Testing

### Test Binary Authorization (GCP only)

```bash
cd infra/targets/gcp-gke
terraform apply -var-file=dev.tfvars \
  -var="enable_binary_authorization=true"
```

### Test Private Cluster (GCP only)

```bash
terraform apply -var-file=dev.tfvars \
  -var="enable_nist_compliance=true" \
  -var='authorized_networks=[{cidr="YOUR_IP/32",display_name="My IP"}]'
```

### Test Pod Security Standards (Both targets)

```bash
# Agnostic
terraform apply -var-file=dev.tfvars \
  -var="enable_pod_security_standards=true" \
  -var="pod_security_level=restricted"

# GCP-GKE
terraform apply -var-file=dev.tfvars \
  -var="enable_pod_security_standards=true"
```

## Next Steps

After validating the minimal stack works:

1. **Extract more modules** (postgres, redis, vllm, langfuse)
2. **Add IAM resources** to gcp-gke target
3. **Test full application deployment**
4. **Migrate production** to new structure
5. **Archive old code** in `deployment/terraform/`

## Getting Help

- **Implementation Status**: [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md)
- **Architecture**: [plans/monorepo-refactoring-plan.md](../plans/monorepo-refactoring-plan.md)
- **Security Postures**: [plans/monorepo-security-postures.md](../plans/monorepo-security-postures.md)
- **Migration Guide**: [plans/monorepo-migration-guide.md](../plans/monorepo-migration-guide.md)

## Success Criteria

✅ Minimal deployment works (namespace + MinIO)  
✅ Can access MinIO console  
✅ Terraform state persists correctly  
✅ Can destroy and recreate cleanly  
✅ Both targets work independently  

**Once these pass, you're ready to extract remaining modules.**
