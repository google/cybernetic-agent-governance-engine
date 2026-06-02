# Integration Testing Plan

**Created**: 2026-03-15  
**Purpose**: Validate all 9 Terraform modules across both deployment targets

---

## Test Overview

This plan tests the complete monorepo refactoring implementation:
- 9 Terraform modules (k8s_namespace, minio_storage, postgres_db, redis_cache, vllm_inference, langfuse_stack, compliance_bridge, opa_policy, gcp_gke_cluster)
- 2 deployment targets (agnostic, gcp-gke)
- 2 environments per target (dev, prod)

---

## Prerequisites

### For Agnostic Target
- [ ] Kubernetes cluster running (k3s, kind, minikube, etc.)
- [ ] kubectl configured with correct context
- [ ] Terraform >= 1.5.0 installed
- [ ] Helm >= 3.0 installed
- [ ] `terraform-state` namespace created: `kubectl create namespace terraform-state`

### For GCP-GKE Target
- [ ] GCP project with billing enabled
- [ ] gcloud CLI authenticated: `gcloud auth application-default login`
- [ ] Required GCP APIs enabled (container, compute, storage)
- [ ] Terraform >= 1.5.0 installed
- [ ] Sufficient GCP quotas (GPUs if testing vLLM)

---

## Test 1: Agnostic Target - Minimal Stack (Dev)

**Duration**: 10-15 minutes  
**Goal**: Validate core modules (namespace, minio, postgres, redis)

### Steps

```bash
cd infra/targets/agnostic

# Initialize
terraform init -backend-config="config_path=~/.kube/config"

# Plan
terraform plan -var-file=dev.tfvars

# Apply
terraform apply -var-file=dev.tfvars -auto-approve
```

### Expected Resources

- ✅ Namespace: `governance-stack-dev`
- ✅ MinIO: 1 pod running
- ✅ PostgreSQL: 1 pod running  
- ✅ Redis: 1 pod running (standalone)
- ✅ Langfuse Web: 1 pod running
- ✅ Langfuse Worker: 1 pod running
- ✅ OPA: 1 pod running

### Validation Commands

```bash
# Check all pods
kubectl get pods -n governance-stack-dev

# Check services
kubectl get svc -n governance-stack-dev

# Check PVCs
kubectl get pvc -n governance-stack-dev

# Test MinIO
kubectl port-forward svc/minio 9000:9000 -n governance-stack-dev &
curl http://localhost:9000/minio/health/live

# Test PostgreSQL
kubectl run psql-test --rm -it --image=postgres:15 \
  -n governance-stack-dev -- \
  psql postgresql://REDACTED:REDACTED@postgresql:5432/langfuse -c '\l'

# Test Redis
kubectl run redis-test --rm -it --image=redis \
  -n governance-stack-dev -- \
  redis-cli -h redis-master ping

# Test Langfuse
kubectl port-forward svc/langfuse-web 3000:3000 -n governance-stack-dev &
curl http://localhost:3000/api/public/health

# Test OPA
kubectl port-forward svc/opa 8181:8181 -n governance-stack-dev &
curl http://localhost:8181/health
```

### Success Criteria

- [ ] All pods in Running state
- [ ] All services created
- [ ] All PVCs bound
- [ ] Health checks pass
- [ ] No errors in pod logs

---

## Test 2: Agnostic Target - Full Stack (with vLLM)

**Duration**: 20-30 minutes (includes model download)  
**Goal**: Validate vLLM inference module  
**Prerequisites**: GPU nodes available OR skip vLLM

### Steps

```bash
cd infra/targets/agnostic

# Plan with vLLM enabled
terraform plan -var-file=dev.tfvars \
  -var="enable_vllm=true" \
  -var="vllm_model_path=meta-llama/Llama-3.2-1B-Instruct"

# Apply
terraform apply -var-file=dev.tfvars \
  -var="enable_vllm=true" \
  -var="vllm_model_path=meta-llama/Llama-3.2-1B-Instruct" \
  -auto-approve
```

### Validation

```bash
# Check vLLM pod
kubectl get pods -l app=vllm-inference -n governance-stack-dev

# Check GPU allocation
kubectl describe pod -l app=vllm-inference -n governance-stack-dev | grep -A 5 "Limits"

# Test inference
kubectl port-forward svc/vllm-service 8000:8000 -n governance-stack-dev &
curl http://localhost:8000/v1/models

# Test completion
curl http://localhost:8000/v1/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "meta-llama/Llama-3.2-1B-Instruct",
    "prompt": "Hello, how are you?",
    "max_tokens": 50
  }'
```

### Success Criteria

- [ ] vLLM pod running
- [ ] GPU allocated (if GPU nodes present)
- [ ] Model loaded successfully
- [ ] Inference endpoint responds
- [ ] Health check passes

---

## Test 3: GCP-GKE Target - Full Stack (Dev)

**Duration**: 30-45 minutes (includes cluster provisioning)  
**Goal**: Validate complete GCP-GKE deployment

### Steps

```bash
cd infra/targets/gcp-gke

# Set required variables
export TF_VAR_project_id="your-gcp-project"
export TF_VAR_minio_root_password="SecurePassword123!"

# Initialize
terraform init

# Plan
terraform plan -var-file=dev.tfvars

# Apply
terraform apply -var-file=dev.tfvars -auto-approve
```

### Expected Resources

#### GCP Resources
- ✅ GKE cluster with 2 node pools
- ✅ VPC network (if private cluster)
- ✅ Cloud NAT (if NIST compliance)
- ✅ GCS bucket for Langfuse

#### Kubernetes Resources
- ✅ Namespace: `governance-stack-dev`
- ✅ MinIO: 1 pod
- ✅ PostgreSQL: 1 pod
- ✅ Redis: 1 pod (standalone in dev)
- ✅ Langfuse Web: 1 pod
- ✅ Langfuse Worker: 1 pod
- ✅ OPA: 1 pod
- ✅ vLLM: 1 pod (if enabled)

### Validation Commands

```bash
# Configure kubectl
gcloud container clusters get-credentials <cluster-name> \
  --zone=<zone> \
  --project=<project-id>

# Check cluster
kubectl cluster-info
kubectl get nodes

# Check all pods
kubectl get pods -n governance-stack-dev -o wide

# Check GPU nodes (if enabled)
kubectl get nodes -l cloud.google.com/gke-accelerator

# Run all validation commands from Test 1
# ... (same kubectl commands)
```

### Success Criteria

- [ ] GKE cluster provisioned
- [ ] All node pools ready
- [ ] All pods running
- [ ] All services accessible
- [ ] Health checks pass
- [ ] GPU nodes available (if enabled)

---

## Test 4: GCP-GKE Target - Production Mode (NIST Compliance)

**Duration**: 45-60 minutes  
**Goal**: Validate NIST compliance features

### Steps

```bash
cd infra/targets/gcp-gke

# Plan with prod config
terraform plan -var-file=prod.tfvars

# Review security features before applying
# - Private cluster endpoints
# - Binary Authorization
# - CMEK encryption
# - Audit logging
# - Network policies

# Apply (review carefully!)
terraform apply -var-file=prod.tfvars -auto-approve
```

### Expected NIST Features

#### Cluster Level
- ✅ Private master endpoint
- ✅ Binary Authorization enabled
- ✅ Audit logging enabled
- ✅ CMEK for secrets (if kms_key_id provided)
- ✅ Workload Identity enabled
- ✅ Network policy enabled

#### Application Level
- ✅ Pod Security Standards enforced
- ✅ Resource limits on all pods
- ✅ PostgreSQL backups enabled
- ✅ Redis replication (3 replicas + Sentinel)
- ✅ Langfuse: 2 web + 2 worker replicas
- ✅ OPA: 2 replicas
- ✅ Pod Disruption Budgets

### Validation

```bash
# Check cluster features
gcloud container clusters describe <cluster-name> \
  --zone=<zone> --project=<project-id> \
  --format="yaml(privateClusterConfig,binaryAuthorization,loggingConfig)"

# Check Redis replication
kubectl get statefulset redis -n governance-stack-prod
kubectl get pods -l app=redis -n governance-stack-prod

# Check resource limits
kubectl get pods -n governance-stack-prod -o json | \
  jq '.items[].spec.containers[].resources'

# Check PDBs
kubectl get pdb -n governance-stack-prod
```

### Success Criteria

- [ ] All NIST features enabled
- [ ] High availability configured
- [ ] Resource limits enforced
- [ ] Backups enabled
- [ ] Security posture verified

---

## Test 5: Module Independence

**Duration**: 15 minutes  
**Goal**: Validate modules can be used independently

### Test Each Module

#### k8s_namespace
```bash
cd infra/modules/k8s_namespace
terraform init
terraform validate
```

#### postgres_db
```bash
cd infra/modules/postgres_db
terraform init
terraform validate
```

*Repeat for all 9 modules*

### Success Criteria

- [ ] All modules pass `terraform validate`
- [ ] No undefined variables (all have defaults or are required)
- [ ] README exists for each module
- [ ] Outputs documented

---

## Test 6: Terraform State Management

**Duration**: 10 minutes  
**Goal**: Validate state backend configuration

### Agnostic Target

```bash
cd infra/targets/agnostic

# Check state stored in Kubernetes
kubectl get secret -n terraform-state | grep tfstate-agnostic

# Verify can read state
terraform state list

# Test locking (run in two terminals simultaneously)
terraform plan &
terraform plan &
# Second should wait for lock
```

### GCP-GKE Target

```bash
cd infra/targets/gcp-gke

# Check state backend
cat .terraform/terraform.tfstate  # Should show remote backend

# List state
terraform state list

# Test state locking
terraform plan &
terraform plan &
```

### Success Criteria

- [ ] State stored in correct backend
- [ ] State locking works
- [ ] Can list resources
- [ ] Can import/export state

---

## Test 7: Cleanup and Teardown

**Duration**: 15-20 minutes  
**Goal**: Validate terraform destroy works correctly

### Agnostic Target

```bash
cd infra/targets/agnostic

# Destroy in reverse order
terraform destroy -var-file=dev.tfvars -auto-approve

# Verify all resources removed
kubectl get all -n governance-stack-dev
kubectl get pvc -n governance-stack-dev
```

### GCP-GKE Target

```bash
cd infra/targets/gcp-gke

# Destroy
terraform destroy -var-file=dev.tfvars -auto-approve

# Verify GCP resources removed
gcloud compute instances list --project=<project-id>
gcloud container clusters list --project=<project-id>
gcloud storage buckets list --project=<project-id> | grep langfuse
```

### Success Criteria

- [ ] All Kubernetes resources deleted
- [ ] All PVCs deleted
- [ ] All GCP resources deleted (GKE target)
- [ ] No orphaned resources
- [ ] Clean state file

---

## Test Matrix

| Target | Environment | Modules | Duration | Status |
|--------|-------------|---------|----------|--------|
| agnostic | dev | Core (no vLLM) | 10 min | ⏳ Pending |
| agnostic | dev | Full (with vLLM) | 30 min | ⏳ Pending |
| agnostic | prod | Full | 30 min | ⏳ Pending |
| gcp-gke | dev | Full | 45 min | ⏳ Pending |
| gcp-gke | prod | Full (NIST) | 60 min | ⏳ Pending |

**Total Testing Time**: ~3 hours

---

## Automated Testing Script

**File**: `infra/run_tests.sh`

```bash
#!/usr/bin/env bash
set -euo pipefail

echo "🧪 Running infrastructure integration tests..."

# Test 1: Agnostic minimal
echo "Test 1: Agnostic minimal stack..."
cd infra/targets/agnostic
terraform init -backend-config="config_path=~/.kube/config"
terraform plan -var-file=dev.tfvars
terraform apply -var-file=dev.tfvars -auto-approve

# Validate
kubectl wait --for=condition=ready pod -l app=minio -n governance-stack-dev --timeout=300s
kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=postgresql -n governance-stack-dev --timeout=300s
kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=redis -n governance-stack-dev --timeout=300s

echo "✅ Test 1 passed"

# Cleanup
terraform destroy -var-file=dev.tfvars -auto-approve

echo "✅ All tests passed!"
```

---

## Known Issues / Limitations

### vLLM Testing
- Requires GPU nodes (expensive/scarce)
- Model download can be slow
- May need to skip in CI/CD

### GCP Quotas
- GPU quotas may be 0 by default
- Need to request quota increase
- Test with small instances first

### State Management
- Kubernetes backend requires cluster to exist
- GCS backend requires bucket to exist
- Manual setup required for first run

---

## Quick Validation Commands

### Check All Modules Exist
```bash
ls -la infra/modules/
# Should show: k8s_namespace, gcp_gke_cluster, minio_storage, postgres_db,
#              redis_cache, vllm_inference, langfuse_stack, compliance_bridge, opa_policy
```

### Validate All Modules
```bash
for module in infra/modules/*/; do
  echo "Validating $(basename $module)..."
  (cd "$module" && terraform init && terraform validate)
done
```

### Check Targets
```bash
ls -la infra/targets/
# Should show: agnostic, gcp-gke
```

### Validate Targets
```bash
# Agnostic
cd infra/targets/agnostic
terraform init -backend-config="config_path=~/.kube/config"
terraform validate

# GCP-GKE
cd infra/targets/gcp-gke
terraform init
terraform validate
```

---

## Test Results Template

### Test Execution Log

| Test | Target | Environment | Start Time | End Time | Status | Notes |
|------|--------|-------------|------------|----------|--------|-------|
| 1 | agnostic | dev | - | - | ⏳ | Minimal stack |
| 2 | agnostic | dev | - | - | ⏳ | With vLLM |
| 3 | gcp-gke | dev | - | - | ⏳ | Full stack |
| 4 | gcp-gke | prod | - | - | ⏳ | NIST mode |

### Issues Found

| Issue | Module | Severity | Resolution |
|-------|--------|----------|------------|
| | | | |

---

## Post-Test Checklist

- [ ] All tests passed
- [ ] No errors in logs
- [ ] Resources cleaned up
- [ ] Documentation updated with test results
- [ ] Known issues documented
- [ ] Ready for production migration
