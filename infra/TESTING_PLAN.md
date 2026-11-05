# Integration Testing Plan

**Created**: 2026-03-15  
**Purpose**: Validate the CAGE Terraform modules and the `gcp-gke` deployment target (`infra/targets/gcp-gke/`)

---

## Test Overview

This plan validates the CAGE infrastructure-as-code stack (`POAM-2026-185` retired the unvalidated `2bacc478:infra/targets/agnostic/` target and its `minio_storage`, `postgres_db`, and `redis_cache` modules):
- 21 Terraform modules under `infra/modules/`
- 1 Kubernetes/Terraform deployment target (`infra/targets/gcp-gke/`)
- 3 environments (`dev`, `staging`, `prod`) plus regional overlays (`eu-dev`, `eu-prod`, `apac-dev`, `apac-prod`)

---

## Prerequisites

### For GCP-GKE Target (`infra/targets/gcp-gke/`)
- [ ] GCP project with billing enabled
- [ ] `gcloud` CLI authenticated: `gcloud auth application-default login`
- [ ] Required GCP APIs enabled via [`scripts/bootstrap_gcp_project.sh`](../scripts/bootstrap_gcp_project.sh)
- [ ] Terraform >= 1.7.0 installed
- [ ] Sufficient GCP quotas (GPUs if testing `inference_backend = "vllm"`)

---

## Test 1: Hermetic Terraform Test Suite (`terraform test`)

**Duration**: ~2 minutes  
**Goal**: Validate all `infra/targets/gcp-gke/tests/*.tftest.hcl` suites hermetically without live cloud credentials

### Steps

```bash
cd infra/targets/gcp-gke
terraform init -backend=false
terraform validate
terraform test
```

### Success Criteria

- [ ] `terraform validate` exits 0
- [ ] All `.tftest.hcl` suites (`guard_placement.tftest.hcl`, `retention_posture.tftest.hcl`, `w6.tftest.hcl`) pass

---

## Test 2: GCP-GKE Target - Staging / Dev Stack

**Duration**: 30-45 minutes (includes cluster provisioning)  
**Goal**: Validate complete GCP-GKE deployment

### Steps

```bash
./deploy_all.sh --target gcp-gke --env staging \
  --var project_id="<YOUR_GCP_PROJECT_ID>" \
  --auto-approve
```

### Expected Resources

#### GCP Resources
- ✅ GKE cluster with CPU, ClickHouse, and GPU node pools bound to `cage-gke-nodes-<env>`
- ✅ VPC network, subnetwork, Cloud Router, and Cloud NAT
- ✅ Retention-locked GCS WORM evidence bucket and Langfuse event upload bucket
- ✅ Cloud SQL PostgreSQL and Memorystore Redis/Valkey
- ✅ Cloud KMS keyring and signing/CMEK keys

#### Kubernetes Resources
- ✅ Namespace: `governance-stack`
- ✅ ClickHouse: 1 pod (in `dev`/`staging`)
- ✅ Langfuse Web & Worker pods
- ✅ OPA, Gateway, Compliance Bridge, and Reconciliation Worker pods
- ✅ vLLM pods in `vllm-inference` (when `inference_backend = "vllm"`)

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
kubectl get pods -n governance-stack -o wide

# Check GPU nodes (if enabled)
kubectl get nodes -l cloud.google.com/gke-accelerator
```

### Success Criteria

- [ ] GKE cluster provisioned
- [ ] All node pools ready
- [ ] All pods running
- [ ] All services accessible
- [ ] Health checks pass
- [ ] GPU nodes available (if `inference_backend = "vllm"`)

---

## Test 3: GCP-GKE Target - Production Mode (Full Compliance Posture)

**Duration**: 45-60 minutes  
**Goal**: Validate production security posture (`local.enforcing_posture = true`)

### Steps

```bash
cd infra/targets/gcp-gke

# Plan with prod config
terraform plan -var-file=prod.tfvars -var-file=image_digests.<short_sha>.tfvars.json

# Apply (review carefully!)
terraform apply -var-file=prod.tfvars -var-file=image_digests.<short_sha>.tfvars.json
```

### Expected Production Features

#### Cluster Level
- ✅ Scoped `authorized_networks` enforced by `control_plane_access_guard`
- ✅ Binary Authorization enabled
- ✅ Audit logging enabled
- ✅ CMEK database/node encryption
- ✅ Workload Identity and dedicated node-pool service account (`cage-gke-nodes-prod`)
- ✅ Network policy / Dataplane V2 enabled

#### Application Level
- ✅ Pod Security Standards (`restricted`) enforced
- ✅ Resource limits on all pods
- ✅ Cloud SQL PITR and deletion protection enabled
- ✅ Langfuse: 2 web + 2 worker replicas
- ✅ OPA: 2 replicas
- ✅ Pod Disruption Budgets

### Validation

```bash
# Check cluster features
gcloud container clusters describe <cluster-name> \
  --zone=<zone> --project=<project-id> \
  --format="yaml(privateClusterConfig,binaryAuthorization,loggingConfig)"

# Check resource limits
kubectl get pods -n governance-stack -o json | \
  jq '.items[].spec.containers[].resources'

# Check PDBs
kubectl get pdb -n governance-stack
```

### Success Criteria

- [ ] All enforcing posture features enabled
- [ ] High availability configured
- [ ] Resource limits enforced
- [ ] Backups enabled
- [ ] Security posture verified

---

## Test 4: Module Independence

**Duration**: 5 minutes  
**Goal**: Validate modules pass `terraform validate` independently

### Validate All Modules
```bash
for module in infra/modules/*/; do
  echo "Validating $(basename "$module")..."
  (cd "$module" && terraform init -backend=false && terraform validate)
done
```

### Success Criteria

- [ ] All 21 modules in `infra/modules/` pass `terraform validate`
- [ ] `infra/targets/gcp-gke` passes `terraform validate`

---

## Test 5: Terraform State Management (`gcp-gke`)

**Duration**: 10 minutes  
**Goal**: Validate GCS remote state backend configuration

```bash
cd infra/targets/gcp-gke

# List state
terraform state list

# Test state locking
terraform plan -var-file=staging.tfvars &
terraform plan -var-file=staging.tfvars &
```

### Success Criteria

- [ ] State stored in GCS backend (`gs://<project_id>-tfstate`)
- [ ] State locking works
- [ ] Can list resources

---

## Test 6: Cleanup and Teardown

**Duration**: 15-20 minutes  
**Goal**: Validate `terraform destroy` works cleanly (or via [`scripts/staging_lifecycle.sh`](../scripts/staging_lifecycle.sh))

```bash
cd infra/targets/gcp-gke

# Destroy
terraform destroy -var-file=dev.tfvars \
  -var-file=image_digests.<short_sha>.tfvars.json \
  -var project_id=<project-id> -auto-approve

# Verify GCP resources removed
gcloud compute instances list --project=<project-id>
gcloud container clusters list --project=<project-id>
```

### Success Criteria

- [ ] All Kubernetes resources deleted
- [ ] All PVCs deleted
- [ ] GKE cluster deleted
- [ ] No orphaned compute resources

---

## Test Matrix

| Target | Environment | Mode | Duration | Status |
|--------|-------------|------|----------|--------|
| `gcp-gke` | Hermetic CI | `terraform test` | 2 min | ✅ Automated in CI (`terraform-test`) |
| `gcp-gke` | `staging` | Full enforcing posture (`inference_backend = "none"`) | 30 min | ⏳ Live validation |
| `gcp-gke` | `dev` | Full stack (`inference_backend = "vllm"`) | 45 min | ⏳ Live validation |
| `gcp-gke` | `prod` | Full HA + compliance posture | 60 min | ⏳ Live validation |
