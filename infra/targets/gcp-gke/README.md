# GCP-GKE Deployment Target

Provisions a complete GKE cluster with GCP-optimized settings and security posture toggles.

## Quick Start

### Prerequisites

1. **GCP Project** with billing enabled
2. **gcloud CLI** authenticated (`gcloud auth application-default login`)
3. **Terraform** >= 1.5.0
4. **kubectl** installed
5. **uv** (Python package manager)

### Deploy to Dev

```bash
# From repository root
./deploy_all.sh --target gcp-gke --env dev --auto-approve

# Or manually
cd infra/targets/gcp-gke

# First time: Enable GCS backend (optional)
# gsutil mb -p YOUR_PROJECT gs://YOUR_PROJECT-tfstate

terraform init
terraform apply -var-file=dev.tfvars \
  -var="minio_root_password=SecurePassword123"
```

### Deploy to Prod

```bash
./deploy_all.sh --target gcp-gke --env prod

# Or manually (review plan first!)
cd infra/targets/gcp-gke
terraform plan -var-file=prod.tfvars
terraform apply -var-file=prod.tfvars
```

## What Gets Provisioned

### GCP Resources

- ✅ GKE cluster (with private nodes option)
- ✅ Primary CPU node pool (autoscaling)
- ✅ GPU node pool (NVIDIA L4 or T4 - regionally sourced across `us-central1-a/b/c`)
- ✅ GCS bucket for Langfuse events (7-year retention)
- ✅ Cloud Router & NAT (when private cluster enabled)
- ✅ Workload Identity federation service accounts
- ✅ IAM bindings and KMS storage keys

### Kubernetes Resources

- ✅ Namespace with environment labels
- ✅ MinIO object storage (S3-compatible)
- ✅ PostgreSQL database
- ✅ Redis cache
- ✅ vLLM inference engines (both fast instructions and reasoning)
- ✅ Langfuse stack (observability, database, ClickHouse, UI)
- ✅ Compliance bridge (Langfuse-to-Lula dynamic bootstrapping)
- ✅ OPA policy engine

## Security Postures

### Dev (Fast Iteration)

```hcl
enable_nist_compliance      = false  # Public cluster
enable_binary_authorization = false  # Any image can run
enable_audit_logging        = false  # Minimal logging
enable_cmek                 = false  # Google-managed keys

# Cost optimization
gpu_node_pool_min_count = 0  # Scale to zero
primary_node_pool_machine_type = "e2-medium"
```

**Result**: Public cluster, accessible from anywhere, cheap nodes, scales to zero.

### Prod (NIST RMF Compliance)

```hcl
enable_nist_compliance      = true   # Private cluster
enable_binary_authorization = true   # Only signed images
enable_audit_logging        = true   # Comprehensive logs
enable_cmek                 = true   # Customer-managed keys

# High availability
gpu_node_pool_min_count = 2  # Always available
primary_node_pool_min_count = 3  # HA requirement
```

**Result**: Private cluster, VPN-only access, audit logs to immutable GCS bucket, signed images only.

## Testing Individual Controls

You can test NIST controls one at a time:

```bash
# Test binary authorization
terraform apply -var-file=dev.tfvars \
  -var="enable_binary_authorization=true"

# Test private cluster
terraform apply -var-file=dev.tfvars \
  -var="enable_nist_compliance=true" \
  -var="authorized_networks=[{cidr=\"YOUR_IP/32\",display_name=\"My IP\"}]"

# Test audit logging
terraform apply -var-file=dev.tfvars \
  -var="enable_audit_logging=true"
```

## Access the Cluster

### Configure kubectl

```bash
# After deployment
gcloud container clusters get-credentials <your-cluster-name> \
  --zone=us-central1-a \
  --project=YOUR_PROJECT

# Verify
kubectl cluster-info
kubectl get nodes
```

### Access MinIO Console

```bash
kubectl port-forward svc/minio 9001:9001 -n governance-stack-dev
# Open: http://localhost:9001
```

## Cost Estimates

### Dev Cluster (Minimal)
- **Primary nodes**: 1x e2-medium = ~$25/month
- **GPU nodes**: 0-1x n1-standard-4 + T4 = ~$200/month when running
- **Storage**: 50 GB pd-standard = ~$2/month
- **GCS**: ~$1/month

**Total**: ~$30/month (idle), ~$230/month (GPU active)

### Prod Cluster (HA)
- **Primary nodes**: 3x e2-standard-8 = ~$200/month
- **GPU nodes**: 2x g2-standard-8 (L4) = ~$1200/month
- **Storage**: 500 GB pd-ssd = ~$90/month
- **GCS**: ~$5/month

**Total**: ~$1500/month

## NIST Control Evidence

For compliance audits:

```bash
# Show cluster configuration
gcloud container clusters describe cage-prod \
  --zone=us-central1-a \
  --project=YOUR_PROJECT

# Show private cluster config (SC-7)
gcloud container clusters describe cage-prod \
  --zone=us-central1-a \
  --format="value(privateClusterConfig)"

# Show binary authorization status (CM-7)
gcloud container clusters describe cage-prod \
  --zone=us-central1-a \
  --format="value(binaryAuthorization.evaluationMode)"

# Show audit logging config (AU-2)
gcloud container clusters describe cage-prod \
  --zone=us-central1-a \
  --format="value(loggingConfig.componentConfig.enableComponents)"
```

## Troubleshooting

### Terraform state locked

```bash
# List locks
terraform force-unlock <LOCK_ID>
```

### Provider authentication failed

```bash
# Re-authenticate
gcloud auth application-default login

# Verify credentials
gcloud auth list
```

### GPU quota exceeded

```bash
# Request quota increase in Cloud Console
# Navigation: IAM & Admin → Quotas → NVIDIA L4 GPUs
```

## Migration from Old Structure

If migrating from `deployment/terraform/`, see the Migration Guide.

The old code in `deployment/terraform/gcp/` can be safely archived after validating this target works.

## See Also

- [Agnostic Target](../agnostic/) - Deploy to any Kubernetes cluster
- [GKE Cluster Module](../../modules/gcp_gke_cluster/) - Module documentation
- Security Postures - Dev vs Prod configurations
- [NIST Controls Mapping](../../modules/gcp_gke_cluster/NIST_CONTROLS.md)
