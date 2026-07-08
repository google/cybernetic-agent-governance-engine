# Agnostic Deployment Target

Deploys Cybernetic Governance Engine to any existing Kubernetes cluster.

## Supported Platforms

- ✅ k3s (local development)
- ✅ minikube (local development)
- ✅ kind (local development)
- ✅ Amazon EKS
- ✅ Azure AKS
- ✅ Google GKE (without GCP-specific optimizations)
- ✅ Any Kubernetes 1.24+ cluster

## Quick Start

### Prerequisites

1. **Kubernetes cluster** with kubectl configured
2. **Terraform** >= 1.5.0
3. **uv** (for Python dependency management)

### Deploy to Dev

```bash
# From repository root
./deploy_all.sh --target agnostic --env dev --auto-approve

# Or manually
cd infra/targets/agnostic
terraform init \
  -backend-config="config_path=~/.kube/config"
terraform apply -var-file=dev.tfvars \
  -var="minio_root_password=SecurePassword123"
```

### Deploy to Prod

```bash
./deploy_all.sh --target agnostic --env prod

# Or manually
cd infra/targets/agnostic
terraform init \
  -backend-config="config_path=~/.kube/config" \
  -backend-config="config_context=production-cluster"
terraform apply -var-file=prod.tfvars
```

## State Management

This target uses the **Kubernetes backend** to store Terraform state as a Kubernetes Secret. No external cloud storage required.

### Setup

1. **Create terraform-state namespace** (one-time):
```bash
kubectl create namespace terraform-state
```

2. **Initialize with backend config**:
```bash
terraform init \
  -backend-config="config_path=~/.kube/config"
```

3. **Verify state storage**:
```bash
kubectl get secret -n terraform-state tfstate-agnostic -o yaml
```

### Benefits

- ✅ No cloud provider dependencies
- ✅ State stored securely in cluster
- ✅ Automatic encryption at rest
- ✅ Works on any Kubernetes platform

## Storage Class Configuration

Update `storage_class` in `.tfvars` based on your platform:

| Platform | Dev | Prod |
|----------|-----|------|
| k3s | `local-path` | `local-path` |
| minikube | `standard` | `standard` |
| kind | `standard` | `standard` |
| EKS | `gp2` | `gp3` |
| AKS | `default` | `managed-premium` |
| GKE | `standard` | `pd-ssd` |

## What Gets Deployed

All infrastructure modules are fully implemented. Enable them by uncommenting the relevant blocks in [`main.tf`](main.tf) and providing the required variables in your `.tfvars` file.

- ✅ Kubernetes namespace with labels
- ✅ MinIO object storage (S3-compatible)
- ✅ PostgreSQL database (`infra/modules/postgres_db/`)
- ✅ Redis cache with Sentinel HA (`infra/modules/redis_cache/`)
- ✅ vLLM inference backend (`infra/modules/vllm_inference/`)
- ✅ Langfuse observability stack (`infra/modules/langfuse_stack/`)
- ✅ Compliance bridge (`infra/modules/compliance_bridge/`)
- ✅ OPA policy engine (`infra/modules/opa_policy/`)

## Security Postures

### Dev
- No resource limits (faster debugging)
- No security contexts (easier troubleshooting)
- No Pod Security Standards
- Public registry access

### Prod
- Resource limits enforced
- Security contexts (runAsNonRoot, readOnlyRootFilesystem)
- Pod Security Standards: restricted
- Private registry with authentication

## Testing

### Verify Deployment

```bash
# Check namespace
kubectl get ns governance-stack-dev

# Check MinIO
kubectl get pods -n governance-stack-dev
kubectl get svc minio -n governance-stack-dev

# Access MinIO console
kubectl port-forward svc/minio 9001:9001 -n governance-stack-dev
# Open: http://localhost:9001
```

### Get MinIO Credentials

```bash
kubectl get secret minio-credentials -n governance-stack-dev \
  -o jsonpath='{.data.access-key}' | base64 -d

kubectl get secret minio-credentials -n governance-stack-dev \
  -o jsonpath='{.data.secret-key}' | base64 -d
```

## Troubleshooting

### Backend Initialization Fails

```bash
# Ensure terraform-state namespace exists
kubectl create namespace terraform-state

# Re-initialize
terraform init -reconfigure \
  -backend-config="config_path=~/.kube/config"
```

### Storage Class Not Found

```bash
# List available storage classes
kubectl get storageclass

# Update dev.tfvars with correct storage_class value
```

### Module Not Found

```bash
# Ensure you're in the correct directory
cd infra/targets/agnostic

# Re-initialize to download modules
terraform init
```

## See Also

- [GCP-GKE Target](../gcp-gke/) - GCP-optimized deployment
- Migration Guide
- Security Postures
