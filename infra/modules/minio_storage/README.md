# MinIO Storage Module

Deploys MinIO S3-compatible object storage via Helm chart. Cloud-agnostic and works on any Kubernetes cluster.

## Features

- S3-compatible API for model weight storage
- Persistent volume for data durability
- Standalone or distributed mode
- Automatic credential generation
- Security context toggles for prod environments

## Usage

### Dev Environment (Minimal Resources)

```hcl
module "minio" {
  source = "../../modules/minio_storage"
  
  namespace     = "governance-stack-dev"
  storage_class = "local-path"  # k3s default
  storage_size  = "10Gi"
  
  # No resource limits for faster debugging
  # No security context
}
```

### Production Environment (With Limits)

```hcl
module "minio" {
  source = "../../modules/minio_storage"
  
  namespace     = "governance-stack"
  storage_class = "pd-ssd"  # GKE: Use SSD
  storage_size  = "500Gi"
  
  # Resource limits
  resources_limits_memory = "4Gi"
  resources_limits_cpu    = "2000m"
  
  # Security context
  enable_security_context = true
}
```

### GCP with SSD Storage

```hcl
module "minio" {
  source = "../../modules/minio_storage"
  
  namespace     = "governance-stack"
  storage_class = "pd-ssd"  # GCP SSD persistent disk
  storage_size  = "100Gi"
  root_user     = "admin"
  root_password = var.minio_password  # From tfvars
}
```

### AWS EKS

```hcl
module "minio" {
  source = "../../modules/minio_storage"
  
  namespace     = "governance-stack"
  storage_class = "gp3"  # AWS EBS gp3
  storage_size  = "100Gi"
}
```

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| namespace | Kubernetes namespace | string | - | yes |
| storage_class | Storage class (local-path, pd-ssd, gp3) | string | "standard" | no |
| storage_size | PVC size | string | "50Gi" | no |
| root_user | MinIO root username | string | "minio-admin" | no |
| root_password | MinIO root password (auto-generated if empty) | string | "" | no |
| mode | MinIO mode (standalone or distributed) | string | "standalone" | no |
| replicas | Number of replicas (4 for distributed) | number | 1 | no |
| enable_security_context | Enable security context | bool | false | no |
| resources_limits_memory | Memory limit (empty for dev) | string | "" | no |
| resources_limits_cpu | CPU limit (empty for dev) | string | "" | no |

## Outputs

| Name | Description |
|------|-------------|
| endpoint | MinIO S3 API endpoint |
| console_endpoint | MinIO web console endpoint |
| credentials_secret_name | K8s secret with access/secret keys |
| access_key | MinIO access key |
| secret_key | MinIO secret key (sensitive) |

## Storage Class by Platform

| Platform | Storage Class | Notes |
|----------|---------------|-------|
| k3s | `local-path` | Default k3s storage class |
| GKE | `pd-standard` | Cheaper for dev |
| GKE | `pd-ssd` | Faster for prod |
| EKS | `gp2` | Default AWS EBS |
| EKS | `gp3` | Newer, better performance |
| AKS | `default` | Azure managed disk |
| AKS | `managed-premium` | Premium SSD |

## Accessing MinIO

### From within cluster

```bash
# S3 API endpoint
http://minio.governance-stack.svc.cluster.local:9000

# Web console (port-forward for local access)
kubectl port-forward svc/minio 9001:9001 -n governance-stack
# Open: http://localhost:9001
```

### Using mc (MinIO Client)

```bash
# Get credentials
kubectl get secret minio-credentials -n governance-stack \
  -o jsonpath='{.data.access-key}' | base64 -d
kubectl get secret minio-credentials -n governance-stack \
  -o jsonpath='{.data.secret-key}' | base64 -d

# Configure mc
mc alias set myminio \
  http://localhost:9000 \
  <access-key> \
  <secret-key>

# Create bucket
mc mb myminio/vllm-models

# Upload model weights
mc cp model.safetensors myminio/vllm-models/
```

## Examples

### Dev: No Limits, Fast Storage

```hcl
module "minio_dev" {
  source = "../../modules/minio_storage"
  
  namespace     = "dev"
  storage_class = "local-path"
  storage_size  = "5Gi"
  
  # Minimal resources for laptop testing
  resources_requests_memory = "256Mi"
  resources_requests_cpu    = "100m"
}
```

### Prod: With Limits and Security

```hcl
module "minio_prod" {
  source = "../../modules/minio_storage"
  
  namespace     = "prod"
  storage_class = "pd-ssd"
  storage_size  = "1Ti"
  
  # Production resources
  resources_requests_memory = "2Gi"
  resources_requests_cpu    = "1000m"
  resources_limits_memory   = "4Gi"
  resources_limits_cpu      = "2000m"
  
  # Security context
  enable_security_context = true
}
```

## See Also

- [vLLM Inference Module](../vllm_inference/) - Consumes MinIO for model weights
- [Kubernetes Namespace Module](../k8s_namespace/) - Create namespace first
