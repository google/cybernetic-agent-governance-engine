# GCP GKE Cluster Module

Provisions a Google Kubernetes Engine (GKE) cluster with security posture toggles for dev/prod environments.

## Features

- **Dual Security Postures**: Toggle between fast dev iteration and NIST RMF compliance
- **GPU Support**: Optional GPU node pool for vLLM inference
- **Workload Identity**: Secure GCP service account binding
- **Network Isolation**: Private cluster configuration for production
- **Audit Logging**: Comprehensive logging when enabled
- **CMEK**: Customer-managed encryption keys for production
- **Binary Authorization**: Enforce signed images in production

## Security Feature Flags

The module uses boolean flags to toggle security controls:

| Flag | NIST Control | Dev | Prod | Description |
|------|--------------|-----|------|-------------|
| `enable_nist_compliance` | SC-7, AC-3 | `false` | `true` | Private cluster, authorized networks, deletion protection |
| `enable_binary_authorization` | CM-7, SI-7 | `false` | `true` | Only signed container images allowed |
| `enable_audit_logging` | AU-2, AU-3, AU-9 | `false` | `true` | Comprehensive logging to immutable storage |
| `enable_cmek` | SC-12, SC-13 | `false` | `true` | Customer-managed encryption keys |

## Usage

### Dev Environment (Fast Iteration)

```hcl
module "gke_dev" {
  source = "../../modules/gcp_gke_cluster"
  
  project_id   = "my-project"
  region       = "us-central1"
  zone         = "us-central1-a"
  cluster_name = "cage-dev"
  
  # Security: All disabled for fast iteration
  enable_nist_compliance      = false
  enable_binary_authorization = false
  enable_audit_logging        = false
  enable_cmek                 = false
  
  # Cost-optimized dev settings
  primary_node_pool_machine_type = "e2-medium"
  primary_node_pool_min_count    = 1
  primary_node_pool_max_count    = 3
  
  # GPUs: Cheaper T4 for testing
  gpu_type                   = "nvidia-t4"
  gpu_node_pool_machine_type = "n1-standard-4"
  gpu_node_pool_min_count    = 0  # Scale to zero when idle
}
```

### Production Environment (ISO 42001 Baseline + Jurisdictional Hardening)

> **Architecture Note:** `enable_nist_compliance=true` activates NIST SP 800-53 controls and is appropriate **only** for `CAGE_DEPLOYMENT_REGION=US_FED`. EU_ECB and APAC_MAS production deployments use `eu-prod.tfvars` and `apac-prod.tfvars` respectively, which set the correct regional compliance flags without activating NIST-specific hardening.
>
> | `CAGE_DEPLOYMENT_REGION` | Compliance Flags | Var-file |
> |--------------------------|-----------------|----------|
> | `US_FED` | `enable_nist_compliance=true` | `prod.tfvars` |
> | `EU_ECB` | `enable_eu_ecb_compliance=true` | `eu-prod.tfvars` |
> | `APAC_MAS` | `enable_apac_mas_compliance=true` | `apac-prod.tfvars` |

```hcl
# US_FED production deployment
module "gke_prod" {
  source = "../../modules/gcp_gke_cluster"
  
  project_id   = "my-project"
  region       = "us-central1"
  zone         = "us-central1-a"
  cluster_name = "cage-governance"
  
  # Security: All enabled for ISO 42001 baseline + NIST RMF (US_FED only)
  enable_nist_compliance         = true  # US_FED only — do NOT set for EU_ECB or APAC_MAS
  enable_binary_authorization    = true
  enable_audit_logging           = true
  enable_cmek                    = true
  enable_private_master_endpoint = true
  
  # Lock down to corporate VPN only
  authorized_networks = [
    {
      cidr         = "10.0.0.0/8"
      display_name = "Corporate VPN"
    }
  ]
  
  # KMS key for encryption
  kms_key_id = "projects/my-project/locations/us-central1/keyRings/cage-prod/cryptoKeys/gke-disk"
  
  # Production sizing
  primary_node_pool_machine_type  = "e2-standard-8"
  primary_node_pool_min_count     = 3
  primary_node_pool_max_count     = 10
  primary_node_pool_initial_count = 3
  
  # Production GPUs
  gpu_type                    = "nvidia-l4"
  gpu_node_pool_machine_type  = "g2-standard-8"
  gpu_node_pool_min_count     = 2
  gpu_node_pool_max_count     = 5
  gpu_node_pool_initial_count = 2
}
```

## Inputs

### Core Configuration

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| project_id | GCP project ID | string | - | yes |
| region | GCP region | string | - | yes |
| zone | GCP zone | string | - | yes |
| cluster_name | GKE cluster name | string | - | yes |
| environment | Environment (dev/prod) | string | "dev" | no |

### Security Toggles

| Name | Description | Type | Default |
|------|-------------|------|---------|
| enable_nist_compliance | Enable NIST RMF controls | bool | false |
| enable_binary_authorization | Enforce signed images | bool | false |
| enable_audit_logging | Comprehensive logging | bool | false |
| enable_cmek | Customer-managed encryption | bool | false |
| enable_private_master_endpoint | Private master endpoint | bool | false |

### Node Pool Configuration

| Name | Description | Type | Default |
|------|-------------|------|---------|
| primary_node_pool_machine_type | Primary pool machine type | string | "e2-standard-4" |
| primary_node_pool_min_count | Min primary nodes | number | 1 |
| primary_node_pool_max_count | Max primary nodes | number | 5 |
| enable_gpu_node_pool | Enable GPU node pool | bool | true |
| gpu_type | GPU type (nvidia-l4, nvidia-t4) | string | "nvidia-l4" |
| gpu_count | GPUs per node | number | 1 |
| gpu_node_pool_machine_type | GPU pool machine type | string | "g2-standard-4" |
| gpu_node_locations | List of zones for GPU node pool (regional sourcing) | list(string) | [] |


See [`variables.tf`](variables.tf) for complete list.

## Outputs

| Name | Description |
|------|-------------|
| cluster_name | GKE cluster name |
| cluster_endpoint | Cluster API endpoint (sensitive) |
| cluster_ca_certificate | Cluster CA certificate (sensitive) |
| workload_identity_pool | Workload Identity pool for IAM bindings |
| primary_node_pool_name | Primary node pool name |
| gpu_node_pool_name | GPU node pool name |

## NIST Control Mapping

| Flag | NIST Controls | Description |
|------|---------------|-------------|
| `enable_nist_compliance` | SC-7, AC-3 | Boundary protection, private cluster, authorized networks |
| `enable_binary_authorization` | CM-7, SI-7 | Least functionality, software integrity |
| `enable_audit_logging` | AU-2, AU-3, AU-9 | Audit events, content, protection |
| `enable_cmek` | SC-12, SC-13 | Cryptographic key management, protection |

## Examples

### Minimal Dev Cluster

```hcl
module "gke" {
  source = "../../modules/gcp_gke_cluster"
  
  project_id   = "my-project"
  region       = "us-central1"
  zone         = "us-central1-a"
  cluster_name = "test-cluster"
  
  # No GPU for testing
  enable_gpu_node_pool = false
}
```

### Gradual Security Hardening

Test one control at a time:

```hcl
# Step 1: Test binary authorization
module "gke" {
  source = "../../modules/gcp_gke_cluster"
  
  project_id   = "my-project"
  region       = "us-central1"
  zone         = "us-central1-a"
  cluster_name = "cage-staging"
  
  enable_binary_authorization = true  # Test first
  # Leave other controls disabled
}

# Step 2: Add audit logging
# enable_audit_logging = true

# Step 3: Enable full NIST compliance
# enable_nist_compliance = true
```

## Network Requirements

### Dev (Public Cluster)
- No VPN required
- Accessible from any IP
- Nodes have public IPs

### Prod (Private Cluster)
- Requires Cloud NAT for outbound traffic
- Requires VPN or Cloud Interconnect for kubectl access (if private master endpoint enabled)
- Nodes have only private IPs

## Dependencies

This module creates:
- `google_container_cluster.primary`
- `google_container_node_pool.primary_nodes`
- `google_container_node_pool.gpu_nodes` (if enabled)

It does NOT create:
- VPC networks (uses existing)
- Cloud NAT (create separately if using private nodes)
- IAM service accounts (create in target, not module)
- GCS buckets (create in target)

## See Also

- [Networking Module](../gcp_networking/) - Cloud Router & NAT (not implemented yet)
- [GCP IAM Resources](../../targets/gcp-gke/iam.tf) - Created in target, not module
- [Security Postures Guide](../../../plans/monorepo-security-postures.md)
