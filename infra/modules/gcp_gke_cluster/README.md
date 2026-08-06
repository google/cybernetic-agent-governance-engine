# GCP GKE Cluster Module

Provisions a Google Kubernetes Engine (GKE) cluster with security posture toggles for dev/prod environments and multi-jurisdictional compliance support.

## Features

- **Dual security postures:** Toggle between fast dev iteration and full compliance hardening
- **Jurisdictional compliance:** `US_FED` (NIST SP 800-53), `EU_ECB` (GDPR/EU AI Act/DORA), `APAC_MAS` (MAS FEAT/Notice 655/TRM)
- **GPU support:** Optional GPU node pool (Spot VMs by default) for vLLM inference
- **Workload Identity:** Secure GCP service account binding (ISO 42001 A.8.4)
- **Shielded Nodes:** Secure boot + integrity monitoring
- **Network isolation:** Private cluster configuration for production
- **Audit logging:** Comprehensive logging when enabled (AU-2, AU-3, AU-9)
- **CMEK:** Customer-managed encryption keys (SC-12, SC-13)
- **Binary Authorization:** Enforce signed images (CM-7, SI-7)
- **Vertical Pod Autoscaling:** Enabled by default
- **GCS Fuse CSI driver:** Enabled by default (model weight streaming from GCS)

---

## Security Feature Flags

| Flag | Scope | NIST Control | Dev | Prod | Description |
|------|-------|--------------|-----|------|-------------|
| `enable_nist_compliance` | US_FED only | SC-7, AC-3 | `false` | `true` | Private cluster, master authorized networks, deletion protection |
| `enable_binary_authorization` | Universal (ISO 42001 A.5.2) | CM-7, SI-7 | `false` | `true` | Only signed container images allowed |
| `enable_audit_logging` | Universal (ISO 42001 A.5.3) | AU-2, AU-3, AU-9 | `false` | `true` | Comprehensive logging to Cloud Logging |
| `enable_cmek` | Universal (ISO 42001 A.9.2) | SC-12, SC-13 | `false` | `true` | Customer-managed KMS encryption |
| `enable_private_nodes` | Optional | SC-7 | `false` | `false` | Private node IPs; requires Cloud NAT |
| `enable_private_master_endpoint` | Optional | SC-7 | `false` | `false` | Private master endpoint; requires VPN |

> **Important:** `enable_nist_compliance=true` is appropriate **only** for `CAGE_DEPLOYMENT_REGION=US_FED`. EU_ECB and APAC_MAS production deployments use `eu-prod.tfvars` and `apac-prod.tfvars` respectively, which set region-specific flags without activating NIST-specific hardening. ISO 42001 baseline controls are always active in all prod deployments.

---

## Usage

### Dev environment (fast iteration)

```hcl
module "gke_dev" {
  source = "../../modules/gcp_gke_cluster"

  project_id   = "my-project"
  region       = "us-central1"
  zone         = "us-central1-a"
  cluster_name = "cage-dev"
  environment  = "dev"

  # Security: all disabled for fast iteration
  enable_nist_compliance      = false
  enable_binary_authorization = false
  enable_audit_logging        = false
  enable_cmek                 = false

  # Cost-optimized dev settings
  primary_node_pool_machine_type = "e2-standard-4"
  primary_node_pool_min_count    = 1
  primary_node_pool_max_count    = 3

  # GPU: T4 for dev testing; scale to zero when idle
  gpu_type                   = "nvidia-l4"
  gpu_node_pool_machine_type = "g2-standard-4"
  gpu_node_pool_min_count    = 0
  gpu_node_pool_spot         = true
}
```

### US_FED production (ISO 42001 + NIST SP 800-53)

```hcl
module "gke_prod" {
  source = "../../modules/gcp_gke_cluster"

  project_id   = "my-project"
  region       = "us-central1"
  zone         = "us-central1-a"
  cluster_name = "cage-governance"
  environment  = "prod"

  # ISO 42001 baseline + NIST SP 800-53 (US_FED only)
  enable_nist_compliance         = true   # US_FED only — private cluster + deletion protection
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

  # KMS key for CMEK (must be in us-central1 for US_FED)
  kms_key_id = "projects/my-project/locations/us-central1/keyRings/cage-prod/cryptoKeys/gke-disk"

  # Production sizing
  primary_node_pool_machine_type  = "e2-standard-8"
  primary_node_pool_min_count     = 3
  primary_node_pool_max_count     = 10
  primary_node_pool_initial_count = 3

  # Production GPUs (nvidia-l4 on g2 instances)
  gpu_type                    = "nvidia-l4"
  gpu_node_pool_machine_type  = "g2-standard-8"
  gpu_node_pool_min_count     = 2
  gpu_node_pool_max_count     = 5
  gpu_node_pool_initial_count = 2
  gpu_node_pool_spot          = true
  gpu_node_locations          = ["us-central1-a", "us-central1-b", "us-central1-c"]
}
```

### EU_ECB production (ISO 42001 + EU AI Act / GDPR / DORA)

Use `infra/targets/gcp-gke/eu-prod.tfvars`:

```hcl
# cage_deployment_region = "EU_ECB"
# region                 = "europe-west1"
# zone                   = "europe-west1-b"
# enable_nist_compliance = false   # NIST hardening is US_FED only
# enable_audit_logging   = true    # Required by DORA Art. 10
# enable_cmek            = true    # GDPR Art. 32 — key in europe-west1
```

### APAC_MAS production (ISO 42001 + MAS FEAT / Notice 655 / TRM)

Use `infra/targets/gcp-gke/apac-prod.tfvars`:

```hcl
# cage_deployment_region = "APAC_MAS"
# region                 = "asia-southeast1"
# zone                   = "asia-southeast1-a"
# enable_nist_compliance = false   # NIST hardening is US_FED only
# enable_audit_logging   = true    # Required by MAS Notice 655
# enable_cmek            = true    # MAS TRM §9.1 — key in asia-southeast1
```

---

## Inputs

### Core configuration

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| `project_id` | GCP project ID | string | — | yes |
| `region` | GCP region | string | — | yes |
| `zone` | GCP zone | string | — | yes |
| `cluster_name` | GKE cluster name | string | — | yes |
| `environment` | Environment (dev/prod) | string | `"dev"` | no |

### Security toggles

| Name | Description | Type | Default |
|------|-------------|------|---------|
| `enable_nist_compliance` | Private cluster + deletion protection (US_FED only) | bool | `false` |
| `enable_binary_authorization` | Enforce signed images (ISO 42001 A.5.2) | bool | `false` |
| `enable_audit_logging` | Comprehensive Cloud Logging (ISO 42001 A.5.3) | bool | `false` |
| `enable_cmek` | Customer-managed KMS encryption (ISO 42001 A.9.2) | bool | `false` |
| `enable_private_master_endpoint` | Private master endpoint (SC-7) | bool | `false` |
| `enable_private_nodes` | Private node IPs; independent of `enable_nist_compliance` | bool | `false` |

### Network configuration

| Name | Description | Type | Default |
|------|-------------|------|---------|
| `network` | VPC network name | string | `"default"` |
| `subnetwork` | VPC subnetwork name | string | `"default"` |
| `pod_cidr` | CIDR block for pods | string | `"10.100.0.0/14"` |
| `service_cidr` | CIDR block for services | string | `"10.104.0.0/20"` |
| `authorized_networks` | Master authorized networks (list of `{cidr, display_name}`) | list(object) | `[]` |
| `master_ipv4_cidr_block` | Master CIDR block (private cluster) | string | `"172.16.0.0/28"` |

### Primary node pool

| Name | Description | Type | Default |
|------|-------------|------|---------|
| `primary_node_pool_machine_type` | Machine type | string | `"e2-standard-4"` |
| `primary_node_pool_min_count` | Minimum nodes | number | `1` |
| `primary_node_pool_max_count` | Maximum nodes | number | `5` |
| `primary_node_pool_initial_count` | Initial node count | number | `2` |
| `primary_node_pool_disk_size` | Disk size in GB | number | `100` |
| `primary_node_pool_disk_type` | Disk type | string | `"pd-standard"` |

### GPU node pool

| Name | Description | Type | Default |
|------|-------------|------|---------|
| `enable_gpu_node_pool` | Enable GPU node pool | bool | `true` |
| `gpu_type` | GPU type (`nvidia-l4`, `nvidia-t4`, `nvidia-a100-80gb`) | string | `"nvidia-l4"` |
| `gpu_count` | GPUs per node | number | `1` |
| `gpu_node_pool_machine_type` | GPU pool machine type | string | `"g2-standard-4"` |
| `gpu_node_pool_min_count` | Minimum GPU nodes | number | `0` |
| `gpu_node_pool_max_count` | Maximum GPU nodes | number | `2` |
| `gpu_node_pool_initial_count` | Initial GPU node count | number | `1` |
| `gpu_node_pool_disk_size` | Disk size in GB for GPU nodes | number | `200` |
| `gpu_node_pool_disk_type` | Disk type for GPU nodes | string | `"pd-balanced"` |
| `gpu_node_pool_spot` | Use Spot VMs for GPU pool | bool | `true` |
| `gpu_node_locations` | Zones for GPU node pool (multi-zonal sourcing) | list(string) | `["us-central1-a","us-central1-b","us-central1-c"]` |

### Additional options

| Name | Description | Type | Default |
|------|-------------|------|---------|
| `kms_key_id` | Cloud KMS key for CMEK (required if `enable_cmek=true`) | string | `""` |
| `enable_gcs_fuse_csi` | Enable GCS Fuse CSI driver | bool | `true` |
| `enable_vertical_pod_autoscaling` | Enable VPA | bool | `true` |
| `maintenance_start_time` | Maintenance window start (HH:MM) | string | `"03:00"` |

See [`variables.tf`](variables.tf) for the complete list.

---

## Outputs

| Name | Description |
|------|-------------|
| `cluster_name` | GKE cluster name |
| `cluster_endpoint` | Cluster API endpoint (sensitive) |
| `cluster_ca_certificate` | Cluster CA certificate (sensitive) |
| `workload_identity_pool` | Workload Identity pool for IAM bindings |
| `primary_node_pool_name` | Primary node pool name |
| `gpu_node_pool_name` | GPU node pool name |

---

## Resources Created

This module creates:

- `google_container_cluster.primary`
- `google_container_node_pool.primary_nodes`
- `google_container_node_pool.gpu_nodes` (if `enable_gpu_node_pool=true`)

This module does **not** create:

- VPC networks (uses existing; default: `default` network)
- Cloud NAT (create separately if using private nodes)
- IAM service accounts (created in `infra/targets/gcp-gke/iam.tf`)
- GCS buckets (created in target)
- KMS keys (must pre-exist if `enable_cmek=true`)

---

## Network Requirements

### Dev (public cluster)

- No VPN required
- Accessible from any IP (no master authorized networks)
- Nodes can have public IPs

### Prod US_FED (private cluster)

- Requires Cloud NAT for outbound traffic from nodes (no public IPs)
- Requires VPN or Cloud Interconnect for `kubectl` access if `enable_private_master_endpoint=true`
- `authorized_networks` restricts master endpoint to specified CIDRs

---

## Examples

### Minimal dev cluster (no GPU)

```hcl
module "gke" {
  source = "../../modules/gcp_gke_cluster"

  project_id   = "my-project"
  region       = "us-central1"
  zone         = "us-central1-a"
  cluster_name = "test-cluster"

  enable_gpu_node_pool = false
}
```

### Gradual security hardening

Test one control at a time before enabling full compliance:

```bash
# Step 1: Binary authorization (ISO 42001 A.5.2)
terraform apply -var-file=dev.tfvars \
  -var="enable_binary_authorization=true"

# Step 2: Add audit logging (ISO 42001 A.5.3)
terraform apply -var-file=dev.tfvars \
  -var="enable_binary_authorization=true" \
  -var="enable_audit_logging=true"

# Step 3: Full US_FED NIST compliance
terraform apply -var-file=prod.tfvars
# (prod.tfvars sets cage_deployment_region=US_FED + all NIST flags)
```

---

## NIST Control Mapping

See [`NIST_CONTROLS.md`](NIST_CONTROLS.md) for the full jurisdictional control breakdown (ISO 42001 universal controls + US_FED, EU_ECB, and APAC_MAS regional additions).

---

## See Also

- [`NIST_CONTROLS.md`](NIST_CONTROLS.md) — full compliance control matrix
- [`infra/targets/gcp-gke/iam.tf`](../../targets/gcp-gke/iam.tf) — IAM service accounts and Workload Identity
- [`infra/targets/gcp-gke/README.md`](../../targets/gcp-gke/README.md) — GCP-GKE target documentation
- [`docs/compliance/cross-region/JURISDICTIONAL_SEPARATION_ANALYSIS.md`](../../../docs/compliance/cross-region/JURISDICTIONAL_SEPARATION_ANALYSIS.md) — jurisdictional separation rationale
