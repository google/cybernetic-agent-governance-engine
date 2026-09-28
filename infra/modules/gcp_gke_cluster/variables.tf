# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "region" {
  description = "GCP region"
  type        = string
}

variable "zone" {
  description = "GCP zone for zonal cluster"
  type        = string
}

variable "cluster_name" {
  description = "GKE cluster name"
  type        = string
}

# ─── Security Posture Toggles ────────────────────────────────────────────────

variable "enable_nist_compliance" {
  description = "Enable strict NIST RMF security controls (Private cluster, Master Authorized Networks)"
  type        = bool
  default     = false
}

# POAM-024: Decoupled from enable_nist_compliance to allow ephemeral staging clusters.
# Staging needs full security validation (enable_nist_compliance=true) but must be
# teardown-capable (enable_deletion_protection=false) to cap spend.
variable "enable_deletion_protection" {
  description = "Enable deletion protection on the GKE cluster. Set false for ephemeral environments (staging) that need terraform destroy capability. Set true for production to prevent accidental cluster deletion."
  type        = bool
  default     = false
}

variable "enable_binary_authorization" {
  description = "Enable Binary Authorization (only signed images allowed) - CM-7, SI-7"
  type        = bool
  default     = false
}

variable "enable_audit_logging" {
  description = "Enable comprehensive audit logging to immutable GCS bucket - AU-2, AU-3, AU-9"
  type        = bool
  default     = false
}

variable "enable_cmek" {
  description = "Enable Customer-Managed Encryption Keys for cluster data - SC-12, SC-13"
  type        = bool
  default     = false
}

variable "enable_private_master_endpoint" {
  description = "Make master endpoint private (requires Cloud VPN/Interconnect) - SC-7"
  type        = bool
  default     = false
}

variable "enable_private_nodes" {
  description = "Enable private nodes (no external IPs on node VMs). Required when org policy constraints/compute.vmExternalIpAccess is enforced. Nodes use Cloud NAT for egress. Independent of enable_nist_compliance."
  type        = bool
  default     = false
}

variable "regional_cluster" {
  description = "When true, provisions a regional GKE cluster (location = var.region). Defaults to true when environment == 'prod', false (zonal) in dev and staging (§1.1)."
  type        = bool
  default     = null
}

variable "enable_dataplane_v2" {
  description = <<-EOT
    Enable GKE Dataplane V2 (Cilium/eBPF via anetd). Required for GKE FQDNNetworkPolicy
    enforcement (§1.1, §5.3). When true, the legacy Calico network_policy addon is removed
    (they are mutually exclusive). Enabled at cluster creation in every posture (dev, staging, prod).
  EOT
  type        = bool
  default     = true
}

variable "enable_fqdn_network_policy" {
  description = <<-EOT
    Enable GKE FQDNNetworkPolicy (networking.gke.io/v1alpha1) enforcement at cluster creation
    alongside Dataplane V2 (§5.3, §7). Requires Dataplane V2, GKE >= 1.27.1-gke.400, and
    kube-dns or Cloud DNS (custom CoreDNS is unsupported).
  EOT
  type        = bool
  default     = true
}

variable "release_channel" {
  description = "GKE release channel (REGULAR, STABLE, RAPID) to guarantee control-plane version >= 1.27.1-gke.400 for FQDNNetworkPolicy (§5.3)."
  type        = string
  default     = "REGULAR"

  validation {
    condition     = contains(["RAPID", "REGULAR", "STABLE"], var.release_channel)
    error_message = "release_channel must be RAPID, REGULAR, or STABLE."
  }
}

variable "min_master_version" {
  description = "Minimum GKE control-plane version (>= 1.27.1-gke.400 required for FQDNNetworkPolicy — §5.3)."
  type        = string
  default     = "1.28"
}

variable "cluster_dns_provider" {
  description = "Cluster DNS provider. FQDNNetworkPolicy requires kube-dns (PROVIDER_UNSPECIFIED) or CLOUD_DNS; custom CoreDNS is forbidden (§5.3, §7)."
  type        = string
  default     = "PROVIDER_UNSPECIFIED"

  validation {
    condition     = contains(["PROVIDER_UNSPECIFIED", "CLOUD_DNS"], var.cluster_dns_provider)
    error_message = "cluster_dns_provider must be PROVIDER_UNSPECIFIED (kube-dns) or CLOUD_DNS. Custom CoreDNS is unsupported by GKE FQDNNetworkPolicy (§5.3, §7)."
  }
}

# ─── Network Configuration ───────────────────────────────────────────────────

variable "network" {
  description = "VPC network name"
  type        = string
  default     = "default"
}

variable "subnetwork" {
  description = "VPC subnetwork name"
  type        = string
  default     = "default"
}

variable "pod_cidr" {
  description = "CIDR block for pods"
  type        = string
  default     = "10.100.0.0/14"
}

variable "service_cidr" {
  description = "CIDR block for services"
  type        = string
  default     = "10.104.0.0/20"
}

variable "authorized_networks" {
  description = "Master authorized networks (for NIST compliance mode)"
  type = list(object({
    cidr         = string
    display_name = string
  }))
  default = []
}

# ─── Security & Compliance ───────────────────────────────────────────────────

variable "kms_key_id" {
  description = "Cloud KMS key ID for CMEK encryption (required if enable_cmek=true)"
  type        = string
  default     = ""
}

variable "enable_gcs_fuse_csi" {
  description = "Enable GCS Fuse CSI driver for GCS bucket mounting"
  type        = bool
  default     = true
}

variable "enable_vertical_pod_autoscaling" {
  description = "Enable Vertical Pod Autoscaling"
  type        = bool
  default     = true
}

# ─── Environment & Labels ────────────────────────────────────────────────────

variable "environment" {
  description = "Environment (dev, staging, prod)"
  type        = string
  default     = "dev"
}

variable "cluster_labels" {
  description = "Additional labels to apply to the cluster"
  type        = map(string)
  default     = {}
}

variable "maintenance_start_time" {
  description = "Maintenance window start time (HH:MM format)"
  type        = string
  default     = "03:00"
}

# ─── General Node Pool Configuration (§3: general) ───────────────────────────

variable "primary_node_pool_machine_type" {
  description = "Machine type for general (primary) node pool: e2-standard-4 (dev/staging), e2-standard-8 (prod)"
  type        = string
  default     = "e2-standard-4"
}

variable "primary_node_pool_min_count" {
  description = "Minimum nodes in general (primary) pool"
  type        = number
  default     = 1
}

variable "primary_node_pool_max_count" {
  description = "Maximum nodes in general (primary) pool"
  type        = number
  default     = 5
}

variable "primary_node_pool_initial_count" {
  description = "Initial node count for general (primary) pool"
  type        = number
  default     = 2
}

variable "primary_node_pool_disk_size" {
  description = "Disk size in GB for general (primary) nodes"
  type        = number
  default     = 100
}

variable "primary_node_pool_disk_type" {
  description = "Disk type for general (primary) nodes (pd-standard, pd-ssd, pd-balanced)"
  type        = string
  default     = "pd-standard"
}

variable "primary_node_pool_labels" {
  description = "Additional labels for general (primary) node pool"
  type        = map(string)
  default     = {}
}

# ─── General-Spot Node Pool Configuration (§3: general-spot) ─────────────────

variable "enable_general_spot_node_pool" {
  description = "Enable general-spot node pool (c3-highcpu-4, Spot, 0-5 in staging only; tainted cloud.google.com/gke-spot=true:NoSchedule — §3)"
  type        = bool
  default     = null
}

variable "general_spot_machine_type" {
  description = "Machine type for general-spot node pool (§3)"
  type        = string
  default     = "c3-highcpu-4"
}

variable "general_spot_min_count" {
  description = "Minimum nodes in general-spot pool (§3: 0 in staging)"
  type        = number
  default     = 0
}

variable "general_spot_max_count" {
  description = "Maximum nodes in general-spot pool (§3: 5 in staging)"
  type        = number
  default     = 5
}

variable "general_spot_initial_count" {
  description = "Initial node count for general-spot pool"
  type        = number
  default     = 0
}

# ─── GPU Node Pool Configuration (§3: gpu-l4) ────────────────────────────────

variable "enable_gpu_node_pool" {
  description = "Enable GPU node pool for vLLM inference"
  type        = bool
  default     = true
}

variable "gpu_type" {
  description = "GPU accelerator type (nvidia-l4, nvidia-t4, nvidia-a100-80gb)"
  type        = string
  default     = "nvidia-l4"
}

variable "gpu_count" {
  description = "Number of GPUs per node"
  type        = number
  default     = 1
}

variable "gpu_node_pool_machine_type" {
  description = "Machine type for GPU node pool (g2-standard-8, 1x L4 — §3)"
  type        = string
  default     = "g2-standard-8"
}

variable "gpu_node_pool_min_count" {
  description = "Minimum GPU nodes (0 in dev/staging, 2 in prod — §3)"
  type        = number
  default     = 0
}

variable "gpu_node_pool_max_count" {
  description = "Maximum GPU nodes (2 in dev/staging, 5 in prod — §3)"
  type        = number
  default     = 2
}

variable "gpu_node_pool_initial_count" {
  description = "Initial GPU node count"
  type        = number
  default     = 1
}

variable "gpu_node_pool_disk_size" {
  description = "Disk size in GB for GPU nodes (larger for model weights)"
  type        = number
  default     = 200
}

variable "gpu_node_pool_disk_type" {
  description = "Disk type for GPU nodes (pd-balanced recommended for GPUs)"
  type        = string
  default     = "pd-balanced"
}

variable "gpu_node_pool_labels" {
  description = "Additional labels for GPU node pool"
  type        = map(string)
  default     = {}
}

variable "gpu_node_pool_spot" {
  description = "GPU Spot must remain false in every posture (§3, §7): measurement and governance runs must not be preempted."
  type        = bool
  default     = false

  validation {
    condition     = var.gpu_node_pool_spot == false
    error_message = "GPU Spot must stay false in every posture (§3, §7): measurement runs must not be preempted."
  }
}

variable "gpu_node_locations" {
  description = "List of zones to deploy the GPU node pool to. Enables multi-zonal/regional node configuration."
  type        = list(string)
  default     = ["us-central1-a", "us-central1-b", "us-central1-c"]
}

variable "master_ipv4_cidr_block" { default = "172.16.0.0/28" }

# ─── ClickHouse Node Pool Configuration (§3, §7: clickhouse) ─────────────────

variable "enable_clickhouse_node_pool" {
  description = "Enable dedicated ClickHouse node pool with local SSD and workload=clickhouse:NoSchedule taint (§3, §7)"
  type        = bool
  default     = true
}

variable "clickhouse_node_pool_machine_type" {
  description = "Machine type for ClickHouse node pool (local-SSD machine type)"
  type        = string
  default     = "n2-standard-4"
}

variable "clickhouse_node_pool_min_count" {
  description = "Minimum nodes in ClickHouse pool (1 in dev/staging, 3 in prod — §3)"
  type        = number
  default     = null
}

variable "clickhouse_node_pool_max_count" {
  description = "Maximum nodes in ClickHouse pool (1 in dev/staging, 3 in prod — §3)"
  type        = number
  default     = null
}

variable "clickhouse_node_pool_initial_count" {
  description = "Initial node count for ClickHouse pool (1 in dev/staging, 3 in prod — §3)"
  type        = number
  default     = null
}

variable "clickhouse_node_pool_local_ssd_count" {
  description = "Number of raw-block local NVMe SSDs attached to each ClickHouse node for hot-tier storage"
  type        = number
  default     = 1
}

# ─── Node Pool List Specification (§3) ───────────────────────────────────────

variable "node_pools" {
  description = "Optional list of additional node pool specifications (§3)"
  type = list(object({
    name              = string
    machine_type      = string
    min_count         = number
    max_count         = number
    initial_count     = optional(number, 1)
    disk_size_gb      = optional(number, 100)
    disk_type         = optional(string, "pd-standard")
    spot              = optional(bool, false)
    local_ssd_count   = optional(number, 0)
    labels            = optional(map(string), {})
    taints = optional(list(object({
      key    = string
      value  = string
      effect = string
    })), [])
  }))
  default = []
}


