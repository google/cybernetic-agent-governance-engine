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
  description = "Enable strict NIST RMF security controls (Private cluster, deletion protection, Master Authorized Networks)"
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

# ─── Primary Node Pool Configuration ─────────────────────────────────────────

variable "primary_node_pool_machine_type" {
  description = "Machine type for primary node pool"
  type        = string
  default     = "e2-standard-4"
}

variable "primary_node_pool_min_count" {
  description = "Minimum nodes in primary pool"
  type        = number
  default     = 1
}

variable "primary_node_pool_max_count" {
  description = "Maximum nodes in primary pool"
  type        = number
  default     = 5
}

variable "primary_node_pool_initial_count" {
  description = "Initial node count for primary pool"
  type        = number
  default     = 2
}

variable "primary_node_pool_disk_size" {
  description = "Disk size in GB for primary nodes"
  type        = number
  default     = 100
}

variable "primary_node_pool_disk_type" {
  description = "Disk type for primary nodes (pd-standard, pd-ssd, pd-balanced)"
  type        = string
  default     = "pd-standard"
}

variable "primary_node_pool_labels" {
  description = "Additional labels for primary node pool"
  type        = map(string)
  default     = {}
}

# ─── GPU Node Pool Configuration ─────────────────────────────────────────────

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
  description = "Machine type for GPU node pool"
  type        = string
  default     = "g2-standard-4"
}

variable "gpu_node_pool_min_count" {
  description = "Minimum GPU nodes"
  type        = number
  default     = 0
}

variable "gpu_node_pool_max_count" {
  description = "Maximum GPU nodes"
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
  description = "Use Spot VMs for the GPU node pool"
  type        = bool
  default     = true
}

variable "gpu_node_locations" {
  description = "List of zones to deploy the GPU node pool to. Enables multi-zonal/regional node configuration to source GPUs from other zones during Spot capacity shortages."
  type        = list(string)
  default     = ["us-central1-a", "us-central1-b", "us-central1-c"]
}

variable "master_ipv4_cidr_block" { default = "172.16.0.0/28" }
