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
  description = "Google Cloud project ID"
  type        = string
}

variable "environment" {
  description = "Deployment environment (dev, staging, prod)"
  type        = string
}

variable "region" {
  description = "Google Cloud region"
  type        = string
}

variable "instance_id" {
  description = "Memorystore instance ID (defaults to cage-valkey-<environment>)"
  type        = string
  default     = ""
}

variable "network_id" {
  description = "The consumer network ID (e.g. projects/<project>/global/networks/<name>) for PSC connection"
  type        = string
}

variable "shard_count" {
  description = "Number of shards (1 for CLUSTER_DISABLED)"
  type        = number
  default     = 1
}

variable "replica_count" {
  description = "Number of replica nodes per shard (0 for dev, 1 for staging gov, 1+ for prod)"
  type        = number
  default     = 0
}

variable "node_type" {
  description = "Machine type for individual nodes (SHARED_CORE_NANO, STANDARD_SMALL, HIGHMEM_MEDIUM, HIGHMEM_XLARGE)"
  type        = string
  default     = "SHARED_CORE_NANO"
}

variable "mode" {
  description = "Cluster mode: CLUSTER_DISABLED (single-shard, multi-key EVAL allowed) or CLUSTER"
  type        = string
  default     = "CLUSTER_DISABLED"
}

variable "authorization_mode" {
  description = "Authorization mode: IAM_AUTH or AUTH_DISABLED"
  type        = string
  default     = "IAM_AUTH"
}

variable "transit_encryption_mode" {
  description = "Transit encryption mode: SERVER_AUTHENTICATION or TRANSIT_ENCRYPTION_DISABLED"
  type        = string
  default     = "SERVER_AUTHENTICATION"
}

variable "enable_cmek" {
  description = "Enable Customer-Managed Encryption Key (CMEK)"
  type        = bool
  default     = false
}

variable "kms_key_id" {
  description = "KMS crypto key ID for CMEK encryption"
  type        = string
  default     = null
}

variable "deletion_protection_enabled" {
  description = "Whether deletion protection is enabled"
  type        = bool
  default     = false
}
