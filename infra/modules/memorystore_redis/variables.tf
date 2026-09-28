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

variable "name" {
  description = "Instance name (defaults to cage-redis-<environment>)"
  type        = string
  default     = ""
}

variable "memory_size_gb" {
  description = "Redis instance memory size in GiB"
  type        = number
  default     = 1
}

variable "redis_tier" {
  description = "Service tier: BASIC or STANDARD_HA"
  type        = string
  default     = "BASIC"
}

variable "authorized_network" {
  description = "VPC network ID for PSA peering"
  type        = string
}

variable "replica_count" {
  description = "Number of read replicas"
  type        = number
  default     = 0
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

variable "enable_auth" {
  description = "Enable Redis AUTH string authentication"
  type        = bool
  default     = true
}

variable "enable_transit_encryption" {
  description = "Enable TLS in-transit encryption"
  type        = bool
  default     = true
}

variable "persistence_mode" {
  description = "Persistence mode: DISABLED or RDB"
  type        = string
  default     = "RDB"
}

variable "rdb_snapshot_period" {
  description = "Period between RDB snapshots: ONE_HOUR, SIX_HOURS, TWELVE_HOURS, TWENTY_FOUR_HOURS"
  type        = string
  default     = "ONE_HOUR"
}
