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

variable "namespace" {
  description = "Kubernetes namespace to deploy ClickHouse"
  type        = string
}

variable "chart_version" {
  description = "ClickHouse Helm chart version"
  type        = string
  # Pinned to 6.2.11 (ClickHouse 23.8.x LTS) — chart 9.x bundles
  # bitnami/clickhouse:25.7.x which does not exist on Docker Hub.
  default = "9.4.4"
}

variable "replicas" {
  description = "Number of ClickHouse replicas"
  type        = number
  default     = 1
}

variable "shards" {
  description = "Number of shards for distributed setup"
  type        = number
  default     = 1
}

variable "replicas_per_shard" {
  description = "Number of replicas per shard"
  type        = number
  default     = 1
}

variable "storage_class" {
  description = "Storage class for persistent volumes"
  type        = string
  default     = ""
}

variable "storage_size" {
  description = "Storage size for data"
  type        = string
  default     = "20Gi"
}

variable "enable_persistence" {
  description = "Enable persistent storage"
  type        = bool
  default     = true
}

variable "enable_pdb" {
  description = "Enable Pod Disruption Budget"
  type        = bool
  default     = false
}

variable "enable_nist_compliance" {
  description = "Enable NIST compliance features (network policies, etc.)"
  type        = bool
  default     = false
}

variable "enable_security_context" {
  description = "Enable security context"
  type        = bool
  default     = false
}

# Resource limits
variable "resources_requests_cpu" {
  description = "CPU request"
  type        = string
  default     = "100m"
}

variable "resources_requests_memory" {
  description = "Memory request"
  type        = string
  default     = "512Mi"
}

variable "resources_limits_cpu" {
  description = "CPU limit (empty string for no limit)"
  type        = string
  default     = ""
}

variable "resources_limits_memory" {
  description = "Memory limit (empty string for no limit)"
  type        = string
  default     = ""
}
