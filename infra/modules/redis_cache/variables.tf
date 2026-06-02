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
  description = "Kubernetes namespace to deploy Redis"
  type        = string
}

variable "release_name" {
  description = "Helm release name"
  type        = string
  default     = "redis"
}

variable "chart_version" {
  description = "Redis Helm chart version"
  type        = string
  default     = "25.3.2"
}

variable "password" {
  description = "Redis password (leave empty to auto-generate)"
  type        = string
  default     = ""
  sensitive   = true
}

variable "enable_auth" {
  description = "Enable Redis authentication"
  type        = bool
  default     = true
}

variable "architecture" {
  description = "Redis architecture: standalone or replication"
  type        = string
  default     = "standalone"
  validation {
    condition     = contains(["standalone", "replication"], var.architecture)
    error_message = "Architecture must be 'standalone' or 'replication'"
  }
}

variable "replica_count" {
  description = "Number of Redis replicas (only for replication architecture)"
  type        = number
  default     = 3
}

variable "enable_sentinel" {
  description = "Enable Redis Sentinel for HA"
  type        = bool
  default     = false
}

variable "enable_persistence" {
  description = "Enable persistent storage"
  type        = bool
  default     = true
}

variable "storage_size" {
  description = "PVC storage size"
  type        = string
  default     = "10Gi"
}

variable "storage_class" {
  description = "Storage class for PVC"
  type        = string
  default     = ""
}

variable "resources_limits_memory" {
  description = "Memory limit for Redis pod"
  type        = string
  default     = ""
}

variable "resources_limits_cpu" {
  description = "CPU limit for Redis pod"
  type        = string
  default     = ""
}

variable "resources_requests_memory" {
  description = "Memory request for Redis pod"
  type        = string
  default     = "256Mi"
}

variable "resources_requests_cpu" {
  description = "CPU request for Redis pod"
  type        = string
  default     = "100m"
}

variable "use_redis_stack" {
  description = "Use Redis Stack Server (includes JSON, Search, etc.)"
  type        = bool
  default     = false
}

variable "create_credentials_secret" {
  description = "Create Kubernetes Secret with credentials"
  type        = bool
  default     = true
}

variable "credentials_secret_name" {
  description = "Name of the Kubernetes Secret for credentials"
  type        = string
  default     = "redis-credentials"
}

variable "maxmemory" {
  description = "Maxmemory limit for Redis"
  type        = string
  default     = "1024mb"
}

variable "maxmemory_policy" {
  description = "Eviction policy for Redis"
  type        = string
  default     = "noeviction"
}
