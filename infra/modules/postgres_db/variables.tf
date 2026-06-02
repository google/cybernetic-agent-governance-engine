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
  description = "Kubernetes namespace to deploy PostgreSQL"
  type        = string
}

variable "release_name" {
  description = "Helm release name"
  type        = string
  default     = "postgresql"
}

variable "chart_version" {
  description = "PostgreSQL Helm chart version"
  type        = string
  default     = "18.5.6"
}

variable "database_name" {
  description = "PostgreSQL database name"
  type        = string
  default     = "langfuse"
}

variable "database_user" {
  description = "PostgreSQL database user"
  type        = string
  default     = "langfuse"
}

variable "storage_size" {
  description = "PVC storage size"
  type        = string
  default     = "50Gi"
}

variable "storage_class" {
  description = "Storage class for PVC"
  type        = string
  default     = ""
}

variable "enable_persistence" {
  description = "Enable persistent storage"
  type        = bool
  default     = true
}

variable "enable_backup" {
  description = "Enable automated backups"
  type        = bool
  default     = false
}

variable "backup_schedule" {
  description = "Cron schedule for backups"
  type        = string
  default     = "0 2 * * *" # 2 AM daily
}

variable "resources_limits_memory" {
  description = "Memory limit for PostgreSQL pod"
  type        = string
  default     = ""
}

variable "resources_requests_cpu" {
  description = "CPU request"
  type        = string
  default     = "100m"
}

variable "resources_requests_memory" {
  description = "Memory request"
  type        = string
  default     = "256Mi"
}

variable "resources_limits_cpu" {
  description = "CPU limit for PostgreSQL pod"
  type        = string
  default     = ""
}

variable "credentials_secret_name" {
  description = "Name of the Kubernetes Secret to create with DB credentials"
  type        = string
  default     = "langfuse-db-credentials"
}
