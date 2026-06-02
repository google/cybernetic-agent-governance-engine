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
  description = "Kubernetes namespace for MinIO deployment"
  type        = string
}

variable "release_name" {
  description = "Helm release name"
  type        = string
  default     = "minio"
}

variable "chart_version" {
  description = "MinIO Helm chart version"
  type        = string
  default     = "5.0.14"
}

variable "storage_class" {
  description = "Storage class for PVC (e.g., standard, pd-ssd, local-path for k3s)"
  type        = string
  default     = "standard"
}

variable "storage_size" {
  description = "PVC size"
  type        = string
  default     = "50Gi"
}

variable "root_user" {
  description = "MinIO root username"
  type        = string
  default     = "minio-admin"
}

variable "root_password" {
  description = "MinIO root password (auto-generated if empty)"
  type        = string
  sensitive   = true
  default     = ""
}

variable "mode" {
  description = "MinIO mode (standalone or distributed)"
  type        = string
  default     = "standalone"

  validation {
    condition     = contains(["standalone", "distributed"], var.mode)
    error_message = "Mode must be standalone or distributed."
  }
}

variable "replicas" {
  description = "Number of MinIO replicas (must be 4 for distributed mode)"
  type        = number
  default     = 1
}

variable "service_type" {
  description = "Kubernetes service type"
  type        = string
  default     = "ClusterIP"
}

variable "service_port" {
  description = "MinIO S3 API port"
  type        = number
  default     = 9000
}

variable "console_port" {
  description = "MinIO console port"
  type        = number
  default     = 9001
}

# ─── Resource Configuration ──────────────────────────────────────────────────

variable "resources_requests_memory" {
  description = "Memory request"
  type        = string
  default     = "512Mi"
}

variable "resources_requests_cpu" {
  description = "CPU request"
  type        = string
  default     = "250m"
}

variable "resources_limits_memory" {
  description = "Memory limit (empty = no limit for dev)"
  type        = string
  default     = ""
}

variable "resources_limits_cpu" {
  description = "CPU limit (empty = no limit for dev)"
  type        = string
  default     = ""
}

# ─── Security Configuration ──────────────────────────────────────────────────

variable "enable_security_context" {
  description = "Enable security context (runAsNonRoot, runAsUser=1000)"
  type        = bool
  default     = false
}
