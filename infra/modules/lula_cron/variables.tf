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
  description = "Kubernetes namespace in which the Lula CronJob and ConfigMap run."
  type        = string
}

variable "image" {
  description = "Container image for the Lula auditor CronJob (must not use :latest)."
  type        = string

  validation {
    condition     = trimspace(var.image) != "" && !can(regex(":latest(@|$)", var.image))
    error_message = "lula_cron image must be non-empty and must not use the mutable :latest tag."
  }
}

variable "service_account_name" {
  description = "Dedicated Kubernetes ServiceAccount for the Lula auditor (never empty or default)."
  type        = string

  validation {
    condition = (
      trimspace(var.service_account_name) != "" &&
      var.service_account_name != "default" &&
      var.service_account_name != "financial-advisor-sa"
    )
    error_message = "service_account_name must name a dedicated Lula KSA (financial-advisor-sa is retired)."
  }
}

variable "schedule" {
  description = "Cron schedule expression for periodic in-cluster Lula compliance validation."
  type        = string
  default     = "*/15 * * * *"
}

variable "lula_manifests_dir" {
  description = "Filesystem directory containing compliance/lula/lula-validation-*.yaml manifests."
  type        = string
}

variable "compliance_bridge_events_url" {
  description = "Internal compliance-bridge /v1/infra/events URL (defaults to port 8085 in var.namespace)."
  type        = string
  default     = ""
}

variable "network_policy_hash" {
  description = "Optional SHA-256 digest of active NetworkPolicy specifications for pod template metadata."
  type        = string
  default     = ""
}

variable "cpu_request" {
  description = "CPU request for the lula-audit container."
  type        = string
  default     = "100m"
}

variable "memory_request" {
  description = "Memory request for the lula-audit container."
  type        = string
  default     = "128Mi"
}

variable "cpu_limit" {
  description = "CPU limit for the lula-audit container."
  type        = string
  default     = "500m"
}

variable "memory_limit" {
  description = "Memory limit for the lula-audit container."
  type        = string
  default     = "512Mi"
}
