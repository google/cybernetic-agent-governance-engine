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
  description = "Kubernetes namespace for the deterministic inference stub."
  type        = string
}

variable "image" {
  description = "inference-stub image built from src/integrations/inference_stub/Dockerfile (Wolfi, non-root UID 1000), pinned by @sha256: digest."
  type        = string
}

variable "environment" {
  description = "Deployment environment (dev, development, test, staging). Refused in prod/production via Deployment precondition (POAM-2026-180, POAM-2026-191)."
  type        = string
}

variable "service_account_name" {
  description = "Dedicated zero-cloud-identity Kubernetes ServiceAccount for the inference stub (POAM-2026-079)."
  type        = string

  validation {
    condition     = var.service_account_name != "" && var.service_account_name != "financial-advisor-sa"
    error_message = "service_account_name must name the workload's own KSA; the shared financial-advisor-sa is retired (POAM-2026-079)."
  }
}

variable "deployment_name" {
  description = "Kubernetes Deployment and app selector name."
  type        = string
  default     = "inference-stub"
}

variable "service_name" {
  description = "Kubernetes ClusterIP Service name."
  type        = string
  default     = "inference-stub"
}

variable "port" {
  description = "Container and Service HTTP port exposing /health and /v1/chat/completions."
  type        = number
  default     = 8000
}

variable "replicas" {
  description = "Number of deterministic stub pod replicas."
  type        = number
  default     = 1
}

variable "cpu_request" {
  description = "CPU request for the stub container (non-GPU CPU pool)."
  type        = string
  default     = "50m"
}

variable "memory_request" {
  description = "Memory request for the stub container."
  type        = string
  default     = "128Mi"
}

variable "cpu_limit" {
  description = "CPU limit for the stub container."
  type        = string
  default     = "250m"
}

variable "memory_limit" {
  description = "Memory limit for the stub container."
  type        = string
  default     = "512Mi"
}

variable "network_policy_hash" {
  description = "Optional NetworkPolicy spec digest annotation to roll pods on policy changes."
  type        = string
  default     = ""
}
