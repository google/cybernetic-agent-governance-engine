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
  description = "Kubernetes namespace"
  type        = string
}

variable "image" {
  description = "OPA container image"
  type        = string
  default     = "openpolicyagent/opa:latest-static"
}

variable "replicas" {
  description = "Number of replicas"
  type        = number
  default     = 1
}

variable "create_policy_configmap" {
  description = "Create ConfigMap for policies"
  type        = bool
  default     = true
}

variable "create_config_configmap" {
  description = "Create ConfigMap for OPA config"
  type        = bool
  default     = false
}

variable "policy_files" {
  description = "Map of policy filenames to policy content"
  type        = map(string)
  default     = {}
}

variable "opa_config" {
  description = "OPA configuration YAML content"
  type        = string
  default     = ""
}

variable "service_type" {
  description = "Kubernetes service type"
  type        = string
  default     = "ClusterIP"
}

variable "memory_request" {
  description = "Memory request"
  type        = string
  default     = "128Mi"
}

variable "cpu_request" {
  description = "CPU request"
  type        = string
  default     = "100m"
}

variable "memory_limit" {
  description = "Memory limit"
  type        = string
  default     = "256Mi"
}

variable "cpu_limit" {
  description = "CPU limit"
  type        = string
  default     = "500m"
}
