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
  description = "Kubernetes namespace to deploy SLM"
  type        = string
}

variable "deployment_name" {
  description = "Name of the deployment"
  type        = string
  default     = "slm-inference"
}

variable "service_name" {
  description = "Name of the service"
  type        = string
  default     = "slm"
}

variable "image" {
  description = "SLM container image"
  type        = string
  default     = "gcr.io/PROJECT_ID/slm-inference:latest"
}

variable "image_pull_policy" {
  description = "Image pull policy"
  type        = string
  default     = "IfNotPresent"
}

variable "replicas" {
  description = "Number of replicas"
  type        = number
  default     = 1
}

variable "service_port" {
  description = "Service port"
  type        = number
  default     = 5000
}

variable "model_name" {
  description = "Sentence transformer model name"
  type        = string
  default     = "all-MiniLM-L6-v2"
}

# Resource limits
variable "resources_requests_cpu" {
  description = "CPU request"
  type        = string
  default     = "500m"
}

variable "resources_requests_memory" {
  description = "Memory request"
  type        = string
  default     = "1Gi"
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

variable "enable_security_context" {
  description = "Enable security context"
  type        = bool
  default     = false
}

variable "enable_pdb" {
  description = "Enable Pod Disruption Budget"
  type        = bool
  default     = false
}

variable "node_selector" {
  description = "Node selector for pod placement"
  type        = map(string)
  default     = {}
}

variable "tolerations" {
  description = "Tolerations for pod scheduling"
  type        = list(map(string))
  default     = []
}
