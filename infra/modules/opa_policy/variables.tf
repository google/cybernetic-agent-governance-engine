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

variable "create_policy_configmap" {
  description = "Create read-only ConfigMap for domain Rego policies mounted into the gateway OPA sidecar"
  type        = bool
  default     = true
}

variable "create_config_configmap" {
  description = "Create ConfigMap for OPA runtime configuration (enabled by default for console decision logs, F-102)"
  type        = bool
  default     = true
}

variable "policy_files" {
  description = "Map of policy filenames to Rego policy content"
  type        = map(string)
  default     = {}
}

variable "opa_config" {
  description = "OPA configuration YAML content (console decision logs enabled by default per F-102)"
  type        = string
  default     = <<-EOT
    decision_logs:
      console: true
  EOT

  validation {
    condition     = trimspace(var.opa_config) != ""
    error_message = "opa_config must not be empty; F-102 requires structured OPA runtime configuration (decision_logs.console = true)."
  }
}
