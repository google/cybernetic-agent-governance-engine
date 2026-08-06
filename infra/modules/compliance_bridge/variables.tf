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
  description = "Compliance bridge container image"
  type        = string
}

variable "image_pull_policy" {
  description = "Image pull policy"
  type        = string
  default     = "Always"
}

variable "replicas" {
  description = "Number of replicas"
  type        = number
  default     = 1
}

variable "langfuse_host" {
  description = "Langfuse host URL"
  type        = string
  default     = "http://langfuse-web:3000"
}

variable "env_vars" {
  description = "Additional environment variables"
  type        = map(string)
  default     = {}
}

variable "service_type" {
  description = "Kubernetes service type"
  type        = string
  default     = "ClusterIP"
}

variable "memory_request" {
  description = "Memory request"
  type        = string
  default     = "256Mi"
}

variable "cpu_request" {
  description = "CPU request"
  type        = string
  default     = "100m"
}

variable "memory_limit" {
  description = "Memory limit"
  type        = string
  default     = "1Gi"
}

variable "cpu_limit" {
  description = "CPU limit"
  type        = string
  default     = "500m"
}

variable "remediation_model" {
  type    = string
  default = "Qwen/Qwen2.5-1.5B-Instruct"
}

variable "remediation_max_tokens" {
  type    = string
  default = "2048"
}

variable "remediation_timeout_ms" {
  type    = string
  default = "30000"
}

variable "vllm_base_url" {
  type = string
}

variable "vllm_api_key" {
  type = string
}

variable "alert_channel" {
  type    = string
  default = "console"
}

variable "oscal_s3_bucket" {
  type = string
}

variable "oscal_s3_region" {
  type = string
}

variable "cage_env" {
  description = "Runtime environment for the compliance bridge (development, staging, production). Controls KMS/Langfuse startup enforcement."
  type        = string
  default     = "development"
}

# K-3: KMS_GOVERNANCE_KEY for compliance-bridge KMSBatchSigner.
# Without this the compliance-bridge logs:
#   "[KMSBatchSigner] Failed to load signer at startup: KMS_GOVERNANCE_KEY is not set"
# and starts degraded (no asymmetric signatures on compliance evidence).
# The actual key resource name goes in terraform.auto.tfvars (gitignored) —
# never commit a real value here. Empty string falls back to HMAC-SHA256
# GOVERNANCE_SALT signing — acceptable in dev/CI postures.
variable "kms_governance_key" {
  description = "Full Cloud KMS key version resource name for CTRL_KMS_001 asymmetric governance signing (KMS_GOVERNANCE_KEY). Empty string falls back to legacy HMAC-SHA256 signing — acceptable only in dev/CI."
  type        = string
  default     = ""
  sensitive   = true
}

# CAGE_DEPLOYMENT_REGION selects which jurisdictional compliance framework
# controls (US_FED/NIST/FedRAMP, EU_ECB/EU AI Act, APAC_MAS/MAS FEAT) are
# exposed by GET /v1/controls and GET /v1/metrics/summary. Without this,
# get_control_meta("") only returns universal ISO 42001 controls, silently
# under-reporting jurisdictional compliance posture. Must match the region
# passed to the gateway and governed_advisor modules (via advisor-secrets).
variable "cage_deployment_region" {
  description = "Deployment jurisdiction: US_FED, EU_ECB, or APAC_MAS. Controls which compliance framework controls are exposed."
  type        = string
  default     = "US_FED"

  validation {
    condition     = contains(["US_FED", "EU_ECB", "APAC_MAS"], var.cage_deployment_region)
    error_message = "cage_deployment_region must be one of: US_FED, EU_ECB, APAC_MAS."
  }
}
