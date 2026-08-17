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

variable "salt" {
  type      = string
  sensitive = true
}

variable "alphavantage_api_key" {
  type      = string
  sensitive = true
  default   = ""
}

variable "openai_api_key" {
  type      = string
  sensitive = true
  default   = "not-needed-for-local-vllm"
}

variable "langfuse_public_key" {
  type      = string
  sensitive = true
}

variable "langfuse_secret_key" {
  type      = string
  sensitive = true
}

variable "langfuse_host" {
  type = string
}

variable "clickhouse_url" {
  type = string
}

variable "clickhouse_migration_url" {
  type = string
}

variable "clickhouse_user" {
  type = string
}

variable "clickhouse_password" {
  type      = string
  sensitive = true
}

variable "database_url" {
  type      = string
  sensitive = true
}

variable "nextauth_secret" {
  type      = string
  sensitive = true
}

variable "nextauth_url" {
  type = string
}

variable "aws_access_key_id" {
  type      = string
  sensitive = true
  default   = ""
}

variable "aws_secret_access_key" {
  type      = string
  sensitive = true
  default   = ""
}

variable "s3_endpoint_url" {
  type    = string
  default = ""
}

variable "s3_bucket_name" {
  type    = string
  default = ""
}

variable "minio_root_user" {
  type      = string
  sensitive = true
  default   = ""
}

variable "minio_root_password" {
  type      = string
  sensitive = true
  default   = ""
}

variable "hf_token" {
  type      = string
  sensitive = true
  default   = ""
}

variable "langfuse_compliance_public_key" {
  type      = string
  sensitive = true
  default   = ""
}

variable "langfuse_compliance_secret_key" {
  type      = string
  sensitive = true
  default   = ""
}

variable "oscal_api_key" {
  type      = string
  sensitive = true
  default   = "DUMMY_API_KEY_FOR_LOCAL_DEV"
}

variable "opa_url" {
  type    = string
  default = ""
}

variable "model_fast" {
  type    = string
  default = "Qwen/Qwen2.5-1.5B-Instruct"
}

variable "model_reasoning" {
  type    = string
  default = "deepseek-ai/DeepSeek-R1-Distill-Llama-8B"
}

# DEP-09 (module): Remove "US_FED" default — the parent module (main.tf) must
# always pass cage_deployment_region explicitly. A missing value now causes a
# Terraform plan error rather than silently applying US_FED compliance posture.
variable "cage_deployment_region" {
  description = "CAGE deployment region compliance profile (US_FED, EU_ECB, APAC_MAS). Must be passed explicitly from the parent module — no default to prevent silent US_FED posture on non-US deployments."
  type        = string

  validation {
    condition     = contains(["US_FED", "EU_ECB", "APAC_MAS"], var.cage_deployment_region)
    error_message = "cage_deployment_region must be one of: US_FED, EU_ECB, APAC_MAS."
  }
}

variable "routing_seal_secret" {
  description = "HMAC secret for CAGE routing seal enforcement"
  type        = string
  sensitive   = true
}

variable "governance_salt" {
  description = "Salt value for governance HMAC operations"
  type        = string
  sensitive   = true
}
