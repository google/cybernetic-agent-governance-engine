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
  description = "Container image for the governed advisor backend"
  type        = string
}

variable "replicas" {
  description = "Number of pod replicas"
  type        = number
  default     = 1
}

variable "project_id" {
  type = string
}

variable "region" {
  type = string
}

variable "enable_logging" {
  type    = string
  default = "true"
}

variable "redis_host" {
  type = string
}

variable "redis_port" {
  type    = string
  default = "6379"
}

variable "model_fast" {
  type = string
}

variable "model_reasoning" {
  type = string
}

variable "model_consensus" {
  type = string
}

variable "vllm_base_url" {
  type = string
}

variable "vllm_api_key" {
  type    = string
  default = "EMPTY"
}

variable "vllm_fast_api_base" {
  type = string
}

variable "vllm_reasoning_api_base" {
  type = string
}

variable "vllm_gateway_url" {
  type    = string
  default = ""
}

variable "opa_url" {
  type = string
}

variable "langfuse_host" {
  type = string
}

variable "otel_exporter_otlp_headers" {
  type    = string
  default = ""
}

variable "trace_sampling_rate" {
  type    = string
  default = "0.01"
}

variable "otel_python_excluded_urls" {
  type    = string
  default = "healthz,readiness,liveness,metrics,huggingface.co/api/resolve"
}

variable "cold_tier_gcs_bucket" {
  type    = string
  default = ""
}

variable "cold_tier_gcs_prefix" {
  type    = string
  default = "cold_tier"
}

variable "gateway_host" {
  type    = string
  default = "gateway.governance-stack.svc.cluster.local"
}

variable "gateway_grpc_port" {
  type    = string
  default = "50051"
}

variable "gateway_url" {
  type    = string
  default = "http://gateway.governance-stack.svc.cluster.local:8080"
}

variable "governance_salt" {
  type      = string
  sensitive = true
}

variable "mcp_mode" {
  type    = string
  default = "stdio"
}

variable "redis_password" {
  description = "Redis password"
  type        = string
  default     = ""
  sensitive   = true
}

variable "alphavantage_api_key" {
  type    = string
  default = ""
}

variable "gcp_service_account_name" {
  description = "Name (not email) of the GCP service account used for Workload Identity binding on the financial-advisor-sa KSA"
  type        = string
  default     = "financial-advisor-sa"
}

variable "cage_env" {
  description = "Runtime environment for the advisor (development, staging, production). Controls dev-mode auth bypass (auth.py) and KMS/salt startup enforcement guards."
  type        = string
  default     = "development"
}

variable "cage_seal_enforcement" {
  description = "Routing seal enforcement mode for the advisor: 'enforce' or 'log'."
  type        = string
  default     = "log"
}

variable "kms_governance_key" {
  description = "Full Cloud KMS key version resource name for CTRL_KMS_001 asymmetric governance signing (KMS_GOVERNANCE_KEY). Empty string falls back to legacy HMAC-SHA256 GOVERNANCE_SALT signing — acceptable only in dev/CI."
  type        = string
  default     = ""
}

variable "cage_kms_provider" {
  description = "Cloud KMS provider backend for governance signing (CAGE_KMS_PROVIDER): gcp, aws, or azure."
  type        = string
  default     = "gcp"
}
