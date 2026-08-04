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
  description = "Container image for the gateway"
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

variable "otel_python_excluded_urls" {
  type    = string
  default = "healthz,readiness,liveness,metrics,huggingface.co/api/resolve"
}

variable "redis_host" {
  type = string
}

variable "redis_port" {
  type    = string
  default = "6379"
}

variable "redis_password" {
  type      = string
  default   = ""
  sensitive = true
}

variable "vllm_base_url" {
  type = string
}

variable "vllm_gateway_url" {
  type    = string
  default = ""
}

variable "vllm_reasoning_api_base" {
  type = string
}

variable "vllm_fast_api_base" {
  type = string
}

variable "guardrails_model_name" {
  type = string
}

variable "cage_env" {
  description = "Runtime environment for the gateway (development, staging, production)"
  type        = string
  default     = "production"
}

variable "opa_url" {
  type = string
}

variable "governance_salt" {
  description = "Salt value for governance HMAC operations"
  type        = string
  sensitive   = true
}

variable "langfuse_host" {
  description = "Langfuse host URL (e.g. http://langfuse-web.<namespace>.svc.cluster.local:3000)"
  type        = string
  default     = ""
}

variable "otel_exporter_otlp_headers" {
  description = "HTTP Basic Auth header for Langfuse OTLP ingestion (Authorization=Basic <b64>)"
  type        = string
  default     = ""
  sensitive   = true
}

# K-1: Explicit variable for CAGE_ROUTING_SEAL_SECRET.
# The gateway pod already receives this via the advisor-secrets bulk env_from
# mount, but declaring it here makes the Terraform dependency graph explicit
# and allows verify_remote.py / plan-time checks to confirm the value is
# non-empty before apply.  Actual value must come from terraform.auto.tfvars
# (gitignored) — never commit a real secret here.
variable "routing_seal_secret" {
  description = "Gateway routing seal secret (CAGE_ROUTING_SEAL_SECRET). Set via terraform.auto.tfvars (gitignored). Empty string silently disables seal enforcement in non-dev environments."
  type        = string
  default     = ""
  sensitive   = true
}
