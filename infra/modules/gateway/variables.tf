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

# POAM-2026-080: callers are authenticated by Linkerd mTLS workload identity,
# not by a shared HMAC secret. The gateway refuses every non-open path unless
# l5d-client-id is one of these identities.
variable "trusted_client_identities" {
  description = "Linkerd workload identities (l5d-client-id format: <sa>.<namespace>.serviceaccount.identity.linkerd.<trust-domain>) allowed to call the gateway's gated routes. Rendered into CAGE_TRUSTED_CLIENT_IDENTITIES and the mesh AuthorizationPolicy."
  type        = list(string)

  validation {
    condition = length(var.trusted_client_identities) > 0 && alltrue([
      for id in var.trusted_client_identities :
      can(regex("^[a-z0-9]([-a-z0-9]*[a-z0-9])?\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?\\.serviceaccount\\.identity\\.linkerd\\.[a-z0-9]([-a-z0-9.]*[a-z0-9])?$", id))
    ])
    error_message = "trusted_client_identities must be a non-empty list of Linkerd identities (<sa>.<namespace>.serviceaccount.identity.linkerd.<trust-domain>), not spiffe:// URIs."
  }
}

variable "enable_mesh_policy" {
  description = "Install the gateway's Linkerd Server/HTTPRoute/AuthorizationPolicy set. Requires the Linkerd CRDs (infra/modules/service_mesh)."
  type        = bool
  default     = true
}

variable "reconciliation_provider" {
  description = "RECONCILIATION_PROVIDER label for the startup posture check (must not be \"stub\" in production). The reconciler always runs the simulated Tier 2 provider."
  type        = string
  default     = "simulated"
}

variable "kms_governance_key" {
  description = "Cloud KMS governance key version resource name"
  type        = string
  default     = ""
}

variable "cage_kms_provider" {
  description = "KMS provider implementation (gcp, aws, stub)"
  type        = string
  default     = "gcp"
}

variable "service_account_name" {
  description = "Kubernetes ServiceAccount the pods run as. Must be this workload's own KSA, bound 1:1 to its own GSA (POAM-2026-079). No default: a missing identity fails the plan."
  type        = string

  validation {
    condition     = var.service_account_name != "" && var.service_account_name != "financial-advisor-sa"
    error_message = "service_account_name must name the workload's own KSA; the shared financial-advisor-sa is retired (POAM-2026-079)."
  }
}

variable "reconciler_kms_key" {
  description = "Cloud KMS key version of the reconciler-snapshot key (RECONCILER_KMS_KEY). The governor trusts ground-truth snapshots only from this key (G8); the startup posture check refuses an unset value or one equal to KMS_GOVERNANCE_KEY."
  type        = string
}
