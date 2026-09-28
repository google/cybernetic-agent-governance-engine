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

# K-3 / Track 6d (§5.2): EVIDENCE_KMS_KEY for compliance-bridge KMSBatchSigner.
# Separate from the gateway's KMS_GOVERNANCE_KEY and the reconciler's RECONCILER_KMS_KEY.
# Empty string falls back to HMAC-SHA256 signing — acceptable only in dev/CI postures.
variable "evidence_kms_key" {
  description = "Full Cloud KMS key version resource name for compliance evidence batch signing (EVIDENCE_KMS_KEY). Empty string falls back to legacy HMAC-SHA256 signing — acceptable only in dev/CI."
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

variable "service_account_name" {
  description = "Kubernetes ServiceAccount the pods run as. Must be this workload's own KSA, bound 1:1 to its own GSA (POAM-2026-079). No default: a missing identity fails the plan."
  type        = string

  validation {
    condition     = var.service_account_name != "" && var.service_account_name != "financial-advisor-sa"
    error_message = "service_account_name must name the workload's own KSA; the shared financial-advisor-sa is retired (POAM-2026-079)."
  }
}

# ─── Evidence WORM Cold Store & ClickHouse Query Plane (§2.6) ─────────────────

variable "evidence_cold_store" {
  description = "Evidence cold store backend ('gcs', 's3', or 'null'). System of record is the retention-locked GCS WORM bucket ('gcs')."
  type        = string
  default     = "gcs"
}

variable "evidence_cold_store_bucket" {
  description = "Retention-locked GCS WORM bucket name for durable evidence archival (defaults to oscal_s3_bucket when empty)."
  type        = string
  default     = ""
}

variable "cmek_key_resource_name" {
  description = "Full Cloud KMS key resource name for CMEK encryption verification on the WORM bucket (POAM-014 / SC-28)."
  type        = string
  default     = ""
}

variable "clickhouse_host" {
  description = "ClickHouse query-plane service hostname (fed by src/compliance_bridge/clickhouse_sink.py)."
  type        = string
  default     = "clickhouse"
}

variable "clickhouse_port" {
  description = "ClickHouse query-plane HTTP port."
  type        = string
  default     = "8123"
}

variable "clickhouse_database" {
  description = "ClickHouse query-plane database name."
  type        = string
  default     = "default"
}

