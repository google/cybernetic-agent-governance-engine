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

# K-3 / Track 6d (§5.2): EVIDENCE_KMS_KEY for the compliance-bridge KMSBatchSigner.
# Separate from the gateway's KMS_GOVERNANCE_KEY and the reconciler's RECONCILER_KMS_KEY.
# There is no HMAC fallback: empty is allowed only in dev/test/ci postures, where
# evidence batches are written unsigned; enforcing postures refuse to start.
variable "evidence_kms_key" {
  description = "Full Cloud KMS key version resource name the EvidenceCustodian uses to sign per-batch evidence attestations (EVIDENCE_KMS_KEY). There is no HMAC fallback: an empty value is allowed only in dev/test/ci postures, where evidence batches are written unsigned; enforcing postures (staging/prod) refuse to start without it."
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
  description = "ClickHouse query-plane database name (CLICKHOUSE_DATABASE). Must match deployment/clickhouse/evidence_stream_schema.sql."
  type        = string
  default     = "cage_evidence"
}

variable "clickhouse_enabled" {
  description = "Enable the ClickHouse query-plane sink (CLICKHOUSE_ENABLED, read by src/compliance_bridge/clickhouse_sink.py)."
  type        = bool
  default     = true
}

variable "clickhouse_username" {
  description = "ClickHouse user for the query-plane sink (CLICKHOUSE_USERNAME). The password is always taken from a Secret via secretKeyRef."
  type        = string
  default     = "default"
}

variable "clickhouse_password_secret_name" {
  description = "Kubernetes Secret holding the ClickHouse password for clickhouse_username."
  type        = string
  default     = "advisor-secrets"
}

variable "clickhouse_password_secret_key" {
  description = "Key within clickhouse_password_secret_name for the ClickHouse password."
  type        = string
  default     = "CLICKHOUSE_PASSWORD"
}

# ─── Evidence custody (EvidenceCustodian) ─────────────────────────────────────
# The bridge reads the gateway's evidence stream on the governance Memorystore
# instance, re-verifies the hash chain, signs a per-batch attestation with
# EVIDENCE_KMS_KEY and writes the batch to the WORM bucket. Its durable cursor
# lives in the Redis hash "<evidence_stream_key>:custody" on the same instance.

variable "evidence_stream_redis_url" {
  description = "Redis URL of the governance Memorystore instance holding the gateway's evidence stream (EVIDENCE_STREAM_REDIS_URL). Must equal the value passed to the gateway module."
  type        = string

  validation {
    condition     = can(regex("^rediss?://", var.evidence_stream_redis_url))
    error_message = "evidence_stream_redis_url must be a redis:// or rediss:// URL."
  }
}

variable "evidence_stream_redis_db" {
  description = "Redis logical database of the evidence stream (EVIDENCE_STREAM_REDIS_DB). Must equal the gateway module's value."
  type        = number
}

variable "evidence_stream_key" {
  description = "Redis Stream key of the evidence chain (EVIDENCE_STREAM_KEY). Must equal the gateway module's value."
  type        = string

  validation {
    condition     = var.evidence_stream_key != ""
    error_message = "evidence_stream_key must not be empty."
  }
}

variable "evidence_custody_interval_s" {
  description = "Seconds between EvidenceCustodian flush cycles (EVIDENCE_CUSTODY_INTERVAL_S)."
  type        = number
  default     = 60
}

variable "enable_redis_tls" {
  description = "Enable TLS for the governance Memorystore connection (REDIS_TLS). Must match the gateway module."
  type        = bool
  default     = false
}

variable "redis_ca_cert_path" {
  description = "CA certificate path for Redis TLS server certificate pinning (REDIS_CA_CERT_PATH)."
  type        = string
  default     = ""
}

variable "redis_auth_mode" {
  description = "Redis authentication mode for the governance Memorystore instance ('iam', 'password', 'none'; REDIS_AUTH_MODE). Must match the gateway module."
  type        = string
  default     = ""
}

