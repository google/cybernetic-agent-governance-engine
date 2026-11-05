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
  description = "Kubernetes namespace hosting governance workloads."
  type        = string
}

variable "image" {
  description = "Digest-pinned container image containing src.gateway.governance.reconciliation.daemon (the compliance-bridge image)."
  type        = string

  validation {
    condition     = can(regex("@sha256:[0-9a-f]{64}$", var.image))
    error_message = "Reconciliation worker image must be pinned by @sha256 digest."
  }
}

variable "service_account_name" {
  description = "Kubernetes ServiceAccount bound via Workload Identity to the sole signer GSA for reconciler-snapshot (G8 / POAM-2026-079 / POAM-2026-096)."
  type        = string
}

variable "reconciler_kms_key" {
  description = "Cloud KMS CryptoKeyVersion resource name for reconciler-snapshot (populated into Secret/reconciliation-worker-secrets key reconciler-kms-key)."
  type        = string

  validation {
    condition     = trimspace(var.reconciler_kms_key) != ""
    error_message = "reconciler_kms_key must not be empty."
  }
}

variable "deployment_config_map_name" {
  description = "ConfigMap holding CAGE_DEPLOYMENT_REGION (output of modules/deployment_config)."
  type        = string
}

variable "cage_env" {
  description = "CAGE runtime environment (dev, staging, prod)."
  type        = string
  default     = "staging"
}

variable "cage_kms_provider" {
  description = "KMS signer provider loaded by GroundTruthReconciler (gcp in GKE)."
  type        = string
  default     = "gcp"
}

variable "redis_url" {
  description = "Governance Memorystore Valkey db 0 endpoint URL (redis://<ip>:<port>) shared with the gateway for signed ground-truth snapshots and settlement ledger."
  type        = string

  validation {
    condition     = can(regex("^rediss?://", var.redis_url))
    error_message = "redis_url must be a redis:// or rediss:// URL."
  }
}

variable "enable_redis_tls" {
  description = "Enable TLS for governance Redis connections (REDIS_TLS)."
  type        = bool
  default     = false
}

variable "redis_ca_pem" {
  description = "PEM-encoded CA certificate bundle for Redis TLS server certificate pinning."
  type        = string
  default     = ""
}

variable "redis_auth_mode" {
  description = "Redis authentication mode ('iam', 'password', 'none')."
  type        = string
  default     = ""
}

variable "evidence_stream_redis_url" {
  description = "Redis URL of the governance Memorystore instance holding the evidence stream (EVIDENCE_STREAM_REDIS_URL)."
  type        = string

  validation {
    condition     = can(regex("^rediss?://", var.evidence_stream_redis_url))
    error_message = "evidence_stream_redis_url must be a redis:// or rediss:// URL."
  }
}

variable "evidence_stream_redis_db" {
  description = "Redis logical database for the evidence stream (EVIDENCE_STREAM_REDIS_DB)."
  type        = number
  default     = 1
}

variable "evidence_stream_key" {
  description = "Redis Stream key for the evidence chain (EVIDENCE_STREAM_KEY)."
  type        = string
  default     = "cage:evidence:stream"
}

variable "poll_interval_seconds" {
  description = "Reconciler polling cadence in seconds (RECONCILIATION_POLL_INTERVAL_SECONDS)."
  type        = number
  default     = 60
}

variable "ttl_seconds" {
  description = "Verified ground-truth snapshot TTL in seconds (RECONCILIATION_TTL_SECONDS); must be >= 2 * poll_interval_seconds (POAM-2026-096)."
  type        = number
  default     = 300
}

variable "settlement_lag_seconds" {
  description = "Simulated custodian settlement lag in seconds (CAGE_SIM_SETTLEMENT_LAG_SECONDS; must match gateway, ADR-010)."
  type        = number
  default     = 90
}

variable "otel_endpoint" {
  description = "Optional OTLP HTTP trace endpoint URL; empty disables OTLP trace export."
  type        = string
  default     = ""
}

variable "network_policy_hash" {
  description = "SHA-256 digest of active NetworkPolicy/FQDNNetworkPolicy specs to trigger rollout on policy tightening."
  type        = string
  default     = ""
}
