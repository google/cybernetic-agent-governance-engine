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
  description = "Kubernetes namespace for ClickHouse operator, Keeper, and ClickHouse pods"
  type        = string
}

variable "environment" {
  description = "Deployment posture (dev, staging, prod). Controls single-node local SSD vs. Operator + ReplicatedMergeTree + Keeper (3 nodes) + GCS cold tier (§1.1, §2.6)."
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be one of: dev, staging, prod."
  }
}

variable "enable_high_availability" {
  description = "Enable HA topology: 3-node ReplicatedMergeTree cluster, 3-node ClickHouse Keeper quorum, GCS cold tier, and PodDisruptionBudgets."
  type        = bool
  default     = false
}

variable "enable_operator" {
  description = "Deploy the Altinity ClickHouse Operator Helm release (enabled automatically in prod or when enable_high_availability is true)."
  type        = bool
  default     = null
}

variable "operator_chart_version" {
  description = "Altinity ClickHouse Operator Helm chart version"
  type        = string
  default     = "0.24.2"
}

variable "image" {
  description = "ClickHouse Server container image"
  type        = string
  default     = "docker.io/clickhouse/clickhouse-server:24.3-alpine"
}

variable "keeper_image" {
  description = "ClickHouse Keeper container image for ReplicatedMergeTree coordination"
  type        = string
  default     = "docker.io/clickhouse/clickhouse-keeper:24.3-alpine"
}

variable "storage_class" {
  description = "Kubernetes StorageClass for hot-tier local SSD volumes"
  type        = string
  default     = "local-ssd"
}

variable "storage_size" {
  description = "Hot-tier local SSD PVC size per ClickHouse replica"
  type        = string
  default     = "50Gi"
}

variable "keeper_storage_size" {
  description = "Persistent storage size per ClickHouse Keeper quorum node"
  type        = string
  default     = "10Gi"
}

variable "cold_tier_bucket" {
  description = "Dedicated GCS bucket for the ClickHouse cold storage tier in prod (§1.1, §2.6). ClickHouse deletes S3-disk objects on merge/TTL, so this must NEVER be the retention-locked evidence WORM bucket; it must have no retention policy."
  type        = string
  default     = ""
}

variable "cold_tier_endpoint" {
  description = "GCS XML API endpoint for ClickHouse cold storage disk in prod"
  type        = string
  default     = "https://storage.googleapis.com"
}

variable "cold_tier_credentials_secret_name" {
  description = "Kubernetes Secret holding the GCS HMAC key (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY) of the ClickHouse service account, read by the cold_gcs S3 disk via use_environment_credentials. Required whenever the cold tier is active."
  type        = string
  default     = ""
}

variable "service_account_name" {
  description = "Kubernetes ServiceAccount the ClickHouse pods run as (own KSA bound 1:1 to its own GSA, the only identity with access to cold_tier_bucket). Empty leaves the namespace default KSA."
  type        = string
  default     = ""
}

variable "hot_to_cold_move_factor" {
  description = "Free-space ratio on hot local SSD below which parts automatically move to the GCS cold tier"
  type        = number
  default     = 0.2
}

variable "password_secret_name" {
  description = "Name of the Kubernetes Secret containing the ClickHouse password"
  type        = string
  default     = "advisor-secrets"
}

variable "password_secret_key" {
  description = "Key within password_secret_name for the ClickHouse password"
  type        = string
  default     = "CLICKHOUSE_PASSWORD"
}

variable "evidence_database" {
  description = "Database holding evidence_stream; must match deployment/clickhouse/evidence_stream_schema.sql."
  type        = string
  default     = "cage_evidence"
}

variable "evidence_sink_username" {
  description = "Least-privilege ClickHouse user for the compliance-bridge sink (INSERT on evidence_stream only)."
  type        = string
  default     = "cage_evidence_sink"

  validation {
    condition     = can(regex("^[a-z][a-z0-9_]{2,62}$", var.evidence_sink_username)) && var.evidence_sink_username != "default"
    error_message = "evidence_sink_username must be a lowercase identifier and must not be the admin user \"default\"."
  }
}

variable "evidence_sink_secret_name" {
  description = "Kubernetes Secret (key CLICKHOUSE_PASSWORD) holding the evidence sink user's password."
  type        = string
  default     = "clickhouse-evidence-sink"
}

variable "cpu_request" {
  description = "CPU request for ClickHouse server pods"
  type        = string
  default     = "500m"
}

variable "memory_request" {
  description = "Memory request for ClickHouse server pods"
  type        = string
  default     = "1Gi"
}

variable "cpu_limit" {
  description = "CPU limit for ClickHouse server pods"
  type        = string
  default     = "2000m"
}

variable "memory_limit" {
  description = "Memory limit for ClickHouse server pods"
  type        = string
  default     = "4Gi"
}
