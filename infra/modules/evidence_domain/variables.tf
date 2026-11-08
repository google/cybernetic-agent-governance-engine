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

# ─── Persistent Evidence Domain Module Variables (§10a, R-10, F-66, F-94, F-97) ─

variable "evidence_project_id" {
  description = "Dedicated GCP project ID for the persistent evidence custody domain (e.g. '<PROJECT_ID>-evidence'). Isolated from the ephemeral workload project so cluster teardown never destroys WORM evidence, audit logs, or CMEK keys (F-66, F-94, F-97)."
  type        = string
}

variable "workload_project_id" {
  description = "GCP project ID of the workload cluster producing evidence and audit logs."
  type        = string
}

variable "environment" {
  description = "Deployment posture (dev, staging, prod)."
  type        = string
}

variable "region" {
  description = "GCP region for the evidence domain KMS key ring and WORM buckets."
  type        = string
}

variable "cage_deployment_region" {
  description = "Sovereign deployment jurisdiction (US_FED, EU_ECB, APAC_MAS)."
  type        = string
}

variable "external_evidence_domain_enabled" {
  description = "When true, the persistent evidence domain is managed in an external Terraform root (<PROJECT_ID>-evidence) and adopted via read-only data sources / inputs so the workload deployer SA holds zero destroy paths over evidence buckets or CMEK keys (AU-9(4), F-66, F-94)."
  type        = bool
  default     = false
}

variable "external_evidence_cmek_key_id" {
  description = "Resource ID of the externally managed evidence CMEK CryptoKey when external_evidence_domain_enabled = true."
  type        = string
  default     = ""
}

variable "require_separate_evidence_project" {
  description = "When true, enforces at plan time that external_evidence_domain_enabled = true or evidence_project_id != workload_project_id so the workload deployer SA holds zero storage/KMS admin roles in the evidence domain (AU-9(4), F-66, F-97)."
  type        = bool
  default     = false
}

variable "evidence_bucket_name" {
  description = "Name of the WORM evidence bucket in the persistent evidence domain."
  type        = string
}

variable "audit_logs_bucket_name" {
  description = "Optional override for the retention-locked Cloud Audit Logs WORM bucket name (defaults to '<evidence_project_id>-audit-logs-worm-<environment>')."
  type        = string
  default     = ""
}

variable "retention_period_seconds" {
  description = "WORM retention duration in seconds (minimum 86400s; 220752000s / 7 years in prod)."
  type        = number
  default     = 220752000

  validation {
    condition     = var.retention_period_seconds >= 86400
    error_message = "retention_period_seconds must be at least 86400 seconds (24 hours)."
  }
}

variable "retention_locked" {
  description = "Whether the WORM retention policy is irreversibly locked."
  type        = bool
  default     = true
}

variable "enable_cmek" {
  description = "Encrypt evidence and audit-log buckets with the evidence domain's dedicated CMEK key (F-97)."
  type        = bool
  default     = true
}

variable "key_ring_prefix" {
  description = "Prefix for the evidence custody Cloud KMS KeyRing."
  type        = string
  default     = "cage-evidence-custody-keyring"
}

variable "kms_protection_level" {
  description = "Protection level for the evidence CMEK key (SOFTWARE or HSM)."
  type        = string
  default     = "HSM"

  validation {
    condition     = contains(["SOFTWARE", "HSM"], var.kms_protection_level)
    error_message = "kms_protection_level must be SOFTWARE or HSM."
  }
}

variable "custodian_service_account_email" {
  description = "Workload compliance-bridge custodian GSA email granted objectCreator (put_if_absent only, zero delete/admin) and CMEK encrypt/decrypt."
  type        = string
}

variable "audit_log_sink_writer_identities" {
  description = "Map of static sink names (e.g. 'kms_signing_audit', 'admin_activity_audit') to Cloud Logging sink writer identities granted objectCreator on audit-logs-worm."
  type        = map(string)
  default     = {}
}

variable "offline_verifier_principal" {
  description = "Optional IAM principal (e.g. 'serviceAccount:...' or 'group:...') for the out-of-cluster CustodyVerifier granted roles/storage.objectViewer."
  type        = string
  default     = ""
}

variable "deployer_service_account_email" {
  description = "Workload deployer GSA email (sa-cage-deployer). Receives zero storage or KMS admin roles in the evidence domain when evidence_project_id != workload_project_id (AU-9(4))."
  type        = string
  default     = ""
}

variable "signing_key_manifest" {
  description = "Map of signing key roles ('gateway-seal', 'compliance-evidence', 'reconciler-snapshot') to their kid/key_version_id, algorithm, and real PEM public_key_pem archived in the evidence bucket for post-teardown verification (PF8 in reverse)."
  type = map(object({
    kid            = string
    key_version_id = string
    algorithm      = string
    public_key_pem = string
  }))
  default = {}
}

variable "isolation_guard_ready" {
  description = "Dependency token from terraform_data.evidence_domain_isolation_guard so targeted plans on managed custody resources evaluate the root isolation guard without deferring data.google_project.evidence."
  type        = string
  default     = ""
}
