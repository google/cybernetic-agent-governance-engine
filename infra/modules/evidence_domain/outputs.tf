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

# ─── Persistent Evidence Domain Module Outputs (§10a, R-10, F-66, F-94, F-97) ─

output "evidence_project_id" {
  description = "GCP project ID hosting the persistent evidence custody boundary."
  value       = var.evidence_project_id
}

output "cross_project_isolated" {
  description = "True when the persistent evidence domain lives in an external root or dedicated GCP project separate from the workload project (AU-9(4))."
  value       = local.cross_project_isolated
}

output "evidence_cmek_key_id" {
  description = "Resource ID of the dedicated evidence CMEK CryptoKey (120-day destroy_scheduled_duration, F-97)."
  value = (
    var.external_evidence_domain_enabled
    ? var.external_evidence_cmek_key_id
    : google_kms_crypto_key.evidence_cmek[0].id
  )
  depends_on = [google_kms_crypto_key_iam_binding.evidence_cmek_crypto_operator]
}

output "evidence_cmek_iam_ready" {
  description = "Dependency token confirming the GCS service agent holds cryptoKeyEncrypterDecrypter on the evidence CMEK key before CMEK buckets are created."
  value = (
    var.external_evidence_domain_enabled
    ? "external"
    : google_kms_crypto_key_iam_binding.evidence_cmek_crypto_operator[0].id
  )
  depends_on = [google_kms_crypto_key_iam_binding.evidence_cmek_crypto_operator]
}

output "evidence_cmek_destroy_scheduled_duration" {
  description = "Scheduled destruction window of the evidence CMEK key (10368000s / 120 days)."
  value = (
    var.external_evidence_domain_enabled
    ? "10368000s"
    : google_kms_crypto_key.evidence_cmek[0].destroy_scheduled_duration
  )
}

output "audit_logs_worm_bucket_name" {
  description = "Name of the retention-locked Cloud Audit Logs WORM bucket in the evidence domain."
  value = (
    var.external_evidence_domain_enabled
    ? data.google_storage_bucket.external_audit_logs_worm[0].name
    : google_storage_bucket.audit_logs_worm[0].name
  )
}

output "audit_logs_worm_bucket_url" {
  description = "GCS URL of the retention-locked Cloud Audit Logs WORM bucket."
  value = (
    var.external_evidence_domain_enabled
    ? data.google_storage_bucket.external_audit_logs_worm[0].url
    : google_storage_bucket.audit_logs_worm[0].url
  )
}

output "signing_key_manifest_object_name" {
  description = "GCS object path of the archived signing public key (`kid`) manifest."
  value       = !var.external_evidence_domain_enabled && length(var.signing_key_manifest) > 0 ? local.signing_key_manifest_object_name : ""
}

output "gcs_service_agent_email" {
  description = "Cloud Storage Service Agent email bound as CMEK crypto operator when managed"
  value       = !var.external_evidence_domain_enabled ? "service-${data.google_project.evidence[0].number}@gs-project-accounts.iam.gserviceaccount.com" : ""
}

output "cmek_crypto_operator_members" {
  description = "Principals granted roles/cloudkms.cryptoKeyEncrypterDecrypter on the evidence CMEK key"
  value       = !var.external_evidence_domain_enabled ? toset(local.evidence_cmek_operators) : toset([])
}

output "managed_custody_resource_count" {
  description = "Count of managed custody KMS/bucket/manifest resources planned in this module (0 when external_evidence_domain_enabled = true)."
  value       = length(google_kms_crypto_key.evidence_cmek) + length(google_storage_bucket.audit_logs_worm) + length(google_storage_bucket_object.signing_key_manifest)
}

output "audit_log_sink_writers" {
  description = "Writer identities granted roles/storage.objectCreator on audit-logs-worm, keyed by static sink name."
  value       = { for name, grant in google_storage_bucket_iam_member.audit_log_sink_writer : name => grant.member }
}
