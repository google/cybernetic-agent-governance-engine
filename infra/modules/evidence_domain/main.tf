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

# ─── Persistent Evidence Custody Domain (§10a, R-10, F-66, F-94, F-97) ─────────
#
# Isolates long-lived compliance evidence, retention-locked Cloud Audit Logs,
# the evidence CMEK decryption key, and the signing public key archive (kid
# manifest) into a persistent evidence domain (`var.evidence_project_id`,
# e.g. `<PROJECT_ID>-evidence`) separate from the ephemeral GKE workload stack.

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.43"
    }
  }
}

data "google_project" "evidence" {
  count      = var.external_evidence_domain_enabled ? 0 : 1
  project_id = var.evidence_project_id
}

data "google_storage_bucket" "external_audit_logs_worm" {
  count = var.external_evidence_domain_enabled ? 1 : 0
  name  = local.audit_logs_bucket_name
}

locals {
  audit_logs_bucket_name = (
    var.audit_logs_bucket_name != ""
    ? var.audit_logs_bucket_name
    : "${var.evidence_project_id}-audit-logs-worm-${var.environment}"
  )

  cross_project_isolated = var.external_evidence_domain_enabled || var.evidence_project_id != var.workload_project_id

  # Cloud Storage service agent in the evidence project MUST hold
  # roles/cloudkms.cryptoKeyEncrypterDecrypter BEFORE CMEK-encrypted buckets
  # are created, preventing live GCP HTTP 403 errors on bucket creation.
  gcs_evidence_service_agent = (
    var.external_evidence_domain_enabled
    ? ""
    : "serviceAccount:service-${data.google_project.evidence[0].number}@gs-project-accounts.iam.gserviceaccount.com"
  )

  # Authoritative list of principals permitted to encrypt/decrypt with the
  # evidence CMEK key (F-97). The workload deployer SA and workload pods
  # (gateway, advisor, vllm) are never included.
  evidence_cmek_operators = compact(concat(
    [
      local.gcs_evidence_service_agent,
      "serviceAccount:${var.custodian_service_account_email}",
    ],
    var.offline_verifier_principal != "" ? [var.offline_verifier_principal] : [],
  ))

  signing_key_manifest_json = jsonencode({
    schema                 = "cage-signing-key-manifest/1"
    evidence_project_id    = var.evidence_project_id
    workload_project_id    = var.workload_project_id
    environment            = var.environment
    cage_deployment_region = var.cage_deployment_region
    keys                   = var.signing_key_manifest
  })

  # Content-addressed manifest object name so key rotation appends a new
  # immutable versioned object in the WORM-locked bucket without colliding
  # with prior retention-locked manifests.
  signing_key_manifest_object_name = "trust-anchors/signing-key-manifest-${substr(sha256(local.signing_key_manifest_json), 0, 16)}.json"
}

# ─── 1. Evidence CMEK Key Inside the Custody Boundary (F-97, SC-12, SC-28) ────

resource "google_kms_key_ring" "evidence_custody" {
  count = var.external_evidence_domain_enabled ? 0 : 1

  name     = "${var.key_ring_prefix}-${var.environment}"
  location = var.region
  project  = var.evidence_project_id

  lifecycle {
    prevent_destroy = true

    precondition {
      condition     = var.isolation_guard_ready != "__unreachable__"
      error_message = "Isolation guard must evaluate before creating the evidence custody keyring."
    }
  }
}

resource "google_kms_crypto_key" "evidence_cmek" {
  count = var.external_evidence_domain_enabled ? 0 : 1

  name     = "cage-evidence-cmek-key"
  key_ring = google_kms_key_ring.evidence_custody[0].id
  purpose  = "ENCRYPT_DECRYPT"

  # 90-day automatic key rotation (NIST SP 800-53 SC-12).
  rotation_period = "7776000s"

  # F-97: 120-day (maximum allowed by Cloud KMS) scheduled destruction window
  # so a compromised workload deployer cannot fast-destroy the CMEK key and
  # cryptographically shred multi-year WORM evidence in 24 hours.
  destroy_scheduled_duration = "10368000s"

  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = var.kms_protection_level
  }

  labels = {
    environment            = var.environment
    component              = "evidence-custody-cmek"
    managed-by             = "terraform"
    cage-deployment-region = lower(var.cage_deployment_region)
  }

  lifecycle {
    prevent_destroy = true

    precondition {
      condition     = !var.require_separate_evidence_project || var.evidence_project_id != var.workload_project_id
      error_message = "[AU-9(4) / F-97] Persistent evidence domain requires evidence_project_id ('${var.evidence_project_id}') to differ from workload_project_id ('${var.workload_project_id}') when require_separate_evidence_project = true."
    }

    precondition {
      condition     = var.deployer_service_account_email == "" || var.deployer_service_account_email != var.custodian_service_account_email
      error_message = "[AU-9(4) / F-97] Workload deployer service account ('${var.deployer_service_account_email}') must never share the evidence custodian identity ('${var.custodian_service_account_email}')."
    }
  }
}

# Authoritative IAM binding on the evidence CMEK key: only the evidence
# project's GCS service agent, the evidence custodian, and optional offline
# verifier may use the key. The workload deployer SA holds zero KMS admin or
# cryptoKeyEncrypterDecrypter permissions.
resource "google_kms_crypto_key_iam_binding" "evidence_cmek_crypto_operator" {
  count = var.external_evidence_domain_enabled ? 0 : 1

  crypto_key_id = google_kms_crypto_key.evidence_cmek[0].id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  members       = local.evidence_cmek_operators
}

# ─── 2. Retention-Locked Cloud Audit Logs WORM Bucket (R-4, F-66, F-94) ──────

resource "google_storage_bucket" "audit_logs_worm" {
  count = var.external_evidence_domain_enabled ? 0 : 1

  name          = local.audit_logs_bucket_name
  location      = var.region
  project       = var.evidence_project_id
  force_destroy = false

  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  versioning {
    enabled = true
  }

  retention_policy {
    is_locked        = var.retention_locked
    retention_period = var.retention_period_seconds
  }

  dynamic "encryption" {
    for_each = var.enable_cmek ? [1] : []
    content {
      default_kms_key_name = google_kms_crypto_key.evidence_cmek[0].id
    }
  }

  labels = {
    environment            = var.environment
    purpose                = "cloud-audit-logs-worm"
    compliance             = "nist-au-9-au-11"
    managed-by             = "terraform"
    cage-deployment-region = lower(var.cage_deployment_region)
  }

  depends_on = [google_kms_crypto_key_iam_binding.evidence_cmek_crypto_operator]

  lifecycle {
    prevent_destroy = true

    precondition {
      condition = (
        (var.cage_deployment_region == "EU_ECB" && startswith(var.region, "europe-")) ||
        (var.cage_deployment_region == "APAC_MAS" && startswith(var.region, "asia-")) ||
        (var.cage_deployment_region == "US_FED" && startswith(var.region, "us-"))
      )
      error_message = "Audit logs WORM bucket region '${var.region}' violates data residency for cage_deployment_region='${var.cage_deployment_region}'."
    }

    precondition {
      condition     = !var.require_separate_evidence_project || var.evidence_project_id != var.workload_project_id
      error_message = "[AU-9(4) / F-66] Audit logs WORM bucket must reside in a separate evidence_project_id ('${var.evidence_project_id}') distinct from workload_project_id ('${var.workload_project_id}') when require_separate_evidence_project = true."
    }
  }
}

# ─── 3. Signing Public Key Archive (`kid` Manifest — PF8 in Reverse) ─────────
# Archives the real PEM asymmetric public keys (`gateway-seal`,
# `compliance-evidence`, `reconciler-snapshot`) into a content-addressed WORM
# object (`trust-anchors/signing-key-manifest-<sha256>.json`) so offline
# verifiers can resolve `kid` trust anchors across cluster rebuilds and key
# rotations without colliding with WORM retention locks.

resource "google_storage_bucket_object" "signing_key_manifest" {
  count = !var.external_evidence_domain_enabled && length(keys(var.signing_key_manifest)) > 0 ? 1 : 0

  name         = local.signing_key_manifest_object_name
  bucket       = var.evidence_bucket_name
  content_type = "application/json"
  content      = local.signing_key_manifest_json

  lifecycle {
    create_before_destroy = true

    precondition {
      condition = alltrue([
        for _, entry in var.signing_key_manifest :
        startswith(trimspace(entry.public_key_pem), "-----BEGIN PUBLIC KEY-----")
      ])
      error_message = "Every signing_key_manifest entry must supply real PEM public key material ('-----BEGIN PUBLIC KEY-----'), never a KMS resource path."
    }
  }
}

# ─── 4. Cross-Project Least-Privilege IAM Grants (AU-9(4) Separation) ────────

# Workload compliance-bridge custodian SA: append-only `roles/storage.objectCreator`
# (`put_if_absent` only, zero delete/overwrite/admin permissions) on the evidence bucket.
resource "google_storage_bucket_iam_member" "custodian_object_creator" {
  count = var.external_evidence_domain_enabled ? 0 : 1

  bucket = var.evidence_bucket_name
  role   = "roles/storage.objectCreator"
  member = "serviceAccount:${var.custodian_service_account_email}"
}

# Log sink writer identities (keyed by static sink names): append-only
# `roles/storage.objectCreator` on the retention-locked `audit-logs-worm` bucket (R-4).
resource "google_storage_bucket_iam_member" "audit_log_sink_writer" {
  for_each = var.external_evidence_domain_enabled ? {} : var.audit_log_sink_writer_identities

  bucket = google_storage_bucket.audit_logs_worm[0].name
  role   = "roles/storage.objectCreator"
  member = each.value
}

# Out-of-cluster CustodyVerifier principal: read-only `roles/storage.objectViewer`
# on both the evidence WORM bucket and the audit-logs WORM bucket.
resource "google_storage_bucket_iam_member" "offline_verifier_evidence_viewer" {
  count = !var.external_evidence_domain_enabled && var.offline_verifier_principal != "" ? 1 : 0

  bucket = var.evidence_bucket_name
  role   = "roles/storage.objectViewer"
  member = var.offline_verifier_principal
}

resource "google_storage_bucket_iam_member" "offline_verifier_audit_logs_viewer" {
  count = !var.external_evidence_domain_enabled && var.offline_verifier_principal != "" ? 1 : 0

  bucket = google_storage_bucket.audit_logs_worm[0].name
  role   = "roles/storage.objectViewer"
  member = var.offline_verifier_principal
}
