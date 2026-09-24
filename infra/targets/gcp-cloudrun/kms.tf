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

# ─── KMS Key Ring ─────────────────────────────────────────────────────────────
# Phase C: Customer-Managed Encryption Keys (CMEK) for data-at-rest encryption
# across Cloud SQL, Redis, GCS, and Cloud Run services. Enforces 90-day automatic
# key rotation and regional data residency lifecycle preconditions per DEP-08.

resource "google_kms_key_ring" "cloudrun_keyring" {
  count    = var.enable_cmek ? 1 : 0
  name     = "cage-cloudrun-keyring-${var.environment}"
  location = var.region
  project  = var.project_id

  # DEP-08: Data residency lifecycle precondition — fail plan if region is unset
  # or defaults to us-central1 without explicit operator acknowledgment.
  lifecycle {
    precondition {
      condition     = var.region != ""
      error_message = "CMEK key ring requires explicit region assignment via jurisdiction-specific tfvars. Omitting var.region violates DEP-08 data residency mandate."
    }
    precondition {
      condition     = var.region != "us-central1" || var.cage_deployment_region == "US_FED"
      error_message = "CMEK key ring location us-central1 is only valid for cage_deployment_region=US_FED. EU_ECB and APAC_MAS deployments must use compliant regional key rings (e.g., europe-west1, asia-southeast1)."
    }
  }
}

# ─── Crypto Key for Cloud Run Services ───────────────────────────────────────

resource "google_kms_crypto_key" "cloudrun_cmek" {
  count           = var.enable_cmek ? 1 : 0
  name            = "cage-cloudrun-cmek-${var.environment}"
  key_ring        = google_kms_key_ring.cloudrun_keyring[0].id
  rotation_period = "7776000s" # 90 days

  purpose = "ENCRYPT_DECRYPT"

  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = "SOFTWARE"
  }

  lifecycle {
    prevent_destroy = true
  }
}

# ─── Service Agent IAM Bindings ───────────────────────────────────────────────
# Grant Cloud Run, Cloud SQL, GCS, and Redis service agents cryptoKeyEncrypterDecrypter
# role to use the CMEK key for data-at-rest encryption.

# Cloud Run Service Agent
resource "google_kms_crypto_key_iam_member" "cloudrun_agent" {
  count         = var.enable_cmek ? 1 : 0
  crypto_key_id = google_kms_crypto_key.cloudrun_cmek[0].id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:service-${data.google_project.current.number}@serverless-robot-prod.iam.gserviceaccount.com"
}

# Cloud SQL Service Agent
resource "google_kms_crypto_key_iam_member" "cloudsql_agent" {
  count         = var.enable_cmek ? 1 : 0
  crypto_key_id = google_kms_crypto_key.cloudrun_cmek[0].id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:service-${data.google_project.current.number}@gcp-sa-cloud-sql.iam.gserviceaccount.com"
}

# GCS Service Agent
resource "google_kms_crypto_key_iam_member" "gcs_agent" {
  count         = var.enable_cmek ? 1 : 0
  crypto_key_id = google_kms_crypto_key.cloudrun_cmek[0].id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:service-${data.google_project.current.number}@gs-project-accounts.iam.gserviceaccount.com"
}

# Cloud Memorystore Redis Service Agent
resource "google_kms_crypto_key_iam_member" "redis_agent" {
  count         = var.enable_cmek ? 1 : 0
  crypto_key_id = google_kms_crypto_key.cloudrun_cmek[0].id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:service-${data.google_project.current.number}@cloud-redis.iam.gserviceaccount.com"
}
