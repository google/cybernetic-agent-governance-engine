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

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.43"
    }
  }
}

data "google_project" "current" {
  project_id = var.project_id
}

locals {
  keyring_name = var.keyring_name != "" ? var.keyring_name : "cage-keyring-${var.environment}"
  key_name     = var.key_name != "" ? var.key_name : "cage-cmek-${var.environment}"
}

# ─── KMS Key Ring ─────────────────────────────────────────────────────────────
# Phase C / SC-12 / SC-13: Customer-Managed Encryption Keys (CMEK) for data-at-rest.

resource "google_kms_key_ring" "keyring" {
  name     = local.keyring_name
  location = var.region
  project  = var.project_id

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

# ─── Symmetric Crypto Key ─────────────────────────────────────────────────────

resource "google_kms_crypto_key" "cmek_key" {
  name            = local.key_name
  key_ring        = google_kms_key_ring.keyring.id
  rotation_period = var.rotation_period
  purpose         = "ENCRYPT_DECRYPT"

  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = var.protection_level
  }
}

# ─── Service Agent IAM Bindings ───────────────────────────────────────────────

resource "google_kms_crypto_key_iam_member" "cloudsql_agent" {
  count         = var.grant_service_agents ? 1 : 0
  crypto_key_id = google_kms_crypto_key.cmek_key.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:service-${data.google_project.current.number}@gcp-sa-cloud-sql.iam.gserviceaccount.com"
}

resource "google_kms_crypto_key_iam_member" "gcs_agent" {
  count         = var.grant_service_agents ? 1 : 0
  crypto_key_id = google_kms_crypto_key.cmek_key.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:service-${data.google_project.current.number}@gs-project-accounts.iam.gserviceaccount.com"
}

resource "google_kms_crypto_key_iam_member" "redis_agent" {
  count         = var.grant_service_agents ? 1 : 0
  crypto_key_id = google_kms_crypto_key.cmek_key.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:service-${data.google_project.current.number}@cloud-redis.iam.gserviceaccount.com"
}

resource "google_kms_crypto_key_iam_member" "additional_members" {
  for_each      = toset(var.additional_encrypter_decrypter_members)
  crypto_key_id = google_kms_crypto_key.cmek_key.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = each.value
}
