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

locals {
  bucket_name   = var.bucket_name != "" ? var.bucket_name : "${var.project_id}-compliance-artifacts-${var.environment}"
  force_destroy = var.force_destroy != null ? var.force_destroy : (var.environment != "prod")
}

resource "google_storage_bucket" "bucket" {
  name          = local.bucket_name
  location      = var.region
  project       = var.project_id
  force_destroy = local.force_destroy

  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  dynamic "encryption" {
    for_each = var.enable_cmek && var.kms_key_id != null && var.kms_key_id != "" ? [1] : []
    content {
      default_kms_key_name = var.kms_key_id
    }
  }

  versioning {
    enabled = true
  }

  # AU-9: WORM retention — 2555 days (7 years) immutable retention in prod,
  # short lock in staging, unlocked in dev (§1.1, §2.6).
  # Prevents deletion before the retention period expires.
  # When is_locked is true, the policy cannot be reduced or removed.
  retention_policy {
    retention_period = var.retention_period_seconds
    is_locked        = var.is_locked
  }

  lifecycle_rule {
    condition {
      age = var.archive_transition_days
    }
    action {
      type          = "SetStorageClass"
      storage_class = "ARCHIVE"
    }
  }

  labels = merge(
    {
      environment = var.environment
      component   = "evidence-worm-cold-store"
      managed-by  = "terraform"
    },
    var.labels
  )

  # Jurisdictional data-residency guard (GDPR Art. 44, MAS TRM §4.2, NIST SC-7)
  lifecycle {
    precondition {
      condition = (
        (var.cage_deployment_region == "EU_ECB" && can(regex("^europe-", var.region))) ||
        (var.cage_deployment_region == "APAC_MAS" && can(regex("^asia-", var.region))) ||
        (var.cage_deployment_region == "US_FED" && can(regex("^us-", var.region)))
      )
      error_message = "Data residency violation on WORM bucket: cage_deployment_region=${var.cage_deployment_region} requires a matching regional prefix in var.region (got '${var.region}')."
    }
  }
}

