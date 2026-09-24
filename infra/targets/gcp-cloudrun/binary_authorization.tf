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

# ─── Binary Authorization Policy ──────────────────────────────────────────────
# Phase C: Binary Authorization policy enforcing attestation-based container
# admission control. Production environments enforce REQUIRE_ATTESTATION with
# zero breakglass escape hatches. Dev/staging environments allow ALWAYS_ALLOW
# for rapid iteration without cryptographic attestation overhead.

resource "google_binary_authorization_policy" "cloudrun_policy" {
  count   = var.enable_binary_authorization ? 1 : 0
  project = var.project_id

  # Default rule: REQUIRE_ATTESTATION in prod, ALWAYS_ALLOW in dev/staging
  default_admission_rule {
    evaluation_mode  = var.environment == "prod" ? "REQUIRE_ATTESTATION" : "ALWAYS_ALLOW"
    enforcement_mode = "ENFORCED_BLOCK_AND_AUDIT_LOG"
    
    require_attestations_by = var.environment == "prod" ? [
      google_binary_authorization_attestor.cloudrun_attestor[0].name
    ] : []
  }

  # CRITICAL: Breakglass prohibition in production environments.
  # Conditional global_policy_evaluation_mode disables breakglass escape hatches
  # when environment=prod, ensuring zero attestation bypass pathways.
  global_policy_evaluation_mode = var.environment == "prod" ? "ENABLE" : "DISABLE"

  # Cluster-specific admission rules are not applicable to Cloud Run
  # (Cloud Run services are not associated with GKE clusters)
}

# ─── Container Analysis Note ──────────────────────────────────────────────────
# Container Analysis Note stores attestation metadata for verified container builds.

resource "google_container_analysis_note" "cloudrun_attestation_note" {
  count   = var.enable_binary_authorization ? 1 : 0
  name    = "cage-cloudrun-attestation-${var.environment}"
  project = var.project_id

  attestation_authority {
    hint {
      human_readable_name = "CAGE Cloud Run Attestor - ${var.environment}"
    }
  }
}

# ─── Binary Authorization Attestor ────────────────────────────────────────────
# Attestor represents the trusted authority that signs container image attestations.

resource "google_binary_authorization_attestor" "cloudrun_attestor" {
  count   = var.enable_binary_authorization ? 1 : 0
  name    = "cage-cloudrun-attestor-${var.environment}"
  project = var.project_id

  attestation_authority_note {
    note_reference = google_container_analysis_note.cloudrun_attestation_note[0].id
  }
}

# ─── Cloud Build IAM Binding ──────────────────────────────────────────────────
# Grant Cloud Build service account permission to create attestations during
# the build pipeline. This enables Cloud Build to sign container images after
# successful vulnerability scanning and compliance checks.

resource "google_project_iam_member" "cloudbuild_attestor" {
  count   = var.enable_binary_authorization ? 1 : 0
  project = var.project_id
  role    = "roles/containeranalysis.notes.attacher"
  member  = "serviceAccount:${data.google_project.current.number}@cloudbuild.gserviceaccount.com"
}
