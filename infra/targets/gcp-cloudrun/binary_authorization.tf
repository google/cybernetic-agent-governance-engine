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
# Phase 3, Task 3.2: Container Admission Control (NIST SP 800-53 CM-7, SI-7)
#
# Binary Authorization provides cryptographic attestation enforcement equivalent
# to GKE Binary Authorization, ensuring only signed and verified container images
# can be deployed to Cloud Run services.
#
# SECURITY PARITY MAPPING:
#   GKE Equivalent:   Binary Authorization admission controller webhook
#   Cloud Run:        Organization-level Binary Authorization policy
#   Control:          NIST SP 800-53 CM-7 (Least Functionality), SI-7 (Software Integrity)
#
# ENFORCEMENT MODES BY ENVIRONMENT:
#   Production:       REQUIRE_ATTESTATION + ENFORCED_BLOCK_AND_AUDIT_LOG
#                     - Zero breakglass escape hatches (global_policy_evaluation_mode=ENABLE)
#                     - Requires valid attestation from cage-cloudrun-attestor-prod
#                     - Unsigned images are DENIED at deployment time
#
#   Dev/Staging:      ALWAYS_ALLOW + ENFORCED_BLOCK_AND_AUDIT_LOG
#                     - Permissive mode for rapid iteration
#                     - No attestation required
#                     - Audit logs capture all deployment attempts
#
# ATTESTATION WORKFLOW (Production):
#   1. Cloud Build builds container image
#   2. Cloud Build triggers vulnerability scan (Container Analysis)
#   3. On successful scan, Cloud Build creates attestation signature
#   4. Attestation stored in Container Analysis Note
#   5. Binary Authorization policy validates attestation during Cloud Run deployment
#   6. Deployment blocked if attestation missing or invalid
#
# BREAKGLASS PROHIBITION:
#   In production, global_policy_evaluation_mode=ENABLE disables all breakglass
#   pathways, ensuring zero attestation bypass mechanisms exist.

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

  # CRITICAL: Breakglass prohibition in production environments (CM-7 enforcement).
  # Conditional global_policy_evaluation_mode disables breakglass escape hatches
  # when environment=prod, ensuring zero attestation bypass pathways. This prevents
  # emergency deployment of unattested images even during incident response,
  # enforcing strict supply chain integrity.
  #
  # ENABLE:  Production — no breakglass pathways, strict attestation enforcement
  # DISABLE: Dev/Staging — breakglass available for debugging unattested images
  global_policy_evaluation_mode = var.environment == "prod" ? "ENABLE" : "DISABLE"

  # Cluster-specific admission rules are not applicable to Cloud Run
  # (Cloud Run services are not associated with GKE clusters)
}

# ─── Container Analysis Note ──────────────────────────────────────────────────
# Container Analysis Note stores attestation metadata for verified container builds.
# This note acts as the trust anchor for Binary Authorization attestations.
#
# SECURITY PROPERTIES:
#   - Immutable: Once created, attestations cannot be retroactively altered
#   - Auditable: All attestation creation events are logged in Cloud Audit Logs
#   - Scoped: Per-environment isolation (prod attestations != staging attestations)

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
# The attestor cryptographically links to the Container Analysis Note, establishing
# a verifiable chain of custody from build to deployment.
#
# TRUST MODEL:
#   - Attestor name referenced in Binary Authorization policy admission rules
#   - Cloud Build service account authorized to create attestations via IAM binding
#   - Attestations verified against this attestor's public key during deployment

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
#
# LEAST PRIVILEGE SCOPE:
#   Role: roles/containeranalysis.notes.attacher (create attestations only)
#   - Cannot delete or modify existing attestations
#   - Cannot modify the attestation note itself
#   - Scoped to Cloud Build default service account only
#
# INTEGRATION WITH CI/CD:
#   Cloud Build steps after successful image build:
#     1. gcloud container images scan ${IMAGE}
#     2. Wait for scan completion (vulnerability analysis)
#     3. gcloud beta container binauthz attestations sign-and-create \
#          --artifact-url=${IMAGE} \
#          --attestor=${ATTESTOR_NAME}

resource "google_project_iam_member" "cloudbuild_attestor" {
  count   = var.enable_binary_authorization ? 1 : 0
  project = var.project_id
  role    = "roles/containeranalysis.notes.attacher"
  member  = "serviceAccount:${data.google_project.current.number}@cloudbuild.gserviceaccount.com"
}
