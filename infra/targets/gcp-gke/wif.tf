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

# ─── GitHub Actions Workload Identity Federation & Two-Identity Partition (POAM-2026-165) ─
# NIST SP 800-53 AC-6 (Least Privilege), CM-5 (Access Restrictions for Change),
# SI-7 (Software, Firmware, and Information Integrity).
#
# Separates privileged infrastructure deployment (sa-cage-deployer) from
# branch-dispatched CI partner conformance testing (cage-partner-harness):
#
# 1. Pool & OIDC Provider:
#    - Pool `github-actions`, provider `github` (`https://token.actions.githubusercontent.com`).
#    - Provider condition restricts token exchange to `assertion.repository == var.github_repository`.
#    - Attribute mapping projects both `attribute.ref = assertion.ref` and
#      `attribute.environment = assertion.environment` so IAM bindings can
#      distinguish `refs/heads/main` from unreviewed feature branches.
#
# 2. Deployer Identity (`sa-cage-deployer`):
#    - Authoritative `google_service_account_iam_binding` on `roles/iam.workloadIdentityUser`
#      and `roles/iam.serviceAccountTokenCreator` restricts WIF impersonation to
#      `principalSet://.../attribute.ref/${var.github_deployer_ref}` (`refs/heads/main`).
#    - Excludes the repository-wide principal set and the Compute Engine default
#      service account (`<PROJECT_NUMBER>-compute@developer.gserviceaccount.com`).
#
# 3. Partner Conformance Harness Identity (`cage-partner-harness`):
#    - Bound to `principalSet://.../attribute.repository/${var.github_repository}` so
#      branch-dispatched `ci-partner-integration.yml` runs can execute without
#      holding deployer authority.
#    - Granted only:
#      a) `roles/iam.serviceAccountTokenCreator` on `cage-gateway` (authoritative
#         binding) to mint audience-bound Cloud Run OIDC ID tokens for `provider_01`;
#      b) `roles/cloudkms.signer`, `roles/cloudkms.publicKeyViewer`, and
#         `roles/cloudkms.viewer` (authoritative key policy) on the dedicated
#         `actuator-01-signing` key.

resource "google_iam_workload_identity_pool" "github_actions" {
  workload_identity_pool_id = "github-actions"
  display_name              = "GitHub Actions Pool"
  description               = "Workload Identity Federation pool for GitHub Actions CI"
  project                   = var.project_id
}

resource "google_iam_workload_identity_pool_provider" "github" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.github_actions.workload_identity_pool_id
  workload_identity_pool_provider_id = "github"
  display_name                       = "GitHub Actions OIDC"
  project                            = var.project_id
  attribute_condition                = "assertion.repository == '${var.github_repository}'"

  attribute_mapping = {
    "google.subject"             = "assertion.sub"
    "attribute.actor"            = "assertion.actor"
    "attribute.repository"       = "assertion.repository"
    "attribute.repository_owner" = "assertion.repository_owner"
    "attribute.ref"              = "assertion.ref"
    "attribute.environment"      = "assertion.environment"
  }

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

# ─── 1. Privileged Deployer Identity (main branch only) ──────────────────────

resource "google_service_account" "deployer" {
  account_id   = "sa-cage-deployer"
  display_name = "CAGE Deployer"
  description  = "Terraform and CI/CD deployer for CAGE GKE"
  project      = var.project_id
}

resource "google_service_account_iam_binding" "deployer_workload_identity" {
  service_account_id = google_service_account.deployer.name
  role               = "roles/iam.workloadIdentityUser"
  members = [
    "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github_actions.name}/attribute.ref/${var.github_deployer_ref}",
  ]
}

resource "google_service_account_iam_binding" "deployer_token_creator" {
  service_account_id = google_service_account.deployer.name
  role               = "roles/iam.serviceAccountTokenCreator"
  members = [
    "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github_actions.name}/attribute.ref/${var.github_deployer_ref}",
    "serviceAccount:${google_service_account.deployer.email}",
  ]
}

# ─── 2. Low-Privilege Partner Test Identity (any branch in repository) ───────

resource "google_service_account" "partner_harness" {
  account_id   = "cage-partner-harness"
  display_name = "CAGE Partner Conformance Harness"
  description  = "Low-privilege WIF identity for CI partner integration runs from any branch (POAM-2026-165)"
  project      = var.project_id
}

resource "google_service_account_iam_binding" "partner_harness_workload_identity" {
  service_account_id = google_service_account.partner_harness.name
  role               = "roles/iam.workloadIdentityUser"
  members = [
    "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github_actions.name}/attribute.repository/${var.github_repository}",
  ]
}

resource "google_service_account_iam_binding" "partner_harness_token_creator" {
  service_account_id = google_service_account.partner_harness.name
  role               = "roles/iam.serviceAccountTokenCreator"
  members = [
    "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github_actions.name}/attribute.repository/${var.github_repository}",
    "serviceAccount:${google_service_account.partner_harness.email}",
  ]
}

# Authoritative Token Creator binding on cage-gateway: only cage-partner-harness
# may mint Cloud Run OIDC ID tokens as cage-gateway for provider_01 CI tests.
resource "google_service_account_iam_binding" "gateway_partner_token_creator" {
  service_account_id = google_service_account.gateway.name
  role               = "roles/iam.serviceAccountTokenCreator"
  members = [
    "serviceAccount:${google_service_account.partner_harness.email}",
  ]
}

# Authoritative key-level policy on the dedicated actuator-01-signing KMS key:
# grants signing and public-key read access exclusively to cage-partner-harness.
data "google_iam_policy" "partner_harness_kms_signer" {
  count = var.partner_harness_kms_key != "" ? 1 : 0

  binding {
    role    = "roles/cloudkms.signer"
    members = ["serviceAccount:${google_service_account.partner_harness.email}"]
  }

  binding {
    role    = "roles/cloudkms.publicKeyViewer"
    members = ["serviceAccount:${google_service_account.partner_harness.email}"]
  }

  binding {
    role    = "roles/cloudkms.viewer"
    members = ["serviceAccount:${google_service_account.partner_harness.email}"]
  }
}

resource "google_kms_crypto_key_iam_policy" "partner_harness_kms_signer" {
  count         = var.partner_harness_kms_key != "" ? 1 : 0
  crypto_key_id = "projects/${var.project_id}/locations/${var.region}/keyRings/${var.partner_harness_kms_keyring}/cryptoKeys/${var.partner_harness_kms_key}"
  policy_data   = data.google_iam_policy.partner_harness_kms_signer[0].policy_data
}
