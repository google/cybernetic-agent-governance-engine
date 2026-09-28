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

# ---------------------------------------------------------------------------
# Signing keys: one key per signer (POAM-2026-079 / SC-12 / SC-13 / AC-5)
#
# Each key has exactly one signing workload. Every key's IAM policy is
# authoritative (google_kms_crypto_key_iam_policy): a grant added out of band
# is removed on the next apply and shows up as drift in terraform plan.
#
# No role is ever granted on the keyring. A keyring-scoped grant is inherited
# by every key in the ring, including keys added later.
#
#   Key                  Signer (cloudkms.signer)      Public-key readers
#   -------------------  ----------------------------  ---------------------------
#   gateway-seal         gateway, advisor (temporary)  gateway, advisor
#   reconciler-snapshot  reconciler                    reconciler, gateway, advisor
#   compliance-evidence  compliance bridge             compliance bridge
#   benchmark-signing    benchmark job                 benchmark job
#
# benchmark-signing exists only to measure KMS signing latency. It is not a
# trust anchor: no verifier loads its public key, so its signatures carry no
# authority.
#
# The advisor's signer grant on gateway-seal is a residual of POAM-2026-079:
# the advisor still hosts an in-process SymbolicGovernor that mints routing
# seals (governor/verdicts.py issue_seal). It is removed once that governor
# moves behind the gateway.
#
# Readers get roles/cloudkms.publicKeyViewer (GetPublicKey) plus
# roles/cloudkms.viewer on the key only (GetCryptoKeyVersion /
# ListCryptoKeyVersions, used by src/integrations/gcp/kms_provider.py).
# ---------------------------------------------------------------------------

resource "google_kms_key_ring" "signing" {
  name     = "cage-signing-${var.environment}"
  location = var.region
  project  = var.project_id
}

resource "google_kms_crypto_key" "gateway_seal" {
  name     = "gateway-seal"
  key_ring = google_kms_key_ring.signing.id
  purpose  = "ASYMMETRIC_SIGN"

  version_template {
    algorithm        = "EC_SIGN_P256_SHA256"
    protection_level = var.kms_signing_protection_level
  }

  labels = {
    "cage-signer" = "gateway"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key" "reconciler_snapshot" {
  name     = "reconciler-snapshot"
  key_ring = google_kms_key_ring.signing.id
  purpose  = "ASYMMETRIC_SIGN"

  version_template {
    algorithm        = "EC_SIGN_P256_SHA256"
    protection_level = var.kms_signing_protection_level
  }

  labels = {
    "cage-signer" = "reconciler"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key" "compliance_evidence" {
  name     = "compliance-evidence"
  key_ring = google_kms_key_ring.signing.id
  purpose  = "ASYMMETRIC_SIGN"

  version_template {
    algorithm        = "EC_SIGN_P256_SHA256"
    protection_level = var.kms_signing_protection_level
  }

  labels = {
    "cage-signer" = "compliance-bridge"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key" "benchmark_signing" {
  name     = "benchmark-signing"
  key_ring = google_kms_key_ring.signing.id
  purpose  = "ASYMMETRIC_SIGN"

  version_template {
    algorithm        = "EC_SIGN_P256_SHA256"
    protection_level = var.kms_signing_protection_level
  }

  labels = {
    "cage-signer" = "benchmark"
  }

  lifecycle {
    prevent_destroy = true
  }
}

locals {
  gateway_member           = "serviceAccount:${google_service_account.gateway.email}"
  advisor_member           = "serviceAccount:${google_service_account.advisor.email}"
  reconciler_member        = "serviceAccount:${google_service_account.reconciler.email}"
  compliance_bridge_member = "serviceAccount:${google_service_account.compliance_bridge.email}"
  benchmark_member         = "serviceAccount:${google_service_account.benchmark.email}"

  signing_key_access = {
    gateway_seal = {
      key     = google_kms_crypto_key.gateway_seal.id
      signers = [local.gateway_member, local.advisor_member]
      readers = [local.gateway_member, local.advisor_member]
    }
    reconciler_snapshot = {
      key     = google_kms_crypto_key.reconciler_snapshot.id
      signers = [local.reconciler_member]
      readers = [local.reconciler_member, local.gateway_member, local.advisor_member]
    }
    compliance_evidence = {
      key     = google_kms_crypto_key.compliance_evidence.id
      signers = [local.compliance_bridge_member]
      readers = [local.compliance_bridge_member]
    }
    benchmark_signing = {
      key     = google_kms_crypto_key.benchmark_signing.id
      signers = [local.benchmark_member]
      readers = [local.benchmark_member]
    }
  }

  # Initial version created with each asymmetric key. Workloads pin a version
  # so the JWKS kid is stable; rotation adds a version and updates these.
  gateway_seal_key_version        = "${google_kms_crypto_key.gateway_seal.id}/cryptoKeyVersions/1"
  reconciler_snapshot_key_version = "${google_kms_crypto_key.reconciler_snapshot.id}/cryptoKeyVersions/1"
  compliance_evidence_key_version = "${google_kms_crypto_key.compliance_evidence.id}/cryptoKeyVersions/1"
  benchmark_signing_key_version   = "${google_kms_crypto_key.benchmark_signing.id}/cryptoKeyVersions/1"
}

data "google_iam_policy" "signing_key" {
  for_each = local.signing_key_access

  binding {
    role    = "roles/cloudkms.signer"
    members = each.value.signers
  }

  binding {
    role    = "roles/cloudkms.publicKeyViewer"
    members = each.value.readers
  }

  binding {
    role    = "roles/cloudkms.viewer"
    members = each.value.readers
  }
}

resource "google_kms_crypto_key_iam_policy" "signing_key" {
  for_each = local.signing_key_access

  crypto_key_id = each.value.key
  policy_data   = data.google_iam_policy.signing_key[each.key].policy_data
}
