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

# Plan-time contract for POAM-2026-204 (CAS issuer Workload Identity IAM
# propagation + per-incarnation GSA account_id override):
#   1. Default cas_issuer_account_id ("") preserves "cage-cas-issuer".
#   2. Explicit suffixed cas_issuer_account_id ("cage-cas-issuer-f6f72d26")
#      sets google_service_account.cas_issuer.account_id and avoids deleted-GSA
#      same-email negative IAM cache residue across Stage 5/6 rebuilds.
#   3. time_sleep.cas_issuer_iam_propagation waits 90s before mesh_identity
#      creates Certificate/linkerd-identity-issuer so google-cas-issuer v0.13.0
#      never hits its ~60s PermanentError cutoff (1-hour cert-manager backoff).
#   4. Invalid cas_issuer_account_id values fail plan-time validation.

mock_provider "google" {}
mock_provider "helm" {}
mock_provider "kubernetes" {}
mock_provider "time" {}

variables {
  project_id             = "mesh-test-project"
  region                 = "us-central1"
  environment            = "staging"
  master_ipv4_cidr_block = "172.16.0.0/28"
}

run "default_cas_issuer_account_id_and_iam_propagation_sleep" {
  command = plan

  assert {
    condition     = google_service_account.cas_issuer.account_id == "cage-cas-issuer"
    error_message = "default cas_issuer_account_id must preserve account_id = 'cage-cas-issuer'"
  }
  assert {
    condition     = time_sleep.cas_issuer_iam_propagation.create_duration == "90s"
    error_message = "cas_issuer_iam_propagation must wait 90s before Certificate/linkerd-identity-issuer is created"
  }
}

run "suffixed_cas_issuer_account_id_overrides_gsa_name" {
  command = plan

  variables {
    cas_issuer_account_id = "cage-cas-issuer-f6f72d26"
  }

  assert {
    condition     = google_service_account.cas_issuer.account_id == "cage-cas-issuer-f6f72d26"
    error_message = "suffixed cas_issuer_account_id must set google_service_account.cas_issuer.account_id"
  }
}

run "invalid_cas_issuer_account_id_is_rejected" {
  command = plan

  variables {
    cas_issuer_account_id = "INVALID_UPPERCASE_SA"
  }

  expect_failures = [
    var.cas_issuer_account_id,
  ]
}
