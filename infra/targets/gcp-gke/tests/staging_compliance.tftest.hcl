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

# POAM-2026-174 & POAM-2026-181 & POAM-2026-130 (CM-6 / AC-3 / CP-9):
# staging.tfvars sets environment = "staging", which activates
# local.enforcing_posture in main.tf directly, so a direct terraform run with
# -var-file=staging.tfvars plans the same posture deploy_all.sh does. CI runs
# it in the terraform-test job:
#   terraform -chdir=infra/targets/gcp-gke test -var-file=staging.tfvars \
#     -var-file=tests/fixtures/image_digests.tfvars
#
# module.gke is planned for real against the mock provider, so the assertions
# read the cluster's planned master_authorized_networks_config back through
# module.gke.master_authorized_cidrs. Mock providers only, so no credentials and
# no state.
#
# The key values and CIDRs below are test fixtures, not credentials or
# operator addresses (203.0.113.0/24 is TEST-NET-3).

mock_provider "google" {}
mock_provider "helm" {}
mock_provider "kubernetes" {}
mock_provider "random" {}

override_module {
  target = module.memorystore_governance
  outputs = {
    managed_server_ca     = ["-----BEGIN CERTIFICATE-----test-----END CERTIFICATE-----"]
    primary_endpoint_ip   = "10.10.0.5"
    primary_endpoint_port = 6379
    replica_count         = 1
  }
}

override_module {
  target = module.memorystore_app
  outputs = {
    primary_endpoint_ip   = "10.10.0.6"
    primary_endpoint_port = 6379
  }
}

variables {
  project_id          = "staging-compliance-test-project"
  authorized_networks = [{ cidr = "203.0.113.7/32", display_name = "test" }]

  # An enforcing posture needs distinct compliance telemetry keys (POAM-019).
  langfuse_compliance_public_key = "fake-compliance-public-key"
  langfuse_compliance_secret_key = "fake-compliance-secret-key"
}

# ─── The profile alone activates the posture ────────────────────────────────

run "staging_profile_alone_activates_compliance" {
  command = plan

  assert {
    condition     = var.environment == "staging"
    error_message = "staging.tfvars must set environment = \"staging\""
  }
  assert {
    condition     = local.enforcing_posture && output.deployment_summary.enforcing_posture
    error_message = "staging.tfvars alone must make local.enforcing_posture true"
  }
  assert {
    condition     = module.cloudsql_postgres.point_in_time_recovery_enabled
    error_message = "staging must plan Cloud SQL point-in-time recovery under local.enforcing_posture"
  }
}

# ─── Control-plane access on the staging path ───────────────────────────────

run "staging_with_authorized_networks_plans_only_those_cidrs" {
  command = plan

  assert {
    condition     = module.gke.master_authorized_cidrs == ["203.0.113.7/32"]
    error_message = "staging must plan master_authorized_networks_config with exactly the supplied authorized_networks"
  }
  assert {
    condition     = !contains(module.gke.master_authorized_cidrs, "0.0.0.0/0")
    error_message = "staging must never fall back to 0.0.0.0/0 on the control plane"
  }
}

# The intended fail-closed path: the posture enforces and nobody is named, so
# the plan stops at the guard instead of leaving GKE's allowlist off.
run "staging_with_empty_authorized_networks_is_refused" {
  command = plan

  variables {
    authorized_networks = []
  }

  expect_failures = [terraform_data.control_plane_access_guard]
}

run "staging_with_an_open_authorized_network_is_refused" {
  command = plan

  variables {
    authorized_networks = [{ cidr = "0.0.0.0/0", display_name = "open" }]
  }

  expect_failures = [terraform_data.control_plane_access_guard]
}

# The fallback the module plans when nothing enforces: a dev plan with
# enforce_in_dev = false. Kept so the assertions above cannot pass by reading an
# output that never sees the fallback. Since POAM-2026-181 a staging plan never
# plans it (posture_guards.tftest.hcl).
run "dev_without_a_flag_falls_back_to_an_open_control_plane" {
  command = plan

  variables {
    environment    = "dev"
    enforce_in_dev = false
  }

  assert {
    condition     = !local.enforcing_posture
    error_message = "this run must plan with no enforcing posture"
  }
  assert {
    condition     = module.gke.master_authorized_cidrs == ["0.0.0.0/0"]
    error_message = "with nothing enforcing, the module's fallback must be visible in master_authorized_cidrs"
  }
  assert {
    condition     = !module.cloudsql_postgres.point_in_time_recovery_enabled
    error_message = "with nothing enforcing, Cloud SQL plans no point-in-time recovery"
  }
}
