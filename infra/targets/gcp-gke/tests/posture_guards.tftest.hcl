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

# POAM-2026-181 & POAM-2026-130 (AC-3 / SC-7 / AU-9 / CP-9): the control-plane
# guard, both POAM-019 key guards, module.gke's allowlist, Cloud SQL PITR and
# the NeMo securityContext follow local.enforcing_posture: every staging and
# prod plan, whatever jurisdiction it selects, and a dev plan only with
# enforce_in_dev = true. They used to follow local.any_compliance_active (the
# three removed enable_*_compliance variables), so a staging or prod plan that
# selected no jurisdiction flag dropped all of them and planned a 0.0.0.0/0
# control plane. Every run here sets enforce_in_dev = false unless it says so.
# For each tier and jurisdiction, three runs: the supplied allowlist is planned
# exactly, an empty allowlist is refused, and empty compliance keys are refused.
# CI runs it in the terraform-test job:
#   terraform -chdir=infra/targets/gcp-gke test -var-file=staging.tfvars \
#     -var-file=tests/fixtures/image_digests.tfvars
#
# Mock providers and module overrides only, so no credentials and no state. The
# key values and CIDRs below are test fixtures, not credentials or operator
# addresses (203.0.113.0/24 is TEST-NET-3).

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
  project_id          = "posture-guards-test-project"
  evidence_project_id = "posture-guards-evidence-project"
  authorized_networks = [{ cidr = "203.0.113.7/32", display_name = "test" }]

  enforce_in_dev = false

  langfuse_compliance_public_key = "fake-compliance-public-key"
  langfuse_compliance_secret_key = "fake-compliance-secret-key"
}

# ─── Staging, US_FED (the profile's own jurisdiction) ───────────────────────

run "us_staging_without_a_flag_keeps_the_allowlist_and_pitr" {
  command = plan

  assert {
    condition     = var.environment == "staging" && local.enforcing_posture && !var.enforce_in_dev
    error_message = "this run must plan the staging tier with enforce_in_dev = false"
  }
  assert {
    condition     = module.gke.master_authorized_cidrs == ["203.0.113.7/32"]
    error_message = "a staging plan with no jurisdiction flag must plan exactly the supplied allowlist, never 0.0.0.0/0"
  }
  assert {
    condition     = module.cloudsql_postgres.point_in_time_recovery_enabled
    error_message = "a staging plan with no jurisdiction flag must keep Cloud SQL point-in-time recovery"
  }
}

run "us_staging_without_a_flag_refuses_an_empty_allowlist" {
  command = plan

  variables {
    authorized_networks = []
  }

  expect_failures = [terraform_data.control_plane_access_guard]
}

run "us_staging_without_a_flag_refuses_empty_compliance_keys" {
  command = plan

  variables {
    langfuse_compliance_public_key = ""
    langfuse_compliance_secret_key = ""
  }

  expect_failures = [terraform_data.poam_019_empty_key_guard]
}

run "us_staging_without_a_flag_refuses_shared_compliance_keys" {
  command = plan

  variables {
    langfuse_public_key            = "fake-app-public-key"
    langfuse_secret_key            = "fake-app-secret-key"
    langfuse_compliance_public_key = "fake-app-public-key"
    langfuse_compliance_secret_key = "fake-app-secret-key"
  }

  expect_failures = [terraform_data.poam_019_shared_key_guard]
}

# ─── Staging, EU_ECB ────────────────────────────────────────────────────────

run "eu_staging_without_a_flag_keeps_the_allowlist_and_pitr" {
  command = plan

  variables {
    cage_deployment_region = "EU_ECB"
    region                 = "europe-west1"
    zone                   = "europe-west1-b"
    gpu_node_locations     = ["europe-west1-b", "europe-west1-c"]
  }

  assert {
    condition     = local.enforcing_posture && !var.enforce_in_dev
    error_message = "this run must plan the staging tier with enforce_in_dev = false"
  }
  assert {
    condition     = module.gke.master_authorized_cidrs == ["203.0.113.7/32"]
    error_message = "an EU_ECB staging plan with no flag must plan exactly the supplied allowlist, never 0.0.0.0/0"
  }
  assert {
    condition     = module.cloudsql_postgres.point_in_time_recovery_enabled
    error_message = "an EU_ECB staging plan with no flag must keep Cloud SQL point-in-time recovery"
  }
}

run "eu_staging_without_a_flag_refuses_an_empty_allowlist" {
  command = plan

  variables {
    cage_deployment_region = "EU_ECB"
    region                 = "europe-west1"
    zone                   = "europe-west1-b"
    gpu_node_locations     = ["europe-west1-b", "europe-west1-c"]
    authorized_networks    = []
  }

  expect_failures = [terraform_data.control_plane_access_guard]
}

run "eu_staging_without_a_flag_refuses_empty_compliance_keys" {
  command = plan

  variables {
    cage_deployment_region         = "EU_ECB"
    region                         = "europe-west1"
    zone                           = "europe-west1-b"
    gpu_node_locations             = ["europe-west1-b", "europe-west1-c"]
    langfuse_compliance_public_key = ""
    langfuse_compliance_secret_key = ""
  }

  expect_failures = [terraform_data.poam_019_empty_key_guard]
}

# ─── Staging, APAC_MAS ──────────────────────────────────────────────────────

run "apac_staging_without_a_flag_keeps_the_allowlist_and_pitr" {
  command = plan

  variables {
    cage_deployment_region = "APAC_MAS"
    region                 = "asia-southeast1"
    zone                   = "asia-southeast1-a"
    gpu_node_locations     = ["asia-southeast1-a", "asia-southeast1-b", "asia-southeast1-c"]
  }

  assert {
    condition     = local.enforcing_posture && !var.enforce_in_dev
    error_message = "this run must plan the staging tier with enforce_in_dev = false"
  }
  assert {
    condition     = module.gke.master_authorized_cidrs == ["203.0.113.7/32"]
    error_message = "an APAC_MAS staging plan with no flag must plan exactly the supplied allowlist, never 0.0.0.0/0"
  }
  assert {
    condition     = module.cloudsql_postgres.point_in_time_recovery_enabled
    error_message = "an APAC_MAS staging plan with no flag must keep Cloud SQL point-in-time recovery"
  }
}

run "apac_staging_without_a_flag_refuses_an_empty_allowlist" {
  command = plan

  variables {
    cage_deployment_region = "APAC_MAS"
    region                 = "asia-southeast1"
    zone                   = "asia-southeast1-a"
    gpu_node_locations     = ["asia-southeast1-a", "asia-southeast1-b", "asia-southeast1-c"]
    authorized_networks    = []
  }

  expect_failures = [terraform_data.control_plane_access_guard]
}

run "apac_staging_without_a_flag_refuses_empty_compliance_keys" {
  command = plan

  variables {
    cage_deployment_region         = "APAC_MAS"
    region                         = "asia-southeast1"
    zone                           = "asia-southeast1-a"
    gpu_node_locations             = ["asia-southeast1-a", "asia-southeast1-b", "asia-southeast1-c"]
    langfuse_compliance_public_key = ""
    langfuse_compliance_secret_key = ""
  }

  expect_failures = [terraform_data.poam_019_empty_key_guard]
}

# ─── Prod, US_FED ───────────────────────────────────────────────────────────

run "us_prod_without_a_flag_keeps_the_allowlist" {
  command = plan

  variables {
    environment = "prod"
  }

  assert {
    condition     = module.gke.master_authorized_cidrs == ["203.0.113.7/32"]
    error_message = "a prod plan with no jurisdiction flag must plan exactly the supplied allowlist, never 0.0.0.0/0"
  }
}

run "us_prod_without_a_flag_refuses_an_empty_allowlist" {
  command = plan

  variables {
    environment         = "prod"
    authorized_networks = []
  }

  expect_failures = [terraform_data.control_plane_access_guard]
}

run "us_prod_without_a_flag_refuses_empty_compliance_keys" {
  command = plan

  variables {
    environment                    = "prod"
    langfuse_compliance_public_key = ""
    langfuse_compliance_secret_key = ""
  }

  expect_failures = [terraform_data.poam_019_empty_key_guard]
}

# ─── Prod, EU_ECB ───────────────────────────────────────────────────────────

run "eu_prod_without_a_flag_keeps_the_allowlist" {
  command = plan

  variables {
    environment            = "prod"
    cage_deployment_region = "EU_ECB"
    region                 = "europe-west1"
    zone                   = "europe-west1-b"
    gpu_node_locations     = ["europe-west1-b", "europe-west1-c"]
  }

  assert {
    condition     = module.gke.master_authorized_cidrs == ["203.0.113.7/32"]
    error_message = "an EU_ECB prod plan with no flag must plan exactly the supplied allowlist, never 0.0.0.0/0"
  }
}

run "eu_prod_without_a_flag_refuses_an_empty_allowlist" {
  command = plan

  variables {
    environment            = "prod"
    cage_deployment_region = "EU_ECB"
    region                 = "europe-west1"
    zone                   = "europe-west1-b"
    gpu_node_locations     = ["europe-west1-b", "europe-west1-c"]
    authorized_networks    = []
  }

  expect_failures = [terraform_data.control_plane_access_guard]
}

run "eu_prod_without_a_flag_refuses_empty_compliance_keys" {
  command = plan

  variables {
    environment                    = "prod"
    cage_deployment_region         = "EU_ECB"
    region                         = "europe-west1"
    zone                           = "europe-west1-b"
    gpu_node_locations             = ["europe-west1-b", "europe-west1-c"]
    langfuse_compliance_public_key = ""
    langfuse_compliance_secret_key = ""
  }

  expect_failures = [terraform_data.poam_019_empty_key_guard]
}

# ─── Prod, APAC_MAS ─────────────────────────────────────────────────────────

run "apac_prod_without_a_flag_keeps_the_allowlist" {
  command = plan

  variables {
    environment            = "prod"
    cage_deployment_region = "APAC_MAS"
    region                 = "asia-southeast1"
    zone                   = "asia-southeast1-a"
    gpu_node_locations     = ["asia-southeast1-a", "asia-southeast1-b", "asia-southeast1-c"]
  }

  assert {
    condition     = module.gke.master_authorized_cidrs == ["203.0.113.7/32"]
    error_message = "an APAC_MAS prod plan with no flag must plan exactly the supplied allowlist, never 0.0.0.0/0"
  }
}

run "apac_prod_without_a_flag_refuses_an_empty_allowlist" {
  command = plan

  variables {
    environment            = "prod"
    cage_deployment_region = "APAC_MAS"
    region                 = "asia-southeast1"
    zone                   = "asia-southeast1-a"
    gpu_node_locations     = ["asia-southeast1-a", "asia-southeast1-b", "asia-southeast1-c"]
    authorized_networks    = []
  }

  expect_failures = [terraform_data.control_plane_access_guard]
}

run "apac_prod_without_a_flag_refuses_empty_compliance_keys" {
  command = plan

  variables {
    environment                    = "prod"
    cage_deployment_region         = "APAC_MAS"
    region                         = "asia-southeast1"
    zone                           = "asia-southeast1-a"
    gpu_node_locations             = ["asia-southeast1-a", "asia-southeast1-b", "asia-southeast1-c"]
    langfuse_compliance_public_key = ""
    langfuse_compliance_secret_key = ""
  }

  expect_failures = [terraform_data.poam_019_empty_key_guard]
}

# ─── Dev: enforce_in_dev = true makes it enforce ────────────────────────────
# Dev with enforce_in_dev = false is the control run in staging_compliance.tftest.hcl.

run "dev_with_a_flag_refuses_an_empty_allowlist" {
  command = plan

  variables {
    environment         = "dev"
    enforce_in_dev      = true
    authorized_networks = []
  }

  expect_failures = [terraform_data.control_plane_access_guard]
}
