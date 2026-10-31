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

# POAM-019 (AU-9): plan-time contracts of the compliance telemetry key guards.
# With a compliance posture active, empty compliance keys and compliance keys
# equal to the application project's are refused by two separate resources, so
# each run names exactly the guards it expects to fail; any other failure fails
# the run. Mock providers and module overrides only, so no credentials and no
# state. CI runs it in the terraform-test job:
#   terraform -chdir=infra/targets/gcp-gke test -var-file=staging.tfvars
#
# The key values below are test fixtures, not credentials.

mock_provider "google" {
  mock_resource "google_container_cluster" {
    override_during = plan
    defaults = {
      endpoint    = "203.0.113.10"
      master_auth = [{ cluster_ca_certificate = "dGVzdA==", client_certificate = "", client_key = "", client_certificate_config = [] }]
    }
  }
}
mock_provider "helm" {}
mock_provider "kubernetes" {}
mock_provider "random" {}

override_module {
  target = module.gke
  outputs = {
    cluster_ca_certificate = "dGVzdA=="
    cluster_endpoint       = "203.0.113.10"
    cluster_location       = "us-central1-a"
    cluster_name           = "cage-staging"
    is_regional            = false
    node_pools             = {}
    workload_identity_pool = "poam-019-test-project.svc.id.goog"
  }
}

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
  project_id          = "poam-019-test-project"
  authorized_networks = [{ cidr = "203.0.113.7/32", display_name = "test" }]
}

# Nothing loaded: every key is empty. Only the empty-key guard may fire;
# "" == "" must not also be reported as a shared key.
run "compliance_active_empty_keys_fails_only_empty_key_guard" {
  command = plan
  variables {
    enable_nist_compliance = true
  }
  expect_failures = [terraform_data.poam_019_empty_key_guard]
}

run "compliance_active_shared_keys_fails_only_shared_key_guard" {
  command = plan
  variables {
    enable_nist_compliance         = true
    langfuse_public_key            = "fake-app-public-key"
    langfuse_secret_key            = "fake-app-secret-key"
    langfuse_compliance_public_key = "fake-app-public-key"
    langfuse_compliance_secret_key = "fake-app-secret-key"
  }
  expect_failures = [terraform_data.poam_019_shared_key_guard]
}

# One key empty and the other shared, both ways round: each guard reports its
# own condition, and each checks both keys.
run "compliance_active_empty_public_shared_secret_fails_both_guards" {
  command = plan
  variables {
    enable_nist_compliance         = true
    langfuse_public_key            = "fake-app-public-key"
    langfuse_secret_key            = "fake-app-secret-key"
    langfuse_compliance_secret_key = "fake-app-secret-key"
  }
  expect_failures = [
    terraform_data.poam_019_empty_key_guard,
    terraform_data.poam_019_shared_key_guard,
  ]
}

run "compliance_active_empty_secret_shared_public_fails_both_guards" {
  command = plan
  variables {
    enable_nist_compliance         = true
    langfuse_public_key            = "fake-app-public-key"
    langfuse_secret_key            = "fake-app-secret-key"
    langfuse_compliance_public_key = "fake-app-public-key"
  }
  expect_failures = [
    terraform_data.poam_019_empty_key_guard,
    terraform_data.poam_019_shared_key_guard,
  ]
}

run "compliance_active_distinct_keys_passes" {
  command = plan
  variables {
    enable_nist_compliance         = true
    langfuse_public_key            = "fake-app-public-key"
    langfuse_secret_key            = "fake-app-secret-key"
    langfuse_compliance_public_key = "fake-compliance-public-key"
    langfuse_compliance_secret_key = "fake-compliance-secret-key"
  }
  assert {
    condition     = local.any_compliance_active
    error_message = "this run must plan with a compliance posture active"
  }
}

# Without a compliance posture neither guard applies.
run "compliance_inactive_empty_keys_passes" {
  command = plan
  variables {
    enable_nist_compliance = false
  }
  assert {
    condition     = !local.any_compliance_active
    error_message = "this run must plan with no compliance posture active"
  }
}

run "compliance_inactive_shared_keys_passes" {
  command = plan
  variables {
    enable_nist_compliance         = false
    langfuse_public_key            = "fake-app-public-key"
    langfuse_secret_key            = "fake-app-secret-key"
    langfuse_compliance_public_key = "fake-app-public-key"
    langfuse_compliance_secret_key = "fake-app-secret-key"
  }
  assert {
    condition     = !local.any_compliance_active
    error_message = "this run must plan with no compliance posture active"
  }
}
