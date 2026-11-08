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

# POAM-2026-198: Verify dynamic multi-domain OPA ConfigMap discovery in GKE.
# Asserts both positive and negative bundle membership across healthcare and
# finance domains, and verifies that stub domains without .rego policies
# (physical_ai) fail closed at terraform plan via the opa_policies precondition.

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
  project_id          = "domain-opa-policies-test-project"
  authorized_networks = [{ cidr = "203.0.113.7/32", display_name = "test" }]

  enforce_in_dev = false

  langfuse_compliance_public_key = "fake-compliance-public-key"
  langfuse_compliance_secret_key = "fake-compliance-secret-key"
}

run "healthcare_mounts_dosing_not_trade" {
  command = plan

  variables {
    cage_domain = "healthcare"
  }

  assert {
    condition     = contains(keys(module.opa.policy_files_data), "dosing_governance.rego")
    error_message = "healthcare domain must mount dosing_governance.rego"
  }

  assert {
    condition     = !contains(keys(module.opa.policy_files_data), "trade_governance.rego")
    error_message = "healthcare domain must not mount trade_governance.rego"
  }

  assert {
    condition     = !contains(keys(module.opa.policy_files_data), "dosing_governance_test.rego")
    error_message = "healthcare domain must exclude *_test.rego from the runtime OPA ConfigMap"
  }
}

run "finance_mounts_trade_not_dosing" {
  command = plan

  variables {
    cage_domain = "finance"
  }

  assert {
    condition     = contains(keys(module.opa.policy_files_data), "trade_governance.rego")
    error_message = "finance domain must mount trade_governance.rego"
  }

  assert {
    condition     = !contains(keys(module.opa.policy_files_data), "dosing_governance.rego")
    error_message = "finance domain must not mount dosing_governance.rego"
  }
}

run "physical_ai_stub_fails_precondition" {
  command = plan

  variables {
    cage_domain = "physical_ai"
  }

  expect_failures = [terraform_data.domain_opa_policies_guard]
}

run "opa_module_empty_policy_files_fails_precondition" {
  command = plan

  module {
    source = "../../modules/opa_policy"
  }

  variables {
    namespace    = "cage-system"
    policy_files = {}
  }

  expect_failures = [kubernetes_config_map.opa_policies]
}
