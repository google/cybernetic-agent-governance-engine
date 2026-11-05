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

# POAM-2026-196 & R-2 / F-84 root-level gcp-gke wiring contract tests.
# Child-module resource precondition refusal cases live in:
#   - infra/modules/compliance_bridge/tests/operator_identity.tftest.hcl
#   - infra/modules/app_secrets/tests/gateway_secrets_partition.tftest.hcl
# per the POAM-2026-180 guard placement matrix in infra/targets/gcp-gke/main.tf.

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
    workload_identity_pool = "hitl-test-project.svc.id.goog"
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
  project_id                     = "hitl-test-project"
  authorized_networks            = [{ cidr = "203.0.113.7/32", display_name = "test" }]
  langfuse_compliance_public_key = "fake-compliance-public-key"
  langfuse_compliance_secret_key = "fake-compliance-secret-key"
}

run "staging_default_auto_generates_distinct_gateway_and_advisor_telemetry_keys" {
  command = plan

  assert {
    condition     = length(var.trusted_operator_identities) == 2
    error_message = "staging.tfvars must supply two human operator OIDC principals for 2-of-2 quorum"
  }
  assert {
    condition     = startswith(var.operator_jwks_uri, "https://") && startswith(var.operator_oidc_issuer, "https://")
    error_message = "staging.tfvars must supply https:// operator_oidc_issuer and operator_jwks_uri"
  }
  assert {
    condition     = random_password.gateway_telemetry_public_key.length == 32 && random_password.gateway_telemetry_secret_key.length == 32
    error_message = "root module must provision independent random_password resources for gateway and advisor telemetry keys"
  }
}

run "staging_explicit_distinct_gateway_and_advisor_telemetry_keys_succeeds" {
  command = plan

  variables {
    langfuse_public_key         = "fake-advisor-public-key"
    langfuse_secret_key         = "fake-advisor-secret-key"
    gateway_langfuse_public_key = "fake-gateway-public-key"
    gateway_langfuse_secret_key = "fake-gateway-secret-key"
  }

  assert {
    condition     = module.app_secrets != null && length(module.compliance_bridge) == 1
    error_message = "app_secrets and compliance_bridge must plan cleanly when distinct telemetry keys and human operators are supplied"
  }
}
