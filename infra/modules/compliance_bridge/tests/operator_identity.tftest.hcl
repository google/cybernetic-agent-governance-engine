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

# Plan-time contract of the POAM-2026-196 HITL human operator precondition on
# kubernetes_deployment.compliance_bridge. Tested from the module's own test
# directory per the POAM-2026-180 placement matrix in infra/targets/gcp-gke/main.tf.

mock_provider "kubernetes" {}
mock_provider "helm" {}

variables {
  namespace                  = "governance-stack"
  image                      = "us-central1-docker.pkg.dev/hitl-test-project/cage-images/compliance-bridge@sha256:0000000000000000000000000000000000000000000000000000000000000001"
  service_account_name       = "cage-compliance-bridge-sa"
  vllm_base_url              = "http://vllm-inference:8000/v1"
  vllm_api_key               = "not-needed"
  oscal_s3_bucket            = "cage-oscal-staging"
  oscal_s3_region            = "us-central1"
  evidence_stream_redis_url  = "rediss://10.10.0.5:6379"
  evidence_stream_redis_db   = 0
  evidence_stream_key        = "cage:evidence:stream"
  enable_redis_tls           = true
  redis_ca_pem               = "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n"
  deployment_config_map_name = "cage-deployment"

  cage_env                    = "staging"
  trusted_operator_identities = ["risk-officer-1@cage.example", "risk-officer-2@cage.example"]
  operator_oidc_issuer        = "https://idp.cage.example"
  operator_oidc_audience      = "cage-compliance-bridge"
  operator_jwks_uri           = "https://idp.cage.example/.well-known/jwks.json"
}

run "enforcing_valid_human_operator_identities_plans" {
  command = plan

  assert {
    condition     = kubernetes_deployment.compliance_bridge.metadata[0].name == "compliance-bridge"
    error_message = "compliance-bridge deployment must plan cleanly when human operator OIDC config is valid"
  }
}

run "enforcing_empty_operator_identities_is_refused" {
  command = plan

  variables {
    trusted_operator_identities = []
  }

  expect_failures = [
    kubernetes_deployment.compliance_bridge,
  ]
}

run "enforcing_spiffe_workload_operator_identity_is_refused" {
  command = plan

  variables {
    trusted_operator_identities = [
      "spiffe://cluster.local/ns/governance-stack/sa/governed-financial-advisor",
    ]
  }

  expect_failures = [
    kubernetes_deployment.compliance_bridge,
  ]
}

run "enforcing_linkerd_workload_operator_identity_is_refused" {
  command = plan

  variables {
    trusted_operator_identities = [
      "cage-advisor-sa.governance-stack.serviceaccount.identity.linkerd.cluster.local",
    ]
  }

  expect_failures = [
    kubernetes_deployment.compliance_bridge,
  ]
}

run "enforcing_non_https_operator_jwks_uri_is_refused" {
  command = plan

  variables {
    operator_jwks_uri = "http://idp.cage.example/.well-known/jwks.json"
  }

  expect_failures = [
    kubernetes_deployment.compliance_bridge,
  ]
}

run "development_posture_allows_empty_operator_identities" {
  command = plan

  variables {
    cage_env                    = "development"
    trusted_operator_identities = []
    operator_oidc_issuer        = ""
    operator_jwks_uri           = ""
  }

  assert {
    condition     = kubernetes_deployment.compliance_bridge.metadata[0].name == "compliance-bridge"
    error_message = "development posture must allow empty operator OIDC config"
  }
}
