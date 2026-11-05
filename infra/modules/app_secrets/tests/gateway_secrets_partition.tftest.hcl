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

# Plan-time contract of the R-2 / F-43 / F-84 gateway/advisor secret split and
# telemetry-key precondition on kubernetes_secret.gateway_secrets.

mock_provider "kubernetes" {}

variables {
  namespace              = "governance-stack"
  salt                   = "test-langfuse-salt-value-32chars!!"
  governance_salt        = "test-governance-salt-value-32chars"
  cage_api_key           = "test-advisor-api-key-distinct"
  cage_internal_token    = "test-bridge-internal-token-distinct"
  langfuse_host          = "http://langfuse-web:3000"
  database_url           = "postgresql://app:pw@10.10.0.9:5432/langfuse"
  nextauth_secret        = "test-nextauth-secret"
  nextauth_url           = "https://langfuse.cage.example"
  cage_deployment_region = "US_FED"

  cage_env                    = "staging"
  langfuse_public_key         = "fake-advisor-telemetry-public"
  langfuse_secret_key         = "fake-advisor-telemetry-secret"
  gateway_langfuse_public_key = "fake-gateway-telemetry-public"
  gateway_langfuse_secret_key = "fake-gateway-telemetry-secret"
}

run "distinct_gateway_and_advisor_secrets_plan_and_omit_internal_token_from_advisor" {
  command = plan

  assert {
    condition     = !contains(keys(nonsensitive(kubernetes_secret.advisor_secrets.data)), "CAGE_INTERNAL_TOKEN")
    error_message = "advisor-secrets must never contain CAGE_INTERNAL_TOKEN (F-43)"
  }
  assert {
    condition     = nonsensitive(kubernetes_secret.gateway_secrets.data["TELEMETRY_PUBLIC_KEY"]) == "fake-gateway-telemetry-public"
    error_message = "gateway-secrets must bind gateway_langfuse_public_key"
  }
}

run "enforcing_shared_public_telemetry_key_is_refused" {
  command = plan

  variables {
    gateway_langfuse_public_key = "fake-advisor-telemetry-public"
  }

  expect_failures = [
    kubernetes_secret.gateway_secrets,
  ]
}

run "enforcing_shared_secret_telemetry_key_is_refused" {
  command = plan

  variables {
    gateway_langfuse_secret_key = "fake-advisor-telemetry-secret"
  }

  expect_failures = [
    kubernetes_secret.gateway_secrets,
  ]
}

run "enforcing_empty_gateway_telemetry_key_is_refused" {
  command = plan

  variables {
    gateway_langfuse_public_key = ""
  }

  expect_failures = [
    kubernetes_secret.gateway_secrets,
  ]
}

run "development_posture_allows_empty_gateway_telemetry_keys" {
  command = plan

  variables {
    cage_env                    = "development"
    gateway_langfuse_public_key = ""
    gateway_langfuse_secret_key = ""
  }

  assert {
    condition     = kubernetes_secret.gateway_secrets.metadata[0].name == "gateway-secrets"
    error_message = "development posture must allow empty gateway telemetry keys"
  }
}
