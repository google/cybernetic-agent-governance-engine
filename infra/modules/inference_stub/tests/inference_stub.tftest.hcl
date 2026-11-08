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

# Plan-time contracts of infra/modules/inference_stub (POAM-2026-191, F-34,
# POAM-2026-180). Mock kubernetes provider only; CI executes this in the
# terraform-test job:
#   terraform -chdir=infra/modules/inference_stub test

mock_provider "kubernetes" {}

variables {
  namespace            = "governance-stack"
  image                = "registry.invalid/cage-test/gateway@sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
  environment          = "staging"
  service_account_name = "cage-inference-stub-sa"
}

run "staging_plans_hardened_stub_deployment_and_service" {
  command = plan

  assert {
    condition     = kubernetes_deployment_v1.inference_stub.metadata[0].name == "inference-stub"
    error_message = "inference_stub module must plan the inference-stub Deployment in staging"
  }
  assert {
    condition = (
      kubernetes_deployment_v1.inference_stub.spec[0].template[0].spec[0].service_account_name == "cage-inference-stub-sa" &&
      kubernetes_deployment_v1.inference_stub.spec[0].template[0].spec[0].automount_service_account_token == false
    )
    error_message = "inference_stub pod must run under its dedicated KSA"
  }
  assert {
    condition     = tolist(kubernetes_deployment_v1.inference_stub.spec[0].template[0].spec[0].container[0].command) == tolist(["python", "-m", "src.integrations.inference_stub.server"])
    error_message = "inference_stub container must invoke src.integrations.inference_stub.server"
  }
  assert {
    condition = (
      kubernetes_deployment_v1.inference_stub.spec[0].template[0].spec[0].container[0].security_context[0].run_as_non_root == true &&
      tonumber(kubernetes_deployment_v1.inference_stub.spec[0].template[0].spec[0].container[0].security_context[0].run_as_user) == 1000 &&
      kubernetes_deployment_v1.inference_stub.spec[0].template[0].spec[0].container[0].security_context[0].read_only_root_filesystem == true &&
      kubernetes_deployment_v1.inference_stub.spec[0].template[0].spec[0].container[0].security_context[0].allow_privilege_escalation == false
    )
    error_message = "inference_stub container must satisfy PSA restricted non-root read-only securityContext"
  }
  assert {
    condition = (
      kubernetes_service_v1.inference_stub.metadata[0].name == "inference-stub" &&
      kubernetes_service_v1.inference_stub.spec[0].port[0].port == 8000
    )
    error_message = "inference_stub Service must expose ClusterIP port 8000"
  }
}

run "prod_environment_refused_by_deployment_precondition" {
  command = plan

  variables {
    environment = "prod"
  }

  expect_failures = [kubernetes_deployment_v1.inference_stub]
}

run "production_environment_refused_by_deployment_precondition" {
  command = plan

  variables {
    environment = "production"
  }

  expect_failures = [kubernetes_deployment_v1.inference_stub]
}

run "retired_shared_service_account_refused" {
  command = plan

  variables {
    service_account_name = "financial-advisor-sa"
  }

  expect_failures = [var.service_account_name]
}

run "empty_service_account_refused" {
  command = plan

  variables {
    service_account_name = ""
  }

  expect_failures = [var.service_account_name]
}
