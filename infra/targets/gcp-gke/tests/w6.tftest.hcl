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

# W6 (AG-7): plan-time contracts of the gcp-gke target. What each inference
# backend deploys, and what the plan refuses. Mock providers and module
# overrides only, so no credentials and no state. CI runs it in the
# terraform-test job:
#   terraform -chdir=infra/targets/gcp-gke test -var-file=staging.tfvars

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
    workload_identity_pool = "w6-test-project.svc.id.goog"
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
  project_id          = "w6-test-project"
  authorized_networks = [{ cidr = "203.0.113.7/32", display_name = "test" }]
}

run "staging_none_deploys_no_model_workloads" {
  command = plan

  assert {
    condition     = length(module.vllm) == 0 && length(module.vllm_reasoning) == 0
    error_message = "inference_backend = none must deploy no vLLM"
  }
  assert {
    condition     = length(module.governed_advisor) == 0 && length(module.gcp_geap_advisor) == 0
    error_message = "inference_backend = none must deploy no advisor"
  }
  assert {
    condition     = length(module.nemo_guardrails) == 0
    error_message = "staging must deploy no NeMo server"
  }
  assert {
    condition     = local.vllm_fast_url == "" && local.vllm_reasoning_url == "" && local.vllm_api_key == ""
    error_message = "under none no workload is pointed at a model service"
  }
  assert {
    condition     = output.advisor_runtime == "none" && output.geap_agent_principal == ""
    error_message = "outputs must report the absent advisor"
  }
}

run "flip_to_vllm_brings_up_model_and_advisor" {
  command = plan
  variables {
    inference_backend = "vllm"
  }
  assert {
    condition     = length(module.vllm) == 1 && length(module.vllm_reasoning) == 1
    error_message = "vllm must deploy both vLLM services"
  }
  assert {
    condition     = length(module.gcp_geap_advisor) == 1 && length(module.governed_advisor) == 0
    error_message = "vllm must deploy the advisor on the configured runtime (geap by default)"
  }
  assert {
    condition     = local.vllm_api_key == "EMPTY" && startswith(local.vllm_fast_url, "http://vllm-service.")
    error_message = "vllm must give the gateway and bridge a URL and a non-empty key"
  }
}

run "vllm_on_gke_runtime" {
  command = plan
  variables {
    inference_backend = "vllm"
    advisor_runtime   = "gke"
  }
  assert {
    condition     = length(module.governed_advisor) == 1 && length(module.gcp_geap_advisor) == 0
    error_message = "advisor_runtime = gke must deploy the in-cluster advisor only"
  }
}

run "external_is_refused_on_gke" {
  command = plan
  variables {
    inference_backend = "external"
  }
  expect_failures = [var.inference_backend]
}

run "enable_vllm_true_fails_with_migration_message" {
  command = plan
  variables {
    enable_vllm = true
  }
  expect_failures = [var.enable_vllm]
}

run "enable_vllm_false_fails_too" {
  command = plan
  variables {
    enable_vllm = false
  }
  expect_failures = [var.enable_vllm]
}

run "vllm_without_gpu_pool_is_refused" {
  command = plan
  variables {
    inference_backend    = "vllm"
    enable_gpu_node_pool = false
  }
  expect_failures = [terraform_data.inference_backend_guard]
}

run "nemo_server_without_vllm_is_refused" {
  command = plan
  variables {
    enable_nemo_guardrails = true
  }
  expect_failures = [terraform_data.inference_backend_guard]
}

run "nemo_server_with_vllm_is_allowed" {
  command = plan
  variables {
    inference_backend      = "vllm"
    enable_nemo_guardrails = true
  }
  assert {
    condition     = length(module.nemo_guardrails) == 1
    error_message = "the optional NeMo server must still deploy when asked, under vllm"
  }
}

run "none_on_gke_runtime_deploys_no_advisor" {
  command = plan
  variables {
    advisor_runtime = "gke"
  }
  assert {
    condition     = length(module.governed_advisor) == 0 && length(module.gcp_geap_advisor) == 0
    error_message = "inference_backend = none must deploy no advisor on either runtime"
  }
}
