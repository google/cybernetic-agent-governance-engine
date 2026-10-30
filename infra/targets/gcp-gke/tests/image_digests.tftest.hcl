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

# POAM-2026-131: image_digests has no default and no committed value. These runs
# pin what the variable must hold: every image the profile deploys and nothing it
# doesn't need, each pinned by a digest that is not a placeholder. Mock providers
# and module overrides only. CI runs it in the terraform-test job:
#   terraform -chdir=infra/targets/gcp-gke test -var-file=staging.tfvars \
#     -var-file=tests/fixtures/image_digests.tfvars

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
    workload_identity_pool = "digests-test-project.svc.id.goog"
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
  project_id          = "digests-test-project"
  authorized_networks = [{ cidr = "203.0.113.7/32", display_name = "test" }]

  # What staging deploys under inference_backend = "none" with the bridge on.
  core = {
    "gateway"           = "registry.invalid/cage-test/gateway@sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    "opa"               = "registry.invalid/cage-test/opa@sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    "agentsight-ui"     = "registry.invalid/cage-test/agentsight-ui@sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    "langfuse"          = "registry.invalid/cage-test/langfuse@sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    "langfuse-worker"   = "registry.invalid/cage-test/langfuse-worker@sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    "cloud-sql-proxy"   = "registry.invalid/cage-test/cloud-sql-proxy@sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    "clickhouse-server" = "registry.invalid/cage-test/clickhouse-server@sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    "clickhouse-keeper" = "registry.invalid/cage-test/clickhouse-keeper@sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    "compliance-bridge" = "registry.invalid/cage-test/compliance-bridge@sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
  }
}

run "staging_none_needs_only_the_images_it_deploys" {
  command = plan
  variables {
    image_digests = var.core
  }
  assert {
    condition = toset(local.required_image_digests) == toset([
      "gateway", "opa", "agentsight-ui", "langfuse", "langfuse-worker",
      "cloud-sql-proxy", "clickhouse-server", "clickhouse-keeper", "compliance-bridge",
    ])
    error_message = "staging under none must require exactly the images it deploys: no vLLM, advisor, NeMo or Presidio image"
  }
}

run "a_missing_deployed_image_is_refused" {
  command = plan
  variables {
    image_digests = { for k, v in var.core : k => v if k != "gateway" }
  }
  expect_failures = [var.image_digests]
}

run "vllm_requires_the_model_and_advisor_images" {
  command = plan
  variables {
    inference_backend = "vllm"
    image_digests     = var.core
  }
  expect_failures = [var.image_digests]
}

run "vllm_with_both_images_plans" {
  command = plan
  variables {
    inference_backend = "vllm"
    image_digests = merge(var.core, {
      "vllm-streamer"              = "registry.invalid/cage-test/vllm-streamer@sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
      "governed-financial-advisor" = "registry.invalid/cage-test/governed-financial-advisor@sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    })
  }
  assert {
    condition     = contains(local.required_image_digests, "vllm-streamer") && contains(local.required_image_digests, "governed-financial-advisor")
    error_message = "vllm must require the vLLM and advisor images"
  }
}

run "a_vllm_image_override_replaces_the_map_entry" {
  command = plan
  variables {
    inference_backend = "vllm"
    vllm_image        = "registry.invalid/cage-test/vllm-streamer@sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    image_digests = merge(var.core, {
      "governed-financial-advisor" = "registry.invalid/cage-test/governed-financial-advisor@sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    })
  }
  assert {
    condition     = !contains(local.required_image_digests, "vllm-streamer")
    error_message = "an explicit vllm_image must replace the vllm-streamer map entry"
  }
}

run "nemo_requires_its_server_and_presidio_images" {
  command = plan
  variables {
    inference_backend      = "vllm"
    enable_nemo_guardrails = true
    image_digests = merge(var.core, {
      "vllm-streamer"              = "registry.invalid/cage-test/vllm-streamer@sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
      "governed-financial-advisor" = "registry.invalid/cage-test/governed-financial-advisor@sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    })
  }
  expect_failures = [var.image_digests]
}

run "no_bridge_needs_no_bridge_image" {
  command = plan
  variables {
    enable_compliance_bridge = false
    image_digests            = { for k, v in var.core : k => v if k != "compliance-bridge" }
  }
  assert {
    condition     = !contains(local.required_image_digests, "compliance-bridge")
    error_message = "with the compliance bridge off, its image must not be required"
  }
}

run "the_empty_input_digest_is_refused" {
  command = plan
  variables {
    image_digests = merge(var.core, {
      "gateway" = "registry.invalid/cage-test/gateway@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    })
  }
  expect_failures = [var.image_digests]
}

run "a_tag_reference_is_refused" {
  command = plan
  variables {
    image_digests = merge(var.core, {
      "gateway" = "registry.invalid/cage-test/gateway:v1.2.3"
    })
  }
  expect_failures = [var.image_digests]
}
