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

# POAM-2026-132 / Probe #12: plan-time contracts for GPU pool total autoscaling,
# zero initial node count, and verified regional L4 + g2-standard-8 zones.

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
  project_id          = "gpu-pool-test-project"
  authorized_networks = [{ cidr = "203.0.113.7/32", display_name = "test" }]
}

run "staging_plans_real_gke_module_with_three_verified_zones" {
  command = plan

  assert {
    condition     = module.gke.gpu_node_pool_name == "gpu-node-pool-nvidia-l4"
    error_message = "staging must plan the real GPU node pool"
  }
  assert {
    condition = (
      [for p in module.gke.node_pools : p.initial_count if p.name == "gpu-l4"][0] == 0 &&
      [for p in module.gke.node_pools : p.min_count if p.name == "gpu-l4"][0] == 0 &&
      [for p in module.gke.node_pools : p.max_count if p.name == "gpu-l4"][0] == 2
    )
    error_message = "staging must pass initial=0, min=0, max=2 into module.gke"
  }
  assert {
    condition     = var.gpu_node_locations == tolist(["us-central1-a", "us-central1-b", "us-central1-c"])
    error_message = "staging must list all three verified us-central1 L4 zones"
  }
}

run "module_gpu_nodes_uses_total_autoscaling_not_per_zone" {
  command = plan

  module {
    source = "../../modules/gcp_gke_cluster"
  }

  variables {
    project_id          = "gpu-pool-test-project"
    region              = "us-central1"
    zone                = "us-central1-a"
    cluster_name        = "cage-gpu-test"
    environment         = "staging"
    authorized_networks = [{ cidr = "203.0.113.7/32", display_name = "test" }]
  }

  assert {
    condition     = google_container_node_pool.gpu_nodes[0].initial_node_count == 0
    error_message = "module default gpu_node_pool_initial_count must be 0"
  }
  assert {
    condition = (
      google_container_node_pool.gpu_nodes[0].autoscaling[0].total_min_node_count == 0 &&
      google_container_node_pool.gpu_nodes[0].autoscaling[0].total_max_node_count == 2 &&
      google_container_node_pool.gpu_nodes[0].autoscaling[0].location_policy == "ANY"
    )
    error_message = "gpu_nodes must configure total_min_node_count / total_max_node_count with location_policy = ANY"
  }
  assert {
    condition = (
      google_container_node_pool.gpu_nodes[0].autoscaling[0].min_node_count == null &&
      google_container_node_pool.gpu_nodes[0].autoscaling[0].max_node_count == null
    )
    error_message = "per-zone min_node_count / max_node_count must remain unset so zones do not multiply counts"
  }
  assert {
    condition     = google_container_node_pool.gpu_nodes[0].node_locations == toset(["us-central1-a", "us-central1-b", "us-central1-c"])
    error_message = "gpu_nodes must span all three verified us-central1 zones"
  }
}

run "europe_west1_d_is_refused_for_l4_pool" {
  command = plan

  module {
    source = "../../modules/gcp_gke_cluster"
  }

  variables {
    project_id          = "gpu-pool-test-project"
    region              = "europe-west1"
    zone                = "europe-west1-b"
    cluster_name        = "cage-eu-gpu-test"
    environment         = "dev"
    gpu_node_locations  = ["europe-west1-b", "europe-west1-c", "europe-west1-d"]
    authorized_networks = [{ cidr = "203.0.113.7/32", display_name = "test" }]
  }

  expect_failures = [google_container_node_pool.gpu_nodes]
}

run "europe_west1_b_and_c_succeed_for_l4_pool" {
  command = plan

  module {
    source = "../../modules/gcp_gke_cluster"
  }

  variables {
    project_id          = "gpu-pool-test-project"
    region              = "europe-west1"
    zone                = "europe-west1-b"
    cluster_name        = "cage-eu-gpu-test"
    environment         = "dev"
    gpu_node_locations  = ["europe-west1-b", "europe-west1-c"]
    authorized_networks = [{ cidr = "203.0.113.7/32", display_name = "test" }]
  }

  assert {
    condition     = google_container_node_pool.gpu_nodes[0].node_locations == toset(["europe-west1-b", "europe-west1-c"])
    error_message = "europe-west1-b and europe-west1-c must succeed for L4 + g2-standard-8"
  }
}

run "asia_southeast1_verified_zones_succeed_for_l4_pool" {
  command = plan

  module {
    source = "../../modules/gcp_gke_cluster"
  }

  variables {
    project_id              = "gpu-pool-test-project"
    region                  = "asia-southeast1"
    zone                    = "asia-southeast1-a"
    cluster_name            = "cage-apac-gpu-test"
    environment             = "prod"
    gpu_node_pool_min_count = 0
    gpu_node_pool_max_count = 5
    gpu_node_locations      = ["asia-southeast1-a", "asia-southeast1-b", "asia-southeast1-c"]
    authorized_networks     = [{ cidr = "203.0.113.7/32", display_name = "test" }]
  }

  assert {
    condition = (
      google_container_node_pool.gpu_nodes[0].initial_node_count == 0 &&
      google_container_node_pool.gpu_nodes[0].autoscaling[0].total_min_node_count == 0 &&
      google_container_node_pool.gpu_nodes[0].autoscaling[0].total_max_node_count == 5 &&
      google_container_node_pool.gpu_nodes[0].node_locations == toset(["asia-southeast1-a", "asia-southeast1-b", "asia-southeast1-c"])
    )
    error_message = "asia-southeast1 L4 pool must configure total 0..5 across -a/-b/-c"
  }
}

run "out_of_region_gpu_zone_is_refused" {
  command = plan

  module {
    source = "../../modules/gcp_gke_cluster"
  }

  variables {
    project_id          = "gpu-pool-test-project"
    region              = "asia-southeast1"
    zone                = "asia-southeast1-a"
    cluster_name        = "cage-apac-gpu-test"
    environment         = "dev"
    gpu_node_locations  = ["us-central1-a"]
    authorized_networks = [{ cidr = "203.0.113.7/32", display_name = "test" }]
  }

  expect_failures = [google_container_node_pool.gpu_nodes]
}
