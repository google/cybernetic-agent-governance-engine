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

# POAM-2026-164 EF4 / EF5 / EF6:
# Offline plan-time contract verification for Stage 1 -> Stage 2 clean-project
# ordering without overriding module.memorystore_governance,
# module.memorystore_app, module.cloudsql_postgres, or module.gke.
#
# Note on offline vs live scope:
# - EF5 (deterministic kubernetes_config_map_v1.redis_ca count when
#   module.memorystore_governance.managed_server_ca is unknown) IS proven here
#   by omitting override_module on memorystore_governance.
# - Mock kubernetes/helm providers do not open live TLS/OpenAPI sockets, so live
#   provider client behavior for EF4 (pre-Stage-1 `terraform import`) and EF6
#   (Stage 2 plan against the real Stage 1 GKE cluster) still requires the
#   post-Step-A3 live clean-project walk.

mock_provider "google" {
  mock_data "google_monitoring_notification_channel" {
    defaults = {
      enabled = true
      name    = "projects/cage-test-project/notificationChannels/12345"
    }
  }
}
mock_provider "helm" {}
mock_provider "kubernetes" {}
mock_provider "random" {}

variables {
  project_id          = "bootstrap-order-test-project"
  authorized_networks = [{ cidr = "203.0.113.7/32", display_name = "test" }]

  langfuse_compliance_public_key = "fake-compliance-public-key"
  langfuse_compliance_secret_key = "fake-compliance-secret-key"
}

run "stage2_plan_with_unknown_memorystore_ca_resolves_redis_ca_counts_ef5" {
  command = plan

  assert {
    condition     = var.enable_memorystore_tls
    error_message = "staging.tfvars must enable Memorystore TLS so EF5 count determinism is exercised"
  }
  assert {
    condition     = var.bootstrap_without_cluster == false
    error_message = "bootstrap_without_cluster must default to false outside Stage 1 bootstrap/import"
  }
  assert {
    condition     = module.gateway.service_name != ""
    error_message = "EF5 regression: module.gateway (and redis_ca counts) must plan cleanly when module.memorystore_governance.managed_server_ca is unknown"
  }
  assert {
    condition     = length(local.fqdn_network_policies) > 0
    error_message = "EF6 contract: local.fqdn_network_policies keys must resolve deterministically at plan time"
  }
}

run "bootstrap_without_cluster_flag_plans_cleanly_for_stage1_and_import_ef4" {
  command = plan

  variables {
    bootstrap_without_cluster = true
  }

  assert {
    condition     = var.bootstrap_without_cluster == true
    error_message = "bootstrap_without_cluster must accept true during --import-state and Stage 1 foundation apply"
  }
}
