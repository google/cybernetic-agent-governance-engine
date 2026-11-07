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

  # staging.tfvars activates a compliance posture, which needs distinct
  # compliance telemetry keys (POAM-019). Test fixtures, not credentials.
  langfuse_compliance_public_key = "fake-compliance-public-key"
  langfuse_compliance_secret_key = "fake-compliance-secret-key"
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

run "kms_module_grants_cmek_to_memorystore_and_redis_p4sas" {
  command = plan

  module {
    source = "../../modules/kms"
  }

  assert {
    condition = (
      length(google_kms_crypto_key_iam_member.memorystore_agent) == 1 &&
      google_kms_crypto_key_iam_member.memorystore_agent[0].role == "roles/cloudkms.cryptoKeyEncrypterDecrypter" &&
      endswith(google_kms_crypto_key_iam_member.memorystore_agent[0].member, "@gcp-sa-memorystore.iam.gserviceaccount.com")
    )
    error_message = "module.kms must grant cryptoKeyEncrypterDecrypter to the Memorystore for Valkey P4SA (gcp-sa-memorystore)"
  }
  assert {
    condition = (
      length(google_kms_crypto_key_iam_member.redis_agent) == 1 &&
      google_kms_crypto_key_iam_member.redis_agent[0].role == "roles/cloudkms.cryptoKeyEncrypterDecrypter" &&
      endswith(google_kms_crypto_key_iam_member.redis_agent[0].member, "@cloud-redis.iam.gserviceaccount.com")
    )
    error_message = "module.kms must keep the cloud-redis P4SA CMEK grant"
  }
}

run "kms_module_respects_grant_service_agents_false" {
  command = plan

  module {
    source = "../../modules/kms"
  }

  variables {
    grant_service_agents = false
  }

  assert {
    condition     = length(google_kms_crypto_key_iam_member.memorystore_agent) == 0
    error_message = "grant_service_agents = false must omit google_kms_crypto_key_iam_member.memorystore_agent"
  }
}

run "compliance_bridge_artifactregistry_writer_uses_service_account_resource" {
  command = plan

  override_resource {
    target          = google_service_account.compliance_bridge
    override_during = plan
    values = {
      email = "cage-compliance-bridge@cage-test-project.iam.gserviceaccount.com"
      name  = "projects/cage-test-project/serviceAccounts/cage-compliance-bridge@cage-test-project.iam.gserviceaccount.com"
    }
  }

  override_data {
    target          = data.google_iam_policy.signing_key["compliance_evidence"]
    override_during = plan
    values = {
      policy_data = "{}"
    }
  }

  assert {
    condition     = google_service_account.compliance_bridge.account_id == "cage-compliance-bridge"
    error_message = "google_service_account.compliance_bridge account_id must be cage-compliance-bridge"
  }
  assert {
    condition = (
      google_project_iam_member.compliance_bridge_sa_artifactregistry_writer.role == "roles/artifactregistry.writer" &&
      google_project_iam_member.compliance_bridge_sa_artifactregistry_writer.member == "serviceAccount:cage-compliance-bridge@cage-test-project.iam.gserviceaccount.com"
    )
    error_message = "compliance_bridge_sa_artifactregistry_writer must reference google_service_account.compliance_bridge.email"
  }
}

run "gke_module_binds_dedicated_node_service_account_to_every_node_pool" {
  command = plan

  module {
    source = "../../modules/gcp_gke_cluster"
  }

  variables {
    project_id                    = "node-sa-test-project"
    region                        = "us-central1"
    zone                          = "us-central1-a"
    cluster_name                  = "cage-node-sa-test"
    environment                   = "staging"
    enable_general_spot_node_pool = true
    enable_gpu_node_pool          = true
    enable_clickhouse_node_pool   = true
    node_pools = [
      {
        name         = "custom-pool"
        machine_type = "e2-standard-4"
        min_count    = 0
        max_count    = 2
      }
    ]
  }

  assert {
    condition = (
      google_service_account.gke_nodes.account_id == "cage-gke-nodes-staging" &&
      output.node_service_account_email == "cage-gke-nodes-staging@node-sa-test-project.iam.gserviceaccount.com"
    )
    error_message = "module.gke must provision google_service_account.gke_nodes and output node_service_account_email"
  }

  assert {
    condition = (
      google_project_iam_member.gke_nodes_default_node_sa.role == "roles/container.defaultNodeServiceAccount" &&
      google_project_iam_member.gke_nodes_default_node_sa.member == "serviceAccount:cage-gke-nodes-staging@node-sa-test-project.iam.gserviceaccount.com" &&
      google_project_iam_member.gke_nodes_artifact_registry_reader.role == "roles/artifactregistry.reader" &&
      google_project_iam_member.gke_nodes_artifact_registry_reader.member == "serviceAccount:cage-gke-nodes-staging@node-sa-test-project.iam.gserviceaccount.com"
    )
    error_message = "module.gke must grant roles/container.defaultNodeServiceAccount and roles/artifactregistry.reader to the dedicated node GSA"
  }

  assert {
    condition = (
      google_container_cluster.primary.node_config[0].service_account == "cage-gke-nodes-staging@node-sa-test-project.iam.gserviceaccount.com" &&
      google_container_node_pool.primary_nodes.node_config[0].service_account == "cage-gke-nodes-staging@node-sa-test-project.iam.gserviceaccount.com" &&
      google_container_node_pool.general_spot_nodes[0].node_config[0].service_account == "cage-gke-nodes-staging@node-sa-test-project.iam.gserviceaccount.com" &&
      google_container_node_pool.gpu_nodes[0].node_config[0].service_account == "cage-gke-nodes-staging@node-sa-test-project.iam.gserviceaccount.com" &&
      google_container_node_pool.clickhouse_nodes[0].node_config[0].service_account == "cage-gke-nodes-staging@node-sa-test-project.iam.gserviceaccount.com" &&
      google_container_node_pool.extra_pools["custom-pool"].node_config[0].service_account == "cage-gke-nodes-staging@node-sa-test-project.iam.gserviceaccount.com"
    )
    error_message = "every GKE node_config block must bind the dedicated node service account"
  }

  # Decision A4 (POAM-2026-187): every node_config intentionally retains
  # oauth_scopes = ["https://www.googleapis.com/auth/cloud-platform"] alongside
  # the dedicated least-privilege node GSA (`cage-gke-nodes-staging`). In GCP,
  # effective VM permissions equal `OAuth scope ∩ IAM roles`; per Google's GKE
  # hardening guidance, setting `cloud-platform` avoids brittle legacy per-API
  # OAuth scope lists while bounding node permissions strictly through the two
  # IAM bindings verified above.
  assert {
    condition = (
      google_container_cluster.primary.node_config[0].oauth_scopes == toset(["https://www.googleapis.com/auth/cloud-platform"]) &&
      google_container_node_pool.primary_nodes.node_config[0].oauth_scopes == toset(["https://www.googleapis.com/auth/cloud-platform"]) &&
      google_container_node_pool.general_spot_nodes[0].node_config[0].oauth_scopes == toset(["https://www.googleapis.com/auth/cloud-platform"]) &&
      google_container_node_pool.gpu_nodes[0].node_config[0].oauth_scopes == toset(["https://www.googleapis.com/auth/cloud-platform"]) &&
      google_container_node_pool.clickhouse_nodes[0].node_config[0].oauth_scopes == toset(["https://www.googleapis.com/auth/cloud-platform"]) &&
      google_container_node_pool.extra_pools["custom-pool"].node_config[0].oauth_scopes == toset(["https://www.googleapis.com/auth/cloud-platform"])
    )
    error_message = "every GKE node_config block must retain cloud-platform oauth_scopes bounded by IAM (Decision A4)"
  }
}

run "datastore_egress_follows_endpoints" {
  command = plan

  override_module {
    target = module.memorystore_governance
    outputs = {
      managed_server_ca     = ["-----BEGIN CERTIFICATE-----test-----END CERTIFICATE-----"]
      primary_endpoint_ip   = "10.20.1.11"
      primary_endpoint_port = 6379
      replica_count         = 1
    }
  }

  override_module {
    target = module.memorystore_app
    outputs = {
      primary_endpoint_ip   = "10.20.2.22"
      primary_endpoint_port = 6379
    }
  }

  override_module {
    target = module.cloudsql_postgres
    outputs = {
      private_ip_address             = "10.20.3.33"
      connection_name                = "w6-test-project:us-central1:cage-postgres-staging"
      database_name                  = "langfuse"
      iam_user_name                  = "cage-langfuse@w6-test-project.iam"
      point_in_time_recovery_enabled = true
    }
  }

  assert {
    condition = (
      local.governance_valkey_cidr == "10.20.1.11/32" &&
      local.app_valkey_cidr == "10.20.2.22/32" &&
      local.cloud_sql_cidr == "10.20.3.33/32"
    )
    error_message = "derived data-store /32 locals must follow the live module endpoint outputs"
  }

  assert {
    condition = (
      toset(flatten([
        for r in kubernetes_network_policy_v1.datastore_egress.spec[0].egress : [
          for t in r.to : t.ip_block[0].cidr if length(t.ip_block) > 0
        ] if contains([for p in r.ports : p.port], "6379")
      ])) == toset(["10.20.1.11/32", "10.20.2.22/32"])
    )
    error_message = "kubernetes_network_policy_v1.datastore_egress must allow TCP 6379 to both Valkey /32 endpoints"
  }

  assert {
    condition = (
      toset(flatten([
        for r in kubernetes_network_policy_v1.datastore_egress.spec[0].egress : [
          for t in r.to : t.ip_block[0].cidr if length(t.ip_block) > 0
        ] if contains([for p in r.ports : p.port], "3307") && contains([for p in r.ports : p.port], "5432")
      ])) == toset(["10.20.3.33/32"])
    )
    error_message = "kubernetes_network_policy_v1.datastore_egress must allow TCP 3307 and 5432 to the Cloud SQL /32 endpoint"
  }

  assert {
    condition = (
      length([
        for r in kubernetes_network_policy_v1.default_deny_external_egress.spec[0].egress : r
        if anytrue([for p in r.ports : contains(["3307", "5432", "6379"], p.port)])
      ]) == 0
    )
    error_message = "kubernetes_network_policy_v1.default_deny_external_egress must hold no 3307/5432/6379 data-store rule (DE-M2)"
  }

  assert {
    condition = (
      toset(flatten([
        for r in kubernetes_network_policy_v1.gateway_egress_l3_l4.spec[0].egress : [
          for t in r.to : t.ip_block[0].cidr if length(t.ip_block) > 0
        ] if contains([for p in r.ports : p.port], "6379")
      ])) == toset(["10.20.1.11/32"]) &&
      toset(flatten([
        for r in kubernetes_network_policy_v1.compliance_bridge_egress_l3_l4.spec[0].egress : [
          for t in r.to : t.ip_block[0].cidr if length(t.ip_block) > 0
        ] if contains([for p in r.ports : p.port], "6379")
      ])) == toset(["10.20.1.11/32"]) &&
      toset(flatten([
        for r in kubernetes_network_policy_v1.financial_advisor_egress_internal_only.spec[0].egress : [
          for t in r.to : t.ip_block[0].cidr if length(t.ip_block) > 0
        ] if contains([for p in r.ports : p.port], "6379")
      ])) == toset(["10.20.2.22/32"]) &&
      toset(flatten([
        for r in kubernetes_network_policy_v1.reconciliation_worker_egress.spec[0].egress : [
          for t in r.to : t.ip_block[0].cidr if length(t.ip_block) > 0
        ] if contains([for p in r.ports : p.port], "6379")
      ])) == toset(["10.20.1.11/32"])
    )
    error_message = "per-workload NetworkPolicies must derive their Valkey /32 CIDRs from the governance and app endpoints"
  }
}
