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

# POAM-2026-173 & Step A3 (EF7a, EF7b, EF7c): plan-time contracts binding the
# five custom-VPC consumers (module.gke, module.service_mesh,
# module.cloudsql_postgres, module.memorystore_governance, and
# module.memorystore_app) to module.vpc_network in the create path and to
# var.network / var.subnetwork in the BYO path, while module.gcp_geap_advisor
# stays unchanged under POAM-2026-189.
#
# Mock providers only, so no credentials and no state. CI runs this file in
# the terraform-test job:
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

  mock_resource "google_memorystore_instance" {
    override_during = plan
    defaults = {
      endpoints = [{
        connections = [{
          psc_auto_connection = [{
            connection_type    = "CONNECTION_TYPE_PRIMARY"
            forwarding_rule    = "projects/cage-test-project/regions/us-central1/forwardingRules/test"
            ip_address         = "10.0.0.45"
            network            = "projects/cage-test-project/global/networks/cage-vpc-staging"
            port               = 6379
            project_id         = "cage-test-project"
            psc_connection_id  = "test"
            service_attachment = "projects/cage-test-project/regions/us-central1/serviceAttachments/test"
          }]
        }]
      }]
      managed_server_ca = [{ ca_certs = [{ certificates = ["-----BEGIN CERTIFICATE-----test-----END CERTIFICATE-----"] }] }]
    }
  }

  mock_resource "google_sql_database_instance" {
    override_during = plan
    defaults = {
      private_ip_address = "10.17.0.3"
    }
  }
}
mock_provider "helm" {}
mock_provider "kubernetes" {}
mock_provider "random" {}
mock_provider "time" {}

variables {
  project_id          = "cage-test-project"
  authorized_networks = [{ cidr = "203.0.113.7/32", display_name = "test" }]

  # staging.tfvars activates an enforcing posture, which needs distinct
  # compliance telemetry keys (POAM-019). Test fixtures, not credentials.
  langfuse_compliance_public_key = "fake-compliance-public-key"
  langfuse_compliance_secret_key = "fake-compliance-secret-key"
}

# ─── Run 1: Create path binds all five consumers to cage-vpc-staging ─────────

run "create_path_binds_five_consumers" {
  command = plan

  assert {
    condition = (
      length(module.vpc_network) == 1 &&
      module.vpc_network[0].network_name == "cage-vpc-staging" &&
      module.vpc_network[0].subnetwork_name == "cage-subnet-staging" &&
      module.vpc_network[0].private_service_access_network_name == "cage-vpc-staging" &&
      module.vpc_network[0].memorystore_psc_network_name == "cage-vpc-staging" &&
      module.vpc_network[0].pod_secondary_range_name == "gke-pods" &&
      module.vpc_network[0].service_secondary_range_name == "gke-services"
    )
    error_message = "module.vpc_network[0] must export the custom VPC, subnet, PSA/SCP readiness network names, and GKE secondary range names"
  }

  assert {
    condition = (
      module.vpc_network[0].memorystore_service_connection_policy_network == "projects/cage-test-project/global/networks/cage-vpc-staging" &&
      tolist(module.vpc_network[0].memorystore_service_connection_policy_subnetworks) == tolist(["projects/cage-test-project/regions/us-central1/subnetworks/cage-subnet-staging"])
    )
    error_message = "module.vpc_network[0] must provision the gcp-memorystore Service Connection Policy on cage-vpc-staging and cage-subnet-staging (EF7c)"
  }

  assert {
    condition = (
      module.gke.network == "cage-vpc-staging" &&
      module.gke.subnetwork == "cage-subnet-staging" &&
      module.gke.cluster_secondary_range_name == "gke-pods" &&
      module.gke.services_secondary_range_name == "gke-services"
    )
    error_message = "module.gke must bind to cage-vpc-staging, cage-subnet-staging, and the gke-pods / gke-services secondary ranges (VB-M5)"
  }

  assert {
    condition     = module.service_mesh.webhook_firewall_network == "cage-vpc-staging"
    error_message = "module.service_mesh must bind google_compute_firewall.mesh_webhooks to cage-vpc-staging"
  }

  assert {
    condition     = module.cloudsql_postgres.private_network == "projects/cage-test-project/global/networks/cage-vpc-staging"
    error_message = "module.cloudsql_postgres must bind private_network to projects/cage-test-project/global/networks/cage-vpc-staging"
  }

  assert {
    condition = (
      module.memorystore_governance.psc_network == "projects/cage-test-project/global/networks/cage-vpc-staging" &&
      module.memorystore_app.psc_network == "projects/cage-test-project/global/networks/cage-vpc-staging"
    )
    error_message = "both Memorystore Valkey instances must bind desired_auto_created_endpoints to projects/cage-test-project/global/networks/cage-vpc-staging"
  }
}

# ─── Run 2a: BYO VPC with existing named secondary ranges ────────────────────

run "byo_named_secondary_ranges" {
  command = plan

  variables {
    create_vpc_network            = false
    network                       = "byo-vpc"
    subnetwork                    = "byo-subnet"
    cluster_secondary_range_name  = "byo-pods"
    services_secondary_range_name = "byo-services"
    pod_cidr                      = null
    service_cidr                  = null
  }

  assert {
    condition     = length(module.vpc_network) == 0
    error_message = "create_vpc_network = false must not plan module.vpc_network"
  }

  assert {
    condition = (
      module.gke.network == "byo-vpc" &&
      module.gke.subnetwork == "byo-subnet" &&
      module.gke.cluster_secondary_range_name == "byo-pods" &&
      module.gke.services_secondary_range_name == "byo-services"
    )
    error_message = "BYO named-range mode must pass network, subnetwork, cluster_secondary_range_name, and services_secondary_range_name through to module.gke (VB-M3)"
  }

  assert {
    condition = (
      module.service_mesh.webhook_firewall_network == "byo-vpc" &&
      module.cloudsql_postgres.private_network == "projects/cage-test-project/global/networks/byo-vpc" &&
      module.memorystore_governance.psc_network == "projects/cage-test-project/global/networks/byo-vpc" &&
      module.memorystore_app.psc_network == "projects/cage-test-project/global/networks/byo-vpc"
    )
    error_message = "BYO mode must bind the webhook firewall, Cloud SQL, and both Memorystore instances to var.network"
  }
}

# ─── Run 2b: BYO VPC with GKE-allocated CIDR blocks ──────────────────────────

run "byo_cidr_blocks" {
  command = plan

  variables {
    create_vpc_network            = false
    network                       = "byo-vpc"
    subnetwork                    = "byo-subnet"
    cluster_secondary_range_name  = null
    services_secondary_range_name = null
    pod_cidr                      = "10.100.0.0/14"
    service_cidr                  = "10.104.0.0/20"
  }

  assert {
    condition     = length(module.vpc_network) == 0
    error_message = "create_vpc_network = false must not plan module.vpc_network"
  }

  assert {
    condition = (
      module.gke.network == "byo-vpc" &&
      module.gke.subnetwork == "byo-subnet" &&
      module.gke.cluster_ipv4_cidr_block == "10.100.0.0/14" &&
      module.gke.services_ipv4_cidr_block == "10.104.0.0/20"
    )
    error_message = "BYO CIDR mode must pass pod_cidr and service_cidr through to google_container_cluster.primary.ip_allocation_policy"
  }
}

# ─── Run 2c: Setting both a range name and a CIDR is refused (no discard) ────

run "named_range_refuses_discarded_cidr" {
  command = plan

  module {
    source = "../../modules/gcp_gke_cluster"
  }

  variables {
    project_id                    = "cage-test-project"
    region                        = "us-central1"
    zone                          = "us-central1-a"
    cluster_name                  = "cage-range-guard-test"
    environment                   = "staging"
    cluster_secondary_range_name  = "byo-pods"
    services_secondary_range_name = "byo-services"
    pod_cidr                      = "10.100.0.0/14"
    service_cidr                  = null
  }

  expect_failures = [google_container_cluster.primary]
}

run "services_named_range_refuses_discarded_cidr" {
  command = plan

  module {
    source = "../../modules/gcp_gke_cluster"
  }

  variables {
    project_id                    = "cage-test-project"
    region                        = "us-central1"
    zone                          = "us-central1-a"
    cluster_name                  = "cage-range-guard-test"
    environment                   = "staging"
    cluster_secondary_range_name  = "byo-pods"
    services_secondary_range_name = "byo-services"
    pod_cidr                      = null
    service_cidr                  = "10.104.0.0/20"
  }

  expect_failures = [google_container_cluster.primary]
}

# ─── Run 3: Memorystore module uses desired_auto_created_endpoints ───────────

run "memorystore_sets_desired_auto_created_endpoints" {
  command = plan

  module {
    source = "../../modules/memorystore_valkey"
  }

  variables {
    project_id  = "cage-test-project"
    environment = "staging"
    region      = "us-central1"
    network_id  = "cage-vpc-staging"
  }

  assert {
    condition = (
      length(google_memorystore_instance.instance.desired_auto_created_endpoints) == 1 &&
      google_memorystore_instance.instance.desired_auto_created_endpoints[0].network == "projects/cage-test-project/global/networks/cage-vpc-staging" &&
      google_memorystore_instance.instance.desired_auto_created_endpoints[0].project_id == "cage-test-project" &&
      output.psc_network == "projects/cage-test-project/global/networks/cage-vpc-staging"
    )
    error_message = "memorystore_valkey must configure desired_auto_created_endpoints with the full VPC network path and export psc_network (VB-M2)"
  }

  assert {
    condition     = length(google_memorystore_instance.instance.desired_psc_auto_connections) == 0
    error_message = "memorystore_valkey must not set the deprecated desired_psc_auto_connections block (VB-M2)"
  }
}

# ─── Run 4a / 4b: PSA and Memorystore SCP flags are independent ──────────────

run "psa_disabled_keeps_memorystore_scp_enabled" {
  command = plan

  module {
    source = "../../modules/vpc_network"
  }

  variables {
    project_id             = "cage-test-project"
    environment            = "staging"
    region                 = "us-central1"
    pod_cidr               = "10.100.0.0/14"
    service_cidr           = "10.104.0.0/20"
    enable_psa             = false
    enable_memorystore_psc = true
  }

  assert {
    condition = (
      length(google_compute_global_address.private_ip_alloc) == 0 &&
      length(google_service_networking_connection.private_service_access) == 0 &&
      length(google_network_connectivity_service_connection_policy.memorystore) == 1 &&
      output.private_service_access_network_name == null &&
      output.memorystore_psc_network_name == "cage-vpc-staging"
    )
    error_message = "disabling enable_psa must not disable google_network_connectivity_service_connection_policy.memorystore or memorystore_psc_network_name (VB-M1)"
  }
}

run "memorystore_scp_disabled_keeps_psa_enabled" {
  command = plan

  module {
    source = "../../modules/vpc_network"
  }

  variables {
    project_id             = "cage-test-project"
    environment            = "staging"
    region                 = "us-central1"
    pod_cidr               = "10.100.0.0/14"
    service_cidr           = "10.104.0.0/20"
    enable_psa             = true
    enable_memorystore_psc = false
  }

  assert {
    condition = (
      length(google_compute_global_address.private_ip_alloc) == 1 &&
      length(google_service_networking_connection.private_service_access) == 1 &&
      length(google_network_connectivity_service_connection_policy.memorystore) == 0 &&
      output.private_service_access_network_name == "cage-vpc-staging" &&
      output.memorystore_psc_network_name == null
    )
    error_message = "disabling enable_memorystore_psc must not disable PSA peering or private_service_access_network_name"
  }
}

# ─── Run 5: Data-store egress follows the endpoints across the VPC move ──────

run "datastore_egress_across_vpc_binding" {
  command = plan

  override_module {
    target = module.memorystore_governance
    outputs = {
      managed_server_ca     = ["-----BEGIN CERTIFICATE-----test-----END CERTIFICATE-----"]
      primary_endpoint_ip   = "10.0.0.45"
      primary_endpoint_port = 6379
      replica_count         = 1
    }
  }

  override_module {
    target = module.memorystore_app
    outputs = {
      primary_endpoint_ip   = "10.0.0.112"
      primary_endpoint_port = 6379
    }
  }

  override_module {
    target = module.cloudsql_postgres
    outputs = {
      connection_name                = "cage-test-project:us-central1:cage-postgres-staging"
      database_name                  = "langfuse"
      iam_user_name                  = "cage-langfuse@cage-test-project.iam"
      instance_id                    = "projects/cage-test-project/instances/cage-postgres-staging"
      instance_name                  = "cage-postgres-staging"
      point_in_time_recovery_enabled = true
      private_ip_address             = "10.17.0.3"
      private_network                = "projects/cage-test-project/global/networks/cage-vpc-staging"
      user_name                      = "cage-langfuse@cage-test-project.iam"
    }
  }

  assert {
    condition = (
      local.governance_valkey_cidr == "10.0.0.45/32" &&
      local.app_valkey_cidr == "10.0.0.112/32" &&
      local.cloud_sql_cidr == "10.17.0.3/32"
    )
    error_message = "derived data-store CIDRs must follow the custom-VPC endpoints in the create path"
  }

  assert {
    condition = (
      contains(flatten([for r in kubernetes_network_policy_v1.datastore_egress.spec[0].egress : [for t in r.to : t.ip_block[0].cidr]]), "10.0.0.45/32") &&
      contains(flatten([for r in kubernetes_network_policy_v1.datastore_egress.spec[0].egress : [for t in r.to : t.ip_block[0].cidr]]), "10.0.0.112/32") &&
      contains(flatten([for r in kubernetes_network_policy_v1.datastore_egress.spec[0].egress : [for t in r.to : t.ip_block[0].cidr]]), "10.17.0.3/32")
    )
    error_message = "kubernetes_network_policy_v1.datastore_egress must allow egress to the custom-VPC /32 endpoints"
  }

  assert {
    condition = length([
      for r in kubernetes_network_policy_v1.default_deny_external_egress.spec[0].egress : r
      if contains([for p in r.ports : tostring(p.port)], "6379") ||
      contains([for p in r.ports : tostring(p.port)], "5432") ||
      contains([for p in r.ports : tostring(p.port)], "3307")
    ]) == 0
    error_message = "default_deny_external_egress must remain independent of data-store endpoints across the VPC binding"
  }
}
