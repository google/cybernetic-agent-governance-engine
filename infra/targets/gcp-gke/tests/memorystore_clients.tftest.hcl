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

# Memorystore clients: an instance with IAM auth or TLS on refuses every client
# that cannot follow, so infra/modules/memorystore_valkey refuses to plan either
# mode while a client in its clients list cannot follow it. #788 drove the app
# instance from the governance switches, which staging turns on, while its one
# client, Langfuse, can do neither.
#
# The refusal is a precondition on the instance itself, so it runs in every
# plan that includes the instance, targeted or not, and a client cannot be
# planned without it. A root-level test cannot name a resource in a child
# module in expect_failures (the placement matrix below
# terraform_data.control_plane_access_guard in main.tf), so the module runs at
# the end show it refusing, as governance_persistence.tftest.hcl does for
# persistence. The root run checks what the staging profile plans.
# tests/infrastructure/test_memorystore_client_capability.py finds every client
# by reference and derives each clients list from the client blocks.
#
# Like governance_persistence.tftest.hcl, this file does not override the two
# Memorystore modules: each plans its real google_memorystore_instance against
# the mock provider, so the modes are read back from the planned resource. Mock
# providers only, so no credentials and no state. CI runs it in the
# terraform-test job:
#   terraform -chdir=infra/targets/gcp-gke test -var-file=staging.tfvars \
#     -var-file=tests/fixtures/image_digests.tfvars
#
# The key values below are test fixtures, not credentials.

mock_provider "google" {
  mock_data "google_monitoring_notification_channel" {
    defaults = {
      enabled = true
      name    = "projects/cage-test-project/notificationChannels/12345"
    }
  }
  mock_resource "google_container_cluster" {
    override_during = plan
    defaults = {
      endpoint    = "203.0.113.10"
      master_auth = [{ cluster_ca_certificate = "dGVzdA==", client_certificate = "", client_key = "", client_certificate_config = [] }]
    }
  }

  # Both instances' endpoints and the governance instance's managed CA must be
  # known at plan time: the target interpolates the endpoints into URLs, and the
  # governance clients count their CA ConfigMaps from the CA. Only computed
  # attributes the configuration leaves unset take these defaults, so the two
  # modes always come from the module inputs.
  mock_resource "google_memorystore_instance" {
    override_during = plan
    defaults = {
      endpoints = [{
        connections = [{
          psc_auto_connection = [{
            connection_type    = "CONNECTION_TYPE_PRIMARY"
            forwarding_rule    = "projects/clients-test-project/regions/us-central1/forwardingRules/test"
            ip_address         = "10.10.0.5"
            network            = "projects/clients-test-project/global/networks/default"
            port               = 6379
            project_id         = "clients-test-project"
            psc_connection_id  = "test"
            service_attachment = "projects/clients-test-project/regions/us-central1/serviceAttachments/test"
          }]
        }]
      }]
      managed_server_ca = [{ ca_certs = [{ certificates = ["-----BEGIN CERTIFICATE-----test-----END CERTIFICATE-----"] }] }]
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
    workload_identity_pool = "clients-test-project.svc.id.goog"
  }
}

variables {
  project_id          = "clients-test-project"
  evidence_project_id = "clients-evidence-project"
  authorized_networks = [{ cidr = "203.0.113.7/32", display_name = "test" }]

  # An enforcing posture needs distinct compliance telemetry keys (POAM-019).
  langfuse_compliance_public_key = "fake-compliance-public-key"
  langfuse_compliance_secret_key = "fake-compliance-secret-key"
}

# staging.tfvars as CI passes it: the governance instance requires IAM auth and
# TLS, the app instance neither, which is what live staging runs. The plan
# succeeding is itself the check that no listed client is locked out.
run "staging_keeps_the_app_instance_open_to_langfuse" {
  command = plan

  assert {
    condition = (
      module.memorystore_governance.authorization_mode == "IAM_AUTH" &&
      module.memorystore_governance.transit_encryption_mode == "SERVER_AUTHENTICATION"
    )
    error_message = "staging must plan the governance instance with IAM_AUTH and SERVER_AUTHENTICATION"
  }
  assert {
    condition = (
      module.memorystore_app.authorization_mode == "AUTH_DISABLED" &&
      module.memorystore_app.transit_encryption_mode == "TRANSIT_ENCRYPTION_DISABLED"
    )
    error_message = "staging must plan the app instance with AUTH_DISABLED and TRANSIT_ENCRYPTION_DISABLED: Langfuse can do neither IAM auth nor TLS"
  }
}

# ─── The module on its own ───────────────────────────────────────────────────
# Each refusing run turns on one mode only, so only one precondition can fail.

run "module_refuses_iam_auth_while_a_client_cannot_send_a_token" {
  command = plan

  module {
    source = "../../modules/memorystore_valkey"
  }

  variables {
    network_id              = "default"
    authorization_mode      = "IAM_AUTH"
    transit_encryption_mode = "TRANSIT_ENCRYPTION_DISABLED"
    clients = {
      "module.langfuse" = { iam_auth = false, tls = false }
    }
  }

  expect_failures = [google_memorystore_instance.instance]
}

run "module_refuses_tls_while_a_client_connects_in_plaintext" {
  command = plan

  module {
    source = "../../modules/memorystore_valkey"
  }

  variables {
    network_id              = "default"
    authorization_mode      = "AUTH_DISABLED"
    transit_encryption_mode = "SERVER_AUTHENTICATION"
    clients = {
      "module.langfuse" = { iam_auth = false, tls = false }
    }
  }

  expect_failures = [google_memorystore_instance.instance]
}

# One client that cannot follow is enough, whatever the others can do.
run "module_refuses_iam_auth_for_one_client_among_many" {
  command = plan

  module {
    source = "../../modules/memorystore_valkey"
  }

  variables {
    network_id              = "default"
    authorization_mode      = "IAM_AUTH"
    transit_encryption_mode = "TRANSIT_ENCRYPTION_DISABLED"
    clients = {
      "module.gateway"  = { iam_auth = true, tls = true }
      "module.langfuse" = { iam_auth = false, tls = false }
    }
  }

  expect_failures = [google_memorystore_instance.instance]
}

run "module_plans_both_modes_when_every_client_follows" {
  command = plan

  module {
    source = "../../modules/memorystore_valkey"
  }

  variables {
    network_id              = "default"
    authorization_mode      = "IAM_AUTH"
    transit_encryption_mode = "SERVER_AUTHENTICATION"
    clients = {
      "module.gateway"           = { iam_auth = true, tls = true }
      "module.compliance_bridge" = { iam_auth = true, tls = true }
    }
  }

  assert {
    condition     = output.authorization_mode == "IAM_AUTH" && output.transit_encryption_mode == "SERVER_AUTHENTICATION"
    error_message = "with every client able to follow, the module must plan IAM_AUTH and SERVER_AUTHENTICATION"
  }
}

run "module_keeps_a_client_that_cannot_follow_while_both_modes_are_off" {
  command = plan

  module {
    source = "../../modules/memorystore_valkey"
  }

  variables {
    network_id              = "default"
    authorization_mode      = "AUTH_DISABLED"
    transit_encryption_mode = "TRANSIT_ENCRYPTION_DISABLED"
    clients = {
      "module.langfuse" = { iam_auth = false, tls = false }
    }
  }

  assert {
    condition     = output.authorization_mode == "AUTH_DISABLED" && output.transit_encryption_mode == "TRANSIT_ENCRYPTION_DISABLED"
    error_message = "a client that can do neither must not stop an instance that requires neither"
  }
}
