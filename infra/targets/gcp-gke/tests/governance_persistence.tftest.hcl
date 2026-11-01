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

# POAM-2026-156 item 3 (SC-24): plan-time contracts of the governance Valkey
# instance's persistence. Whenever the posture enforces (local.enforcing_posture
# in main.tf: the prod and staging tiers always, dev only under a compliance
# flag), the governance instance plans AOF with append_fsync = ALWAYS, and
# otherwise an explicit DISABLED. The app instance always plans an explicit
# DISABLED. The profile runs read the committed .tfvars files and plan the
# tier, region and compliance flags each one sets, so an edit that would take
# AOF away from a profile fails here.
#
# Unlike the other files in this directory, this one does not override the two
# Memorystore modules. Each plans its real google_memorystore_instance against
# the mock provider, and the assertions read the persistence back from the
# planned resource through the module's outputs. The module runs at the end
# test infra/modules/memorystore_valkey on its own: its default, what it renders
# and what it refuses. Mock providers only, so no credentials and no state.
# CI's terraform-test job runs this file with the staging profile
# (.github/workflows/ci.yml).
#
# The key values below are test fixtures, not credentials.

mock_provider "google" {
  mock_resource "google_container_cluster" {
    override_during = plan
    defaults = {
      endpoint    = "203.0.113.10"
      master_auth = [{ cluster_ca_certificate = "dGVzdA==", client_certificate = "", client_key = "", client_certificate_config = [] }]
    }
  }

  # The plan needs both instances' endpoints and the governance instance's
  # managed CA known: the target interpolates the endpoints into URLs, and the
  # gateway and compliance-bridge modules count their CA ConfigMaps from the CA.
  # Only computed attributes the configuration leaves unset take these defaults.
  # persistence_config is deliberately not among them: it must come from the
  # module, or the assertions below fail.
  mock_resource "google_memorystore_instance" {
    override_during = plan
    defaults = {
      endpoints = [{
        connections = [{
          psc_auto_connection = [{
            connection_type    = "CONNECTION_TYPE_PRIMARY"
            forwarding_rule    = "projects/persistence-test-project/regions/us-central1/forwardingRules/test"
            ip_address         = "10.10.0.5"
            network            = "projects/persistence-test-project/global/networks/default"
            port               = 6379
            project_id         = "persistence-test-project"
            psc_connection_id  = "test"
            service_attachment = "projects/persistence-test-project/regions/us-central1/serviceAttachments/test"
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
    workload_identity_pool = "persistence-test-project.svc.id.goog"
  }
}

variables {
  project_id          = "persistence-test-project"
  authorized_networks = [{ cidr = "203.0.113.7/32", display_name = "test" }]

  # A compliance posture needs distinct compliance telemetry keys (POAM-019).
  langfuse_compliance_public_key = "fake-compliance-public-key"
  langfuse_compliance_secret_key = "fake-compliance-secret-key"

  # The committed profiles' top-level string and boolean settings, read from the
  # files themselves. Indented lines belong to nested blocks and are skipped.
  dev       = { for m in regexall("(?m)^([a-z_][a-z0-9_]*)[[:space:]]*=[[:space:]]*(\"[^\"]*\"|true|false)", file("dev.tfvars")) : m[0] => trim(m[1], "\"") }
  us_dev    = { for m in regexall("(?m)^([a-z_][a-z0-9_]*)[[:space:]]*=[[:space:]]*(\"[^\"]*\"|true|false)", file("us-dev.tfvars")) : m[0] => trim(m[1], "\"") }
  eu_dev    = { for m in regexall("(?m)^([a-z_][a-z0-9_]*)[[:space:]]*=[[:space:]]*(\"[^\"]*\"|true|false)", file("eu-dev.tfvars")) : m[0] => trim(m[1], "\"") }
  apac_dev  = { for m in regexall("(?m)^([a-z_][a-z0-9_]*)[[:space:]]*=[[:space:]]*(\"[^\"]*\"|true|false)", file("apac-dev.tfvars")) : m[0] => trim(m[1], "\"") }
  prod      = { for m in regexall("(?m)^([a-z_][a-z0-9_]*)[[:space:]]*=[[:space:]]*(\"[^\"]*\"|true|false)", file("prod.tfvars")) : m[0] => trim(m[1], "\"") }
  eu_prod   = { for m in regexall("(?m)^([a-z_][a-z0-9_]*)[[:space:]]*=[[:space:]]*(\"[^\"]*\"|true|false)", file("eu-prod.tfvars")) : m[0] => trim(m[1], "\"") }
  apac_prod = { for m in regexall("(?m)^([a-z_][a-z0-9_]*)[[:space:]]*=[[:space:]]*(\"[^\"]*\"|true|false)", file("apac-prod.tfvars")) : m[0] => trim(m[1], "\"") }
}

# ─── Staging: AOF, every write saved, as in prod ─────────────────────────────

# staging.tfvars as CI passes it, with no compliance flag set.
run "staging_profile_persists_governance_state_on_every_write" {
  command = plan

  assert {
    condition = (
      module.memorystore_governance.persistence_mode == "AOF" &&
      module.memorystore_governance.aof_append_fsync == "ALWAYS"
    )
    error_message = "staging must plan the governance instance with AOF and append_fsync = ALWAYS, as prod does, or it stops being a rehearsal of prod"
  }
  assert {
    condition     = module.memorystore_app.persistence_mode == "DISABLED"
    error_message = "the app instance must plan an explicit DISABLED"
  }
}

# What deploy_all.sh plans for US_FED staging: it injects enable_nist_compliance.
run "staging_with_injected_nist_flag_keeps_aof_always" {
  command = plan

  variables {
    enable_nist_compliance = true
  }

  assert {
    condition = (
      module.memorystore_governance.persistence_mode == "AOF" &&
      module.memorystore_governance.aof_append_fsync == "ALWAYS"
    )
    error_message = "staging must keep AOF with append_fsync = ALWAYS whatever the compliance flags say"
  }
  assert {
    condition     = module.memorystore_app.persistence_mode == "DISABLED"
    error_message = "the app instance must plan an explicit DISABLED"
  }
}

# ─── Prod: AOF, every write saved, in every committed prod profile ──────────

run "prod_profile_persists_governance_state_on_every_write" {
  command = plan

  variables {
    environment                = var.prod["environment"]
    region                     = var.prod["region"]
    zone                       = var.prod["zone"]
    cage_deployment_region     = var.prod["cage_deployment_region"]
    enable_nist_compliance     = lookup(var.prod, "enable_nist_compliance", "false") == "true"
    enable_eu_ecb_compliance   = lookup(var.prod, "enable_eu_ecb_compliance", "false") == "true"
    enable_apac_mas_compliance = lookup(var.prod, "enable_apac_mas_compliance", "false") == "true"
  }

  assert {
    condition = (
      module.memorystore_governance.persistence_mode == "AOF" &&
      module.memorystore_governance.aof_append_fsync == "ALWAYS"
    )
    error_message = "prod.tfvars must plan the governance instance with AOF and append_fsync = ALWAYS"
  }
  assert {
    condition     = module.memorystore_app.persistence_mode == "DISABLED"
    error_message = "prod.tfvars must plan the app instance with an explicit DISABLED"
  }
}

run "eu_prod_profile_persists_governance_state_on_every_write" {
  command = plan

  variables {
    environment                = var.eu_prod["environment"]
    region                     = var.eu_prod["region"]
    zone                       = var.eu_prod["zone"]
    cage_deployment_region     = var.eu_prod["cage_deployment_region"]
    enable_nist_compliance     = lookup(var.eu_prod, "enable_nist_compliance", "false") == "true"
    enable_eu_ecb_compliance   = lookup(var.eu_prod, "enable_eu_ecb_compliance", "false") == "true"
    enable_apac_mas_compliance = lookup(var.eu_prod, "enable_apac_mas_compliance", "false") == "true"
  }

  assert {
    condition = (
      module.memorystore_governance.persistence_mode == "AOF" &&
      module.memorystore_governance.aof_append_fsync == "ALWAYS"
    )
    error_message = "eu-prod.tfvars must plan the governance instance with AOF and append_fsync = ALWAYS"
  }
  assert {
    condition     = module.memorystore_app.persistence_mode == "DISABLED"
    error_message = "eu-prod.tfvars must plan the app instance with an explicit DISABLED"
  }
}

run "apac_prod_profile_persists_governance_state_on_every_write" {
  command = plan

  variables {
    environment                = var.apac_prod["environment"]
    region                     = var.apac_prod["region"]
    zone                       = var.apac_prod["zone"]
    cage_deployment_region     = var.apac_prod["cage_deployment_region"]
    enable_nist_compliance     = lookup(var.apac_prod, "enable_nist_compliance", "false") == "true"
    enable_eu_ecb_compliance   = lookup(var.apac_prod, "enable_eu_ecb_compliance", "false") == "true"
    enable_apac_mas_compliance = lookup(var.apac_prod, "enable_apac_mas_compliance", "false") == "true"
  }

  assert {
    condition = (
      module.memorystore_governance.persistence_mode == "AOF" &&
      module.memorystore_governance.aof_append_fsync == "ALWAYS"
    )
    error_message = "apac-prod.tfvars must plan the governance instance with AOF and append_fsync = ALWAYS"
  }
  assert {
    condition     = module.memorystore_app.persistence_mode == "DISABLED"
    error_message = "apac-prod.tfvars must plan the app instance with an explicit DISABLED"
  }
}

# The tier alone enforces in prod; it does not wait for a compliance flag.
run "prod_tier_without_compliance_flags_keeps_aof_always" {
  command = plan

  variables {
    environment = "prod"
  }

  assert {
    condition = (
      module.memorystore_governance.persistence_mode == "AOF" &&
      module.memorystore_governance.aof_append_fsync == "ALWAYS"
    )
    error_message = "the prod tier must plan AOF with append_fsync = ALWAYS with no compliance flag set"
  }
}

# ─── Dev, the default tier: AOF only under a compliance flag ─────────────────
# dev.tfvars sets neither region nor cage_deployment_region: deploy_all.sh takes
# them from .env, so these runs use US_FED's, which us-dev.tfvars names for the
# same cluster.

run "dev_profile_keeps_persistence_disabled" {
  command = plan

  variables {
    environment                = lookup(var.dev, "environment", "dev")
    region                     = lookup(var.dev, "region", "us-central1")
    zone                       = lookup(var.dev, "zone", "us-central1-a")
    cage_deployment_region     = lookup(var.dev, "cage_deployment_region", "US_FED")
    enable_nist_compliance     = lookup(var.dev, "enable_nist_compliance", "false") == "true"
    enable_eu_ecb_compliance   = lookup(var.dev, "enable_eu_ecb_compliance", "false") == "true"
    enable_apac_mas_compliance = lookup(var.dev, "enable_apac_mas_compliance", "false") == "true"
  }

  assert {
    condition     = module.memorystore_governance.persistence_mode == "DISABLED"
    error_message = "dev.tfvars sets no compliance flag, so the governance instance must plan an explicit DISABLED"
  }
  assert {
    condition     = module.memorystore_app.persistence_mode == "DISABLED"
    error_message = "dev.tfvars must plan the app instance with an explicit DISABLED"
  }
}

run "us_dev_profile_keeps_persistence_disabled" {
  command = plan

  variables {
    environment                = lookup(var.us_dev, "environment", "dev")
    region                     = lookup(var.us_dev, "region", "us-central1")
    zone                       = lookup(var.us_dev, "zone", "us-central1-a")
    cage_deployment_region     = lookup(var.us_dev, "cage_deployment_region", "US_FED")
    enable_nist_compliance     = lookup(var.us_dev, "enable_nist_compliance", "false") == "true"
    enable_eu_ecb_compliance   = lookup(var.us_dev, "enable_eu_ecb_compliance", "false") == "true"
    enable_apac_mas_compliance = lookup(var.us_dev, "enable_apac_mas_compliance", "false") == "true"
  }

  assert {
    condition     = module.memorystore_governance.persistence_mode == "DISABLED"
    error_message = "us-dev.tfvars sets no compliance flag, so the governance instance must plan an explicit DISABLED"
  }
  assert {
    condition     = module.memorystore_app.persistence_mode == "DISABLED"
    error_message = "us-dev.tfvars must plan the app instance with an explicit DISABLED"
  }
}

run "eu_dev_profile_persists_governance_state_on_every_write" {
  command = plan

  variables {
    environment                = lookup(var.eu_dev, "environment", "dev")
    region                     = var.eu_dev["region"]
    zone                       = var.eu_dev["zone"]
    cage_deployment_region     = var.eu_dev["cage_deployment_region"]
    enable_nist_compliance     = lookup(var.eu_dev, "enable_nist_compliance", "false") == "true"
    enable_eu_ecb_compliance   = lookup(var.eu_dev, "enable_eu_ecb_compliance", "false") == "true"
    enable_apac_mas_compliance = lookup(var.eu_dev, "enable_apac_mas_compliance", "false") == "true"
  }

  assert {
    condition = (
      module.memorystore_governance.persistence_mode == "AOF" &&
      module.memorystore_governance.aof_append_fsync == "ALWAYS"
    )
    error_message = "eu-dev.tfvars sets enable_eu_ecb_compliance, so the governance instance must plan AOF with append_fsync = ALWAYS"
  }
  assert {
    condition     = module.memorystore_app.persistence_mode == "DISABLED"
    error_message = "eu-dev.tfvars must plan the app instance with an explicit DISABLED"
  }
}

run "apac_dev_profile_persists_governance_state_on_every_write" {
  command = plan

  variables {
    environment                = lookup(var.apac_dev, "environment", "dev")
    region                     = var.apac_dev["region"]
    zone                       = var.apac_dev["zone"]
    cage_deployment_region     = var.apac_dev["cage_deployment_region"]
    enable_nist_compliance     = lookup(var.apac_dev, "enable_nist_compliance", "false") == "true"
    enable_eu_ecb_compliance   = lookup(var.apac_dev, "enable_eu_ecb_compliance", "false") == "true"
    enable_apac_mas_compliance = lookup(var.apac_dev, "enable_apac_mas_compliance", "false") == "true"
  }

  assert {
    condition = (
      module.memorystore_governance.persistence_mode == "AOF" &&
      module.memorystore_governance.aof_append_fsync == "ALWAYS"
    )
    error_message = "apac-dev.tfvars sets enable_apac_mas_compliance, so the governance instance must plan AOF with append_fsync = ALWAYS"
  }
  assert {
    condition     = module.memorystore_app.persistence_mode == "DISABLED"
    error_message = "apac-dev.tfvars must plan the app instance with an explicit DISABLED"
  }
}

# The NIST flag on the dev tier, which no committed dev profile sets.
run "dev_tier_with_nist_flag_persists_governance_state_on_every_write" {
  command = plan

  variables {
    environment            = "dev"
    enable_nist_compliance = true
  }

  assert {
    condition = (
      module.memorystore_governance.persistence_mode == "AOF" &&
      module.memorystore_governance.aof_append_fsync == "ALWAYS"
    )
    error_message = "a compliance flag on the dev tier must plan the governance instance with AOF and append_fsync = ALWAYS"
  }
  assert {
    condition     = module.memorystore_app.persistence_mode == "DISABLED"
    error_message = "the app instance must plan an explicit DISABLED under a compliance flag too"
  }
}

# ─── The module on its own ───────────────────────────────────────────────────
# Region and environment come from staging.tfvars, which CI passes to every run.

run "module_renders_an_explicit_disabled_by_default" {
  command = plan

  module {
    source = "../../modules/memorystore_valkey"
  }

  variables {
    network_id = "default"
  }

  assert {
    condition     = google_memorystore_instance.instance.persistence_config[0].mode == "DISABLED"
    error_message = "with no persistence input the module must render mode = DISABLED, not leave persistence to a default"
  }
}

run "module_renders_aof_with_the_fsync_policy_it_is_given" {
  command = plan

  module {
    source = "../../modules/memorystore_valkey"
  }

  variables {
    network_id       = "default"
    persistence_mode = "AOF"
    aof_append_fsync = "EVERY_SEC"
  }

  assert {
    condition = (
      google_memorystore_instance.instance.persistence_config[0].mode == "AOF" &&
      google_memorystore_instance.instance.persistence_config[0].aof_config[0].append_fsync == "EVERY_SEC"
    )
    error_message = "the module must render mode = AOF with the aof_config.append_fsync it is given"
  }
  assert {
    condition = (
      output.persistence_mode == "AOF" &&
      output.aof_append_fsync == "EVERY_SEC"
    )
    error_message = "the module's outputs must report the persistence the instance is planned with"
  }
}

run "module_refuses_rdb" {
  command = plan

  module {
    source = "../../modules/memorystore_valkey"
  }

  variables {
    network_id       = "default"
    persistence_mode = "RDB"
  }

  expect_failures = [var.persistence_mode]
}

run "module_refuses_the_gcloud_fsync_spelling" {
  command = plan

  module {
    source = "../../modules/memorystore_valkey"
  }

  variables {
    network_id       = "default"
    persistence_mode = "AOF"
    aof_append_fsync = "always"
  }

  expect_failures = [var.aof_append_fsync]
}

# AOF without a policy would run on the service's default fsync.
run "module_refuses_aof_without_a_fsync_policy" {
  command = plan

  module {
    source = "../../modules/memorystore_valkey"
  }

  variables {
    network_id       = "default"
    persistence_mode = "AOF"
  }

  expect_failures = [google_memorystore_instance.instance]
}

# A policy without AOF would persist nothing while reading as if it did.
run "module_refuses_a_fsync_policy_without_aof" {
  command = plan

  module {
    source = "../../modules/memorystore_valkey"
  }

  variables {
    network_id       = "default"
    aof_append_fsync = "ALWAYS"
  }

  expect_failures = [google_memorystore_instance.instance]
}
