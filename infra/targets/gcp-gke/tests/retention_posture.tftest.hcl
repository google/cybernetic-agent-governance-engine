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

# POAM-2026-159 (AU-9 / AU-11): plan-time contracts of the retention posture the
# Langfuse event-upload bucket and the evidence WORM bucket share
# (local.retention_period_seconds and local.retention_locked in main.tf). Only
# the staging tier takes the one-day lock. Every committed prod profile, and
# every other tier, keeps 2555 days. The profile runs read the committed .tfvars
# files and plan the tier, region and compliance flags each one sets, so an edit
# that would hand a prod profile the short lock fails here. Mock providers and
# module overrides only, so no credentials and no state. CI's terraform-test job
# runs it with the staging profile (.github/workflows/ci.yml).
#
# An unset tier is the variable's default, dev, which the dev profile runs plan.
# CI passes staging.tfvars to every run, so no run can leave the tier unset:
# tests/infrastructure/test_clickhouse_operator.py pins the default instead. A
# null tier fails the plan in the variable's validation.
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
    workload_identity_pool = "retention-test-project.svc.id.goog"
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
  project_id          = "retention-test-project"
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

# ─── Staging: one day, locked, on both buckets, from one source ──────────────

# staging.tfvars as CI passes it, with no compliance flag set.
run "staging_profile_locks_both_buckets_for_one_day" {
  command = plan

  assert {
    condition     = local.retention_period_seconds == 86400 && local.retention_locked
    error_message = "staging must select the one-day locked retention"
  }
  assert {
    condition     = google_storage_bucket.langfuse_event_upload.retention_policy[0].retention_period == local.retention_period_seconds
    error_message = "the Langfuse event-upload bucket must take its retention period from local.retention_period_seconds"
  }
  assert {
    condition     = module.worm_bucket.retention_period_seconds == local.retention_period_seconds
    error_message = "the evidence WORM bucket must take its retention period from local.retention_period_seconds"
  }
  assert {
    condition = (
      google_storage_bucket.langfuse_event_upload.retention_policy[0].is_locked &&
      module.worm_bucket.retention_locked
    )
    error_message = "staging must lock both buckets, or an unlock would force the provider to replace them"
  }
}

# What deploy_all.sh plans for US_FED staging: it injects enable_nist_compliance.
# The lock must not depend on it, since turning a lock off replaces the bucket.
run "staging_with_injected_nist_flag_keeps_the_same_lock" {
  command = plan

  variables {
    enable_nist_compliance = true
  }

  assert {
    condition = (
      google_storage_bucket.langfuse_event_upload.retention_policy[0].retention_period == 86400 &&
      module.worm_bucket.retention_period_seconds == 86400
    )
    error_message = "staging must keep the one-day period whatever the compliance flags say"
  }
  assert {
    condition = (
      google_storage_bucket.langfuse_event_upload.retention_policy[0].is_locked &&
      module.worm_bucket.retention_locked
    )
    error_message = "staging must keep both buckets locked whatever the compliance flags say"
  }
}

# ─── Prod: 2555 days, locked, in every committed prod profile ────────────────

run "prod_profile_keeps_2555_days_locked" {
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
      google_storage_bucket.langfuse_event_upload.retention_policy[0].retention_period == 220752000 &&
      module.worm_bucket.retention_period_seconds == 220752000
    )
    error_message = "prod.tfvars must keep 2555 days on both buckets"
  }
  assert {
    condition = (
      google_storage_bucket.langfuse_event_upload.retention_policy[0].is_locked &&
      module.worm_bucket.retention_locked
    )
    error_message = "prod.tfvars must lock both buckets"
  }
}

run "eu_prod_profile_keeps_2555_days_locked" {
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
      google_storage_bucket.langfuse_event_upload.retention_policy[0].retention_period == 220752000 &&
      module.worm_bucket.retention_period_seconds == 220752000
    )
    error_message = "eu-prod.tfvars must keep 2555 days on both buckets"
  }
  assert {
    condition = (
      google_storage_bucket.langfuse_event_upload.retention_policy[0].is_locked &&
      module.worm_bucket.retention_locked
    )
    error_message = "eu-prod.tfvars must lock both buckets"
  }
}

run "apac_prod_profile_keeps_2555_days_locked" {
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
      google_storage_bucket.langfuse_event_upload.retention_policy[0].retention_period == 220752000 &&
      module.worm_bucket.retention_period_seconds == 220752000
    )
    error_message = "apac-prod.tfvars must keep 2555 days on both buckets"
  }
  assert {
    condition = (
      google_storage_bucket.langfuse_event_upload.retention_policy[0].is_locked &&
      module.worm_bucket.retention_locked
    )
    error_message = "apac-prod.tfvars must lock both buckets"
  }
}

# The tier alone locks prod; it does not wait for a compliance flag.
run "prod_tier_without_compliance_flags_keeps_2555_days_locked" {
  command = plan

  variables {
    environment = "prod"
  }

  assert {
    condition = (
      google_storage_bucket.langfuse_event_upload.retention_policy[0].retention_period == 220752000 &&
      module.worm_bucket.retention_period_seconds == 220752000
    )
    error_message = "the prod tier must keep 2555 days with no compliance flag set"
  }
  assert {
    condition = (
      google_storage_bucket.langfuse_event_upload.retention_policy[0].is_locked &&
      module.worm_bucket.retention_locked
    )
    error_message = "the prod tier must lock both buckets with no compliance flag set"
  }
}

# ─── Dev, the default tier: 2555 days, locked only under a compliance flag ───
# dev.tfvars sets neither region nor cage_deployment_region: deploy_all.sh takes
# them from .env, so these runs use US_FED's, which us-dev.tfvars names for the
# same cluster.

run "dev_profile_keeps_2555_days_unlocked" {
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
    condition = (
      google_storage_bucket.langfuse_event_upload.retention_policy[0].retention_period == 220752000 &&
      module.worm_bucket.retention_period_seconds == 220752000
    )
    error_message = "dev.tfvars must keep 2555 days on both buckets, never the staging period"
  }
  assert {
    condition = (
      !google_storage_bucket.langfuse_event_upload.retention_policy[0].is_locked &&
      !module.worm_bucket.retention_locked
    )
    error_message = "dev.tfvars sets no compliance flag, so neither bucket may be locked"
  }
}

run "us_dev_profile_keeps_2555_days_unlocked" {
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
    condition = (
      google_storage_bucket.langfuse_event_upload.retention_policy[0].retention_period == 220752000 &&
      module.worm_bucket.retention_period_seconds == 220752000
    )
    error_message = "us-dev.tfvars must keep 2555 days on both buckets, never the staging period"
  }
  assert {
    condition = (
      !google_storage_bucket.langfuse_event_upload.retention_policy[0].is_locked &&
      !module.worm_bucket.retention_locked
    )
    error_message = "us-dev.tfvars sets no compliance flag, so neither bucket may be locked"
  }
}

run "eu_dev_profile_keeps_2555_days_locked" {
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
      google_storage_bucket.langfuse_event_upload.retention_policy[0].retention_period == 220752000 &&
      module.worm_bucket.retention_period_seconds == 220752000
    )
    error_message = "eu-dev.tfvars must keep 2555 days on both buckets, never the staging period"
  }
  assert {
    condition = (
      google_storage_bucket.langfuse_event_upload.retention_policy[0].is_locked &&
      module.worm_bucket.retention_locked
    )
    error_message = "eu-dev.tfvars sets enable_eu_ecb_compliance, so both buckets must be locked"
  }
}

run "apac_dev_profile_keeps_2555_days_locked" {
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
      google_storage_bucket.langfuse_event_upload.retention_policy[0].retention_period == 220752000 &&
      module.worm_bucket.retention_period_seconds == 220752000
    )
    error_message = "apac-dev.tfvars must keep 2555 days on both buckets, never the staging period"
  }
  assert {
    condition = (
      google_storage_bucket.langfuse_event_upload.retention_policy[0].is_locked &&
      module.worm_bucket.retention_locked
    )
    error_message = "apac-dev.tfvars sets enable_apac_mas_compliance, so both buckets must be locked"
  }
}

# ─── Unknown tiers: refused before any bucket is planned ─────────────────────

run "unknown_tier_is_refused" {
  command = plan

  variables {
    environment = "qa"
  }

  expect_failures = [var.environment]
}

# The short lock needs the exact tier: a near miss is refused, not folded into it.
run "near_miss_staging_spelling_is_refused" {
  command = plan

  variables {
    environment = "Staging"
  }

  expect_failures = [var.environment]
}
