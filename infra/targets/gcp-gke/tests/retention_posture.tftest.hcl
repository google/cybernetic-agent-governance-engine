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

# POAM-2026-159 & INF-02 (AU-9 / AU-11): plan-time contracts of data-class WORM
# retention (local.telemetry_retention_period_seconds, local.evidence_retention_period_seconds,
# local.retention_locked) and workload CAGE_ENV (local.effective_cage_env). Prod
# locks both classes for 2555d; non-prod cross-project custody or certification_mode
# locks evidence for 2555d while keeping telemetry at 1d; ordinary non-prod locks
# both for 1d; permissive dev keeps 2555d unlocked. Profile runs read committed
# .tfvars files directly. Mock providers and module overrides only, so no state.
# CI's terraform-test job runs this suite with the staging profile
# (.github/workflows/ci.yml).
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
  evidence_project_id = null
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

# staging.tfvars as CI passes it.
run "staging_profile_locks_both_buckets_for_one_day" {
  command = plan

  assert {
    condition     = local.telemetry_retention_period_seconds == 86400 && local.evidence_retention_period_seconds == 86400 && local.retention_locked
    error_message = "ordinary single-project staging must select the one-day locked retention across both data classes"
  }
  assert {
    condition     = google_storage_bucket.langfuse_event_upload.retention_policy[0].retention_period == local.telemetry_retention_period_seconds
    error_message = "the Langfuse event-upload bucket must take its retention period from local.telemetry_retention_period_seconds"
  }
  assert {
    condition     = module.worm_bucket.retention_period_seconds == local.evidence_retention_period_seconds
    error_message = "the evidence WORM bucket must take its retention period from local.evidence_retention_period_seconds"
  }
  assert {
    condition = (
      google_storage_bucket.langfuse_event_upload.retention_policy[0].is_locked &&
      module.worm_bucket.retention_locked
    )
    error_message = "staging must lock both buckets, or an unlock would force the provider to replace them"
  }
  assert {
    condition = (
      local.effective_cage_env == "staging" &&
      output.deployment_summary.effective_cage_env == "staging" &&
      one([for e in kubernetes_deployment_v1.gateway_canary[0].spec[0].template[0].spec[0].container[0].env : e.value if e.name == "CAGE_ENV"]) == "staging"
    )
    error_message = "staging must set effective_cage_env = 'staging' across workload pods"
  }
}

# The staging tier with enforce_in_dev forced off. The lock must not depend
# on enforce_in_dev, since turning a lock off replaces the bucket.
run "staging_without_nist_flag_keeps_the_same_lock" {
  command = plan

  variables {
    enforce_in_dev = false
  }

  assert {
    condition = (
      google_storage_bucket.langfuse_event_upload.retention_policy[0].retention_period == 86400 &&
      module.worm_bucket.retention_period_seconds == 86400
    )
    error_message = "staging must keep the one-day period whatever enforce_in_dev says"
  }
  assert {
    condition = (
      google_storage_bucket.langfuse_event_upload.retention_policy[0].is_locked &&
      module.worm_bucket.retention_locked &&
      local.effective_cage_env == "staging"
    )
    error_message = "staging must keep both buckets locked and effective_cage_env = 'staging' whatever enforce_in_dev says"
  }
}

# ─── Prod: 2555 days, locked, in every committed prod profile ────────────────

run "prod_profile_keeps_2555_days_locked" {
  command = plan

  variables {
    environment            = var.prod["environment"]
    region                 = var.prod["region"]
    zone                   = var.prod["zone"]
    cage_deployment_region = var.prod["cage_deployment_region"]
    enforce_in_dev         = lookup(var.prod, "enforce_in_dev", "false") == "true"
    evidence_project_id    = "retention-evidence-project"
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
  assert {
    condition = (
      local.effective_cage_env == "prod" &&
      output.deployment_summary.effective_cage_env == "prod" &&
      one([for e in kubernetes_deployment_v1.gateway_canary[0].spec[0].template[0].spec[0].container[0].env : e.value if e.name == "CAGE_ENV"]) == "prod"
    )
    error_message = "prod.tfvars must keep effective_cage_env = 'prod' across workload pods"
  }
}

run "eu_prod_profile_keeps_2555_days_locked" {
  command = plan

  variables {
    environment            = var.eu_prod["environment"]
    region                 = var.eu_prod["region"]
    zone                   = var.eu_prod["zone"]
    cage_deployment_region = var.eu_prod["cage_deployment_region"]
    enforce_in_dev         = lookup(var.eu_prod, "enforce_in_dev", "false") == "true"
    evidence_project_id    = "retention-evidence-project"
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
  assert {
    condition     = local.effective_cage_env == "prod" && output.deployment_summary.effective_cage_env == "prod"
    error_message = "eu-prod.tfvars must keep effective_cage_env = 'prod'"
  }
}

run "apac_prod_profile_keeps_2555_days_locked" {
  command = plan

  variables {
    environment            = var.apac_prod["environment"]
    region                 = var.apac_prod["region"]
    zone                   = var.apac_prod["zone"]
    cage_deployment_region = var.apac_prod["cage_deployment_region"]
    enforce_in_dev         = lookup(var.apac_prod, "enforce_in_dev", "false") == "true"
    evidence_project_id    = "retention-evidence-project"
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
  assert {
    condition     = local.effective_cage_env == "prod" && output.deployment_summary.effective_cage_env == "prod"
    error_message = "apac-prod.tfvars must keep effective_cage_env = 'prod'"
  }
}

# The tier alone locks prod; it does not wait for enforce_in_dev.
run "prod_tier_without_compliance_flags_keeps_2555_days_locked" {
  command = plan

  variables {
    environment         = "prod"
    enforce_in_dev      = false
    evidence_project_id = "retention-evidence-project"
  }

  assert {
    condition = (
      google_storage_bucket.langfuse_event_upload.retention_policy[0].retention_period == 220752000 &&
      module.worm_bucket.retention_period_seconds == 220752000
    )
    error_message = "the prod tier must keep 2555 days with enforce_in_dev = false"
  }
  assert {
    condition = (
      google_storage_bucket.langfuse_event_upload.retention_policy[0].is_locked &&
      module.worm_bucket.retention_locked
    )
    error_message = "the prod tier must lock both buckets with enforce_in_dev = false"
  }
  assert {
    condition     = local.effective_cage_env == "prod"
    error_message = "the prod tier must keep effective_cage_env = 'prod' whatever enforce_in_dev says"
  }
}

# ─── Dev: unlocked 2555d when permissive; locked 1d + staging CAGE_ENV when enforcing ─
# dev.tfvars sets neither region nor cage_deployment_region: deploy_all.sh takes
# them from .env, so these runs use US_FED's, which us-dev.tfvars names for the
# same cluster.

run "dev_profile_keeps_2555_days_unlocked" {
  command = plan

  variables {
    environment            = lookup(var.dev, "environment", "dev")
    region                 = lookup(var.dev, "region", "us-central1")
    zone                   = lookup(var.dev, "zone", "us-central1-a")
    cage_deployment_region = lookup(var.dev, "cage_deployment_region", "US_FED")
    enforce_in_dev         = lookup(var.dev, "enforce_in_dev", "false") == "true"
  }

  assert {
    condition = (
      google_storage_bucket.langfuse_event_upload.retention_policy[0].retention_period == 220752000 &&
      module.worm_bucket.retention_period_seconds == 220752000
    )
    error_message = "dev.tfvars must keep 2555 days unlocked on both buckets"
  }
  assert {
    condition = (
      !google_storage_bucket.langfuse_event_upload.retention_policy[0].is_locked &&
      !module.worm_bucket.retention_locked
    )
    error_message = "dev.tfvars sets enforce_in_dev = false, so neither bucket may be locked"
  }
  assert {
    condition = (
      local.effective_cage_env == "dev" &&
      output.deployment_summary.effective_cage_env == "dev" &&
      one([for e in kubernetes_deployment_v1.gateway_canary[0].spec[0].template[0].spec[0].container[0].env : e.value if e.name == "CAGE_ENV"]) == "dev"
    )
    error_message = "dev.tfvars sets enforce_in_dev = false, so effective_cage_env must stay 'dev'"
  }
}

run "us_dev_profile_keeps_2555_days_unlocked" {
  command = plan

  variables {
    environment            = lookup(var.us_dev, "environment", "dev")
    region                 = lookup(var.us_dev, "region", "us-central1")
    zone                   = lookup(var.us_dev, "zone", "us-central1-a")
    cage_deployment_region = lookup(var.us_dev, "cage_deployment_region", "US_FED")
    enforce_in_dev         = lookup(var.us_dev, "enforce_in_dev", "false") == "true"
  }

  assert {
    condition = (
      google_storage_bucket.langfuse_event_upload.retention_policy[0].retention_period == 220752000 &&
      module.worm_bucket.retention_period_seconds == 220752000
    )
    error_message = "us-dev.tfvars must keep 2555 days unlocked on both buckets"
  }
  assert {
    condition = (
      !google_storage_bucket.langfuse_event_upload.retention_policy[0].is_locked &&
      !module.worm_bucket.retention_locked
    )
    error_message = "us-dev.tfvars sets enforce_in_dev = false, so neither bucket may be locked"
  }
  assert {
    condition = (
      local.effective_cage_env == "dev" &&
      output.deployment_summary.effective_cage_env == "dev" &&
      one([for e in kubernetes_deployment_v1.gateway_canary[0].spec[0].template[0].spec[0].container[0].env : e.value if e.name == "CAGE_ENV"]) == "dev"
    )
    error_message = "us-dev.tfvars sets enforce_in_dev = false, so effective_cage_env must stay 'dev'"
  }
}

run "eu_dev_profile_locks_both_buckets_for_one_day" {
  command = plan

  variables {
    environment            = lookup(var.eu_dev, "environment", "dev")
    region                 = var.eu_dev["region"]
    zone                   = var.eu_dev["zone"]
    cage_deployment_region = var.eu_dev["cage_deployment_region"]
    enforce_in_dev         = lookup(var.eu_dev, "enforce_in_dev", "false") == "true"
  }

  assert {
    condition = (
      google_storage_bucket.langfuse_event_upload.retention_policy[0].retention_period == 86400 &&
      module.worm_bucket.retention_period_seconds == 86400
    )
    error_message = "eu-dev.tfvars (enforcing dev) must cap locked retention at 86400 s (1 day) on both buckets, never 2555 days"
  }
  assert {
    condition = (
      google_storage_bucket.langfuse_event_upload.retention_policy[0].is_locked &&
      module.worm_bucket.retention_locked
    )
    error_message = "eu-dev.tfvars sets enforce_in_dev = true, so both buckets must be locked"
  }
  assert {
    condition = (
      local.effective_cage_env == "staging" &&
      output.deployment_summary.effective_cage_env == "staging" &&
      one([for e in kubernetes_deployment_v1.gateway_canary[0].spec[0].template[0].spec[0].container[0].env : e.value if e.name == "CAGE_ENV"]) == "staging"
    )
    error_message = "eu-dev.tfvars sets enforce_in_dev = true, so workload runtime effective_cage_env must be 'staging'"
  }
  assert {
    condition = (
      output.deployment_summary.environment == "dev" &&
      google_kms_key_ring.signing.name == "cage-signing-dev"
    )
    error_message = "eu-dev.tfvars must keep cloud resource naming on var.environment ('dev')"
  }
}

run "apac_dev_profile_locks_both_buckets_for_one_day" {
  command = plan

  variables {
    environment            = lookup(var.apac_dev, "environment", "dev")
    region                 = var.apac_dev["region"]
    zone                   = var.apac_dev["zone"]
    cage_deployment_region = var.apac_dev["cage_deployment_region"]
    enforce_in_dev         = lookup(var.apac_dev, "enforce_in_dev", "false") == "true"
  }

  assert {
    condition = (
      google_storage_bucket.langfuse_event_upload.retention_policy[0].retention_period == 86400 &&
      module.worm_bucket.retention_period_seconds == 86400
    )
    error_message = "apac-dev.tfvars (enforcing dev) must cap locked retention at 86400 s (1 day) on both buckets, never 2555 days"
  }
  assert {
    condition = (
      google_storage_bucket.langfuse_event_upload.retention_policy[0].is_locked &&
      module.worm_bucket.retention_locked
    )
    error_message = "apac-dev.tfvars sets enforce_in_dev = true, so both buckets must be locked"
  }
  assert {
    condition = (
      local.effective_cage_env == "staging" &&
      output.deployment_summary.effective_cage_env == "staging" &&
      one([for e in kubernetes_deployment_v1.gateway_canary[0].spec[0].template[0].spec[0].container[0].env : e.value if e.name == "CAGE_ENV"]) == "staging"
    )
    error_message = "apac-dev.tfvars sets enforce_in_dev = true, so workload runtime effective_cage_env must be 'staging'"
  }
  assert {
    condition = (
      output.deployment_summary.environment == "dev" &&
      google_kms_key_ring.signing.name == "cage-signing-dev"
    )
    error_message = "apac-dev.tfvars must keep cloud resource naming on var.environment ('dev')"
  }
}

# ─── Data-class split: certification_mode & cross-project evidence custody ───

run "staging_certification_mode_refuses_single_project_evidence_custody" {
  command = plan

  variables {
    certification_mode = true
  }

  expect_failures = [terraform_data.evidence_domain_isolation_guard]
}

run "staging_certification_mode_with_separate_project_splits_retention" {
  command = plan

  variables {
    certification_mode  = true
    evidence_project_id = "evidence-test-project"
  }

  assert {
    condition = (
      google_storage_bucket.langfuse_event_upload.retention_policy[0].retention_period == 86400 &&
      google_storage_bucket.langfuse_event_upload.retention_policy[0].is_locked &&
      output.deployment_summary.telemetry_retention_period_seconds == 86400
    )
    error_message = "non-prod certification_mode must keep operational telemetry (langfuse_event_upload) at 1 day (86400 s) locked"
  }
  assert {
    condition = (
      module.worm_bucket.retention_period_seconds == 220752000 &&
      module.worm_bucket.retention_locked &&
      local.evidence_retention_period_seconds == 220752000 &&
      output.deployment_summary.evidence_retention_period_seconds == 220752000 &&
      output.deployment_summary.certification_mode
    )
    error_message = "certification_mode with separate evidence_project_id must lock worm_bucket and evidence_domain for 2555 days (220752000 s)"
  }
}

run "staging_cross_project_custody_without_certification_mode_splits_retention" {
  command = plan

  variables {
    certification_mode  = false
    evidence_project_id = "evidence-test-project"
  }

  assert {
    condition = (
      google_storage_bucket.langfuse_event_upload.retention_policy[0].retention_period == 86400 &&
      google_storage_bucket.langfuse_event_upload.retention_policy[0].is_locked
    )
    error_message = "staging with cross-project custody must keep operational telemetry at 86400 s locked"
  }
  assert {
    condition = (
      module.worm_bucket.retention_period_seconds == 220752000 &&
      module.worm_bucket.retention_locked &&
      local.evidence_retention_period_seconds == 220752000
    )
    error_message = "cross-project evidence custody must lock worm_bucket and evidence_domain for 2555 days (220752000 s) even when certification_mode = false"
  }
}

run "eu_dev_cross_project_custody_without_certification_mode_splits_retention" {
  command = plan

  variables {
    environment            = lookup(var.eu_dev, "environment", "dev")
    region                 = var.eu_dev["region"]
    zone                   = var.eu_dev["zone"]
    cage_deployment_region = var.eu_dev["cage_deployment_region"]
    enforce_in_dev         = lookup(var.eu_dev, "enforce_in_dev", "false") == "true"
    certification_mode     = false
    evidence_project_id    = "evidence-test-project"
  }

  assert {
    condition = (
      google_storage_bucket.langfuse_event_upload.retention_policy[0].retention_period == 86400 &&
      google_storage_bucket.langfuse_event_upload.retention_policy[0].is_locked &&
      module.worm_bucket.retention_period_seconds == 220752000 &&
      module.worm_bucket.retention_locked &&
      local.evidence_retention_period_seconds == 220752000
    )
    error_message = "eu-dev with dedicated evidence_project_id must keep telemetry at 86400 s locked while locking WORM evidence for 220752000 s"
  }
}

run "staging_certification_mode_explicit_single_project_override_splits_retention" {
  command = plan

  variables {
    certification_mode                = true
    require_separate_evidence_project = false
  }

  assert {
    condition = (
      google_storage_bucket.langfuse_event_upload.retention_policy[0].retention_period == 86400 &&
      google_storage_bucket.langfuse_event_upload.retention_policy[0].is_locked &&
      module.worm_bucket.retention_period_seconds == 220752000 &&
      module.worm_bucket.retention_locked &&
      local.evidence_retention_period_seconds == 220752000
    )
    error_message = "explicit require_separate_evidence_project = false must allow single-project certification_mode with 86400 s telemetry and 220752000 s evidence retention"
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
