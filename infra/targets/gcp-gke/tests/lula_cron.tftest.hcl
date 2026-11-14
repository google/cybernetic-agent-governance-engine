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

# Plan-time verification of the in-cluster Lula compliance auditor CronJob,
# active-spec ConfigMap filtering (`# cage-status: planned` exclusion), KSA
# non-default coverage (AC-2), compliance-bridge internal port 8085, and
# NetworkPolicy isolation (CA-2, CA-7, SC-7).

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
    workload_identity_pool = "lula-cron-test-project.svc.id.goog"
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
  project_id                     = "lula-cron-test-project"
  authorized_networks            = [{ cidr = "203.0.113.7/32", display_name = "test" }]
  langfuse_compliance_public_key = "fake-compliance-public-key"
  langfuse_compliance_secret_key = "fake-compliance-secret-key"
  trusted_operator_identities    = ["alice@example.org"]
  operator_oidc_issuer           = "https://idp.example.org"
  operator_oidc_audience         = "cage-compliance-bridge"
  operator_jwks_uri              = "https://idp.example.org/.well-known/jwks.json"
}

run "staging_plans_lula_cron_active_specs_and_dedicated_ksas" {
  command = plan

  assert {
    condition     = length(module.lula_cron) == 1
    error_message = "staging must plan module.lula_cron by default (enable_lula_cron = true)"
  }

  assert {
    condition     = module.lula_cron[0].cron_job_name == "lula-audit" && module.lula_cron[0].config_map_name == "lula-active-validations"
    error_message = "module.lula_cron must plan CronJob/lula-audit and ConfigMap/lula-active-validations"
  }

  assert {
    condition     = module.lula_cron[0].active_spec_count == 26
    error_message = "ConfigMap/lula-active-validations must include all 26 active Lula specs and exclude the 7 planned/not-applicable specs"
  }

  assert {
    condition = (
      !contains(module.lula_cron[0].active_spec_names, "lula-validation-ra5.yaml") &&
      !contains(module.lula_cron[0].active_spec_names, "lula-validation-dora-art10.yaml") &&
      !contains(module.lula_cron[0].active_spec_names, "lula-validation-eu-ai-act-art9.yaml") &&
      !contains(module.lula_cron[0].active_spec_names, "lula-validation-gdpr-art22.yaml") &&
      !contains(module.lula_cron[0].active_spec_names, "lula-validation-mas-feat.yaml") &&
      !contains(module.lula_cron[0].active_spec_names, "lula-validation-mas-notice655.yaml") &&
      !contains(module.lula_cron[0].active_spec_names, "lula-validation-mas-trm-s6.yaml")
    )
    error_message = "planned and not-applicable Lula specs must never be mounted into ConfigMap/lula-active-validations"
  }

  assert {
    condition = (
      kubernetes_service_account.workload["lula"].metadata[0].name == "cage-lula-sa" &&
      kubernetes_service_account.workload["agentsight_ui"].metadata[0].name == "cage-agentsight-ui-sa"
    )
    error_message = "AC-2: lula and agentsight_ui must each have a dedicated non-default KSA (OPA runs inside the gateway pod under cage-gateway-sa)"
  }

  assert {
    condition     = kubernetes_network_policy_v1.lula_audit_egress.metadata[0].name == "lula-audit-egress"
    error_message = "SC-7: lula-audit-egress NetworkPolicy must be planned in governance-stack"
  }

  assert {
    condition = (
      length(google_monitoring_alert_policy.lula_audit_failure) == 1 &&
      length(google_monitoring_alert_policy.lula_audit_failure[0].conditions) == 1 &&
      google_monitoring_alert_policy.lula_audit_failure[0].user_labels["owner"] == "platform-compliance-oncall" &&
      strcontains(google_monitoring_alert_policy.lula_audit_failure[0].documentation[0].content, "platform-compliance-oncall") &&
      google_monitoring_alert_policy.lula_audit_failure[0].conditions[0].condition_prometheus_query_language[0].disable_metric_validation == true &&
      length(google_monitoring_alert_policy.lula_audit_pod_restart) == 1 &&
      google_monitoring_alert_policy.lula_audit_pod_restart[0].user_labels["owner"] == "platform-compliance-oncall" &&
      length(google_monitoring_alert_policy.prometheus_metrics_scrape_liveness) == 1 &&
      length(google_monitoring_alert_policy.prometheus_metrics_scrape_liveness[0].conditions) == 1 &&
      google_monitoring_alert_policy.prometheus_metrics_scrape_liveness[0].user_labels["owner"] == "platform-compliance-oncall" &&
      google_monitoring_alert_policy.prometheus_metrics_scrape_liveness[0].conditions[0].condition_prometheus_query_language[0].disable_metric_validation == true &&
      strcontains(google_monitoring_alert_policy.prometheus_metrics_scrape_liveness[0].conditions[0].condition_prometheus_query_language[0].query, "job=\"gateway-metrics\"") &&
      strcontains(google_monitoring_alert_policy.prometheus_metrics_scrape_liveness[0].conditions[0].condition_prometheus_query_language[0].query, "absent_over_time(cage_event_loop_lag_seconds_count") &&
      strcontains(google_monitoring_alert_policy.prometheus_metrics_scrape_liveness[0].conditions[0].condition_prometheus_query_language[0].query, "job=\"compliance-bridge-metrics\"") &&
      strcontains(google_monitoring_alert_policy.prometheus_metrics_scrape_liveness[0].conditions[0].condition_prometheus_query_language[0].query, "absent_over_time(cage_lula_audit_not_satisfied_controls") &&
      strcontains(google_monitoring_alert_policy.prometheus_metrics_scrape_liveness[0].conditions[0].condition_prometheus_query_language[0].query, "absent_over_time(cage_lula_audit_insufficient_traffic_controls") &&
      strcontains(google_monitoring_alert_policy.prometheus_metrics_scrape_liveness[0].conditions[0].condition_prometheus_query_language[0].query, "absent_over_time(cage_evidence_verified_batches") &&
      strcontains(google_monitoring_alert_policy.prometheus_metrics_scrape_liveness[0].conditions[0].condition_prometheus_query_language[0].query, "absent_over_time(cage_gateway_gated_requests_total") &&
      length(google_monitoring_alert_policy.gateway_sustained_refusal_ratio) == 1 &&
      length(google_monitoring_alert_policy.gateway_sustained_refusal_ratio[0].conditions) == 1 &&
      google_monitoring_alert_policy.gateway_sustained_refusal_ratio[0].user_labels["owner"] == "platform-compliance-oncall" &&
      strcontains(google_monitoring_alert_policy.gateway_sustained_refusal_ratio[0].documentation[0].content, "platform-compliance-oncall") &&
      google_monitoring_alert_policy.gateway_sustained_refusal_ratio[0].conditions[0].condition_prometheus_query_language[0].disable_metric_validation == true &&
      google_monitoring_alert_policy.gateway_sustained_refusal_ratio[0].conditions[0].condition_prometheus_query_language[0].duration == "180s" &&
      strcontains(google_monitoring_alert_policy.gateway_sustained_refusal_ratio[0].conditions[0].condition_prometheus_query_language[0].query, "cage_gateway_gated_requests_total") &&
      strcontains(google_monitoring_alert_policy.gateway_sustained_refusal_ratio[0].conditions[0].condition_prometheus_query_language[0].query, "outcome=\"blocked\"") &&
      strcontains(google_monitoring_alert_policy.gateway_sustained_refusal_ratio[0].conditions[0].condition_prometheus_query_language[0].query, ">= 0.95") &&
      length(google_monitoring_alert_policy.gateway_zero_permitted_requests) == 1 &&
      length(google_monitoring_alert_policy.gateway_zero_permitted_requests[0].conditions) == 1 &&
      google_monitoring_alert_policy.gateway_zero_permitted_requests[0].user_labels["owner"] == "platform-compliance-oncall" &&
      strcontains(google_monitoring_alert_policy.gateway_zero_permitted_requests[0].documentation[0].content, "platform-compliance-oncall") &&
      google_monitoring_alert_policy.gateway_zero_permitted_requests[0].conditions[0].condition_prometheus_query_language[0].disable_metric_validation == true &&
      google_monitoring_alert_policy.gateway_zero_permitted_requests[0].conditions[0].condition_prometheus_query_language[0].duration == "900s" &&
      strcontains(google_monitoring_alert_policy.gateway_zero_permitted_requests[0].conditions[0].condition_prometheus_query_language[0].query, "rate(cage_gateway_gated_requests_total") &&
      strcontains(google_monitoring_alert_policy.gateway_zero_permitted_requests[0].conditions[0].condition_prometheus_query_language[0].query, "outcome=\"permitted\"") &&
      strcontains(google_monitoring_alert_policy.gateway_zero_permitted_requests[0].conditions[0].condition_prometheus_query_language[0].query, "== 0") &&
      strcontains(google_monitoring_alert_policy.gateway_zero_permitted_requests[0].conditions[0].condition_prometheus_query_language[0].query, "cage_gateway_canary_requests_total") &&
      length(google_monitoring_alert_policy.gateway_canary_probe_absent) == 1 &&
      length(google_monitoring_alert_policy.gateway_canary_probe_absent[0].conditions) == 1 &&
      google_monitoring_alert_policy.gateway_canary_probe_absent[0].user_labels["component"] == "gateway-canary" &&
      google_monitoring_alert_policy.gateway_canary_probe_absent[0].conditions[0].condition_prometheus_query_language[0].duration == "300s" &&
      strcontains(google_monitoring_alert_policy.gateway_canary_probe_absent[0].conditions[0].condition_prometheus_query_language[0].query, "cage_gateway_canary_requests_total") &&
      length(google_monitoring_alert_policy.gateway_canary_pod_health) == 1 &&
      length(google_monitoring_alert_policy.gateway_canary_pod_health[0].conditions) == 2 &&
      google_monitoring_alert_policy.gateway_canary_pod_health[0].user_labels["component"] == "gateway-canary" &&
      length(kubernetes_deployment_v1.gateway_canary) == 1 &&
      kubernetes_service_account.workload["gateway_canary"].metadata[0].name == "cage-gateway-canary-sa" &&
      length(coalesce(kubernetes_service_account.workload["gateway_canary"].metadata[0].annotations, tomap({}))) == 0 &&
      kubernetes_network_policy_v1.gateway_canary_egress.metadata[0].name == "gateway-canary-egress"
    )
    error_message = "CA-7 / AU-12 / SI-4: enforcing deployments must provision single-condition PromQL lula_audit_failure, lula_audit_pod_restart, prometheus_metrics_scrape_liveness, gateway_sustained_refusal_ratio, gateway_zero_permitted_requests, gateway_canary_probe_absent, gateway_canary_pod_health, and in-mesh Deployment/gateway-canary under cage-gateway-canary-sa"
  }
}

run "disabling_gateway_canary_omits_zero_permitted_alert_policy" {
  command = plan

  variables {
    enable_gateway_canary = false
  }

  assert {
    condition = (
      length(kubernetes_deployment_v1.gateway_canary) == 0 &&
      length(google_monitoring_alert_policy.gateway_zero_permitted_requests) == 0 &&
      length(google_monitoring_alert_policy.gateway_canary_probe_absent) == 0 &&
      length(google_monitoring_alert_policy.gateway_canary_pod_health) == 0 &&
      length(google_monitoring_alert_policy.gateway_sustained_refusal_ratio) == 1
    )
    error_message = "enable_gateway_canary = false must omit Deployment/gateway-canary, gateway_zero_permitted_requests, gateway_canary_probe_absent, and gateway_canary_pod_health"
  }
}

run "disabling_lula_cron_drops_lula_from_required_image_digests" {
  command = plan

  variables {
    enable_lula_cron = false
  }

  assert {
    condition     = length(module.lula_cron) == 0 && !contains(local.required_image_digests, "lula")
    error_message = "enable_lula_cron = false must omit module.lula_cron and drop 'lula' from local.required_image_digests"
  }
}

run "lula_image_override_replaces_map_entry" {
  command = plan

  variables {
    lula_image = "registry.invalid/cage-test/lula@sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
  }

  assert {
    condition     = !contains(local.required_image_digests, "lula")
    error_message = "an explicit lula_image override must replace the 'lula' entry in local.required_image_digests"
  }
}

run "lula_image_latest_tag_is_refused" {
  command = plan

  variables {
    lula_image = "registry.invalid/cage-test/lula:latest"
  }

  expect_failures = [var.lula_image]
}

run "custom_lula_alert_owner_and_channels_propagate" {
  command = plan

  variables {
    lula_alert_owner                 = "secops-compliance-oncall"
    lula_alert_notification_channels = ["projects/lula-cron-test-project/notificationChannels/12345"]
  }

  assert {
    condition = (
      google_monitoring_alert_policy.lula_audit_failure[0].user_labels["owner"] == "secops-compliance-oncall" &&
      strcontains(google_monitoring_alert_policy.lula_audit_failure[0].documentation[0].content, "secops-compliance-oncall") &&
      contains(google_monitoring_alert_policy.lula_audit_failure[0].notification_channels, "projects/lula-cron-test-project/notificationChannels/12345") &&
      google_monitoring_alert_policy.lula_audit_pod_restart[0].user_labels["owner"] == "secops-compliance-oncall" &&
      contains(google_monitoring_alert_policy.lula_audit_pod_restart[0].notification_channels, "projects/lula-cron-test-project/notificationChannels/12345") &&
      google_monitoring_alert_policy.prometheus_metrics_scrape_liveness[0].user_labels["owner"] == "secops-compliance-oncall" &&
      contains(google_monitoring_alert_policy.prometheus_metrics_scrape_liveness[0].notification_channels, "projects/lula-cron-test-project/notificationChannels/12345") &&
      google_monitoring_alert_policy.gateway_sustained_refusal_ratio[0].user_labels["owner"] == "secops-compliance-oncall" &&
      strcontains(google_monitoring_alert_policy.gateway_sustained_refusal_ratio[0].documentation[0].content, "secops-compliance-oncall") &&
      contains(google_monitoring_alert_policy.gateway_sustained_refusal_ratio[0].notification_channels, "projects/lula-cron-test-project/notificationChannels/12345") &&
      google_monitoring_alert_policy.gateway_zero_permitted_requests[0].user_labels["owner"] == "secops-compliance-oncall" &&
      strcontains(google_monitoring_alert_policy.gateway_zero_permitted_requests[0].documentation[0].content, "secops-compliance-oncall") &&
      contains(google_monitoring_alert_policy.gateway_zero_permitted_requests[0].notification_channels, "projects/lula-cron-test-project/notificationChannels/12345") &&
      google_monitoring_alert_policy.gateway_canary_probe_absent[0].user_labels["owner"] == "secops-compliance-oncall" &&
      strcontains(google_monitoring_alert_policy.gateway_canary_probe_absent[0].documentation[0].content, "secops-compliance-oncall") &&
      contains(google_monitoring_alert_policy.gateway_canary_probe_absent[0].notification_channels, "projects/lula-cron-test-project/notificationChannels/12345") &&
      google_monitoring_alert_policy.gateway_canary_pod_health[0].user_labels["owner"] == "secops-compliance-oncall" &&
      strcontains(google_monitoring_alert_policy.gateway_canary_pod_health[0].documentation[0].content, "secops-compliance-oncall") &&
      contains(google_monitoring_alert_policy.gateway_canary_pod_health[0].notification_channels, "projects/lula-cron-test-project/notificationChannels/12345")
    )
    error_message = "custom lula_alert_owner and lula_alert_notification_channels must propagate into Lula, GMP scrape-liveness, gateway refusal-ratio, gateway zero-permitted, and gateway canary liveness alert policies"
  }
}

run "empty_lula_alert_owner_is_refused" {
  command = plan

  variables {
    lula_alert_owner = "   "
  }

  expect_failures = [var.lula_alert_owner]
}
