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

# ─── In-Cluster Lula Compliance Audit Alerting (ISO/IEC 42001 A.5.3 / CA-7) ───
# Pairs with compliance-bridge `ingest_infra_event` (`cage_lula_audit_*` GMP
# metrics) and `sla_monitor.py` (`2 x schedule` dead-man's switch) so every
# `lula_audit` failure, `< 26` manifest corpus-floor breach, dead-man breach,
# or `lula-audit` container restart routes to `var.alert_notification_channels`
# (GCP Pub/Sub terminal sink by design in the CAGE reference architecture;
# `var.alert_owner_label` is triage metadata only and routes nothing).

resource "google_monitoring_alert_policy" "lula_audit_failure" {
  count = var.enable_compliance_bridge && local.enforcing_posture ? 1 : 0

  project               = var.project_id
  display_name          = "${var.cluster_name} - Lula Compliance Audit Failure / Dead-Man Switch (A.5.3)"
  combiner              = "OR"
  enabled               = true
  severity              = "CRITICAL"
  notification_channels = local.resolved_alert_notification_channels

  alert_strategy {
    auto_close = "1800s"
  }

  user_labels = {
    owner       = trimspace(var.alert_owner_label)
    component   = "compliance-auditor"
    control     = "a-5-3"
    environment = var.environment
  }

  documentation {
    mime_type = "text/markdown"
    content   = <<-EOT
      ## CAGE In-Cluster Lula Compliance Audit Alert (ISO/IEC 42001 A.5.3 / NIST CA-7)

      - **Owner Label (metadata only; routes nothing):** `${trimspace(var.alert_owner_label)}`
      - **Delivery Route:** Bound `var.alert_notification_channels` (GCP Pub/Sub terminal sink in reference architecture)
      - **Cluster:** `${var.cluster_name}` (`${var.namespace}`)
      - **Schedule:** `${var.lula_schedule}` (`2 x schedule` = `${local.lula_audit_max_age_seconds}s` dead-man window)

      Fires when:
      1. `cage_lula_audit_not_satisfied_controls > 0`
         (real control violations, stale evidence, or `< 26` active-manifest
         corpus-floor breaches; statistical controls `a52`/`a53`/`a92` with
         `assessment_status=insufficient_traffic` (`total_traces == 0`) or
         `assessment_status=insufficient_sample` (`0 < total_traces < min_sample_size`)
         report separately on `cage_lula_audit_insufficient_traffic_controls` and
         `cage_lula_audit_insufficient_sample_controls`, advancing auditor liveness
         `cage_lula_audit_last_healthy_run_timestamp_seconds` without claiming
         statistical satisfaction on `cage_lula_audit_last_pass_timestamp_seconds`), or
      2. `increase(cage_lula_audit_deadman_breaches_total[5m]) > 0`
         because no auditor-healthy (`>= 26` evaluated, `failed_count == 0`)
         `lula_audit` run completed within `2 x schedule` (`${local.lula_audit_max_age_seconds}s`).
    EOT
  }

  conditions {
    display_name = "Lula not-satisfied controls > 0 or 2x-schedule dead-man switch breach > 0"

    condition_prometheus_query_language {
      query                     = "(cage_lula_audit_not_satisfied_controls{namespace=\"${module.namespace.name}\"} > 0) or (increase(cage_lula_audit_deadman_breaches_total{namespace=\"${module.namespace.name}\"}[5m]) > 0)"
      duration                  = "0s"
      evaluation_interval       = "60s"
      disable_metric_validation = true
    }
  }

  lifecycle {
    precondition {
      condition     = local.alert_channels_valid
      error_message = local.alert_channels_error_message
    }
  }

  depends_on = [module.gke]
}

resource "google_monitoring_alert_policy" "lula_audit_pod_restart" {
  count = var.enable_lula_cron && local.enforcing_posture ? 1 : 0

  project               = var.project_id
  display_name          = "${var.cluster_name} - Lula Compliance Auditor Pod Restart (A.5.3)"
  combiner              = "OR"
  enabled               = true
  severity              = "CRITICAL"
  notification_channels = local.resolved_alert_notification_channels

  # POAM-2026-230 Finding A: CronJob Job pods terminate after completion, stopping
  # per-pod series; REDUCE_SUM + 30m auto_close prevents 7-day orphaned incidents.
  alert_strategy {
    auto_close = "1800s"
  }

  user_labels = {
    owner       = trimspace(var.alert_owner_label)
    component   = "compliance-auditor"
    control     = "a-5-3"
    environment = var.environment
  }

  documentation {
    mime_type = "text/markdown"
    content   = <<-EOT
      ## CAGE In-Cluster Lula Auditor Pod Restart Alert (ISO/IEC 42001 A.5.3 / NIST CA-7)

      - **Owner Label (metadata only; routes nothing):** `${trimspace(var.alert_owner_label)}`
      - **Delivery Route:** Bound `var.alert_notification_channels` (GCP Pub/Sub terminal sink in reference architecture)
      - **Cluster:** `${var.cluster_name}` (`${var.namespace}`)

      Fires when workload-aggregated `kubernetes.io/container/restart_count` delta
      exceeds `0` for `lula-audit` pods (`REDUCE_SUM` across pod turnovers with
      `1800s` `auto_close` so completed CronJob pods never leave 7-day orphaned
      incidents). Separated from `lula_audit_failure` because Cloud Monitoring
      restricts `prometheus_query_language` alert policies to a single condition.
    EOT
  }

  conditions {
    display_name = "Lula auditor pod container restart > 0"

    condition_threshold {
      filter          = "resource.type = \"k8s_container\" AND resource.labels.namespace_name = \"${module.namespace.name}\" AND metadata.system_labels.top_level_controller_name = \"lula-audit\" AND metric.type = \"kubernetes.io/container/restart_count\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "0s"

      aggregations {
        alignment_period     = "300s"
        per_series_aligner   = "ALIGN_DELTA"
        cross_series_reducer = "REDUCE_SUM"
      }
    }
  }

  lifecycle {
    precondition {
      condition     = local.alert_channels_valid
      error_message = local.alert_channels_error_message
    }
  }

  depends_on = [module.gke]
}
