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
# metrics) and `sla_monitor.py` (`2 x schedule` = 1800s dead-man's switch) so
# every `lula_audit` failure, `< 26` manifest corpus-floor breach, dead-man
# breach, or `lula-audit` container restart pages the named owner.

resource "google_monitoring_alert_policy" "lula_audit_failure" {
  count = var.enable_compliance_bridge && local.enforcing_posture ? 1 : 0

  project               = var.project_id
  display_name          = "${var.cluster_name} - Lula Compliance Audit Failure / Dead-Man Switch (A.5.3)"
  combiner              = "OR"
  enabled               = true
  severity              = "CRITICAL"
  notification_channels = var.lula_alert_notification_channels

  user_labels = {
    owner       = trimspace(var.lula_alert_owner)
    component   = "compliance-auditor"
    control     = "a-5-3"
    environment = var.environment
  }

  documentation {
    mime_type = "text/markdown"
    content   = <<-EOT
      ## CAGE In-Cluster Lula Compliance Audit Alert (ISO/IEC 42001 A.5.3 / NIST CA-7)

      - **Owner:** `${trimspace(var.lula_alert_owner)}`
      - **Cluster:** `${var.cluster_name}` (`${var.namespace}`)
      - **Schedule:** `${var.lula_schedule}` (`2 x schedule` = `1800s` dead-man window)

      Fires when:
      1. `cage_lula_audit_not_satisfied_controls > 0`
         (including `< 26` active-manifest corpus-floor breaches),
      2. `increase(cage_lula_audit_deadman_breaches_total[5m]) > 0`
         because no clean `lula_audit PASS` completed within `2 x schedule`, or
      3. `kubernetes.io/container/restart_count` increases for `lula-audit` pods.
    EOT
  }

  conditions {
    display_name = "Lula not-satisfied or missing corpus-floor controls > 0"

    condition_prometheus_query_language {
      query                     = "cage_lula_audit_not_satisfied_controls{namespace=\"${module.namespace.name}\"} > 0"
      duration                  = "0s"
      evaluation_interval       = "60s"
      disable_metric_validation = true
    }
  }

  conditions {
    display_name = "Lula 2x-schedule dead-man switch breach > 0"

    condition_prometheus_query_language {
      query                     = "increase(cage_lula_audit_deadman_breaches_total{namespace=\"${module.namespace.name}\"}[5m]) > 0"
      duration                  = "0s"
      evaluation_interval       = "60s"
      disable_metric_validation = true
    }
  }

  conditions {
    display_name = "Lula auditor pod container restart > 0"

    condition_threshold {
      filter          = "resource.type = \"k8s_container\" AND resource.labels.namespace_name = \"${module.namespace.name}\" AND metadata.system_labels.top_level_controller_name = \"lula-audit\" AND metric.type = \"kubernetes.io/container/restart_count\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "0s"

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_DELTA"
      }
    }
  }

  depends_on = [module.gke]
}
