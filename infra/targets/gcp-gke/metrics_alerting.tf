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

# ─── GKE Managed Prometheus Scrape & Series-Arrival Liveness Alerting (AU-12 / AU-5) ───
# Port :9090 traverses Linkerd's inbound proxy (no skip-inbound-ports = "9090"),
# governed by Server/gateway-metrics and Server/compliance-bridge-metrics with
# HTTPRoute Exact GET /metrics and AuthorizationPolicy scoped to
# NetworkAuthentication/workload-probe-network and compliance-bridge-probe-network.
# Checking up alone is insufficient because HTTP 200 from an empty or uninitialised
# registry yields up == 1 while zero cage_* series arrive. Both targets therefore
# combine scrape-target health (up == 0 or absent_over_time(up[5m])) with named
# startup-registered series absence:
#   - gateway:           cage_event_loop_lag_seconds_count (250 ms Histogram)
#   - compliance-bridge: cage_lula_audit_not_satisfied_controls &
#                        cage_evidence_verified_batches (unlabeled Gauges)

locals {
  gateway_metrics_scrape_failure_promql = join(" or ", [
    "(up{job=\"gateway-metrics\",namespace=\"${module.namespace.name}\"} == 0)",
    "absent_over_time(up{job=\"gateway-metrics\",namespace=\"${module.namespace.name}\"}[5m])",
    "absent_over_time(cage_event_loop_lag_seconds_count{namespace=\"${module.namespace.name}\"}[5m])",
  ])
  compliance_bridge_metrics_scrape_failure_promql = join(" or ", [
    "(up{job=\"compliance-bridge-metrics\",namespace=\"${module.namespace.name}\"} == 0)",
    "absent_over_time(up{job=\"compliance-bridge-metrics\",namespace=\"${module.namespace.name}\"}[5m])",
    "absent_over_time(cage_lula_audit_not_satisfied_controls{namespace=\"${module.namespace.name}\"}[5m])",
    "absent_over_time(cage_evidence_verified_batches{namespace=\"${module.namespace.name}\"}[5m])",
  ])
  prometheus_metrics_scrape_liveness_promql = var.enable_compliance_bridge ? "${local.gateway_metrics_scrape_failure_promql} or ${local.compliance_bridge_metrics_scrape_failure_promql}" : local.gateway_metrics_scrape_failure_promql
}

resource "google_monitoring_alert_policy" "prometheus_metrics_scrape_liveness" {
  count = local.enforcing_posture ? 1 : 0

  project               = var.project_id
  display_name          = "${var.cluster_name} - GMP Metrics Scrape & Series Arrival Down / Absent (AU-12)"
  combiner              = "OR"
  enabled               = true
  severity              = "CRITICAL"
  notification_channels = var.lula_alert_notification_channels

  user_labels = {
    owner       = trimspace(var.lula_alert_owner)
    component   = "metrics-pipeline"
    control     = "au-12"
    environment = var.environment
  }

  documentation {
    mime_type = "text/markdown"
    content   = <<-EOT
      ## CAGE GMP Metrics Scrape & Named-Series Arrival Alert (NIST SP 800-53 AU-12 / AU-5)

      - **Owner:** `${trimspace(var.lula_alert_owner)}`
      - **Cluster:** `${var.cluster_name}` (`${var.namespace}`)
      - **Targets:** `PodMonitoring/gateway-metrics` (`:9090/metrics`)${var.enable_compliance_bridge ? " and `PodMonitoring/compliance-bridge-metrics` (`:9090/metrics`)" : ""}

      Fires when GKE Managed Prometheus records `up == 0` (HTTP `403` from
      Linkerd `Server` / `AuthorizationPolicy`, `probeCidrs` source-IP mismatch,
      `NetworkPolicy` drop, or connection failure), `absent_over_time(up[5m])`
      (missing `PodMonitoring` target or collector outage), or `absent_over_time`
      on startup-registered `cage_*` series (`cage_event_loop_lag_seconds_count`
      on `gateway`; `cage_lula_audit_not_satisfied_controls` and
      `cage_evidence_verified_batches` on `compliance-bridge`, catching HTTP `200`
      from an empty registry) for `120s`.
    EOT
  }

  conditions {
    display_name = "GMP PodMonitoring scrape target down (up == 0) or named cage_* series absent for 5m"

    condition_prometheus_query_language {
      query                     = local.prometheus_metrics_scrape_liveness_promql
      duration                  = "120s"
      evaluation_interval       = "60s"
      disable_metric_validation = true
    }
  }

  depends_on = [module.gke]
}
