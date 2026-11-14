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
    "absent_over_time(cage_gateway_gated_requests_total{namespace=\"${module.namespace.name}\",outcome=\"blocked\"}[5m])",
    "absent_over_time(cage_gateway_gated_requests_total{namespace=\"${module.namespace.name}\",outcome=\"permitted\"}[5m])",
  ])
  compliance_bridge_metrics_scrape_failure_promql = join(" or ", [
    "(up{job=\"compliance-bridge-metrics\",namespace=\"${module.namespace.name}\"} == 0)",
    "absent_over_time(up{job=\"compliance-bridge-metrics\",namespace=\"${module.namespace.name}\"}[5m])",
    "absent_over_time(cage_lula_audit_not_satisfied_controls{namespace=\"${module.namespace.name}\"}[5m])",
    "absent_over_time(cage_evidence_verified_batches{namespace=\"${module.namespace.name}\"}[5m])",
  ])
  prometheus_metrics_scrape_liveness_promql = var.enable_compliance_bridge ? "${local.gateway_metrics_scrape_failure_promql} or ${local.compliance_bridge_metrics_scrape_failure_promql}" : local.gateway_metrics_scrape_failure_promql

  gateway_refusal_ratio_min_requests = 5
  gateway_refusal_ratio_threshold    = "0.95"
  gateway_sustained_refusal_ratio_promql = join(" ", [
    "((sum(increase(cage_gateway_gated_requests_total{job=\"gateway-metrics\",namespace=\"${module.namespace.name}\",outcome=\"blocked\"}[5m])) or vector(0))",
    "/",
    "(sum(increase(cage_gateway_gated_requests_total{job=\"gateway-metrics\",namespace=\"${module.namespace.name}\"}[5m])) >= ${local.gateway_refusal_ratio_min_requests}))",
    ">= ${local.gateway_refusal_ratio_threshold}",
  ])
  gateway_zero_permitted_requests_promql = "sum(rate(cage_gateway_gated_requests_total{job=\"gateway-metrics\",namespace=\"${module.namespace.name}\",outcome=\"permitted\"}[5m])) == 0"
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
      and `cage_gateway_gated_requests_total` on `gateway`;
      `cage_lula_audit_not_satisfied_controls` and
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

# ─── Gateway Sustained Refusal-Ratio & Zero-Permitted Alerting (SI-4 / AU-5) ──
# When a runtime dependency fails soft or becomes unreachable after boot (for
# example quarantine/evidence Redis, OPA sidecar, or Linkerd proxy identity
# wiring), /healthz continues returning HTTP 200, PodMonitoring scrapes remain
# healthy (up == 1 and startup-registered cage_* series arrive), and the Lula
# CronJob sees fresh cluster state — while gated gateway routes return 403/503
# or protocol-wrapped refusals on ~100% of traffic. Excluding OPEN_EXACT_PATHS
# (/health, /healthz, JWKS) prevents kubelet probes from diluting the ratio.
#
# Denominator / ingress-posture assumption (WorkloadIdentityMiddleware):
#   workload_identity.py classifies every non-open HTTP response with status
#   >= 400 (including 400/404/422) as outcome="blocked". That holds under the
#   current deny-by-default Linkerd mesh ingress (CAGE_TRUSTED_CLIENT_IDENTITIES
#   + Server/AuthorizationPolicy), where unauthenticated scanner 404s are
#   rejected before reaching downstream routes and a compromised in-mesh caller
#   cannot send 404s to inflate outcome="permitted". If gateway ingress is ever
#   widened to expose public or unauthenticated routes outside OPEN_EXACT_PATHS,
#   random 400/404 scanner noise will count toward outcome="blocked" and page —
#   narrow the blocked HTTP status predicate (or split client_error out of
#   blocked/permitted) before opening ingress.
#
# Two-stage outage coverage (separated because Cloud Monitoring restricts
# prometheus_query_language alert policies to one condition per AlertPolicy):
#   1. gateway_sustained_refusal_ratio (180s duration, >= 5 req / 5m floor):
#      pages quickly during the initial retry burst of a total-denial event or
#      an active adversarial flood, without false-paging on single-shot probes.
#   2. gateway_zero_permitted_requests (900s duration, no volume floor):
#      prevents the alert from clearing itself as the outage deepens and callers
#      stop retrying / open circuit breakers, dropping total traffic below the
#      5 req / 5m floor while permitted throughput remains 0.

resource "google_monitoring_alert_policy" "gateway_sustained_refusal_ratio" {
  count = local.enforcing_posture ? 1 : 0

  project               = var.project_id
  display_name          = "${var.cluster_name} - Gateway Sustained Refusal Ratio >= 95% (SI-4 / AU-5)"
  combiner              = "OR"
  enabled               = true
  severity              = "CRITICAL"
  notification_channels = var.lula_alert_notification_channels

  user_labels = {
    owner       = trimspace(var.lula_alert_owner)
    component   = "gateway"
    control     = "si-4"
    environment = var.environment
  }

  documentation {
    mime_type = "text/markdown"
    content   = <<-EOT
      ## CAGE Gateway Sustained Refusal-Ratio Alert (NIST SP 800-53 SI-4 / AU-5)

      - **Owner:** `${trimspace(var.lula_alert_owner)}`
      - **Cluster:** `${var.cluster_name}` (`${var.namespace}`)
      - **Metric:** `cage_gateway_gated_requests_total{outcome="blocked"|"permitted"}` on `PodMonitoring/gateway-metrics` (`:9090/metrics`)

      Fires when at least `${local.gateway_refusal_ratio_min_requests}` non-open
      gateway requests arrive within `5m` and the `blocked` share stays
      `>= ${local.gateway_refusal_ratio_threshold}` for `180s` (`OPEN_EXACT_PATHS`
      such as `/health`, `/healthz`, and JWKS are excluded so kubelet probes
      never dilute the denominator). Paired with `gateway_zero_permitted_requests`
      (`rate(permitted) == 0` over `900s`) so paging persists if callers back off
      below the `${local.gateway_refusal_ratio_min_requests}` req / `5m` floor.

      ### Triage Checklist
      1. **Fail-closed dependency outage (gateway alive, `/healthz` = `200`, routes `403`/`503`):**
         Check gateway logs for quarantine Redis / evidence stream connectivity,
         OPA UDS sidecar readiness, KMS signing errors, or `INGRESS_IDENTITY_*`
         Linkerd `l5d-client-id` proxy mismatches.
      2. **Sustained adversarial probing or GCRA rate-limit flood:**
         Correlate `cage_governance_refusals_total{tier}` and
         `cage_rate_limit_hits_total{route,scope}` with gateway refusal receipts.
    EOT
  }

  conditions {
    display_name = "Gateway blocked-over-total gated request ratio >= 0.95 (>= 5 req / 5m) for 180s"

    condition_prometheus_query_language {
      query                     = local.gateway_sustained_refusal_ratio_promql
      duration                  = "180s"
      evaluation_interval       = "60s"
      disable_metric_validation = true
    }
  }

  depends_on = [module.gke]
}

resource "google_monitoring_alert_policy" "gateway_zero_permitted_requests" {
  count = local.enforcing_posture ? 1 : 0

  project               = var.project_id
  display_name          = "${var.cluster_name} - Gateway Zero Permitted Gated Requests for 15m (SI-4 / AU-5)"
  combiner              = "OR"
  enabled               = true
  severity              = "CRITICAL"
  notification_channels = var.lula_alert_notification_channels

  user_labels = {
    owner       = trimspace(var.lula_alert_owner)
    component   = "gateway"
    control     = "si-4"
    environment = var.environment
  }

  documentation {
    mime_type = "text/markdown"
    content   = <<-EOT
      ## CAGE Gateway Zero Permitted Gated Requests Alert (NIST SP 800-53 SI-4 / AU-5)

      - **Owner:** `${trimspace(var.lula_alert_owner)}`
      - **Cluster:** `${var.cluster_name}` (`${var.namespace}`)
      - **Metric:** `cage_gateway_gated_requests_total{outcome="permitted"}` on `PodMonitoring/gateway-metrics` (`:9090/metrics`)

      Fires when `sum(rate(cage_gateway_gated_requests_total{outcome="permitted"}[5m])) == 0`
      continuously for `900s` (`15m`) with no minimum request floor. Closes the
      second stage of a total-denial outage after upstream callers stop retrying
      or trip circuit breakers and gated traffic drops below the
      `${local.gateway_refusal_ratio_min_requests}` req / `5m` floor of
      `gateway_sustained_refusal_ratio` while zero requests are succeeding.
    EOT
  }

  conditions {
    display_name = "Gateway permitted gated request rate == 0 for 900s (15m)"

    condition_prometheus_query_language {
      query                     = local.gateway_zero_permitted_requests_promql
      duration                  = "900s"
      evaluation_interval       = "60s"
      disable_metric_validation = true
    }
  }

  depends_on = [module.gke]
}
