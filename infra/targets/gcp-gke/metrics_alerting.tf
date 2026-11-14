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
    "absent_over_time(cage_gateway_canary_requests_total{namespace=\"${module.namespace.name}\",outcome=\"blocked\"}[5m])",
    "absent_over_time(cage_gateway_canary_requests_total{namespace=\"${module.namespace.name}\",outcome=\"permitted\"}[5m])",
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
  # Conditioned on canary probe arrival (> 0) so a crashed, evicted, or Linkerd-
  # dropped canary prober pages gateway_canary_probe_absent / gateway_canary_pod_health
  # (component = "gateway-canary") rather than misattributing an outage to gateway.
  gateway_zero_permitted_requests_promql = join(" ", [
    "(sum(rate(cage_gateway_gated_requests_total{job=\"gateway-metrics\",namespace=\"${module.namespace.name}\",outcome=\"permitted\"}[5m])) == 0)",
    "and",
    "(sum(rate(cage_gateway_canary_requests_total{job=\"gateway-metrics\",namespace=\"${module.namespace.name}\"}[5m])) > 0)",
  ])
  gateway_canary_probe_absent_promql = "sum(rate(cage_gateway_canary_requests_total{job=\"gateway-metrics\",namespace=\"${module.namespace.name}\"}[5m])) == 0"
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
      on startup-registered `cage_*` series (`cage_event_loop_lag_seconds_count`,
      `cage_gateway_gated_requests_total`, and `cage_gateway_canary_requests_total`
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

# ─── Gateway Sustained Refusal-Ratio, Zero-Permitted & Canary Liveness (SI-4 / AU-5) ─
# When a runtime dependency fails soft or becomes unreachable after boot (for
# example quarantine/evidence Redis, OPA sidecar, or KMS signing), /healthz
# continues returning HTTP 200, PodMonitoring scrapes remain healthy (up == 1
# and startup-registered cage_* series arrive), and the Lula CronJob sees fresh
# cluster state — while gated gateway routes return 403/503 or protocol-wrapped
# refusals on ~100% of traffic. Excluding OPEN_EXACT_PATHS (/health, /healthz,
# JWKS) prevents kubelet probes from diluting the ratio.
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
# Outage & Canary Attribution Partition (separated because Cloud Monitoring
# restricts prometheus_query_language alert policies to one condition per policy):
#   1. gateway_sustained_refusal_ratio (component="gateway", 180s, >= 5 req / 5m):
#      pages quickly during the initial retry burst of a total-denial event or
#      an active adversarial flood, without false-paging on single-shot probes.
#   2. gateway_zero_permitted_requests (component="gateway", 900s, gated on
#      var.enable_gateway_canary): fires when rate(permitted) == 0 AND
#      rate(cage_gateway_canary_requests_total) > 0 — proving the canary prober
#      IS reaching WorkloadIdentityMiddleware and the gateway itself is refusing
#      everything after external callers backed off.
#   3. gateway_canary_probe_absent (component="gateway-canary", 300s, gated on
#      var.enable_gateway_canary): fires when rate(cage_gateway_canary_requests_total) == 0
#      — proving synthetic probes stopped reaching WorkloadIdentityMiddleware
#      (dead/wedged prober, NetworkPolicy drop, or broken HTTPRoute/gateway-canary).
#   4. gateway_canary_pod_health (component="gateway-canary", native k8s_container
#      restart_count > 0 OR uptime absent for 300s): immediately separates
#      "Deployment/gateway-canary crashed or was evicted" from "canary pod is
#      running, but mesh/network delivery to gateway:8080 broke".

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
      never dilute the denominator).${var.enable_gateway_canary ? " Paired with `gateway_zero_permitted_requests` (`rate(permitted) == 0 and rate(canary) > 0` over `900s`) and `gateway_canary_probe_absent` (`rate(canary) == 0` over `300s`) so paging persists if callers back off while distinguishing gateway refusal from prober failure." : ""}

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
  count = local.enforcing_posture && var.enable_gateway_canary ? 1 : 0

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
      - **Metrics:** `cage_gateway_gated_requests_total{outcome="permitted"}` and `cage_gateway_canary_requests_total` on `PodMonitoring/gateway-metrics` (`:9090/metrics`)
      - **Synthetic Liveness Canary:** `Deployment/gateway-canary` (`cage-gateway-canary-sa`, 1 governed request / `${var.gateway_canary_interval_seconds}s`)

      Fires when `sum(rate(cage_gateway_gated_requests_total{outcome="permitted"}[5m])) == 0`
      **and** `sum(rate(cage_gateway_canary_requests_total[5m])) > 0` continuously
      for `900s` (`15m`). Because `cage_gateway_canary_requests_total` confirms
      synthetic probes **are** reaching `WorkloadIdentityMiddleware` and being
      classified as `blocked`, this alert unambiguously attributes the outage to
      the **gateway refusing traffic** (quarantine/evidence Redis, OPA sidecar,
      or KMS failure) rather than a dead or disconnected canary prober (which
      pages `gateway_canary_probe_absent` / `gateway_canary_pod_health` under
      `component = "gateway-canary"` instead).
    EOT
  }

  conditions {
    display_name = "Gateway permitted rate == 0 while synthetic canary probes arrive (> 0) for 900s (15m)"

    condition_prometheus_query_language {
      query                     = local.gateway_zero_permitted_requests_promql
      duration                  = "900s"
      evaluation_interval       = "60s"
      disable_metric_validation = true
    }
  }

  depends_on = [module.gke]
}

resource "google_monitoring_alert_policy" "gateway_canary_probe_absent" {
  count = local.enforcing_posture && var.enable_gateway_canary ? 1 : 0

  project               = var.project_id
  display_name          = "${var.cluster_name} - Gateway Synthetic Canary Probes Absent for 5m (SI-4 / CA-7)"
  combiner              = "OR"
  enabled               = true
  severity              = "CRITICAL"
  notification_channels = var.lula_alert_notification_channels

  user_labels = {
    owner       = trimspace(var.lula_alert_owner)
    component   = "gateway-canary"
    control     = "si-4"
    environment = var.environment
  }

  documentation {
    mime_type = "text/markdown"
    content   = <<-EOT
      ## CAGE Gateway Synthetic Canary Probe Absence Alert (NIST SP 800-53 SI-4 / CA-7)

      - **Owner:** `${trimspace(var.lula_alert_owner)}`
      - **Cluster:** `${var.cluster_name}` (`${var.namespace}`)
      - **Metric:** `cage_gateway_canary_requests_total` on `PodMonitoring/gateway-metrics` (`:9090/metrics`)
      - **Prober:** `Deployment/gateway-canary` (`cage-gateway-canary-sa`, expected every `${var.gateway_canary_interval_seconds}s`)

      Fires when `sum(rate(cage_gateway_canary_requests_total[5m])) == 0` for `300s`
      (`5m`), meaning zero synthetic canary probes reached the gateway's
      `WorkloadIdentityMiddleware`. Separated from `gateway_zero_permitted_requests`
      so operators can immediately distinguish **"the prober stopped running or
      stopped reaching the gateway"** from **"the gateway is refusing everything"**:
      1. If `gateway_canary_pod_health` is also firing: `Deployment/gateway-canary`
         crashlooped, was evicted, or is unschedulable.
      2. If `gateway_canary_pod_health` is green: `gateway-canary` is running, so
         check Linkerd `HTTPRoute/gateway-canary` / `AuthorizationPolicy/gateway-canary`,
         `NetworkPolicy/gateway-canary-egress`, `CAGE_CANARY_CLIENT_IDENTITIES`,
         or `:8080` listener availability on `Deployment/gateway`.
    EOT
  }

  conditions {
    display_name = "Synthetic canary probe arrival rate == 0 at gateway for 300s (5m)"

    condition_prometheus_query_language {
      query                     = local.gateway_canary_probe_absent_promql
      duration                  = "300s"
      evaluation_interval       = "60s"
      disable_metric_validation = true
    }
  }

  depends_on = [module.gke]
}

resource "google_monitoring_alert_policy" "gateway_canary_pod_health" {
  count = local.enforcing_posture && var.enable_gateway_canary ? 1 : 0

  project               = var.project_id
  display_name          = "${var.cluster_name} - Gateway Synthetic Canary Pod Restart / Eviction (SI-4 / CA-7)"
  combiner              = "OR"
  enabled               = true
  severity              = "CRITICAL"
  notification_channels = var.lula_alert_notification_channels

  user_labels = {
    owner       = trimspace(var.lula_alert_owner)
    component   = "gateway-canary"
    control     = "si-4"
    environment = var.environment
  }

  documentation {
    mime_type = "text/markdown"
    content   = <<-EOT
      ## CAGE Gateway Synthetic Canary Pod Restart / Eviction Alert (NIST SP 800-53 SI-4 / CA-7)

      - **Owner:** `${trimspace(var.lula_alert_owner)}`
      - **Cluster:** `${var.cluster_name}` (`${var.namespace}`)
      - **Workload:** `Deployment/gateway-canary` (`cage-gateway-canary-sa`)

      Fires when `Deployment/gateway-canary` experiences a container restart
      (`kubernetes.io/container/restart_count` delta `> 0`) or has no running
      container reporting `kubernetes.io/container/uptime` for `300s` (pod
      eviction, node-pool scheduling failure, or replica scaled to `0`).
    EOT
  }

  conditions {
    display_name = "Gateway canary pod container restart > 0"

    condition_threshold {
      filter          = "resource.type = \"k8s_container\" AND resource.labels.namespace_name = \"${module.namespace.name}\" AND metadata.system_labels.top_level_controller_name = \"gateway-canary\" AND metric.type = \"kubernetes.io/container/restart_count\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "0s"

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_DELTA"
      }
    }
  }

  conditions {
    display_name = "Gateway canary container uptime absent for 300s (evicted or unscheduled)"

    condition_absent {
      filter   = "resource.type = \"k8s_container\" AND resource.labels.namespace_name = \"${module.namespace.name}\" AND metadata.system_labels.top_level_controller_name = \"gateway-canary\" AND metric.type = \"kubernetes.io/container/uptime\""
      duration = "300s"

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_MEAN"
      }
    }
  }

  depends_on = [module.gke]
}

