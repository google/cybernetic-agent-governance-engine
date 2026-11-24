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
# registry yields up == 1 while zero cage_* series arrive.
#
# POAM-2026-230 Finding B (Rollout-Noise Elimination):
#   1. Aggregate `up` across replicas via `max by (job, namespace) (up{...}) == 0`
#      so a terminating or starting pod with `up == 0` never fires per-pod alerts
#      while another replica serves `up == 1`.
#   2. Use a `10m` `absent_over_time(...[10m])` lookback paired with a `600s` (`10m`)
#      sustain duration (exceeding the observed 6–7 minute single-replica rollout
#      turnover + GMP target-discovery lag) and `alert_strategy.auto_close = "1800s"`.

locals {
  gateway_metrics_scrape_failure_promql = join(" or ", [
    "(max by (job, namespace) (up{job=\"gateway-metrics\",namespace=\"${module.namespace.name}\"}) == 0)",
    "absent_over_time(up{job=\"gateway-metrics\",namespace=\"${module.namespace.name}\"}[10m])",
    "absent_over_time(cage_event_loop_lag_seconds_count{namespace=\"${module.namespace.name}\"}[10m])",
    "absent_over_time(cage_gateway_gated_requests_total{namespace=\"${module.namespace.name}\",outcome=\"blocked\"}[10m])",
    "absent_over_time(cage_gateway_gated_requests_total{namespace=\"${module.namespace.name}\",outcome=\"permitted\"}[10m])",
    "absent_over_time(cage_gateway_canary_requests_total{namespace=\"${module.namespace.name}\",outcome=\"blocked\"}[10m])",
    "absent_over_time(cage_gateway_canary_requests_total{namespace=\"${module.namespace.name}\",outcome=\"permitted\"}[10m])",
    "absent_over_time(cage_gateway_evidence_records_appended_total{namespace=\"${module.namespace.name}\"}[10m])",
    "absent_over_time(cage_gateway_evidenced_requests_permitted_total{namespace=\"${module.namespace.name}\"}[10m])",
  ])
  compliance_bridge_metrics_scrape_failure_promql = join(" or ", [
    "(max by (job, namespace) (up{job=\"compliance-bridge-metrics\",namespace=\"${module.namespace.name}\"}) == 0)",
    "absent_over_time(up{job=\"compliance-bridge-metrics\",namespace=\"${module.namespace.name}\"}[10m])",
    "absent_over_time(cage_lula_audit_not_satisfied_controls{namespace=\"${module.namespace.name}\"}[10m])",
    "absent_over_time(cage_lula_audit_insufficient_traffic_controls{namespace=\"${module.namespace.name}\"}[10m])",
    "absent_over_time(cage_lula_audit_insufficient_sample_controls{namespace=\"${module.namespace.name}\"}[10m])",
    "absent_over_time(cage_lula_audit_last_healthy_run_timestamp_seconds{namespace=\"${module.namespace.name}\"}[10m])",
    "absent_over_time(cage_evidence_verified_batches{namespace=\"${module.namespace.name}\"}[10m])",
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
  # dropped canary prober triggers gateway_canary_probe_absent / gateway_canary_pod_health
  # (component = "gateway-canary") rather than misattributing an outage to gateway.
  gateway_zero_permitted_requests_promql = join(" ", [
    "(sum(rate(cage_gateway_gated_requests_total{job=\"gateway-metrics\",namespace=\"${module.namespace.name}\",outcome=\"permitted\"}[5m])) == 0)",
    "and",
    "(sum(rate(cage_gateway_canary_requests_total{job=\"gateway-metrics\",namespace=\"${module.namespace.name}\"}[5m])) > 0)",
  ])
  gateway_canary_probe_absent_promql = "sum(rate(cage_gateway_canary_requests_total{job=\"gateway-metrics\",namespace=\"${module.namespace.name}\"}[5m])) == 0"
  # POAM-2026-217: Two-ways-of-counting rate reconciliation between ingress-counted
  # permitted requests (WorkloadIdentityMiddleware) and Redis-acknowledged stream
  # appends (EvidenceStreamSink._acknowledge). Evaluates rate() over a 15m window
  # (longer than both EvidenceStreamSink group-commit/CAS retry lag, PodMonitoring's
  # 15s scrape cadence, and EvidenceCustodian's 300s flush/verify interval) and
  # sustains for 600s (10m) so asynchronous batching and boundary skew at t=window-edge
  # never trigger false positives under normal or burst load.
  gateway_evidence_reconciliation_min_requests = 5
  gateway_evidence_reconciliation_ratio_floor  = "0.85"
  gateway_evidence_append_reconciliation_promql = join(" ", [
    "((sum(rate(cage_gateway_gated_requests_total{job=\"gateway-metrics\",namespace=\"${module.namespace.name}\",outcome=\"permitted\"}[15m])) >= (3 / 900))",
    "and",
    "((sum(rate(cage_gateway_evidence_records_appended_total{job=\"gateway-metrics\",namespace=\"${module.namespace.name}\"}[15m])) or vector(0)) == 0))",
    "or",
    "((((sum(rate(cage_gateway_evidence_records_appended_total{job=\"gateway-metrics\",namespace=\"${module.namespace.name}\"}[15m])) or vector(0))",
    "+",
    "(sum(rate(cage_evidence_trace_shed_total{job=\"gateway-metrics\",namespace=\"${module.namespace.name}\"}[15m])) or vector(0)))",
    "/",
    "(sum(rate(cage_gateway_evidenced_requests_permitted_total{job=\"gateway-metrics\",namespace=\"${module.namespace.name}\"}[15m])) >= (${local.gateway_evidence_reconciliation_min_requests} / 900)))",
    "< ${local.gateway_evidence_reconciliation_ratio_floor})",
  ])
}

resource "google_monitoring_alert_policy" "prometheus_metrics_scrape_liveness" {
  count = local.enforcing_posture ? 1 : 0

  project               = var.project_id
  display_name          = "${var.cluster_name} - GMP Metrics Scrape & Series Arrival Down / Absent (AU-12)"
  combiner              = "OR"
  enabled               = true
  severity              = "CRITICAL"
  notification_channels = local.resolved_alert_notification_channels

  alert_strategy {
    auto_close = "1800s"
  }

  user_labels = {
    owner       = trimspace(var.alert_owner_label)
    component   = "metrics-pipeline"
    control     = "au-12"
    environment = var.environment
  }

  documentation {
    mime_type = "text/markdown"
    content   = <<-EOT
      ## CAGE GMP Metrics Scrape & Named-Series Arrival Alert (NIST SP 800-53 AU-12 / AU-5)

      - **Owner Label (metadata only; routes nothing):** `${trimspace(var.alert_owner_label)}`
      - **Delivery Route:** Bound `var.alert_notification_channels` (GCP Pub/Sub terminal sink in reference architecture)
      - **Cluster:** `${var.cluster_name}` (`${var.namespace}`)
      - **Targets:** `PodMonitoring/gateway-metrics` (`:9090/metrics`)${var.enable_compliance_bridge ? " and `PodMonitoring/compliance-bridge-metrics` (`:9090/metrics`)" : ""}

      Fires when GKE Managed Prometheus records workload-wide `max by (job, namespace) (up) == 0`
      (HTTP `403` from Linkerd `Server` / `AuthorizationPolicy`, `probeCidrs` source-IP
      mismatch, `NetworkPolicy` drop, or connection failure across all replicas),
      `absent_over_time(up[10m])` (missing `PodMonitoring` target or collector outage),
      or `absent_over_time(...[10m])` on startup-registered `cage_*` series continuously
      for `600s` (`10m`, exceeding single-replica rolling deploy turnover so normal
      rollouts do not emit alert fatigue).
    EOT
  }

  conditions {
    display_name = "GMP PodMonitoring scrape target down (max up == 0) or named cage_* series absent for 10m"

    condition_prometheus_query_language {
      query                     = local.prometheus_metrics_scrape_liveness_promql
      duration                  = "600s"
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
#   random 400/404 scanner noise will count toward outcome="blocked" and trigger
#   this alert — narrow the blocked HTTP status predicate (or split client_error
#   out of blocked/permitted) before opening ingress.
#
# Outage & Canary Attribution Partition (separated because Cloud Monitoring
# restricts prometheus_query_language alert policies to one condition per policy):
#   1. gateway_sustained_refusal_ratio (component="gateway", 180s, >= 5 req / 5m):
#      fires during the initial retry burst of a total-denial event or an active
#      adversarial flood, without firing on single-shot probes.
#   2. gateway_zero_permitted_requests (component="gateway", 900s, gated on
#      var.enable_gateway_canary): fires when rate(permitted) == 0 AND
#      rate(cage_gateway_canary_requests_total) > 0 — proving the canary prober
#      IS reaching WorkloadIdentityMiddleware and the gateway itself is refusing
#      everything after external callers backed off.
#   3. gateway_canary_probe_absent (component="gateway-canary", 300s, gated on
#      var.enable_gateway_canary): fires when rate(cage_gateway_canary_requests_total) == 0
#      — proving synthetic probes stopped reaching WorkloadIdentityMiddleware
#      (dead/wedged prober, NetworkPolicy drop, or broken HTTPRoute/gateway-canary).
#   4. gateway_canary_pod_health (component="gateway-canary", workload-aggregated
#      k8s_container restart_count > 0 OR uptime absent for 300s): immediately
#      separates "Deployment/gateway-canary crashed or was evicted" from "canary
#      pod is running, but mesh/network delivery to gateway:8080 broke".

resource "google_monitoring_alert_policy" "gateway_sustained_refusal_ratio" {
  count = local.enforcing_posture ? 1 : 0

  project               = var.project_id
  display_name          = "${var.cluster_name} - Gateway Sustained Refusal Ratio >= 95% (SI-4 / AU-5)"
  combiner              = "OR"
  enabled               = true
  severity              = "CRITICAL"
  notification_channels = local.resolved_alert_notification_channels

  alert_strategy {
    auto_close = "1800s"
  }

  user_labels = {
    owner       = trimspace(var.alert_owner_label)
    component   = "gateway"
    control     = "si-4"
    environment = var.environment
  }

  documentation {
    mime_type = "text/markdown"
    content   = <<-EOT
      ## CAGE Gateway Sustained Refusal-Ratio Alert (NIST SP 800-53 SI-4 / AU-5)

      - **Owner Label (metadata only; routes nothing):** `${trimspace(var.alert_owner_label)}`
      - **Delivery Route:** Bound `var.alert_notification_channels` (GCP Pub/Sub terminal sink in reference architecture)
      - **Cluster:** `${var.cluster_name}` (`${var.namespace}`)
      - **Metric:** `cage_gateway_gated_requests_total{outcome="blocked"|"permitted"}` on `PodMonitoring/gateway-metrics` (`:9090/metrics`)

      Fires when at least `${local.gateway_refusal_ratio_min_requests}` non-open
      gateway requests arrive within `5m` and the `blocked` share stays
      `>= ${local.gateway_refusal_ratio_threshold}` for `180s` (`OPEN_EXACT_PATHS`
      such as `/health`, `/healthz`, and JWKS are excluded so kubelet probes
      never dilute the denominator).${var.enable_gateway_canary ? " Paired with `gateway_zero_permitted_requests` (`rate(permitted) == 0 and rate(canary) > 0` over `900s`) and `gateway_canary_probe_absent` (`rate(canary) == 0` over `300s`) so detection persists if callers back off while distinguishing gateway refusal from prober failure." : ""}

      ### Triage Checklist
      1. **Fail-closed dependency outage (gateway alive, `/healthz` = `200`, routes `403`/`503`):**
         Correlate `cage_governance_infrastructure_blocks_total{dependency,code}`
         against `503` responses, then check gateway logs for quarantine Redis /
         evidence stream connectivity, OPA UDS sidecar readiness, KMS signing
         errors, or `INGRESS_IDENTITY_*` Linkerd `l5d-client-id` proxy mismatches.
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

  lifecycle {
    precondition {
      condition     = local.alert_channels_valid
      error_message = local.alert_channels_error_message
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
  notification_channels = local.resolved_alert_notification_channels

  alert_strategy {
    auto_close = "1800s"
  }

  user_labels = {
    owner       = trimspace(var.alert_owner_label)
    component   = "gateway"
    control     = "si-4"
    environment = var.environment
  }

  documentation {
    mime_type = "text/markdown"
    content   = <<-EOT
      ## CAGE Gateway Zero Permitted Gated Requests Alert (NIST SP 800-53 SI-4 / AU-5)

      - **Owner Label (metadata only; routes nothing):** `${trimspace(var.alert_owner_label)}`
      - **Delivery Route:** Bound `var.alert_notification_channels` (GCP Pub/Sub terminal sink in reference architecture)
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
      triggers `gateway_canary_probe_absent` / `gateway_canary_pod_health` under
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

  lifecycle {
    precondition {
      condition     = local.alert_channels_valid
      error_message = local.alert_channels_error_message
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
  notification_channels = local.resolved_alert_notification_channels

  alert_strategy {
    auto_close = "1800s"
  }

  user_labels = {
    owner       = trimspace(var.alert_owner_label)
    component   = "gateway-canary"
    control     = "si-4"
    environment = var.environment
  }

  documentation {
    mime_type = "text/markdown"
    content   = <<-EOT
      ## CAGE Gateway Synthetic Canary Probe Absence Alert (NIST SP 800-53 SI-4 / CA-7)

      - **Owner Label (metadata only; routes nothing):** `${trimspace(var.alert_owner_label)}`
      - **Delivery Route:** Bound `var.alert_notification_channels` (GCP Pub/Sub terminal sink in reference architecture)
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

  lifecycle {
    precondition {
      condition     = local.alert_channels_valid
      error_message = local.alert_channels_error_message
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
  notification_channels = local.resolved_alert_notification_channels

  # POAM-2026-230 Finding A: ReplicaSet replacements delete old pod series;
  # REDUCE_SUM/REDUCE_MAX + 30m auto_close prevents 7-day orphaned incidents.
  alert_strategy {
    auto_close = "1800s"
  }

  user_labels = {
    owner       = trimspace(var.alert_owner_label)
    component   = "gateway-canary"
    control     = "si-4"
    environment = var.environment
  }

  documentation {
    mime_type = "text/markdown"
    content   = <<-EOT
      ## CAGE Gateway Synthetic Canary Pod Restart / Eviction Alert (NIST SP 800-53 SI-4 / CA-7)

      - **Owner Label (metadata only; routes nothing):** `${trimspace(var.alert_owner_label)}`
      - **Delivery Route:** Bound `var.alert_notification_channels` (GCP Pub/Sub terminal sink in reference architecture)
      - **Cluster:** `${var.cluster_name}` (`${var.namespace}`)
      - **Workload:** `Deployment/gateway-canary` (`cage-gateway-canary-sa`)

      Fires when `Deployment/gateway-canary` experiences a container restart
      (workload-aggregated `kubernetes.io/container/restart_count` delta `> 0`) or
      has no running container reporting `kubernetes.io/container/uptime` for `300s`
      (pod eviction, node-pool scheduling failure, or replica scaled to `0`).
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
        alignment_period     = "300s"
        per_series_aligner   = "ALIGN_DELTA"
        cross_series_reducer = "REDUCE_SUM"
      }
    }
  }

  conditions {
    display_name = "Gateway canary container uptime absent for 300s (evicted or unscheduled)"

    condition_absent {
      filter   = "resource.type = \"k8s_container\" AND resource.labels.namespace_name = \"${module.namespace.name}\" AND metadata.system_labels.top_level_controller_name = \"gateway-canary\" AND metric.type = \"kubernetes.io/container/uptime\""
      duration = "300s"

      aggregations {
        alignment_period     = "60s"
        per_series_aligner   = "ALIGN_MEAN"
        cross_series_reducer = "REDUCE_MAX"
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

resource "google_monitoring_alert_policy" "gateway_evidence_append_reconciliation" {
  count = local.enforcing_posture ? 1 : 0

  project               = var.project_id
  display_name          = "${var.cluster_name} - Gateway Permitted Traffic vs Evidence Appends Deficit (AU-5 / AU-12)"
  combiner              = "OR"
  enabled               = true
  severity              = "CRITICAL"
  notification_channels = local.resolved_alert_notification_channels

  alert_strategy {
    auto_close = "1800s"
  }

  user_labels = {
    owner       = trimspace(var.alert_owner_label)
    component   = "gateway"
    control     = "au-5"
    environment = var.environment
  }

  documentation {
    mime_type = "text/markdown"
    content   = <<-EOT
      ## CAGE Gateway Evidence Append Reconciliation Alert (NIST SP 800-53 AU-5 / AU-12 / POAM-2026-217)

      - **Owner Label (metadata only; routes nothing):** `${trimspace(var.alert_owner_label)}`
      - **Delivery Route:** Bound `var.alert_notification_channels` (GCP Pub/Sub terminal sink in reference architecture)
      - **Cluster:** `${var.cluster_name}` (`${var.namespace}`)
      - **Ingress Metrics:** `cage_gateway_gated_requests_total{outcome="permitted"}` and `cage_gateway_evidenced_requests_permitted_total` (`WorkloadIdentityMiddleware`)
      - **Custody Metric:** `cage_gateway_evidence_records_appended_total` (`EvidenceStreamSink._acknowledge` after Redis `XADD`)

      Reconciles two independent rate series across the gateway request boundary and
      the Redis evidence stream over a `15m` window (`POAM-2026-217`), evaluated
      across a sustained `600s` (`10m`) duration (exceeding group-commit batching,
      `15s` `PodMonitoring` scrape skew, and `EvidenceCustodian`'s `300s` cadence
      so asynchronous flush lag at window boundaries does not trigger false alerts).
      Fires when for `600s` either:
      1. Permitted request rate is `>= 3 / 15m` while `rate(cage_gateway_evidence_records_appended_total[15m]) == 0`
         (total append stall), **or**
      2. `(rate(appended[15m]) + rate(trace_shed[15m])) / rate(evidenced_requests_permitted[15m]) < ${local.gateway_evidence_reconciliation_ratio_floor}`
         with `>= ${local.gateway_evidence_reconciliation_min_requests}` evidenced permitted requests per `15m`
         (sustained per-route evidence loss even while synthetic canary probes
         continue appending on `/governance/validate-action`).

      **Operator note (`EC-1`):** Under `EVIDENCE_CHAIN_BLOCKING=true` (enforcing
      default), a `memorystore_governance` Redis custody outage fails all governed
      traffic closed (`503` — full gateway outage, triggering `gateway_sustained_refusal_ratio`
      and `gateway_zero_permitted_requests`). This reconciliation policy catches the
      complementary failure mode (`EVIDENCE_CHAIN_BLOCKING=false` break-glass or a
      code-path regression) where traffic is permitted without durable Redis appends.
    EOT
  }

  conditions {
    display_name = "Sustained 15m evidence-append rate deficit (< ${local.gateway_evidence_reconciliation_ratio_floor} of evidenced permitted rate) for 600s (10m)"

    condition_prometheus_query_language {
      query                     = local.gateway_evidence_append_reconciliation_promql
      duration                  = "600s"
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

resource "google_monitoring_alert_policy" "gateway_aged_unknown_actuations" {
  count = local.enforcing_posture ? 1 : 0

  project               = var.project_id
  display_name          = "${var.cluster_name} - Aged Unresolved UNKNOWN Actuations (SC-4 / SC-24)"
  combiner              = "OR"
  enabled               = true
  severity              = "CRITICAL"
  notification_channels = local.resolved_alert_notification_channels

  alert_strategy {
    auto_close = "1800s"
  }

  user_labels = {
    owner       = trimspace(var.alert_owner_label)
    component   = "gateway"
    control     = "sc-24"
    environment = var.environment
  }

  documentation {
    mime_type = "text/markdown"
    content   = <<-EOT
      ## CAGE Aged Unresolved UNKNOWN Actuations Alert (NIST SP 800-53 SC-4 / SC-24 / POAM-2026-232)

      - **Owner Label (metadata only; routes nothing):** `${trimspace(var.alert_owner_label)}`
      - **Delivery Route:** Bound `var.alert_notification_channels` (GCP Pub/Sub terminal sink in reference architecture)
      - **Cluster:** `${var.cluster_name}` (`${var.namespace}`)
      - **Metric:** `cage_gateway_aged_unknown_actuations`

      Fires whenever one or more confirmed fiscal reservations originating from
      `ActuationOutcome.UNKNOWN` actuations remain unresolved beyond the
      reconciliation age threshold (`max_age_seconds`). Daily fiscal capacity stays
      held fail-closed until broker lookup or operator settlement resolves the trade.
    EOT
  }

  conditions {
    display_name = "Aged unresolved UNKNOWN actuations > 0 for 300s"

    condition_prometheus_query_language {
      query                     = "max(cage_gateway_aged_unknown_actuations{job=\"gateway-metrics\",namespace=\"${module.namespace.name}\"}) > 0"
      duration                  = "300s"
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
