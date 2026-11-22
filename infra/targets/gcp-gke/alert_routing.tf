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

# ─── Target-Wide Cloud Monitoring Alert Channel Resolution & Heartbeat (POAM-2026-230) ───
#
# Reference Architecture Boundary:
#   CAGE is a reference architecture, not a deployed production service. By design,
#   the verified terminal destination for Cloud Monitoring AlertPolicies and the
#   compliance-bridge notifier on GKE is a GCP Pub/Sub topic/subscription
#   (var.alert_notification_channels / var.alert_pubsub_topic), rather than personal
#   email, SMS, or commercial paging fan-out. Adopters deploying CAGE in production
#   either attach their incident-response fan-out behind that Pub/Sub topic or bind
#   additional verified NotificationChannels.
#
# Plan-Time Validity (Property 1):
#   Every entry in var.alert_notification_channels is looked up via
#   data.google_monitoring_notification_channel.bound, and every
#   google_monitoring_alert_policy resource in this target carries a lifecycle
#   precondition requiring local.alert_channels_valid (non-empty set, every channel
#   resolved with a valid resource name, and enabled == true). Placing the
#   precondition directly on each protected policy ensures targeted plans
#   (-target=google_monitoring_alert_policy.<name>) still fail closed (POAM-2026-180)
#   while terraform destroy succeeds without channel inputs (POAM-2026-174).

data "google_monitoring_notification_channel" "bound" {
  for_each = local.enforcing_posture ? {
    for idx, ch in var.alert_notification_channels : tostring(idx) => ch
  } : {}

  project      = var.project_id
  display_name = trimspace(each.value.display_name)
  type         = each.value.type != null && trimspace(each.value.type) != "" ? trimspace(each.value.type) : null
  labels       = length(each.value.labels) > 0 ? each.value.labels : null
}

locals {
  resolved_alert_notification_channels = local.enforcing_posture ? [
    for idx in range(length(var.alert_notification_channels)) :
    data.google_monitoring_notification_channel.bound[tostring(idx)].name
  ] : []

  alert_channels_valid = !local.enforcing_posture || (
    length(var.alert_notification_channels) > 0 &&
    length(data.google_monitoring_notification_channel.bound) == length(var.alert_notification_channels) &&
    alltrue([
      for idx, spec in var.alert_notification_channels :
      data.google_monitoring_notification_channel.bound[tostring(idx)].enabled == true &&
      can(
        regex(
          "^projects/[^/]+/notificationChannels/[^/]+$",
          data.google_monitoring_notification_channel.bound[tostring(idx)].name,
        )
      ) &&
      (
        spec.name == null ||
        trimspace(spec.name) == "" ||
        data.google_monitoring_notification_channel.bound[tostring(idx)].name == trimspace(spec.name)
      )
    ])
  )

  effective_compliance_alert_channel = local.enforcing_posture ? trimspace(var.compliance_alert_channel) : (
    trimspace(var.compliance_alert_channel) != "" ? trimspace(var.compliance_alert_channel) : "console"
  )

  alert_channels_error_message = trimspace(<<-EOT
    [POAM-2026-230] Enforcing posture refuses empty, disabled, or mismatched Cloud Monitoring notification channels. To remediate: (1) If upgrading from lula_alert_notification_channels (ignored with 'Warning: Value for undeclared variable' in .tfvars), migrate to alert_notification_channels = [{ display_name = "<channel-display-name>", type = "pubsub" }] in gitignored infra/targets/gcp-gke/terraform.auto.tfvars (see AL-01 in docs/BREAKING_CHANGES.md). (2) On a new project, create a Pub/Sub topic + Cloud Monitoring channel ('gcloud pubsub topics create cage-alerts --project=${var.project_id}' and 'gcloud beta monitoring channels create --project=${var.project_id} --display-name=cage-alerts-pubsub --type=pubsub --channel-labels=topic=projects/${var.project_id}/topics/cage-alerts') and bind it in terraform.auto.tfvars (see terraform.auto.tfvars.example). (3) If an existing channel is disabled, run 'gcloud beta monitoring channels update <CHANNEL_ID> --enabled --project=${var.project_id}'. (4) If a bound channel was deleted out-of-band and you are running terraform destroy, pass -var='alert_notification_channels=[]' so data.google_monitoring_notification_channel.bound is skipped during teardown.
  EOT
  )
}

# ─── Synthetic Alert Pipeline Heartbeat Policy (POAM-2026-230 Property 3) ─────
# Tripped exclusively by scripts/verify_alert_delivery.py writing
# custom.googleapis.com/cage/alert_heartbeat_probe = 1 (and reset to 0 once
# observed at the destination Pub/Sub subscription). Never trip real operational
# policies for scheduled delivery tests: synthetic pages on real alarms train
# operators to ignore them.
#
# Explicit MetricDescriptor is required so google_monitoring_alert_policy
# creation succeeds on a brand-new GCP project before any probe sample has been
# written (Cloud Monitoring returns 404 on condition_threshold when a custom
# metric descriptor does not yet exist).

resource "google_monitoring_metric_descriptor" "alert_heartbeat_probe" {
  count = local.enforcing_posture ? 1 : 0

  project      = var.project_id
  type         = "custom.googleapis.com/cage/alert_heartbeat_probe"
  metric_kind  = "GAUGE"
  value_type   = "INT64"
  display_name = "CAGE Alert Pipeline Synthetic Heartbeat Probe"
  description  = "Synthetic gauge (0 = idle, 1 = probe active) written exclusively by scripts/verify_alert_delivery.py to verify end-to-end Cloud Monitoring alert delivery without tripping operational alarms (POAM-2026-230)."
}

resource "google_monitoring_alert_policy" "alert_pipeline_heartbeat" {
  count = local.enforcing_posture ? 1 : 0

  project               = var.project_id
  display_name          = "${var.cluster_name} - Alert Pipeline Synthetic Heartbeat (No Action Required)"
  combiner              = "OR"
  enabled               = true
  severity              = "WARNING"
  notification_channels = local.resolved_alert_notification_channels

  alert_strategy {
    auto_close = "1800s"
  }

  user_labels = {
    owner       = trimspace(var.alert_owner_label)
    component   = "alert-pipeline-heartbeat"
    control     = "ca-7"
    environment = var.environment
    alert_kind  = "heartbeat"
  }

  documentation {
    mime_type = "text/markdown"
    content   = <<-EOT
      ## SYNTHETIC PIPELINE HEARTBEAT — NO OPERATOR ACTION REQUIRED (`POAM-2026-230`)

      - **Owner Label (metadata only; routes nothing):** `${trimspace(var.alert_owner_label)}`
      - **Cluster:** `${var.cluster_name}` (`${var.namespace}`)
      - **Delivery Route:** Bound `var.alert_notification_channels` (GCP Pub/Sub terminal sink in reference architecture)

      Synthetic end-to-end delivery probe tripped by `scripts/verify_alert_delivery.py`
      writing `custom.googleapis.com/cage/alert_heartbeat_probe > 0` and immediately
      resetting to `0` once observed on the destination subscription. Requires **no
      operator action**.
    EOT
  }

  conditions {
    display_name = "Synthetic alert-pipeline heartbeat probe > 0"

    condition_threshold {
      filter          = "resource.type = \"global\" AND metric.type = \"custom.googleapis.com/cage/alert_heartbeat_probe\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "0s"

      aggregations {
        alignment_period     = "60s"
        per_series_aligner   = "ALIGN_MAX"
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

  depends_on = [
    module.gke,
    google_monitoring_metric_descriptor.alert_heartbeat_probe,
  ]
}

# ─── Compliance-Bridge Pub/Sub Alert Publisher IAM (POAM-2026-230) ────────────
# Grants least-privilege topic-scoped publisher authority exclusively to the
# dedicated compliance-bridge GSA when PubSubNotifier is the active notifier.

resource "google_pubsub_topic_iam_member" "compliance_bridge_alert_publisher" {
  count = (
    var.enable_compliance_bridge &&
    lower(local.effective_compliance_alert_channel) == "pubsub" &&
    trimspace(var.alert_pubsub_topic) != ""
  ) ? 1 : 0

  project = var.project_id
  topic   = trimspace(var.alert_pubsub_topic)
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:${google_service_account.compliance_bridge.email}"
}

