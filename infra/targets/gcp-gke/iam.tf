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

locals {
  # Service account IDs
  sa_gateway          = "cage-gateway"
  sa_compliance_bridge = "cage-compliance-bridge"
  sa_lula             = "cage-lula"
  sa_vllm             = "cage-vllm"
  sa_agentsight       = "cage-agentsight"
}

# ---------------------------------------------------------------------------
# Service Account Definitions
# ---------------------------------------------------------------------------

resource "google_service_account" "gateway" {
  account_id   = local.sa_gateway
  display_name = "CAGE Gateway Service Account"
  description  = "Least-privilege SA for the CAGE gateway. Reads model weights, accesses secrets, signs audit evidence. (POAM-002 / AC-6)"
  project      = var.project_id
}

resource "google_service_account" "compliance_bridge" {
  account_id   = local.sa_compliance_bridge
  display_name = "CAGE Compliance Bridge Service Account"
  description  = "Least-privilege SA for the compliance bridge. Writes OSCAL artifacts to GCS. (POAM-002 / AC-6)"
  project      = var.project_id
}

resource "google_service_account" "lula" {
  account_id   = local.sa_lula
  display_name = "CAGE Lula Validation Service Account"
  description  = "Read-only SA for Lula compliance validation. Inspects GKE Deployments for manifest assertions. (POAM-002 / AC-6)"
  project      = var.project_id
}

resource "google_service_account" "vllm" {
  account_id   = local.sa_vllm
  display_name = "CAGE vLLM Service Account"
  description  = "Least-privilege SA for vLLM inference. Reads model weights from GCS. (POAM-002 / AC-6)"
  project      = var.project_id
}

resource "google_service_account" "agentsight" {
  account_id   = local.sa_agentsight
  display_name = "CAGE AgentSight Service Account"
  description  = "Least-privilege SA for AgentSight eBPF monitoring. Writes telemetry to Cloud Logging and Monitoring. (POAM-002 / AC-6)"
  project      = var.project_id
}

# ---------------------------------------------------------------------------
# IAM Role Bindings — Gateway
# Roles: Storage Object Viewer, Secret Manager Accessor, KMS Encrypter/Decrypter
# ---------------------------------------------------------------------------

resource "google_project_iam_member" "gateway_storage_viewer" {
  project = var.project_id
  role    = "roles/storage.objectViewer"
  member  = "serviceAccount:${google_service_account.gateway.email}"

  condition {
    title       = "cage-gateway-model-bucket-only"
    description = "Restrict storage.objectViewer to the CAGE model bucket only"
    expression  = "resource.name.startsWith(\"projects/_/buckets/${var.model_bucket_name}\")"
  }
}

resource "google_project_iam_member" "gateway_secret_accessor" {
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.gateway.email}"
}

resource "google_project_iam_member" "gateway_kms_encrypter_decrypter" {
  count   = var.enable_cmek ? 1 : 0
  project = var.project_id
  role    = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member  = "serviceAccount:${google_service_account.gateway.email}"
}

# ---------------------------------------------------------------------------
# IAM Role Bindings — Compliance Bridge
# Roles: Storage Object Creator (OSCAL artifacts), Storage Object Viewer (reads)
# ---------------------------------------------------------------------------

resource "google_project_iam_member" "compliance_bridge_storage_creator" {
  project = var.project_id
  role    = "roles/storage.objectCreator"
  member  = "serviceAccount:${google_service_account.compliance_bridge.email}"
}

resource "google_project_iam_member" "compliance_bridge_storage_viewer" {
  project = var.project_id
  role    = "roles/storage.objectViewer"
  member  = "serviceAccount:${google_service_account.compliance_bridge.email}"
}

resource "google_project_iam_member" "compliance_bridge_secret_accessor" {
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.compliance_bridge.email}"
}

# ---------------------------------------------------------------------------
# IAM Role Bindings — Lula
# Roles: Container Viewer (read-only cluster inspection for Lula manifests)
# ---------------------------------------------------------------------------

resource "google_project_iam_member" "lula_container_viewer" {
  project = var.project_id
  role    = "roles/container.viewer"
  member  = "serviceAccount:${google_service_account.lula.email}"
}

# ---------------------------------------------------------------------------
# IAM Role Bindings — vLLM
# Roles: Storage Object Viewer (model weights from GCS)
# ---------------------------------------------------------------------------

resource "google_project_iam_member" "vllm_storage_viewer" {
  count   = var.enable_vllm ? 1 : 0
  project = var.project_id
  role    = "roles/storage.objectViewer"
  member  = "serviceAccount:${google_service_account.vllm.email}"

  condition {
    title       = "cage-vllm-model-bucket-only"
    description = "Restrict storage.objectViewer to the CAGE model bucket only"
    expression  = "resource.name.startsWith(\"projects/_/buckets/${var.model_bucket_name}\")"
  }
}

# ---------------------------------------------------------------------------
# IAM Role Bindings — AgentSight
# Roles: Log Writer, Metric Writer (telemetry only)
# ---------------------------------------------------------------------------

resource "google_project_iam_member" "agentsight_log_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.agentsight.email}"
}

resource "google_project_iam_member" "agentsight_metric_writer" {
  project = var.project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.agentsight.email}"
}

# ---------------------------------------------------------------------------
# Workload Identity Federation bindings
# Bind each K8s ServiceAccount to the corresponding GCP ServiceAccount.
# This eliminates the need for long-lived service account keys.
# ---------------------------------------------------------------------------

resource "google_service_account_iam_binding" "gateway_workload_identity" {
  service_account_id = google_service_account.gateway.name
  role               = "roles/iam.workloadIdentityUser"

  members = [
    "serviceAccount:${var.project_id}.svc.id.goog[${var.namespace}/${local.sa_gateway}]",
  ]
}

resource "google_service_account_iam_binding" "compliance_bridge_workload_identity" {
  service_account_id = google_service_account.compliance_bridge.name
  role               = "roles/iam.workloadIdentityUser"

  members = [
    "serviceAccount:${var.project_id}.svc.id.goog[${var.namespace}/${local.sa_compliance_bridge}]",
  ]
}

resource "google_service_account_iam_binding" "lula_workload_identity" {
  service_account_id = google_service_account.lula.name
  role               = "roles/iam.workloadIdentityUser"

  members = [
    "serviceAccount:${var.project_id}.svc.id.goog[${var.namespace}/${local.sa_lula}]",
  ]
}
