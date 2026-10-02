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
  # Service account IDs (GSAs)
  sa_gateway           = "cage-gateway"
  sa_reconciler        = "cage-reconciler"
  sa_compliance_bridge = "cage-compliance-bridge"
  sa_lula              = "cage-lula"
  sa_vllm              = "cage-vllm"
  sa_agentsight        = "cage-agentsight"
  sa_benchmark         = "cage-benchmark"
  sa_langfuse          = "langfuse"
  sa_clickhouse        = "cage-clickhouse"

  # Kubernetes ServiceAccount names (KSAs), one per workload (POAM-2026-079).
  # The "-sa" suffix matches the Linkerd mesh identities in
  # deployment/k8s/linkerd-mtls-policy.yaml, so one KSA carries both the
  # Workload Identity and the SPIFFE identity of a workload.
  ksa_gateway           = "cage-gateway-sa"
  ksa_advisor           = "cage-advisor-sa"
  ksa_reconciler        = "cage-reconciler-sa"
  ksa_compliance_bridge = "cage-compliance-bridge-sa"
  ksa_vllm              = "cage-vllm-sa"
  ksa_lula              = "cage-lula-sa"
  ksa_benchmark         = "cage-benchmark-sa"
  ksa_langfuse          = "langfuse-sa"
  ksa_clickhouse        = "cage-clickhouse-sa"

  # vLLM runs in var.namespace when deployed by Terraform and in
  # "vllm-inference" when deployed from deployment/k8s/ manifests.
  vllm_workload_namespaces = distinct([var.namespace, "vllm-inference"])

  # Resolve default model bucket name when var.model_bucket_name is empty
  model_bucket_name = var.model_bucket_name != "" ? var.model_bucket_name : "${var.project_id}-models"
}

# ---------------------------------------------------------------------------
# Service Account Definitions
# ---------------------------------------------------------------------------

resource "google_service_account" "gateway" {
  account_id   = local.sa_gateway
  display_name = "CAGE Gateway Service Account"
  description  = "Least-privilege SA for the CAGE gateway. Reads model weights, accesses secrets, signs routing seals with the gateway-seal key. (POAM-002 / POAM-2026-079 / AC-6)"
  project      = var.project_id
}

resource "google_service_account" "reconciler" {
  account_id   = local.sa_reconciler
  display_name = "CAGE Reconciler Service Account"
  description  = "SA for the ground-truth reconciliation worker. Sole signer on the reconciler-snapshot key (G8 / POAM-2026-079)."
  project      = var.project_id
}

resource "google_service_account" "compliance_bridge" {
  account_id   = local.sa_compliance_bridge
  display_name = "CAGE Compliance Bridge Service Account"
  description  = "Least-privilege SA for the compliance bridge. Writes OSCAL artifacts to GCS and signs evidence batches with the compliance-evidence key. (POAM-002 / POAM-2026-079 / AC-6)"
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
  description  = "Least-privilege SA for vLLM inference. Reads model weights from GCS. Holds no KMS role (POAM-002 / POAM-2026-079 / AC-6)"
  project      = var.project_id
}

resource "google_service_account" "benchmark" {
  account_id   = local.sa_benchmark
  display_name = "CAGE Benchmark Service Account"
  description  = "SA for the paper benchmark job (deployment/k8s/benchmark-job.yaml). Signs only with the benchmark-signing key, which no verifier trusts (POAM-2026-079)."
  project      = var.project_id
}

resource "google_service_account" "agentsight" {
  account_id   = local.sa_agentsight
  display_name = "CAGE AgentSight Service Account"
  description  = "Least-privilege SA for AgentSight eBPF monitoring. Writes telemetry to Cloud Logging and Monitoring. (POAM-002 / AC-6)"
  project      = var.project_id
}

resource "google_service_account" "clickhouse" {
  account_id   = local.sa_clickhouse
  display_name = "CAGE ClickHouse Query-Plane Service Account"
  description  = "Sole identity with IAM on the dedicated, non-retention-locked ClickHouse cold-tier bucket. No access to the evidence WORM bucket. (§2.6 / AC-6)"
  project      = var.project_id
}

resource "google_service_account" "langfuse" {
  account_id   = local.sa_langfuse
  display_name = "CAGE Langfuse Service Account"
  description  = "Least-privilege SA for Langfuse observability. Connects to Cloud SQL via IAM authentication and Memorystore app cache. (POAM-002 / POAM-2026-079 / AC-6)"
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
    expression  = "resource.name.startsWith(\"projects/_/buckets/${local.model_bucket_name}\")"
  }
}

resource "google_project_iam_member" "gateway_secret_accessor" {
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.gateway.email}"
}

resource "google_kms_crypto_key_iam_member" "gateway_kms_encrypter_decrypter" {
  count         = var.enable_cmek ? 1 : 0
  crypto_key_id = local.cmek_key_id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${google_service_account.gateway.email}"
}

resource "google_project_iam_member" "gateway_memorystore_user" {
  count   = var.enable_memorystore_iam_auth ? 1 : 0
  project = var.project_id
  role    = "roles/memorystore.dbConnectionUser"
  member  = "serviceAccount:${google_service_account.gateway.email}"
}

# ---------------------------------------------------------------------------
# IAM Role Bindings — Reconciler
# Roles: Memorystore DB Connection User (when IAM auth is enabled; signing role
# is bound per-key in kms_signing.tf)
# ---------------------------------------------------------------------------

resource "google_project_iam_member" "reconciler_memorystore_user" {
  count   = var.enable_memorystore_iam_auth ? 1 : 0
  project = var.project_id
  role    = "roles/memorystore.dbConnectionUser"
  member  = "serviceAccount:${google_service_account.reconciler.email}"
}

# ---------------------------------------------------------------------------
# IAM Role Bindings — Compliance Bridge
# Roles: WORM bucket Storage Object Creator (append-only evidence & OSCAL artifacts),
#        WORM bucket Storage Object Viewer (reads), Secret Manager Accessor (§5.1),
#        Memorystore DB Connection User (EvidenceCustodian reads the gateway's
#        evidence stream and keeps its cursor on the governance instance).
# Storage roles are bucket-scoped only: a project-wide grant would also reach
# the ClickHouse tiering bucket, which only the ClickHouse GSA may touch.
# ---------------------------------------------------------------------------

resource "google_storage_bucket_iam_member" "compliance_bridge_worm_creator" {
  bucket = module.worm_bucket.bucket_name
  role   = "roles/storage.objectCreator"
  member = "serviceAccount:${google_service_account.compliance_bridge.email}"
}

resource "google_storage_bucket_iam_member" "compliance_bridge_worm_viewer" {
  bucket = module.worm_bucket.bucket_name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.compliance_bridge.email}"
}

resource "google_project_iam_member" "compliance_bridge_memorystore_user" {
  count   = var.enable_memorystore_iam_auth ? 1 : 0
  project = var.project_id
  role    = "roles/memorystore.dbConnectionUser"
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
    expression  = "resource.name.startsWith(\"projects/_/buckets/${local.model_bucket_name}\")"
  }
}

resource "google_storage_bucket_iam_member" "vllm_bucket_reader" {
  count  = var.enable_vllm ? 1 : 0
  bucket = local.model_bucket_name
  role   = "roles/storage.legacyBucketReader"
  member = "serviceAccount:${google_service_account.vllm.email}"
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
# IAM Role Bindings — Langfuse
# Roles: Cloud SQL Client, Cloud SQL Instance User (IAM DB authn, no static password),
#        Memorystore DB Connection User (when IAM auth is enabled)
# ---------------------------------------------------------------------------

resource "google_project_iam_member" "langfuse_cloudsql_client" {
  project = var.project_id
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${google_service_account.langfuse.email}"
}

resource "google_project_iam_member" "langfuse_cloudsql_instance_user" {
  project = var.project_id
  role    = "roles/cloudsql.instanceUser"
  member  = "serviceAccount:${google_service_account.langfuse.email}"
}

resource "google_project_iam_member" "langfuse_memorystore_user" {
  count   = var.enable_memorystore_iam_auth ? 1 : 0
  project = var.project_id
  role    = "roles/memorystore.dbConnectionUser"
  member  = "serviceAccount:${google_service_account.langfuse.email}"
}

# ---------------------------------------------------------------------------
# Kubernetes ServiceAccounts for Terraform-deployed workloads
# One KSA per workload, annotated to its own GSA (POAM-2026-079 / AC-5 / AC-6).
# The advisor is the untrusted neural plane: its KSA has no GSA at all, so the
# pod cannot authenticate to KMS or any other Google Cloud API.
# The reconciler runs only from deployment/k8s/reconciliation-worker.yaml, so
# its KSA is defined in deployment/k8s/service-account.yaml, not here.
# ---------------------------------------------------------------------------

locals {
  terraform_workload_ksas = {
    gateway = {
      name    = local.ksa_gateway
      gsa     = google_service_account.gateway.email
      purpose = "governance-gateway"
    }
    advisor = {
      name    = local.ksa_advisor
      gsa     = null # zero cloud identity (POAM-2026-079)
      purpose = "governed-advisor"
    }
    compliance_bridge = {
      name    = local.ksa_compliance_bridge
      gsa     = google_service_account.compliance_bridge.email
      purpose = "compliance-evidence"
    }
    vllm = {
      name    = local.ksa_vllm
      gsa     = google_service_account.vllm.email
      purpose = "model-inference"
    }
    langfuse = {
      name    = local.ksa_langfuse
      gsa     = google_service_account.langfuse.email
      purpose = "telemetry"
    }
    clickhouse = {
      name    = local.ksa_clickhouse
      gsa     = google_service_account.clickhouse.email
      purpose = "query-plane"
    }
  }
}

resource "kubernetes_service_account" "workload" {
  for_each = local.terraform_workload_ksas

  metadata {
    name      = each.value.name
    namespace = module.namespace.name
    labels = {
      "app.kubernetes.io/managed-by" = "terraform"
      "cage.io/account-purpose"      = each.value.purpose
    }
    annotations = each.value.gsa == null ? {} : {
      "iam.gke.io/gcp-service-account" = each.value.gsa
    }
  }

  depends_on = [module.namespace]
}

# ---------------------------------------------------------------------------
# Workload Identity Federation bindings
# Bind each K8s ServiceAccount to exactly one GCP ServiceAccount. The bindings
# are authoritative for roles/iam.workloadIdentityUser, so a KSA added out of
# band shows up as drift in terraform plan.
# ---------------------------------------------------------------------------

resource "google_service_account_iam_binding" "gateway_workload_identity" {
  service_account_id = google_service_account.gateway.name
  role               = "roles/iam.workloadIdentityUser"

  members = [
    "serviceAccount:${var.project_id}.svc.id.goog[${var.namespace}/${local.ksa_gateway}]",
  ]
}

resource "google_service_account_iam_binding" "reconciler_workload_identity" {
  service_account_id = google_service_account.reconciler.name
  role               = "roles/iam.workloadIdentityUser"

  members = [
    "serviceAccount:${var.project_id}.svc.id.goog[${var.namespace}/${local.ksa_reconciler}]",
  ]
}

resource "google_service_account_iam_binding" "compliance_bridge_workload_identity" {
  service_account_id = google_service_account.compliance_bridge.name
  role               = "roles/iam.workloadIdentityUser"

  members = [
    "serviceAccount:${var.project_id}.svc.id.goog[${var.namespace}/${local.ksa_compliance_bridge}]",
  ]
}

resource "google_service_account_iam_binding" "vllm_workload_identity" {
  service_account_id = google_service_account.vllm.name
  role               = "roles/iam.workloadIdentityUser"

  members = [
    for ns in local.vllm_workload_namespaces :
    "serviceAccount:${var.project_id}.svc.id.goog[${ns}/${local.ksa_vllm}]"
  ]
}

resource "google_service_account_iam_binding" "lula_workload_identity" {
  service_account_id = google_service_account.lula.name
  role               = "roles/iam.workloadIdentityUser"

  members = [
    "serviceAccount:${var.project_id}.svc.id.goog[${var.namespace}/${local.ksa_lula}]",
  ]
}

resource "google_service_account_iam_binding" "benchmark_workload_identity" {
  service_account_id = google_service_account.benchmark.name
  role               = "roles/iam.workloadIdentityUser"

  members = [
    "serviceAccount:${var.project_id}.svc.id.goog[${var.namespace}/${local.ksa_benchmark}]",
  ]
}

resource "google_service_account_iam_binding" "langfuse_workload_identity" {
  service_account_id = google_service_account.langfuse.name
  role               = "roles/iam.workloadIdentityUser"

  members = [
    "serviceAccount:${var.project_id}.svc.id.goog[${var.namespace}/${local.ksa_langfuse}]",
  ]
}

resource "google_service_account_iam_binding" "clickhouse_workload_identity" {
  service_account_id = google_service_account.clickhouse.name
  role               = "roles/iam.workloadIdentityUser"

  members = [
    "serviceAccount:${var.project_id}.svc.id.goog[${var.namespace}/${local.ksa_clickhouse}]",
  ]
}
