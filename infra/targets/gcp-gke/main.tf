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

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.43"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.23"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.11"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }

  # Store Terraform state in GCS bucket.
  # Activate by setting TF_BACKEND_BUCKET before running terraform init:
  #   export TF_BACKEND_BUCKET="${PROJECT_ID}-tfstate"
  #   terraform init -backend-config="bucket=${TF_BACKEND_BUCKET}"
  # D-03 remediation: backend is declared; bucket name is injected at init time
  # via -backend-config to avoid committing project-specific values.
  backend "gcs" {
    prefix = "cage/gcp-gke"
    # bucket is supplied via: terraform init -backend-config="bucket=<PROJECT>-tfstate"
    # or TF_CLI_ARGS_init="-backend-config=bucket=<PROJECT>-tfstate"
  }
}

# ─── Data Sources ─────────────────────────────────────────────────────────────

data "google_client_config" "default" {}

# Resolve project number — required for VPC Service Controls perimeter resource naming in perimeter.tf.
data "google_project" "current" {
  project_id = var.project_id
}

# ─── Provision Symmetric CMEK Key Ring & Key ──────────────────────────────────
# §5.2 / D2: Symmetric encryption-at-rest CMEK key ring (cage-keyring-${var.environment})
# kept strictly separate from the asymmetric signing key ring in kms_signing.tf.

module "kms" {
  count  = var.enable_cmek && var.kms_key_id == "" ? 1 : 0
  source = "../../modules/kms"

  project_id             = var.project_id
  environment            = var.environment
  region                 = var.region
  cage_deployment_region = var.cage_deployment_region
  protection_level       = var.environment == "dev" ? "SOFTWARE" : "HSM"
}

locals {
  cmek_key_id = var.kms_key_id != "" ? var.kms_key_id : (var.enable_cmek ? module.kms[0].crypto_key_id : "")
}

# ─── Provision GKE Cluster ────────────────────────────────────────────────────

module "gke" {
  source = "../../modules/gcp_gke_cluster"

  project_id       = var.project_id
  region           = var.region
  zone             = var.zone
  cluster_name     = var.cluster_name
  environment      = var.environment
  regional_cluster = var.regional_cluster

  # Security posture toggles
  enable_nist_compliance         = var.enable_nist_compliance
  enable_deletion_protection     = var.enable_deletion_protection
  enable_binary_authorization    = var.enable_binary_authorization
  enable_audit_logging           = var.enable_audit_logging
  enable_cmek                    = var.enable_cmek
  enable_private_master_endpoint = var.enable_private_master_endpoint
  enable_private_nodes           = var.enable_private_nodes
  enable_dataplane_v2            = var.enable_dataplane_v2
  enable_fqdn_network_policy     = var.enable_fqdn_network_policy
  release_channel                = var.release_channel
  min_master_version             = var.min_master_version
  cluster_dns_provider           = var.cluster_dns_provider

  # NIST-specific configuration
  authorized_networks       = var.authorized_networks
  kms_key_id                = local.cmek_key_id
  database_encryption_state = var.database_encryption_state

  # Pool 1: General node pool (§3: general)
  primary_node_pool_machine_type  = var.primary_node_pool_machine_type
  primary_node_pool_min_count     = var.primary_node_pool_min_count
  primary_node_pool_max_count     = var.primary_node_pool_max_count
  primary_node_pool_initial_count = var.primary_node_pool_initial_count
  primary_node_pool_disk_type     = var.primary_node_pool_disk_type

  # Pool 2: General-spot node pool (§3: general-spot, staging 0-5)
  enable_general_spot_node_pool = var.enable_general_spot_node_pool
  general_spot_machine_type     = var.general_spot_machine_type
  general_spot_min_count        = var.general_spot_min_count
  general_spot_max_count        = var.general_spot_max_count
  general_spot_initial_count    = var.general_spot_initial_count

  # Pool 3: GPU node pool (§3: gpu-l4, spot=false in every posture)
  enable_gpu_node_pool        = var.enable_gpu_node_pool
  gpu_type                    = var.gpu_type
  gpu_count                   = var.gpu_count
  gpu_node_pool_machine_type  = var.gpu_node_pool_machine_type
  gpu_node_pool_min_count     = var.gpu_node_pool_min_count
  gpu_node_pool_max_count     = var.gpu_node_pool_max_count
  gpu_node_pool_initial_count = var.gpu_node_pool_initial_count
  gpu_node_pool_spot          = var.gpu_node_pool_spot
  gpu_node_locations          = var.gpu_node_locations

  # Pool 4: ClickHouse node pool (§3: clickhouse, local SSD, tainted)
  enable_clickhouse_node_pool          = var.enable_clickhouse_node_pool
  clickhouse_node_pool_machine_type    = var.clickhouse_node_pool_machine_type
  clickhouse_node_pool_min_count       = var.clickhouse_node_pool_min_count
  clickhouse_node_pool_max_count       = var.clickhouse_node_pool_max_count
  clickhouse_node_pool_initial_count   = var.clickhouse_node_pool_initial_count
  clickhouse_node_pool_local_ssd_count = var.clickhouse_node_pool_local_ssd_count

  # GCP-specific features
  enable_gcs_fuse_csi = var.enable_gcs_fuse_csi

  # Networking
  network                = var.network
  subnetwork             = var.subnetwork
  pod_cidr               = var.pod_cidr
  service_cidr           = var.service_cidr
  master_ipv4_cidr_block = var.master_ipv4_cidr_block
}

# ─── Create Namespace ─────────────────────────────────────────────────────────

module "namespace" {
  source = "../../modules/k8s_namespace"

  name        = var.namespace
  environment = var.environment

  enable_pod_security_standards = var.enable_pod_security_standards
  pod_security_level            = var.pod_security_level

  # POAM-2026-080: every pod in the namespace gets a Linkerd proxy, so every
  # call carries a verified mTLS identity. Pods started before the injector
  # exists have no proxy; restart them after the first mesh install.
  annotations = {
    "linkerd.io/inject" = "enabled"
  }

  depends_on = [module.gke]
}

# ─── Service Mesh (Linkerd, trust anchor in Google CAS) ──────────────────────

module "service_mesh" {
  source = "../../modules/service_mesh"

  project_id             = var.project_id
  region                 = var.region
  environment            = var.environment
  master_ipv4_cidr_block = var.master_ipv4_cidr_block
  # proxy-init needs NET_ADMIN, which 'restricted' Pod Security forbids; the
  # CNI plugin sets up the redirect on the node instead.
  enable_cni = var.enable_pod_security_standards && var.pod_security_level != "privileged"

  depends_on = [module.gke]
}

# ─── GCS Bucket for Langfuse Events ───────────────────────────────────────────

resource "random_id" "bucket_suffix" {
  byte_length = 4
}

resource "google_storage_bucket" "langfuse_events" {
  name          = "langfuse-events-${var.project_id}-${random_id.bucket_suffix.hex}"
  location      = var.region
  project       = var.project_id
  force_destroy = var.environment == "dev" ? true : false

  uniform_bucket_level_access = true

  # AU-9: WORM retention (B5 fix) — 2555 days (7 years) immutable retention.
  # Prevents deletion before 2555 days AND locks the policy irreversibly.
  # Compounding with downgraded writer SA (objectCreator instead of objectAdmin)
  # ensures even the compliance bridge cannot erase evidence it writes.
  retention_policy {
    retention_period = 220752000 # 2555 days in seconds
    is_locked        = var.enable_nist_compliance ? true : false
  }

  # Lifecycle rule now transitions to cold storage, not deletes
  lifecycle_rule {
    condition {
      age = 365
    }
    action {
      type          = "SetStorageClass"
      storage_class = "ARCHIVE"
    }
  }

  labels = {
    environment            = var.environment
    managed-by             = "terraform"
    purpose                = "langfuse-traces"
    cage-deployment-region = lower(var.cage_deployment_region)
  }

  # DEP-10: Enforce data residency — GCS bucket region must match cage_deployment_region.
  # Without this precondition, a misconfigured deployment could create the compliance
  # evidence bucket in the wrong region without any Terraform-level error, silently
  # violating GDPR Art. 44 (EU_ECB) and MAS TRM §4.2 (APAC_MAS).
  # R-3, R-4: data residency must be enforced at the infrastructure layer.
  lifecycle {
    precondition {
      condition = (
        (var.cage_deployment_region == "EU_ECB" && startswith(var.region, "europe-")) ||
        (var.cage_deployment_region == "APAC_MAS" && startswith(var.region, "asia-")) ||
        (var.cage_deployment_region == "US_FED" && startswith(var.region, "us-"))
      )
      error_message = "GCS bucket region '${var.region}' does not satisfy data residency requirements for cage_deployment_region='${var.cage_deployment_region}'. EU_ECB requires europe-*, APAC_MAS requires asia-*, US_FED requires us-*. Check your tfvars file."
    }
  }
}

# ─── Evidence WORM Bucket — System of Record (§1.1, §2.6, NIST AU-9) ─────────
# Durable tamper-evident cold store for hash-chained governance evidence and
# OSCAL assessment artifacts. ClickHouse is only the query plane (§2.6); losing
# ClickHouse nodes never loses evidence persisted to this retention-locked bucket.
#
# Posture matrix (§1.1):
#   - dev:     is_locked = false, retention = 220752000s (unlocked for teardown)
#   - staging: is_locked = true,  retention = 86400s (1 day — locked short)
#   - prod:    is_locked = true,  retention = 220752000s (2555 days / 7 years)
module "worm_bucket" {
  source = "../../modules/worm_bucket"

  project_id               = var.project_id
  environment              = var.environment
  region                   = var.region
  cage_deployment_region   = var.cage_deployment_region
  bucket_name              = "${var.project_id}-evidence-worm-${var.environment}"
  enable_cmek              = var.enable_cmek
  kms_key_id               = local.cmek_key_id
  retention_period_seconds = var.environment == "staging" ? 86400 : 220752000
  is_locked                = var.environment == "prod" || var.environment == "staging" || var.enable_nist_compliance
  force_destroy            = var.environment == "dev" && !var.enable_nist_compliance
}


# ─── GCS S3-compatible HMAC Keys (Langfuse Blob Storage) ─────────────────────

resource "google_service_account" "langfuse_gcs" {
  account_id   = "langfuse-gcs-${var.environment}"
  display_name = "Langfuse GCS S3-compatible access"
  project      = var.project_id
}

# B5 fix — downgraded from objectAdmin to enforce AU-9 WORM compliance
resource "google_storage_bucket_iam_member" "langfuse_gcs_creator" {
  bucket = google_storage_bucket.langfuse_events.name
  role   = "roles/storage.objectCreator"
  member = "serviceAccount:${google_service_account.langfuse_gcs.email}"
}

resource "google_storage_bucket_iam_member" "langfuse_gcs_reader" {
  bucket = google_storage_bucket.langfuse_events.name
  role   = "roles/storage.legacyBucketReader"
  member = "serviceAccount:${google_service_account.langfuse_gcs.email}"
}

resource "google_storage_bucket_iam_member" "langfuse_gcs_viewer" {
  bucket = google_storage_bucket.langfuse_events.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.langfuse_gcs.email}"
}

resource "google_storage_hmac_key" "langfuse_key" {
  service_account_email = google_service_account.langfuse_gcs.email
  project               = var.project_id
}

# ─── Cloud Build IAM — Artifact Registry push permission ─────────────────────
#
# Dedicated Cloud Build identity (google_service_account.cloudbuild) and its
# Artifact Registry / Cloud Logging / staging-bucket bindings are declared in
# iam.tf (POAM-2026-083). The compliance-bridge-sa binding below is retained
# for legacy console triggers that still reference compliance-bridge-sa.

resource "google_project_iam_member" "compliance_bridge_sa_artifactregistry_writer" {
  project = var.project_id
  role    = "roles/artifactregistry.writer"
  member  = "serviceAccount:compliance-bridge-sa@${var.project_id}.iam.gserviceaccount.com"
}

# ─── Deploy Cloud SQL PostgreSQL (Langfuse Metadata Store) ─────────────────────
# §2.5: Managed Cloud SQL PostgreSQL (PG15, private IP, ENCRYPTED_ONLY, PITR in prod).
# IAM database authentication is used with Cloud SQL Auth Proxy sidecar (no static password).

locals {
  # Any jurisdiction-specific compliance flag activates hardening
  any_compliance_active = (
    var.enable_nist_compliance ||
    var.enable_eu_ecb_compliance ||
    var.enable_apac_mas_compliance
  )
}

module "cloudsql_postgres" {
  source = "../../modules/cloudsql_postgres"

  project_id         = var.project_id
  environment        = var.environment
  region             = var.region
  instance_name      = "cage-postgres-${var.environment}"
  database_version   = "POSTGRES_15"
  authorized_network = var.network

  # §1.1 Infrastructure Posture:
  # dev: db-f1-micro, ZONAL
  # staging: db-g1-small, ZONAL
  # prod: db-custom-2-7680, REGIONAL, PITR
  tier                          = var.environment == "prod" ? "db-custom-2-7680" : (var.environment == "staging" ? "db-g1-small" : var.postgres_tier)
  enable_high_availability      = var.environment == "prod" || var.enable_high_availability
  enable_point_in_time_recovery = var.environment == "prod" || local.any_compliance_active
  disk_size                     = var.postgres_disk_size

  enable_cmek = var.enable_cmek
  kms_key_id  = local.cmek_key_id

  deletion_protection = var.enable_deletion_protection

  database_name   = "langfuse"
  user_name       = google_service_account.langfuse.email
  user_type       = "CLOUD_IAM_SERVICE_ACCOUNT"
  enable_iam_auth = true

  depends_on = [module.gke]
}

# ─── Deploy Memorystore Instances (Valkey Cluster Mode Disabled) ───────────────
# D5, D6: Two separate instances for governance state integrity and app isolation.

module "memorystore_governance" {
  source = "../../modules/memorystore_valkey"

  project_id  = var.project_id
  environment = var.environment
  region      = var.region
  instance_id = var.memorystore_governance_instance_id != "" ? var.memorystore_governance_instance_id : "cage-valkey-gov-${var.environment}"
  network_id  = var.network

  # §1.1 Infrastructure Posture:
  # dev: 0 replicas (saves 1s per commit on WAIT)
  # staging: 1 replica (enables real WAIT 1 testing)
  # prod: 2+ replicas across zones
  replica_count = var.environment == "prod" ? 2 : (var.environment == "staging" ? 1 : 0)
  shard_count   = 1
  node_type     = var.environment == "prod" ? "HIGHMEM_MEDIUM" : "SHARED_CORE_NANO"
  mode          = "CLUSTER_DISABLED"

  authorization_mode      = var.enable_memorystore_iam_auth ? "IAM_AUTH" : "AUTH_DISABLED"
  transit_encryption_mode = var.enable_memorystore_tls ? "SERVER_AUTHENTICATION" : "TRANSIT_ENCRYPTION_DISABLED"

  enable_cmek = var.enable_cmek
  kms_key_id  = local.cmek_key_id

  deletion_protection_enabled = var.enable_deletion_protection

  depends_on = [module.gke]
}

module "memorystore_app" {
  source = "../../modules/memorystore_valkey"

  project_id  = var.project_id
  environment = var.environment
  region      = var.region
  instance_id = var.memorystore_app_instance_id != "" ? var.memorystore_app_instance_id : "cage-valkey-app-${var.environment}"
  network_id  = var.network

  # §1.1 Infrastructure Posture:
  # dev: 0 replicas
  # staging: 0 replicas
  # prod: 1 replica (HA)
  replica_count = var.environment == "prod" ? 1 : 0
  shard_count   = 1
  node_type     = var.environment == "prod" ? "HIGHMEM_MEDIUM" : "SHARED_CORE_NANO"
  mode          = "CLUSTER_DISABLED"

  authorization_mode      = "AUTH_DISABLED"
  transit_encryption_mode = "TRANSIT_ENCRYPTION_DISABLED"

  enable_cmek = var.enable_cmek
  kms_key_id  = local.cmek_key_id

  deletion_protection_enabled = var.enable_deletion_protection

  depends_on = [module.gke]
}

# ─── Evidence Stream Contract (gateway producer ↔ compliance-bridge custodian) ─
# The gateway appends unsigned hash-chained records to a Redis Stream on the
# GOVERNANCE Memorystore instance; the compliance bridge's EvidenceCustodian
# reads the same stream and keeps its cursor in "<key>:custody" on the same
# instance. Both modules take these exact values so they cannot drift.
#
# The URL is built exactly like the gateway's REDIS_URL (redis://<psc-ip>:<port>);
# TLS and IAM auth ride on REDIS_TLS / REDIS_AUTH_MODE, passed to both modules.
# The governance instance runs mode = CLUSTER_DISABLED, which supports logical
# databases, so the evidence stream stays isolated in db 1 (the code default)
# away from governance state in db 0.
locals {
  evidence_stream_redis_url = "redis://${module.memorystore_governance.primary_endpoint_ip}:${module.memorystore_governance.primary_endpoint_port}"
  evidence_stream_redis_db  = 1
  evidence_stream_key       = "cage:evidence:stream"
  governance_redis_auth     = var.enable_memorystore_iam_auth ? "iam" : "none"
}

# ─── ClickHouse Cold-Tier Bucket (dedicated, NOT retention-locked) ─────────────
# ClickHouse deletes S3-disk objects on part merges and TTL, which a
# retention-locked bucket forbids. The cold tier therefore gets its own
# CMEK-encrypted bucket with no retention policy, separate from the WORM system
# of record, and only the ClickHouse GSA holds IAM on it. It exists only where
# the cold tier is used (prod / HA posture).
locals {
  clickhouse_cold_tier_enabled = var.environment == "prod" || var.enable_high_availability
}

resource "google_storage_bucket" "clickhouse_tiering" {
  count = local.clickhouse_cold_tier_enabled ? 1 : 0

  name          = "${var.project_id}-clickhouse-tiering-${var.environment}"
  location      = var.region
  project       = var.project_id
  force_destroy = var.environment == "dev"

  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  dynamic "encryption" {
    for_each = var.enable_cmek && local.cmek_key_id != "" ? [1] : []
    content {
      default_kms_key_name = local.cmek_key_id
    }
  }

  # Deliberately no retention_policy and no versioning: ClickHouse owns the
  # object lifecycle and must be able to delete parts it has merged away.
  soft_delete_policy {
    retention_duration_seconds = 0
  }

  labels = {
    environment            = var.environment
    component              = "clickhouse-cold-tier"
    managed-by             = "terraform"
    cage-deployment-region = lower(var.cage_deployment_region)
  }

  lifecycle {
    precondition {
      condition = (
        (var.cage_deployment_region == "EU_ECB" && startswith(var.region, "europe-")) ||
        (var.cage_deployment_region == "APAC_MAS" && startswith(var.region, "asia-")) ||
        (var.cage_deployment_region == "US_FED" && startswith(var.region, "us-"))
      )
      error_message = "ClickHouse tiering bucket region '${var.region}' violates data residency for cage_deployment_region='${var.cage_deployment_region}'."
    }
    precondition {
      condition     = "${var.project_id}-clickhouse-tiering-${var.environment}" != module.worm_bucket.bucket_name
      error_message = "The ClickHouse cold tier must never share the retention-locked evidence WORM bucket."
    }
  }
}

# Only the ClickHouse GSA may read, write and delete tiering objects.
resource "google_storage_bucket_iam_member" "clickhouse_tiering_object_admin" {
  count  = local.clickhouse_cold_tier_enabled ? 1 : 0
  bucket = google_storage_bucket.clickhouse_tiering[0].name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.clickhouse.email}"
}

# The cold_gcs disk speaks the S3 XML API (SigV4), so it authenticates with an
# HMAC key minted for the ClickHouse GSA; the key inherits only that GSA's IAM.
resource "google_storage_hmac_key" "clickhouse_tiering" {
  count                 = local.clickhouse_cold_tier_enabled ? 1 : 0
  service_account_email = google_service_account.clickhouse.email
  project               = var.project_id
}

resource "kubernetes_secret" "clickhouse_tiering_hmac" {
  count = local.clickhouse_cold_tier_enabled ? 1 : 0

  metadata {
    name      = "clickhouse-tiering-hmac"
    namespace = module.namespace.name
  }

  data = {
    "AWS_ACCESS_KEY_ID"     = google_storage_hmac_key.clickhouse_tiering[0].access_id
    "AWS_SECRET_ACCESS_KEY" = google_storage_hmac_key.clickhouse_tiering[0].secret
  }
}

# ─── Deploy ClickHouse Operator & Query Plane (§1.1, §2.6, §3, §7) ───────────
# ClickHouse is strictly the analytical query plane fed by clickhouse_sink.py.
# The retention-locked GCS WORM bucket (module.worm_bucket) is the system of record;
# the cold tier uses the dedicated google_storage_bucket.clickhouse_tiering.
#
# Posture matrix (§1.1, §2.6):
#   - dev / staging: 1 node on local SSD (MergeTree)
#   - prod:          Operator, ReplicatedMergeTree + Keeper (3 nodes),
#                    local SSD for hot parts, GCS disk for the cold tier
module "clickhouse_operator" {
  source = "../../modules/clickhouse_operator"

  namespace                         = module.namespace.name
  environment                       = var.environment
  enable_high_availability          = local.clickhouse_cold_tier_enabled
  image                             = var.image_digests["clickhouse-server"]
  keeper_image                      = var.image_digests["clickhouse-keeper"]
  storage_size                      = var.clickhouse_storage_size
  storage_class                     = var.storage_class
  service_account_name              = kubernetes_service_account.workload["clickhouse"].metadata[0].name
  cold_tier_bucket                  = local.clickhouse_cold_tier_enabled ? google_storage_bucket.clickhouse_tiering[0].name : ""
  cold_tier_credentials_secret_name = local.clickhouse_cold_tier_enabled ? kubernetes_secret.clickhouse_tiering_hmac[0].metadata[0].name : ""

  cpu_request    = "1000m"
  memory_request = "2Gi"
  cpu_limit      = var.enable_high_availability ? "3000m" : "2000m"
  memory_limit   = var.enable_high_availability ? "6Gi" : "4Gi"

  depends_on = [module.gke, google_storage_bucket_iam_member.clickhouse_tiering_object_admin]
}


# ─── Deploy NeMo Guardrails + Microsoft Presidio ───────────────────────────────

module "nemo_guardrails" {
  count = var.enable_nemo_guardrails ? 1 : 0

  source = "../../modules/nemo_guardrails"

  namespace       = module.namespace.name
  deployment_name = "nemo-guardrails"
  service_name    = "nemo-guardrails"
  replicas        = var.enable_high_availability ? 2 : 1
  enable_pdb      = var.enable_high_availability
  environment     = var.environment

  # NeMo container image pinned by @sha256: digest via var.image_digests
  nemo_image = var.nemo_image != "" ? var.nemo_image : var.image_digests["nemo-guardrails"]

  # Presidio images mirrored into Artifact Registry and pinned by @sha256: digest
  presidio_analyzer_image   = var.presidio_analyzer_image != "" ? var.presidio_analyzer_image : var.image_digests["presidio-analyzer"]
  presidio_anonymizer_image = var.presidio_anonymizer_image != "" ? var.presidio_anonymizer_image : var.image_digests["presidio-anonymizer"]

  # LLM backend: NeMo rails call vLLM fast service for rail evaluation
  llm_api_base   = "http://vllm-service.${module.namespace.name}.svc.cluster.local:8000/v1"
  llm_api_key    = "EMPTY"
  llm_model_name = var.served_model_fast

  # Resource sizing
  nemo_cpu_request    = "500m"
  nemo_memory_request = "1Gi"
  nemo_cpu_limit      = var.enable_high_availability ? "2000m" : ""
  nemo_memory_limit   = var.enable_high_availability ? "4Gi" : ""

  presidio_cpu_request    = "200m"
  presidio_memory_request = "512Mi"
  presidio_cpu_limit      = var.enable_high_availability ? "1000m" : ""
  presidio_memory_limit   = var.enable_high_availability ? "2Gi" : ""

  enable_security_context = var.enable_nist_compliance

  depends_on = [module.gke, module.vllm]
}

# Workload ServiceAccounts are defined per workload in iam.tf
# (kubernetes_service_account.workload), each bound 1:1 to its own GSA.

# ─── Deploy vLLM Inference Engine ──────────────────────────────────────────────

module "vllm" {
  count = var.enable_vllm ? 1 : 0

  source = "../../modules/vllm_inference"

  namespace            = module.namespace.name
  deployment_name      = "vllm-inference"
  service_account_name = kubernetes_service_account.workload["vllm"].metadata[0].name
  image                = var.vllm_image != "" ? var.vllm_image : var.image_digests["vllm-streamer"]
  # model_path loads weights from GCS model bucket via runai_streamer
  model_path         = replace(var.model_fast, "gs://cage-models/", "gs://${local.model_bucket_name}/")
  served_model_name  = var.served_model_name != "" ? var.served_model_name : var.served_model_fast
  gpu_count          = var.vllm_gpu_count
  gpu_product        = var.gpu_type
  replicas           = var.vllm_replicas
  enable_pdb         = var.enable_high_availability
  memory_limit       = var.vllm_memory_limit
  cpu_limit          = var.vllm_cpu_limit
  memory_request     = var.vllm_memory_request
  cpu_request        = var.vllm_cpu_request
  shared_memory_size = var.vllm_shared_memory_size

  # Stream weights from GCS via Run:ai model streamer when gs:// is provided
  vllm_load_format = can(regex("^gs://", var.model_fast)) ? "runai_streamer" : "auto"

  # --enable-auto-tool-choice + --tool-call-parser hermes: this pool serves
  # MODEL_FAST (Qwen2.5-7B-Instruct), which is bound via llm.bind_tools() in
  # data_analyst_graph.py (Doer node) and governed_trader_graph.py (Executor
  # node). Without these flags, vLLM rejects any request containing an
  # OpenAI-style `tool_choice: "auto"` payload with HTTP 400
  # ("\"auto\" tool choice requires --enable-auto-tool-choice and
  # --tool-call-parser to be set"), which the FastAPI layer surfaces as a
  # 500 to the caller — this crashed every DataAnalyst/GovernedTrader
  # tool-calling request in the 2026-08-01 measurement run. "hermes" is the
  # vLLM tool-call parser compatible with Qwen2.5-Instruct's tool-calling
  # output format.
  vllm_command = "python3 -m vllm.entrypoints.openai.api_server --model $MODEL_PATH --served-model-name $SERVED_MODEL_NAME --load-format $VLLM_LOAD_FORMAT --host 0.0.0.0 --port 8000 --enable-auto-tool-choice --tool-call-parser hermes"

  # GCS model streamer requires GOOGLE_CLOUD_PROJECT to authenticate with GCS.
  # Without it, runai_model_streamer_gcs raises OSError: Project was not passed.
  # Offline flags forbid runtime egress to huggingface.co.
  env_vars = {
    "GOOGLE_CLOUD_PROJECT" = var.project_id
    "HF_HUB_OFFLINE"       = "1"
    "TRANSFORMERS_OFFLINE" = "1"
  }

  # GCP-specific GPU node targeting
  # Use cloud.google.com/gke-nodepool (known to autoscaler at scale-from-zero time).
  # nvidia.com/gpu.product is applied post-startup by device plugin — autoscaler can't match it.
  node_selector = {
    "workload-type" = "gpu"
  }

  tolerations = [
    {
      key      = "nvidia.com/gpu"
      operator = "Equal"
      value    = "present"
      effect   = "NoSchedule"
    }
  ]

  depends_on = [module.gke, kubernetes_service_account.workload["vllm"]]
}

# ─── Deploy vLLM Reasoning Engine ──────────────────────────────────────────────

module "vllm_reasoning" {
  count = var.enable_vllm ? 1 : 0

  source = "../../modules/vllm_inference"

  namespace            = module.namespace.name
  deployment_name      = "vllm-reasoning"
  service_account_name = kubernetes_service_account.workload["vllm"].metadata[0].name
  service_name         = "vllm-reasoning"
  image                = var.vllm_image != "" ? var.vllm_image : var.image_digests["vllm-streamer"]
  # model_path loads weights from GCS model bucket via runai_streamer
  model_path         = replace(var.model_reasoning, "gs://cage-models/", "gs://${local.model_bucket_name}/")
  served_model_name  = var.served_model_name != "" ? var.served_model_name : var.served_model_reasoning
  gpu_count          = var.vllm_gpu_count
  gpu_product        = var.gpu_type
  replicas           = var.vllm_replicas
  enable_pdb         = var.enable_high_availability
  memory_limit       = var.vllm_memory_limit
  cpu_limit          = var.vllm_cpu_limit
  memory_request     = var.vllm_memory_request
  cpu_request        = var.vllm_cpu_request
  shared_memory_size = var.vllm_shared_memory_size

  # Stream weights from GCS via Run:ai model streamer when gs:// is provided
  vllm_load_format = can(regex("^gs://", var.model_reasoning)) ? "runai_streamer" : "auto"

  # Cap max context to 16K — 14B AWQ model needs 24 GiB KV for 131K default (> 8.9 GiB available)
  vllm_command = "python3 -m vllm.entrypoints.openai.api_server --model $MODEL_PATH --served-model-name $SERVED_MODEL_NAME --load-format $VLLM_LOAD_FORMAT --host 0.0.0.0 --port 8000 --max-model-len 16384"

  # GCS model streamer requires GOOGLE_CLOUD_PROJECT to authenticate with GCS.
  # Without it, runai_model_streamer_gcs raises OSError: Project was not passed.
  # Offline flags forbid runtime egress to huggingface.co.
  env_vars = {
    "GOOGLE_CLOUD_PROJECT" = var.project_id
    "HF_HUB_OFFLINE"       = "1"
    "TRANSFORMERS_OFFLINE" = "1"
  }

  # GCP-specific GPU node targeting
  # Use cloud.google.com/gke-nodepool (known to autoscaler at scale-from-zero time).
  node_selector = {
    "workload-type" = "gpu"
  }

  tolerations = [
    {
      key      = "nvidia.com/gpu"
      operator = "Equal"
      value    = "present"
      effect   = "NoSchedule"
    }
  ]

  depends_on = [module.gke, kubernetes_service_account.workload["vllm"]]
}

# ─── Deploy Langfuse Observability ─────────────────────────────────────────────

module "langfuse" {
  source = "../../modules/langfuse_stack"

  namespace                = module.namespace.name
  service_account_name     = kubernetes_service_account.workload["langfuse"].metadata[0].name
  langfuse_image           = var.image_digests["langfuse"]
  langfuse_worker_image    = var.image_digests["langfuse-worker"]
  cloudsql_proxy_image     = var.image_digests["cloud-sql-proxy"]
  enable_cloudsql_proxy    = true
  cloudsql_connection_name = module.cloudsql_postgres.connection_name
  cloudsql_iam_user        = module.cloudsql_postgres.iam_user_name
  cloudsql_database_name   = module.cloudsql_postgres.database_name
  clickhouse_url           = "http://${module.clickhouse_operator.service_name}:${module.clickhouse_operator.http_port}"
  clickhouse_migration_url = "clickhouse://default:${module.clickhouse_operator.password}@${module.clickhouse_operator.service_name}:${module.clickhouse_operator.tcp_port}"
  clickhouse_user          = "default"
  clickhouse_password      = module.clickhouse_operator.password
  redis_connection_string  = "redis://${module.memorystore_app.primary_endpoint_ip}:${module.memorystore_app.primary_endpoint_port}"
  redis_host               = module.memorystore_app.primary_endpoint_ip
  redis_port               = tostring(module.memorystore_app.primary_endpoint_port)

  # S3-compatible blob storage via GCS HMAC keys
  s3_endpoint   = var.langfuse_s3_endpoint
  s3_bucket     = var.langfuse_s3_bucket != "" ? var.langfuse_s3_bucket : google_storage_bucket.langfuse_events.name
  s3_access_key = var.langfuse_s3_access_key != "" ? var.langfuse_s3_access_key : google_storage_hmac_key.langfuse_key.access_id
  s3_secret_key = var.langfuse_s3_secret_key != "" ? var.langfuse_s3_secret_key : google_storage_hmac_key.langfuse_key.secret
  s3_region     = var.region

  nextauth_url          = var.langfuse_nextauth_url
  web_replicas          = var.enable_high_availability ? 2 : 1
  worker_replicas       = var.enable_high_availability ? 2 : 1
  web_cpu_request       = "50m"
  worker_cpu_request    = "50m"
  web_memory_request    = "256Mi"
  worker_memory_request = "256Mi"

  langfuse_public_key = var.langfuse_public_key
  langfuse_secret_key = var.langfuse_secret_key

  langfuse_init_user_email    = "dev-admin@local.com"
  langfuse_init_user_password = "dev-password-123"
  langfuse_init_project_name  = "cybernetic-governance"
  langfuse_init_project_id    = "cybernetic-governance"
  langfuse_init_org_id        = "CAGE"
  langfuse_init_org_name      = "CAGE"

  depends_on = [module.cloudsql_postgres, module.clickhouse_operator, module.memorystore_app, google_storage_hmac_key.langfuse_key, module.gke]
}

# ─── Deploy Compliance Bridge ───────────────────────────────────────────────────

module "compliance_bridge" {
  count = var.enable_compliance_bridge ? 1 : 0

  source = "../../modules/compliance_bridge"

  namespace     = module.namespace.name
  image         = var.compliance_bridge_image != "" ? var.compliance_bridge_image : var.image_digests["compliance-bridge"]
  langfuse_host = "http://${module.langfuse.web_service_name}.${module.namespace.name}.svc.cluster.local:3000"
  replicas      = var.enable_high_availability ? 2 : 1

  remediation_model          = var.served_model_fast
  remediation_max_tokens     = "2048"
  remediation_timeout_ms     = "30000"
  vllm_base_url              = "http://vllm-service.${module.namespace.name}.svc.cluster.local:8000/v1"
  vllm_api_key               = "EMPTY"
  alert_channel              = "console"
  oscal_s3_bucket            = module.worm_bucket.bucket_name
  oscal_s3_region            = var.region
  evidence_cold_store        = "gcs"
  evidence_cold_store_bucket = module.worm_bucket.bucket_name
  cmek_key_resource_name     = var.enable_cmek ? local.cmek_key_id : ""
  clickhouse_host            = module.clickhouse_operator.service_name
  clickhouse_port            = tostring(module.clickhouse_operator.http_port)
  clickhouse_database        = "cage_evidence"
  clickhouse_enabled         = true
  # Least-privilege writer (INSERT on evidence_stream only), never `default`.
  clickhouse_username             = module.clickhouse_operator.evidence_sink_username
  clickhouse_password_secret_name = module.clickhouse_operator.evidence_sink_password_secret_name
  clickhouse_password_secret_key  = module.clickhouse_operator.evidence_sink_password_secret_key
  cage_env                        = var.environment
  cage_deployment_region          = var.cage_deployment_region

  # EvidenceCustodian: same governance Memorystore instance, db, key, TLS and
  # IAM auth mode as the gateway producer (see local.evidence_stream_*).
  evidence_stream_redis_url   = local.evidence_stream_redis_url
  evidence_stream_redis_db    = local.evidence_stream_redis_db
  evidence_stream_key         = local.evidence_stream_key
  evidence_custody_interval_s = 60
  evidence_verify_interval_s  = 300
  enable_redis_tls            = var.enable_memorystore_tls
  redis_ca_pem                = var.enable_memorystore_tls ? join("\n", module.memorystore_governance.managed_server_ca) : ""
  redis_auth_mode             = local.governance_redis_auth

  # POAM-2026-079 / §5.2: own identity and own signing key. KMSBatchSigner reads
  # the key from EVIDENCE_KMS_KEY (never KMS_GOVERNANCE_KEY).
  service_account_name = kubernetes_service_account.workload["compliance_bridge"].metadata[0].name
  evidence_kms_key     = local.compliance_evidence_key_version

  depends_on = [module.langfuse, module.vllm, module.worm_bucket, module.clickhouse_operator, module.memorystore_governance]
}


# ─── Deploy OPA Policy Engine ──────────────────────────────────────────────────

module "opa" {
  source = "../../modules/opa_policy"

  namespace = module.namespace.name
  image     = var.image_digests["opa"]
  replicas  = var.enable_high_availability ? 2 : 1

  # Optional: Add custom policies
  policy_files = {
    "trade_governance.rego" = file("${path.module}/../../../src/cage_finance/opa/trade_governance.rego")
  }

  depends_on = [module.gke]
}

# ─── Deploy Gateway ─────────────────────────────────────────────────────────────

module "gateway" {
  source = "../../modules/gateway"

  namespace                      = module.namespace.name
  image                          = var.image_digests["gateway"]
  replicas                       = var.enable_high_availability ? 2 : 1
  project_id                     = var.project_id
  region                         = var.region
  enable_logging                 = "true"
  cage_domain                    = var.cage_domain
  cage_env                       = var.environment
  redis_host                     = module.memorystore_governance.primary_endpoint_ip
  redis_port                     = tostring(module.memorystore_governance.primary_endpoint_port)
  redis_password                 = ""
  governance_redis_replica_count = module.memorystore_governance.replica_count
  enable_redis_tls               = var.enable_memorystore_tls
  redis_ca_pem                   = var.enable_memorystore_tls ? join("\n", module.memorystore_governance.managed_server_ca) : ""
  redis_auth_mode                = local.governance_redis_auth

  # Evidence stream producer — identical contract to the compliance bridge.
  evidence_stream_redis_url = local.evidence_stream_redis_url
  evidence_stream_redis_db  = local.evidence_stream_redis_db
  evidence_stream_key       = local.evidence_stream_key
  vllm_base_url             = "http://vllm-service.${module.namespace.name}.svc.cluster.local:8000/v1"
  vllm_reasoning_api_base   = "http://vllm-reasoning.${module.namespace.name}.svc.cluster.local:8000/v1"
  vllm_fast_api_base        = "http://vllm-service.${module.namespace.name}.svc.cluster.local:8000/v1"
  guardrails_model_name     = var.served_model_fast
  opa_url                   = "http://${module.opa.service_name}.${module.namespace.name}.svc.cluster.local:8181"
  governance_salt           = var.governance_salt

  # POAM-2026-080: only the advisor's mesh identity may call gated routes.
  # The gateway does not call itself, so its own identity is not listed.
  trusted_client_identities = [
    "${local.ksa_advisor}.${module.namespace.name}.${module.service_mesh.identity_suffix}",
  ]

  # K-4: wire OTLP auth header so Langfuse trace ingestion returns 200, not 401.
  # If an explicit override is provided use it; otherwise derive from the
  # Langfuse project keys using HTTP Basic-auth encoding (publicKey:secretKey).
  otel_exporter_otlp_headers = var.otel_exporter_otlp_headers != "" ? var.otel_exporter_otlp_headers : (
    var.langfuse_public_key != "" ? "Authorization=Basic ${base64encode("${var.langfuse_public_key}:${var.langfuse_secret_key}")}" : ""
  )
  reconciliation_provider = "simulated"
  cage_kms_provider       = "gcp"

  # POAM-2026-079: own identity; signs seals with gateway-seal and trusts
  # ground truth only from reconciler-snapshot (G8).
  service_account_name = kubernetes_service_account.workload["gateway"].metadata[0].name
  kms_governance_key   = local.gateway_seal_key_version
  reconciler_kms_key   = local.reconciler_snapshot_key_version

  # §5.3, §7: Trigger gateway pod rollout whenever network/FQDN policy specs change
  # so pre-change connections do not outlive a policy tightening.
  network_policy_hash = local.network_policy_spec_hash

  depends_on = [module.app_secrets, module.opa, module.vllm, module.memorystore_governance, module.service_mesh]
}

# ─── Deploy Governed Financial Advisor ────────────────────────────────────────

module "governed_advisor" {
  source = "../../modules/governed_advisor"

  namespace               = module.namespace.name
  image                   = var.image_digests["governed-financial-advisor"]
  replicas                = var.enable_high_availability ? 2 : 1
  project_id              = var.project_id
  region                  = var.region
  enable_logging          = "true"
  redis_host              = module.memorystore_app.primary_endpoint_ip
  redis_port              = tostring(module.memorystore_app.primary_endpoint_port)
  redis_password          = ""
  model_fast              = var.served_model_fast
  model_reasoning         = var.served_model_reasoning
  model_consensus         = var.served_model_reasoning
  vllm_base_url           = "http://vllm-service.${module.namespace.name}.svc.cluster.local:8000/v1"
  vllm_fast_api_base      = "http://vllm-service.${module.namespace.name}.svc.cluster.local:8000/v1"
  vllm_reasoning_api_base = "http://vllm-reasoning.${module.namespace.name}.svc.cluster.local:8000/v1"
  opa_url                 = "http://${module.opa.service_name}.${module.namespace.name}.svc.cluster.local:8181"
  # Langfuse web service exposes port 3000 (not 80) — corrected from initial misconfiguration.
  langfuse_host = "http://${module.langfuse.web_service_name}.${module.namespace.name}.svc.cluster.local:3000"
  gateway_url   = "http://${module.gateway.service_name}.${module.namespace.name}.svc.cluster.local:8080"
  # POAM-2026-079: own KSA with no cloud identity and no signing key. The
  # advisor refuses to start if a signing-key variable is set.
  service_account_name = kubernetes_service_account.workload["advisor"].metadata[0].name
  cage_env             = var.environment

  # K-4: wire OTLP auth header so governed-financial-advisor traces reach
  # Langfuse rather than returning 401 Unauthorized.
  # If an explicit override is provided use it; otherwise derive from keys.
  otel_exporter_otlp_headers = var.otel_exporter_otlp_headers != "" ? var.otel_exporter_otlp_headers : (
    var.langfuse_public_key != "" ? "Authorization=Basic ${base64encode("${var.langfuse_public_key}:${var.langfuse_secret_key}")}" : ""
  )

  depends_on = [module.gateway, module.langfuse, module.vllm, module.opa, module.service_mesh]
}

# ─── Deploy AgentSight UI ─────────────────────────────────────────────────────

module "agentsight_ui" {
  source = "../../modules/agentsight_ui"

  namespace = module.namespace.name
  image     = var.image_digests["agentsight-ui"]
  replicas  = 1

  depends_on = [module.gke]
}

# ─── Application Secrets ──────────────────────────────────────────────────────

module "app_secrets" {
  source = "../../modules/app_secrets"

  namespace = module.namespace.name

  governance_salt      = var.governance_salt
  salt                 = var.governance_salt
  alphavantage_api_key = "" # Add variable if needed
  openai_api_key       = ""
  model_fast           = var.served_model_fast
  model_reasoning      = var.served_model_reasoning

  langfuse_public_key = var.langfuse_public_key != "" ? var.langfuse_public_key : module.langfuse.public_key
  langfuse_secret_key = var.langfuse_secret_key != "" ? var.langfuse_secret_key : module.langfuse.secret_key
  langfuse_host       = "http://${module.langfuse.web_service_name}.${module.namespace.name}.svc.cluster.local:3000"

  clickhouse_url           = "http://${module.clickhouse_operator.service_name}:${module.clickhouse_operator.http_port}"
  clickhouse_migration_url = "clickhouse://default:${module.clickhouse_operator.password}@${module.clickhouse_operator.service_name}:${module.clickhouse_operator.tcp_port}"
  clickhouse_user          = "default"
  clickhouse_password      = module.clickhouse_operator.password
  database_url             = ""
  nextauth_secret          = module.langfuse.nextauth_secret
  nextauth_url             = var.langfuse_nextauth_url

  aws_access_key_id     = var.aws_access_key
  aws_secret_access_key = var.aws_secret_key
  s3_endpoint_url       = "https://storage.googleapis.com"
  s3_bucket_name        = google_storage_bucket.langfuse_events.name

  # ─── Langfuse compliance project keys (P2-2) ────────────────────────────────
  # Dev posture: pass the key as-is (may be empty → module skips secret creation
  #   when enable_nist_compliance=false; compliance bridge handles None gracefully).
  # Prod posture (enable_nist_compliance=true): the precondition below enforces
  #   that a real, distinct cage-compliance project key is provided.
  #   The silent fallback to module.langfuse.public_key has been removed to prevent
  #   circular evidence contamination in Step 5 (_fetch_failing_traces).
  langfuse_compliance_public_key = var.langfuse_compliance_public_key
  langfuse_compliance_secret_key = var.langfuse_compliance_secret_key

  oscal_api_key = "DUMMY_API_KEY_FOR_LOCAL_DEV"

  opa_url = "http://${module.opa.service_name}.${module.namespace.name}.svc.cluster.local:8181"

  cage_deployment_region = var.cage_deployment_region

  depends_on = [module.langfuse, module.cloudsql_postgres, module.clickhouse_operator]
}


# POAM-019 enforcement: fail the plan if compliance keys are missing when
# enable_nist_compliance=true.  lifecycle { precondition } is only valid inside
# resource blocks, not module blocks, so this terraform_data resource carries
# the guard.  It runs at plan time and provides a clear error message citing
# the POAM item and remediation path.
resource "terraform_data" "poam_019_compliance_key_guard" {
  lifecycle {
    precondition {
      condition     = !var.enable_memorystore_tls || length(module.memorystore_governance.managed_server_ca) > 0
      error_message = "[POAM-2026-086] SC-8 Memorystore CA pinning invariant violated: when enable_memorystore_tls=true, module.memorystore_governance.managed_server_ca must be non-empty so gateway and compliance-bridge pods can pin the server CA."
    }
    precondition {
      condition = !(var.enable_nist_compliance && (
        var.langfuse_compliance_public_key == "" ||
        var.langfuse_compliance_secret_key == "" ||
        var.langfuse_compliance_public_key == var.langfuse_public_key ||
        var.langfuse_compliance_secret_key == var.langfuse_secret_key
      ))
      error_message = <<-EOT
        [POAM-019] AU-9 dual-project telemetry isolation violated.
        When enable_nist_compliance=true, the Langfuse compliance project keys
        (langfuse_compliance_public_key / langfuse_compliance_secret_key) must be:
          (1) Non-empty
          (2) Distinct from the application project keys (langfuse_public_key / langfuse_secret_key)
        An empty or identical compliance key silently collapses the dual-project
        architecture, defeating evidentiary independence for NIST SP 800-53 AU-9.
        Remediation: Set langfuse_compliance_public_key and langfuse_compliance_secret_key
        to valid cage-compliance Langfuse project credentials in prod.tfvars.
        See docs/POAM_US_FED.md#POAM-019.
      EOT
    }
  }
}
