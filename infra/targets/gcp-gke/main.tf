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
  # 1.7: the removed block that forgets the pre-POAM-2026-159 Langfuse bucket.
  # 1.9: variable validations reference other variables and locals
  # (image_digests follows local.required_image_digests).
  required_version = ">= 1.9.0"

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

  # Terraform state lives in GCS, one state per cluster:
  #   gs://<bucket>/cage/gcp-gke/<cluster_name>/default.tfstate
  # Neither bucket nor prefix is committed (D-03). deploy_all.sh supplies both
  # at init: the bucket is <project>-tfstate (or TF_BACKEND_BUCKET), and the
  # prefix is keyed on the cluster_name the tfvars file sets, so one
  # environment can never plan against another environment's state. By hand:
  #   terraform init -reconfigure \
  #     -backend-config="bucket=<project>-tfstate" \
  #     -backend-config="prefix=cage/gcp-gke/<cluster_name>"
  backend "gcs" {}
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

  # Security posture: the control-plane allowlist follows the tier (POAM-2026-181)
  restrict_control_plane         = local.enforcing_posture
  enable_deletion_protection     = var.enable_deletion_protection
  enable_binary_authorization    = var.enable_binary_authorization
  enable_audit_logging           = var.enable_audit_logging
  enable_cmek                    = var.enable_cmek
  enable_private_master_endpoint = var.enable_private_master_endpoint
  enable_private_nodes           = var.enable_private_nodes
  enable_dataplane_v2            = var.enable_dataplane_v2
  enable_fqdn_network_policy     = var.enable_fqdn_network_policy
  enable_network_policy_logging  = local.network_policy_logging_enabled
  release_channel                = var.release_channel
  min_master_version             = var.min_master_version
  cluster_dns_provider           = var.cluster_dns_provider

  # NIST-specific configuration
  authorized_networks = var.authorized_networks
  kms_key_id          = local.cmek_key_id

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
  create_cloud_nat              = !var.create_vpc_network
  network                       = local.effective_network_name
  subnetwork                    = local.effective_subnetwork_name
  cluster_secondary_range_name  = local.gke_pods_range_name
  services_secondary_range_name = local.gke_services_range_name
  pod_cidr                      = local.gke_pod_cidr
  service_cidr                  = local.gke_service_cidr
  master_ipv4_cidr_block        = var.master_ipv4_cidr_block
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
  # exists have no proxy; restart them after the first mesh install. The
  # service_mesh module refuses pods created here without the proxy
  # (proxy_required_namespaces, POAM-2026-167).
  annotations = merge(
    {
      "linkerd.io/inject" = "enabled"
    },
    local.dataplane_v2_network_logging_active ? {
      # D-195-4 (R-5, F-87): keep governance-stack opted into GKE Dataplane V2
      # denied-connection logging even if an operator sets delegate = true.
      "policy.network.gke.io/enable-deny-logging" = "true"
    } : {},
  )

  depends_on = [module.gke]
}

# ─── Service Mesh (Linkerd, trust anchor in Google CAS) ──────────────────────

resource "random_id" "mesh_ca_pool_suffix" {
  byte_length = 4
}

module "service_mesh" {
  source = "../../modules/service_mesh"

  enable_deletion_protection = var.enable_deletion_protection

  project_id             = var.project_id
  region                 = var.region
  environment            = var.environment
  ca_pool_id             = "cage-mesh-${var.environment}-${random_id.mesh_ca_pool_suffix.hex}"
  network                = local.effective_network_name
  master_ipv4_cidr_block = var.master_ipv4_cidr_block
  # proxy-init needs NET_ADMIN, which 'restricted' Pod Security forbids; the
  # CNI plugin sets up the redirect on the node instead.
  enable_cni = var.enable_pod_security_standards && var.pod_security_level != "privileged"
  # The injector's webhook fails open. Without this, a pod created in the
  # namespace while the injector is down runs without a proxy, and the gateway
  # then has no proxy to vouch for its callers (POAM-2026-167).
  proxy_required_namespaces = [var.namespace]

  depends_on = [module.gke]
}

# ─── Enforcing Posture ────────────────────────────────────────────────────────
# The one predicate for the controls that hold whenever this deployment
# enforces: the prod and staging tiers always, whatever jurisdiction they
# select, and dev only with enforce_in_dev (POAM-2026-130). It gates the retention
# lock (POAM-2026-159), governance Valkey AOF (POAM-2026-156 item 3), the
# control-plane and POAM-019 guards, module.gke's allowlist, Cloud SQL PITR and
# the NeMo securityContext (POAM-2026-181), so staging rehearses prod anywhere.
#
#   tier      enforcing
#   dev       only with enforce_in_dev = true
#   staging   always
#   prod      always
locals {
  enforcing_posture = var.environment == "prod" || var.environment == "staging" || var.enforce_in_dev
}

# ─── Retention Posture (§1.1, NIST AU-9 / AU-11, POAM-2026-159) ──────────────
# The one source of the retention lock on both retention-locked buckets: the
# Langfuse event-upload bucket and the evidence WORM bucket. The tier
# (var.environment, which variables.tf limits to dev, staging and prod) selects
# it, and only the exact tier "staging" gets the short period: every other value,
# the dev default included, keeps 2555 days. Staging is always locked,
# because GCS refuses to shorten or remove a locked policy and the provider
# replaces a bucket whose lock is turned off.
#
#   tier      retention period          locked
#   dev       220752000 s (2555 days)   only with enforce_in_dev = true
#   staging   86400 s (1 day)           always
#   prod      220752000 s (2555 days)   always
locals {
  retention_period_seconds = var.environment == "staging" ? 86400 : 220752000
  retention_locked         = local.enforcing_posture
}

# ─── GCS Bucket for Langfuse Event Uploads ────────────────────────────────────
# Langfuse writes every raw ingestion event here (LANGFUSE_S3_EVENT_UPLOAD_BUCKET)
# and its worker reads the events back into ClickHouse. The events stay for at
# least the retention period above: one day in staging, 2555 days elsewhere.

resource "random_id" "bucket_suffix" {
  byte_length = 4
}

resource "google_storage_bucket" "langfuse_event_upload" {
  name          = "langfuse-event-upload-${var.project_id}-${random_id.bucket_suffix.hex}"
  location      = var.region
  project       = var.project_id
  force_destroy = var.environment == "dev" ? true : false

  uniform_bucket_level_access = true

  # AU-9 / AU-11: no object can be deleted or overwritten before it is
  # local.retention_period_seconds old. Locking is irreversible.
  retention_policy {
    retention_period = local.retention_period_seconds
    is_locked        = local.retention_locked
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

# POAM-2026-159: this bucket used to be google_storage_bucket.langfuse_events,
# locked for 2555 days whenever a compliance flag was set, staging included.
# GCS refuses to shorten a locked policy, so that bucket can never take the
# staging lock. This block makes the next apply forget it without deleting it,
# and the same apply creates the bucket above under its new name. The forgotten
# bucket keeps its objects and its locked policy until its newest object's
# retention expires, and the project keeps its Cloud Storage lien at least that
# long. A destroy plan ignores this block (verified on Terraform 1.15.8), so
# apply once before any teardown. The migration is in
# docs/operations/DEPLOYMENT_RULES.md.
removed {
  from = google_storage_bucket.langfuse_events

  lifecycle {
    destroy = false
  }
}

# ─── Evidence WORM Bucket — System of Record (§1.1, §2.6, NIST AU-9) ─────────
# Durable tamper-evident cold store in the persistent evidence custody boundary.
# CMEK and WORM audit-log custody are coordinated via module.evidence_domain.
module "worm_bucket" {
  source = "../../modules/worm_bucket"

  project_id               = local.evidence_project_id
  environment              = var.environment
  region                   = var.region
  cage_deployment_region   = var.cage_deployment_region
  bucket_name              = local.evidence_bucket_name
  external_bucket_enabled  = var.external_evidence_domain_enabled
  enable_cmek              = var.enable_cmek
  kms_key_id               = local.evidence_cmek_key_id
  cmek_iam_ready           = module.evidence_domain.evidence_cmek_iam_ready
  retention_period_seconds = local.retention_period_seconds
  is_locked                = local.retention_locked
  force_destroy            = !local.enforcing_posture
  depends_on               = [terraform_data.evidence_domain_isolation_guard]
}


# ─── GCS Workload Identity IAM (Langfuse Event Upload Storage) ───────────────
# Native Google Cloud Storage (@google-cloud/storage via GKE Workload Identity on
# google_service_account.langfuse) avoids service-account HMAC keys so clean-room
# projects enforcing constraints/iam.disableServiceAccountKeyCreation provision
# cleanly. Least-privilege bucket-scoped roles only; the bucket's retention
# policy refuses overwrites or deletes until local.retention_period_seconds.
resource "google_storage_bucket_iam_member" "langfuse_gcs_creator" {
  bucket = google_storage_bucket.langfuse_event_upload.name
  role   = "roles/storage.objectUser"
  member = "serviceAccount:${google_service_account.langfuse.email}"
}

resource "google_storage_bucket_iam_member" "langfuse_gcs_reader" {
  bucket = google_storage_bucket.langfuse_event_upload.name
  role   = "roles/storage.legacyBucketReader"
  member = "serviceAccount:${google_service_account.langfuse.email}"
}

resource "google_storage_bucket_iam_member" "langfuse_gcs_viewer" {
  bucket = google_storage_bucket.langfuse_event_upload.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.langfuse.email}"
}

# ─── Cloud Build IAM — Artifact Registry push permission ─────────────────────
#
# Dedicated Cloud Build identity (google_service_account.cloudbuild) and its
# Artifact Registry / Cloud Logging / staging-bucket bindings are declared in
# iam.tf (POAM-2026-083). The compliance_bridge GSA binding below is retained
# for legacy console triggers that still reference that service account.

resource "google_project_iam_member" "compliance_bridge_sa_artifactregistry_writer" {
  project = var.project_id
  role    = "roles/artifactregistry.writer"
  member  = "serviceAccount:${google_service_account.compliance_bridge.email}"
}

# ─── Deploy Cloud SQL PostgreSQL (Langfuse Metadata Store) ─────────────────────
# §2.5: Managed Cloud SQL PostgreSQL (PG15, private IP, ENCRYPTED_ONLY, PITR when enforcing).
# IAM database authentication is used with Cloud SQL Auth Proxy sidecar (no static password).

# POAM-2026-130 removed the three jurisdiction flags, enable_nist_compliance,
# enable_eu_ecb_compliance and enable_apac_mas_compliance, and the
# local.any_compliance_active they set. All three did the same thing and
# selected nothing jurisdiction-specific. OSCAL and the workloads read
# cage_deployment_region, every control the flags once gated follows
# local.enforcing_posture (POAM-2026-181), and their last effect, making a
# dev plan enforce, is now var.enforce_in_dev. A tfvars file that still sets
# a removed flag gets a "Value for undeclared variable" warning and is ignored.

resource "random_id" "cloudsql_suffix" {
  byte_length = 4
}

module "cloudsql_postgres" {
  source = "../../modules/cloudsql_postgres"

  project_id         = var.project_id
  environment        = var.environment
  region             = var.region
  instance_name      = "cage-postgres-${var.environment}-${random_id.cloudsql_suffix.hex}"
  database_version   = "POSTGRES_15"
  authorized_network = local.cloudsql_network_name

  # §1.1 Infrastructure Posture:
  # dev: db-f1-micro, ZONAL
  # staging: db-g1-small, ZONAL
  # prod: db-custom-2-7680, REGIONAL; PITR whenever enforcing (POAM-2026-181)
  tier                          = var.environment == "prod" ? "db-custom-2-7680" : (var.environment == "staging" ? "db-g1-small" : var.postgres_tier)
  enable_high_availability      = var.environment == "prod" || var.enable_high_availability
  enable_point_in_time_recovery = local.enforcing_posture
  disk_size                     = var.postgres_disk_size

  enable_cmek = var.enable_cmek
  kms_key_id  = local.cmek_key_id

  deletion_protection = var.enable_deletion_protection

  database_name   = "langfuse"
  user_name       = google_service_account.langfuse.email
  user_type       = "CLOUD_IAM_SERVICE_ACCOUNT"
  enable_iam_auth = true
}

# ─── Deploy Memorystore Instances (Valkey Cluster Mode Disabled) ───────────────
# D5, D6: Two separate instances for governance state integrity and app isolation.

module "memorystore_governance" {
  source = "../../modules/memorystore_valkey"

  project_id  = var.project_id
  environment = var.environment
  region      = var.region
  instance_id = var.memorystore_governance_instance_id != "" ? var.memorystore_governance_instance_id : "cage-valkey-gov-${var.environment}"
  network_id  = local.memorystore_network_name

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

  # POAM-2026-156 item 3: whenever the posture enforces, governance state (CBF
  # commits, single-use markers, deferrals, the evidence stream) is persisted
  # with AOF, and every write is saved to durable storage. Dev without
  # enforce_in_dev keeps persistence off.
  persistence_mode = local.enforcing_posture ? "AOF" : "DISABLED"
  aof_append_fsync = local.enforcing_posture ? "ALWAYS" : null
}

module "memorystore_app" {
  source = "../../modules/memorystore_valkey"

  project_id  = var.project_id
  environment = var.environment
  region      = var.region
  instance_id = var.memorystore_app_instance_id != "" ? var.memorystore_app_instance_id : "cage-valkey-app-${var.environment}"
  network_id  = local.memorystore_network_name

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

  # No governance state lives here (D6), so persistence stays off, stated
  # explicitly rather than left to a default.
  persistence_mode = "DISABLED"
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

# ─── Deploy ClickHouse Operator & Langfuse OLAP Plane (§1.1, §2.6, §3, §7) ───
# ClickHouse serves strictly as the Langfuse v3 OLAP store (`langfuse_app` on `langfuse.*`).
# The retention-locked GCS WORM bucket (module.worm_bucket) is the evidence system of record;
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
  keeper_service_account_name       = kubernetes_service_account.workload["clickhouse_keeper"].metadata[0].name
  cold_tier_bucket                  = local.clickhouse_cold_tier_enabled ? google_storage_bucket.clickhouse_tiering[0].name : ""
  cold_tier_credentials_secret_name = local.clickhouse_cold_tier_enabled ? kubernetes_secret.clickhouse_tiering_hmac[0].metadata[0].name : ""

  cpu_request    = "1000m"
  memory_request = "2Gi"
  cpu_limit      = var.enable_high_availability ? "3000m" : "2000m"
  memory_limit   = var.enable_high_availability ? "6Gi" : "4Gi"

  depends_on = [
    module.gke,
    google_storage_bucket_iam_member.clickhouse_tiering_object_admin,
    kubernetes_service_account.workload["clickhouse"],
    kubernetes_service_account.workload["clickhouse_keeper"],
  ]
}


# ─── Inference Backend (W6) ───────────────────────────────────────────────────
# inference_backend decides what is deployed, not only how it is configured.
# Under "none" nothing that needs a model exists: no vLLM, no advisor, no NeMo
# server. Absent, not degraded: a workload pointed at a model service that does
# not exist crash-loops. The GPU pool stays (min 0), so moving to "vllm" is a
# variable change and an apply, not an infrastructure rebuild.
locals {
  vllm_enabled           = var.inference_backend == "vllm"
  inference_stub_enabled = var.enable_e2e_advisor && !local.vllm_enabled

  # POAM-2026-191 (F-30..F-33): decouple advisor deployment from GPU vLLM so
  # non-production E2E runs (-var enable_e2e_advisor=true) exercise the full
  # gated loop against the deterministic CPU inference-stub backend.
  advisor_enabled = local.vllm_enabled || var.enable_e2e_advisor

  effective_inference_backend = local.inference_stub_enabled ? "stub" : var.inference_backend

  # In-cluster vLLM URLs (empty unless vllm is deployed). Only the gateway may
  # reach them (model-backend-ingress, EA-1).
  vllm_fast_url      = local.vllm_enabled ? "http://vllm-service.${module.namespace.name}.svc.cluster.local:8000/v1" : ""
  vllm_reasoning_url = local.vllm_enabled ? "http://vllm-reasoning.${module.namespace.name}.svc.cluster.local:8000/v1" : ""

  # Gateway upstream model URLs: forward to deterministic inference-stub in
  # opt-in E2E mode when vLLM is absent, otherwise to in-cluster vLLM.
  inference_stub_url          = local.inference_stub_enabled ? "http://inference-stub.${module.namespace.name}.svc.cluster.local:8000/v1" : ""
  gateway_model_fast_url      = local.inference_stub_enabled ? local.inference_stub_url : local.vllm_fast_url
  gateway_model_reasoning_url = local.inference_stub_enabled ? local.inference_stub_url : local.vllm_reasoning_url
  # In-cluster vLLM and inference-stub run without --api-key; startup requires a
  # non-empty placeholder whenever an upstream backend is configured.
  gateway_model_api_key = (local.vllm_enabled || local.inference_stub_enabled) ? "EMPTY" : ""

  # R-16 / F-103: Advisor inference ALWAYS routes through the gateway's
  # OpenAI-compatible /v1/chat/completions proxy so Stage-1 scanning (A.5.2),
  # TokenQuotaProxy (TQP-007), and PII scrubbing (A.9.2) sit on the live path.
  advisor_inference_url     = local.advisor_enabled ? "http://${module.gateway.service_name}.${module.namespace.name}.svc.cluster.local:8080/v1" : ""
  advisor_inference_api_key = local.advisor_enabled ? "EMPTY" : ""
}

# ─── Images Each Profile Deploys (POAM-2026-131) ──────────────────────────────
# The keys var.image_digests must hold. Each entry follows the count of the
# module that reads it, so an absent workload needs no image: staging under
# inference_backend = "none" renders no vLLM, advisor or NeMo image. An explicit
# *_image override replaces the map entry it would otherwise read. The in-cluster
# advisor consumes the advisor image. deploy_all.sh selects the
# images to build from the same profile variables; scripts/render_image_digests.sh
# must be able to render every name here.
locals {
  required_image_digests = concat(
    ["gateway", "opa", "agentsight-ui", "langfuse", "langfuse-worker", "cloud-sql-proxy", "clickhouse-server", "clickhouse-keeper"],
    (var.enable_compliance_bridge || var.enable_reconciliation_worker) && var.compliance_bridge_image == "" ? ["compliance-bridge"] : [],
    var.enable_lula_cron && var.lula_image == "" ? ["lula"] : [],
    local.vllm_enabled && var.vllm_image == "" ? ["vllm-streamer"] : [],
    local.inference_stub_enabled && var.inference_stub_image == "" ? ["inference-stub"] : [],
    local.advisor_enabled ? ["governed-financial-advisor"] : [],
  )
}


# Workload ServiceAccounts are defined per workload in iam.tf
# (kubernetes_service_account.workload), each bound 1:1 to its own GSA.

# ─── Deploy vLLM Inference Engine ──────────────────────────────────────────────

module "vllm" {
  count = local.vllm_enabled ? 1 : 0

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
  count = local.vllm_enabled ? 1 : 0

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

# ─── Deploy Deterministic Inference Stub (opt-in non-prod E2E, POAM-2026-191) ─

module "inference_stub" {
  count = local.inference_stub_enabled ? 1 : 0

  source = "../../modules/inference_stub"

  namespace            = module.namespace.name
  image                = var.inference_stub_image != "" ? var.inference_stub_image : var.image_digests["inference-stub"]
  environment          = var.environment
  service_account_name = kubernetes_service_account.workload["inference_stub"].metadata[0].name
  network_policy_hash  = local.network_policy_spec_hash

  depends_on = [module.gke, module.service_mesh, kubernetes_service_account.workload["inference_stub"]]
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
  clickhouse_db            = module.clickhouse_operator.langfuse_database
  clickhouse_migration_url = "clickhouse://${module.clickhouse_operator.langfuse_username}:${module.clickhouse_operator.langfuse_password}@${module.clickhouse_operator.service_name}:${module.clickhouse_operator.tcp_port}/${module.clickhouse_operator.langfuse_database}"
  clickhouse_user          = module.clickhouse_operator.langfuse_username
  clickhouse_password      = module.clickhouse_operator.langfuse_password
  redis_connection_string  = "redis://${module.memorystore_app.primary_endpoint_ip}:${module.memorystore_app.primary_endpoint_port}"
  redis_host               = module.memorystore_app.primary_endpoint_ip
  redis_port               = tostring(module.memorystore_app.primary_endpoint_port)

  # Native GCS via GKE Workload Identity by default (zero HMAC / SA keys);
  # falls back to explicit S3 credentials only when var.langfuse_s3_access_key != "".
  use_google_cloud_storage = var.langfuse_s3_access_key == ""
  s3_endpoint              = var.langfuse_s3_endpoint
  s3_bucket                = var.langfuse_s3_bucket != "" ? var.langfuse_s3_bucket : google_storage_bucket.langfuse_event_upload.name
  s3_access_key            = var.langfuse_s3_access_key
  s3_secret_key            = var.langfuse_s3_secret_key
  s3_region                = var.region

  nextauth_url          = var.langfuse_nextauth_url
  web_replicas          = var.enable_high_availability ? 2 : 1
  worker_replicas       = var.enable_high_availability ? 2 : 1
  web_cpu_request       = "50m"
  worker_cpu_request    = "50m"
  web_memory_request    = "256Mi"
  worker_memory_request = "256Mi"

  langfuse_public_key            = var.langfuse_public_key
  langfuse_secret_key            = var.langfuse_secret_key
  langfuse_compliance_project_id = "cage-compliance"
  langfuse_compliance_public_key = var.langfuse_compliance_public_key
  langfuse_compliance_secret_key = var.langfuse_compliance_secret_key

  langfuse_init_user_email    = var.langfuse_init_user_email
  langfuse_init_user_password = var.langfuse_init_user_password
  langfuse_init_project_name  = "cybernetic-governance"
  langfuse_init_project_id    = "cybernetic-governance"
  langfuse_init_org_id        = "CAGE"
  langfuse_init_org_name      = "CAGE"

  depends_on = [
    module.cloudsql_postgres,
    module.clickhouse_operator,
    module.memorystore_app,
    google_storage_bucket_iam_member.langfuse_gcs_creator,
    google_storage_bucket_iam_member.langfuse_gcs_reader,
    google_storage_bucket_iam_member.langfuse_gcs_viewer,
    module.gke,
  ]
}

# ─── Deploy Compliance Bridge ───────────────────────────────────────────────────

module "compliance_bridge" {
  count = var.enable_compliance_bridge ? 1 : 0

  source = "../../modules/compliance_bridge"

  namespace     = module.namespace.name
  image         = var.compliance_bridge_image != "" ? var.compliance_bridge_image : var.image_digests["compliance-bridge"]
  langfuse_host = "http://${module.langfuse.web_service_name}.${module.namespace.name}.svc.cluster.local:3000"
  replicas      = var.enable_high_availability ? 2 : 1

  remediation_model      = var.served_model_fast
  remediation_max_tokens = "2048"
  remediation_timeout_ms = "30000"
  # EA-1: model backends admit TCP 8000 from the gateway alone
  # (model-backend-ingress), so the bridge has no model to call. "none" records
  # the remediation advisory as not performed instead of dialling a dropped URL.
  cage_inference_backend     = "none"
  vllm_base_url              = ""
  vllm_api_key               = ""
  alert_channel              = "console"
  oscal_s3_bucket            = module.worm_bucket.bucket_name
  trusted_mesh_identities    = ["${local.ksa_gateway}.${module.namespace.name}.${module.service_mesh.identity_suffix}"]
  auditor_mesh_identity      = "${local.ksa_lula}.${module.namespace.name}.${module.service_mesh.identity_suffix}"
  oscal_s3_region            = var.region
  evidence_cold_store        = "gcs"
  evidence_cold_store_bucket = module.worm_bucket.bucket_name
  cmek_key_resource_name     = var.enable_cmek ? local.evidence_cmek_key_id : ""
  cage_env                   = var.environment
  startup_grace_hours        = var.startup_grace_hours
  deployment_config_map_name = module.deployment_config.config_map_name

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

  trusted_infra_producers = [
    "agentsight-daemon.${module.namespace.name}.${module.service_mesh.identity_suffix}",
    "cage-agentsight-sa.${module.namespace.name}.${module.service_mesh.identity_suffix}",
    "cilium-monitor-exporter.kube-system.${module.service_mesh.identity_suffix}",
    "cilium-monitor-exporter.${module.namespace.name}.${module.service_mesh.identity_suffix}",
    "${local.ksa_lula}.${module.namespace.name}.${module.service_mesh.identity_suffix}",
  ]

  # POAM-2026-196: Human operator OIDC trust-anchor and allowlist configuration.
  trusted_operator_identities = var.trusted_operator_identities
  operator_oidc_issuer        = var.operator_oidc_issuer
  operator_oidc_audience      = var.operator_oidc_audience
  operator_jwks_uri           = var.operator_jwks_uri
  enable_e2e_mode             = var.enable_e2e_advisor
  operator_jwks_json          = var.enable_e2e_advisor ? trimspace(var.e2e_operator_jwks_json) : ""

  depends_on = [module.langfuse, module.vllm, module.worm_bucket, module.memorystore_governance, module.service_mesh]
}


# ─── OPA Read-Only Bundle ConfigMaps (Gateway UDS Sidecar, D-195-3) ───────────

locals {
  domain_opa_dir = "${path.module}/../../../src/cage_${var.cage_domain}/opa"
  domain_opa_policies = {
    for f in try(fileset(local.domain_opa_dir, "*.rego"), toset([])) :
    f => file("${local.domain_opa_dir}/${f}")
    if !endswith(f, "_test.rego")
  }
}

resource "terraform_data" "domain_opa_policies_guard" {
  lifecycle {
    precondition {
      condition     = length(local.domain_opa_policies) > 0
      error_message = "Active cage_domain (${var.cage_domain}) has no non-test .rego policies under src/cage_${var.cage_domain}/opa/; stub domains cannot deploy an empty OPA bundle (POAM-2026-198)."
    }
  }
}

module "opa" {
  source = "../../modules/opa_policy"

  namespace    = module.namespace.name
  policy_files = local.domain_opa_policies

  depends_on = [module.namespace, terraform_data.domain_opa_policies_guard]
}

# ─── Deploy Gateway ─────────────────────────────────────────────────────────────

module "gateway" {
  source = "../../modules/gateway"

  namespace                      = module.namespace.name
  deployment_config_map_name     = module.deployment_config.config_map_name
  image                          = var.image_digests["gateway"]
  opa_image                      = var.image_digests["opa"]
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
  evidence_stream_redis_url                  = local.evidence_stream_redis_url
  evidence_stream_redis_db                   = local.evidence_stream_redis_db
  evidence_stream_key                        = local.evidence_stream_key
  evidence_previous_chain_head_hash          = var.evidence_previous_chain_head_hash
  evidence_previous_batch_attestation_digest = var.evidence_previous_batch_attestation_digest
  cage_inference_backend                     = local.effective_inference_backend
  vllm_base_url                              = local.gateway_model_fast_url
  vllm_reasoning_api_base                    = local.gateway_model_reasoning_url
  vllm_fast_api_base                         = local.gateway_model_fast_url
  vllm_api_key                               = local.gateway_model_api_key
  guardrails_model_name                      = var.served_model_fast
  opa_url                                    = module.opa.uds_url
  opa_policies_config_map_name               = module.opa.policies_config_map_name
  opa_system_authz_config_map_name           = module.opa.system_authz_config_map_name
  opa_config_config_map_name                 = module.opa.config_config_map_name
  opa_bundle_sha256                          = module.opa.bundle_sha256
  opa_policy_files                           = module.opa.policy_files_data
  governance_salt                            = var.governance_salt

  # POAM-2026-080: only the advisor's mesh identity may call gated routes.
  # The gateway does not call itself, so its own identity is not listed.
  trusted_client_identities = [
    "${local.ksa_advisor}.${module.namespace.name}.${module.service_mesh.identity_suffix}",
  ]

  # K-4 / R-2 / F-84: derive OTLP auth header exclusively from the dedicated
  # gateway telemetry keypair (never shared with advisor-secrets).
  otel_exporter_otlp_headers = local.effective_gateway_otlp_headers
  reconciliation_provider    = "simulated"
  cage_kms_provider          = "gcp"

  # POAM-2026-079: own identity; signs seals with gateway-seal and trusts
  # ground truth only from reconciler-snapshot (G8).
  service_account_name = kubernetes_service_account.workload["gateway"].metadata[0].name
  kms_governance_key   = local.gateway_seal_key_version
  reconciler_kms_key   = local.reconciler_snapshot_key_version

  # §5.3, §7: Trigger gateway pod rollout whenever network/FQDN policy specs change
  # so pre-change connections do not outlive a policy tightening.
  network_policy_hash = local.network_policy_spec_hash

  # R-6 / F-91: Keep GMP PodMonitoring/gateway-metrics in Terraform state across W.
  enable_pod_monitoring  = true
  enable_service_monitor = var.enable_service_monitor

  depends_on = [module.app_secrets, module.opa, module.vllm, module.inference_stub, module.memorystore_governance, module.service_mesh]
}

# ─── Deploy Ground-Truth Reconciliation Worker (POAM-2026-096, F-86, CA-7) ────
# Single-writer Deployment signing ground-truth CBF snapshots with
# reconciler-snapshot via cage-reconciler-sa Workload Identity (G8). Reuses the
# digest-pinned compliance-bridge image, which ships src/gateway on PYTHONPATH.

module "reconciliation_worker" {
  count = var.enable_reconciliation_worker ? 1 : 0

  source = "../../modules/reconciliation_worker"

  namespace                  = module.namespace.name
  image                      = var.compliance_bridge_image != "" ? var.compliance_bridge_image : var.image_digests["compliance-bridge"]
  service_account_name       = kubernetes_service_account.workload["reconciler"].metadata[0].name
  reconciler_kms_key         = local.reconciler_snapshot_key_version
  deployment_config_map_name = module.deployment_config.config_map_name
  cage_env                   = var.environment
  cage_kms_provider          = "gcp"

  # Governance Memorystore Valkey: db 0 for ground-truth snapshots + settlement
  # ledger (shared with gateway), db 1 for hash-chained fence evidence.
  redis_url                 = local.evidence_stream_redis_url
  enable_redis_tls          = var.enable_memorystore_tls
  redis_ca_pem              = var.enable_memorystore_tls ? join("\n", module.memorystore_governance.managed_server_ca) : ""
  redis_auth_mode           = local.governance_redis_auth
  evidence_stream_redis_url = local.evidence_stream_redis_url
  evidence_stream_redis_db  = local.evidence_stream_redis_db
  evidence_stream_key       = local.evidence_stream_key
  network_policy_hash       = local.network_policy_spec_hash

  depends_on = [module.deployment_config, module.memorystore_governance, module.service_mesh]
}

# ─── Deploy Governed Financial Advisor (in-cluster GKE Deployment) ───────────
# The advisor exists only with a model backend (local.advisor_enabled).

module "governed_advisor" {
  count  = local.advisor_enabled ? 1 : 0
  source = "../../modules/governed_advisor"

  namespace                  = module.namespace.name
  deployment_config_map_name = module.deployment_config.config_map_name
  image                      = var.image_digests["governed-financial-advisor"]
  replicas                   = var.enable_high_availability ? 2 : 1
  project_id                 = var.project_id
  region                     = var.region
  enable_logging             = "true"
  redis_host                 = module.memorystore_app.primary_endpoint_ip
  redis_port                 = tostring(module.memorystore_app.primary_endpoint_port)
  redis_password             = ""
  model_fast                 = var.served_model_fast
  model_reasoning            = var.served_model_reasoning
  model_consensus            = var.served_model_reasoning
  vllm_base_url              = local.advisor_inference_url
  vllm_fast_api_base         = local.advisor_inference_url
  vllm_reasoning_api_base    = local.advisor_inference_url
  vllm_gateway_url           = local.advisor_inference_url
  vllm_api_key               = local.advisor_inference_api_key
  # Langfuse web service exposes port 3000 (not 80) — corrected from initial misconfiguration.
  langfuse_host = "http://${module.langfuse.web_service_name}.${module.namespace.name}.svc.cluster.local:3000"
  gateway_url   = "http://${module.gateway.service_name}.${module.namespace.name}.svc.cluster.local:8080"
  # POAM-2026-079: own KSA with no cloud identity and no signing key. The
  # advisor refuses to start if a signing-key variable is set.
  service_account_name = kubernetes_service_account.workload["advisor"].metadata[0].name
  cage_env             = var.environment
  enable_e2e_mode      = var.enable_e2e_advisor

  # K-4: wire OTLP auth header so governed-financial-advisor traces reach
  # Langfuse rather than returning 401 Unauthorized.
  # If an explicit override is provided use it; otherwise derive from keys.
  otel_exporter_otlp_headers = var.otel_exporter_otlp_headers != "" ? var.otel_exporter_otlp_headers : (
    var.langfuse_public_key != "" ? "Authorization=Basic ${base64encode("${var.langfuse_public_key}:${var.langfuse_secret_key}")}" : ""
  )

  depends_on = [module.gateway, module.langfuse, module.vllm, module.inference_stub, module.service_mesh]
}

# ─── Deploy AgentSight UI ─────────────────────────────────────────────────────

module "agentsight_ui" {
  source = "../../modules/agentsight_ui"

  namespace            = module.namespace.name
  image                = var.image_digests["agentsight-ui"]
  replicas             = 1
  service_account_name = kubernetes_service_account.workload["agentsight_ui"].metadata[0].name

  depends_on = [module.gke, module.service_mesh, kubernetes_service_account.workload["agentsight_ui"]]
}

# ─── Deploy In-Cluster Lula Compliance Auditor (CA-2 / CA-7) ──────────────────

module "lula_cron" {
  count  = var.enable_lula_cron ? 1 : 0
  source = "../../modules/lula_cron"

  namespace                    = module.namespace.name
  image                        = var.lula_image != "" ? var.lula_image : var.image_digests["lula"]
  service_account_name         = kubernetes_service_account.workload["lula"].metadata[0].name
  schedule                     = var.lula_schedule
  lula_manifests_dir           = "${path.module}/../../../compliance/lula"
  compliance_bridge_events_url = "http://compliance-bridge.${module.namespace.name}.svc.cluster.local:8085/v1/infra/events"
  network_policy_hash          = local.network_policy_spec_hash

  depends_on = [
    module.gke,
    module.namespace,
    module.service_mesh,
    kubernetes_service_account.workload["lula"],
  ]
}

# ─── Deployment Jurisdiction ──────────────────────────────────────────────────
# The cage-deployment ConfigMap is the single source of CAGE_DEPLOYMENT_REGION
# for every workload (and for integration-test region discovery).

module "deployment_config" {
  source = "../../modules/deployment_config"

  namespace              = module.namespace.name
  cage_deployment_region = var.cage_deployment_region
}

# ─── Application Secrets ──────────────────────────────────────────────────────

resource "random_password" "advisor_salt" {
  length  = 32
  special = false
}

resource "random_password" "cage_api_key" {
  length  = 32
  special = false
}

resource "random_password" "cage_internal_token" {
  length  = 32
  special = false
}

resource "random_password" "gateway_telemetry_public_key" {
  length  = 32
  special = false
}

resource "random_password" "gateway_telemetry_secret_key" {
  length  = 32
  special = false
}

locals {
  effective_gateway_telemetry_public_key = (
    var.gateway_langfuse_public_key != ""
    ? var.gateway_langfuse_public_key
    : random_password.gateway_telemetry_public_key.result
  )
  effective_gateway_telemetry_secret_key = (
    var.gateway_langfuse_secret_key != ""
    ? var.gateway_langfuse_secret_key
    : random_password.gateway_telemetry_secret_key.result
  )
  effective_gateway_otlp_headers = (
    var.gateway_otel_exporter_otlp_headers != ""
    ? var.gateway_otel_exporter_otlp_headers
    : "Authorization=Basic ${base64encode("${local.effective_gateway_telemetry_public_key}:${local.effective_gateway_telemetry_secret_key}")}"
  )
}

module "app_secrets" {
  source = "../../modules/app_secrets"

  namespace = module.namespace.name
  cage_env  = local.enforcing_posture ? "staging" : var.environment

  governance_salt      = var.governance_salt
  salt                 = random_password.advisor_salt.result
  cage_api_key         = var.cage_api_key != "" ? var.cage_api_key : random_password.cage_api_key.result
  cage_internal_token  = var.cage_internal_token != "" ? var.cage_internal_token : random_password.cage_internal_token.result
  alphavantage_api_key = "" # Add variable if needed
  openai_api_key       = ""
  model_fast           = var.served_model_fast
  model_reasoning      = var.served_model_reasoning

  langfuse_public_key = var.langfuse_public_key != "" ? var.langfuse_public_key : module.langfuse.public_key
  langfuse_secret_key = var.langfuse_secret_key != "" ? var.langfuse_secret_key : module.langfuse.secret_key
  langfuse_host       = "http://${module.langfuse.web_service_name}.${module.namespace.name}.svc.cluster.local:3000"

  otel_exporter_otlp_headers = var.otel_exporter_otlp_headers != "" ? var.otel_exporter_otlp_headers : (
    var.langfuse_public_key != "" ? "Authorization=Basic ${base64encode("${var.langfuse_public_key}:${var.langfuse_secret_key}")}" : "Authorization=Basic ${base64encode("${module.langfuse.public_key}:${module.langfuse.secret_key}")}"
  )
  redis_password = ""

  gateway_langfuse_public_key        = local.effective_gateway_telemetry_public_key
  gateway_langfuse_secret_key        = local.effective_gateway_telemetry_secret_key
  gateway_otel_exporter_otlp_headers = local.effective_gateway_otlp_headers
  gateway_redis_password             = var.gateway_redis_password

  database_url    = ""
  nextauth_secret = module.langfuse.nextauth_secret
  nextauth_url    = var.langfuse_nextauth_url

  aws_access_key_id     = var.aws_access_key
  aws_secret_access_key = var.aws_secret_key
  s3_endpoint_url       = "https://storage.googleapis.com"
  s3_bucket_name        = google_storage_bucket.langfuse_event_upload.name

  # ─── Langfuse compliance project keys (P2-2) ────────────────────────────────
  # Dev without enforce_in_dev: pass the key as-is. It may be empty: the module
  #   still writes the secret, empty, and the compliance bridge only warns in dev.
  # Enforcing posture (every staging and prod plan, POAM-2026-181): the POAM-019
  #   guards below refuse an empty or shared key in untargeted plans (POAM-2026-180).
  #   The silent fallback to module.langfuse.public_key has been removed to prevent
  #   circular evidence contamination in Step 5 (_fetch_failing_traces).
  langfuse_compliance_public_key = var.langfuse_compliance_public_key
  langfuse_compliance_secret_key = var.langfuse_compliance_secret_key


  cage_deployment_region = var.cage_deployment_region

  depends_on = [module.langfuse, module.cloudsql_postgres, module.clickhouse_operator]
}


# POAM-2026-086 (SC-8): with in-transit encryption on, the gateway and
# compliance-bridge pods pin the governance instance's managed server CA, so it
# must not be empty.
resource "terraform_data" "memorystore_ca_pinning_guard" {
  lifecycle {
    precondition {
      condition     = !var.enable_memorystore_tls || length(module.memorystore_governance.managed_server_ca) > 0
      error_message = "[POAM-2026-086] SC-8 Memorystore CA pinning invariant violated: when enable_memorystore_tls=true, module.memorystore_governance.managed_server_ca must be non-empty so gateway and compliance-bridge pods can pin the server CA."
    }
  }
}

# POAM-019 (AU-9 / SC-7): under an enforcing posture (every staging and prod plan,
# POAM-2026-181), the cage-compliance Langfuse project keys must be set, and must
# differ from the application project's. lifecycle { precondition } is only
# valid inside resource blocks, not module blocks, so terraform_data resources
# carry the guards, at plan time. Each condition has its own resource, whose
# error headline names that condition: terraform test's expect_failures names a
# resource, not a precondition, so tests/poam_019.tftest.hcl can check each
# guard on its own. Error lines stay within 76 columns so that Terraform does
# not re-wrap them when its output is not a terminal.
resource "terraform_data" "poam_019_empty_key_guard" {
  lifecycle {
    precondition {
      condition = !local.enforcing_posture || (
        var.langfuse_compliance_public_key != "" &&
        var.langfuse_compliance_secret_key != ""
      )
      error_message = <<-EOT
        [POAM-019] Compliance telemetry keys are empty under an enforcing posture.
        This is a staging or prod plan, or a dev plan with enforce_in_dev,
        and langfuse_compliance_public_key or
        langfuse_compliance_secret_key is empty. AU-9 dual-project telemetry
        isolation needs the cage-compliance Langfuse project's own keys.
        Remediation: supply both keys through TF_VAR_* or terraform.auto.tfvars,
        never a committed tfvars file. If you ran terraform directly, load .env
        first: ./deploy_all.sh maps LANGFUSE_COMPLIANCE_* from .env, or source
        infra/load_env.sh from bash. If .env was loaded, check that it sets
        LANGFUSE_COMPLIANCE_PUBLIC_KEY and LANGFUSE_COMPLIANCE_SECRET_KEY.
        See POAM-019 in docs/compliance/us_fed/POAM_US_FED.md.
      EOT
    }
  }
}

resource "terraform_data" "poam_019_shared_key_guard" {
  lifecycle {
    precondition {
      # An empty compliance key is the empty-key guard's finding. Skipping it here
      # keeps unset keys ("" == "") from also being reported as shared.
      condition = !local.enforcing_posture || !(
        (var.langfuse_compliance_public_key != "" && var.langfuse_compliance_public_key == var.langfuse_public_key) ||
        (var.langfuse_compliance_secret_key != "" && var.langfuse_compliance_secret_key == var.langfuse_secret_key)
      )
      error_message = <<-EOT
        [POAM-019] Compliance telemetry keys equal the application project keys.
        The posture is enforcing, and langfuse_compliance_public_key equals
        langfuse_public_key or langfuse_compliance_secret_key equals
        langfuse_secret_key. A key shared by both projects collapses the
        dual-project telemetry architecture and defeats the evidentiary
        independence NIST SP 800-53 AU-9 relies on.
        Remediation: supply the cage-compliance Langfuse project's own keys
        (LANGFUSE_COMPLIANCE_* in .env, TF_VAR_* or terraform.auto.tfvars), never
        a committed tfvars file.
        See POAM-019 in docs/compliance/us_fed/POAM_US_FED.md.
      EOT
    }
  }
}

# POAM-2026-126 (AC-3 / SC-7): an enforcing posture must name who may reach the
# control plane. With an empty list the cluster module emits no authorized-networks
# block, so GKE leaves its allowlist off and the endpoint accepts any address; a /0
# entry does the same explicitly. staging.tfvars shipped 0.0.0.0/0 under a header
# that claimed VPN scope, and nothing read the list. The cluster's own node, Pod and
# Service ranges can always reach the control plane, whatever this list says.
resource "terraform_data" "control_plane_access_guard" {
  lifecycle {
    precondition {
      condition = !local.enforcing_posture || (
        length(var.authorized_networks) > 0 &&
        alltrue([for n in var.authorized_networks : !endswith(n.cidr, "/0")])
      )
      error_message = <<-EOT
        [POAM-2026-126] AC-3 control-plane access: under an enforcing posture,
        authorized_networks must hold at least one operator CIDR and no /0.
        An empty list leaves GKE's allowlist off, so the control plane would accept
        any address. Supply your VPN range or the deploying machine's egress /32 with
        TF_VAR_authorized_networks or a --var-file after the profile, never in a
        committed profile. Terraform's kubernetes and helm providers use the public
        endpoint, so the machine running terraform must be on the list.
      EOT
    }
  }
}

# Where a plan-time check goes (POAM-2026-174, POAM-2026-180). Two plans decide
# it: a plan targeted at the resource the check protects, and a destroy plan run
# without the inputs the check reads. Every cell was run on Terraform 1.15.8 and
# 1.17.1:
#
#   placement of the check                      plan -target=<it>   destroy plan
#   standalone terraform_data guard             skipped             succeeds
#   the protected resource depends_on a guard   refused             succeeds
#   precondition on the protected resource      refused             succeeds
#   variable validation                         refused             blocked
#
# A new check goes in one of the two middle rows. A precondition on the protected
# resource cannot be separated from it, but when that resource is in a child
# module, a root-level terraform test cannot name it in expect_failures (both
# versions reject the reference), so the check is tested from the module's own
# tests. A root guard keeps root-level tests, but only while every protected
# resource keeps its depends_on; one that drops it is back in the first row.
# A destroy plan reports resource preconditions only as warnings, so
# `terraform destroy -var-file=staging.tfvars` needs neither authorized_networks
# nor the compliance keys, while a variable validation fails the destroy plan.
# The five legacy guards above and below are standalone: POAM-2026-180 tracks
# moving them, and tests/infrastructure/test_guard_placement.py fails on a new one.

# W6: what each inference backend deploys must be able to run. "vllm" schedules
# its pods on the GPU pool, so it needs one (min 0 costs nothing while idle).
resource "terraform_data" "inference_backend_guard" {
  lifecycle {
    precondition {
      condition     = !local.vllm_enabled || var.enable_gpu_node_pool
      error_message = "inference_backend = \"vllm\" needs enable_gpu_node_pool = true: the vLLM pods schedule only on the GPU pool. Keep the pool at min 0 to pay nothing while idle."
    }
  }
}

# ─── Persistent Evidence Custody Domain (§10a, R-10, F-66, F-94, F-97) ─────────

locals {
  evidence_project_id = coalesce(var.evidence_project_id, var.project_id)
  evidence_bucket_name = (
    var.evidence_bucket_name != ""
    ? var.evidence_bucket_name
    : "${local.evidence_project_id}-evidence-worm-${var.environment}"
  )
  require_separate_evidence_project = (
    var.require_separate_evidence_project != null
    ? var.require_separate_evidence_project
    : (var.environment == "prod")
  )
  effective_kms_protection_level = (
    var.kms_protection_level != ""
    ? var.kms_protection_level
    : (var.environment == "dev" ? "SOFTWARE" : "HSM")
  )
  evidence_cmek_key_id = var.enable_cmek ? module.evidence_domain.evidence_cmek_key_id : ""
}

resource "terraform_data" "evidence_domain_isolation_guard" {
  lifecycle {
    precondition {
      condition     = !local.require_separate_evidence_project || var.external_evidence_domain_enabled || local.evidence_project_id != var.project_id
      error_message = "[AU-9(4) / F-66 / F-97] Production evidence custody isolation requires external_evidence_domain_enabled = true or a dedicated evidence_project_id ('${local.evidence_project_id}') distinct from project_id ('${var.project_id}') so the workload deployer SA holds zero destroy path over evidence resources."
    }

    precondition {
      condition     = !var.external_evidence_domain_enabled || !var.enable_cmek || var.external_evidence_cmek_key_id != ""
      error_message = "[F-97] When external_evidence_domain_enabled = true and enable_cmek = true, external_evidence_cmek_key_id must be set to the external evidence CMEK CryptoKey ID."
    }
  }
}

module "evidence_domain" {
  source = "../../modules/evidence_domain"

  evidence_project_id               = coalesce(var.evidence_project_id, var.project_id)
  workload_project_id               = var.project_id
  environment                       = var.environment
  region                            = var.region
  cage_deployment_region            = var.cage_deployment_region
  external_evidence_domain_enabled  = var.external_evidence_domain_enabled
  external_evidence_cmek_key_id     = var.external_evidence_cmek_key_id
  require_separate_evidence_project = local.require_separate_evidence_project
  evidence_bucket_name              = module.worm_bucket.bucket_name
  audit_logs_bucket_name            = var.audit_logs_bucket_name
  retention_period_seconds          = local.retention_period_seconds
  retention_locked                  = local.retention_locked
  enable_cmek                       = var.enable_cmek
  kms_protection_level              = local.effective_kms_protection_level
  custodian_service_account_email   = google_service_account.compliance_bridge.email
  audit_log_sink_writer_identities = merge(
    var.audit_log_sink_writer_identities,
    local.managed_audit_log_sink_writer_identities,
  )
  offline_verifier_principal     = var.offline_verifier_principal
  deployer_service_account_email = google_service_account.deployer.email
  signing_key_manifest           = local.signing_key_manifest

  isolation_guard_ready = terraform_data.evidence_domain_isolation_guard.id
}
