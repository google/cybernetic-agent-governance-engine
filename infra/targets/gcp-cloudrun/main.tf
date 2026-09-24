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

# ─── Data Sources ─────────────────────────────────────────────────────────────

data "google_project" "current" {
  project_id = var.project_id
}

# ─── VPC Network ──────────────────────────────────────────────────────────────

resource "google_compute_network" "vpc" {
  name                    = "cage-cloudrun-vpc-${var.environment}"
  auto_create_subnetworks = false
  project                 = var.project_id
}

resource "google_compute_subnetwork" "subnet" {
  name          = "cage-cloudrun-subnet-${var.environment}"
  ip_cidr_range = var.subnet_cidr
  region        = var.region
  network       = google_compute_network.vpc.id
  project       = var.project_id

  private_ip_google_access = true
}

# ─── VPC Access Connector ─────────────────────────────────────────────────────
# REMOVED: B6 defect — services use Direct VPC Egress (network_interfaces),
# making the connector unreachable infrastructure with standing cost and attack
# surface. The connector and network_interfaces are mutually exclusive vpc_access
# modes per https://cloud.google.com/run/docs/configuring/vpc-direct-vpc

# ─── Cloud Memorystore Redis ──────────────────────────────────────────────────

resource "google_redis_instance" "redis" {
  name               = "cage-cloudrun-redis-${var.environment}"
  tier               = var.enable_high_availability ? "STANDARD_HA" : var.redis_tier
  memory_size_gb     = var.redis_memory_size_gb
  region             = var.region
  authorized_network = google_compute_network.vpc.id
  connect_mode       = "PRIVATE_SERVICE_ACCESS"
  project            = var.project_id

  redis_version = "REDIS_7_0"

  # CMEK encryption (Phase C)
  customer_managed_key = var.enable_cmek ? google_kms_crypto_key.cloudrun_cmek[0].id : null

  # High Availability configuration
  replica_count        = var.enable_high_availability ? 1 : 0
  read_replicas_mode   = var.enable_high_availability ? "READ_REPLICAS_ENABLED" : "READ_REPLICAS_DISABLED"
  
  # Persistence configuration
  persistence_config {
    persistence_mode    = "RDB"
    rdb_snapshot_period = "ONE_HOUR"
  }

  maintenance_policy {
    weekly_maintenance_window {
      day = "SUNDAY"
      start_time {
        hours   = 2
        minutes = 0
        seconds = 0
        nanos   = 0
      }
    }
  }

  depends_on = [google_compute_network.vpc]
}

# ─── Cloud SQL PostgreSQL ─────────────────────────────────────────────────────

resource "random_password" "postgres_password" {
  length  = 32
  special = true
}

resource "google_sql_database_instance" "postgres" {
  name             = "cage-cloudrun-postgres-${var.environment}"
  database_version = "POSTGRES_15"
  region           = var.region
  project          = var.project_id

  # CMEK encryption (Phase C)
  encryption_key_name = var.enable_cmek ? google_kms_crypto_key.cloudrun_cmek[0].id : null

  settings {
    tier              = var.postgres_tier
    availability_type = var.enable_high_availability ? "REGIONAL" : "ZONAL"
    disk_size         = var.postgres_disk_size
    disk_type         = "PD_SSD"

    backup_configuration {
      enabled                        = true
      start_time                     = "02:00"
      point_in_time_recovery_enabled = var.enable_high_availability
      transaction_log_retention_days = 7
      backup_retention_settings {
        retained_backups = 7
        retention_unit   = "COUNT"
      }
    }

    ip_configuration {
      ipv4_enabled    = false
      private_network = google_compute_network.vpc.id
      require_ssl     = true
    }

    maintenance_window {
      day          = 7 # Sunday
      hour         = 2
      update_track = "stable"
    }

    database_flags {
      name  = "max_connections"
      value = "100"
    }
  }

  deletion_protection = var.enable_nist_compliance

  depends_on = [google_compute_network.vpc]
}

resource "google_sql_database" "langfuse" {
  name     = "langfuse"
  instance = google_sql_database_instance.postgres.name
  project  = var.project_id
}

resource "google_sql_user" "langfuse" {
  name     = "langfuse"
  instance = google_sql_database_instance.postgres.name
  password = random_password.postgres_password.result
  project  = var.project_id
}

# ─── GCS Buckets ──────────────────────────────────────────────────────────────

resource "google_storage_bucket" "langfuse_traces" {
  name          = var.traces_bucket_name != "" ? var.traces_bucket_name : "${var.project_id}-langfuse-traces-${var.environment}"
  location      = var.region
  project       = var.project_id
  force_destroy = var.environment != "prod"

  uniform_bucket_level_access = true

  # CMEK encryption (Phase C)
  dynamic "encryption" {
    for_each = var.enable_cmek ? [1] : []
    content {
      default_kms_key_name = google_kms_crypto_key.cloudrun_cmek[0].id
    }
  }

  versioning {
    enabled = var.enable_nist_compliance
  }

  lifecycle_rule {
    condition {
      age = 90
    }
    action {
      type          = "SetStorageClass"
      storage_class = "COLDLINE"
    }
  }
}

resource "google_storage_bucket" "compliance_artifacts" {
  name          = var.artifacts_bucket_name != "" ? var.artifacts_bucket_name : "${var.project_id}-compliance-artifacts-${var.environment}"
  location      = var.region
  project       = var.project_id
  force_destroy = var.environment != "prod"

  uniform_bucket_level_access = true

  # CMEK encryption (Phase C)
  dynamic "encryption" {
    for_each = var.enable_cmek ? [1] : []
    content {
      default_kms_key_name = google_kms_crypto_key.cloudrun_cmek[0].id
    }
  }

  versioning {
    enabled = true
  }

  # AU-9: WORM retention (B5 fix) — 2555 days (7 years) immutable retention.
  # Prevents deletion before 2555 days AND locks the policy irreversibly.
  # Compounding with downgraded writer SA (objectCreator instead of objectAdmin)
  # ensures even the compliance bridge cannot erase evidence it writes.
  retention_policy {
    retention_period = 220752000  # 2555 days in seconds
    is_locked        = var.enable_nist_compliance ? true : false
  }

  lifecycle_rule {
    condition {
      age = 365
    }
    action {
      type          = "SetStorageClass"
      storage_class = "ARCHIVE"
    }
  }
}

# ─── Secret Manager Secrets ───────────────────────────────────────────────────

resource "google_secret_manager_secret" "routing_seal_secret" {
  secret_id = "cage-routing-seal-secret-${var.environment}"
  project   = var.project_id

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "routing_seal_secret" {
  secret      = google_secret_manager_secret.routing_seal_secret.id
  secret_data = var.routing_seal_secret
}

resource "google_secret_manager_secret" "routing_seal_salt" {
  secret_id = "cage-routing-seal-salt-${var.environment}"
  project   = var.project_id

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "routing_seal_salt" {
  secret      = google_secret_manager_secret.routing_seal_salt.id
  secret_data = var.routing_seal_salt
}

resource "google_secret_manager_secret" "langfuse_nextauth_secret" {
  secret_id = "langfuse-nextauth-secret-${var.environment}"
  project   = var.project_id

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "langfuse_nextauth_secret" {
  secret      = google_secret_manager_secret.langfuse_nextauth_secret.id
  secret_data = var.langfuse_nextauth_secret
}

resource "google_secret_manager_secret" "langfuse_salt" {
  secret_id = "langfuse-salt-${var.environment}"
  project   = var.project_id

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "langfuse_salt" {
  secret      = google_secret_manager_secret.langfuse_salt.id
  secret_data = var.langfuse_salt
}

resource "google_secret_manager_secret" "postgres_password" {
  secret_id = "postgres-password-${var.environment}"
  project   = var.project_id

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "postgres_password" {
  secret      = google_secret_manager_secret.postgres_password.id
  secret_data = random_password.postgres_password.result
}

resource "google_secret_manager_secret" "langfuse_public_key" {
  count     = var.langfuse_public_key != "" ? 1 : 0
  secret_id = "langfuse-public-key-${var.environment}"
  project   = var.project_id

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "langfuse_public_key" {
  count       = var.langfuse_public_key != "" ? 1 : 0
  secret      = google_secret_manager_secret.langfuse_public_key[0].id
  secret_data = var.langfuse_public_key
}

resource "google_secret_manager_secret" "langfuse_secret_key" {
  count     = var.langfuse_secret_key != "" ? 1 : 0
  secret_id = "langfuse-secret-key-${var.environment}"
  project   = var.project_id

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "langfuse_secret_key" {
  count       = var.langfuse_secret_key != "" ? 1 : 0
  secret      = google_secret_manager_secret.langfuse_secret_key[0].id
  secret_data = var.langfuse_secret_key
}

resource "google_secret_manager_secret" "langfuse_compliance_public_key" {
  count     = var.langfuse_compliance_public_key != "" ? 1 : 0
  secret_id = "langfuse-compliance-public-key-${var.environment}"
  project   = var.project_id

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "langfuse_compliance_public_key" {
  count       = var.langfuse_compliance_public_key != "" ? 1 : 0
  secret      = google_secret_manager_secret.langfuse_compliance_public_key[0].id
  secret_data = var.langfuse_compliance_public_key
}

resource "google_secret_manager_secret" "langfuse_compliance_secret_key" {
  count     = var.langfuse_compliance_secret_key != "" ? 1 : 0
  secret_id = "langfuse-compliance-secret-key-${var.environment}"
  project   = var.project_id

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "langfuse_compliance_secret_key" {
  count       = var.langfuse_compliance_secret_key != "" ? 1 : 0
  secret      = google_secret_manager_secret.langfuse_compliance_secret_key[0].id
  secret_data = var.langfuse_compliance_secret_key
}

# ─── IAM Service Accounts ─────────────────────────────────────────────────────

resource "google_service_account" "gateway" {
  account_id   = "cage-gateway-${var.environment}"
  display_name = "CAGE Gateway Service Account"
  project      = var.project_id
}

resource "google_service_account" "governed_advisor" {
  account_id   = "cage-advisor-${var.environment}"
  display_name = "CAGE Governed Financial Advisor Service Account"
  project      = var.project_id
}

resource "google_service_account" "agentsight_ui" {
  account_id   = "cage-agentsight-${var.environment}"
  display_name = "CAGE AgentSight UI Service Account"
  project      = var.project_id
}

resource "google_service_account" "compliance_bridge" {
  account_id   = "cage-compliance-${var.environment}"
  display_name = "CAGE Compliance Bridge Service Account"
  project      = var.project_id
}

resource "google_service_account" "langfuse" {
  account_id   = "cage-langfuse-${var.environment}"
  display_name = "CAGE Langfuse Service Account"
  project      = var.project_id
}

resource "google_service_account" "nemo_guardrails" {
  account_id   = "cage-nemo-${var.environment}"
  display_name = "CAGE NeMo Guardrails Service Account"
  project      = var.project_id
}

resource "google_service_account" "reconciliation_daemon" {
  account_id   = "cage-reconciliation-${var.environment}"
  display_name = "CAGE Reconciliation Daemon Service Account"
  project      = var.project_id
}

# ─── IAM Bindings ─────────────────────────────────────────────────────────────

# Gateway: Secret Manager access
resource "google_secret_manager_secret_iam_member" "gateway_routing_seal_secret" {
  secret_id = google_secret_manager_secret.routing_seal_secret.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.gateway.email}"
  project   = var.project_id
}

resource "google_secret_manager_secret_iam_member" "gateway_routing_seal_salt" {
  secret_id = google_secret_manager_secret.routing_seal_salt.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.gateway.email}"
  project   = var.project_id
}

# Gateway: GCS bucket access (B5 fix — downgraded from objectAdmin)
# objectCreator: can write objects but NOT delete them (AU-9 WORM compliance)
# legacyBucketReader: can list bucket contents for evidence enumeration
resource "google_storage_bucket_iam_member" "gateway_compliance_artifacts_creator" {
  bucket = google_storage_bucket.compliance_artifacts.name
  role   = "roles/storage.objectCreator"
  member = "serviceAccount:${google_service_account.gateway.email}"
}

resource "google_storage_bucket_iam_member" "gateway_compliance_artifacts_reader" {
  bucket = google_storage_bucket.compliance_artifacts.name
  role   = "roles/storage.legacyBucketReader"
  member = "serviceAccount:${google_service_account.gateway.email}"
}

# Langfuse: Secret Manager access
resource "google_secret_manager_secret_iam_member" "langfuse_nextauth_secret" {
  secret_id = google_secret_manager_secret.langfuse_nextauth_secret.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.langfuse.email}"
  project   = var.project_id
}

resource "google_secret_manager_secret_iam_member" "langfuse_salt" {
  secret_id = google_secret_manager_secret.langfuse_salt.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.langfuse.email}"
  project   = var.project_id
}

resource "google_secret_manager_secret_iam_member" "langfuse_postgres_password" {
  secret_id = google_secret_manager_secret.postgres_password.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.langfuse.email}"
  project   = var.project_id
}

# Langfuse: GCS bucket access
resource "google_storage_bucket_iam_member" "langfuse_traces" {
  bucket = google_storage_bucket.langfuse_traces.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.langfuse.email}"
}

# Compliance Bridge: GCS bucket access (B5 fix — downgraded from objectAdmin)
# objectCreator: can write evidence but NOT delete it (AU-9 WORM compliance)
# legacyBucketReader: can list bucket contents for evidence enumeration
resource "google_storage_bucket_iam_member" "compliance_bridge_artifacts_creator" {
  bucket = google_storage_bucket.compliance_artifacts.name
  role   = "roles/storage.objectCreator"
  member = "serviceAccount:${google_service_account.compliance_bridge.email}"
}

resource "google_storage_bucket_iam_member" "compliance_bridge_artifacts_reader" {
  bucket = google_storage_bucket.compliance_artifacts.name
  role   = "roles/storage.legacyBucketReader"
  member = "serviceAccount:${google_service_account.compliance_bridge.email}"
}

# Reconciliation Daemon: GCS access for evidence enumeration
resource "google_storage_bucket_iam_member" "reconciliation_compliance_artifacts_viewer" {
  bucket = google_storage_bucket.compliance_artifacts.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.reconciliation_daemon.email}"
}

# Reconciliation Daemon: KMS access for signature verification
resource "google_kms_crypto_key_iam_member" "reconciliation_kms_verifier" {
  count         = var.kms_governance_key != "" ? 1 : 0
  crypto_key_id = var.kms_governance_key
  role          = "roles/cloudkms.signerVerifier"
  member        = "serviceAccount:${google_service_account.reconciliation_daemon.email}"
}

# ─── Cloud Run Services ───────────────────────────────────────────────────────

# Gateway Service
resource "google_cloud_run_v2_service" "gateway" {
  name     = "cage-gateway-${var.environment}"
  location = var.region
  project  = var.project_id

  # B2: Conditional ingress tightening — only restrict to LB traffic when LB exists
  ingress = var.enable_load_balancer ? "INGRESS_TRAFFIC_INTERNAL_AND_CLOUD_LOAD_BALANCING" : "INGRESS_TRAFFIC_ALL"

  template {
    service_account = google_service_account.gateway.email

    # CMEK encryption (Phase C)
    encryption_key = var.enable_cmek ? google_kms_crypto_key.cloudrun_cmek[0].id : null

    scaling {
      min_instance_count = var.enable_high_availability ? 2 : var.gateway_min_instances
      max_instance_count = var.gateway_max_instances
    }

    vpc_access {
      network_interfaces {
        network    = google_compute_network.vpc.id
        subnetwork = google_compute_subnetwork.subnet.id
      }
      egress = "ALL_TRAFFIC"
    }

    # OPA Sidecar Container (must start before gateway)
    containers {
      name  = "opa"
      image = var.opa_sidecar_image != "" ? var.opa_sidecar_image : "gcr.io/${var.project_id}/cage-opa:latest"

      # NO ports block - OPA sidecar does not expose external ports
      # Only localhost communication with gateway container

      resources {
        limits = {
          cpu    = "0.5"
          memory = "256Mi"
        }
      }

      startup_probe {
        http_get {
          path = "/health"
          port = 8181
        }
        initial_delay_seconds = 5
        period_seconds        = 3
        timeout_seconds       = 2
        failure_threshold     = 10
      }

      env {
        name  = "ENVIRONMENT"
        value = var.environment
      }

      env {
        name  = "CAGE_DEPLOYMENT_REGION"
        value = var.cage_deployment_region
      }

      env {
        name  = "CAGE_COMPLIANCE_BRIDGE_URL"
        value = google_cloud_run_v2_service.compliance_bridge.uri
      }
    }

    # Gateway Container (depends on OPA sidecar)
    containers {
      name       = "gateway"
      image      = var.gateway_image != "" ? var.gateway_image : "gcr.io/${var.project_id}/cage-gateway:latest"
      depends_on = ["opa"]

      ports {
        container_port = 8080
      }

      resources {
        limits = {
          cpu    = var.gateway_cpu
          memory = var.gateway_memory
        }
      }

      env {
        name  = "ENVIRONMENT"
        value = var.environment
      }

      env {
        name  = "CAGE_DEPLOYMENT_REGION"
        value = var.cage_deployment_region
      }

      env {
        name  = "OPA_URL"
        value = "http://localhost:8181"
      }

      env {
        name  = "REDIS_HOST"
        value = google_redis_instance.redis.host
      }

      env {
        name  = "REDIS_PORT"
        value = tostring(google_redis_instance.redis.port)
      }

      env {
        name = "CAGE_ROUTING_SEAL_SECRET"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.routing_seal_secret.secret_id
            version = "latest"
          }
        }
      }

      env {
        name = "CAGE_ROUTING_SEAL_SALT"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.routing_seal_salt.secret_id
            version = "latest"
          }
        }
      }
    }
  }

  # B2: Critical ordering — gateway service creation is naturally ordered:
  # When enable_load_balancer=false: no LB resources exist, ingress=ALL
  # When enable_load_balancer=true: Terraform creates LB first (via count-based
  # conditional resources), then applies INTERNAL_AND_CLOUD_LOAD_BALANCING ingress.
  # The conditional `count` in load balancer resources prevents circular dependency.
  depends_on = [google_redis_instance.redis]
}

# Governed Financial Advisor Service
resource "google_cloud_run_v2_service" "governed_advisor" {
  name     = "cage-governed-advisor-${var.environment}"
  location = var.region
  project  = var.project_id

  # Internal service: only accessible from within VPC
  ingress = "INGRESS_TRAFFIC_INTERNAL_ONLY"

  template {
    service_account = google_service_account.governed_advisor.email

    # CMEK encryption (Phase C)
    encryption_key = var.enable_cmek ? google_kms_crypto_key.cloudrun_cmek[0].id : null

    scaling {
      min_instance_count = var.enable_high_availability ? 2 : var.advisor_min_instances
      max_instance_count = var.advisor_max_instances
    }

    vpc_access {
      network_interfaces {
        network    = google_compute_network.vpc.id
        subnetwork = google_compute_subnetwork.subnet.id
      }
      egress = "ALL_TRAFFIC"
    }

    containers {
      image = var.governed_advisor_image != "" ? var.governed_advisor_image : "gcr.io/${var.project_id}/cage-governed-advisor:latest"

      ports {
        container_port = 8080
      }

      resources {
        limits = {
          cpu    = var.advisor_cpu
          memory = var.advisor_memory
        }
      }

      env {
        name  = "ENVIRONMENT"
        value = var.environment
      }

      env {
        name  = "CAGE_DEPLOYMENT_REGION"
        value = var.cage_deployment_region
      }

      env {
        name  = "REDIS_HOST"
        value = google_redis_instance.redis.host
      }

      env {
        name  = "REDIS_PORT"
        value = tostring(google_redis_instance.redis.port)
      }
    }
  }

  depends_on = [google_redis_instance.redis]
}

# AgentSight UI Service
resource "google_cloud_run_v2_service" "agentsight_ui" {
  name     = "cage-agentsight-ui-${var.environment}"
  location = var.region
  project  = var.project_id

  # Internal service: only accessible from within VPC
  ingress = "INGRESS_TRAFFIC_INTERNAL_ONLY"

  template {
    service_account = google_service_account.agentsight_ui.email

    # CMEK encryption (Phase C)
    encryption_key = var.enable_cmek ? google_kms_crypto_key.cloudrun_cmek[0].id : null

    scaling {
      min_instance_count = var.enable_high_availability ? 2 : 0
      max_instance_count = 5
    }

    vpc_access {
      network_interfaces {
        network    = google_compute_network.vpc.id
        subnetwork = google_compute_subnetwork.subnet.id
      }
      egress = "ALL_TRAFFIC"
    }

    containers {
      image = var.agentsight_ui_image != "" ? var.agentsight_ui_image : "gcr.io/${var.project_id}/cage-agentsight-ui:latest"

      ports {
        container_port = 8080
      }

      resources {
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }
      }

      env {
        name  = "ENVIRONMENT"
        value = var.environment
      }

      env {
        name  = "CAGE_DEPLOYMENT_REGION"
        value = var.cage_deployment_region
      }
    }
  }

  # No explicit depends_on needed — network_interfaces reference ensures VPC creation order
}

# Compliance Bridge Service
resource "google_cloud_run_v2_service" "compliance_bridge" {
  name     = "cage-compliance-bridge-${var.environment}"
  location = var.region
  project  = var.project_id

  # Internal service: only accessible from within VPC
  ingress = "INGRESS_TRAFFIC_INTERNAL_ONLY"

  template {
    service_account = google_service_account.compliance_bridge.email

    # CMEK encryption (Phase C)
    encryption_key = var.enable_cmek ? google_kms_crypto_key.cloudrun_cmek[0].id : null

    scaling {
      min_instance_count = var.enable_high_availability ? 2 : 0
      max_instance_count = 5
    }

    vpc_access {
      network_interfaces {
        network    = google_compute_network.vpc.id
        subnetwork = google_compute_subnetwork.subnet.id
      }
      egress = "ALL_TRAFFIC"
    }

    containers {
      image = var.compliance_bridge_image != "" ? var.compliance_bridge_image : "gcr.io/${var.project_id}/cage-compliance-bridge:latest"

      ports {
        container_port = 8080
      }

      resources {
        limits = {
          cpu    = "1"
          memory = "1Gi"
        }
      }

      env {
        name  = "ENVIRONMENT"
        value = var.environment
      }

      env {
        name  = "CAGE_DEPLOYMENT_REGION"
        value = var.cage_deployment_region
      }

      env {
        name  = "GCS_BUCKET"
        value = google_storage_bucket.compliance_artifacts.name
      }

      env {
        name  = "EVIDENCE_STREAM_ENABLED"
        value = "true"
      }
    }
  }

  # No explicit depends_on needed — network_interfaces reference ensures VPC creation order
}

# Langfuse Web Service
resource "google_cloud_run_v2_service" "langfuse_web" {
  name     = "cage-langfuse-web-${var.environment}"
  location = var.region
  project  = var.project_id

  # Internal service: only accessible from within VPC
  ingress = "INGRESS_TRAFFIC_INTERNAL_ONLY"

  template {
    service_account = google_service_account.langfuse.email

    # CMEK encryption (Phase C)
    encryption_key = var.enable_cmek ? google_kms_crypto_key.cloudrun_cmek[0].id : null

    scaling {
      min_instance_count = var.enable_high_availability ? 2 : 0
      max_instance_count = 5
    }

    vpc_access {
      network_interfaces {
        network    = google_compute_network.vpc.id
        subnetwork = google_compute_subnetwork.subnet.id
      }
      egress = "ALL_TRAFFIC"
    }

    containers {
      image = var.langfuse_web_image

      ports {
        container_port = 3000
      }

      resources {
        limits = {
          cpu    = "2"
          memory = "2Gi"
        }
      }

      env {
        name  = "NODE_ENV"
        value = "production"
      }

      env {
        name  = "DATABASE_HOST"
        value = google_sql_database_instance.postgres.private_ip_address
      }

      env {
        name  = "DATABASE_NAME"
        value = google_sql_database.langfuse.name
      }

      env {
        name  = "DATABASE_USERNAME"
        value = google_sql_user.langfuse.name
      }

      env {
        name = "DATABASE_PASSWORD"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.postgres_password.secret_id
            version = "latest"
          }
        }
      }

      env {
        name = "NEXTAUTH_SECRET"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.langfuse_nextauth_secret.secret_id
            version = "latest"
          }
        }
      }

      env {
        name = "SALT"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.langfuse_salt.secret_id
            version = "latest"
          }
        }
      }

      env {
        name  = "LANGFUSE_S3_EVENT_UPLOAD_BUCKET"
        value = google_storage_bucket.langfuse_traces.name
      }

      env {
        name  = "LANGFUSE_S3_EVENT_UPLOAD_REGION"
        value = "auto"
      }

      env {
        name  = "LANGFUSE_S3_EVENT_UPLOAD_ENDPOINT"
        value = "https://storage.googleapis.com"
      }
    }
  }

  depends_on = [
    google_sql_database_instance.postgres,
    google_sql_database.langfuse
  ]
}

# Langfuse Worker Service
resource "google_cloud_run_v2_service" "langfuse_worker" {
  name     = "cage-langfuse-worker-${var.environment}"
  location = var.region
  project  = var.project_id

  # Internal service: only accessible from within VPC
  ingress = "INGRESS_TRAFFIC_INTERNAL_ONLY"

  template {
    service_account = google_service_account.langfuse.email

    # CMEK encryption (Phase C)
    encryption_key = var.enable_cmek ? google_kms_crypto_key.cloudrun_cmek[0].id : null

    scaling {
      min_instance_count = var.enable_high_availability ? 2 : 0
      max_instance_count = 10
    }

    vpc_access {
      network_interfaces {
        network    = google_compute_network.vpc.id
        subnetwork = google_compute_subnetwork.subnet.id
      }
      egress = "ALL_TRAFFIC"
    }

    containers {
      image = var.langfuse_worker_image

      resources {
        limits = {
          cpu    = "2"
          memory = "2Gi"
        }
      }

      env {
        name  = "NODE_ENV"
        value = "production"
      }

      env {
        name  = "DATABASE_HOST"
        value = google_sql_database_instance.postgres.private_ip_address
      }

      env {
        name  = "DATABASE_NAME"
        value = google_sql_database.langfuse.name
      }

      env {
        name  = "DATABASE_USERNAME"
        value = google_sql_user.langfuse.name
      }

      env {
        name = "DATABASE_PASSWORD"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.postgres_password.secret_id
            version = "latest"
          }
        }
      }

      env {
        name = "SALT"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.langfuse_salt.secret_id
            version = "latest"
          }
        }
      }

      env {
        name  = "LANGFUSE_S3_EVENT_UPLOAD_BUCKET"
        value = google_storage_bucket.langfuse_traces.name
      }

      env {
        name  = "LANGFUSE_S3_EVENT_UPLOAD_REGION"
        value = "auto"
      }

      env {
        name  = "LANGFUSE_S3_EVENT_UPLOAD_ENDPOINT"
        value = "https://storage.googleapis.com"
      }
    }
  }

  depends_on = [
    google_sql_database_instance.postgres,
    google_sql_database.langfuse
  ]
}

# NeMo Guardrails Service (Phase D - Requirement 9)
resource "google_cloud_run_v2_service" "nemo_guardrails" {
  count    = var.enable_nemo_guardrails ? 1 : 0
  name     = "cage-nemo-guardrails-${var.environment}"
  location = var.region
  project  = var.project_id

  # Internal service: only accessible from within VPC (AC-3)
  ingress = "INGRESS_TRAFFIC_INTERNAL_ONLY"

  template {
    service_account = google_service_account.nemo_guardrails.email

    scaling {
      min_instance_count = var.enable_high_availability ? 2 : 0
      max_instance_count = 5
    }

    vpc_access {
      network_interfaces {
        network    = google_compute_network.vpc.id
        subnetwork = google_compute_subnetwork.subnet.id
      }
      egress = "ALL_TRAFFIC"
    }

    containers {
      name  = "nemo"
      image = var.nemo_image != "" ? var.nemo_image : "gcr.io/${var.project_id}/cage-nemo-guardrails:latest"

      ports {
        container_port = 8000
      }

      resources {
        limits = {
          cpu    = "1"
          memory = "2Gi"
        }
      }

      # Health checks on port 8000
      startup_probe {
        http_get {
          path = "/health"
          port = 8000
        }
        initial_delay_seconds = 10
        period_seconds        = 3
        timeout_seconds       = 2
        failure_threshold     = 10
      }

      liveness_probe {
        http_get {
          path = "/health"
          port = 8000
        }
        period_seconds    = 20
        timeout_seconds   = 5
        failure_threshold = 3
      }

      env {
        name  = "ENVIRONMENT"
        value = var.environment
      }

      env {
        name  = "CAGE_DEPLOYMENT_REGION"
        value = var.cage_deployment_region
      }

      env {
        name  = "VLLM_BASE_URL"
        value = "http://vllm-service:8000"
      }

      env {
        name  = "LANGFUSE_HOST"
        value = google_cloud_run_v2_service.langfuse_web.uri
      }

      # Langfuse compliance credentials for input validation telemetry (AU-9)
      dynamic "env" {
        for_each = var.langfuse_compliance_public_key != "" ? [1] : []
        content {
          name = "LANGFUSE_PUBLIC_KEY"
          value_source {
            secret_key_ref {
              secret  = google_secret_manager_secret.langfuse_compliance_public_key[0].secret_id
              version = "latest"
            }
          }
        }
      }

      dynamic "env" {
        for_each = var.langfuse_compliance_secret_key != "" ? [1] : []
        content {
          name = "LANGFUSE_SECRET_KEY"
          value_source {
            secret_key_ref {
              secret  = google_secret_manager_secret.langfuse_compliance_secret_key[0].secret_id
              version = "latest"
            }
          }
        }
      }
    }
  }

  depends_on = [google_cloud_run_v2_service.langfuse_web]
}

# Reconciliation Daemon Service (Phase D - Requirement 11)
resource "google_cloud_run_v2_service" "reconciliation_daemon" {
  name     = "cage-reconciliation-daemon-${var.environment}"
  location = var.region
  project  = var.project_id

  # Internal service: only accessible from within VPC
  ingress = "INGRESS_TRAFFIC_INTERNAL_ONLY"

  template {
    service_account = google_service_account.reconciliation_daemon.email

    scaling {
      min_instance_count = 1
      max_instance_count = 1
    }

    # Critical: CPU always allocated for continuous reconciliation loop
    containers {
      image = var.compliance_bridge_image != "" ? var.compliance_bridge_image : "gcr.io/${var.project_id}/cage-compliance-bridge:latest"

      ports {
        container_port = 8080
      }

      resources {
        cpu_idle = false  # CPU always allocated — prevents daemon freeze between requests
        limits = {
          cpu    = "1"
          memory = "1Gi"
        }
      }

      env {
        name  = "ENVIRONMENT"
        value = var.environment
      }

      env {
        name  = "CAGE_DEPLOYMENT_REGION"
        value = var.cage_deployment_region
      }

      env {
        name  = "GCS_BUCKET"
        value = google_storage_bucket.compliance_artifacts.name
      }

      # Continuous mode: daemon runs reconciliation loop indefinitely
      env {
        name  = "RECONCILIATION_SINGLE_SHOT"
        value = "false"
      }

      # KMS key for signature verification
      dynamic "env" {
        for_each = var.kms_governance_key != "" ? [1] : []
        content {
          name  = "KMS_GOVERNANCE_KEY"
          value = var.kms_governance_key
        }
      }
    }
  }

  depends_on = [google_storage_bucket.compliance_artifacts]
}

# ─── Cloud Run Jobs (Phase D - Requirement 10) ────────────────────────────────

# Lula Compliance Audit Job (CA-7)
resource "google_cloud_run_v2_job" "lula_audit" {
  name     = "cage-lula-audit-${var.environment}"
  location = var.region
  project  = var.project_id

  template {
    template {
      service_account = google_service_account.compliance_bridge.email

      timeout = "600s"  # 10 minutes

      vpc_access {
        network_interfaces {
          network    = google_compute_network.vpc.id
          subnetwork = google_compute_subnetwork.subnet.id
        }
        egress = "ALL_TRAFFIC"
      }

      containers {
        image = var.compliance_bridge_image != "" ? var.compliance_bridge_image : "gcr.io/${var.project_id}/cage-compliance-bridge:latest"

        resources {
          limits = {
            cpu    = "1"
            memory = "1Gi"
          }
        }

        env {
          name  = "ENVIRONMENT"
          value = var.environment
        }

        env {
          name  = "CAGE_DEPLOYMENT_REGION"
          value = var.cage_deployment_region
        }

        env {
          name  = "GCS_BUCKET"
          value = google_storage_bucket.compliance_artifacts.name
        }

        # Langfuse compliance credentials
        dynamic "env" {
          for_each = var.langfuse_compliance_public_key != "" ? [1] : []
          content {
            name = "LANGFUSE_COMPLIANCE_PUBLIC_KEY"
            value_source {
              secret_key_ref {
                secret  = google_secret_manager_secret.langfuse_compliance_public_key[0].secret_id
                version = "latest"
              }
            }
          }
        }

        dynamic "env" {
          for_each = var.langfuse_compliance_secret_key != "" ? [1] : []
          content {
            name = "LANGFUSE_COMPLIANCE_SECRET_KEY"
            value_source {
              secret_key_ref {
                secret  = google_secret_manager_secret.langfuse_compliance_secret_key[0].secret_id
                version = "latest"
              }
            }
          }
        }

        # Inline Python script executing compliance audit workflow
        command = ["python3", "-c"]
        args = [<<-PYTHON
          import asyncio, json, sys, time, yaml as _yaml
          sys.path.insert(0, "/app")

          from compliance_bridge.metrics import get_compliance_metrics
          from compliance_bridge.oscal_exporter import build_oscal_assessment_results, findings_from_metrics_dict
          from compliance_bridge.audit_workflow import run_audit_workflow

          SUPPORTED_CONTROLS = ["A.5.2", "A.5.3", "A.9.2", "SC-4"]
          AUDIT_ID = f"cloudrun-{int(time.time())}"

          print("🔍 Starting Lula ISO 42001 audit...")

          async def _main():
              controls_data = {}
              async def _fetch(cid):
                  try:
                      m = await asyncio.wait_for(get_compliance_metrics(cid, 24), timeout=8.0)
                      controls_data[cid] = m.model_dump()
                  except Exception as exc:
                      controls_data[cid] = {"error": str(exc)}

              await asyncio.wait_for(
                  asyncio.gather(*[_fetch(cid) for cid in SUPPORTED_CONTROLS]),
                  timeout=25.0,
              )
              return controls_data

          controls_data = asyncio.run(_main())
          findings = findings_from_metrics_dict(controls_data, AUDIT_ID)
          doc = build_oscal_assessment_results(findings=findings, audit_id=AUDIT_ID, window_hours=24)
          oscal_yaml = _yaml.dump(doc, default_flow_style=False, allow_unicode=True)
          result_lines = oscal_yaml.count("\n")
          print(f"✅ Lula audit complete. Result: oscal-assessment-{AUDIT_ID}.yaml ({result_lines} lines)")

          result = asyncio.run(run_audit_workflow(oscal_yaml=oscal_yaml, audit_id=AUDIT_ID))
          print(f"📊 Ingest result:")
          print(json.dumps(result, indent=2))

          if result.get("status") != "ok":
              print(f"❌ Ingest failed: {result}", file=sys.stderr)
              sys.exit(1)

          print("✅ OSCAL results ingested into Langfuse compliance project.")
        PYTHON
        ]
      }
    }
  }
}

# SBOM Generator Job (CM-8)
resource "google_cloud_run_v2_job" "sbom_generator" {
  name     = "cage-sbom-generator-${var.environment}"
  location = var.region
  project  = var.project_id

  template {
    template {
      service_account = google_service_account.compliance_bridge.email

      timeout = "3600s"  # 1 hour

      containers {
        image = "anchore/syft:v1.10.0"

        resources {
          limits = {
            cpu    = "1"
            memory = "2Gi"
          }
        }

        env {
          name  = "GCP_PROJECT_ID"
          value = var.project_id
        }

        env {
          name  = "SBOM_GCS_BUCKET"
          value = google_storage_bucket.compliance_artifacts.name
        }

        # Syft SBOM generation script
        command = ["/bin/sh", "-c"]
        args = [<<-SCRIPT
          set -euo pipefail
          echo "🔍 CAGE SBOM Generator starting — CM-8"
          DATE=$(date +%Y-%m-%d)
          RESULTS_DIR="/tmp/sbom-$${DATE}"
          mkdir -p "$${RESULTS_DIR}"

          # Image list to scan
          IMAGES="
            gcr.io/$${GCP_PROJECT_ID}/cage-gateway:latest
            gcr.io/$${GCP_PROJECT_ID}/cage-compliance-bridge:latest
            gcr.io/$${GCP_PROJECT_ID}/cage-governed-advisor:latest
            gcr.io/$${GCP_PROJECT_ID}/cage-agentsight-ui:latest
          "

          for IMAGE in $${IMAGES}; do
            echo "🔬 Scanning image: $${IMAGE}"
            SAFE_NAME=$(echo "$${IMAGE}" | tr '/:@' '---')
            SBOM_FILE="$${RESULTS_DIR}/$${SAFE_NAME}-$${DATE}.cdx.json"
            
            if syft "$${IMAGE}" -o cyclonedx-json --file "$${SBOM_FILE}" --quiet; then
              echo "  ✅ SBOM generated: $${SBOM_FILE}"
            else
              echo "  ⚠️  Syft scan failed for $${IMAGE}"
            fi
          done

          echo "📤 Uploading SBOMs to GCS: gs://$${SBOM_GCS_BUCKET}/sbom/$${DATE}/"
          if command -v gsutil > /dev/null 2>&1; then
            gsutil -m cp "$${RESULTS_DIR}/"*.json "gs://$${SBOM_GCS_BUCKET}/sbom/$${DATE}/" || echo "⚠️  GCS upload failed"
          else
            echo "⚠️  gsutil not found"
          fi
          echo "✅ SBOM generation complete"
        SCRIPT
        ]
      }
    }
  }
}

# Security Scan Job (RA-5)
resource "google_cloud_run_v2_job" "security_scan" {
  name     = "cage-security-scan-${var.environment}"
  location = var.region
  project  = var.project_id

  template {
    template {
      service_account = google_service_account.compliance_bridge.email

      timeout = "1800s"  # 30 minutes

      containers {
        image = "aquasec/trivy:0.51.4"

        resources {
          limits = {
            cpu    = "1"
            memory = "2Gi"
          }
        }

        env {
          name  = "GCP_PROJECT_ID"
          value = var.project_id
        }

        env {
          name  = "SCAN_GCS_BUCKET"
          value = google_storage_bucket.compliance_artifacts.name
        }

        # Trivy security scan script
        command = ["/bin/sh", "-c"]
        args = [<<-SCRIPT
          set -euo pipefail
          echo "🔍 CAGE Security Scanner starting — RA-5"
          DATE=$(date +%Y-%m-%d)
          RESULTS_DIR="/tmp/scan-$${DATE}"
          mkdir -p "$${RESULTS_DIR}"

          # Image list to scan
          IMAGES="
            gcr.io/$${GCP_PROJECT_ID}/cage-gateway:latest
            gcr.io/$${GCP_PROJECT_ID}/cage-compliance-bridge:latest
          "

          for IMAGE in $${IMAGES}; do
            echo "🔬 Scanning image: $${IMAGE}"
            SAFE_NAME=$(echo "$${IMAGE}" | tr '/:@' '---')
            SCAN_FILE="$${RESULTS_DIR}/$${SAFE_NAME}-$${DATE}.json"
            
            if trivy image --format json --output "$${SCAN_FILE}" "$${IMAGE}"; then
              echo "  ✅ Scan complete: $${SCAN_FILE}"
            else
              echo "  ⚠️  Trivy scan failed for $${IMAGE}"
            fi
          done

          echo "📤 Uploading scan results to GCS: gs://$${SCAN_GCS_BUCKET}/security-scans/$${DATE}/"
          if command -v gsutil > /dev/null 2>&1; then
            gsutil -m cp "$${RESULTS_DIR}/"*.json "gs://$${SCAN_GCS_BUCKET}/security-scans/$${DATE}/" || echo "⚠️  GCS upload failed"
          else
            echo "⚠️  gsutil not found"
          fi
          echo "✅ Security scan complete"
        SCRIPT
        ]
      }
    }
  }
}

# ─── Cloud Scheduler Jobs (Phase D - Requirement 10) ──────────────────────────

# Lula Audit Trigger (every 6 hours)
resource "google_cloud_scheduler_job" "lula_audit_trigger" {
  name             = "cage-lula-audit-trigger-${var.environment}"
  region           = var.region
  project          = var.project_id
  schedule         = "0 */6 * * *"
  time_zone        = "UTC"
  attempt_deadline = "600s"

  http_target {
    http_method = "POST"
    uri         = "https://${var.region}-run.googleapis.com/apis/run.googleapis.com/v1/namespaces/${var.project_id}/jobs/${google_cloud_run_v2_job.lula_audit.name}:run"

    oauth_token {
      service_account_email = google_service_account.compliance_bridge.email
    }
  }

  depends_on = [google_cloud_run_v2_job.lula_audit]
}

# SBOM Generator Trigger (daily at 02:00 UTC)
resource "google_cloud_scheduler_job" "sbom_trigger" {
  name             = "cage-sbom-trigger-${var.environment}"
  region           = var.region
  project          = var.project_id
  schedule         = "0 2 * * *"
  time_zone        = "UTC"
  attempt_deadline = "3600s"

  http_target {
    http_method = "POST"
    uri         = "https://${var.region}-run.googleapis.com/apis/run.googleapis.com/v1/namespaces/${var.project_id}/jobs/${google_cloud_run_v2_job.sbom_generator.name}:run"

    oauth_token {
      service_account_email = google_service_account.compliance_bridge.email
    }
  }

  depends_on = [google_cloud_run_v2_job.sbom_generator]
}

# Security Scan Trigger (weekly Sunday at 03:00 UTC)
resource "google_cloud_scheduler_job" "security_scan_trigger" {
  name             = "cage-security-scan-trigger-${var.environment}"
  region           = var.region
  project          = var.project_id
  schedule         = "0 3 * * 0"
  time_zone        = "UTC"
  attempt_deadline = "1800s"

  http_target {
    http_method = "POST"
    uri         = "https://${var.region}-run.googleapis.com/apis/run.googleapis.com/v1/namespaces/${var.project_id}/jobs/${google_cloud_run_v2_job.security_scan.name}:run"

    oauth_token {
      service_account_email = google_service_account.compliance_bridge.email
    }
  }

  depends_on = [google_cloud_run_v2_job.security_scan]
}

# ─── POAM-019 Telemetry Isolation (Phase D - Requirement 12) ──────────────────

resource "terraform_data" "poam_019_langfuse_isolation" {
  count = var.enable_nist_compliance ? 1 : 0

  lifecycle {
    precondition {
      condition = (
        var.langfuse_compliance_public_key != "" &&
        var.langfuse_compliance_secret_key != "" &&
        var.langfuse_compliance_public_key != var.langfuse_public_key &&
        var.langfuse_compliance_secret_key != var.langfuse_secret_key
      )
      error_message = <<-EOM
        POAM-019 telemetry isolation failure (AU-9):
        
        When enable_nist_compliance=true, compliance and application Langfuse
        credentials must be non-empty AND distinct.
        
        Current state:
          - langfuse_compliance_public_key: ${length(var.langfuse_compliance_public_key) > 0 ? "set" : "EMPTY"}
          - langfuse_compliance_secret_key: ${length(var.langfuse_compliance_secret_key) > 0 ? "set" : "EMPTY"}
          - Keys match application keys: ${var.langfuse_compliance_public_key == var.langfuse_public_key ? "YES (INVALID)" : "no"}
        
        Remediation:
          1. Provision a separate Langfuse project for compliance telemetry
          2. Set langfuse_compliance_public_key and langfuse_compliance_secret_key
             in terraform.auto.tfvars (gitignored)
          3. Ensure compliance keys differ from application keys
        
        Reference: docs/POAM.md POAM-019, NIST SP 800-53 AU-9
      EOM
    }
  }
}

# ─── IAM Policy for Public Access (Optional) ──────────────────────────────────

# Uncomment for public access in dev/staging environments
# resource "google_cloud_run_v2_service_iam_member" "gateway_public" {
#   count    = var.environment != "prod" ? 1 : 0
#   name     = google_cloud_run_v2_service.gateway.name
#   location = google_cloud_run_v2_service.gateway.location
#   role     = "roles/run.invoker"
#   member   = "allUsers"
#   project  = var.project_id
# }
