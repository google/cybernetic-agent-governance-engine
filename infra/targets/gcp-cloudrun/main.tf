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
        container_port = 3000
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
