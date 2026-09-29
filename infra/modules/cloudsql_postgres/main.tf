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
  }
}

locals {
  instance_name = var.instance_name != "" ? var.instance_name : "cage-postgres-${var.environment}"
  network_link  = can(regex("^projects/", var.authorized_network)) ? var.authorized_network : "projects/${var.project_id}/global/networks/${var.authorized_network}"
}

resource "google_sql_database_instance" "postgres" {
  name             = local.instance_name
  database_version = var.database_version
  region           = var.region
  project          = var.project_id

  encryption_key_name = var.enable_cmek ? var.kms_key_id : null

  settings {
    tier              = var.tier
    availability_type = var.enable_high_availability ? "REGIONAL" : "ZONAL"
    disk_size         = var.disk_size
    disk_type         = "PD_SSD"

    backup_configuration {
      enabled                        = true
      start_time                     = "02:00"
      point_in_time_recovery_enabled = var.enable_point_in_time_recovery || var.enable_high_availability
      transaction_log_retention_days = 7
      backup_retention_settings {
        retained_backups = 7
        retention_unit   = "COUNT"
      }
    }

    ip_configuration {
      ipv4_enabled    = false
      private_network = local.network_link
      ssl_mode        = "ENCRYPTED_ONLY"
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

    dynamic "database_flags" {
      for_each = var.enable_iam_auth ? [1] : []
      content {
        name  = "cloudsql.iam_authentication"
        value = "on"
      }
    }
  }

  deletion_protection = var.deletion_protection
}

resource "google_sql_database" "db" {
  name     = var.database_name
  instance = google_sql_database_instance.postgres.name
  project  = var.project_id
}

locals {
  # For PostgreSQL, Cloud SQL IAM Service Account users must NOT have the .gserviceaccount.com suffix.
  effective_user_name = var.user_type == "CLOUD_IAM_SERVICE_ACCOUNT" ? trimsuffix(var.user_name, ".gserviceaccount.com") : var.user_name
}

resource "google_sql_user" "db_user" {
  name     = local.effective_user_name
  instance = google_sql_database_instance.postgres.name
  password = var.user_type == "BUILT_IN" ? var.user_password : null
  type     = var.user_type
  project  = var.project_id
}
