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

# ─── ClickHouse Password ──────────────────────────────────────────────────────

resource "random_password" "clickhouse_password" {
  length  = 32
  special = true
}

resource "google_secret_manager_secret" "clickhouse_password" {
  secret_id = "cage-clickhouse-password-${var.environment}"
  project   = var.project_id

  replication {
    auto {}
  }

  labels = {
    environment = var.environment
    managed-by  = "terraform"
  }
}

resource "google_secret_manager_secret_version" "clickhouse_password" {
  secret      = google_secret_manager_secret.clickhouse_password.id
  secret_data = random_password.clickhouse_password.result
}

# ─── ClickHouse Persistent Disk ───────────────────────────────────────────────

resource "google_compute_disk" "clickhouse_data" {
  name    = "cage-clickhouse-data-${var.environment}"
  type    = "pd-ssd"
  zone    = var.zone
  size    = var.clickhouse_disk_size_gb
  project = var.project_id

  # CMEK encryption when enabled (SC-13)
  dynamic "disk_encryption_key" {
    for_each = var.enable_cmek ? [1] : []
    content {
      kms_key_self_link = google_kms_crypto_key.cloudrun_cmek[0].id
    }
  }

  labels = {
    environment = var.environment
    workload    = "clickhouse-olap"
    managed-by  = "terraform"
  }
}

# ─── Daily Snapshot Policy (CA-7, CP-9) ───────────────────────────────────────

resource "google_compute_resource_policy" "clickhouse_snapshots" {
  name    = "cage-clickhouse-snapshots-${var.environment}"
  region  = var.region
  project = var.project_id

  snapshot_schedule_policy {
    schedule {
      daily_schedule {
        days_in_cycle = 1
        start_time    = "04:00" # 4 AM UTC (off-peak)
      }
    }

    retention_policy {
      max_retention_days    = var.environment == "prod" ? 30 : 7
      on_source_disk_delete = "KEEP_AUTO_SNAPSHOTS"
    }

    snapshot_properties {
      labels = {
        environment = var.environment
        managed-by  = "terraform"
        backup-type = "daily-automated"
      }
      storage_locations = [var.region]
    }
  }
}

resource "google_compute_disk_resource_policy_attachment" "clickhouse_data" {
  name    = google_compute_resource_policy.clickhouse_snapshots.name
  disk    = google_compute_disk.clickhouse_data.name
  zone    = var.zone
  project = var.project_id
}

# ─── ClickHouse Service Account (AC-3) ────────────────────────────────────────

resource "google_service_account" "clickhouse" {
  account_id   = "cage-clickhouse-${var.environment}"
  display_name = "CAGE ClickHouse GCE Service Account"
  project      = var.project_id
}

# Grant Secret Manager access for password retrieval
resource "google_secret_manager_secret_iam_member" "clickhouse_password_access" {
  secret_id = google_secret_manager_secret.clickhouse_password.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.clickhouse.email}"
}

# Grant logging permissions (AU-2)
resource "google_project_iam_member" "clickhouse_logging" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.clickhouse.email}"
}

# ─── Compute Engine Instance (SC-7: No External IP) ───────────────────────────

resource "google_compute_instance" "clickhouse" {
  name         = "cage-clickhouse-${var.environment}"
  machine_type = var.clickhouse_machine_type
  zone         = var.zone
  project      = var.project_id

  tags = ["cage-clickhouse-internal"]

  # Container-Optimized OS for minimal attack surface
  boot_disk {
    initialize_params {
      image = "cos-cloud/cos-stable"
      size  = 20
      type  = "pd-standard"
    }
  }

  # Attach persistent data disk
  attached_disk {
    source      = google_compute_disk.clickhouse_data.id
    device_name = "clickhouse-data"
    mode        = "READ_WRITE"
  }

  # CRITICAL: No access_config block → NO public IP (SC-7)
  network_interface {
    network    = google_compute_network.vpc.id
    subnetwork = google_compute_subnetwork.subnet.id
  }

  service_account {
    email  = google_service_account.clickhouse.email
    scopes = ["cloud-platform"]
  }

  # Startup script: Mount disk + launch ClickHouse
  metadata_startup_script = templatefile("${path.module}/scripts/clickhouse_startup.sh", {
    clickhouse_password = random_password.clickhouse_password.result
  })

  # Prevent accidental deletion in production
  deletion_protection = var.environment == "prod"

  # Automatic restart on failure
  scheduling {
    automatic_restart   = true
    on_host_maintenance = "MIGRATE"
    preemptible         = false
  }

  # Shielded VM (SI-7)
  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  depends_on = [
    google_compute_subnetwork.subnet,
    google_compute_disk.clickhouse_data
  ]
}

# ─── VPC Firewall Rule (SC-7: Internal-Only Access) ───────────────────────────

resource "google_compute_firewall" "allow_clickhouse_internal" {
  name    = "cage-allow-clickhouse-internal-${var.environment}"
  network = google_compute_network.vpc.name
  project = var.project_id

  allow {
    protocol = "tcp"
    ports    = ["8123", "9000"] # HTTP API + Native TCP
  }

  # Only allow traffic from VPC subnet (Cloud Run services)
  source_ranges = [var.subnet_cidr]
  target_tags   = ["cage-clickhouse-internal"]

  log_config {
    metadata = "INCLUDE_ALL_METADATA" # AU-2: Full audit logging
  }
}
