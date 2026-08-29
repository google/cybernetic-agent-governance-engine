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
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

# ─── GKE Cluster ──────────────────────────────────────────────────────────────

resource "google_container_cluster" "primary" {
  name     = var.cluster_name
  location = var.zone
  project  = var.project_id

  # Remove default node pool immediately (we'll create custom pools below)
  remove_default_node_pool = true
  initial_node_count       = 1

  # Network configuration
  network    = var.network
  subnetwork = var.subnetwork

  # Workload Identity for secure GCP service account binding
  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }

  # ─── SC-7: Boundary Protection ─────────────────────────────────────────────
  # POAM-024: deletion_protection now controlled independently of security compliance.
  # Allows staging (full security, ephemeral lifecycle) to be destroyed.
  # Prod: deletion_protection=true; dev/staging: deletion_protection=false
  deletion_protection = var.enable_deletion_protection

  # ─── SC-7: Private Cluster Configuration ───────────────────────────────────
  # Dev: Public nodes for easier access (unless org policy forces private nodes)
  # Prod: Private nodes with NAT for outbound traffic
  # enable_private_nodes can be set independently of enable_nist_compliance to
  # satisfy constraints/compute.vmExternalIpAccess org policy without activating
  # the full NIST compliance stack (Redis HA, PDB, audit logging, etc.).
  dynamic "private_cluster_config" {
    for_each = (var.enable_nist_compliance || var.enable_private_nodes) ? [1] : []
    content {
      enable_private_nodes    = true
      enable_private_endpoint = var.enable_private_master_endpoint
      master_ipv4_cidr_block  = var.master_ipv4_cidr_block
    }
  }

  # ─── AC-3: Master Authorized Networks ───────────────────────────────────────
  # Dev: Allow all (0.0.0.0/0)
  # Prod: Only corporate VPN or specific IPs
  dynamic "master_authorized_networks_config" {
    for_each = var.enable_nist_compliance && length(var.authorized_networks) > 0 ? [1] : []
    content {
      dynamic "cidr_blocks" {
        for_each = var.authorized_networks
        content {
          cidr_block   = cidr_blocks.value.cidr
          display_name = cidr_blocks.value.display_name
        }
      }
    }
  }

  # Fallback: Allow all for dev
  dynamic "master_authorized_networks_config" {
    for_each = !var.enable_nist_compliance ? [1] : []
    content {
      cidr_blocks {
        cidr_block   = "0.0.0.0/0"
        display_name = "All (Dev Only)"
      }
    }
  }

  # ─── CM-7: Binary Authorization ─────────────────────────────────────────────
  # Dev: Disabled for faster deployments
  # Prod: Only signed images allowed
  binary_authorization {
    evaluation_mode = var.enable_binary_authorization ? "PROJECT_SINGLETON_POLICY_ENFORCE" : "DISABLED"
  }

  # ─── SC-12, SC-13: Database Encryption (CMEK) ───────────────────────────────
  # Dev: Google-managed keys
  # Prod: Customer-managed KMS keys
  dynamic "database_encryption" {
    for_each = var.enable_cmek && var.kms_key_id != "" ? [1] : []
    content {
      state    = "ENCRYPTED"
      key_name = var.kms_key_id
    }
  }

  # Shielded nodes (always enabled for basic security)
  enable_shielded_nodes = true

  # Network policy support (always enabled)
  network_policy {
    enabled = true
  }

  # Addons
  addons_config {
    http_load_balancing {
      disabled = false
    }
    horizontal_pod_autoscaling {
      disabled = false
    }
    network_policy_config {
      disabled = false
    }
    # GCS Fuse CSI driver for GCS bucket mounting
    gcs_fuse_csi_driver_config {
      enabled = var.enable_gcs_fuse_csi
    }
    # GCE Persistent Disk CSI driver
    gce_persistent_disk_csi_driver_config {
      enabled = true
    }
  }

  # ─── AU-2, AU-3: Logging Configuration ─────────────────────────────────────
  # Dev: Minimal logging
  # Prod: Comprehensive audit logs
  dynamic "logging_config" {
    for_each = var.enable_audit_logging ? [1] : []
    content {
      enable_components = [
        "SYSTEM_COMPONENTS",
        "WORKLOADS",
        "API_SERVER",
        "SCHEDULER",
        "CONTROLLER_MANAGER"
      ]
    }
  }

  # ─── AU-9: Monitoring Configuration ─────────────────────────────────────────
  # Prod: Managed Prometheus for compliance metrics
  dynamic "monitoring_config" {
    for_each = var.enable_audit_logging ? [1] : []
    content {
      enable_components = [
        "SYSTEM_COMPONENTS",
        "WORKLOADS"
      ]
      managed_prometheus {
        enabled = true
      }
    }
  }

  # IP allocation for pods and services
  ip_allocation_policy {
    cluster_ipv4_cidr_block  = var.pod_cidr
    services_ipv4_cidr_block = var.service_cidr
  }

  # Maintenance window
  maintenance_policy {
    daily_maintenance_window {
      start_time = var.maintenance_start_time
    }
  }

  # Resource labels
  resource_labels = merge(
    {
      environment = var.environment
      managed-by  = "terraform"
      component   = "governance-engine"
    },
    var.cluster_labels
  )

  # Ensure default-pool creation complies with org policies before it's deleted
  node_config {
    shielded_instance_config {
      enable_secure_boot          = true
      enable_integrity_monitoring = true
    }
  }

  # Vertical pod autoscaling
  vertical_pod_autoscaling {
    enabled = var.enable_vertical_pod_autoscaling
  }

  lifecycle {
    ignore_changes = [
      node_version,
    ]
  }
}

# ─── Primary Node Pool (CPU workloads) ────────────────────────────────────────

resource "google_container_node_pool" "primary_nodes" {
  name     = "primary-node-pool"
  cluster  = google_container_cluster.primary.id
  location = var.zone

  # Autoscaling for cost optimization
  initial_node_count = var.primary_node_pool_initial_count

  autoscaling {
    min_node_count = var.primary_node_pool_min_count
    max_node_count = var.primary_node_pool_max_count
  }

  # Node configuration
  node_config {
    machine_type = var.primary_node_pool_machine_type
    disk_size_gb = var.primary_node_pool_disk_size
    disk_type    = var.primary_node_pool_disk_type

    # OAuth scopes for GCP service access
    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform",
    ]

    # Workload Identity
    workload_metadata_config {
      mode = "GKE_METADATA"
    }

    # Shielded instance features
    shielded_instance_config {
      enable_secure_boot          = true
      enable_integrity_monitoring = true
    }

    # Labels for workload scheduling
    labels = merge(
      {
        workload-type = "general"
        environment   = var.environment
      },
      var.primary_node_pool_labels
    )

    metadata = {
      disable-legacy-endpoints = "true"
    }
  }

  # Node management
  management {
    auto_repair  = true
    auto_upgrade = true
  }

  lifecycle {
    ignore_changes = [
      initial_node_count,
    ]
  }
}

# ─── GPU Node Pool (for vLLM) ─────────────────────────────────────────────────

resource "google_container_node_pool" "gpu_nodes" {
  count = var.enable_gpu_node_pool ? 1 : 0

  name     = "gpu-node-pool-${var.gpu_type}"
  cluster  = google_container_cluster.primary.id
  location       = var.zone
  node_locations = var.gpu_node_locations

  # GPU node pool sizing
  initial_node_count = var.gpu_node_pool_initial_count

  autoscaling {
    min_node_count = var.gpu_node_pool_min_count
    max_node_count = var.gpu_node_pool_max_count
  }

  # Node configuration with GPUs
  node_config {
    machine_type = var.gpu_node_pool_machine_type
    disk_size_gb = var.gpu_node_pool_disk_size
    disk_type    = var.gpu_node_pool_disk_type
    spot         = var.gpu_node_pool_spot

    # GPU accelerator
    guest_accelerator {
      type  = var.gpu_type
      count = var.gpu_count
      gpu_driver_installation_config {
        gpu_driver_version = "DEFAULT"
      }
    }

    # OAuth scopes
    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform",
    ]

    # Workload Identity
    workload_metadata_config {
      mode = "GKE_METADATA"
    }

    # Shielded instance features
    shielded_instance_config {
      enable_secure_boot          = true
      enable_integrity_monitoring = true
    }

    # Labels for GPU workload scheduling
    labels = merge(
      {
        workload-type    = "gpu"
        gpu-type         = var.gpu_type
        environment      = var.environment
        "nvidia.com/gpu" = "true"
      },
      var.gpu_node_pool_labels
    )

    metadata = {
      disable-legacy-endpoints = "true"
    }
  }

  # Node management
  management {
    auto_repair  = true
    auto_upgrade = true
  }

  lifecycle {
    ignore_changes = [
      initial_node_count,

      # node_locations is immutable on GKE node pools — any change forces
      # destroy+recreate, which would drain vllm-inference and vllm-reasoning
      # GPU workloads. GKE also auto-populates node_locations from the cluster
      # zone after creation, so the live value may differ from the config.
      node_locations,
    ]
  }

  # Ensure cluster is fully created before adding GPU node pool
  depends_on = [
    google_container_cluster.primary,
    google_container_node_pool.primary_nodes,
  ]
}

