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
      version = "~> 6.43"
    }
  }
}

locals {
  # §1.1: Regional cluster in prod, zonal in dev and staging.
  is_regional      = var.regional_cluster != null ? var.regional_cluster : (var.environment == "prod")
  cluster_location = local.is_regional ? var.region : var.zone

  # §3: general-spot pool (c3-highcpu-4, Spot, 0-5) enabled in staging only by default.
  enable_general_spot = var.enable_general_spot_node_pool != null ? var.enable_general_spot_node_pool : (var.environment == "staging")

  # §3: ClickHouse pool sizing: 1 node in dev/staging, 3 nodes in prod (Keeper colocated).
  clickhouse_min_count     = var.clickhouse_node_pool_min_count != null ? var.clickhouse_node_pool_min_count : (var.environment == "prod" ? 3 : 1)
  clickhouse_max_count     = var.clickhouse_node_pool_max_count != null ? var.clickhouse_node_pool_max_count : (var.environment == "prod" ? 3 : 1)
  clickhouse_initial_count = var.clickhouse_node_pool_initial_count != null ? var.clickhouse_node_pool_initial_count : (var.environment == "prod" ? 3 : 1)

  # §3: Canonical 4-pool topology specification (general, general-spot, gpu-l4, clickhouse).
  node_pools = [
    {
      name            = "general"
      machine_type    = var.primary_node_pool_machine_type
      min_count       = var.primary_node_pool_min_count
      max_count       = var.primary_node_pool_max_count
      initial_count   = var.primary_node_pool_initial_count
      spot            = false
      local_ssd_count = 0
      taint           = ""
      enabled         = true
    },
    {
      name            = "general-spot"
      machine_type    = var.general_spot_machine_type
      min_count       = var.general_spot_min_count
      max_count       = var.general_spot_max_count
      initial_count   = var.general_spot_initial_count
      spot            = true
      local_ssd_count = 0
      taint           = "cloud.google.com/gke-spot=true:NoSchedule"
      enabled         = local.enable_general_spot
    },
    {
      name            = "gpu-l4"
      machine_type    = var.gpu_node_pool_machine_type
      min_count       = var.gpu_node_pool_min_count
      max_count       = var.gpu_node_pool_max_count
      initial_count   = var.gpu_node_pool_initial_count
      spot            = false
      local_ssd_count = 0
      taint           = "nvidia.com/gpu=present:NoSchedule"
      enabled         = var.enable_gpu_node_pool
    },
    {
      name            = "clickhouse"
      machine_type    = var.clickhouse_node_pool_machine_type
      min_count       = local.clickhouse_min_count
      max_count       = local.clickhouse_max_count
      initial_count   = local.clickhouse_initial_count
      spot            = false
      local_ssd_count = var.clickhouse_node_pool_local_ssd_count
      taint           = "workload=clickhouse:NoSchedule"
      enabled         = var.enable_clickhouse_node_pool
    },
  ]
}

# ─── GKE Cluster ──────────────────────────────────────────────────────────────

resource "google_container_cluster" "primary" {
  name     = var.cluster_name
  location = local.cluster_location
  project  = var.project_id

  # Remove default node pool immediately (we'll create custom pools below)
  remove_default_node_pool = true
  initial_node_count       = 1

  # §5.3: FQDNNetworkPolicy prerequisites: GKE >= 1.27.1-gke.400 and release channel pinned
  min_master_version = var.min_master_version

  release_channel {
    channel = var.release_channel
  }

  # §5.3, §7: Only kube-dns (PROVIDER_UNSPECIFIED) or CLOUD_DNS allowed; custom CoreDNS is forbidden.
  dynamic "dns_config" {
    for_each = var.cluster_dns_provider == "CLOUD_DNS" ? [1] : []
    content {
      cluster_dns       = "CLOUD_DNS"
      cluster_dns_scope = "CLUSTER_SCOPE"
    }
  }

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
  # Staging / Prod: Only signed images allowed (§1.1, §5.4)
  binary_authorization {
    evaluation_mode = var.enable_binary_authorization ? "PROJECT_SINGLETON_POLICY_ENFORCE" : "DISABLED"
  }

  # ─── SC-12, SC-13: Database Encryption (CMEK) ───────────────────────────────
  # Dev: Google-managed keys
  # Staging / Prod: Customer-managed KMS keys (§1.1)
  dynamic "database_encryption" {
    for_each = var.enable_cmek && var.kms_key_id != "" ? [1] : []
    content {
      state    = "ENCRYPTED"
      key_name = var.kms_key_id
    }
  }

  # Shielded nodes (always enabled for basic security)
  enable_shielded_nodes = true

  # ─── CNI: Dataplane V2 (Cilium/eBPF) + FQDNNetworkPolicy (§1.1, §5.3, §7) ──
  # Dataplane V2 (Cilium/eBPF via anetd) is enabled at cluster creation in every
  # posture (dev, staging, prod) alongside FQDNNetworkPolicy enforcement.
  # Cannot coexist with network_policy (Calico); only one must be active.
  # Must be set at cluster creation — not hot-upgradeable.
  datapath_provider          = var.enable_dataplane_v2 ? "ADVANCED_DATAPATH" : "DATAPATH_PROVIDER_UNSPECIFIED"
  enable_fqdn_network_policy = var.enable_dataplane_v2 && var.enable_fqdn_network_policy

  # Legacy Calico addon — only when Dataplane V2 is disabled.
  # Disabled automatically when dataplane_v2_enabled=true (GKE removes it).
  network_policy {
    enabled  = !var.enable_dataplane_v2
    provider = var.enable_dataplane_v2 ? "PROVIDER_UNSPECIFIED" : "CALICO"
  }

  addons_config {
    http_load_balancing { disabled = false }
    horizontal_pod_autoscaling { disabled = false }
    network_policy_config {
      disabled = var.enable_dataplane_v2 # must be disabled when DPv2 is active
    }
    gcs_fuse_csi_driver_config { enabled = var.enable_gcs_fuse_csi }
    gce_persistent_disk_csi_driver_config { enabled = true }
  }

  # ─── AU-2, AU-3: Logging Configuration ─────────────────────────────────────
  # Dev: Minimal logging
  # Staging / Prod: Comprehensive audit logs
  dynamic "logging_config" {
    for_each = var.enable_audit_logging ? [1] : []
    content {
      enable_components = [
        "SYSTEM_COMPONENTS",
        "WORKLOADS",
        "APISERVER",
        "SCHEDULER",
        "CONTROLLER_MANAGER"
      ]
    }
  }

  # ─── AU-9: Monitoring Configuration ─────────────────────────────────────────
  # Staging / Prod: Managed Prometheus for compliance metrics
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
      database_encryption,
      master_authorized_networks_config,
      min_master_version,
      monitoring_config,
      resource_labels,
    ]
  }
}

# ─── Pool 1: General On-Demand Node Pool (§3: general) ────────────────────────
# Hosts gateway, advisor, OPA, NeMo, Langfuse, and reconciler workloads.

resource "google_container_node_pool" "primary_nodes" {
  name     = "primary-node-pool"
  cluster  = google_container_cluster.primary.id
  location = local.cluster_location

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
    spot         = false

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
        pool-name     = "general"
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

# ─── Pool 2: General-Spot Node Pool (§3: general-spot, staging only) ──────────
# c3-highcpu-4 Spot VMs (0-5 in staging), tainted cloud.google.com/gke-spot=true:NoSchedule.
# Stateless replicas and CI runs only; on-demand general pool acts as fallback.
# Governance-critical pods (gateway, reconciler) carry anti-Spot nodeAffinity (§3, §7).

resource "google_container_node_pool" "general_spot_nodes" {
  count = local.enable_general_spot ? 1 : 0

  name     = "general-spot"
  cluster  = google_container_cluster.primary.id
  location = local.cluster_location

  initial_node_count = var.general_spot_initial_count

  autoscaling {
    min_node_count = var.general_spot_min_count
    max_node_count = var.general_spot_max_count
  }

  node_config {
    machine_type = var.general_spot_machine_type
    disk_size_gb = 100
    disk_type    = "pd-balanced"
    spot         = true

    taint {
      key    = "cloud.google.com/gke-spot"
      value  = "true"
      effect = "NO_SCHEDULE"
    }

    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform",
    ]

    workload_metadata_config {
      mode = "GKE_METADATA"
    }

    shielded_instance_config {
      enable_secure_boot          = true
      enable_integrity_monitoring = true
    }

    labels = {
      workload-type              = "general-spot"
      pool-name                  = "general-spot"
      "cloud.google.com/gke-spot" = "true"
      environment                = var.environment
    }

    metadata = {
      disable-legacy-endpoints = "true"
    }
  }

  management {
    auto_repair  = true
    auto_upgrade = true
  }

  lifecycle {
    ignore_changes = [
      initial_node_count,
    ]
  }

  depends_on = [
    google_container_cluster.primary,
    google_container_node_pool.primary_nodes,
  ]
}

# ─── Pool 3: GPU Node Pool (§3: gpu-l4, for vLLM and vllm_reasoning) ─────────
# g2-standard-8, 1x nvidia-l4; 0-2 in dev/staging (scale to zero), 2-5 in prod.
# §3, §7: GPU Spot stays OFF in every posture so measurement runs are never preempted.

resource "google_container_node_pool" "gpu_nodes" {
  count = var.enable_gpu_node_pool ? 1 : 0

  name           = "gpu-node-pool-${var.gpu_type}"
  cluster        = google_container_cluster.primary.id
  location       = local.cluster_location
  node_locations = var.gpu_node_locations

  # GPU node pool sizing
  initial_node_count = var.gpu_node_pool_initial_count

  autoscaling {
    min_node_count  = var.gpu_node_pool_min_count
    max_node_count  = var.gpu_node_pool_max_count
    location_policy = "ANY"
  }

  # Node configuration with GPUs
  node_config {
    machine_type = var.gpu_node_pool_machine_type
    disk_size_gb = var.gpu_node_pool_disk_size
    disk_type    = var.gpu_node_pool_disk_type
    # §3, §7: GPU Spot stays off in every posture
    spot         = false

    # GPU accelerator
    guest_accelerator {
      type  = var.gpu_type
      count = var.gpu_count
      gpu_driver_installation_config {
        gpu_driver_version = "DEFAULT"
      }
    }

    taint {
      key    = "nvidia.com/gpu"
      value  = "present"
      effect = "NO_SCHEDULE"
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

    # GKE Image Streaming (Container File System API) for multi-GB vLLM images
    gcfs_config {
      enabled = true
    }

    # Labels for GPU workload scheduling
    labels = merge(
      {
        workload-type    = "gpu"
        pool-name        = "gpu-l4"
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

# ─── Pool 4: ClickHouse Node Pool (Local SSD, Tainted — §3, §7) ───────────────

resource "google_container_node_pool" "clickhouse_nodes" {
  count = var.enable_clickhouse_node_pool ? 1 : 0

  name     = "clickhouse-node-pool"
  cluster  = google_container_cluster.primary.id
  location = local.cluster_location

  initial_node_count = local.clickhouse_initial_count

  autoscaling {
    min_node_count = local.clickhouse_min_count
    max_node_count = local.clickhouse_max_count
  }

  node_config {
    machine_type = var.clickhouse_node_pool_machine_type
    disk_size_gb = 100
    disk_type    = "pd-ssd"
    # §7 Pitfalls: ClickHouse must NEVER run on Spot nodes
    spot = false

    # §1.1, §2.6, §3: Local NVMe SSD for ClickHouse hot parts
    local_nvme_ssd_block_config {
      local_ssd_count = var.clickhouse_node_pool_local_ssd_count
    }

    # §3, §7: Taint pool workload=clickhouse:NoSchedule so general workloads
    # never land on ClickHouse local-SSD nodes.
    taint {
      key    = "workload"
      value  = "clickhouse"
      effect = "NO_SCHEDULE"
    }

    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform",
    ]

    workload_metadata_config {
      mode = "GKE_METADATA"
    }

    shielded_instance_config {
      enable_secure_boot          = true
      enable_integrity_monitoring = true
    }

    labels = {
      workload      = "clickhouse"
      workload-type = "clickhouse"
      pool-name     = "clickhouse"
      environment   = var.environment
    }

    metadata = {
      disable-legacy-endpoints = "true"
    }
  }

  management {
    auto_repair  = true
    auto_upgrade = true
  }

  lifecycle {
    ignore_changes = [
      initial_node_count,
    ]
  }

  depends_on = [
    google_container_cluster.primary,
    google_container_node_pool.primary_nodes,
  ]
}

# ─── Additional Custom Node Pools (§3: var.node_pools list) ───────────────────

resource "google_container_node_pool" "extra_pools" {
  for_each = { for p in var.node_pools : p.name => p }

  name               = each.value.name
  cluster            = google_container_cluster.primary.id
  location           = local.cluster_location
  initial_node_count = each.value.initial_count

  autoscaling {
    min_node_count = each.value.min_count
    max_node_count = each.value.max_count
  }

  node_config {
    machine_type = each.value.machine_type
    disk_size_gb = each.value.disk_size_gb
    disk_type    = each.value.disk_type
    spot         = each.value.spot

    dynamic "local_nvme_ssd_block_config" {
      for_each = each.value.local_ssd_count > 0 ? [1] : []
      content {
        local_ssd_count = each.value.local_ssd_count
      }
    }

    dynamic "taint" {
      for_each = each.value.taints
      content {
        key    = taint.value.key
        value  = taint.value.value
        effect = taint.value.effect
      }
    }

    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform",
    ]

    workload_metadata_config {
      mode = "GKE_METADATA"
    }

    shielded_instance_config {
      enable_secure_boot          = true
      enable_integrity_monitoring = true
    }

    labels = merge(
      {
        pool-name   = each.value.name
        environment = var.environment
      },
      each.value.labels
    )

    metadata = {
      disable-legacy-endpoints = "true"
    }
  }

  management {
    auto_repair  = true
    auto_upgrade = true
  }

  depends_on = [
    google_container_cluster.primary,
    google_container_node_pool.primary_nodes,
  ]
}



