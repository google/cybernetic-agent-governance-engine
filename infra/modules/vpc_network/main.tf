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
  network_name = var.network_name != "" ? var.network_name : "cage-vpc-${var.environment}"
  subnet_name  = var.subnetwork_name != "" ? var.subnetwork_name : "cage-subnet-${var.environment}"

  default_secondary_ranges = concat(
    var.pod_cidr != "" ? [{
      range_name    = "gke-pods"
      ip_cidr_range = var.pod_cidr
    }] : [],
    var.service_cidr != "" ? [{
      range_name    = "gke-services"
      ip_cidr_range = var.service_cidr
    }] : []
  )
  effective_secondary_ranges = length(var.secondary_ip_ranges) > 0 ? var.secondary_ip_ranges : local.default_secondary_ranges
}

# ─── VPC Network ──────────────────────────────────────────────────────────────

resource "google_compute_network" "vpc" {
  name                    = local.network_name
  auto_create_subnetworks = false
  project                 = var.project_id
}

# ─── Subnetwork (with GKE Pod/Service Secondary Ranges) ───────────────────────

resource "google_compute_subnetwork" "subnet" {
  name          = local.subnet_name
  ip_cidr_range = var.subnet_cidr
  region        = var.region
  network       = google_compute_network.vpc.id
  project       = var.project_id

  private_ip_google_access = true

  dynamic "secondary_ip_range" {
    for_each = local.effective_secondary_ranges
    content {
      range_name    = secondary_ip_range.value.range_name
      ip_cidr_range = secondary_ip_range.value.ip_cidr_range
    }
  }
}

# ─── Cloud Router & Cloud NAT ─────────────────────────────────────────────────

resource "google_compute_router" "router" {
  name    = "${local.network_name}-router"
  region  = var.region
  network = google_compute_network.vpc.id
  project = var.project_id
}

resource "google_compute_router_nat" "nat" {
  name                               = "${local.network_name}-nat"
  router                             = google_compute_router.router.name
  region                             = var.region
  project                            = var.project_id
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"

  log_config {
    enable = var.enable_audit_logging
    filter = var.enable_audit_logging ? "ALL" : "ERRORS_ONLY"
  }
}

# ─── VPC Firewall Rules (SC-7: Boundary Protection) ───────────────────────────

resource "google_compute_firewall" "default_deny_ingress" {
  count   = var.enable_default_deny ? 1 : 0
  name    = "${local.network_name}-default-deny-all-ingress"
  network = google_compute_network.vpc.id
  project = var.project_id

  deny {
    protocol = "all"
  }

  source_ranges = ["0.0.0.0/0"]
  priority      = 65534
  description   = "SC-7: Default deny all ingress traffic not explicitly allowed (fail-closed boundary protection)"

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_firewall" "allow_internal" {
  name    = "${local.network_name}-allow-internal"
  network = google_compute_network.vpc.id
  project = var.project_id

  allow {
    protocol = "all"
  }

  source_ranges = [var.subnet_cidr]
  priority      = 1000
  description   = "Allow internal traffic within the primary subnet"

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_firewall" "allow_https_egress" {
  name      = "${local.network_name}-allow-https-egress"
  network   = google_compute_network.vpc.id
  project   = var.project_id
  direction = "EGRESS"

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }

  destination_ranges = ["0.0.0.0/0"]
  priority           = 1000
  description        = "SC-7: Allow outbound HTTPS egress for external APIs, package registries, and KMS"

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

# ─── Private Services Access (PSA) Peering ───────────────────────────────────
# Required for Cloud SQL and Memorystore Redis Private IP peering via PSA.

resource "google_compute_global_address" "private_ip_alloc" {
  count         = var.enable_psa ? 1 : 0
  name          = "${local.network_name}-psa"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = var.psa_prefix_length
  network       = google_compute_network.vpc.id
  project       = var.project_id
}

resource "google_service_networking_connection" "private_service_access" {
  count                   = var.enable_psa ? 1 : 0
  network                 = google_compute_network.vpc.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_ip_alloc[0].name]
}
