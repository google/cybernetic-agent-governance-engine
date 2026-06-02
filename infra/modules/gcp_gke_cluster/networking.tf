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

resource "google_compute_router" "router" {

  name    = "nat-router-${var.region}"
  region  = var.region
  network = var.network
  project = var.project_id

  bgp {
    asn = 64514
  }
}

# ─── Cloud NAT ────────────────────────────────────────────────────────────────

resource "google_compute_router_nat" "nat" {
  name                               = "nat-config-${var.region}"
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
