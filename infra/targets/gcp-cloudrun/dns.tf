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

# ─── Cloud DNS Record Set Management ──────────────────────────────────────────
# Follows the decoupled lifecycle pattern: Cloud DNS managed zones represent
# persistent foundational infrastructure and should not be ephemeral resources
# created and destroyed with application workloads.
#
# This file manages only the ephemeral DNS record sets pointing to the external
# load balancer IP address.

# Fetch the persistently managed zone (prevents accidental deletion on `terraform destroy`)
data "google_dns_managed_zone" "zone" {
  count   = var.enable_cloud_dns && var.dns_zone_name != "" ? 1 : 0
  name    = var.dns_zone_name
  project = var.project_id
}

# Ephemeral DNS A record pointing gateway custom domain to external load balancer IP
resource "google_dns_record_set" "gateway" {
  count        = var.enable_cloud_dns && var.dns_zone_name != "" && var.enable_load_balancer ? 1 : 0
  name         = "gateway.${data.google_dns_managed_zone.zone[0].dns_name}"
  managed_zone = data.google_dns_managed_zone.zone[0].name
  type         = "A"
  ttl          = 300
  rrdatas      = [google_compute_global_address.gateway[0].address]
  project      = var.project_id
}
