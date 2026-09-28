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

output "network_id" {
  description = "VPC network ID"
  value       = google_compute_network.vpc.id
}

output "network_name" {
  description = "VPC network name"
  value       = google_compute_network.vpc.name
}

output "network_self_link" {
  description = "VPC network self link"
  value       = google_compute_network.vpc.self_link
}

output "subnetwork_id" {
  description = "Subnetwork ID"
  value       = google_compute_subnetwork.subnet.id
}

output "subnetwork_name" {
  description = "Subnetwork name"
  value       = google_compute_subnetwork.subnet.name
}

output "subnetwork_self_link" {
  description = "Subnetwork self link"
  value       = google_compute_subnetwork.subnet.self_link
}

output "subnetwork_cidr" {
  description = "Subnetwork CIDR block"
  value       = google_compute_subnetwork.subnet.ip_cidr_range
}

output "secondary_ip_ranges" {
  description = "Configured secondary IP ranges on the subnet"
  value       = google_compute_subnetwork.subnet.secondary_ip_range
}

output "router_name" {
  description = "Cloud Router name"
  value       = google_compute_router.router.name
}

output "private_service_access_id" {
  description = "ID of the Private Services Access peering connection"
  value       = try(google_service_networking_connection.private_service_access[0].id, null)
}

output "psa_address_name" {
  description = "Name of the global reserved address for PSA"
  value       = try(google_compute_global_address.private_ip_alloc[0].name, null)
}
