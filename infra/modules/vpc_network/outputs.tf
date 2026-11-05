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

output "private_service_access_network_name" {
  description = "VPC network name gated on the Private Services Access peering connection for Cloud SQL"
  value       = var.enable_psa ? google_compute_network.vpc.name : null
  depends_on  = [google_service_networking_connection.private_service_access]
}

output "memorystore_psc_network_name" {
  description = "VPC network name gated on the Network Connectivity Service Connection Policy for Memorystore PSC"
  value       = var.enable_memorystore_psc ? google_compute_network.vpc.name : null
  depends_on  = [google_network_connectivity_service_connection_policy.memorystore]
}

output "pod_secondary_range_name" {
  description = "Pod secondary IP range name read back from google_compute_subnetwork.subnet"
  value       = one([for r in google_compute_subnetwork.subnet.secondary_ip_range : r.range_name if r.range_name == var.pod_range_name])
}

output "service_secondary_range_name" {
  description = "Service secondary IP range name read back from google_compute_subnetwork.subnet"
  value       = one([for r in google_compute_subnetwork.subnet.secondary_ip_range : r.range_name if r.range_name == var.service_range_name])
}

output "memorystore_service_connection_policy_id" {
  description = "ID of the Network Connectivity Service Connection Policy for Memorystore PSC"
  value       = one(google_network_connectivity_service_connection_policy.memorystore[*].id)
}

output "memorystore_service_connection_policy_network" {
  description = "Network URI on the Memorystore Service Connection Policy"
  value       = one(google_network_connectivity_service_connection_policy.memorystore[*].network)
}

output "memorystore_service_connection_policy_subnetworks" {
  description = "Subnetwork URIs on the Memorystore Service Connection Policy psc_config"
  value       = one([for m in google_network_connectivity_service_connection_policy.memorystore : m.psc_config[0].subnetworks])
}
