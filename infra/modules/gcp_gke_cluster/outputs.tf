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

output "cluster_name" {
  description = "GKE cluster name"
  value       = google_container_cluster.primary.name
}

output "cluster_id" {
  description = "GKE cluster ID"
  value       = google_container_cluster.primary.id
}

output "cluster_endpoint" {
  description = "GKE cluster endpoint (IP address)"
  value       = google_container_cluster.primary.endpoint
  sensitive   = true
}

output "cluster_ca_certificate" {
  description = "GKE cluster CA certificate (base64 encoded)"
  value       = try(google_container_cluster.primary.master_auth[0].cluster_ca_certificate, "")
  sensitive   = true
}

output "cluster_location" {
  description = "GKE cluster location (zone or region)"
  value       = google_container_cluster.primary.location
}

output "is_regional" {
  description = "Whether the GKE cluster control plane is regional (true in prod, false in dev/staging)"
  value       = local.is_regional
}

output "primary_node_pool_name" {
  description = "Primary (general) node pool name"
  value       = google_container_node_pool.primary_nodes.name
}

output "general_spot_node_pool_name" {
  description = "General-spot node pool name (empty if disabled)"
  value       = local.enable_general_spot ? google_container_node_pool.general_spot_nodes[0].name : ""
}

output "gpu_node_pool_name" {
  description = "GPU node pool name (empty if disabled)"
  value       = var.enable_gpu_node_pool ? google_container_node_pool.gpu_nodes[0].name : ""
}

output "clickhouse_node_pool_name" {
  description = "ClickHouse node pool name (empty if disabled)"
  value       = var.enable_clickhouse_node_pool ? google_container_node_pool.clickhouse_nodes[0].name : ""
}

output "node_pools" {
  description = "Canonical 4-pool topology configuration (§3)"
  value       = local.node_pools
}

output "workload_identity_pool" {
  description = "Workload Identity pool for service account binding"
  value       = "${var.project_id}.svc.id.goog"
}

# AC-3 (POAM-2026-126, POAM-2026-174): the CIDRs the cluster's
# master_authorized_networks_config allows, as planned. Empty means no block, so
# GKE leaves the allowlist off; ["0.0.0.0/0"] is the non-compliance fallback.
output "master_authorized_cidrs" {
  description = "CIDR blocks in master_authorized_networks_config, as planned"
  value = flatten([
    for c in google_container_cluster.primary.master_authorized_networks_config :
    [for b in c.cidr_blocks : b.cidr_block]
  ])
}

output "node_service_account_email" {
  description = "Dedicated least-privilege Google Service Account email bound to all GKE node_config blocks (AC-6, POAM-2026-187)"
  value       = local.node_service_account_email
}

output "network" {
  description = "VPC network the GKE cluster is planned on"
  value       = google_container_cluster.primary.network
}

output "subnetwork" {
  description = "VPC subnetwork the GKE cluster is planned on"
  value       = google_container_cluster.primary.subnetwork
}

output "cluster_secondary_range_name" {
  description = "Secondary IP range name for GKE pods on google_container_cluster.primary"
  value       = google_container_cluster.primary.ip_allocation_policy[0].cluster_secondary_range_name
}

output "services_secondary_range_name" {
  description = "Secondary IP range name for GKE services on google_container_cluster.primary"
  value       = google_container_cluster.primary.ip_allocation_policy[0].services_secondary_range_name
}

output "cluster_ipv4_cidr_block" {
  description = "Pod IPv4 CIDR block on google_container_cluster.primary"
  value       = google_container_cluster.primary.ip_allocation_policy[0].cluster_ipv4_cidr_block
}

output "services_ipv4_cidr_block" {
  description = "Services IPv4 CIDR block on google_container_cluster.primary"
  value       = google_container_cluster.primary.ip_allocation_policy[0].services_ipv4_cidr_block
}

output "dataplane_v2_policy_logging_enabled" {
  description = "Whether GKE Dataplane V2 advanced datapath observability (`enable_metrics` + `enable_relay`) is configured on `google_container_cluster.primary` (D-195-4, R-5, F-87; note 500 connections/s per-node policy-action logging floor)"
  value = anytrue(flatten([
    for m in google_container_cluster.primary.monitoring_config : [
      for obs in m.advanced_datapath_observability_config :
      obs.enable_metrics && obs.enable_relay
    ]
  ]))
}
