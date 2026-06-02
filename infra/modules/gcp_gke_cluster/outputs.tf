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
  value       = google_container_cluster.primary.master_auth[0].cluster_ca_certificate
  sensitive   = true
}

output "cluster_location" {
  description = "GKE cluster location (zone or region)"
  value       = google_container_cluster.primary.location
}

output "primary_node_pool_name" {
  description = "Primary node pool name"
  value       = google_container_node_pool.primary_nodes.name
}

output "gpu_node_pool_name" {
  description = "GPU node pool name (empty if disabled)"
  value       = var.enable_gpu_node_pool ? google_container_node_pool.gpu_nodes[0].name : ""
}

output "workload_identity_pool" {
  description = "Workload Identity pool for service account binding"
  value       = "${var.project_id}.svc.id.goog"
}
