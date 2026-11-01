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

output "id" {
  description = "Memorystore Valkey instance ID"
  value       = google_memorystore_instance.instance.id
}

output "instance_id" {
  description = "Memorystore Valkey instance resource ID"
  value       = google_memorystore_instance.instance.instance_id
}

# Pitfall guard: The module exports only the primary endpoint to consumers.
# Read-replica endpoints are never exported.
output "primary_endpoint_ip" {
  description = "Primary endpoint IP address via PSC"
  value       = try(google_memorystore_instance.instance.endpoints[0].connections[0].psc_auto_connection[0].ip_address, null)
}

output "primary_endpoint_port" {
  description = "Primary endpoint port via PSC"
  value       = try(google_memorystore_instance.instance.endpoints[0].connections[0].psc_auto_connection[0].port, 6379)
}

output "endpoints" {
  description = "Primary endpoint connection block (primary only)"
  value       = try(google_memorystore_instance.instance.endpoints[0], null)
}

output "managed_server_ca" {
  description = "Managed server Certificate Authority certificates for TLS pinning"
  value       = try(google_memorystore_instance.instance.managed_server_ca[0].ca_certs[0].certificates, [])
}

output "replica_count" {
  description = "Number of replica nodes configured on this instance"
  value       = google_memorystore_instance.instance.replica_count
}

# POAM-2026-156 item 3: the persistence the instance is planned with, read back
# from the resource rather than from the inputs, so a test of these outputs
# checks what the provider is asked to configure.
output "persistence_mode" {
  description = "Persistence mode the instance is planned with: DISABLED or AOF"
  value       = one(google_memorystore_instance.instance.persistence_config[*].mode)
}

output "aof_append_fsync" {
  description = "AOF fsync policy the instance is planned with, or null unless persistence_mode is AOF"
  value = one(flatten([
    for p in google_memorystore_instance.instance.persistence_config :
    p.mode == "AOF" ? [for a in p.aof_config : a.append_fsync] : []
  ]))
}
