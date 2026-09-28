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
  description = "Memorystore Redis instance ID"
  value       = google_redis_instance.redis.id
}

output "host" {
  description = "Memorystore Redis primary host IP"
  value       = google_redis_instance.redis.host
}

output "port" {
  description = "Memorystore Redis primary port"
  value       = google_redis_instance.redis.port
}

output "current_location_id" {
  description = "Current zone hosting the primary Redis node"
  value       = google_redis_instance.redis.current_location_id
}

output "auth_string" {
  description = "Redis AUTH password"
  value       = google_redis_instance.redis.auth_string
  sensitive   = true
}

output "server_ca_certs" {
  description = "List of server CA certificates for TLS verification"
  value       = google_redis_instance.redis.server_ca_certs
}
