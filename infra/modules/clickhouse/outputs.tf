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

output "service_name" {
  description = "ClickHouse service name"
  value       = "${kubernetes_service.clickhouse.metadata[0].name}.${var.namespace}.svc.cluster.local"
}

output "http_port" {
  description = "ClickHouse HTTP port"
  value       = 8123
}

output "tcp_port" {
  description = "ClickHouse TCP port"
  value       = 9000
}

output "password" {
  description = "ClickHouse password (sensitive)"
  value       = random_password.clickhouse_password.result
  sensitive   = true
}

output "connection_string" {
  description = "ClickHouse connection string for Langfuse"
  value       = "http://default:${random_password.clickhouse_password.result}@${kubernetes_service.clickhouse.metadata[0].name}.${var.namespace}.svc.cluster.local:8123"
  sensitive   = true
}
