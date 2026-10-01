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
  description = "ClickHouse Kubernetes service name"
  value       = kubernetes_service.clickhouse.metadata[0].name
}

output "service_fqdn" {
  description = "ClickHouse Kubernetes service FQDN"
  value       = "${kubernetes_service.clickhouse.metadata[0].name}.${var.namespace}.svc.cluster.local"
}

output "http_port" {
  description = "ClickHouse HTTP interface port"
  value       = 8123
}

output "native_port" {
  description = "ClickHouse native TCP protocol port"
  value       = 9000
}

output "tcp_port" {
  description = "ClickHouse native TCP protocol port (alias for native_port)"
  value       = 9000
}

output "http_url" {
  description = "ClickHouse HTTP connection URL"
  value       = "http://${kubernetes_service.clickhouse.metadata[0].name}.${var.namespace}.svc.cluster.local:8123"
}

output "endpoint_url" {
  description = "ClickHouse HTTP endpoint URL"
  value       = "http://${kubernetes_service.clickhouse.metadata[0].name}.${var.namespace}.svc.cluster.local:8123"
}

output "native_url" {
  description = "ClickHouse native TCP connection URL"
  value       = "clickhouse://${kubernetes_service.clickhouse.metadata[0].name}.${var.namespace}.svc.cluster.local:9000"
}

output "password" {
  description = "Generated ClickHouse password"
  value       = random_password.clickhouse.result
  sensitive   = true
}

output "evidence_sink_username" {
  description = "Least-privilege ClickHouse user for the compliance-bridge evidence sink"
  value       = var.evidence_sink_username
}

output "evidence_sink_password_secret_name" {
  description = "Kubernetes Secret holding the evidence sink password (key: evidence_sink_password_secret_key)"
  value       = kubernetes_secret.evidence_sink.metadata[0].name
}

output "evidence_sink_password_secret_key" {
  description = "Key within evidence_sink_password_secret_name for the evidence sink password"
  value       = "CLICKHOUSE_PASSWORD"
}

output "replicas" {
  description = "Number of ClickHouse query-plane replicas (1 in dev/staging, 3 in prod)"
  value       = local.replicas
}


output "keeper_replicas" {
  description = "Number of ClickHouse Keeper coordination nodes (0 in dev/staging, 3 in prod)"
  value       = local.keeper_replicas
}

output "table_engine" {
  description = "ClickHouse table engine for evidence_stream (MergeTree in dev/staging, ReplicatedMergeTree in prod)"
  value       = local.table_engine
}

output "storage_policy" {
  description = "ClickHouse storage policy (default in dev/staging, hot_to_cold with GCS cold tier in prod)"
  value       = local.storage_policy
}
