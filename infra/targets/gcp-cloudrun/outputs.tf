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

# ─── Cloud Run Service URLs ───────────────────────────────────────────────────

output "gateway_url" {
  description = "Gateway service URL"
  value       = google_cloud_run_v2_service.gateway.uri
}

output "governed_advisor_url" {
  description = "Governed Financial Advisor service URL"
  value       = google_cloud_run_v2_service.governed_advisor.uri
}

output "agentsight_ui_url" {
  description = "AgentSight UI service URL"
  value       = google_cloud_run_v2_service.agentsight_ui.uri
}

output "compliance_bridge_url" {
  description = "Compliance Bridge service URL"
  value       = google_cloud_run_v2_service.compliance_bridge.uri
}

output "langfuse_web_url" {
  description = "Langfuse Web service URL"
  value       = google_cloud_run_v2_service.langfuse_web.uri
}

output "langfuse_worker_url" {
  description = "Langfuse Worker service URL"
  value       = google_cloud_run_v2_service.langfuse_worker.uri
}

# ─── Database Connection Parameters ───────────────────────────────────────────

output "redis_host" {
  description = "Redis private IP address"
  value       = google_redis_instance.redis.host
  sensitive   = true
}

output "redis_port" {
  description = "Redis port"
  value       = google_redis_instance.redis.port
}

output "redis_connection_string" {
  description = "Redis connection string (private IP)"
  value       = "redis://${google_redis_instance.redis.host}:${google_redis_instance.redis.port}"
  sensitive   = true
}

output "postgres_connection_name" {
  description = "PostgreSQL Cloud SQL connection name"
  value       = google_sql_database_instance.postgres.connection_name
}

output "postgres_private_ip" {
  description = "PostgreSQL private IP address"
  value       = google_sql_database_instance.postgres.private_ip_address
  sensitive   = true
}

output "postgres_database_name" {
  description = "PostgreSQL database name for Langfuse"
  value       = google_sql_database.langfuse.name
}

output "postgres_user" {
  description = "PostgreSQL username"
  value       = google_sql_user.langfuse.name
}

# ─── ClickHouse OLAP Database ─────────────────────────────────────────────────

output "clickhouse_private_ip" {
  description = "ClickHouse private IP address"
  value       = google_compute_instance.clickhouse.network_interface[0].network_ip
  sensitive   = true
}

output "clickhouse_http_url" {
  description = "ClickHouse HTTP API URL (internal only)"
  value       = "http://${google_compute_instance.clickhouse.network_interface[0].network_ip}:8123"
  sensitive   = true
}

output "clickhouse_instance_name" {
  description = "ClickHouse GCE instance name"
  value       = google_compute_instance.clickhouse.name
}

# ─── vLLM GPU Inference Services ──────────────────────────────────────────────

output "vllm_fast_url" {
  description = "vLLM fast inference service URL (only when enable_vllm_gpu=true)"
  value       = var.enable_vllm_gpu ? google_cloud_run_v2_service.vllm_fast[0].uri : null
}

output "vllm_reasoning_url" {
  description = "vLLM reasoning service URL (only when enable_vllm_gpu=true)"
  value       = var.enable_vllm_gpu ? google_cloud_run_v2_service.vllm_reasoning[0].uri : null
}

# ─── Storage Resources ────────────────────────────────────────────────────────

output "langfuse_traces_bucket" {
  description = "GCS bucket name for Langfuse traces"
  value       = google_storage_bucket.langfuse_traces.name
}

output "compliance_artifacts_bucket" {
  description = "GCS bucket name for compliance artifacts"
  value       = google_storage_bucket.compliance_artifacts.name
}

# ─── Network Resources ────────────────────────────────────────────────────────

output "vpc_network_id" {
  description = "VPC network ID"
  value       = google_compute_network.vpc.id
}

output "vpc_network_name" {
  description = "VPC network name"
  value       = google_compute_network.vpc.name
}

output "subnet_id" {
  description = "Subnet ID"
  value       = google_compute_subnetwork.subnet.id
}

output "subnet_cidr" {
  description = "Subnet CIDR range"
  value       = google_compute_subnetwork.subnet.ip_cidr_range
}

# ─── Service Accounts ─────────────────────────────────────────────────────────

output "gateway_service_account_email" {
  description = "Gateway service account email"
  value       = google_service_account.gateway.email
}

output "governed_advisor_service_account_email" {
  description = "Governed Advisor service account email"
  value       = google_service_account.governed_advisor.email
}

output "langfuse_service_account_email" {
  description = "Langfuse service account email"
  value       = google_service_account.langfuse.email
}

# ─── Load Balancer & Cloud Armor ──────────────────────────────────────────────

output "load_balancer_ip" {
  description = "External load balancer static IP address (only when enable_load_balancer=true)"
  value       = var.enable_load_balancer ? google_compute_global_address.gateway[0].address : null
}

output "gateway_domain" {
  description = "Custom domain for gateway (from var.gateway_domain)"
  value       = var.gateway_domain
}

output "cloud_armor_policy_id" {
  description = "Cloud Armor security policy ID (only when enable_load_balancer=true)"
  value       = var.enable_load_balancer ? google_compute_security_policy.gateway_armor[0].id : null
}

output "gateway_dns_record" {
  description = "DNS record name configured in Cloud DNS (only when enable_cloud_dns=true)"
  value       = var.enable_cloud_dns && var.dns_zone_name != "" && var.enable_load_balancer ? google_dns_record_set.gateway[0].name : null
}

# ─── CMEK & Binary Authorization ──────────────────────────────────────────────

output "kms_key_ring_id" {
  description = "KMS key ring ID for CMEK (only when enable_cmek=true)"
  value       = var.enable_cmek ? google_kms_key_ring.cloudrun_keyring[0].id : null
}

output "kms_crypto_key_id" {
  description = "KMS crypto key ID for CMEK (only when enable_cmek=true)"
  value       = var.enable_cmek ? google_kms_crypto_key.cloudrun_cmek[0].id : null
}

output "binary_authorization_policy_id" {
  description = "Binary Authorization policy ID (only when enable_binary_authorization=true)"
  value       = var.enable_binary_authorization ? google_binary_authorization_policy.cloudrun_policy[0].id : null
}

output "attestor_name" {
  description = "Binary Authorization attestor name (only when enable_binary_authorization=true)"
  value       = var.enable_binary_authorization ? google_binary_authorization_attestor.cloudrun_attestor[0].name : null
}

# ─── Deployment Summary ───────────────────────────────────────────────────────

output "deployment_summary" {
  description = "Cloud Run deployment summary with complete stateful stack"
  value = <<-EOT

  ╔═══════════════════════════════════════════════════════════════════════════╗
  ║  CAGE Cloud Run Deployment Summary (${var.environment})
  ╚═══════════════════════════════════════════════════════════════════════════╝

  ┌─ Core Services ────────────────────────────────────────────────────────────┐
  │ Gateway:             ${google_cloud_run_v2_service.gateway.uri}
  │ Governed Advisor:    ${google_cloud_run_v2_service.governed_advisor.uri}
  │ AgentSight UI:       ${google_cloud_run_v2_service.agentsight_ui.uri}
  │ Compliance Bridge:   ${google_cloud_run_v2_service.compliance_bridge.uri}
  └────────────────────────────────────────────────────────────────────────────┘

  ┌─ Observability Stack ──────────────────────────────────────────────────────┐
  │ Langfuse Web:        ${google_cloud_run_v2_service.langfuse_web.uri}
  │ Langfuse Worker:     ${google_cloud_run_v2_service.langfuse_worker.uri}
  └────────────────────────────────────────────────────────────────────────────┘

  ┌─ Stateful Backend (Private VPC) ───────────────────────────────────────────┐
  │ PostgreSQL (OLTP):   ${google_sql_database_instance.postgres.private_ip_address}:5432
  │ Redis (Cache):       ${google_redis_instance.redis.host}:${google_redis_instance.redis.port}
  │ ClickHouse (OLAP):   ${google_compute_instance.clickhouse.network_interface[0].network_ip}:8123
  │                      ↳ Disk: ${google_compute_disk.clickhouse_data.name} (${var.clickhouse_disk_size_gb}GB pd-ssd)
  │                      ↳ Snapshots: Daily @ 04:00 UTC (${var.environment == "prod" ? "30-day" : "7-day"} retention)
  └────────────────────────────────────────────────────────────────────────────┘

  ┌─ GPU Inference (Serverless L4) ────────────────────────────────────────────┐
  ${var.enable_vllm_gpu ? "│ vLLM Fast (7B):      ${google_cloud_run_v2_service.vllm_fast[0].uri}" : "│ vLLM Fast:           DISABLED (set enable_vllm_gpu=true)"}
  ${var.enable_vllm_gpu ? "│ vLLM Reasoning (14B):${google_cloud_run_v2_service.vllm_reasoning[0].uri}" : "│ vLLM Reasoning:      DISABLED"}
  ${var.enable_vllm_gpu ? "│ Scaling: min=${var.environment == "prod" ? "1" : "0"}, max=3 (fast) / 2 (reasoning)" : ""}
  └────────────────────────────────────────────────────────────────────────────┘

  ┌─ Storage (GCS) ────────────────────────────────────────────────────────────┐
  │ Traces Bucket:       gs://${google_storage_bucket.langfuse_traces.name}
  │ Artifacts Bucket:    gs://${google_storage_bucket.compliance_artifacts.name}
  └────────────────────────────────────────────────────────────────────────────┘

  ${var.enable_load_balancer ? "┌─ External Access ─────────────────────────────────────────────────────────┐\n│ Load Balancer IP:    ${google_compute_global_address.gateway[0].address}\n${var.gateway_domain != "" ? "│ Custom Domain:       https://${var.gateway_domain}\n" : ""}└────────────────────────────────────────────────────────────────────────────┘\n" : ""}
  Next Steps:
    1. Verify PostgreSQL: gcloud sql connect ${google_sql_database_instance.postgres.name}
    2. Verify Redis: redis-cli -h ${google_redis_instance.redis.host} PING
    3. Verify ClickHouse: curl http://${google_compute_instance.clickhouse.network_interface[0].network_ip}:8123/ping
    4. Access Langfuse UI: ${google_cloud_run_v2_service.langfuse_web.uri}
    5. Submit test governance request to gateway
  ${var.enable_vllm_gpu ? "\n  GPU Services:\n    • Cold start latency: 3-5 min (7B), 5-8 min (14B)\n    • Scale-to-zero: ${var.environment == "prod" ? "DISABLED (min=1)" : "ENABLED (min=0)"}" : ""}

  EOT
}
