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
