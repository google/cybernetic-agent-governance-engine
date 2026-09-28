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
  value       = module.gke.cluster_name
}

output "cluster_location" {
  description = "GKE cluster location"
  value       = module.gke.cluster_location
}

output "cluster_endpoint" {
  description = "GKE cluster API endpoint"
  value       = module.gke.cluster_endpoint
  sensitive   = true
}

output "workload_identity_pool" {
  description = "Workload Identity pool"
  value       = module.gke.workload_identity_pool
}

# ─── Namespace ────────────────────────────────────────────────────────────────

output "namespace" {
  description = "Kubernetes namespace"
  value       = module.namespace.name
}

# ─── Storage ──────────────────────────────────────────────────────────────────

output "worm_bucket_name" {
  description = "Retention-locked GCS WORM bucket name (system of record for compliance evidence)"
  value       = module.worm_bucket.bucket_name
}

output "worm_bucket_url" {
  description = "Retention-locked GCS WORM bucket gs:// URL"
  value       = module.worm_bucket.bucket_url
}

output "langfuse_events_bucket" {
  description = "GCS bucket for Langfuse event traces"
  value       = google_storage_bucket.langfuse_events.name
}

output "gcs_s3_endpoint" {
  description = "GCS S3-compatible endpoint for Langfuse"
  value       = "https://storage.googleapis.com"
}

output "gcs_bucket" {
  description = "GCS bucket for Langfuse events"
  value       = google_storage_bucket.langfuse_events.name
}

# ─── kubectl Access Command ───────────────────────────────────────────────────

output "kubectl_command" {
  description = "Command to configure kubectl access (uses --region for regional prod, --zone for zonal dev/staging)"
  value       = "gcloud container clusters get-credentials ${module.gke.cluster_name} ${module.gke.is_regional ? "--region=${var.region}" : "--zone=${var.zone}"} --project=${var.project_id}"
}

output "node_pools" {
  description = "Canonical 4-pool topology summary (§3)"
  value       = module.gke.node_pools
}

output "network_policy_spec_hash" {
  description = "SHA-256 hash of egress NetworkPolicy + FQDNNetworkPolicy specs (§5.3 rollout trigger)"
  value       = local.network_policy_spec_hash
}

# ─── Deployment Summary ───────────────────────────────────────────────────────

output "deployment_summary" {
  description = "Deployment summary"
  value = {
    target                  = "gcp-gke"
    environment             = var.environment
    project_id              = var.project_id
    cluster_name            = module.gke.cluster_name
    cluster_location        = module.gke.cluster_location
    is_regional             = module.gke.is_regional
    namespace               = module.namespace.name
    nist_compliance_enabled = var.enable_nist_compliance
    gpu_node_pool_enabled   = var.enable_gpu_node_pool
    worm_bucket             = module.worm_bucket.bucket_name
    langfuse_bucket         = google_storage_bucket.langfuse_events.name
    postgres_service        = module.cloudsql_postgres.instance_name
    redis_host              = module.memorystore_governance.primary_endpoint_ip
    memorystore_governance  = module.memorystore_governance.primary_endpoint_ip
    memorystore_app         = module.memorystore_app.primary_endpoint_ip
    clickhouse_service      = module.clickhouse_operator.service_name
    clickhouse_engine       = module.clickhouse_operator.table_engine
    langfuse_url            = module.langfuse.web_url
    opa_endpoint            = module.opa.endpoint_url
  }
}


# ─── Database and Cache ───────────────────────────────────────────────────────

output "cloudsql_postgres_instance_name" {
  description = "Cloud SQL PostgreSQL instance name"
  value       = module.cloudsql_postgres.instance_name
}

output "cloudsql_postgres_connection_name" {
  description = "Cloud SQL PostgreSQL connection name"
  value       = module.cloudsql_postgres.connection_name
}

output "cloudsql_postgres_private_ip" {
  description = "Cloud SQL PostgreSQL private IP address"
  value       = module.cloudsql_postgres.private_ip_address
}

output "postgres_service" {
  description = "PostgreSQL instance identifier"
  value       = module.cloudsql_postgres.instance_name
}

output "redis_host" {
  description = "Redis/Valkey governance primary endpoint host"
  value       = module.memorystore_governance.primary_endpoint_ip
}

output "redis_url" {
  description = "Redis/Valkey governance primary connection URL"
  value       = "redis://${module.memorystore_governance.primary_endpoint_ip}:${module.memorystore_governance.primary_endpoint_port}"
  sensitive   = false
}

output "memorystore_governance_host" {
  description = "Memorystore governance primary endpoint IP"
  value       = module.memorystore_governance.primary_endpoint_ip
}

output "memorystore_app_host" {
  description = "Memorystore app primary endpoint IP"
  value       = module.memorystore_app.primary_endpoint_ip
}

# ─── Inference and Observability ──────────────────────────────────────────────

output "vllm_endpoint" {
  description = "vLLM inference endpoint"
  value       = var.enable_vllm ? module.vllm[0].endpoint_url : "Not deployed"
}

output "langfuse_url" {
  description = "Langfuse web UI URL (internal)"
  value       = module.langfuse.web_url
}

output "langfuse_public_key" {
  description = "Langfuse API public key"
  value       = module.langfuse.public_key
  sensitive   = true
}

output "langfuse_secret_key" {
  description = "Langfuse API secret key"
  value       = module.langfuse.secret_key
  sensitive   = true
}

output "opa_endpoint" {
  description = "OPA policy engine endpoint"
  value       = module.opa.endpoint_url
}

# ─── Signing keys (POAM-2026-079) ─────────────────────────────────────────────
# Key version resource names for the manifest deployment path
# (deployment/k8s/): the gateway reads KMS_GOVERNANCE_KEY / RECONCILER_KMS_KEY
# from gateway-secrets. Never put them in advisor-secrets: the advisor loads it
# via envFrom and refuses to start with a signing-key variable set.

output "gateway_seal_key_version" {
  description = "gateway-seal key version (KMS_GOVERNANCE_KEY for the gateway)"
  value       = local.gateway_seal_key_version
}

output "reconciler_snapshot_key_version" {
  description = "reconciler-snapshot key version (RECONCILER_KMS_KEY for the reconciler and gateway)"
  value       = local.reconciler_snapshot_key_version
}

output "compliance_evidence_key_version" {
  description = "compliance-evidence key version (KMS_GOVERNANCE_KEY for the compliance bridge)"
  value       = local.compliance_evidence_key_version
}

output "benchmark_signing_key_version" {
  description = "benchmark-signing key version (KMS_GOVERNANCE_KEY for the benchmark job only; not a trust anchor)"
  value       = local.benchmark_signing_key_version
}
