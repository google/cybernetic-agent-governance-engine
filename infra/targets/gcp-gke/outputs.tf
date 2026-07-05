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
  description = "Command to configure kubectl access"
  value       = "gcloud container clusters get-credentials ${module.gke.cluster_name} --zone=${var.zone} --project=${var.project_id}"
}

# ─── Deployment Summary ───────────────────────────────────────────────────────

output "deployment_summary" {
  description = "Deployment summary"
  value = {
    target                  = "gcp-gke"
    environment             = var.environment
    project_id              = var.project_id
    cluster_name            = module.gke.cluster_name
    namespace               = module.namespace.name
    nist_compliance_enabled = var.enable_nist_compliance
    gpu_node_pool_enabled   = var.enable_gpu_node_pool
    langfuse_bucket         = google_storage_bucket.langfuse_events.name
    postgres_service        = module.postgres.service_name
    redis_host              = module.redis.redis_host
    langfuse_url            = module.langfuse.web_url
    opa_endpoint            = module.opa.endpoint_url
  }
}

# ─── Database and Cache ───────────────────────────────────────────────────────

output "postgres_connection_string" {
  description = "PostgreSQL connection string"
  value       = module.postgres.connection_string
  sensitive   = true
}

output "postgres_service" {
  description = "PostgreSQL service FQDN"
  value       = module.postgres.service_name
}

output "redis_host" {
  description = "Redis host address"
  value       = module.redis.redis_host
}

output "redis_url" {
  description = "Redis connection URL"
  value       = module.redis.redis_url
  sensitive   = true
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
