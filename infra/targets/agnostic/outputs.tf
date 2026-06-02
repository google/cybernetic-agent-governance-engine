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

output "namespace" {
  description = "Kubernetes namespace where resources are deployed"
  value       = module.namespace.name
}

output "minio_endpoint" {
  description = "MinIO S3-compatible API endpoint"
  value       = module.minio.endpoint
}

output "minio_console" {
  description = "MinIO web console endpoint"
  value       = module.minio.console_endpoint
}

output "minio_credentials_secret" {
  description = "Kubernetes secret containing MinIO access/secret keys"
  value       = module.minio.credentials_secret_name
}

output "deployment_summary" {
  description = "Deployment summary"
  value = {
    target      = "agnostic"
    environment = var.environment
    namespace   = module.namespace.name
    kubeconfig  = var.kubeconfig_path
    registry    = var.registry_url
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
}

output "langfuse_secret_key" {
  description = "Langfuse API secret key"
  value       = module.langfuse.secret_key
  sensitive   = true
}

# ─── Compliance and Policy ────────────────────────────────────────────────────

output "compliance_bridge_url" {
  description = "Compliance bridge endpoint"
  value       = var.enable_compliance_bridge ? module.compliance_bridge[0].endpoint_url : "Not deployed"
}

output "opa_endpoint" {
  description = "OPA policy engine endpoint"
  value       = module.opa.endpoint_url
}
