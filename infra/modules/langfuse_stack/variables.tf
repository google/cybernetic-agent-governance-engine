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

variable "namespace" {
  description = "Kubernetes namespace to deploy Langfuse"
  type        = string
}

variable "langfuse_image" {
  description = "Langfuse container image"
  type        = string
  default     = "langfuse/langfuse:3"
}

variable "langfuse_worker_image" {
  description = "Langfuse worker container image"
  type        = string
  default     = "langfuse/langfuse-worker:3"
}

variable "database_url" {
  description = "PostgreSQL database URL"
  type        = string
  sensitive   = true
}

variable "clickhouse_url" {
  description = "ClickHouse database URL (required for Langfuse v3)"
  type        = string
  sensitive   = true
  default     = ""
}

variable "clickhouse_migration_url" {
  description = "ClickHouse database migration URL (required for Langfuse v3 golang-migrate)"
  type        = string
  sensitive   = true
  default     = ""
}

variable "clickhouse_user" {
  description = "ClickHouse user"
  type        = string
  default     = "default"
}

variable "clickhouse_password" {
  description = "ClickHouse password"
  type        = string
  sensitive   = true
  default     = ""
}

variable "redis_connection_string" {
  description = "Redis connection string (required for Langfuse v3 queuing/caching)"
  type        = string
  sensitive   = true
  default     = ""
}

variable "redis_host" {
  description = "Redis host"
  type        = string
  default     = ""
}

variable "redis_port" {
  description = "Redis port"
  type        = string
  default     = "6379"
}

variable "s3_endpoint" {
  description = "S3-compatible endpoint for blob storage (MinIO or GCS)"
  type        = string
  default     = ""
}

variable "s3_bucket" {
  description = "S3 bucket name for Langfuse event storage"
  type        = string
  default     = ""
}

variable "s3_access_key" {
  description = "S3 access key"
  type        = string
  sensitive   = true
  default     = ""
}

variable "s3_secret_key" {
  description = "S3 secret key"
  type        = string
  sensitive   = true
  default     = ""
}

variable "s3_region" {
  description = "S3 region"
  type        = string
  default     = "us-east-1"
}

variable "nextauth_url" {
  description = "NextAuth URL (external URL of Langfuse)"
  type        = string
  default     = "http://localhost:3000"
}

variable "web_replicas" {
  description = "Number of web replicas"
  type        = number
  default     = 2
}

variable "worker_replicas" {
  description = "Number of worker replicas"
  type        = number
  default     = 1
}

variable "service_type" {
  description = "Kubernetes service type"
  type        = string
  default     = "ClusterIP"
}

variable "web_memory_request" {
  description = "Web memory request"
  type        = string
  default     = "512Mi"
}

variable "web_cpu_request" {
  description = "Web CPU request"
  type        = string
  default     = "100m"
}

variable "web_memory_limit" {
  description = "Web memory limit"
  type        = string
  default     = "2Gi"
}

variable "web_cpu_limit" {
  description = "Web CPU limit"
  type        = string
  default     = "1000m"
}

variable "worker_memory_request" {
  description = "Worker memory request"
  type        = string
  default     = "512Mi"
}

variable "worker_cpu_request" {
  description = "Worker CPU request"
  type        = string
  default     = "100m"
}

variable "worker_memory_limit" {
  description = "Worker memory limit"
  type        = string
  default     = "2Gi"
}

variable "worker_cpu_limit" {
  description = "Worker CPU limit"
  type        = string
  default     = "1000m"
}

variable "langfuse_public_key" {
  description = "Pre-existing Langfuse public key (optional)"
  type        = string
  sensitive   = true
  default     = ""
}

variable "langfuse_secret_key" {
  description = "Pre-existing Langfuse secret key (optional)"
  type        = string
  sensitive   = true
  default     = ""
}

variable "langfuse_init_user_email" {
  description = "Initial user email for headless setup"
  type        = string
  default     = ""
}

variable "langfuse_init_user_password" {
  description = "Initial user password for headless setup"
  type        = string
  sensitive   = true
  default     = ""
}

variable "langfuse_init_project_name" {
  description = "Initial project name for headless setup"
  type        = string
  default     = ""
}

variable "langfuse_init_org_id" {
  description = "Initial organization ID for headless setup"
  type        = string
  default     = ""
}

variable "langfuse_init_org_name" {
  description = "Initial organization name for headless setup"
  type        = string
  default     = ""
}

variable "langfuse_init_project_id" {
  description = "Initial project ID for headless setup"
  type        = string
  default     = ""
}
