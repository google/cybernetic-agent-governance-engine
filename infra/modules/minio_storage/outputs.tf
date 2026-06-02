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

output "endpoint" {
  description = "MinIO S3-compatible endpoint"
  value       = "http://${var.release_name}.${var.namespace}.svc.cluster.local:${var.service_port}"
}

output "console_endpoint" {
  description = "MinIO console endpoint"
  value       = "http://${var.release_name}.${var.namespace}.svc.cluster.local:${var.console_port}"
}

output "credentials_secret_name" {
  description = "Kubernetes secret name containing MinIO credentials"
  value       = kubernetes_secret.minio_credentials.metadata[0].name
}

output "access_key" {
  description = "MinIO access key (root user)"
  value       = var.root_user
}

output "secret_key" {
  description = "MinIO secret key (sensitive)"
  value       = local.minio_password
  sensitive   = true
}
