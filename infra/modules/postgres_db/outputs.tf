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

output "release_name" {
  description = "Helm release name"
  value       = helm_release.postgresql.name
}

output "service_name" {
  description = "Kubernetes service name"
  value       = "${var.release_name}.${var.namespace}.svc.cluster.local"
}

output "connection_string" {
  description = "PostgreSQL connection string"
  value       = "postgresql://${var.database_user}:${random_password.db_password.result}@${var.release_name}.${var.namespace}.svc.cluster.local:5432/${var.database_name}"
  sensitive   = true
}

output "database_url_secret_name" {
  description = "Name of the Kubernetes Secret containing DATABASE_URL"
  value       = kubernetes_secret.db_credentials.metadata[0].name
}

output "database_name" {
  description = "PostgreSQL database name"
  value       = var.database_name
}

output "database_user" {
  description = "PostgreSQL database user"
  value       = var.database_user
}

output "password" {
  description = "Generated PostgreSQL password"
  value       = random_password.db_password.result
  sensitive   = true
}
