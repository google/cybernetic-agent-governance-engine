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

output "web_service_name" {
  description = "Langfuse web service name"
  value       = kubernetes_service.langfuse_web.metadata[0].name
}

output "web_service_fqdn" {
  description = "Langfuse web service FQDN"
  value       = "${kubernetes_service.langfuse_web.metadata[0].name}.${var.namespace}.svc.cluster.local"
}

output "web_url" {
  description = "Langfuse web URL (internal)"
  value       = "http://${kubernetes_service.langfuse_web.metadata[0].name}.${var.namespace}.svc.cluster.local:3000"
}

output "public_key" {
  description = "Langfuse public key"
  value       = random_id.public_key.hex
  sensitive   = true
}

output "secret_key" {
  description = "Langfuse secret key"
  value       = random_id.secret_key.hex
  sensitive   = true
}

output "secrets_name" {
  description = "Kubernetes Secret name containing Langfuse keys"
  value       = kubernetes_secret.langfuse_secrets.metadata[0].name
}

output "nextauth_secret" {
  description = "NextAuth secret"
  value       = random_id.nextauth_secret.hex
  sensitive   = true
}
