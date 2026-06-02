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
  value       = helm_release.redis.name
}

output "service_name" {
  description = "Kubernetes service name"
  value       = var.enable_sentinel ? "${var.release_name}.${var.namespace}.svc.cluster.local" : "${var.release_name}-master.${var.namespace}.svc.cluster.local"
}

output "redis_host" {
  description = "Redis host address"
  value       = var.enable_sentinel ? "${var.release_name}.${var.namespace}.svc.cluster.local" : "${var.release_name}-master.${var.namespace}.svc.cluster.local"
}

output "redis_port" {
  description = "Redis port"
  value       = 6379
}

output "redis_url" {
  description = "Redis connection URL"
  value       = "redis://:${var.password != "" ? var.password : random_password.redis_password.result}@${var.enable_sentinel ? var.release_name : "${var.release_name}-master"}.${var.namespace}.svc.cluster.local:6379"
  sensitive   = true
}

output "password" {
  description = "Redis password"
  value       = var.password != "" ? var.password : random_password.redis_password.result
  sensitive   = true
}

output "credentials_secret_name" {
  description = "Name of the Kubernetes Secret containing credentials"
  value       = var.create_credentials_secret ? kubernetes_secret.redis_credentials[0].metadata[0].name : ""
}
