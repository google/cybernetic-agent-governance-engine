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

output "deployment_name" {
  description = "Name of the vLLM deployment"
  value       = kubernetes_deployment.vllm.metadata[0].name
}

output "service_name" {
  description = "Name of the vLLM service"
  value       = kubernetes_service.vllm.metadata[0].name
}

output "service_fqdn" {
  description = "Fully qualified domain name of the service"
  value       = "${kubernetes_service.vllm.metadata[0].name}.${var.namespace}.svc.cluster.local"
}

output "endpoint_url" {
  description = "vLLM endpoint URL"
  value       = "http://${kubernetes_service.vllm.metadata[0].name}.${var.namespace}.svc.cluster.local:8000"
}

output "health_check_url" {
  description = "Health check URL"
  value       = "http://${kubernetes_service.vllm.metadata[0].name}.${var.namespace}.svc.cluster.local:8000/health"
}

output "model_path" {
  description = "Configured model path"
  value       = var.model_path
}

output "replicas" {
  description = "Number of replicas configured"
  value       = var.replicas
}
