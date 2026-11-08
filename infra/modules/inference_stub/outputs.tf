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

output "service_name" {
  description = "Name of the inference stub ClusterIP Service."
  value       = kubernetes_service_v1.inference_stub.metadata[0].name
}

output "deployment_name" {
  description = "Name of the inference stub Deployment."
  value       = kubernetes_deployment_v1.inference_stub.metadata[0].name
}

output "endpoint_url" {
  description = "In-cluster OpenAI-compatible base URL (/v1) of the inference stub."
  value       = "http://${kubernetes_service_v1.inference_stub.metadata[0].name}.${var.namespace}.svc.cluster.local:${var.port}/v1"
}

output "pod_labels" {
  description = "Labels on the inference stub pods. The gcp-gke model-backend-ingress NetworkPolicy selects them by app, admitting only app = \"gateway\" on the service port."
  value       = kubernetes_deployment_v1.inference_stub.spec[0].template[0].metadata[0].labels
}

output "port" {
  description = "Container and Service TCP port serving /health and /v1/chat/completions."
  value       = var.port
}
