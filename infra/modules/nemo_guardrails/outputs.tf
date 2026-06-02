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

output "nemo_service_name" {
  description = "Kubernetes service name for NeMo Guardrails (port 8000)"
  value       = kubernetes_service.nemo_guardrails.metadata[0].name
}

output "nemo_url" {
  description = "In-cluster URL for the NeMo Guardrails API"
  value       = "http://${kubernetes_service.nemo_guardrails.metadata[0].name}.${var.namespace}.svc.cluster.local:8000"
}

output "presidio_analyzer_service_name" {
  description = "Kubernetes service name for Presidio Analyzer (port 5001)"
  value       = kubernetes_service.presidio_analyzer.metadata[0].name
}

output "presidio_analyzer_url" {
  description = "In-cluster URL for Presidio Analyzer"
  value       = "http://${kubernetes_service.presidio_analyzer.metadata[0].name}.${var.namespace}.svc.cluster.local:5001"
}

output "presidio_anonymizer_service_name" {
  description = "Kubernetes service name for Presidio Anonymizer (port 5002)"
  value       = kubernetes_service.presidio_anonymizer.metadata[0].name
}

output "presidio_anonymizer_url" {
  description = "In-cluster URL for Presidio Anonymizer"
  value       = "http://${kubernetes_service.presidio_anonymizer.metadata[0].name}.${var.namespace}.svc.cluster.local:5002"
}

output "deployment_name" {
  description = "Name of the NeMo Guardrails Kubernetes Deployment"
  value       = kubernetes_deployment.nemo_guardrails.metadata[0].name
}
