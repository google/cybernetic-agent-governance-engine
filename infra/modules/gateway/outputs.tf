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
  description = "The name of the Gateway service"
  value       = kubernetes_service.gateway.metadata[0].name
}

output "deployment_name" {
  description = "The name of the Gateway deployment"
  value       = local.gateway_deployment_manifest.metadata.name
  depends_on  = [helm_release.gateway]
}

output "metrics_monitors_release_name" {
  description = "Helm release name managing PodMonitoring/gateway-metrics and optional ServiceMonitor (R-6, F-91)."
  value       = length(helm_release.metrics_monitors) > 0 ? helm_release.metrics_monitors[0].name : ""
}

output "opa_policies_config_map_name" {
  description = "Name of the OPA domain policies ConfigMap mounted into the gateway pod's OPA sidecar"
  value = one([
    for v in local.gateway_deployment_manifest.spec.template.spec.volumes :
    try(v.configMap.name, "")
    if v.name == "opa-policies"
  ])
}

output "opa_bundle_sha256" {
  description = "SHA-256 digest of the OPA bundle stamped on the gateway pod template"
  value       = var.opa_bundle_sha256
}

output "opa_uds_url" {
  description = "OPA_URL configured on the gateway container (in-pod Unix domain socket)"
  value = one([
    for e in local.gateway_deployment_manifest.spec.template.spec.containers[0].env :
    try(e.value, "")
    if e.name == "OPA_URL"
  ])
}

output "opa_sidecar_policy_files" {
  description = "Domain Rego policy files mounted into the gateway OPA UDS sidecar via opa-policies (POAM-2026-198)"
  value       = var.opa_policy_files
}

output "evidence_previous_chain_head_hash" {
  description = "EVIDENCE_PREVIOUS_CHAIN_HEAD_HASH configured on the gateway container for bound genesis rotation (F-94 / R-10)"
  value = one([
    for e in local.gateway_deployment_manifest.spec.template.spec.containers[0].env :
    try(e.value, "")
    if e.name == "EVIDENCE_PREVIOUS_CHAIN_HEAD_HASH"
  ])
}

output "evidence_previous_batch_attestation_digest" {
  description = "EVIDENCE_PREVIOUS_BATCH_ATTESTATION_DIGEST configured on the gateway container for bound genesis rotation (F-94 / R-10)"
  value = one([
    for e in local.gateway_deployment_manifest.spec.template.spec.containers[0].env :
    try(e.value, "")
    if e.name == "EVIDENCE_PREVIOUS_BATCH_ATTESTATION_DIGEST"
  ])
}
