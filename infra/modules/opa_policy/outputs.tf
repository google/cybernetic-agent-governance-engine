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

output "policies_config_map_name" {
  description = "Name of the read-only OPA domain policies ConfigMap mounted by the gateway sidecar"
  value       = var.create_policy_configmap ? kubernetes_config_map.opa_policies[0].metadata[0].name : ""
}

output "system_authz_config_map_name" {
  description = "Name of the OPA system.authz ConfigMap locking the policy/data store at runtime (R-15)"
  value       = kubernetes_config_map.opa_system_authz.metadata[0].name
}

output "config_config_map_name" {
  description = "Name of the OPA runtime configuration ConfigMap (decision_logs.console = true, F-102)"
  value       = var.create_config_configmap ? kubernetes_config_map.opa_config[0].metadata[0].name : ""
}

output "uds_socket_path" {
  description = "In-pod Unix domain socket path where the gateway's OPA sidecar listens"
  value       = local.uds_socket_path
}

output "uds_url" {
  description = "Gateway OPA_URL connecting over the shared in-pod Unix domain socket"
  value       = local.uds_url
}

output "bundle_sha256" {
  description = "SHA-256 digest of rendered policy, system.authz, and config ConfigMaps to trigger gateway pod rollout on change"
  value       = local.bundle_sha256
}

output "policy_files_data" {
  description = "Mounted OPA policy files map in the opa-policies ConfigMap"
  value       = var.create_policy_configmap ? kubernetes_config_map.opa_policies[0].data : {}
}
