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

# ─── Per-Workload Linkerd Authorization Policies (POAM-2026-080, POAM-2026-195) ─
# Complements `infra/modules/gateway/mesh-policy/` (which enforces deny-by-default
# on gateway HTTP 8080) by installing Linkerd `Server`, `HTTPRoute`,
# `MeshTLSAuthentication`, and `AuthorizationPolicy` resources in Terraform state
# for every remaining workload port in `governance-stack` (`F-17`, `F-19`, `R-16`,
# `F-103`). Installed via a local Helm chart so `terraform plan` and
# `terraform test` succeed before Linkerd installs `policy.linkerd.io` CRDs on a
# fresh cluster.
#
# Identity matrix (verified SPIFFE `l5d-client-id` identities derived 1:1 from
# `kubernetes_service_account.workload` and `module.service_mesh.identity_suffix`):
#   - `model-backend-http` (8000):      `cage-gateway-sa` ONLY (`R-16`, `F-103`)
#   - `compliance-bridge-http` (3001):  segmented L7 HTTPRoutes in `infra/modules/compliance_bridge/mesh-policy/`
#   - `gateway-grpc` (50051):           `cage-advisor-sa` ONLY; `9090` `GET /metrics`
#   - `clickhouse-http` (8123):         `cage-compliance-bridge-sa`, `langfuse-sa`, `cage-clickhouse-sa`
#   - `clickhouse-tcp` (9000):          `langfuse-sa`, `cage-clickhouse-sa` (bridge barred)
#   - `clickhouse-interserver` (9009):  `cage-clickhouse-sa` ONLY
#   - `clickhouse-keeper` (9181/9234):  `cage-clickhouse-sa` + `cage-clickhouse-keeper-sa` / keeper-only raft
#   - `langfuse-web-http` (3000):       `cage-gateway-sa`, `cage-compliance-bridge-sa`,
#                                       `cage-advisor-sa`, `cage-reconciler-sa`, `langfuse-sa`
#   - `governed-advisor-http` (8080):   zero AuthorizationPolicy (deny-all inbound)
#   - `agentsight-ui-http` (8080):      exact `GET /` kubelet probe only

locals {
  workload_mesh_identities = {
    gateway           = "${kubernetes_service_account.workload["gateway"].metadata[0].name}.${module.namespace.name}.${module.service_mesh.identity_suffix}"
    advisor           = "${kubernetes_service_account.workload["advisor"].metadata[0].name}.${module.namespace.name}.${module.service_mesh.identity_suffix}"
    compliance_bridge = "${kubernetes_service_account.workload["compliance_bridge"].metadata[0].name}.${module.namespace.name}.${module.service_mesh.identity_suffix}"
    vllm              = "${kubernetes_service_account.workload["vllm"].metadata[0].name}.${module.namespace.name}.${module.service_mesh.identity_suffix}"
    inference_stub    = "${kubernetes_service_account.workload["inference_stub"].metadata[0].name}.${module.namespace.name}.${module.service_mesh.identity_suffix}"
    langfuse          = "${kubernetes_service_account.workload["langfuse"].metadata[0].name}.${module.namespace.name}.${module.service_mesh.identity_suffix}"
    clickhouse        = "${kubernetes_service_account.workload["clickhouse"].metadata[0].name}.${module.namespace.name}.${module.service_mesh.identity_suffix}"
    clickhouse_keeper = "${kubernetes_service_account.workload["clickhouse_keeper"].metadata[0].name}.${module.namespace.name}.${module.service_mesh.identity_suffix}"
    reconciler        = "${local.ksa_reconciler}.${module.namespace.name}.${module.service_mesh.identity_suffix}"
  }

  workload_mesh_policy_values = {
    identities = {
      gatewayGrpcClients           = [local.workload_mesh_identities.advisor]
      modelBackendClients          = [local.workload_mesh_identities.gateway]
      clickhouseHttpClients        = [local.workload_mesh_identities.compliance_bridge, local.workload_mesh_identities.langfuse, local.workload_mesh_identities.clickhouse]
      clickhouseTcpClients         = [local.workload_mesh_identities.langfuse, local.workload_mesh_identities.clickhouse]
      clickhouseInterserverClients = [local.workload_mesh_identities.clickhouse]
      clickhouseKeeperClients      = [local.workload_mesh_identities.clickhouse, local.workload_mesh_identities.clickhouse_keeper]
      clickhouseKeeperRaftClients  = [local.workload_mesh_identities.clickhouse_keeper]
      langfuseWebClients = [
        local.workload_mesh_identities.gateway,
        local.workload_mesh_identities.compliance_bridge,
        local.workload_mesh_identities.advisor,
        local.workload_mesh_identities.reconciler,
        local.workload_mesh_identities.langfuse,
      ]
    }
  }
}

resource "helm_release" "workload_mesh_policy" {
  name            = "workload-mesh-policy"
  chart           = "${path.module}/charts/workload-mesh-policy"
  namespace       = module.namespace.name
  upgrade_install = true
  atomic          = true
  cleanup_on_fail = true
  timeout         = 180

  values = [yamlencode(local.workload_mesh_policy_values)]

  depends_on = [
    module.namespace,
    module.service_mesh,
    kubernetes_service_account.workload,
  ]
}
