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

# ─── GKE Dataplane V2 NetworkPolicy Verdict Logging (D-195-4, R-5, F-78, F-87) ─
# Pairs with `google_container_cluster.primary.monitoring_config[0].advanced_datapath_observability_config`
# in `infra/modules/gcp_gke_cluster/main.tf` and PR-2 VPC firewall / Cloud NAT logging
# to produce SC-7 / SI-4 L3/L4 enforcement evidence in Cloud Logging:
#   logName = "projects/<PROJECT_ID>/logs/policy-action"  (resource.type = "k8s_node")
#
# Platform constraints documented per D-195-4 & F-87:
#   1. 500 connections/s per-node drop logging floor: to bound node CPU overhead,
#      GKE Dataplane V2 (`anetd`) logs up to 500 connections/s per node before
#      dropping excess policy log entries (all NetworkPolicy rules continue to be
#      enforced in eBPF; check `anetd` `:9990/metrics` `policy_logging` counters
#      to detect shed log records during flood scenarios).
#   2. L3/L4 verdicts only (F-78): GKE Dataplane V2 does not parse L7 HTTP/gRPC
#      headers in CNI policy logs, and Linkerd mTLS encrypts in-mesh L7 traffic
#      in transit. L7 identity/route enforcement and observability live in Linkerd
#      (`mesh_policy.tf` + `infra/modules/gateway/mesh-policy/`).
#
# Adoption lifecycle: GKE automatically creates a cluster-scoped `NetworkLogging`
# singleton named `default` on every Dataplane V2 cluster (`cannot be renamed`).
# `kubernetes_labels` + `kubernetes_annotations` apply Helm ownership metadata via
# Server-Side Apply before `helm_release.dataplane_v2_network_logging` reconciles
# `spec.cluster.allow` and `spec.cluster.deny`, avoiding both plan-time CRD
# discovery failures before cluster creation and Helm install ownership errors.

locals {
  network_policy_logging_enabled         = var.enable_network_policy_logging != null ? var.enable_network_policy_logging : local.enforcing_posture
  dataplane_v2_network_logging_active    = var.enable_dataplane_v2 && local.network_policy_logging_enabled
  dataplane_v2_logging_release_name      = "dataplane-v2-network-logging"
  dataplane_v2_logging_release_namespace = "kube-system"
}

resource "kubernetes_labels" "dataplane_v2_network_logging_helm_adopt" {
  count = local.dataplane_v2_network_logging_active ? 1 : 0

  api_version   = "networking.gke.io/v1alpha1"
  kind          = "NetworkLogging"
  field_manager = "terraform-cage-dataplane-v2-logging"
  force         = true

  metadata {
    name = "default"
  }

  labels = {
    "app.kubernetes.io/managed-by" = "Helm"
  }

  depends_on = [module.gke]
}

resource "kubernetes_annotations" "dataplane_v2_network_logging_helm_adopt" {
  count = local.dataplane_v2_network_logging_active ? 1 : 0

  api_version   = "networking.gke.io/v1alpha1"
  kind          = "NetworkLogging"
  field_manager = "terraform-cage-dataplane-v2-logging"
  force         = true

  metadata {
    name = "default"
  }

  annotations = {
    "meta.helm.sh/release-name"      = local.dataplane_v2_logging_release_name
    "meta.helm.sh/release-namespace" = local.dataplane_v2_logging_release_namespace
  }

  depends_on = [module.gke, kubernetes_labels.dataplane_v2_network_logging_helm_adopt]
}

resource "helm_release" "dataplane_v2_network_logging" {
  count = local.dataplane_v2_network_logging_active ? 1 : 0

  name            = local.dataplane_v2_logging_release_name
  chart           = "${path.module}/charts/dataplane-v2-logging"
  namespace       = local.dataplane_v2_logging_release_namespace
  upgrade_install = true
  atomic          = true
  cleanup_on_fail = true
  timeout         = 120

  values = [
    yamlencode({
      logAllow      = true
      delegateAllow = false
      logDeny       = true
      delegateDeny  = false
    }),
  ]

  depends_on = [
    module.gke,
    kubernetes_labels.dataplane_v2_network_logging_helm_adopt,
    kubernetes_annotations.dataplane_v2_network_logging_helm_adopt,
  ]
}
