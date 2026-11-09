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

# PR-7b (§10 — POAM-2026-195, POAM-2026-080, F-16..F-20, F-78, F-87, F-103, R-5, R-16):
# Plan-time contracts for per-workload Kubernetes NetworkPolicy segmentation,
# dedicated workload KSAs + Linkerd mesh-policy identities, and GKE Dataplane V2
# policy-verdict logging.

mock_provider "google" {
  mock_resource "google_container_cluster" {
    override_during = plan
    defaults = {
      endpoint    = "203.0.113.10"
      master_auth = [{ cluster_ca_certificate = "dGVzdA==", client_certificate = "", client_key = "", client_certificate_config = [] }]
    }
  }
}
mock_provider "helm" {}
mock_provider "kubernetes" {}
mock_provider "random" {}

override_module {
  target = module.memorystore_governance
  outputs = {
    managed_server_ca     = ["-----BEGIN CERTIFICATE-----test-----END CERTIFICATE-----"]
    primary_endpoint_ip   = "10.20.0.5"
    primary_endpoint_port = 6379
    replica_count         = 1
  }
}

override_module {
  target = module.memorystore_app
  outputs = {
    primary_endpoint_ip   = "10.20.0.6"
    primary_endpoint_port = 6379
  }
}

override_module {
  target = module.cloudsql_postgres
  outputs = {
    private_ip_address             = "10.20.0.7"
    connection_name                = "seg-test-project:us-central1:cage-postgres-staging"
    database_name                  = "langfuse"
    iam_user_name                  = "langfuse@seg-test-project.iam"
    point_in_time_recovery_enabled = true
  }
}

variables {
  project_id          = "seg-test-project"
  authorized_networks = [{ cidr = "203.0.113.7/32", display_name = "test" }]
  enforce_in_dev      = false

  langfuse_compliance_public_key = "fake-compliance-public-key"
  langfuse_compliance_secret_key = "fake-compliance-secret-key"
}

run "per_workload_network_policy_segmentation" {
  command = plan

  variables {
    inference_backend    = "vllm"
    enable_gpu_node_pool = true
    image_digests = {
      "gateway"                    = "registry.invalid/cage-test/gateway@sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
      "opa"                        = "registry.invalid/cage-test/opa@sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
      "agentsight-ui"              = "registry.invalid/cage-test/agentsight-ui@sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
      "langfuse"                   = "registry.invalid/cage-test/langfuse@sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
      "langfuse-worker"            = "registry.invalid/cage-test/langfuse-worker@sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
      "cloud-sql-proxy"            = "registry.invalid/cage-test/cloud-sql-proxy@sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
      "clickhouse-server"          = "registry.invalid/cage-test/clickhouse-server@sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
      "clickhouse-keeper"          = "registry.invalid/cage-test/clickhouse-keeper@sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
      "compliance-bridge"          = "registry.invalid/cage-test/compliance-bridge@sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
      "golang-migrate"             = "registry.invalid/cage-test/golang-migrate@sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
      "lula"                       = "registry.invalid/cage-test/lula@sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
      "vllm-streamer"              = "registry.invalid/cage-test/vllm-streamer@sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
      "governed-financial-advisor" = "registry.invalid/cage-test/governed-financial-advisor@sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    }
  }

  assert {
    condition = (
      length(coalesce(kubernetes_network_policy_v1.default_deny_ingress.spec[0].pod_selector[0].match_labels, tomap({}))) == 0 &&
      length(kubernetes_network_policy_v1.default_deny_ingress.spec[0].pod_selector[0].match_expressions) == 0 &&
      length(kubernetes_network_policy_v1.default_deny_ingress.spec[0].ingress) == 0 &&
      length(kubernetes_network_policy_v1.default_deny_ingress.spec[0].egress) == 0 &&
      length(coalesce(kubernetes_network_policy_v1.default_deny_external_egress.spec[0].pod_selector[0].match_labels, tomap({}))) == 0 &&
      length(kubernetes_network_policy_v1.default_deny_external_egress.spec[0].pod_selector[0].match_expressions) == 0 &&
      length(kubernetes_network_policy_v1.default_deny_external_egress.spec[0].ingress) == 0 &&
      length(kubernetes_network_policy_v1.default_deny_external_egress.spec[0].egress) == 0
    )
    error_message = "default-deny-ingress and default-deny-external-egress must have empty pod_selector {} and zero allow rules"
  }

  assert {
    condition = alltrue([
      for np in [
        kubernetes_network_policy_v1.gateway_ingress,
        kubernetes_network_policy_v1.gateway_egress_l3_l4,
        kubernetes_network_policy_v1.model_backend_ingress,
        kubernetes_network_policy_v1.vllm_egress_l3_l4,
        kubernetes_network_policy_v1.compliance_bridge_ingress,
        kubernetes_network_policy_v1.compliance_bridge_egress_l3_l4,
        kubernetes_network_policy_v1.financial_advisor_egress_internal_only,
        kubernetes_network_policy_v1.reconciliation_worker_egress,
        kubernetes_network_policy_v1.langfuse_web_ingress,
        kubernetes_network_policy_v1.langfuse_egress_l3_l4,
        kubernetes_network_policy_v1.clickhouse_ingress,
        kubernetes_network_policy_v1.clickhouse_egress_l3_l4,
        kubernetes_network_policy_v1.clickhouse_keeper_ingress,
        kubernetes_network_policy_v1.clickhouse_keeper_egress_l3_l4,
        kubernetes_network_policy_v1.lula_audit_egress,
        ] : (
        length(coalesce(np.spec[0].pod_selector[0].match_labels, tomap({}))) > 0 ||
        length(np.spec[0].pod_selector[0].match_expressions) > 0
      )
    ])
    error_message = "zero allow NetworkPolicies may carry an empty namespace-wide pod_selector {}"
  }

  assert {
    condition = alltrue([
      for np in [
        kubernetes_network_policy_v1.gateway_egress_l3_l4,
        kubernetes_network_policy_v1.vllm_egress_l3_l4,
        kubernetes_network_policy_v1.compliance_bridge_egress_l3_l4,
        kubernetes_network_policy_v1.financial_advisor_egress_internal_only,
        kubernetes_network_policy_v1.reconciliation_worker_egress,
        kubernetes_network_policy_v1.langfuse_egress_l3_l4,
        kubernetes_network_policy_v1.clickhouse_egress_l3_l4,
        kubernetes_network_policy_v1.clickhouse_keeper_egress_l3_l4,
        kubernetes_network_policy_v1.lula_audit_egress,
        ] : length([
          for r in np.spec[0].egress : r
          if anytrue([
            for t in r.to : (
              length(t.namespace_selector) == 0 &&
              length(t.ip_block) == 0 &&
              length(t.pod_selector) > 0 &&
              length(coalesce(t.pod_selector[0].match_labels, tomap({}))) == 0 &&
              length(t.pod_selector[0].match_expressions) == 0
            )
          ])
      ]) == 0
    ])
    error_message = "no egress NetworkPolicy may grant a wildcard intra-namespace `to { pod_selector {} }` rule (F-18)"
  }

  assert {
    condition = (
      contains(flatten([
        for r in kubernetes_network_policy_v1.gateway_egress_l3_l4.spec[0].egress :
        [for t in r.to : t.ip_block[0].cidr if length(t.ip_block) > 0]
        if contains([for p in r.ports : p.port], "6379")
      ]), "10.20.0.5/32") &&
      contains(flatten([
        for r in kubernetes_network_policy_v1.compliance_bridge_egress_l3_l4.spec[0].egress :
        [for t in r.to : t.ip_block[0].cidr if length(t.ip_block) > 0]
        if contains([for p in r.ports : p.port], "6379")
      ]), "10.20.0.5/32") &&
      contains(flatten([
        for r in kubernetes_network_policy_v1.reconciliation_worker_egress.spec[0].egress :
        [for t in r.to : t.ip_block[0].cidr if length(t.ip_block) > 0]
        if contains([for p in r.ports : p.port], "6379")
      ]), "10.20.0.5/32") &&
      alltrue([
        for np in [
          kubernetes_network_policy_v1.financial_advisor_egress_internal_only,
          kubernetes_network_policy_v1.vllm_egress_l3_l4,
          kubernetes_network_policy_v1.langfuse_egress_l3_l4,
          kubernetes_network_policy_v1.clickhouse_egress_l3_l4,
          kubernetes_network_policy_v1.clickhouse_keeper_egress_l3_l4,
          kubernetes_network_policy_v1.lula_audit_egress,
          ] : !contains(flatten([
            for r in np.spec[0].egress :
            [for t in r.to : t.ip_block[0].cidr if length(t.ip_block) > 0]
        ]), "10.20.0.5/32")
      ])
    )
    error_message = "governance Valkey /32 (10.20.0.5/32) must be reachable ONLY from gateway, compliance-bridge, and reconciliation-worker"
  }

  assert {
    condition = (
      toset(kubernetes_network_policy_v1.langfuse_egress_l3_l4.spec[0].pod_selector[0].match_expressions[0].values) == toset(["langfuse-web", "langfuse-worker"]) &&
      contains(flatten([
        for r in kubernetes_network_policy_v1.langfuse_egress_l3_l4.spec[0].egress :
        [for t in r.to : t.ip_block[0].cidr if length(t.ip_block) > 0]
        if contains([for p in r.ports : p.port], "6379")
      ]), "10.20.0.6/32") &&
      contains(flatten([
        for r in kubernetes_network_policy_v1.langfuse_egress_l3_l4.spec[0].egress :
        [for t in r.to : t.ip_block[0].cidr if length(t.ip_block) > 0]
        if contains([for p in r.ports : p.port], "3307") && contains([for p in r.ports : p.port], "5432")
      ]), "10.20.0.7/32") &&
      alltrue([
        for np in [
          kubernetes_network_policy_v1.gateway_egress_l3_l4,
          kubernetes_network_policy_v1.compliance_bridge_egress_l3_l4,
          kubernetes_network_policy_v1.reconciliation_worker_egress,
          kubernetes_network_policy_v1.financial_advisor_egress_internal_only,
          kubernetes_network_policy_v1.vllm_egress_l3_l4,
          kubernetes_network_policy_v1.clickhouse_egress_l3_l4,
          kubernetes_network_policy_v1.clickhouse_keeper_egress_l3_l4,
          kubernetes_network_policy_v1.lula_audit_egress,
          ] : (
          !contains(flatten([
            for r in np.spec[0].egress :
            [for t in r.to : t.ip_block[0].cidr if length(t.ip_block) > 0]
          ]), "10.20.0.6/32") &&
          !contains(flatten([
            for r in np.spec[0].egress :
            [for t in r.to : t.ip_block[0].cidr if length(t.ip_block) > 0]
          ]), "10.20.0.7/32")
        )
      ])
    )
    error_message = "Cloud SQL /32 (10.20.0.7/32) and app Valkey /32 (10.20.0.6/32) must be granted ONLY to langfuse-web and langfuse-worker"
  }

  assert {
    condition = (
      length(kubernetes_network_policy_v1.model_backend_ingress.spec[0].ingress) == 1 &&
      length(kubernetes_network_policy_v1.model_backend_ingress.spec[0].ingress[0].from) == 1 &&
      kubernetes_network_policy_v1.model_backend_ingress.spec[0].ingress[0].from[0].pod_selector[0].match_labels == tomap({ app = "gateway" }) &&
      toset([for p in kubernetes_network_policy_v1.model_backend_ingress.spec[0].ingress[0].ports : p.port]) == toset(["8000", "4143"])
    )
    error_message = "model_backend_ingress must admit ONLY app = gateway on TCP 8000 and Linkerd inbound 4143 (R-16, F-103)"
  }

  assert {
    condition = (
      toset(flatten([
        for r in kubernetes_network_policy_v1.financial_advisor_egress_internal_only.spec[0].egress : [
          for t in r.to : coalesce(t.pod_selector[0].match_labels, tomap({}))["app"]
          if length(t.namespace_selector) == 0 && length(t.pod_selector) > 0 && contains(keys(coalesce(t.pod_selector[0].match_labels, tomap({}))), "app")
        ]
      ])) == toset(["gateway", "langfuse-web"]) &&
      length(flatten([
        for r in kubernetes_network_policy_v1.financial_advisor_egress_internal_only.spec[0].egress : [
          for t in r.to : t.pod_selector[0].match_expressions
          if length(t.namespace_selector) == 0 && length(t.pod_selector) > 0 && length(t.pod_selector[0].match_expressions) > 0
        ]
      ])) == 0
    )
    error_message = "governed-financial-advisor intra-namespace egress must reach ONLY gateway and langfuse-web — never model backends, compliance-bridge, or clickhouse"
  }

  assert {
    condition = (
      yamldecode(helm_release.workload_mesh_policy.values[0]).identities.modelBackendClients == [
        "cage-gateway-sa.governance-stack.serviceaccount.identity.linkerd.cluster.local"
      ] &&
      yamldecode(helm_release.workload_mesh_policy.values[0]).identities.gatewayGrpcClients == [
        "cage-advisor-sa.governance-stack.serviceaccount.identity.linkerd.cluster.local"
      ] &&
      yamldecode(helm_release.workload_mesh_policy.values[0]).identities.clickhouseKeeperRaftClients == [
        "cage-clickhouse-keeper-sa.governance-stack.serviceaccount.identity.linkerd.cluster.local"
      ] &&
      !contains(
        yamldecode(helm_release.workload_mesh_policy.values[0]).identities.clickhouseTcpClients,
        "cage-compliance-bridge-sa.governance-stack.serviceaccount.identity.linkerd.cluster.local"
      )
    )
    error_message = "Linkerd workload_mesh_policy must bind modelBackendClients to cage-gateway-sa, gatewayGrpcClients to cage-advisor-sa, clickhouseKeeperRaftClients to cage-clickhouse-keeper-sa, and exclude compliance-bridge from ClickHouse TCP 9000"
  }

  assert {
    condition = (
      kubernetes_service_account.workload["agentsight_ui"].metadata[0].name == "cage-agentsight-ui-sa" &&
      length(coalesce(kubernetes_service_account.workload["agentsight_ui"].metadata[0].annotations, tomap({}))) == 0 &&
      kubernetes_service_account.workload["clickhouse_keeper"].metadata[0].name == "cage-clickhouse-keeper-sa" &&
      length(coalesce(kubernetes_service_account.workload["clickhouse_keeper"].metadata[0].annotations, tomap({}))) == 0 &&
      kubernetes_service_account.workload["inference_stub"].metadata[0].name == "cage-inference-stub-sa" &&
      length(coalesce(kubernetes_service_account.workload["inference_stub"].metadata[0].annotations, tomap({}))) == 0
    )
    error_message = "agentsight_ui, clickhouse_keeper, and inference_stub must run under dedicated KSAs with zero Workload Identity GSA annotation"
  }
}

run "staging_enables_dataplane_v2_policy_verdict_logging" {
  command = plan

  assert {
    condition = (
      local.enforcing_posture &&
      local.dataplane_v2_network_logging_active &&
      module.gke.dataplane_v2_policy_logging_enabled &&
      length(helm_release.dataplane_v2_network_logging) == 1 &&
      helm_release.dataplane_v2_network_logging[0].namespace == "kube-system" &&
      helm_release.dataplane_v2_network_logging[0].namespace != var.namespace &&
      length(kubernetes_labels.dataplane_v2_network_logging_helm_adopt) == 1 &&
      length(kubernetes_annotations.dataplane_v2_network_logging_helm_adopt) == 1 &&
      yamldecode(helm_release.dataplane_v2_network_logging[0].values[0]).logAllow == true &&
      yamldecode(helm_release.dataplane_v2_network_logging[0].values[0]).logDeny == true &&
      yamldecode(helm_release.dataplane_v2_network_logging[0].values[0]).delegateAllow == false &&
      yamldecode(helm_release.dataplane_v2_network_logging[0].values[0]).delegateDeny == false &&
      kubernetes_network_policy_v1.default_deny_ingress.metadata[0].annotations["policy.network.gke.io/enable-logging"] == "true"
    )
    error_message = "staging must enable GKE Dataplane V2 observability + NetworkLogging/default allow/deny policy verdict logging in kube-system"
  }
}

run "prod_enables_dataplane_v2_logging_and_clickhouse_cold_tier_fqdn" {
  command = plan

  variables {
    environment              = "prod"
    enable_high_availability = true
    evidence_project_id      = "seg-evidence-project"
  }

  assert {
    condition = (
      local.enforcing_posture &&
      module.gke.dataplane_v2_policy_logging_enabled &&
      length(helm_release.dataplane_v2_network_logging) == 1 &&
      contains(keys(local.fqdn_network_policies), "clickhouse_egress_fqdn")
    )
    error_message = "prod must enable Dataplane V2 policy verdict logging and scope ClickHouse cold-tier GCS HTTPS egress via clickhouse_egress_fqdn"
  }
}

run "dev_with_enforce_in_dev_enables_dataplane_v2_policy_verdict_logging" {
  command = plan

  variables {
    environment    = "dev"
    enforce_in_dev = true
  }

  assert {
    condition = (
      local.enforcing_posture &&
      module.gke.dataplane_v2_policy_logging_enabled &&
      length(helm_release.dataplane_v2_network_logging) == 1
    )
    error_message = "dev with enforce_in_dev = true must enable Dataplane V2 policy verdict logging"
  }
}

run "plain_dev_keeps_dataplane_v2_policy_verdict_logging_off_by_default" {
  command = plan

  variables {
    environment    = "dev"
    enforce_in_dev = false
  }

  assert {
    condition = (
      !local.enforcing_posture &&
      !local.dataplane_v2_network_logging_active &&
      !module.gke.dataplane_v2_policy_logging_enabled &&
      length(helm_release.dataplane_v2_network_logging) == 0 &&
      length(kubernetes_labels.dataplane_v2_network_logging_helm_adopt) == 0 &&
      !contains(keys(local.fqdn_network_policies), "clickhouse_egress_fqdn")
    )
    error_message = "non-enforcing dev must leave Dataplane V2 policy verdict logging and ClickHouse cold-tier FQDN egress off by default"
  }
}

run "explicit_false_overrides_enforcing_posture_policy_logging" {
  command = plan

  variables {
    enable_network_policy_logging = false
  }

  assert {
    condition = (
      local.enforcing_posture &&
      !local.dataplane_v2_network_logging_active &&
      !module.gke.dataplane_v2_policy_logging_enabled &&
      length(helm_release.dataplane_v2_network_logging) == 0 &&
      !contains(keys(kubernetes_network_policy_v1.default_deny_ingress.metadata[0].annotations), "policy.network.gke.io/enable-logging")
    )
    error_message = "setting enable_network_policy_logging = false must disable Dataplane V2 policy verdict logging even in an enforcing posture"
  }
}
