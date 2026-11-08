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

# PR-7a (POAM-2026-195, F-19, F-102, R-15, D-195-3, OP-1):
# Plan-time assertions verifying that OPA is off the pod network on gcp-gke:
#   - module.opa renders read-only policy, system.authz, and console decision-log
#     ConfigMaps only (no Service, no standalone Deployment);
#   - module.gateway runs OPA as a read-only UDS sidecar with --authorization=basic,
#     zero TCP listener ports, static /opa check probes, drain-safe shutdown flags,
#     and OPA_URL=http+unix://%2Fvar%2Frun%2Fopa%2Fopa.sock;
#   - NetworkPolicies carry no app=opa / TCP 8181 rules;
#   - governed_advisor carries no OPA_URL or OPA_AUTH_TOKEN env vars.

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
  target = module.gke
  outputs = {
    cluster_ca_certificate     = "dGVzdA=="
    cluster_endpoint           = "203.0.113.10"
    cluster_location           = "us-central1-a"
    cluster_name               = "cage-staging"
    is_regional                = false
    node_pools                 = {}
    node_service_account_email = "cage-gke-nodes-staging@opa-uds-test.iam.gserviceaccount.com"
    workload_identity_pool     = "opa-uds-test.svc.id.goog"
  }
}

override_module {
  target = module.memorystore_governance
  outputs = {
    managed_server_ca     = ["-----BEGIN CERTIFICATE-----test-----END CERTIFICATE-----"]
    primary_endpoint_ip   = "10.10.0.5"
    primary_endpoint_port = 6379
    replica_count         = 1
  }
}

override_module {
  target = module.memorystore_app
  outputs = {
    primary_endpoint_ip   = "10.10.0.6"
    primary_endpoint_port = 6379
  }
}

variables {
  project_id                     = "opa-uds-test"
  authorized_networks            = [{ cidr = "203.0.113.7/32", display_name = "test" }]
  langfuse_compliance_public_key = "fake-compliance-public-key"
  langfuse_compliance_secret_key = "fake-compliance-secret-key"
  trusted_operator_identities    = ["alice@example.org"]
  operator_oidc_issuer           = "https://idp.example.org"
  operator_oidc_audience         = "cage-compliance-bridge"
  operator_jwks_uri              = "https://idp.example.org/.well-known/jwks.json"

  gateway_base = {
    namespace                        = "governance-stack"
    image                            = "registry.invalid/cage-test/gateway@sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    opa_image                        = "registry.invalid/cage-test/opa@sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    project_id                       = "opa-uds-test"
    region                           = "us-central1"
    redis_host                       = "10.10.0.5"
    cage_inference_backend           = "none"
    vllm_base_url                    = ""
    vllm_reasoning_api_base          = ""
    vllm_fast_api_base               = ""
    guardrails_model_name            = ""
    opa_policies_config_map_name     = "opa-policies"
    opa_system_authz_config_map_name = "opa-system-authz"
    opa_config_config_map_name       = "opa-config"
    opa_bundle_sha256                = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    governance_salt                  = "test-salt-fixture"
    trusted_client_identities        = ["cage-advisor-sa.governance-stack.serviceaccount.identity.linkerd.cluster.local"]
    service_account_name             = "cage-gateway-sa"
    reconciler_kms_key               = "projects/opa-uds-test/locations/us-central1/keyRings/kr/cryptoKeys/reconciler/cryptoKeyVersions/1"
    evidence_stream_redis_url        = "rediss://10.10.0.5:6379"
    evidence_stream_redis_db         = 0
    evidence_stream_key              = "cage:evidence:stream"
    deployment_config_map_name       = "cage-deployment"
    gateway_secret_name              = "gateway-secrets"
    gateway_telemetry_public_key     = "gw-telemetry-pub-key"
    advisor_telemetry_public_key     = "adv-telemetry-pub-key"
  }
}

# ─── Root gcp-gke target: OPA UDS wiring and NetworkPolicy cleanliness ──────

run "gcp_gke_wires_opa_over_uds_with_no_network_egress_rule" {
  command = plan

  variables {
    inference_backend = "vllm"
  }

  assert {
    condition = (
      module.opa.uds_socket_path == "/var/run/opa/opa.sock" &&
      module.opa.uds_url == "http+unix://%2Fvar%2Frun%2Fopa%2Fopa.sock" &&
      module.opa.policies_config_map_name == "opa-policies" &&
      module.opa.system_authz_config_map_name == "opa-system-authz" &&
      module.opa.config_config_map_name == "opa-config" &&
      can(regex("^[0-9a-f]{64}$", module.opa.bundle_sha256)) &&
      output.deployment_summary.opa_uds_socket == "/var/run/opa/opa.sock" &&
      !contains(keys(kubernetes_service_account.workload), "opa")
    )
    error_message = "gcp-gke must expose OPA UDS outputs and ConfigMap names with a 64-hex bundle digest and zero standalone opa KSA"
  }

  assert {
    condition = alltrue([
      for rule in kubernetes_network_policy_v1.gateway_egress_l3_l4.spec[0].egress :
      alltrue([
        for peer in rule.to :
        length(peer.pod_selector) == 0 || try(peer.pod_selector[0].match_labels["app"], "") != "opa"
        ]) && alltrue([
        for p in rule.ports : tostring(p.port) != "8181"
      ])
    ])
    error_message = "gateway_egress_l3_l4 must contain no app=opa selector or port 8181 rule"
  }

  assert {
    condition = alltrue([
      for rule in kubernetes_network_policy_v1.financial_advisor_egress_internal_only.spec[0].egress :
      alltrue([
        for peer in rule.to :
        length(peer.pod_selector) == 0 || try(peer.pod_selector[0].match_labels["app"], "") != "opa"
        ]) && alltrue([
        for p in rule.ports : tostring(p.port) != "8181"
      ])
    ])
    error_message = "financial_advisor_egress_internal_only must contain no app=opa selector or port 8181 rule"
  }
}

# ─── opa_policy module: read-only ConfigMaps, system.authz, console logs ────

run "opa_policy_renders_readonly_bundle_and_console_decision_logs" {
  command = plan

  module {
    source = "../../modules/opa_policy"
  }

  variables {
    namespace               = "governance-stack"
    create_policy_configmap = true
    policy_files = {
      "trade_governance.rego" = "package trade.governance\nallow := false\n"
    }
  }

  assert {
    condition = (
      kubernetes_config_map.opa_policies[0].metadata[0].name == "opa-policies" &&
      kubernetes_config_map.opa_policies[0].metadata[0].labels["compliance.iso42001/enabled"] == "true" &&
      strcontains(kubernetes_config_map.opa_policies[0].data["trade_governance.rego"], "package trade.governance")
    )
    error_message = "opa_policy must create ISO 42001-labelled opa-policies ConfigMap"
  }

  assert {
    condition = (
      kubernetes_config_map.opa_system_authz.metadata[0].name == "opa-system-authz" &&
      kubernetes_config_map.opa_system_authz.metadata[0].labels["compliance.iso42001/enabled"] == "true" &&
      strcontains(kubernetes_config_map.opa_system_authz.data["system_authz.rego"], "package system.authz") &&
      strcontains(kubernetes_config_map.opa_system_authz.data["system_authz.rego"], "default allow := false") &&
      strcontains(kubernetes_config_map.opa_system_authz.data["system_authz.rego"], "input.path[2] != \"system\"")
    )
    error_message = "opa_policy must render system_authz.rego denying runtime mutations by default"
  }

  assert {
    condition = (
      kubernetes_config_map.opa_config[0].metadata[0].name == "opa-config" &&
      strcontains(kubernetes_config_map.opa_config[0].data["opa_config.yaml"], "decision_logs:") &&
      strcontains(kubernetes_config_map.opa_config[0].data["opa_config.yaml"], "console: true") &&
      output.uds_socket_path == "/var/run/opa/opa.sock" &&
      output.uds_url == "http+unix://%2Fvar%2Frun%2Fopa%2Fopa.sock"
    )
    error_message = "opa_policy must enable decision_logs.console = true by default (F-102)"
  }
}

run "opa_policy_refuses_blank_config" {
  command = plan

  module {
    source = "../../modules/opa_policy"
  }

  variables {
    namespace  = "governance-stack"
    opa_config = "   "
    policy_files = {
      "trade_governance.rego" = "package trade.governance\nallow := false\n"
    }
  }

  expect_failures = [var.opa_config]
}

# ─── gateway module: UDS sidecar, zero OPA TCP ports, read-only mounts ──────

run "gateway_embeds_readonly_opa_uds_sidecar_with_zero_tcp_ports" {
  command = plan

  module {
    source = "../../modules/gateway"
  }

  variables {
    namespace                        = var.gateway_base.namespace
    image                            = var.gateway_base.image
    opa_image                        = var.gateway_base.opa_image
    project_id                       = var.gateway_base.project_id
    region                           = var.gateway_base.region
    redis_host                       = var.gateway_base.redis_host
    cage_inference_backend           = var.gateway_base.cage_inference_backend
    vllm_base_url                    = var.gateway_base.vllm_base_url
    vllm_reasoning_api_base          = var.gateway_base.vllm_reasoning_api_base
    vllm_fast_api_base               = var.gateway_base.vllm_fast_api_base
    guardrails_model_name            = var.gateway_base.guardrails_model_name
    opa_policies_config_map_name     = var.gateway_base.opa_policies_config_map_name
    opa_system_authz_config_map_name = var.gateway_base.opa_system_authz_config_map_name
    opa_config_config_map_name       = var.gateway_base.opa_config_config_map_name
    opa_bundle_sha256                = var.gateway_base.opa_bundle_sha256
    governance_salt                  = var.gateway_base.governance_salt
    trusted_client_identities        = var.gateway_base.trusted_client_identities
    service_account_name             = var.gateway_base.service_account_name
    reconciler_kms_key               = var.gateway_base.reconciler_kms_key
    evidence_stream_redis_url        = var.gateway_base.evidence_stream_redis_url
    evidence_stream_redis_db         = var.gateway_base.evidence_stream_redis_db
    evidence_stream_key              = var.gateway_base.evidence_stream_key
    deployment_config_map_name       = var.gateway_base.deployment_config_map_name
    gateway_secret_name              = var.gateway_base.gateway_secret_name
    gateway_telemetry_public_key     = var.gateway_base.gateway_telemetry_public_key
    advisor_telemetry_public_key     = var.gateway_base.advisor_telemetry_public_key
    governance_redis_replica_count   = 1
  }

  assert {
    condition = (
      length(kubernetes_deployment.gateway.spec[0].template[0].spec[0].container) == 2 &&
      kubernetes_deployment.gateway.spec[0].template[0].spec[0].container[0].name == "gateway" &&
      kubernetes_deployment.gateway.spec[0].template[0].spec[0].container[1].name == "opa" &&
      tonumber(kubernetes_deployment.gateway.spec[0].template[0].spec[0].termination_grace_period_seconds) >= 30 &&
      kubernetes_deployment.gateway.spec[0].template[0].metadata[0].annotations["cage.io/opa-bundle-sha256"] == var.gateway_base.opa_bundle_sha256 &&
      one([
        for e in kubernetes_deployment.gateway.spec[0].template[0].spec[0].container[0].env :
        e.value if e.name == "OPA_URL"
      ]) == "http+unix://%2Fvar%2Frun%2Fopa%2Fopa.sock"
    )
    error_message = "gateway Deployment must run gateway + opa sidecar with OPA_URL over UDS, >=30s grace period, and opa-bundle-sha256 rollout annotation"
  }

  assert {
    condition = (
      length(kubernetes_deployment.gateway.spec[0].template[0].spec[0].container[1].port) == 0 &&
      contains(kubernetes_deployment.gateway.spec[0].template[0].spec[0].container[1].args, "--addr=unix:///var/run/opa/opa.sock") &&
      contains(kubernetes_deployment.gateway.spec[0].template[0].spec[0].container[1].args, "--authorization=basic") &&
      contains(kubernetes_deployment.gateway.spec[0].template[0].spec[0].container[1].args, "--config-file=/config/opa_config.yaml") &&
      contains(kubernetes_deployment.gateway.spec[0].template[0].spec[0].container[1].args, "--shutdown-wait-period=15") &&
      contains(kubernetes_deployment.gateway.spec[0].template[0].spec[0].container[1].args, "--shutdown-grace-period=15") &&
      contains(kubernetes_deployment.gateway.spec[0].template[0].spec[0].container[1].args, "/etc/opa/authz/system_authz.rego") &&
      !anytrue([for a in kubernetes_deployment.gateway.spec[0].template[0].spec[0].container[1].args : startswith(a, "--diagnostic-addr")]) &&
      kubernetes_deployment.gateway.spec[0].template[0].spec[0].container[1].readiness_probe[0].exec[0].command[0] == "/opa" &&
      kubernetes_deployment.gateway.spec[0].template[0].spec[0].container[1].liveness_probe[0].exec[0].command[0] == "/opa" &&
      kubernetes_deployment.gateway.spec[0].template[0].spec[0].container[1].lifecycle[0].pre_stop[0].exec[0].command[0] == "/opa" &&
      kubernetes_deployment.gateway.spec[0].template[0].spec[0].container[1].security_context[0].read_only_root_filesystem == true &&
      kubernetes_deployment.gateway.spec[0].template[0].spec[0].container[1].security_context[0].allow_privilege_escalation == false &&
      kubernetes_deployment.gateway.spec[0].template[0].spec[0].container[1].security_context[0].run_as_non_root == true &&
      tostring(kubernetes_deployment.gateway.spec[0].template[0].spec[0].container[1].security_context[0].run_as_user) == "1000" &&
      tostring(kubernetes_deployment.gateway.spec[0].template[0].spec[0].container[1].security_context[0].run_as_group) == "1000"
    )
    error_message = "opa sidecar must bind only unix:///var/run/opa/opa.sock with --authorization=basic, static /opa probes, drain flags, zero ports, no --diagnostic-addr, and readOnlyRootFilesystem"
  }

  assert {
    condition = (
      contains([
        for vm in kubernetes_deployment.gateway.spec[0].template[0].spec[0].container[1].volume_mount :
        "${vm.name}:${vm.mount_path}:${coalesce(vm.read_only, false)}"
      ], "opa-policies:/policies:true") &&
      contains([
        for vm in kubernetes_deployment.gateway.spec[0].template[0].spec[0].container[1].volume_mount :
        "${vm.name}:${vm.mount_path}:${coalesce(vm.read_only, false)}"
      ], "opa-system-authz:/etc/opa/authz:true") &&
      contains([
        for vm in kubernetes_deployment.gateway.spec[0].template[0].spec[0].container[1].volume_mount :
        "${vm.name}:${vm.mount_path}:${coalesce(vm.read_only, false)}"
      ], "opa-config:/config:true") &&
      toset([for p in kubernetes_service.gateway.spec[0].port : tonumber(p.port)]) == toset([8080, 50051, 9090])
    )
    error_message = "opa sidecar ConfigMap mounts must be read_only and gateway Service must never expose port 8181"
  }
}

run "gateway_refuses_tcp_opa_url" {
  command = plan

  module {
    source = "../../modules/gateway"
  }

  variables {
    namespace                        = var.gateway_base.namespace
    image                            = var.gateway_base.image
    opa_image                        = var.gateway_base.opa_image
    opa_url                          = "http://opa.governance-stack.svc.cluster.local:8181"
    project_id                       = var.gateway_base.project_id
    region                           = var.gateway_base.region
    redis_host                       = var.gateway_base.redis_host
    cage_inference_backend           = var.gateway_base.cage_inference_backend
    vllm_base_url                    = var.gateway_base.vllm_base_url
    vllm_reasoning_api_base          = var.gateway_base.vllm_reasoning_api_base
    vllm_fast_api_base               = var.gateway_base.vllm_fast_api_base
    guardrails_model_name            = var.gateway_base.guardrails_model_name
    opa_policies_config_map_name     = var.gateway_base.opa_policies_config_map_name
    opa_system_authz_config_map_name = var.gateway_base.opa_system_authz_config_map_name
    opa_config_config_map_name       = var.gateway_base.opa_config_config_map_name
    governance_salt                  = var.gateway_base.governance_salt
    trusted_client_identities        = var.gateway_base.trusted_client_identities
    service_account_name             = var.gateway_base.service_account_name
    reconciler_kms_key               = var.gateway_base.reconciler_kms_key
    evidence_stream_redis_url        = var.gateway_base.evidence_stream_redis_url
    evidence_stream_redis_db         = var.gateway_base.evidence_stream_redis_db
    evidence_stream_key              = var.gateway_base.evidence_stream_key
    deployment_config_map_name       = var.gateway_base.deployment_config_map_name
    gateway_secret_name              = var.gateway_base.gateway_secret_name
    gateway_telemetry_public_key     = var.gateway_base.gateway_telemetry_public_key
    advisor_telemetry_public_key     = var.gateway_base.advisor_telemetry_public_key
    governance_redis_replica_count   = 1
  }

  expect_failures = [var.opa_url]
}

run "gateway_refuses_unpinned_opa_image" {
  command = plan

  module {
    source = "../../modules/gateway"
  }

  variables {
    namespace                        = var.gateway_base.namespace
    image                            = var.gateway_base.image
    opa_image                        = "openpolicyagent/opa:0.70.0-static"
    project_id                       = var.gateway_base.project_id
    region                           = var.gateway_base.region
    redis_host                       = var.gateway_base.redis_host
    cage_inference_backend           = var.gateway_base.cage_inference_backend
    vllm_base_url                    = var.gateway_base.vllm_base_url
    vllm_reasoning_api_base          = var.gateway_base.vllm_reasoning_api_base
    vllm_fast_api_base               = var.gateway_base.vllm_fast_api_base
    guardrails_model_name            = var.gateway_base.guardrails_model_name
    opa_policies_config_map_name     = var.gateway_base.opa_policies_config_map_name
    opa_system_authz_config_map_name = var.gateway_base.opa_system_authz_config_map_name
    opa_config_config_map_name       = var.gateway_base.opa_config_config_map_name
    governance_salt                  = var.gateway_base.governance_salt
    trusted_client_identities        = var.gateway_base.trusted_client_identities
    service_account_name             = var.gateway_base.service_account_name
    reconciler_kms_key               = var.gateway_base.reconciler_kms_key
    evidence_stream_redis_url        = var.gateway_base.evidence_stream_redis_url
    evidence_stream_redis_db         = var.gateway_base.evidence_stream_redis_db
    evidence_stream_key              = var.gateway_base.evidence_stream_key
    deployment_config_map_name       = var.gateway_base.deployment_config_map_name
    gateway_secret_name              = var.gateway_base.gateway_secret_name
    gateway_telemetry_public_key     = var.gateway_base.gateway_telemetry_public_key
    advisor_telemetry_public_key     = var.gateway_base.advisor_telemetry_public_key
    governance_redis_replica_count   = 1
  }

  expect_failures = [var.opa_image]
}

# ─── governed_advisor module: zero OPA env vars ─────────────────────────────

run "governed_advisor_carries_no_opa_env_vars" {
  command = plan

  module {
    source = "../../modules/governed_advisor"
  }

  variables {
    namespace                  = "governance-stack"
    image                      = "registry.invalid/cage-test/governed-financial-advisor@sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    project_id                 = "opa-uds-test"
    region                     = "us-central1"
    redis_host                 = "10.10.0.6"
    model_fast                 = "test-fast"
    model_reasoning            = "test-reasoning"
    model_consensus            = "test-consensus"
    vllm_base_url              = "http://gateway.governance-stack.svc.cluster.local:8080/v1"
    vllm_fast_api_base         = "http://gateway.governance-stack.svc.cluster.local:8080/v1"
    vllm_reasoning_api_base    = "http://gateway.governance-stack.svc.cluster.local:8080/v1"
    langfuse_host              = "http://langfuse-web.governance-stack.svc.cluster.local:3000"
    service_account_name       = "cage-advisor-sa"
    deployment_config_map_name = "cage-deployment"
  }

  assert {
    condition = (
      !contains([for e in kubernetes_deployment.governed_advisor.spec[0].template[0].spec[0].container[0].env : e.name], "OPA_URL") &&
      !contains([for e in kubernetes_deployment.governed_advisor.spec[0].template[0].spec[0].container[0].env : e.name], "OPA_AUTH_TOKEN")
    )
    error_message = "governed_advisor container must inject neither OPA_URL nor OPA_AUTH_TOKEN (D-195-3 / OP-1)"
  }
}
