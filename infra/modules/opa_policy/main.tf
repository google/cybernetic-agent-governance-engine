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

terraform {
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.23"
    }
  }
}

# ============================================================================
# OPA Read-Only Policy, System Authz & Console Decision-Log ConfigMaps
# (F-19, F-102, R-15, D-195-3)
# ============================================================================
# OPA runs exclusively as a sidecar container inside the gateway pod listening
# on an in-pod Unix domain socket (--addr=unix:///var/run/opa/opa.sock) with
# zero TCP listener ports, no Kubernetes Service, and no standalone Deployment.
# Runtime policy-store mutation (PUT/PATCH/DELETE on /v1/policies and /v1/data)
# is denied by --authorization=basic backed by data.system.authz.allow.
# ============================================================================

locals {
  uds_socket_path = "/var/run/opa/opa.sock"
  uds_url         = "http+unix://%2Fvar%2Frun%2Fopa%2Fopa.sock"

  system_authz_rego = <<-REGO
    package system.authz

    import rego.v1

    # Runtime policy-store immutability (R-15, F-19):
    # OPA runs over an in-pod Unix socket with --authorization=basic.
    # Never allow PUT, PATCH, or DELETE on /v1/policies or /v1/data,
    # root /v1/data dumps, /v1/data/system/* queries, or ad-hoc compile/query.
    default allow := false

    # Health probes over the Unix socket.
    allow if {
    	input.method == "GET"
    	count(input.path) >= 1
    	input.path[0] == "health"
    }

    # Gateway startup policy handshake (OPAClient.verify_domain_policy).
    allow if {
    	input.method == "GET"
    	input.path == ["v1", "policies"]
    }

    # Read-only policy decisions on active domain packages
    # (e.g. POST/GET /v1/data/trade/governance and ?explain=full).
    allow if {
    	input.method in {"GET", "POST"}
    	count(input.path) >= 3
    	input.path[0] == "v1"
    	input.path[1] == "data"
    	input.path[2] != "system"
    }
  REGO

  bundle_sha256 = sha256(jsonencode({
    create_policy_configmap = var.create_policy_configmap
    create_config_configmap = var.create_config_configmap
    policy_files            = var.policy_files
    opa_config              = var.opa_config
    system_authz            = local.system_authz_rego
  }))
}

# Read-only domain policy ConfigMap consumed by the gateway pod's OPA sidecar.
resource "kubernetes_config_map" "opa_policies" {
  count = var.create_policy_configmap ? 1 : 0

  metadata {
    name      = "opa-policies"
    namespace = var.namespace
    labels = {
      app                           = "gateway"
      component                     = "opa-policy"
      "compliance.iso42001/enabled" = "true"
      "compliance.iso42001/version" = "2023"
    }
    annotations = {
      "compliance.iso42001/controls" = "A.5.3,SC-4,A.9.2,A.5.2,AC-3"
    }
  }

  data = var.policy_files

  lifecycle {
    precondition {
      condition     = length(var.policy_files) > 0
      error_message = "OPA policy bundle cannot be empty; the active cage_domain must ship at least one non-test .rego policy under src/cage_<domain>/opa/ (POAM-2026-198)."
    }
  }
}

# Built-in system.authz module enforcing runtime policy/data immutability (R-15).
resource "kubernetes_config_map" "opa_system_authz" {
  metadata {
    name      = "opa-system-authz"
    namespace = var.namespace
    labels = {
      app                           = "gateway"
      component                     = "opa-system-authz"
      "compliance.iso42001/enabled" = "true"
      "compliance.iso42001/version" = "2023"
    }
    annotations = {
      "compliance.iso42001/controls" = "A.5.3,SC-4,A.9.2,A.5.2,AC-3"
    }
  }

  data = {
    "system_authz.rego" = local.system_authz_rego
  }
}

# OPA server configuration (console decision logs enabled per F-102).
resource "kubernetes_config_map" "opa_config" {
  count = var.create_config_configmap ? 1 : 0

  metadata {
    name      = "opa-config"
    namespace = var.namespace
    labels = {
      app                           = "gateway"
      component                     = "opa-config"
      "compliance.iso42001/enabled" = "true"
      "compliance.iso42001/version" = "2023"
    }
    annotations = {
      "compliance.iso42001/controls" = "A.5.3,SC-4,A.9.2,A.5.2,AU-12"
    }
  }

  data = {
    "opa_config.yaml" = var.opa_config
  }
}
