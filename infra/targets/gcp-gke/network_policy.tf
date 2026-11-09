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

# ─── Per-Workload NetworkPolicy & GKE FQDNNetworkPolicy Segmentation ──────────
# Enforces default-deny ingress + default-deny egress + explicit per-workload
# pod-to-pod and data-store NetworkPolicies on GKE Dataplane V2 across every
# posture (POAM-2026-195, POAM-2026-190, F-16..F-20, R-16, F-103).
#
# Architectural invariants (§5.3, §7, POAM-2026-195):
#   1. Only `default-deny-ingress` and `default-deny-external-egress` carry an
#      empty `pod_selector {}`, and both carry ZERO allow blocks. Blanket
#      intra-namespace `pod_selector {}` allows and blanket `datastore-egress`
#      are eliminated (`F-16`..`F-20`).
#   2. Governance Valkey (`local.governance_valkey_cidr`, TCP 6379) is granted
#      ONLY to `gateway`, `compliance-bridge`, and `reconciliation-worker`.
#   3. App Valkey (`local.app_valkey_cidr`, TCP 6379) and Cloud SQL private IP
#      (`local.cloud_sql_cidr`, TCP 3307/5432) are granted ONLY to
#      `langfuse-web` and `langfuse-worker`.
#   4. `vllm` (`app in ["vllm-inference", "vllm-reasoning"]`, TCP 8000) admits
#      ingress ONLY from `app = "gateway"` (`R-16`, `F-103`). All model calls
#      must traverse the gateway inference proxy; `governed-financial-advisor`
#      has zero direct egress/ingress path to `vllm`, `opa`, `compliance-bridge`,
#      `clickhouse`, Cloud SQL, or either Memorystore instance.
#   5. DNS egress is restricted strictly to `kube-system` (`kube-dns`,
#      `node-local-dns`) and `var.kube_dns_cidr` on UDP/TCP 53 (never 0.0.0.0/0);
#      Linkerd sidecar control-plane bootstrap egress is scoped to namespace
#      `linkerd` on TCP 8080 (identity), 8086 (destination), and 8090 (policy).
#   6. Every policy spec participates in `local.network_policy_spec_hash` so
#      tightening any rule rolls pods to sever pre-existing connections.

locals {
  # Derived /32 data-store egress CIDRs from the live resource endpoints (POAM-2026-190).
  governance_valkey_cidr = "${module.memorystore_governance.primary_endpoint_ip}/32"
  app_valkey_cidr        = "${module.memorystore_app.primary_endpoint_ip}/32"
  cloud_sql_cidr         = "${module.cloudsql_postgres.private_ip_address}/32"

  # Opt every NetworkPolicy into GKE Dataplane V2 policy-action logging when active (D-195-4).
  network_policy_logging_annotation = local.dataplane_v2_network_logging_active ? {
    "policy.network.gke.io/enable-logging" = "true"
  } : {}

  # Canonical GKE FQDNNetworkPolicy (networking.gke.io/v1alpha1) manifests.
  # Parameterized strictly by tfvars FQDNs; identical structure in every posture,
  # plus the prod/HA ClickHouse cold-tier GCS FQDN rule when enabled.
  fqdn_network_policies = merge(
    {
      gateway_egress_fqdn_allowlist = {
        apiVersion = "networking.gke.io/v1alpha1"
        kind       = "FQDNNetworkPolicy"
        metadata = {
          name      = "gateway-egress-fqdn-allowlist"
          namespace = module.namespace.name
          labels = {
            "app.kubernetes.io/managed-by" = "terraform"
            "cage.io/component"            = "z3n-egress"
          }
          annotations = {
            "compliance.nist.gov/control"  = "SC-7,AC-4,SI-3"
            "compliance.nist.gov/standard" = "SP-800-53-Rev5"
            "cage.io/poam"                 = "POAM-007,POAM-011,POAM-2026-195"
          }
        }
        spec = {
          podSelector = {
            matchLabels = {
              app = "gateway"
            }
          }
          egress = [
            {
              matches = [
                for fqdn in var.gateway_egress_allowed_fqdns : (
                  can(regex("[*]", fqdn))
                  ? { pattern = fqdn, name = null }
                  : { name = fqdn, pattern = null }
                )
              ]
              ports = [
                {
                  protocol = "TCP"
                  port     = 443
                }
              ]
            }
          ]
        }
      }

      compliance_bridge_egress_fqdn = {
        apiVersion = "networking.gke.io/v1alpha1"
        kind       = "FQDNNetworkPolicy"
        metadata = {
          name      = "compliance-bridge-egress-fqdn"
          namespace = module.namespace.name
          labels = {
            "app.kubernetes.io/managed-by" = "terraform"
            "cage.io/component"            = "z3n-egress"
          }
          annotations = {
            "compliance.nist.gov/control"  = "SC-7,AC-4,AU-9"
            "compliance.nist.gov/standard" = "SP-800-53-Rev5"
            "cage.io/poam"                 = "POAM-2026-195"
          }
        }
        spec = {
          podSelector = {
            matchLabels = {
              app = "compliance-bridge"
            }
          }
          egress = [
            {
              matches = [
                for fqdn in var.compliance_bridge_egress_allowed_fqdns : (
                  can(regex("[*]", fqdn))
                  ? { pattern = fqdn, name = null }
                  : { name = fqdn, pattern = null }
                )
              ]
              ports = [
                {
                  protocol = "TCP"
                  port     = 443
                }
              ]
            }
          ]
        }
      }

      reconciliation_worker_egress_fqdn = {
        apiVersion = "networking.gke.io/v1alpha1"
        kind       = "FQDNNetworkPolicy"
        metadata = {
          name      = "reconciliation-worker-egress-fqdn"
          namespace = module.namespace.name
          labels = {
            app                            = "reconciliation-worker"
            "app.kubernetes.io/managed-by" = "terraform"
            "cage.io/component"            = "z3n-egress"
          }
          annotations = {
            "compliance.nist.gov/control"  = "SC-7,AC-4"
            "compliance.nist.gov/standard" = "SP-800-53-Rev5"
            "cage.io/poam"                 = "POAM-2026-195"
          }
        }
        spec = {
          podSelector = {
            matchLabels = {
              app                       = "reconciliation-worker"
              "cage.io/account-purpose" = "ledger-reconciliation"
            }
          }
          egress = [
            {
              matches = [
                for fqdn in var.reconciler_egress_allowed_fqdns : (
                  can(regex("[*]", fqdn))
                  ? { pattern = fqdn, name = null }
                  : { name = fqdn, pattern = null }
                )
              ]
              ports = [
                {
                  protocol = "TCP"
                  port     = 443
                }
              ]
            }
          ]
        }
      }



      vllm_egress_fqdn = {
        apiVersion = "networking.gke.io/v1alpha1"
        kind       = "FQDNNetworkPolicy"
        metadata = {
          name      = "vllm-egress-fqdn"
          namespace = module.namespace.name
          labels = {
            "app.kubernetes.io/managed-by" = "terraform"
            "cage.io/component"            = "z3n-egress"
          }
          annotations = {
            "compliance.nist.gov/control"  = "SC-7,AC-4,IA-2"
            "compliance.nist.gov/standard" = "SP-800-53-Rev5"
            "cage.io/poam"                 = "POAM-007,POAM-011,POAM-2026-082,POAM-2026-195"
          }
        }
        spec = {
          podSelector = {
            matchExpressions = [
              {
                key      = "app"
                operator = "In"
                values   = ["vllm-inference", "vllm-reasoning", "inference-stub"]
              }
            ]
          }
          egress = [
            {
              matches = [
                for fqdn in var.vllm_egress_allowed_fqdns : (
                  can(regex("[*]", fqdn))
                  ? { pattern = fqdn, name = null }
                  : { name = fqdn, pattern = null }
                )
              ]
              ports = [
                {
                  protocol = "TCP"
                  port     = 443
                }
              ]
            }
          ]
        }
      }

      langfuse_egress_fqdn = {
        apiVersion = "networking.gke.io/v1alpha1"
        kind       = "FQDNNetworkPolicy"
        metadata = {
          name      = "langfuse-egress-fqdn"
          namespace = module.namespace.name
          labels = {
            "app.kubernetes.io/managed-by" = "terraform"
            "cage.io/component"            = "z3n-egress"
          }
          annotations = {
            "compliance.nist.gov/control"  = "SC-7,AC-4,AU-9"
            "compliance.nist.gov/standard" = "SP-800-53-Rev5"
            "cage.io/poam"                 = "POAM-2026-195"
          }
        }
        spec = {
          podSelector = {
            matchExpressions = [
              {
                key      = "app"
                operator = "In"
                values   = ["langfuse-web", "langfuse-worker"]
              }
            ]
          }
          egress = [
            {
              matches = [
                { name = "storage.googleapis.com", pattern = null },
                { name = "sqladmin.googleapis.com", pattern = null },
                { name = "oauth2.googleapis.com", pattern = null },
              ]
              ports = [
                {
                  protocol = "TCP"
                  port     = 443
                }
              ]
            }
          ]
        }
      }
    },
    local.clickhouse_cold_tier_enabled ? {
      clickhouse_egress_fqdn = {
        apiVersion = "networking.gke.io/v1alpha1"
        kind       = "FQDNNetworkPolicy"
        metadata = {
          name      = "clickhouse-egress-fqdn"
          namespace = module.namespace.name
          labels = {
            "app.kubernetes.io/managed-by" = "terraform"
            "cage.io/component"            = "z3n-egress"
          }
          annotations = {
            "compliance.nist.gov/control"  = "SC-7,AC-4,AU-9"
            "compliance.nist.gov/standard" = "SP-800-53-Rev5"
            "cage.io/poam"                 = "POAM-2026-195"
          }
        }
        spec = {
          podSelector = {
            matchLabels = {
              app = "clickhouse"
            }
          }
          egress = [
            {
              matches = [
                { name = "storage.googleapis.com", pattern = null },
              ]
              ports = [
                {
                  protocol = "TCP"
                  port     = 443
                }
              ]
            }
          ]
        }
      }
    } : {},
  )

  # Canonical L3/L4 segmentation summary hashed into `network_policy_spec_hash`
  # so any change to ingress callers, egress targets, ports, or conditional
  # toggles triggers workload rollout restarts (§5.3, §7, POAM-2026-195).
  network_policy_l3_l4_matrix = {
    schema_version       = "v3-pr7b-per-workload-segmentation"
    namespace            = module.namespace.name
    clickhouse_cold_tier = local.clickhouse_cold_tier_enabled
    default_deny = {
      ingress = "default-deny-ingress"
      egress  = "default-deny-external-egress"
    }
    ingress = {
      gateway           = { advisor = [8080, 50051, 4143], sovereign_agent = [8080, 50051, 4143], compliance_bridge = [8080, 4143], gmp = [9090, 4191] }
      vllm              = { gateway = [8000, 4143] }
      compliance_bridge = { gateway = [3001, 4143] }
      langfuse_web      = { callers = ["gateway", "compliance-bridge", "governed-financial-advisor", "reconciliation-worker", "langfuse-worker"], ports = [3000, 4143] }
      clickhouse        = { http_8123 = ["compliance-bridge", "langfuse-web", "langfuse-worker", "clickhouse"], tcp_9000 = ["langfuse-web", "langfuse-worker", "clickhouse"], interserver_9009 = ["clickhouse"] }
      clickhouse_keeper = { client_9181 = ["clickhouse", "clickhouse-keeper"], raft_9234 = ["clickhouse-keeper"] }
    }
    datastore_egress_holders = {
      governance_valkey = ["gateway", "compliance-bridge", "reconciliation-worker"]
      app_valkey        = ["langfuse-web", "langfuse-worker"]
      cloud_sql         = ["langfuse-web", "langfuse-worker"]
    }
  }

  # Digest of all NetworkPolicy + FQDNNetworkPolicy parameters.
  # Any change to CIDRs, FQDNs, or policy rules changes this digest and forces
  # a rollout restart of selected workloads (§5.3, §7).
  network_policy_spec_hash = sha256(jsonencode({
    governance_psc_cidr = local.governance_valkey_cidr
    app_psc_cidr        = local.app_valkey_cidr
    cloud_sql_cidr      = local.cloud_sql_cidr
    kube_dns_cidr       = var.kube_dns_cidr
    fqdn_policies       = local.fqdn_network_policies
    l3_l4_policies      = local.network_policy_l3_l4_matrix
  }))
}

# ─── 1a. Pure Default-Deny Ingress (SC-7, SC-8, Lula `default-deny-ingress`) ──
# Zero `ingress` blocks: every inbound pod connection in governance-stack is
# denied unless explicitly permitted by a workload-scoped `*_ingress` policy below.
# GKE Dataplane V2 automatically permits node kubelet probes configured on Pod specs.

resource "kubernetes_network_policy_v1" "default_deny_ingress" {
  metadata {
    name      = "default-deny-ingress"
    namespace = module.namespace.name
    labels = {
      "app.kubernetes.io/managed-by" = "terraform"
      "cage.io/component"            = "z3n-ingress"
    }
    annotations = merge(
      {
        "compliance.nist.gov/control"  = "SC-7,SC-8,AC-4"
        "compliance.nist.gov/standard" = "SP-800-53-Rev5"
        "cage.io/poam"                 = "POAM-2026-195"
      },
      local.network_policy_logging_annotation,
    )
  }

  spec {
    pod_selector {}
    policy_types = ["Ingress"]
  }
}

# ─── 1b. Pure Default-Deny Egress (SC-7, AC-4, POAM-2026-195) ─────────────────
# Zero `egress` blocks: every outbound connection (both intra-namespace and
# cluster-external) is denied unless explicitly permitted by a workload-scoped
# egress NetworkPolicy or FQDNNetworkPolicy below. Replaces both the former
# intra-namespace `to { pod_selector {} }` wildcard (`F-18`) and the temporary
# namespace-wide `datastore-egress` policy (`F-16`, `F-20`, `POAM-2026-195`).

resource "kubernetes_network_policy_v1" "default_deny_external_egress" {
  metadata {
    name      = "default-deny-external-egress"
    namespace = module.namespace.name
    labels = {
      "app.kubernetes.io/managed-by" = "terraform"
      "cage.io/component"            = "z3n-egress"
    }
    annotations = merge(
      {
        "compliance.nist.gov/control"  = "SC-7,AC-4"
        "compliance.nist.gov/standard" = "SP-800-53-Rev5"
        "cage.io/poam"                 = "POAM-2026-195"
      },
      local.network_policy_logging_annotation,
    )
  }

  spec {
    pod_selector {}
    policy_types = ["Egress"]
  }
}

# ─── 2a. Gateway Ingress ──────────────────────────────────────────────────────
# Admits:
#   - `governed-financial-advisor` and `role = "sovereign-agent"` on HTTP 8080,
#     gRPC 50051, and Linkerd inbound proxy 4143;
#   - `compliance-bridge` on HTTP 8080 / 4143;
#   - GKE Managed Prometheus collectors (`gmp-system`, `kube-system`) strictly on
#     metrics port 9090 and Linkerd proxy admin/metrics port 4191 (never 8080/50051).

resource "kubernetes_network_policy_v1" "gateway_ingress" {
  metadata {
    name      = "gateway-ingress-allow"
    namespace = module.namespace.name
    labels = {
      "app.kubernetes.io/managed-by" = "terraform"
      "cage.io/component"            = "z3n-ingress"
    }
    annotations = merge(
      {
        "compliance.nist.gov/control"  = "SC-7,AC-4"
        "compliance.nist.gov/standard" = "SP-800-53-Rev5"
        "cage.io/poam"                 = "POAM-2026-195"
      },
      local.network_policy_logging_annotation,
    )
  }

  spec {
    pod_selector {
      match_labels = {
        app = "gateway"
      }
    }
    policy_types = ["Ingress"]

    ingress {
      from {
        pod_selector {
          match_labels = {
            app = "governed-financial-advisor"
          }
        }
      }
      ports {
        protocol = "TCP"
        port     = "8080"
      }
      ports {
        protocol = "TCP"
        port     = "50051"
      }
      ports {
        protocol = "TCP"
        port     = "4143"
      }
    }

    ingress {
      from {
        pod_selector {
          match_labels = {
            app = "compliance-bridge"
          }
        }
      }
      from {
        pod_selector {
          match_labels = {
            app = "lula-audit"
          }
        }
      }
      ports {
        protocol = "TCP"
        port     = "8080"
      }
      ports {
        protocol = "TCP"
        port     = "4143"
      }
    }

    # GKE Managed Prometheus scrape (AU-12): metrics ports 9090 / 4191 ONLY.
    ingress {
      from {
        namespace_selector {
          match_expressions {
            key      = "kubernetes.io/metadata.name"
            operator = "In"
            values   = ["gmp-system", "kube-system"]
          }
        }
      }
      ports {
        protocol = "TCP"
        port     = "9090"
      }
      ports {
        protocol = "TCP"
        port     = "4191"
      }
    }
  }
}

# ─── 2b. Gateway L3/L4 Egress (DNS + Mesh CP + Governance Valkey + Internal) ──

resource "kubernetes_network_policy_v1" "gateway_egress_l3_l4" {
  metadata {
    name      = "gateway-egress-l3-l4"
    namespace = module.namespace.name
    labels = {
      "app.kubernetes.io/managed-by" = "terraform"
      "cage.io/component"            = "z3n-egress"
    }
    annotations = merge(
      {
        "compliance.nist.gov/control"  = "SC-7,AC-4,SI-3"
        "compliance.nist.gov/standard" = "SP-800-53-Rev5"
        "cage.io/poam"                 = "POAM-007,POAM-011,POAM-2026-195"
      },
      local.network_policy_logging_annotation,
    )
  }

  spec {
    pod_selector {
      match_labels = {
        app = "gateway"
      }
    }
    policy_types = ["Egress"]

    # DNS resolution — kube-dns, node-local-dns, and Cloud DNS only (§5.3, §7)
    egress {
      to {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = "kube-system"
          }
        }
        pod_selector {
          match_labels = {
            "k8s-app" = "kube-dns"
          }
        }
      }
      to {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = "kube-system"
          }
        }
        pod_selector {
          match_labels = {
            "k8s-app" = "node-local-dns"
          }
        }
      }
      to {
        ip_block {
          cidr = var.kube_dns_cidr
        }
      }
      ports {
        protocol = "UDP"
        port     = "53"
      }
      ports {
        protocol = "TCP"
        port     = "53"
      }
    }

    # Linkerd control plane (identity 8080, destination 8086, policy 8090)
    egress {
      to {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = "linkerd"
          }
        }
      }
      ports {
        protocol = "TCP"
        port     = "8080"
      }
      ports {
        protocol = "TCP"
        port     = "8086"
      }
      ports {
        protocol = "TCP"
        port     = "8090"
      }
    }

    # §5.3 / POAM-2026-195: Memorystore GOVERNANCE PSC endpoint (/32) ONLY on 6379
    egress {
      to {
        ip_block {
          cidr = local.governance_valkey_cidr
        }
      }
      ports {
        protocol = "TCP"
        port     = "6379"
      }
    }

    # OPA policy evaluation (kept narrow to gateway only until PR-7a moves OPA to UDS)
    egress {
      ports {
        protocol = "TCP"
        port     = "4143"
      }
    }

    # Compliance bridge internal API (container port 3001 + Linkerd inbound 4143)
    egress {
      to {
        pod_selector {
          match_labels = {
            app = "compliance-bridge"
          }
        }
      }
      ports {
        protocol = "TCP"
        port     = "3001"
      }
      ports {
        protocol = "TCP"
        port     = "4143"
      }
    }

    # vLLM model backends — gateway is the SOLE caller allowed to reach vLLM (R-16, F-103)
    egress {
      to {
        pod_selector {
          match_expressions {
            key      = "app"
            operator = "In"
            values   = ["vllm-inference", "vllm-reasoning", "inference-stub"]
          }
        }
      }
      ports {
        protocol = "TCP"
        port     = "8000"
      }
      ports {
        protocol = "TCP"
        port     = "4143"
      }
    }

    # Langfuse OTLP trace ingestion (port 3000 + Linkerd inbound 4143)
    egress {
      to {
        pod_selector {
          match_labels = {
            app = "langfuse-web"
          }
        }
      }
      ports {
        protocol = "TCP"
        port     = "3000"
      }
      ports {
        protocol = "TCP"
        port     = "4143"
      }
    }

    # GKE compute metadata server (HTTP 80) for Workload Identity (KMS signing / IAM Valkey)
    egress {
      to {
        ip_block {
          cidr = "169.254.169.254/32"
        }
      }
      ports {
        protocol = "TCP"
        port     = "80"
      }
    }

    # GKE Workload Identity metadata server (TCP 988)
    egress {
      to {
        ip_block {
          cidr = "169.254.169.252/32"
        }
      }
      ports {
        protocol = "TCP"
        port     = "988"
      }
    }
  }
}

# ─── 3a. vLLM Ingress — Gateway ONLY (R-16, F-103, POAM-2026-195) ─────────────
# Strictly restricts vLLM (`vllm-inference`, `vllm-reasoning`) port 8000 ingress
# to `app = "gateway"` ONLY. `governed-financial-advisor` and every non-gateway
# workload are denied direct access so all inference traverses `TokenQuotaProxy`
# and Stage-1 governance rails on the gateway inference proxy.

resource "kubernetes_network_policy_v1" "model_backend_ingress" {
  metadata {
    name      = "vllm-ingress-gateway-only"
    namespace = module.namespace.name
    labels = {
      "app.kubernetes.io/managed-by" = "terraform"
      "cage.io/component"            = "z3n-ingress"
    }
    annotations = merge(
      {
        "compliance.nist.gov/control"  = "SC-7,AC-3,AC-4"
        "compliance.nist.gov/standard" = "SP-800-53-Rev5"
        "cage.io/poam"                 = "POAM-2026-080,POAM-2026-195"
      },
      local.network_policy_logging_annotation,
    )
  }

  spec {
    pod_selector {
      match_expressions {
        key      = "app"
        operator = "In"
        values   = ["vllm-inference", "vllm-reasoning", "inference-stub"]
      }
    }
    policy_types = ["Ingress"]

    ingress {
      from {
        pod_selector {
          match_labels = {
            app = "gateway"
          }
        }
      }
      ports {
        protocol = "TCP"
        port     = "8000"
      }
      ports {
        protocol = "TCP"
        port     = "4143"
      }
    }
  }
}

# ─── 3b. vLLM L3/L4 Egress (DNS + Mesh CP + Workload Identity Metadata ONLY) ──
# Zero pod-to-pod egress and zero data-store egress (GCS weights via vllm_egress_fqdn).

resource "kubernetes_network_policy_v1" "vllm_egress_l3_l4" {
  metadata {
    name      = "vllm-egress-l3-l4"
    namespace = module.namespace.name
    labels = {
      "app.kubernetes.io/managed-by" = "terraform"
      "cage.io/component"            = "z3n-egress"
    }
    annotations = merge(
      {
        "compliance.nist.gov/control"  = "SC-7,AC-4,IA-2"
        "compliance.nist.gov/standard" = "SP-800-53-Rev5"
        "cage.io/poam"                 = "POAM-007,POAM-011,POAM-2026-082,POAM-2026-195"
      },
      local.network_policy_logging_annotation,
    )
  }

  spec {
    pod_selector {
      match_expressions {
        key      = "app"
        operator = "In"
        values   = ["vllm-inference", "vllm-reasoning", "inference-stub"]
      }
    }
    policy_types = ["Egress"]

    # DNS — kube-dns, node-local-dns, and Cloud DNS (var.kube_dns_cidr) only
    egress {
      to {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = "kube-system"
          }
        }
        pod_selector {
          match_labels = {
            "k8s-app" = "kube-dns"
          }
        }
      }
      to {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = "kube-system"
          }
        }
        pod_selector {
          match_labels = {
            "k8s-app" = "node-local-dns"
          }
        }
      }
      to {
        ip_block {
          cidr = var.kube_dns_cidr
        }
      }
      ports {
        protocol = "UDP"
        port     = "53"
      }
      ports {
        protocol = "TCP"
        port     = "53"
      }
    }

    # Linkerd control plane (identity 8080, destination 8086, policy 8090)
    egress {
      to {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = "linkerd"
          }
        }
      }
      ports {
        protocol = "TCP"
        port     = "8080"
      }
      ports {
        protocol = "TCP"
        port     = "8086"
      }
      ports {
        protocol = "TCP"
        port     = "8090"
      }
    }

    # GKE compute metadata server (HTTP 80) for Workload Identity (GCS model weights)
    egress {
      to {
        ip_block {
          cidr = "169.254.169.254/32"
        }
      }
      ports {
        protocol = "TCP"
        port     = "80"
      }
    }

    # GKE Workload Identity metadata server (TCP 988)
    egress {
      to {
        ip_block {
          cidr = "169.254.169.252/32"
        }
      }
      ports {
        protocol = "TCP"
        port     = "988"
      }
    }
  }
}

# ─── 4a. Compliance Bridge Ingress ────────────────────────────────────────────

resource "kubernetes_network_policy_v1" "compliance_bridge_ingress" {
  metadata {
    name      = "compliance-bridge-ingress-allow"
    namespace = module.namespace.name
    labels = {
      "app.kubernetes.io/managed-by" = "terraform"
      "cage.io/component"            = "z3n-ingress"
    }
    annotations = merge(
      {
        "compliance.nist.gov/control"  = "SC-7,AC-4,AU-9"
        "compliance.nist.gov/standard" = "SP-800-53-Rev5"
        "cage.io/poam"                 = "POAM-2026-195"
      },
      local.network_policy_logging_annotation,
    )
  }

  spec {
    pod_selector {
      match_labels = {
        app = "compliance-bridge"
      }
    }
    policy_types = ["Ingress"]

    ingress {
      from {
        pod_selector {
          match_labels = {
            app = "gateway"
          }
        }
      }
      from {
        pod_selector {
          match_labels = {
            app = "lula-audit"
          }
        }
      }
      ports {
        protocol = "TCP"
        port     = "3001"
      }
      ports {
        protocol = "TCP"
        port     = "4143"
      }
    }

    # GKE Managed Prometheus scrape (CA-7 / AU-12): metrics ports 9090 / 4191 ONLY.
    ingress {
      from {
        namespace_selector {
          match_expressions {
            key      = "kubernetes.io/metadata.name"
            operator = "In"
            values   = ["gmp-system", "kube-system"]
          }
        }
      }
      ports {
        protocol = "TCP"
        port     = "9090"
      }
      ports {
        protocol = "TCP"
        port     = "4191"
      }
    }
  }
}

# ─── 4b. Compliance Bridge L3/L4 Egress ───────────────────────────────────────
# EvidenceCustodian reads the gateway's evidence stream and persists its custody
# cursor on the GOVERNANCE Valkey instance (`local.governance_valkey_cidr:6379`),
# writes INSERT-only analytical rows to ClickHouse HTTP (`8123`), exports/queries
# compliance traces on `langfuse-web` (`3000`), and reaches GCS WORM / Cloud KMS
# over HTTPS 443 via `compliance_bridge_egress_fqdn`.

resource "kubernetes_network_policy_v1" "compliance_bridge_egress_l3_l4" {
  metadata {
    name      = "compliance-bridge-egress-l3-l4"
    namespace = module.namespace.name
    labels = {
      "app.kubernetes.io/managed-by" = "terraform"
      "cage.io/component"            = "z3n-egress"
    }
    annotations = merge(
      {
        "compliance.nist.gov/control"  = "SC-7,AC-4,AU-9"
        "compliance.nist.gov/standard" = "SP-800-53-Rev5"
        "cage.io/poam"                 = "POAM-2026-195"
      },
      local.network_policy_logging_annotation,
    )
  }

  spec {
    pod_selector {
      match_labels = {
        app = "compliance-bridge"
      }
    }
    policy_types = ["Egress"]

    # DNS resolution — kube-dns, node-local-dns, and Cloud DNS only
    egress {
      to {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = "kube-system"
          }
        }
        pod_selector {
          match_labels = {
            "k8s-app" = "kube-dns"
          }
        }
      }
      to {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = "kube-system"
          }
        }
        pod_selector {
          match_labels = {
            "k8s-app" = "node-local-dns"
          }
        }
      }
      to {
        ip_block {
          cidr = var.kube_dns_cidr
        }
      }
      ports {
        protocol = "UDP"
        port     = "53"
      }
      ports {
        protocol = "TCP"
        port     = "53"
      }
    }

    # Linkerd control plane
    egress {
      to {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = "linkerd"
          }
        }
      }
      ports {
        protocol = "TCP"
        port     = "8080"
      }
      ports {
        protocol = "TCP"
        port     = "8086"
      }
      ports {
        protocol = "TCP"
        port     = "8090"
      }
    }

    # §5.3 / POAM-2026-195: Memorystore governance PSC endpoint CIDR on TLS port 6379
    egress {
      to {
        ip_block {
          cidr = local.governance_valkey_cidr
        }
      }
      ports {
        protocol = "TCP"
        port     = "6379"
      }
    }

    # ClickHouse INSERT-only analytical sink over HTTP 8123 (never native admin 9000)
    egress {
      to {
        pod_selector {
          match_labels = {
            app = "clickhouse"
          }
        }
      }
      ports {
        protocol = "TCP"
        port     = "8123"
      }
      ports {
        protocol = "TCP"
        port     = "4143"
      }
    }

    # Langfuse compliance project API / OTLP (port 3000)
    egress {
      to {
        pod_selector {
          match_labels = {
            app = "langfuse-web"
          }
        }
      }
      ports {
        protocol = "TCP"
        port     = "3000"
      }
      ports {
        protocol = "TCP"
        port     = "4143"
      }
    }

    # Gateway inference proxy / health (never direct vLLM — R-16, F-103)
    egress {
      to {
        pod_selector {
          match_labels = {
            app = "gateway"
          }
        }
      }
      ports {
        protocol = "TCP"
        port     = "8080"
      }
      ports {
        protocol = "TCP"
        port     = "4143"
      }
    }

    # GKE compute metadata server (HTTP 80) for Workload Identity (WORM GCS + KMS)
    egress {
      to {
        ip_block {
          cidr = "169.254.169.254/32"
        }
      }
      ports {
        protocol = "TCP"
        port     = "80"
      }
    }

    # GKE Workload Identity metadata server (TCP 988)
    egress {
      to {
        ip_block {
          cidr = "169.254.169.252/32"
        }
      }
      ports {
        protocol = "TCP"
        port     = "988"
      }
    }
  }
}

# ─── 5. Governed Financial Advisor Internal-Only Egress (POAM-2026-195, R-16) ─
# Untrusted neural advisor plane: reaches ONLY `gateway` (8080/50051/4143),
# `langfuse-web` (3000/4143 OTLP), Linkerd control plane, and kube-dns.
# Strictly NO direct egress to `vllm`, `opa`, `compliance-bridge`, `clickhouse`,
# Cloud SQL, either Memorystore instance, or GKE Workload Identity metadata.

resource "kubernetes_network_policy_v1" "financial_advisor_egress_internal_only" {
  metadata {
    name      = "financial-advisor-egress-internal-only"
    namespace = module.namespace.name
    labels = {
      "app.kubernetes.io/managed-by" = "terraform"
      "cage.io/component"            = "z3n-egress"
    }
    annotations = merge(
      {
        "compliance.nist.gov/control"  = "SC-7,AC-4,SI-3"
        "compliance.nist.gov/standard" = "SP-800-53-Rev5"
        "cage.io/poam"                 = "POAM-007,POAM-2026-195"
      },
      local.network_policy_logging_annotation,
    )
  }

  spec {
    pod_selector {
      match_labels = {
        app = "governed-financial-advisor"
      }
    }
    policy_types = ["Egress"]

    # DNS — kube-dns, node-local-dns, and Cloud DNS only (§5.3, §7)
    egress {
      to {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = "kube-system"
          }
        }
        pod_selector {
          match_labels = {
            "k8s-app" = "kube-dns"
          }
        }
      }
      to {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = "kube-system"
          }
        }
        pod_selector {
          match_labels = {
            "k8s-app" = "node-local-dns"
          }
        }
      }
      to {
        ip_block {
          cidr = var.kube_dns_cidr
        }
      }
      ports {
        protocol = "UDP"
        port     = "53"
      }
      ports {
        protocol = "TCP"
        port     = "53"
      }
    }

    # Linkerd control plane
    egress {
      to {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = "linkerd"
          }
        }
      }
      ports {
        protocol = "TCP"
        port     = "8080"
      }
      ports {
        protocol = "TCP"
        port     = "8086"
      }
      ports {
        protocol = "TCP"
        port     = "8090"
      }
    }

    # CAGE Gateway ONLY (action boundary + `/v1/chat/completions` inference proxy — R-16, F-103)
    egress {
      to {
        pod_selector {
          match_labels = {
            app = "gateway"
          }
        }
      }
      ports {
        protocol = "TCP"
        port     = "8080"
      }
      ports {
        protocol = "TCP"
        port     = "50051"
      }
      ports {
        protocol = "TCP"
        port     = "4143"
      }
    }

    # Langfuse v3 OTLP trace ingestion
    egress {
      to {
        pod_selector {
          match_labels = {
            app = "langfuse-web"
          }
        }
      }
      ports {
        protocol = "TCP"
        port     = "3000"
      }
      ports {
        protocol = "TCP"
        port     = "4143"
      }
    }
  }
}

# ─── 6. Sovereign Agent Internal-Only Egress (§5.3, F-19, POAM-2026-195) ──────
# Direct OPA egress (`app = "opa"`) removed (`F-19`); agents talk solely to `gateway`.


# ─── 7. Reconciliation Worker Egress Isolation (C7, §5.3, §7, POAM-2026-195) ──

resource "kubernetes_network_policy_v1" "reconciliation_worker_egress" {
  metadata {
    name      = "reconciliation-worker-egress"
    namespace = module.namespace.name
    labels = {
      app                            = "reconciliation-worker"
      "app.kubernetes.io/managed-by" = "terraform"
      "cage.io/component"            = "z3n-egress"
    }
    annotations = merge(
      {
        "compliance.nist.gov/control"  = "SC-7,AC-4"
        "compliance.nist.gov/standard" = "SP-800-53-Rev5"
        "cage.io/poam"                 = "POAM-2026-195"
      },
      local.network_policy_logging_annotation,
    )
  }

  spec {
    pod_selector {
      match_labels = {
        app                       = "reconciliation-worker"
        "cage.io/account-purpose" = "ledger-reconciliation"
      }
    }
    policy_types = ["Ingress", "Egress"]

    # No ingress permitted — worker is outbound-only.

    # 1. DNS resolution — kube-dns, node-local-dns, and Cloud DNS only
    egress {
      to {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = "kube-system"
          }
        }
        pod_selector {
          match_labels = {
            "k8s-app" = "kube-dns"
          }
        }
      }
      to {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = "kube-system"
          }
        }
        pod_selector {
          match_labels = {
            "k8s-app" = "node-local-dns"
          }
        }
      }
      to {
        ip_block {
          cidr = var.kube_dns_cidr
        }
      }
      ports {
        protocol = "UDP"
        port     = "53"
      }
      ports {
        protocol = "TCP"
        port     = "53"
      }
    }

    # 2. Linkerd control plane
    egress {
      to {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = "linkerd"
          }
        }
      }
      ports {
        protocol = "TCP"
        port     = "8080"
      }
      ports {
        protocol = "TCP"
        port     = "8086"
      }
      ports {
        protocol = "TCP"
        port     = "8090"
      }
    }

    # 3. Memorystore governance PSC endpoint CIDR ONLY on TLS port 6379
    egress {
      to {
        ip_block {
          cidr = local.governance_valkey_cidr
        }
      }
      ports {
        protocol = "TCP"
        port     = "6379"
      }
    }

    # 4. Langfuse OTLP trace export (port 3000 + Linkerd inbound 4143)
    egress {
      to {
        pod_selector {
          match_labels = {
            app = "langfuse-web"
          }
        }
      }
      ports {
        protocol = "TCP"
        port     = "3000"
      }
      ports {
        protocol = "TCP"
        port     = "4143"
      }
    }

    # 5. GKE Workload Identity metadata server (KMS snapshot signing + IAM Valkey)
    egress {
      to {
        ip_block {
          cidr = "169.254.169.254/32"
        }
      }
      ports {
        protocol = "TCP"
        port     = "80"
      }
    }

    egress {
      to {
        ip_block {
          cidr = "169.254.169.252/32"
        }
      }
      ports {
        protocol = "TCP"
        port     = "988"
      }
    }
  }
}

# ─── 8a. OPA Ingress — Gateway ONLY (F-19, POAM-2026-080, POAM-2026-195) ──────
# Admits ONLY `app = "gateway"` on HTTP 8181 / Linkerd 4143; diagnostics port
# 8282 and every non-gateway pod (`advisor`, `langfuse`, `vllm`, etc.) are denied.



# ─── 8b. OPA Egress (DNS + Linkerd Control Plane ONLY) ────────────────────────



# ─── 9a. NeMo Guardrails + Presidio Ingress — Gateway ONLY ────────────────────



# ─── 9b. NeMo Guardrails + Presidio Egress (DNS + Mesh CP + Gateway Proxy) ────
# Never connects directly to vLLM (`R-16`, `F-103`).



# ─── 10a. Langfuse Web Ingress (OTLP + Compliance Telemetry API) ──────────────

resource "kubernetes_network_policy_v1" "langfuse_web_ingress" {
  metadata {
    name      = "langfuse-web-ingress-allow"
    namespace = module.namespace.name
    labels = {
      "app.kubernetes.io/managed-by" = "terraform"
      "cage.io/component"            = "z3n-ingress"
    }
    annotations = merge(
      {
        "compliance.nist.gov/control"  = "SC-7,AC-4,AU-9"
        "compliance.nist.gov/standard" = "SP-800-53-Rev5"
        "cage.io/poam"                 = "POAM-2026-195"
      },
      local.network_policy_logging_annotation,
    )
  }

  spec {
    pod_selector {
      match_labels = {
        app = "langfuse-web"
      }
    }
    policy_types = ["Ingress"]

    ingress {
      from {
        pod_selector {
          match_labels = {
            app = "gateway"
          }
        }
      }
      from {
        pod_selector {
          match_labels = {
            app = "compliance-bridge"
          }
        }
      }
      from {
        pod_selector {
          match_labels = {
            app = "governed-financial-advisor"
          }
        }
      }
      from {
        pod_selector {
          match_labels = {
            app = "reconciliation-worker"
          }
        }
      }
      from {
        pod_selector {
          match_labels = {
            app = "langfuse-worker"
          }
        }
      }
      ports {
        protocol = "TCP"
        port     = "3000"
      }
      ports {
        protocol = "TCP"
        port     = "4143"
      }
    }
  }
}

# ─── 10b. Langfuse Web & Worker L3/L4 Egress (F-16, F-20, POAM-2026-195) ──────
# SOLE policy in the namespace granting egress to Cloud SQL (`local.cloud_sql_cidr`,
# TCP 3307/5432) and App Memorystore Valkey (`local.app_valkey_cidr`, TCP 6379).
# Zero access to Governance Valkey, `gateway`, `compliance-bridge`, `opa`, or `vllm`.

resource "kubernetes_network_policy_v1" "langfuse_egress_l3_l4" {
  metadata {
    name      = "langfuse-egress-l3-l4"
    namespace = module.namespace.name
    labels = {
      "app.kubernetes.io/managed-by" = "terraform"
      "cage.io/component"            = "z3n-egress"
    }
    annotations = merge(
      {
        "compliance.nist.gov/control"  = "SC-7,AC-4,AU-9"
        "compliance.nist.gov/standard" = "SP-800-53-Rev5"
        "cage.io/poam"                 = "POAM-2026-190,POAM-2026-195"
      },
      local.network_policy_logging_annotation,
    )
  }

  spec {
    pod_selector {
      match_expressions {
        key      = "app"
        operator = "In"
        values   = ["langfuse-web", "langfuse-worker"]
      }
    }
    policy_types = ["Egress"]

    # DNS — kube-dns, node-local-dns, and Cloud DNS only
    egress {
      to {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = "kube-system"
          }
        }
        pod_selector {
          match_labels = {
            "k8s-app" = "kube-dns"
          }
        }
      }
      to {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = "kube-system"
          }
        }
        pod_selector {
          match_labels = {
            "k8s-app" = "node-local-dns"
          }
        }
      }
      to {
        ip_block {
          cidr = var.kube_dns_cidr
        }
      }
      ports {
        protocol = "UDP"
        port     = "53"
      }
      ports {
        protocol = "TCP"
        port     = "53"
      }
    }

    # Linkerd control plane
    egress {
      to {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = "linkerd"
          }
        }
      }
      ports {
        protocol = "TCP"
        port     = "8080"
      }
      ports {
        protocol = "TCP"
        port     = "8086"
      }
      ports {
        protocol = "TCP"
        port     = "8090"
      }
    }

    # Cloud SQL private IP (/32) ONLY for Langfuse Cloud SQL Auth Proxy (3307, 5432)
    egress {
      to {
        ip_block {
          cidr = local.cloud_sql_cidr
        }
      }
      ports {
        protocol = "TCP"
        port     = "3307"
      }
      ports {
        protocol = "TCP"
        port     = "5432"
      }
    }

    # Memorystore APP Valkey (/32) ONLY for Langfuse queue/cache (6379)
    egress {
      to {
        ip_block {
          cidr = local.app_valkey_cidr
        }
      }
      ports {
        protocol = "TCP"
        port     = "6379"
      }
    }

    # ClickHouse analytical store (HTTP 8123 + native migration TCP 9000 + Linkerd 4143)
    egress {
      to {
        pod_selector {
          match_labels = {
            app = "clickhouse"
          }
        }
      }
      ports {
        protocol = "TCP"
        port     = "8123"
      }
      ports {
        protocol = "TCP"
        port     = "9000"
      }
      ports {
        protocol = "TCP"
        port     = "4143"
      }
    }

    # Allow langfuse-worker -> langfuse-web internal coordination if needed (3000/4143)
    egress {
      to {
        pod_selector {
          match_labels = {
            app = "langfuse-web"
          }
        }
      }
      ports {
        protocol = "TCP"
        port     = "3000"
      }
      ports {
        protocol = "TCP"
        port     = "4143"
      }
    }

    # GKE Workload Identity metadata server (Cloud SQL Auth Proxy `--auto-iam-authn`)
    egress {
      to {
        ip_block {
          cidr = "169.254.169.254/32"
        }
      }
      ports {
        protocol = "TCP"
        port     = "80"
      }
    }

    egress {
      to {
        ip_block {
          cidr = "169.254.169.252/32"
        }
      }
      ports {
        protocol = "TCP"
        port     = "988"
      }
    }
  }
}

# ─── 11a. ClickHouse Query-Plane Ingress (F-16, F-20, POAM-2026-195) ──────────
# Scopes HTTP 8123 to `compliance-bridge`, `langfuse-web`, `langfuse-worker`, and
# peer `clickhouse`; native TCP 9000 to `langfuse-*` and peer `clickhouse`
# (excluding `compliance-bridge`); interserver 9009 strictly to peer `clickhouse`.

resource "kubernetes_network_policy_v1" "clickhouse_ingress" {
  metadata {
    name      = "clickhouse-ingress-allow"
    namespace = module.namespace.name
    labels = {
      "app.kubernetes.io/managed-by" = "terraform"
      "cage.io/component"            = "z3n-ingress"
    }
    annotations = merge(
      {
        "compliance.nist.gov/control"  = "SC-7,AC-3,AC-4,AU-9"
        "compliance.nist.gov/standard" = "SP-800-53-Rev5"
        "cage.io/poam"                 = "POAM-2026-195"
      },
      local.network_policy_logging_annotation,
    )
  }

  spec {
    pod_selector {
      match_labels = {
        app = "clickhouse"
      }
    }
    policy_types = ["Ingress"]

    # HTTP 8123: compliance-bridge (INSERT sink), langfuse-web, langfuse-worker, clickhouse
    ingress {
      from {
        pod_selector {
          match_labels = {
            app = "compliance-bridge"
          }
        }
      }
      from {
        pod_selector {
          match_labels = {
            app = "langfuse-web"
          }
        }
      }
      from {
        pod_selector {
          match_labels = {
            app = "langfuse-worker"
          }
        }
      }
      from {
        pod_selector {
          match_labels = {
            app = "clickhouse"
          }
        }
      }
      ports {
        protocol = "TCP"
        port     = "8123"
      }
      ports {
        protocol = "TCP"
        port     = "4143"
      }
    }

    # Native TCP 9000: langfuse migrations + ClickHouse peers only
    ingress {
      from {
        pod_selector {
          match_labels = {
            app = "langfuse-web"
          }
        }
      }
      from {
        pod_selector {
          match_labels = {
            app = "langfuse-worker"
          }
        }
      }
      from {
        pod_selector {
          match_labels = {
            app = "clickhouse"
          }
        }
      }
      ports {
        protocol = "TCP"
        port     = "9000"
      }
      ports {
        protocol = "TCP"
        port     = "4143"
      }
    }

    # Interserver replication 9009: ClickHouse peers ONLY
    ingress {
      from {
        pod_selector {
          match_labels = {
            app = "clickhouse"
          }
        }
      }
      ports {
        protocol = "TCP"
        port     = "9009"
      }
      ports {
        protocol = "TCP"
        port     = "4143"
      }
    }
  }
}

# ─── 11b. ClickHouse Query-Plane Egress ───────────────────────────────────────

resource "kubernetes_network_policy_v1" "clickhouse_egress_l3_l4" {
  metadata {
    name      = "clickhouse-egress-l3-l4"
    namespace = module.namespace.name
    labels = {
      "app.kubernetes.io/managed-by" = "terraform"
      "cage.io/component"            = "z3n-egress"
    }
    annotations = merge(
      {
        "compliance.nist.gov/control"  = "SC-7,AC-4,AU-9"
        "compliance.nist.gov/standard" = "SP-800-53-Rev5"
        "cage.io/poam"                 = "POAM-2026-195"
      },
      local.network_policy_logging_annotation,
    )
  }

  spec {
    pod_selector {
      match_labels = {
        app = "clickhouse"
      }
    }
    policy_types = ["Egress"]

    # DNS — kube-dns, node-local-dns, and Cloud DNS only
    egress {
      to {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = "kube-system"
          }
        }
        pod_selector {
          match_labels = {
            "k8s-app" = "kube-dns"
          }
        }
      }
      to {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = "kube-system"
          }
        }
        pod_selector {
          match_labels = {
            "k8s-app" = "node-local-dns"
          }
        }
      }
      to {
        ip_block {
          cidr = var.kube_dns_cidr
        }
      }
      ports {
        protocol = "UDP"
        port     = "53"
      }
      ports {
        protocol = "TCP"
        port     = "53"
      }
    }

    # Linkerd control plane
    egress {
      to {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = "linkerd"
          }
        }
      }
      ports {
        protocol = "TCP"
        port     = "8080"
      }
      ports {
        protocol = "TCP"
        port     = "8086"
      }
      ports {
        protocol = "TCP"
        port     = "8090"
      }
    }

    # ReplicatedMergeTree inter-replica communication
    egress {
      to {
        pod_selector {
          match_labels = {
            app = "clickhouse"
          }
        }
      }
      ports {
        protocol = "TCP"
        port     = "8123"
      }
      ports {
        protocol = "TCP"
        port     = "9000"
      }
      ports {
        protocol = "TCP"
        port     = "9009"
      }
      ports {
        protocol = "TCP"
        port     = "4143"
      }
    }

    # ClickHouse Keeper client coordination (9181 + Linkerd 4143)
    egress {
      to {
        pod_selector {
          match_labels = {
            app = "clickhouse-keeper"
          }
        }
      }
      ports {
        protocol = "TCP"
        port     = "9181"
      }
      ports {
        protocol = "TCP"
        port     = "4143"
      }
    }

    # GKE Workload Identity metadata server (ClickHouse GSA)
    egress {
      to {
        ip_block {
          cidr = "169.254.169.254/32"
        }
      }
      ports {
        protocol = "TCP"
        port     = "80"
      }
    }

    egress {
      to {
        ip_block {
          cidr = "169.254.169.252/32"
        }
      }
      ports {
        protocol = "TCP"
        port     = "988"
      }
    }
  }
}

# ─── 11c. ClickHouse Keeper Ingress & Egress ──────────────────────────────────

resource "kubernetes_network_policy_v1" "clickhouse_keeper_ingress" {
  metadata {
    name      = "clickhouse-keeper-ingress-allow"
    namespace = module.namespace.name
    labels = {
      "app.kubernetes.io/managed-by" = "terraform"
      "cage.io/component"            = "z3n-ingress"
    }
    annotations = merge(
      {
        "compliance.nist.gov/control"  = "SC-7,AC-4"
        "compliance.nist.gov/standard" = "SP-800-53-Rev5"
        "cage.io/poam"                 = "POAM-2026-195"
      },
      local.network_policy_logging_annotation,
    )
  }

  spec {
    pod_selector {
      match_labels = {
        app = "clickhouse-keeper"
      }
    }
    policy_types = ["Ingress"]

    ingress {
      from {
        pod_selector {
          match_labels = {
            app = "clickhouse"
          }
        }
      }
      from {
        pod_selector {
          match_labels = {
            app = "clickhouse-keeper"
          }
        }
      }
      ports {
        protocol = "TCP"
        port     = "9181"
      }
      ports {
        protocol = "TCP"
        port     = "4143"
      }
    }

    ingress {
      from {
        pod_selector {
          match_labels = {
            app = "clickhouse-keeper"
          }
        }
      }
      ports {
        protocol = "TCP"
        port     = "9234"
      }
      ports {
        protocol = "TCP"
        port     = "4143"
      }
    }
  }
}

resource "kubernetes_network_policy_v1" "clickhouse_keeper_egress_l3_l4" {
  metadata {
    name      = "clickhouse-keeper-egress-l3-l4"
    namespace = module.namespace.name
    labels = {
      "app.kubernetes.io/managed-by" = "terraform"
      "cage.io/component"            = "z3n-egress"
    }
    annotations = merge(
      {
        "compliance.nist.gov/control"  = "SC-7,AC-4"
        "compliance.nist.gov/standard" = "SP-800-53-Rev5"
        "cage.io/poam"                 = "POAM-2026-195"
      },
      local.network_policy_logging_annotation,
    )
  }

  spec {
    pod_selector {
      match_labels = {
        app = "clickhouse-keeper"
      }
    }
    policy_types = ["Egress"]

    egress {
      to {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = "kube-system"
          }
        }
        pod_selector {
          match_labels = {
            "k8s-app" = "kube-dns"
          }
        }
      }
      to {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = "kube-system"
          }
        }
        pod_selector {
          match_labels = {
            "k8s-app" = "node-local-dns"
          }
        }
      }
      to {
        ip_block {
          cidr = var.kube_dns_cidr
        }
      }
      ports {
        protocol = "UDP"
        port     = "53"
      }
      ports {
        protocol = "TCP"
        port     = "53"
      }
    }

    egress {
      to {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = "linkerd"
          }
        }
      }
      ports {
        protocol = "TCP"
        port     = "8080"
      }
      ports {
        protocol = "TCP"
        port     = "8086"
      }
      ports {
        protocol = "TCP"
        port     = "8090"
      }
    }

    egress {
      to {
        pod_selector {
          match_labels = {
            app = "clickhouse-keeper"
          }
        }
      }
      ports {
        protocol = "TCP"
        port     = "9181"
      }
      ports {
        protocol = "TCP"
        port     = "9234"
      }
      ports {
        protocol = "TCP"
        port     = "4143"
      }
    }
  }
}

# ─── 12. AgentSight UI Egress (DNS + Linkerd Control Plane ONLY) ──────────────
# Zero data-store, model, or control-plane service egress (`F-16`, `POAM-2026-195`).



# ─── 13. Trivy Vulnerability Scanner DNS + Mesh CP Egress (§5.3) ──────────────
# L3/L4 egress scope for the in-cluster Lula auditor CronJob (CA-2, CA-7, SC-7).



# ─── 7. Lula Auditor CronJob Egress Isolation (CA-2, CA-7, SC-7, AC-4) ────────

resource "kubernetes_network_policy_v1" "lula_audit_egress" {
  metadata {
    name      = "lula-audit-egress"
    namespace = module.namespace.name
    labels = {
      app                            = "lula-audit"
      "app.kubernetes.io/managed-by" = "terraform"
      "cage.io/component"            = "z3n-egress"
    }
    annotations = {
      "compliance.nist.gov/control"  = "SC-7,AC-4,CA-7"
      "compliance.nist.gov/standard" = "SP-800-53-Rev5"
    }
  }

  spec {
    pod_selector {
      match_labels = {
        app = "lula-audit"
      }
    }
    policy_types = ["Ingress", "Egress"]

    # No ingress permitted — CronJob auditor initiates outbound checks only.

    # 1. DNS resolution — kube-dns, node-local-dns, and Cloud DNS only (§5.3, §7)
    egress {
      to {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = "kube-system"
          }
        }
        pod_selector {
          match_labels = {
            "k8s-app" = "kube-dns"
          }
        }
      }
      to {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = "kube-system"
          }
        }
        pod_selector {
          match_labels = {
            "k8s-app" = "node-local-dns"
          }
        }
      }
      to {
        ip_block {
          cidr = var.kube_dns_cidr
        }
      }
      ports {
        protocol = "UDP"
        port     = "53"
      }
      ports {
        protocol = "TCP"
        port     = "53"
      }
    }

    # 2. Kubernetes API server (kubernetes domain validations)
    egress {
      to {
        ip_block {
          cidr = "${module.gke.cluster_endpoint}/32"
        }
      }
      to {
        ip_block {
          cidr = var.master_ipv4_cidr_block
        }
      }
      dynamic "to" {
        for_each = var.service_cidr != null ? [var.service_cidr] : []
        content {
          ip_block {
            cidr = to.value
          }
        }
      }
      ports {
        protocol = "TCP"
        port     = "443"
      }
      ports {
        protocol = "TCP"
        port     = "6443"
      }
    }

    # 3. Compliance bridge (api domain validations on 80/3001 + event sealing on 8085 + Linkerd 4143)
    egress {
      to {
        pod_selector {
          match_labels = {
            app = "compliance-bridge"
          }
        }
      }
      ports {
        protocol = "TCP"
        port     = "80"
      }
      ports {
        protocol = "TCP"
        port     = "8085"
      }
      ports {
        protocol = "TCP"
        port     = "3001"
      }
      ports {
        protocol = "TCP"
        port     = "4143"
      }
    }

    # 4. Gateway open probes + Linkerd inbound proxy
    egress {
      to {
        pod_selector {
          match_labels = {
            app = "gateway"
          }
        }
      }
      ports {
        protocol = "TCP"
        port     = "8000"
      }
      ports {
        protocol = "TCP"
        port     = "8080"
      }
      ports {
        protocol = "TCP"
        port     = "4143"
      }
    }

    # 5. Linkerd control plane in linkerd namespace
    egress {
      to {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = "linkerd"
          }
        }
      }
      ports {
        protocol = "TCP"
        port     = "8080"
      }
      ports {
        protocol = "TCP"
        port     = "8086"
      }
      ports {
        protocol = "TCP"
        port     = "8090"
      }
    }

    # 6. GKE compute & Workload Identity metadata servers
    egress {
      to {
        ip_block {
          cidr = "169.254.169.254/32"
        }
      }
      ports {
        protocol = "TCP"
        port     = "80"
      }
    }

    egress {
      to {
        ip_block {
          cidr = "169.254.169.252/32"
        }
      }
      ports {
        protocol = "TCP"
        port     = "988"
      }
    }
  }
}



# ─── 13b. AgentSight UI Egress (DNS + Linkerd Control Plane Only) ────────────
# `agentsight-ui` executes in the `linkerd.io/inject = enabled` governance-stack
# namespace, so its Linkerd sidecar requires control-plane egress (`destination`
# `:8086`, `identity` `:8080`, `policy-controller` `:8090`) and cluster DNS to
# flip Ready 2/2 while retaining zero egress to datastores, workloads, or WAN.

resource "kubernetes_network_policy_v1" "agentsight_ui_egress_l3_l4" {
  metadata {
    name      = "agentsight-ui-egress-l3-l4"
    namespace = module.namespace.name
    labels = {
      app                            = "agentsight-ui"
      "app.kubernetes.io/managed-by" = "terraform"
      "cage.io/component"            = "z3n-egress"
    }
    annotations = merge(
      {
        "compliance.nist.gov/control"  = "SC-7,SC-8,AC-4"
        "compliance.nist.gov/standard" = "SP-800-53-Rev5"
        "cage.io/poam"                 = "POAM-2026-195"
      },
      local.network_policy_logging_annotation,
    )
  }

  spec {
    pod_selector {
      match_labels = {
        app = "agentsight-ui"
      }
    }

    policy_types = ["Egress"]

    # Cluster DNS (`kube-dns` / `node-local-dns`) in `kube-system` + ClusterIP CIDR
    egress {
      to {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = "kube-system"
          }
        }
        pod_selector {
          match_labels = {
            "k8s-app" = "kube-dns"
          }
        }
      }
      to {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = "kube-system"
          }
        }
        pod_selector {
          match_labels = {
            "k8s-app" = "node-local-dns"
          }
        }
      }
      to {
        ip_block {
          cidr = var.kube_dns_cidr
        }
      }
      ports {
        protocol = "UDP"
        port     = "53"
      }
      ports {
        protocol = "TCP"
        port     = "53"
      }
    }

    # Linkerd mTLS control-plane services (`identity`, `destination`, `policy`)
    egress {
      to {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = "linkerd"
          }
        }
      }
      ports {
        protocol = "TCP"
        port     = "8080"
      }
      ports {
        protocol = "TCP"
        port     = "8086"
      }
      ports {
        protocol = "TCP"
        port     = "8090"
      }
      ports {
        protocol = "TCP"
        port     = "443"
      }
    }
  }
}

# ─── 14. Materialize GKE FQDNNetworkPolicy Objects in Cluster (§5.3) ─────────

resource "kubernetes_manifest" "fqdn_network_policy" {
  for_each = local.fqdn_network_policies

  manifest        = each.value
  computed_fields = ["spec.egress"]

  depends_on = [module.gke, module.namespace]
}

# ─── 15. Workload Rollout Trigger on Policy Change (§5.3, §7) ─────────────────
# Connections established before a policy change survive until closed on GKE
# Dataplane V2. This resource records the active policy hash and triggers a
# rollout restart of active workloads whenever any NetworkPolicy or
# FQDNNetworkPolicy specification changes.

resource "terraform_data" "network_policy_workload_rollout" {
  triggers_replace = [
    local.network_policy_spec_hash,
  ]

  input = {
    namespace   = module.namespace.name
    policy_hash = local.network_policy_spec_hash
    # Only workloads deployed under the active profile are listed.
    rollout_command = "kubectl rollout restart ${join(" ", concat(
      [
        "deployment/gateway",
        "deployment/opa-service",
        "deployment/langfuse-web",
        "deployment/langfuse-worker",
        "deployment/agentsight-ui",
        "statefulset/clickhouse",
      ],
      length(module.governed_advisor) > 0 ? ["deployment/governed-financial-advisor"] : [],
      var.enable_compliance_bridge ? ["deployment/compliance-bridge"] : [],
      local.vllm_enabled ? ["deployment/vllm-inference", "deployment/vllm-reasoning"] : [],
      local.clickhouse_cold_tier_enabled ? ["statefulset/clickhouse-keeper"] : [],
    ))} -n ${module.namespace.name}"
    fqdn_policy_objects  = local.fqdn_network_policies
    l3_l4_policy_summary = local.network_policy_l3_l4_matrix
  }

  depends_on = [
    kubernetes_network_policy_v1.default_deny_ingress,
    kubernetes_network_policy_v1.default_deny_external_egress,
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
    kubernetes_network_policy_v1.agentsight_ui_egress_l3_l4,
    kubernetes_manifest.fqdn_network_policy,
  ]
}
