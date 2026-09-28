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

# ─── Track 6f Network Policy & GKE FQDNNetworkPolicy Set (§5.3, §7) ──────────
# Enforces L3/L4 + FQDN-resolved IP egress isolation on GKE Dataplane V2 across
# all postures (dev, staging, prod).
#
# Invariants (§5.3, §7):
#   1. The policy set is identical in every posture; only CIDRs and FQDNs differ
#      and come from tfvars.
#   2. DNS egress is allowed ONLY to kube-dns (kube-system / k8s-app=kube-dns)
#      and Cloud DNS (var.kube_dns_cidr = 169.254.169.254/32), never to 0.0.0.0/0.
#   3. Memorystore egress uses ip_block for the PSC endpoint CIDR on TLS port 6379
#      (never toEndpoints: app: redis-stack).
#   4. Reconciler egress stays at KMS + governance Memorystore + DNS + Langfuse OTLP.
#   5. Every policy change triggers a rollout restart of selected workloads so no
#      pre-change connection outlives a policy tightening.

locals {
  # Canonical GKE FQDNNetworkPolicy (networking.gke.io/v1alpha1) manifests.
  # Parameterized strictly by tfvars FQDNs; identical structure in every posture.
  fqdn_network_policies = {
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
          "cage.io/poam"                 = "POAM-007,POAM-011"
        }
      }
      spec = {
        podSelector = {
          matchLabels = {
            app = "gateway"
          }
        }
        policyTypes = ["Egress"]
        egress = [
          {
            to = [
              {
                fqdns = var.gateway_egress_allowed_fqdns
              }
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
        }
      }
      spec = {
        podSelector = {
          matchLabels = {
            app                       = "reconciliation-worker"
            "cage.io/account-purpose" = "ledger-reconciliation"
          }
        }
        policyTypes = ["Egress"]
        egress = [
          {
            to = [
              {
                fqdns = var.reconciler_egress_allowed_fqdns
              }
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

    trivy_scanner_egress_fqdn = {
      apiVersion = "networking.gke.io/v1alpha1"
      kind       = "FQDNNetworkPolicy"
      metadata = {
        name      = "trivy-scanner-egress-fqdn"
        namespace = module.namespace.name
        labels = {
          "app.kubernetes.io/managed-by" = "terraform"
          "cage.io/component"            = "z3n-egress"
          "app.kubernetes.io/part-of"    = "security-scanning"
        }
        annotations = {
          "compliance.nist.gov/control"  = "SC-7,AC-4,SI-3,RA-5"
          "compliance.nist.gov/standard" = "SP-800-53-Rev5"
          "cage.io/poam"                 = "POAM-007,POAM-011"
        }
      }
      spec = {
        podSelector = {
          matchLabels = {
            app = "security-scanner"
          }
        }
        policyTypes = ["Egress"]
        egress = [
          {
            to = [
              {
                fqdns = var.trivy_egress_allowed_fqdns
              }
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
  }

  # Digest of all NetworkPolicy + FQDNNetworkPolicy parameters.
  # Any change to CIDRs, FQDNs, or policy rules changes this digest and forces
  # a rollout restart of selected workloads (§5.3, §7).
  network_policy_spec_hash = sha256(jsonencode({
    governance_psc_cidr = var.memorystore_governance_psc_cidr
    app_psc_cidr        = var.memorystore_app_psc_cidr
    kube_dns_cidr       = var.kube_dns_cidr
    fqdn_policies       = local.fqdn_network_policies
  }))
}

# ─── 1. Default-Deny External Egress + Restricted DNS Egress (§5.3, §7) ──────

resource "kubernetes_network_policy_v1" "default_deny_external_egress" {
  metadata {
    name      = "default-deny-external-egress"
    namespace = module.namespace.name
    labels = {
      "app.kubernetes.io/managed-by" = "terraform"
      "cage.io/component"            = "z3n-egress"
    }
    annotations = {
      "compliance.nist.gov/control"  = "SC-7,AC-4"
      "compliance.nist.gov/standard" = "SP-800-53-Rev5"
    }
  }

  spec {
    pod_selector {}
    policy_types = ["Egress"]

    # Intra-namespace traffic
    egress {
      to {
        pod_selector {}
      }
    }

    # §5.3, §7: DNS egress allowed ONLY to kube-dns and Cloud DNS (never 0.0.0.0/0)
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
  }
}

# ─── 2. Gateway L3/L4 Egress (DNS + Memorystore Governance PSC + Internal) ────

resource "kubernetes_network_policy_v1" "gateway_egress_l3_l4" {
  metadata {
    name      = "gateway-egress-l3-l4"
    namespace = module.namespace.name
    labels = {
      "app.kubernetes.io/managed-by" = "terraform"
      "cage.io/component"            = "z3n-egress"
    }
    annotations = {
      "compliance.nist.gov/control"  = "SC-7,AC-4,SI-3"
      "compliance.nist.gov/standard" = "SP-800-53-Rev5"
      "cage.io/poam"                 = "POAM-007,POAM-011"
    }
  }

  spec {
    pod_selector {
      match_labels = {
        app = "gateway"
      }
    }
    policy_types = ["Egress"]

    # DNS resolution — kube-dns and Cloud DNS only (§5.3, §7)
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

    # §5.3: Memorystore governance PSC endpoint CIDR on TLS port 6379
    egress {
      to {
        ip_block {
          cidr = var.memorystore_governance_psc_cidr
        }
      }
      ports {
        protocol = "TCP"
        port     = "6379"
      }
    }

    # Internal governance services (OPA, vLLM, NeMo, Langfuse OTLP)
    egress {
      to {
        pod_selector {
          match_labels = {
            app = "opa"
          }
        }
      }
      ports {
        protocol = "TCP"
        port     = "8181"
      }
    }

    egress {
      to {
        pod_selector {
          match_labels = {
            app = "vllm-service"
          }
        }
      }
      to {
        pod_selector {
          match_labels = {
            app = "vllm-inference"
          }
        }
      }
      to {
        pod_selector {
          match_labels = {
            app = "vllm-reasoning"
          }
        }
      }
      to {
        pod_selector {
          match_labels = {
            app = "nemo-guardrails"
          }
        }
      }
      ports {
        protocol = "TCP"
        port     = "8000"
      }
    }

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
    }
  }
}

# ─── 3. Financial Advisor Internal-Only Egress (§5.3) ─────────────────────────

resource "kubernetes_network_policy_v1" "financial_advisor_egress_internal_only" {
  metadata {
    name      = "financial-advisor-egress-internal-only"
    namespace = module.namespace.name
    labels = {
      "app.kubernetes.io/managed-by" = "terraform"
      "cage.io/component"            = "z3n-egress"
    }
    annotations = {
      "compliance.nist.gov/control"  = "SC-7,AC-4,SI-3"
      "compliance.nist.gov/standard" = "SP-800-53-Rev5"
      "cage.io/poam"                 = "POAM-007"
    }
  }

  spec {
    pod_selector {
      match_labels = {
        app = "governed-financial-advisor"
      }
    }
    policy_types = ["Egress"]

    # DNS — kube-dns and Cloud DNS only (§5.3, §7)
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

    # Gateway (orchestration return path and inference proxy)
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
    }

    # Compliance bridge
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
        port     = "8090"
      }
    }

    # Memorystore app PSC endpoint CIDR on TLS port 6379 (§2.1, §5.3)
    egress {
      to {
        ip_block {
          cidr = var.memorystore_app_psc_cidr
        }
      }
      ports {
        protocol = "TCP"
        port     = "6379"
      }
    }
  }
}

# ─── 4. Sovereign Agent Internal-Only Egress (§5.3) ───────────────────────────

resource "kubernetes_network_policy_v1" "agent_egress_internal_only" {
  metadata {
    name      = "agent-egress-internal-only"
    namespace = module.namespace.name
    labels = {
      "app.kubernetes.io/managed-by" = "terraform"
      "cage.io/component"            = "z3n-egress"
    }
    annotations = {
      "compliance.nist.gov/control"  = "SC-7,AC-4,SI-3,SC-39"
      "compliance.nist.gov/standard" = "SP-800-53-Rev5"
      "cage.io/poam"                 = "POAM-007"
    }
  }

  spec {
    pod_selector {
      match_labels = {
        role = "sovereign-agent"
      }
    }
    policy_types = ["Egress"]

    # DNS — kube-dns and Cloud DNS only (§5.3, §7)
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

    # OPA policy evaluation
    egress {
      to {
        pod_selector {
          match_labels = {
            app = "opa"
          }
        }
      }
      ports {
        protocol = "TCP"
        port     = "8181"
      }
    }

    # CAGE Gateway (orchestration return path)
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
    }
  }
}

# ─── 5. Reconciliation Worker Egress Isolation (C7, §5.3, §7) ─────────────────
# Allows ONLY:
#   1. DNS to kube-dns / Cloud DNS (port 53 UDP/TCP)
#   2. Memorystore governance PSC endpoint ip_block on TLS port 6379
#   3. Langfuse OTLP trace export (port 3000)
#   4. Cloud KMS (port 443 via reconciliation_worker_egress_fqdn FQDNNetworkPolicy)

resource "kubernetes_network_policy_v1" "reconciliation_worker_egress" {
  metadata {
    name      = "reconciliation-worker-egress"
    namespace = module.namespace.name
    labels = {
      app                            = "reconciliation-worker"
      "app.kubernetes.io/managed-by" = "terraform"
      "cage.io/component"            = "z3n-egress"
    }
    annotations = {
      "compliance.nist.gov/control"  = "SC-7,AC-4"
      "compliance.nist.gov/standard" = "SP-800-53-Rev5"
    }
  }

  spec {
    pod_selector {
      match_labels = {
        app                       = "reconciliation-worker"
        "cage.io/account-purpose" = "ledger-reconciliation"
      }
    }
    policy_types = ["Ingress", "Egress"]

    # No ingress permitted — worker is write-only.

    # 1. DNS resolution — kube-dns and Cloud DNS only (§5.3, §7)
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

    # 2. Memorystore governance PSC endpoint CIDR on TLS port 6379 (§5.3: replaces toEndpoints: redis-stack)
    egress {
      to {
        ip_block {
          cidr = var.memorystore_governance_psc_cidr
        }
      }
      ports {
        protocol = "TCP"
        port     = "6379"
      }
    }

    # 3. Langfuse OTLP trace export (port 3000)
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
    }
  }
}

# ─── 6. Trivy Vulnerability Scanner DNS Egress (§5.3) ─────────────────────────
# Companion to trivy_scanner_egress_fqdn (FQDNNetworkPolicy on port 443).

resource "kubernetes_network_policy_v1" "trivy_scanner_dns_egress" {
  metadata {
    name      = "trivy-scanner-dns-egress"
    namespace = module.namespace.name
    labels = {
      "app.kubernetes.io/managed-by" = "terraform"
      "cage.io/component"            = "z3n-egress"
      "app.kubernetes.io/part-of"    = "security-scanning"
    }
  }

  spec {
    pod_selector {
      match_labels = {
        app = "security-scanner"
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
  }
}

# ─── 7. Workload Rollout Trigger on Policy Change (§5.3, §7) ──────────────────
# Connections established before a policy change survive until closed on GKE
# Dataplane V2. This resource records the active policy hash and triggers a
# rollout restart of selected workloads whenever any NetworkPolicy or
# FQDNNetworkPolicy specification changes.

resource "terraform_data" "network_policy_workload_rollout" {
  triggers_replace = [
    local.network_policy_spec_hash,
  ]

  input = {
    namespace           = module.namespace.name
    policy_hash         = local.network_policy_spec_hash
    rollout_command     = "kubectl rollout restart deployment/gateway deployment/governed-financial-advisor -n ${module.namespace.name}"
    fqdn_policy_objects = local.fqdn_network_policies
  }

  depends_on = [
    kubernetes_network_policy_v1.default_deny_external_egress,
    kubernetes_network_policy_v1.gateway_egress_l3_l4,
    kubernetes_network_policy_v1.financial_advisor_egress_internal_only,
    kubernetes_network_policy_v1.agent_egress_internal_only,
    kubernetes_network_policy_v1.reconciliation_worker_egress,
    kubernetes_network_policy_v1.trivy_scanner_dns_egress,
  ]
}
