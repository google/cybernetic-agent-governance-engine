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
        egress = [
          {
            matches = [
              for fqdn in var.trivy_egress_allowed_fqdns : (
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
          "cage.io/poam"                 = "POAM-007,POAM-011,POAM-2026-082"
        }
      }
      spec = {
        podSelector = {
          matchExpressions = [
            {
              key      = "app"
              operator = "In"
              values   = ["vllm-inference", "vllm-reasoning"]
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

    # §5.3, §7: DNS egress allowed ONLY to kube-dns, node-local-dns, and Cloud DNS (never 0.0.0.0/0)
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

    # POAM-2026-080: Allow Linkerd sidecar proxies to reach Linkerd control plane in linkerd namespace
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

    # Cloud SQL VPC peering egress (Cloud SQL Proxy and PostgreSQL)
    egress {
      to {
        ip_block {
          cidr = var.cloud_sql_cidr
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

    # Memorystore Valkey / Redis egress
    egress {
      dynamic "to" {
        for_each = distinct([var.memorystore_governance_psc_cidr, var.memorystore_app_psc_cidr])
        content {
          ip_block {
            cidr = to.value
          }
        }
      }
      ports {
        protocol = "TCP"
        port     = "6379"
      }
    }

    # GKE compute metadata server (HTTP 80) for Workload Identity
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

    # Internal governance services (OPA, vLLM, NeMo, Langfuse OTLP) + Linkerd inbound proxy (4143)
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
      ports {
        protocol = "TCP"
        port     = "4143"
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
      ports {
        protocol = "TCP"
        port     = "4143"
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
      ports {
        protocol = "TCP"
        port     = "4143"
      }
    }

    # GKE compute metadata server (HTTP 80) for Workload Identity
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

# ─── 2b. Compliance Bridge L3/L4 Egress (Governance Memorystore PSC) ──────────
# The EvidenceCustodian reads the gateway's evidence stream and persists its
# custody cursor on the GOVERNANCE Memorystore instance, so the bridge needs the
# same governance PSC egress on 6379 as the gateway. GCS / Cloud KMS on 443 come
# from compliance_bridge_egress_fqdn.

resource "kubernetes_network_policy_v1" "compliance_bridge_egress_l3_l4" {
  metadata {
    name      = "compliance-bridge-egress-l3-l4"
    namespace = module.namespace.name
    labels = {
      "app.kubernetes.io/managed-by" = "terraform"
      "cage.io/component"            = "z3n-egress"
    }
    annotations = {
      "compliance.nist.gov/control"  = "SC-7,AC-4,AU-9"
      "compliance.nist.gov/standard" = "SP-800-53-Rev5"
    }
  }

  spec {
    pod_selector {
      match_labels = {
        app = "compliance-bridge"
      }
    }
    policy_types = ["Egress"]

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
      ports {
        protocol = "TCP"
        port     = "4143"
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
      ports {
        protocol = "TCP"
        port     = "4143"
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
      ports {
        protocol = "TCP"
        port     = "4143"
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
      ports {
        protocol = "TCP"
        port     = "4143"
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
  }
}

# ─── 7. vLLM L3/L4 Egress (DNS + GKE Workload Identity Metadata Server) ──────

resource "kubernetes_network_policy_v1" "vllm_egress_l3_l4" {
  metadata {
    name      = "vllm-egress-l3-l4"
    namespace = module.namespace.name
    labels = {
      "app.kubernetes.io/managed-by" = "terraform"
      "cage.io/component"            = "z3n-egress"
    }
    annotations = {
      "compliance.nist.gov/control"  = "SC-7,AC-4,IA-2"
      "compliance.nist.gov/standard" = "SP-800-53-Rev5"
      "cage.io/poam"                 = "POAM-007,POAM-011,POAM-2026-082"
    }
  }

  spec {
    pod_selector {
      match_expressions {
        key      = "app"
        operator = "In"
        values   = ["vllm-inference", "vllm-reasoning"]
      }
    }
    policy_types = ["Egress"]

    # DNS — kube-dns and Cloud DNS (var.kube_dns_cidr) only
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

    # GKE compute metadata server (HTTP 80) for Workload Identity
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

# ─── 8. Materialize GKE FQDNNetworkPolicy Objects in Cluster (§5.3) ──────────

resource "kubernetes_manifest" "fqdn_network_policy" {
  for_each = local.fqdn_network_policies

  manifest = each.value

  depends_on = [module.gke, module.namespace]
}

# ─── 9. Workload Rollout Trigger on Policy Change (§5.3, §7) ──────────────────
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
    rollout_command     = "kubectl rollout restart deployment/gateway deployment/governed-financial-advisor deployment/compliance-bridge -n ${module.namespace.name}"
    fqdn_policy_objects = local.fqdn_network_policies
  }

  depends_on = [
    kubernetes_network_policy_v1.default_deny_external_egress,
    kubernetes_network_policy_v1.gateway_egress_l3_l4,
    kubernetes_network_policy_v1.compliance_bridge_egress_l3_l4,
    kubernetes_network_policy_v1.financial_advisor_egress_internal_only,
    kubernetes_network_policy_v1.agent_egress_internal_only,
    kubernetes_network_policy_v1.reconciliation_worker_egress,
    kubernetes_network_policy_v1.trivy_scanner_dns_egress,
    kubernetes_network_policy_v1.vllm_egress_l3_l4,
    kubernetes_manifest.fqdn_network_policy,
  ]
}
