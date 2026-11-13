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

locals {
  all_lula_files = fileset(var.lula_manifests_dir, "lula-validation-*.yaml")

  # Exclude non-active specs explicitly marked `# cage-status: planned` or
  # `# cage-status: not-applicable` so CronJob/lula-audit evaluates only active controls.
  active_lula_specs = {
    for f in local.all_lula_files :
    f => file("${var.lula_manifests_dir}/${f}")
    if !can(regex("(?m)^#[[:space:]]*cage-status:[[:space:]]*(planned|not-applicable)([[:space:]]|$)", file("${var.lula_manifests_dir}/${f}")))
  }

  events_url = (
    trimspace(var.compliance_bridge_events_url) != ""
    ? trimspace(var.compliance_bridge_events_url)
    : "http://compliance-bridge.${var.namespace}.svc.cluster.local:8085/v1/infra/events"
  )
}

resource "kubernetes_config_map_v1" "lula_specs" {
  lifecycle {
    precondition {
      condition     = length(local.active_lula_specs) >= 20
      error_message = "CAGE Invariant (CA-7): lula-active-validations ConfigMap must contain at least 20 active Lula manifests; check lula_manifests_dir and `# cage-status: planned` headers."
    }
  }

  metadata {
    name      = "lula-active-validations"
    namespace = var.namespace
    labels = {
      app                            = "lula-audit"
      "app.kubernetes.io/managed-by" = "terraform"
      "cage.io/component"            = "compliance-auditor"
    }
  }

  data = local.active_lula_specs
}

# Least-privilege read-only ClusterRole for cross-namespace Kubernetes resource
# inspection (e.g., anetd DaemonSet in kube-system for cilium-dpv2). Never grants
# cluster-wide `secrets` access or any write/watch/escalate verb (AC-6).
resource "kubernetes_cluster_role_v1" "lula_reader" {
  metadata {
    name = "cage-lula-auditor-reader-${var.namespace}"
    labels = {
      app                            = "lula-audit"
      "app.kubernetes.io/managed-by" = "terraform"
      "cage.io/component"            = "compliance-auditor"
    }
  }

  rule {
    api_groups = [""]
    resources  = ["pods", "serviceaccounts", "configmaps"]
    verbs      = ["get", "list"]
  }

  rule {
    api_groups = ["apps"]
    resources  = ["deployments", "daemonsets"]
    verbs      = ["get", "list"]
  }

  rule {
    api_groups = ["networking.k8s.io"]
    resources  = ["networkpolicies"]
    verbs      = ["get", "list"]
  }

  rule {
    api_groups = ["monitoring.googleapis.com"]
    resources  = ["podmonitorings"]
    verbs      = ["get", "list"]
  }
}

resource "kubernetes_cluster_role_binding_v1" "lula_reader" {
  metadata {
    name = "cage-lula-auditor-reader-${var.namespace}"
    labels = {
      app                            = "lula-audit"
      "app.kubernetes.io/managed-by" = "terraform"
      "cage.io/component"            = "compliance-auditor"
    }
  }

  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = kubernetes_cluster_role_v1.lula_reader.metadata[0].name
  }

  subject {
    kind      = "ServiceAccount"
    name      = var.service_account_name
    namespace = var.namespace
  }
}

# Namespace-scoped Secret reader strictly inside var.namespace (required by
# lula-validation-ia5.yaml; prevents reading linkerd-identity-issuer CA keys).
resource "kubernetes_role_v1" "lula_namespace_secrets_reader" {
  metadata {
    name      = "cage-lula-secrets-reader"
    namespace = var.namespace
    labels = {
      app                            = "lula-audit"
      "app.kubernetes.io/managed-by" = "terraform"
      "cage.io/component"            = "compliance-auditor"
    }
  }

  rule {
    api_groups = [""]
    resources  = ["secrets"]
    verbs      = ["get", "list"]
  }
}

resource "kubernetes_role_binding_v1" "lula_namespace_secrets_reader" {
  metadata {
    name      = "cage-lula-secrets-reader"
    namespace = var.namespace
    labels = {
      app                            = "lula-audit"
      "app.kubernetes.io/managed-by" = "terraform"
      "cage.io/component"            = "compliance-auditor"
    }
  }

  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "Role"
    name      = kubernetes_role_v1.lula_namespace_secrets_reader.metadata[0].name
  }

  subject {
    kind      = "ServiceAccount"
    name      = var.service_account_name
    namespace = var.namespace
  }
}

resource "kubernetes_cron_job_v1" "lula_audit" {
  metadata {
    name      = "lula-audit"
    namespace = var.namespace
    labels = {
      app                       = "lula-audit"
      "app.kubernetes.io/name"  = "lula-audit"
      "cage.io/component"       = "compliance-auditor"
      "cage.io/account-purpose" = "compliance-validation"
    }
  }

  spec {
    schedule                      = var.schedule
    concurrency_policy            = "Forbid"
    successful_jobs_history_limit = 3
    failed_jobs_history_limit     = 3

    job_template {
      metadata {
        labels = {
          app                       = "lula-audit"
          "app.kubernetes.io/name"  = "lula-audit"
          "cage.io/component"       = "compliance-auditor"
          "cage.io/account-purpose" = "compliance-validation"
        }
      }

      spec {
        backoff_limit           = 0
        active_deadline_seconds = 300

        template {
          metadata {
            labels = {
              app                       = "lula-audit"
              "app.kubernetes.io/name"  = "lula-audit"
              "cage.io/component"       = "compliance-auditor"
              "cage.io/account-purpose" = "compliance-validation"
            }
            annotations = merge(
              {
                "linkerd.io/inject"         = "enabled"
                "cage.io/lula-specs-sha256" = sha256(jsonencode(local.active_lula_specs))
              },
              var.network_policy_hash != "" ? {
                "cage.io/network-policy-sha256" = var.network_policy_hash
              } : {},
            )
          }

          spec {
            service_account_name            = var.service_account_name
            automount_service_account_token = true
            restart_policy                  = "Never"

            affinity {
              node_affinity {
                required_during_scheduling_ignored_during_execution {
                  node_selector_term {
                    match_expressions {
                      key      = "cloud.google.com/gke-spot"
                      operator = "NotIn"
                      values   = ["true"]
                    }
                  }
                }
              }
            }

            security_context {
              run_as_non_root = true
              run_as_user     = 65532
              run_as_group    = 65532
              fs_group        = 65532
              seccomp_profile {
                type = "RuntimeDefault"
              }
            }

            container {
              name              = "lula-audit"
              image             = var.image
              image_pull_policy = "IfNotPresent"
              command           = ["/bin/sh", "-ec"]
              args              = [file("${path.module}/run_lula_audit.sh")]

              env {
                name  = "COMPLIANCE_BRIDGE_EVENTS_URL"
                value = local.events_url
              }

              security_context {
                allow_privilege_escalation = false
                read_only_root_filesystem  = true
                run_as_non_root            = true
                run_as_user                = 65532
                run_as_group               = 65532
                capabilities {
                  drop = ["ALL"]
                }
                seccomp_profile {
                  type = "RuntimeDefault"
                }
              }

              resources {
                requests = {
                  cpu    = var.cpu_request
                  memory = var.memory_request
                }
                limits = {
                  cpu    = var.cpu_limit
                  memory = var.memory_limit
                }
              }

              volume_mount {
                name       = "lula-specs"
                mount_path = "/etc/cage/lula"
                read_only  = true
              }

              volume_mount {
                name       = "tmp"
                mount_path = "/tmp"
              }
            }

            volume {
              name = "lula-specs"
              config_map {
                name = kubernetes_config_map_v1.lula_specs.metadata[0].name
              }
            }

            volume {
              name = "tmp"
              empty_dir {
                size_limit = "64Mi"
              }
            }
          }
        }
      }
    }
  }
}
