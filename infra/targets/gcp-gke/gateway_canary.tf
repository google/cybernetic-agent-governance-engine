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

# ─── Synthetic In-Mesh Governed Liveness Canary (SI-4 / AU-5) ─────────────────
# Resolves the structural observability ambiguity on idle enforcing clusters:
# without synthetic traffic, "every gated route is failing closed and callers
# backed off" and "cluster is idle overnight" produce identical counters
# (rate(permitted) == 0).
#
# `Deployment/gateway-canary` runs inside `governance-stack` under its own
# dedicated zero-cloud-identity KSA (`cage-gateway-canary-sa`), sending one
# non-mutating governed request per minute (`python -m src.gateway.canary`) over
# Linkerd mTLS:
#   1. Linkerd `HTTPRoute/gateway-canary` and `WorkloadIdentityMiddleware`
#      restrict `cage-gateway-canary-sa` strictly to `POST` on the active
#      domain's `CanaryProbe` route (`/governance/validate-action` or
#      `/governance/policy-precheck`), never full `PathPrefix "/"` access.
#   2. `EvidenceStreamSink` stamps `"canary": true` server-side from the
#      verified Linkerd identity (and strips any caller-supplied `"canary"` key
#      on non-canary requests), and `src/compliance_bridge/metrics.py` excludes
#      `"canary": true` records from Lula trace-volume thresholds (`a52`, `a53`,
#      `a92`, `sc4`, etc.) and `safety_rate` so CAGE never self-satisfies
#      compliance controls from traffic it generates itself.

resource "kubernetes_deployment_v1" "gateway_canary" {
  count = var.enable_gateway_canary ? 1 : 0

  lifecycle {
    precondition {
      condition     = var.gateway_canary_interval_seconds >= 5
      error_message = "CAGE Invariant (SI-4): gateway_canary_interval_seconds must be >= 5 seconds."
    }
  }

  metadata {
    name      = "gateway-canary"
    namespace = module.namespace.name
    labels = {
      app                       = "gateway-canary"
      "cage.io/account-purpose" = "liveness-canary"
    }
  }

  wait_for_rollout = false

  spec {
    replicas               = 1
    revision_history_limit = 2

    strategy {
      type = "Recreate"
    }

    selector {
      match_labels = {
        app = "gateway-canary"
      }
    }

    template {
      metadata {
        labels = {
          app                       = "gateway-canary"
          "cage.io/account-purpose" = "liveness-canary"
        }
        annotations = {
          "cage.io/network-policy-sha256" = local.network_policy_spec_hash
        }
      }

      spec {
        service_account_name            = kubernetes_service_account.workload["gateway_canary"].metadata[0].name
        automount_service_account_token = false

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
          run_as_user     = 1000
          seccomp_profile {
            type = "RuntimeDefault"
          }
        }

        container {
          name              = "gateway-canary"
          image             = var.image_digests["gateway"]
          image_pull_policy = "IfNotPresent"
          command           = ["python", "-m", "src.gateway.canary"]

          env {
            name  = "CAGE_DOMAIN"
            value = var.cage_domain
          }
          env {
            name  = "CAGE_ENV"
            value = var.environment
          }
          env {
            name  = "CAGE_GATEWAY_CANARY_URL"
            value = "http://${module.gateway.service_name}.${module.namespace.name}.svc.cluster.local:8080"
          }
          env {
            name  = "CAGE_CANARY_INTERVAL_SECONDS"
            value = tostring(var.gateway_canary_interval_seconds)
          }
          env {
            name  = "LANGSMITH_TRACING"
            value = "false"
          }
          env {
            name  = "LANGCHAIN_TRACING_V2"
            value = "false"
          }
          env {
            name  = "TMPDIR"
            value = "/tmp"
          }
          env {
            name  = "PYTHONDONTWRITEBYTECODE"
            value = "1"
          }

          resources {
            requests = {
              cpu    = "25m"
              memory = "128Mi"
            }
            limits = {
              cpu    = "200m"
              memory = "256Mi"
            }
          }

          security_context {
            allow_privilege_escalation = false
            read_only_root_filesystem  = true
            run_as_non_root            = true
            run_as_user                = 1000
            capabilities {
              drop = ["ALL"]
            }
            seccomp_profile {
              type = "RuntimeDefault"
            }
          }

          volume_mount {
            name       = "tmp"
            mount_path = "/tmp"
          }
        }

        volume {
          name = "tmp"
          empty_dir {
            size_limit = "32Mi"
          }
        }
      }
    }
  }

  depends_on = [
    module.gateway,
    module.service_mesh,
    kubernetes_service_account.workload["gateway_canary"],
    kubernetes_network_policy_v1.gateway_canary_egress,
  ]
}
