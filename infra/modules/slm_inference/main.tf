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

# SLM Deployment
resource "kubernetes_deployment" "slm" {
  metadata {
    name      = var.deployment_name
    namespace = var.namespace
    labels = {
      app       = "slm-inference"
      component = "semantic-similarity"
    }
  }

  spec {
    replicas = var.replicas

    selector {
      match_labels = {
        app = "slm-inference"
      }
    }

    template {
      metadata {
        labels = {
          app = "slm-inference"
        }
      }

      spec {
        container {
          name  = "slm"
          image = var.image

          env {
            name  = "SLM_PORT"
            value = tostring(var.service_port)
          }

          env {
            name  = "SLM_MODEL_NAME"
            value = var.model_name
          }

          port {
            container_port = var.service_port
            name           = "http"
          }

          liveness_probe {
            http_get {
              path = "/health"
              port = "http"
            }
            initial_delay_seconds = 30
            period_seconds        = 10
          }

          readiness_probe {
            http_get {
              path = "/health"
              port = "http"
            }
            initial_delay_seconds = 10
            period_seconds        = 5
          }

          resources {
            requests = {
              cpu    = var.resources_requests_cpu
              memory = var.resources_requests_memory
            }
            limits = var.resources_limits_cpu != "" ? {
              cpu    = var.resources_limits_cpu
              memory = var.resources_limits_memory
            } : {}
          }

          # Security context
          dynamic "security_context" {
            for_each = var.enable_security_context ? [1] : []
            content {
              run_as_user                = 1000
              run_as_non_root            = true
              read_only_root_filesystem  = false
              allow_privilege_escalation = false
              capabilities {
                drop = ["ALL"]
              }
            }
          }
        }

        # Node selector
        node_selector = var.node_selector

        # Tolerations
        dynamic "toleration" {
          for_each = var.tolerations
          content {
            key      = lookup(toleration.value, "key", null)
            operator = lookup(toleration.value, "operator", "Equal")
            value    = lookup(toleration.value, "value", null)
            effect   = lookup(toleration.value, "effect", null)
          }
        }
      }
    }
  }
}

# SLM Service
resource "kubernetes_service" "slm" {
  metadata {
    name      = var.service_name
    namespace = var.namespace
    labels = {
      app = "slm-inference"
    }
  }

  spec {
    selector = {
      app = "slm-inference"
    }

    port {
      port        = var.service_port
      target_port = var.service_port
      protocol    = "TCP"
      name        = "http"
    }

    type = "ClusterIP"
  }
}

# Pod Disruption Budget (for HA)
resource "kubernetes_pod_disruption_budget_v1" "slm_pdb" {
  count = var.enable_pdb ? 1 : 0

  metadata {
    name      = "${var.deployment_name}-pdb"
    namespace = var.namespace
  }

  spec {
    min_available = 1

    selector {
      match_labels = {
        app = "slm-inference"
      }
    }
  }
}
