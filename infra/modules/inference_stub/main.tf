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

resource "kubernetes_deployment_v1" "inference_stub" {
  lifecycle {
    precondition {
      condition     = !contains(["prod", "production"], lower(trimspace(var.environment)))
      error_message = "CAGE Invariant (POAM-2026-191): the deterministic inference stub is a non-production E2E test backend and must never deploy when environment is prod or production."
    }
  }

  metadata {
    name      = var.deployment_name
    namespace = var.namespace
    labels = {
      app = var.deployment_name
    }
  }

  wait_for_rollout = false

  spec {
    replicas               = var.replicas
    revision_history_limit = 2

    selector {
      match_labels = {
        app = var.deployment_name
      }
    }

    template {
      metadata {
        labels = {
          app = var.deployment_name
        }
        annotations = var.network_policy_hash != "" ? {
          "cage.io/network-policy-hash" = var.network_policy_hash
        } : {}
      }

      spec {
        service_account_name            = var.service_account_name
        automount_service_account_token = false

        security_context {
          run_as_non_root = true
          run_as_user     = 1000
          seccomp_profile {
            type = "RuntimeDefault"
          }
        }

        container {
          name              = "inference-stub"
          image             = var.image
          image_pull_policy = "Always"
          command           = ["python", "-m", "src.integrations.inference_stub.server"]

          port {
            name           = "http"
            container_port = var.port
            protocol       = "TCP"
          }

          env {
            name  = "CAGE_ENV"
            value = var.environment
          }
          env {
            name  = "INFERENCE_STUB_HOST"
            value = "0.0.0.0"
          }
          env {
            name  = "INFERENCE_STUB_PORT"
            value = tostring(var.port)
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
              cpu    = var.cpu_request
              memory = var.memory_request
            }
            limits = {
              cpu    = var.cpu_limit
              memory = var.memory_limit
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

          readiness_probe {
            http_get {
              path = "/health"
              port = var.port
            }
            initial_delay_seconds = 3
            period_seconds        = 5
            timeout_seconds       = 3
          }

          liveness_probe {
            http_get {
              path = "/health"
              port = var.port
            }
            initial_delay_seconds = 10
            period_seconds        = 15
            timeout_seconds       = 3
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

resource "kubernetes_service_v1" "inference_stub" {
  metadata {
    name      = var.service_name
    namespace = var.namespace
    labels = {
      app = var.deployment_name
    }
  }

  spec {
    type = "ClusterIP"

    selector = {
      app = var.deployment_name
    }

    port {
      name        = "http"
      port        = var.port
      target_port = var.port
      protocol    = "TCP"
    }
  }
}
