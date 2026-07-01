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

resource "kubernetes_deployment" "agentsight_ui" {
  metadata {
    name      = "agentsight-ui"
    namespace = var.namespace
    labels = {
      app       = "agentsight-ui"
      component = "ebpf-observability"
    }
  }

  spec {
    replicas = var.replicas

    selector {
      match_labels = {
        app = "agentsight-ui"
      }
    }

    template {
      metadata {
        labels = {
          app       = "agentsight-ui"
          component = "ebpf-observability"
        }
      }

      spec {
        container {
          name              = "agentsight-ui"
          image             = var.image
          image_pull_policy = "Always"

          port {
            container_port = 8080
            name           = "http"
          }

          readiness_probe {
            http_get {
              path = "/"
              port = 8080
            }
            initial_delay_seconds = 5
            period_seconds        = 10
            timeout_seconds       = 3
            failure_threshold     = 3
          }

          liveness_probe {
            http_get {
              path = "/"
              port = 8080
            }
            initial_delay_seconds = 10
            period_seconds        = 15
            timeout_seconds       = 3
            failure_threshold     = 3
          }

          resources {
            requests = {
              cpu    = "50m"
              memory = "64Mi"
            }
            limits = {
              cpu    = "200m"
              memory = "128Mi"
            }
          }
        }
      }
    }
  }
}

resource "kubernetes_service" "agentsight_ui" {
  metadata {
    name      = "agentsight-ui"
    namespace = var.namespace
    labels = {
      app       = "agentsight-ui"
      component = "ebpf-observability"
    }
  }

  spec {
    type = "LoadBalancer"

    port {
      port        = 8080
      target_port = 8080
      protocol    = "TCP"
      name        = "http"
    }

    selector = {
      app = "agentsight-ui"
    }
  }
}
