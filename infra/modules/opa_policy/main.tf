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

# ConfigMap for OPA policies
resource "kubernetes_config_map" "opa_policies" {
  count = var.create_policy_configmap ? 1 : 0

  metadata {
    name      = "opa-policies"
    namespace = var.namespace
  }

  data = var.policy_files
}

# ConfigMap for OPA configuration
resource "kubernetes_config_map" "opa_config" {
  count = var.create_config_configmap ? 1 : 0

  metadata {
    name      = "opa-config"
    namespace = var.namespace
  }

  data = {
    "opa_config.yaml" = var.opa_config
  }
}

# OPA Deployment
resource "kubernetes_deployment" "opa" {
  metadata {
    name      = "opa-service"
    namespace = var.namespace
    labels = {
      app                           = "opa"
      "compliance.iso42001/enabled" = "true"
      "compliance.iso42001/version" = "2023"
    }
    annotations = {
      "compliance.iso42001/controls" = "A.5.3,SC-4,A.9.2,A.5.2"
    }
  }

  spec {
    replicas = var.replicas

    selector {
      match_labels = {
        app = "opa"
      }
    }

    template {
      metadata {
        labels = {
          app                           = "opa"
          "compliance.iso42001/enabled" = "true"
        }
        annotations = {
          "compliance.iso42001/controls" = "A.5.3,SC-4,A.9.2,A.5.2"
        }
      }

      spec {
        container {
          name  = "opa"
          image = var.image

          args = concat(
            [
              "run",
              "--server",
              "--addr=:8181",
              "--diagnostic-addr=:8282",
            ],
            var.create_config_configmap ? ["--config-file=/config/opa_config.yaml"] : [],
            var.create_policy_configmap ? ["--ignore=..*", "/policies"] : []
          )

          port {
            container_port = 8181
            name           = "http"
          }

          port {
            container_port = 8282
            name           = "diagnostics"
          }

          # Volume mounts
          dynamic "volume_mount" {
            for_each = var.create_policy_configmap ? [1] : []
            content {
              name       = "policies"
              mount_path = "/policies"
              read_only  = true
            }
          }

          dynamic "volume_mount" {
            for_each = var.create_config_configmap ? [1] : []
            content {
              name       = "config"
              mount_path = "/config"
              read_only  = true
            }
          }

          resources {
            requests = {
              memory = var.memory_request
              cpu    = var.cpu_request
            }
            limits = {
              memory = var.memory_limit
              cpu    = var.cpu_limit
            }
          }

          liveness_probe {
            http_get {
              path = "/health"
              port = 8181
            }
            initial_delay_seconds = 10
            period_seconds        = 10
          }

          readiness_probe {
            http_get {
              path = "/health"
              port = 8181
            }
            initial_delay_seconds = 5
            period_seconds        = 5
          }
        }

        # Volumes
        dynamic "volume" {
          for_each = var.create_policy_configmap ? [1] : []
          content {
            name = "policies"
            config_map {
              name = kubernetes_config_map.opa_policies[0].metadata[0].name
            }
          }
        }

        dynamic "volume" {
          for_each = var.create_config_configmap ? [1] : []
          content {
            name = "config"
            config_map {
              name = kubernetes_config_map.opa_config[0].metadata[0].name
            }
          }
        }
      }
    }
  }
}

# OPA Service
resource "kubernetes_service" "opa" {
  metadata {
    name      = "opa"
    namespace = var.namespace
    labels = {
      app = "opa"
    }
  }

  spec {
    type = var.service_type

    port {
      port        = 8181
      target_port = 8181
      protocol    = "TCP"
      name        = "http"
    }

    port {
      port        = 8282
      target_port = 8282
      protocol    = "TCP"
      name        = "diagnostics"
    }

    selector = {
      app = "opa"
    }
  }
}
