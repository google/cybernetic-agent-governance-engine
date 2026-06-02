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
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.11"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.23"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }
}

# Generate ClickHouse password
resource "random_password" "clickhouse_password" {
  length  = 32
  special = false
}

# ClickHouse credentials secret
resource "kubernetes_secret" "clickhouse_credentials" {
  metadata {
    name      = "clickhouse-credentials"
    namespace = var.namespace
  }

  data = {
    password = random_password.clickhouse_password.result
    username = "default"
  }
}

# Deploy ClickHouse via native StatefulSet to bypass broken Bitnami charts
resource "kubernetes_service" "clickhouse" {
  metadata {
    name      = "clickhouse"
    namespace = var.namespace
  }
  spec {
    selector = {
      app = "clickhouse"
    }
    port {
      name        = "http"
      port        = 8123
      target_port = 8123
    }
    port {
      name        = "tcp"
      port        = 9000
      target_port = 9000
    }
    type = "ClusterIP"
  }
}

resource "kubernetes_stateful_set" "clickhouse" {
  metadata {
    name      = "clickhouse"
    namespace = var.namespace
  }

  spec {
    service_name = "clickhouse"
    replicas     = var.replicas

    selector {
      match_labels = {
        app = "clickhouse"
      }
    }

    template {
      metadata {
        labels = {
          app = "clickhouse"
        }
      }

      spec {
        container {
          name  = "clickhouse"
          image = "docker.io/clickhouse/clickhouse-server:24.3-alpine"

          port {
            container_port = 8123
            name           = "http"
          }
          port {
            container_port = 9000
            name           = "tcp"
          }

          env {
            name  = "CLICKHOUSE_USER"
            value = "default"
          }
          env {
            name = "CLICKHOUSE_PASSWORD"
            value_from {
              secret_key_ref {
                name = kubernetes_secret.clickhouse_credentials.metadata[0].name
                key  = "password"
              }
            }
          }

          # Memory limits
          resources {
            requests = {
              cpu    = var.resources_requests_cpu
              memory = var.resources_requests_memory
            }
          }

          volume_mount {
            name       = "data"
            mount_path = "/var/lib/clickhouse"
          }
        }
      }
    }

    dynamic "volume_claim_template" {
      for_each = var.enable_persistence ? [1] : []
      content {
        metadata {
          name = "data"
        }
        spec {
          access_modes       = ["ReadWriteOnce"]
          storage_class_name = var.storage_class
          resources {
            requests = {
              storage = var.storage_size
            }
          }
        }
      }
    }
  }
}

