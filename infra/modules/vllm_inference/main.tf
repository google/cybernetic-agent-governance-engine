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

# Deployment for vLLM
resource "kubernetes_deployment" "vllm" {
  metadata {
    name      = var.deployment_name
    namespace = var.namespace
    labels = {
      app       = var.deployment_name
      component = "vllm-inference"
    }
  }

  spec {
    replicas = var.replicas

    selector {
      match_labels = {
        app = var.deployment_name
      }
    }

    template {
      metadata {
        labels = {
          app       = var.deployment_name
          component = "vllm-inference"
        }
      }

      spec {
        service_account_name = var.service_account_name

        affinity {
          # Pod Anti-Affinity for GPU distribution
          dynamic "pod_anti_affinity" {
            for_each = var.enable_pod_anti_affinity ? [1] : []
            content {
              required_during_scheduling_ignored_during_execution {
                label_selector {
                  match_expressions {
                    key      = "app"
                    operator = "In"
                    values   = [var.deployment_name]
                  }
                }
                topology_key = "kubernetes.io/hostname"
              }
            }
          }

          # Node Affinity: Prefer Spot instances, fallback to On-Demand
          node_affinity {
            preferred_during_scheduling_ignored_during_execution {
              weight = 100
              preference {
                match_expressions {
                  key      = "cloud.google.com/gke-provisioning"
                  operator = "In"
                  values   = ["spot"]
                }
              }
            }
          }
        }


        # Shared memory volume (required for vLLM)
        volume {
          name = "dshm"
          empty_dir {
            medium     = "Memory"
            size_limit = var.shared_memory_size
          }
        }

        # Model volume (optional)
        dynamic "volume" {
          for_each = var.enable_model_volume ? [1] : []
          content {
            name = "model-storage"
            persistent_volume_claim {
              claim_name = var.model_pvc_name
            }
          }
        }

        container {
          name              = "vllm"
          image             = var.image
          image_pull_policy = var.image_pull_policy

          # Resource limits (GPU)
          resources {
            limits = {
              "nvidia.com/gpu" = tostring(var.gpu_count)
              memory           = var.memory_limit
              cpu              = var.cpu_limit
            }
            requests = {
              memory           = var.memory_request
              cpu              = var.cpu_request
              "nvidia.com/gpu" = tostring(var.gpu_count)
            }
          }

          # Volume mounts
          volume_mount {
            name       = "dshm"
            mount_path = "/dev/shm"
          }

          dynamic "volume_mount" {
            for_each = var.enable_model_volume ? [1] : []
            content {
              name       = "model-storage"
              mount_path = "/model-storage"
            }
          }

          # Environment variables
          dynamic "env" {
            for_each = var.env_vars
            content {
              name  = env.key
              value = env.value
            }
          }

          env {
            name  = "MODEL_PATH"
            value = var.model_path
          }

          env {
            name  = "VLLM_LOAD_FORMAT"
            value = var.vllm_load_format
          }

          # S3/MinIO credentials (optional)
          dynamic "env" {
            for_each = var.enable_s3_credentials ? [1] : []
            content {
              name  = "S3_ENDPOINT_URL"
              value = var.s3_endpoint_url
            }
          }

          dynamic "env" {
            for_each = var.enable_s3_credentials ? [1] : []
            content {
              name = "AWS_ACCESS_KEY_ID"
              value_from {
                secret_key_ref {
                  name     = var.s3_credentials_secret
                  key      = "access-key"
                  optional = true
                }
              }
            }
          }

          dynamic "env" {
            for_each = var.enable_s3_credentials ? [1] : []
            content {
              name = "AWS_SECRET_ACCESS_KEY"
              value_from {
                secret_key_ref {
                  name     = var.s3_credentials_secret
                  key      = "secret-key"
                  optional = true
                }
              }
            }
          }

          env {
            name  = "AWS_EC2_METADATA_DISABLED"
            value = "true"
          }

          # Ports
          port {
            container_port = 8000
            name           = "http"
          }

          # Health checks
          readiness_probe {
            http_get {
              path = "/health"
              port = 8000
            }
            initial_delay_seconds = var.readiness_initial_delay
            period_seconds        = 10
          }

          liveness_probe {
            http_get {
              path = "/health"
              port = 8000
            }
            initial_delay_seconds = var.liveness_initial_delay
            period_seconds        = 15
          }

          # vLLM command
          command = ["/bin/bash", "-c"]
          args    = [var.vllm_command]
        }

        # Node selector for GPU nodes
        node_selector = var.node_selector

        # Tolerations for GPU nodes
        dynamic "toleration" {
          for_each = var.tolerations
          content {
            key      = toleration.value.key
            operator = toleration.value.operator
            value    = lookup(toleration.value, "value", null)
            effect   = toleration.value.effect
          }
        }
      }
    }
  }

  # GPU node pool autoscaling from 0 can take 15-20 minutes
  timeouts {
    create = "25m"
    update = "25m"
  }
}

# Service for vLLM
resource "kubernetes_service" "vllm" {
  metadata {
    name      = var.service_name
    namespace = var.namespace
    labels = {
      app       = var.deployment_name
      component = "vllm-inference"
    }
  }

  spec {
    type = var.service_type

    port {
      port        = 8000
      target_port = 8000
      protocol    = "TCP"
      name        = "http"
    }

    selector = {
      app = var.deployment_name
    }
  }
}

# Pod Disruption Budget (optional)
resource "kubernetes_pod_disruption_budget_v1" "vllm" {
  count = var.enable_pdb ? 1 : 0

  metadata {
    name      = "${var.deployment_name}-pdb"
    namespace = var.namespace
  }

  spec {
    min_available = var.pdb_min_available

    selector {
      match_labels = {
        app = var.deployment_name
      }
    }
  }
}
