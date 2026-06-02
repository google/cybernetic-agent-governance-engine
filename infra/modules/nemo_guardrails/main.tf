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

# ─── NeMo Guardrails + Presidio Deployment ────────────────────────────────────

resource "kubernetes_config_map" "nemo_config" {
  metadata {
    name      = "nemo-guardrails-config"
    namespace = var.namespace
    labels = {
      app       = "nemo-guardrails"
      component = "guardrails"
    }
  }

  data = {
    # Colang configuration for conversational rails
    "config.yml" = var.nemo_config_yaml != "" ? var.nemo_config_yaml : <<-YAML
      models:
        - type: main
          engine: openai
          model: ${var.llm_model_name}

      instructions:
        - type: general
          content: |
            You are a governed financial AI assistant.
            Refuse any requests for illegal financial advice,
            market manipulation, or insider trading instructions.

      rails:
        input:
          flows:
            - check jailbreak
        output:
          flows:
            - check output financial compliance
    YAML

    "financial_rails.co" = <<-COLANG
      define user ask about illegal trading
        "insider trading"
        "market manipulation"
        "pump and dump"
        "front running"

      define bot refuse illegal request
        "I cannot assist with requests that violate financial regulations or securities law."

      define flow check jailbreak
        user ask about illegal trading
        bot refuse illegal request

      define flow check input sensitive data
        $result = execute check_pii(text=$user_message)
        if $result.has_pii
          bot "I noticed your message contains sensitive personal information. Please rephrase without including personal identifiers."
          stop
    COLANG
  }
}

resource "kubernetes_deployment" "nemo_guardrails" {
  metadata {
    name      = var.deployment_name
    namespace = var.namespace
    labels = {
      app       = "nemo-guardrails"
      component = "guardrails"
    }
  }

  spec {
    replicas = var.replicas

    selector {
      match_labels = {
        app = "nemo-guardrails"
      }
    }

    template {
      metadata {
        labels = {
          app       = "nemo-guardrails"
          component = "guardrails"
        }
        annotations = {
          # Force rolling update on config change
          "checksum/config" = sha256(jsonencode(kubernetes_config_map.nemo_config.data))
        }
      }

      spec {
        # ── Volume: NeMo Colang config ──────────────────────────────────────
        volume {
          name = "nemo-config"
          config_map {
            name = kubernetes_config_map.nemo_config.metadata[0].name
          }
        }

        # ── Container 1: NVIDIA NeMo Guardrails server ──────────────────────
        container {
          name              = "nemo-guardrails"
          image             = var.nemo_image
          image_pull_policy = var.image_pull_policy

          port {
            container_port = 8000
            name           = "nemo-http"
          }

          env {
            name  = "NEMO_CONFIG_PATH"
            value = "/etc/nemo/config"
          }

          env {
            name  = "PRESIDIO_ANALYZER_URL"
            value = "http://localhost:5001"
          }

          env {
            name  = "PRESIDIO_ANONYMIZER_URL"
            value = "http://localhost:5002"
          }

          # LLM backend URL for NeMo rails (points at vLLM fast service)
          env {
            name  = "OPENAI_API_BASE"
            value = var.llm_api_base
          }

          env {
            name  = "OPENAI_API_KEY"
            value = var.llm_api_key
          }

          env {
            name  = "NEMO_LLM_MODEL"
            value = var.llm_model_name
          }

          volume_mount {
            name       = "nemo-config"
            mount_path = "/etc/nemo/config"
            read_only  = true
          }

          resources {
            requests = {
              cpu    = var.nemo_cpu_request
              memory = var.nemo_memory_request
            }
            limits = var.nemo_cpu_limit != "" ? {
              cpu    = var.nemo_cpu_limit
              memory = var.nemo_memory_limit
            } : {}
          }

          liveness_probe {
            tcp_socket {
              port = 8000
            }
            initial_delay_seconds = 45
            period_seconds        = 15
            failure_threshold     = 5
          }

          readiness_probe {
            tcp_socket {
              port = 8000
            }
            initial_delay_seconds = 20
            period_seconds        = 10
          }

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

        # ── Container 2: Microsoft Presidio Analyzer ────────────────────────
        container {
          name              = "presidio-analyzer"
          image             = var.presidio_analyzer_image
          image_pull_policy = var.image_pull_policy

          port {
            container_port = 5001
            name           = "pii-analyze"
          }

          env {
            name  = "PORT"
            value = "5001"
          }

          # Enable all entity recognisers relevant to financial domain
          env {
            name  = "PRESIDIO_RECOGNIZERS"
            value = var.presidio_recognizers
          }

          resources {
            requests = {
              cpu    = var.presidio_cpu_request
              memory = var.presidio_memory_request
            }
            limits = var.presidio_cpu_limit != "" ? {
              cpu    = var.presidio_cpu_limit
              memory = var.presidio_memory_limit
            } : {}
          }

          liveness_probe {
            http_get {
              path = "/health"
              port = 5001
            }
            initial_delay_seconds = 30
            period_seconds        = 15
          }

          readiness_probe {
            http_get {
              path = "/health"
              port = 5001
            }
            initial_delay_seconds = 15
            period_seconds        = 10
          }

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

        # ── Container 3: Microsoft Presidio Anonymizer ──────────────────────
        container {
          name              = "presidio-anonymizer"
          image             = var.presidio_anonymizer_image
          image_pull_policy = var.image_pull_policy

          port {
            container_port = 5002
            name           = "presidio-anon"
          }

          env {
            name  = "PORT"
            value = "5002"
          }

          resources {
            requests = {
              cpu    = var.presidio_cpu_request
              memory = var.presidio_memory_request
            }
            limits = var.presidio_cpu_limit != "" ? {
              cpu    = var.presidio_cpu_limit
              memory = var.presidio_memory_limit
            } : {}
          }

          liveness_probe {
            http_get {
              path = "/health"
              port = 5002
            }
            initial_delay_seconds = 30
            period_seconds        = 15
          }

          readiness_probe {
            http_get {
              path = "/health"
              port = 5002
            }
            initial_delay_seconds = 15
            period_seconds        = 10
          }

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

        # Node selector and tolerations
        node_selector = var.node_selector

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

# ─── Services ─────────────────────────────────────────────────────────────────

# NeMo Guardrails service (port 8000) — consumed by gateway and backend
resource "kubernetes_service" "nemo_guardrails" {
  metadata {
    name      = var.service_name
    namespace = var.namespace
    labels = {
      app       = "nemo-guardrails"
      component = "guardrails"
    }
  }

  spec {
    type = "ClusterIP"

    port {
      name        = "nemo-http"
      port        = 8000
      target_port = 8000
      protocol    = "TCP"
    }

    selector = {
      app = "nemo-guardrails"
    }
  }
}

# Presidio Analyzer service — internal only (NeMo reaches it via localhost in-pod)
# Exposed as a ClusterIP service for out-of-pod debugging / direct calls.
resource "kubernetes_service" "presidio_analyzer" {
  metadata {
    name      = "${var.service_name}-presidio-analyzer"
    namespace = var.namespace
    labels = {
      app       = "nemo-guardrails"
      component = "presidio-analyzer"
    }
  }

  spec {
    type = "ClusterIP"

    port {
      name        = "http"
      port        = 5001
      target_port = 5001
      protocol    = "TCP"
    }

    selector = {
      app = "nemo-guardrails"
    }
  }
}

# Presidio Anonymizer service
resource "kubernetes_service" "presidio_anonymizer" {
  metadata {
    name      = "${var.service_name}-presidio-anonymizer"
    namespace = var.namespace
    labels = {
      app       = "nemo-guardrails"
      component = "presidio-anonymizer"
    }
  }

  spec {
    type = "ClusterIP"

    port {
      name        = "http"
      port        = 5002
      target_port = 5002
      protocol    = "TCP"
    }

    selector = {
      app = "nemo-guardrails"
    }
  }
}

# ─── Pod Disruption Budget ────────────────────────────────────────────────────

resource "kubernetes_pod_disruption_budget_v1" "nemo_guardrails" {
  count = var.enable_pdb ? 1 : 0

  metadata {
    name      = "${var.deployment_name}-pdb"
    namespace = var.namespace
  }

  spec {
    min_available = 1

    selector {
      match_labels = {
        app = "nemo-guardrails"
      }
    }
  }
}
