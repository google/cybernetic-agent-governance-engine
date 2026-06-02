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

resource "kubernetes_deployment" "gateway" {
  metadata {
    name      = "gateway"
    namespace = var.namespace
    labels = {
      app = "gateway"
    }
  }

  spec {
    replicas = var.replicas

    selector {
      match_labels = {
        app = "gateway"
      }
    }

    template {
      metadata {
        labels = {
          app = "gateway"
        }
      }

      spec {
        service_account_name = "financial-advisor-sa"

        container {
          name              = "gateway"
          image             = var.image
          image_pull_policy = "Always"

          port {
            container_port = 8080
            name           = "http"
          }
          port {
            container_port = 50051
            name           = "grpc"
          }

          env_from {
            secret_ref {
              name = "advisor-secrets"
            }
          }

          env {
            name  = "PORT"
            value = "8080"
          }
          env {
            name  = "GATEWAY_GRPC_PORT"
            value = "50051"
          }
          env {
            name  = "GOOGLE_CLOUD_PROJECT"
            value = var.project_id
          }
          env {
            name  = "GOOGLE_CLOUD_LOCATION"
            value = var.region
          }
          env {
            name  = "ENABLE_LOGGING"
            value = var.enable_logging
          }
          env {
            name  = "OTEL_TRACES_EXPORTER"
            value = "otlp"
          }
          env {
            name  = "OTEL_EXPORTER_OTLP_ENDPOINT"
            value = "http://otel-collector.${var.namespace}:4318/v1/traces"
          }
          env {
            name  = "OTEL_PYTHON_INSTRUMENTATION_HTTPX_CAPTURE_REQUEST_BODY"
            value = "true"
          }
          env {
            name  = "OTEL_PYTHON_INSTRUMENTATION_HTTPX_CAPTURE_RESPONSE_BODY"
            value = "true"
          }
          env {
            name  = "OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT"
            value = "true"
          }
          env {
            name  = "OTEL_PYTHON_EXCLUDED_URLS"
            value = var.otel_python_excluded_urls
          }
          env {
            name  = "OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SERVER_REQUEST"
            value = "content-type,accept,user-agent,x-request-id,x-goog-authenticated-user-email"
          }
          env {
            name  = "OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SERVER_RESPONSE"
            value = "content-type,content-length"
          }
          env {
            name  = "OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SANITIZE_FIELDS"
            value = ".*session.*,.*token.*,authorization,set-cookie,cookie,x-api-key,proxy-authorization"
          }
          env {
            name  = "REDIS_PORT"
            value = var.redis_port
          }
          env {
            name  = "REDIS_HOST"
            value = var.redis_host
          }
          env {
            name  = "REDIS_PASSWORD"
            value = var.redis_password
          }
          env {
            name  = "REDIS_URL"
            value = var.redis_password != "" ? "redis://:${var.redis_password}@${var.redis_host}:${var.redis_port}" : "redis://${var.redis_host}:${var.redis_port}"
          }
          env {
            name  = "VLLM_BASE_URL"
            value = var.vllm_base_url
          }
          env {
            name  = "VLLM_GATEWAY_URL"
            value = var.vllm_gateway_url
          }
          env {
            name  = "VLLM_REASONING_API_BASE"
            value = var.vllm_reasoning_api_base
          }
          env {
            name  = "VLLM_FAST_API_BASE"
            value = var.vllm_fast_api_base
          }
          env {
            name  = "GUARDRAILS_MODEL_NAME"
            value = var.guardrails_model_name
          }
          env {
            name  = "SERVICE_NAME"
            value = "hybrid-gateway"
          }
          env {
            name  = "CAGE_ENV"
            value = var.cage_env
          }
          env {
            name  = "ENVIRONMENT"
            value = var.cage_env
          }
          env {
            name  = "OPA_URL"
            value = var.opa_url
          }

          resources {
            requests = {
              cpu    = "1000m"
              memory = "2Gi"
            }
            limits = {
              cpu    = "2000m"
              memory = "4Gi"
            }
          }
        }
      }
    }
  }
}

resource "kubernetes_service" "gateway" {
  metadata {
    name      = "gateway"
    namespace = var.namespace
  }

  spec {
    type = "ClusterIP"

    port {
      port        = 8080
      target_port = 8080
      protocol    = "TCP"
      name        = "http"
    }

    port {
      port        = 50051
      target_port = 50051
      protocol    = "TCP"
      name        = "grpc"
    }

    selector = {
      app = "gateway"
    }
  }
}
