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

resource "kubernetes_deployment" "governed_advisor" {
  metadata {
    name      = "governed-financial-advisor"
    namespace = var.namespace
    labels = {
      app = "governed-financial-advisor"
    }
  }

  spec {
    replicas = var.replicas

    selector {
      match_labels = {
        app = "governed-financial-advisor"
      }
    }

    template {
      metadata {
        labels = {
          app = "governed-financial-advisor"
        }
      }

      spec {
        service_account_name = "financial-advisor-sa"

        container {
          name              = "ingress-agent"
          image             = var.image
          image_pull_policy = "Always"

          port {
            container_port = 8080
            name           = "http"
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
            name  = "DEPLOY_TIMESTAMP"
            value = timestamp()
          }

          # Infrastructure
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

          # Redis Session Management
          env {
            name  = "REDIS_HOST"
            value = var.redis_host
          }
          env {
            name  = "REDIS_PORT"
            value = var.redis_port
          }
          env {
            name  = "REDIS_URL"
            value = var.redis_password != "" ? "redis://:${var.redis_password}@${var.redis_host}:${var.redis_port}" : "redis://${var.redis_host}:${var.redis_port}"
          }

          # Model Configuration (Tiered)
          env {
            name  = "MODEL_FAST"
            value = var.model_fast
          }
          env {
            name  = "MODEL_REASONING"
            value = var.model_reasoning
          }
          env {
            name  = "MODEL_CONSENSUS"
            value = var.model_consensus
          }

          # vLLM Inference Endpoints
          env {
            name  = "VLLM_BASE_URL"
            value = var.vllm_base_url
          }
          env {
            name  = "VLLM_API_KEY"
            value = var.vllm_api_key
          }
          env {
            name  = "OPENAI_API_BASE"
            value = var.vllm_base_url
          }
          env {
            name  = "OPENAI_API_KEY"
            value = var.vllm_api_key
          }
          env {
            name  = "VLLM_FAST_API_BASE"
            value = var.vllm_fast_api_base
          }
          env {
            name  = "VLLM_REASONING_API_BASE"
            value = var.vllm_reasoning_api_base
          }
          env {
            name  = "VLLM_GATEWAY_URL"
            value = var.vllm_gateway_url
          }

          # Policy Engine
          env {
            name  = "OPA_URL"
            value = var.opa_url
          }

          # Observability: Langfuse
          env {
            name  = "LANGCHAIN_TRACING_V2"
            value = "false"
          }
          env {
            name  = "LANGSMITH_TRACING"
            value = "false"
          }
          env {
            name  = "LANGFUSE_HOST"
            value = var.langfuse_host
          }
          env {
            name  = "ENABLE_TRACING"
            value = "true"
          }

          # OpenTelemetry (Cold Tier)
          env {
            name  = "OTEL_TRACES_EXPORTER"
            value = "otlp"
          }
          env {
            name  = "OTEL_METRICS_EXPORTER"
            value = "none"
          }
          env {
            name  = "OTEL_LOGS_EXPORTER"
            value = "none"
          }
          env {
            name  = "OTEL_EXPORTER_OTLP_ENDPOINT"
            value = "http://otel-collector.${var.namespace}:4318/v1/traces"
          }
          env {
            name  = "OTEL_EXPORTER_OTLP_HEADERS"
            value = var.otel_exporter_otlp_headers
          }
          env {
            name  = "TRACE_SAMPLING_RATE"
            value = var.trace_sampling_rate
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

          # Cold Tier Storage
          env {
            name  = "COLD_TIER_GCS_BUCKET"
            value = var.cold_tier_gcs_bucket
          }
          env {
            name  = "COLD_TIER_GCS_PREFIX"
            value = var.cold_tier_gcs_prefix
          }

          # Gateway Configuration
          env {
            name  = "GATEWAY_HOST"
            value = var.gateway_host
          }
          env {
            name  = "GATEWAY_GRPC_PORT"
            value = var.gateway_grpc_port
          }
          env {
            name  = "GATEWAY_URL"
            value = var.gateway_url
          }
          env {
            name  = "MCP_SERVER_SSE_URL"
            value = "http://gateway:8080/mcp/sse"
          }
          env {
            name  = "GOVERNANCE_SALT"
            value = var.governance_salt
          }



          # MCP Configuration
          env {
            name  = "MCP_MODE"
            value = var.mcp_mode
          }
          env {
            name  = "ALPHAVANTAGE_API_KEY"
            value = var.alphavantage_api_key
          }

          # Secrets
          env {
            name = "HUGGING_FACE_HUB_TOKEN"
            value_from {
              secret_key_ref {
                name = "hf-token-secret"
                key  = "token"
              }
            }
          }

          resources {
            requests = {
              cpu    = "100m"
              memory = "1Gi"
            }
            limits = {
              cpu    = "500m"
              memory = "2Gi"
            }
          }
        }


      }
    }
  }
}

resource "kubernetes_service" "governed_advisor" {
  metadata {
    name      = "governed-financial-advisor"
    namespace = var.namespace
  }

  spec {
    type = "ClusterIP"

    port {
      port        = 80
      target_port = 8080
      protocol    = "TCP"
      name        = "http"
    }

    selector = {
      app = "governed-financial-advisor"
    }
  }
}
