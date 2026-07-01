terraform {
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.23"
    }
  }
}

resource "kubernetes_deployment" "compliance_bridge" {
  metadata {
    name      = "compliance-bridge"
    namespace = var.namespace
    labels = {
      app                             = "compliance-bridge"
      "compliance.iso42001/component" = "evidence-bridge"
      "app.kubernetes.io/version"     = "0.1.0"
    }
  }

  spec {
    replicas = var.replicas

    selector {
      match_labels = {
        app = "compliance-bridge"
      }
    }

    template {
      metadata {
        labels = {
          app = "compliance-bridge"
        }
      }

      spec {
        service_account_name = "financial-advisor-sa"

        container {
          name              = "compliance-bridge"
          image             = var.image
          image_pull_policy = "Always"

          port {
            container_port = 3001
            name           = "http"
          }

          env {
            name  = "PORT"
            value = "3001"
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
            name = "LANGFUSE_PUBLIC_KEY"
            value_from {
              secret_key_ref {
                name = "langfuse-secrets"
                key  = "public-key"
              }
            }
          }

          env {
            name = "LANGFUSE_SECRET_KEY"
            value_from {
              secret_key_ref {
                name = "langfuse-secrets"
                key  = "secret-key"
              }
            }
          }

          env {
            name = "LANGFUSE_COMPLIANCE_PUBLIC_KEY"
            value_from {
              secret_key_ref {
                name     = "langfuse-compliance-secrets"
                key      = "public-key"
                optional = true
              }
            }
          }

          env {
            name = "LANGFUSE_COMPLIANCE_SECRET_KEY"
            value_from {
              secret_key_ref {
                name     = "langfuse-compliance-secrets"
                key      = "secret-key"
                optional = true
              }
            }
          }

          env {
            name  = "LANGFUSE_HOST"
            value = var.langfuse_host
          }

          env {
            name  = "REMEDIATION_MODEL"
            value = var.remediation_model
          }

          env {
            name  = "REMEDIATION_MAX_TOKENS"
            value = var.remediation_max_tokens
          }

          env {
            name  = "REMEDIATION_TIMEOUT_MS"
            value = var.remediation_timeout_ms
          }

          env {
            name  = "VLLM_BASE_URL"
            value = var.vllm_base_url
          }

          env {
            name  = "VLLM_API_KEY"
            value = var.vllm_api_key
          }

          env {
            name  = "ALERT_CHANNEL"
            value = var.alert_channel
          }

          env {
            name = "COMPLIANCE_ALERT_WEBHOOK_URL"
            value_from {
              secret_key_ref {
                name     = "compliance-alert-secrets"
                key      = "webhook-url"
                optional = true
              }
            }
          }

          env {
            name  = "OSCAL_S3_ENDPOINT"
            value = "https://storage.googleapis.com"
          }

          env {
            name  = "OSCAL_S3_BUCKET"
            value = var.oscal_s3_bucket
          }

          env {
            name  = "OSCAL_S3_REGION"
            value = var.oscal_s3_region
          }

          env {
            name = "OSCAL_S3_ACCESS_KEY"
            value_from {
              secret_key_ref {
                name     = "oscal-artifact-secrets"
                key      = "hmac-access-key"
                optional = true
              }
            }
          }

          env {
            name = "OSCAL_S3_SECRET_KEY"
            value_from {
              secret_key_ref {
                name     = "oscal-artifact-secrets"
                key      = "hmac-secret-key"
                optional = true
              }
            }
          }

          security_context {
            allow_privilege_escalation = false
            run_as_non_root            = true
            run_as_user                = 1000
            capabilities {
              drop = ["ALL"]
            }
            seccomp_profile {
              type = "RuntimeDefault"
            }
          }

          resources {
            requests = {
              cpu    = "50m"
              memory = "128Mi"
            }
            limits = {
              cpu    = "200m"
              memory = "256Mi"
            }
          }

          liveness_probe {
            http_get {
              path = "/health"
              port = 3001
            }
            initial_delay_seconds = 120
            period_seconds        = 30
            timeout_seconds       = 5
            failure_threshold     = 3
          }

          readiness_probe {
            http_get {
              path = "/health"
              port = 3001
            }
            initial_delay_seconds = 120
            period_seconds        = 10
            timeout_seconds       = 5
            failure_threshold     = 3
          }
        }
      }
    }
  }
}

resource "kubernetes_service" "compliance_bridge" {
  metadata {
    name      = "compliance-bridge"
    namespace = var.namespace
  }

  spec {
    type = "ClusterIP"

    port {
      port        = 80
      target_port = 3001
      protocol    = "TCP"
      name        = "http"
    }

    selector = {
      app = "compliance-bridge"
    }
  }
}
