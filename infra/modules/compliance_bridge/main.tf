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

resource "kubernetes_config_map_v1" "redis_ca" {
  count = var.redis_ca_pem != "" ? 1 : 0

  metadata {
    name      = "compliance-bridge-redis-ca"
    namespace = var.namespace
    labels = {
      app = "compliance-bridge"
    }
  }

  data = {
    "ca.pem" = var.redis_ca_pem
  }
}

resource "kubernetes_deployment" "compliance_bridge" {
  lifecycle {
    precondition {
      condition     = !var.enable_redis_tls || trimspace(var.redis_ca_pem) != ""
      error_message = "CAGE Invariant (SC-8 / POAM-2026-086): when enable_redis_tls=true, redis_ca_pem must be non-empty so the pod mounts /etc/cage/tls/redis/ca.pem and sets REDIS_CA_CERT_PATH."
    }
  }

  metadata {
    name      = "compliance-bridge"
    namespace = var.namespace
    labels = {
      app                             = "compliance-bridge"
      "compliance.iso42001/component" = "evidence-bridge"
      "app.kubernetes.io/version"     = "0.1.0"
    }
  }

  wait_for_rollout = false

  spec {
    replicas               = var.replicas
    revision_history_limit = 3

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
        annotations = var.redis_ca_pem != "" ? {
          "cage.io/redis-ca-sha256" = sha256(var.redis_ca_pem)
        } : {}
      }

      spec {
        service_account_name = var.service_account_name

        security_context {
          run_as_non_root = true
          run_as_user     = 1000
          seccomp_profile {
            type = "RuntimeDefault"
          }
        }

        container {
          name              = "compliance-bridge"
          image             = var.image
          image_pull_policy = "Always"

          port {
            container_port = 3001
            name           = "http"
          }

          env_from {
            secret_ref {
              name = "advisor-secrets"
            }
          }

          env {
            name  = "PORT"
            value = "3001"
          }

          env {
            name  = "CAGE_ENV"
            value = var.cage_env
          }

          # K-3 / Track 6d (§5.2): EVIDENCE_KMS_KEY for asymmetric compliance evidence signing.
          # Separate from the gateway's KMS_GOVERNANCE_KEY and the reconciler's RECONCILER_KMS_KEY.
          env {
            name  = "EVIDENCE_KMS_KEY"
            value = var.evidence_kms_key
          }

          env {
            name  = "ENVIRONMENT"
            value = var.cage_env
          }

          # CAGE_DEPLOYMENT_REGION controls which jurisdictional compliance
          # framework controls (US_FED/NIST/FedRAMP, EU_ECB/EU AI Act,
          # APAC_MAS/MAS FEAT) are exposed by GET /v1/controls and
          # GET /v1/metrics/summary. Must match the region configured for
          # the gateway and governed_advisor modules.
          env {
            name  = "CAGE_DEPLOYMENT_REGION"
            value = var.cage_deployment_region
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
            name  = "OSCAL_BUCKET_NAME"
            value = var.evidence_cold_store_bucket != "" ? var.evidence_cold_store_bucket : var.oscal_s3_bucket
          }

          # §2.6: Retention-locked GCS WORM bucket is the system of record
          env {
            name  = "EVIDENCE_COLD_STORE"
            value = var.evidence_cold_store
          }

          env {
            name  = "EVIDENCE_COLD_STORE_BUCKET"
            value = var.evidence_cold_store_bucket != "" ? var.evidence_cold_store_bucket : var.oscal_s3_bucket
          }

          env {
            name  = "CMEK_KEY_RESOURCE_NAME"
            value = var.cmek_key_resource_name
          }

          # ─── Evidence custody (EvidenceCustodian) ─────────────────────────
          # Reads the gateway's evidence stream on the governance Memorystore
          # instance (same URL/db/key as the gateway, same TLS + IAM auth mode),
          # re-verifies the chain, signs per-batch attestations with
          # EVIDENCE_KMS_KEY and writes batches to EVIDENCE_COLD_STORE_BUCKET.
          env {
            name  = "EVIDENCE_STREAM_ENABLED"
            value = "true"
          }

          env {
            name  = "EVIDENCE_STREAM_REDIS_URL"
            value = var.evidence_stream_redis_url
          }

          env {
            name  = "EVIDENCE_STREAM_REDIS_DB"
            value = tostring(var.evidence_stream_redis_db)
          }

          env {
            name  = "EVIDENCE_STREAM_KEY"
            value = var.evidence_stream_key
          }

          env {
            name  = "EVIDENCE_CUSTODY_INTERVAL_S"
            value = tostring(var.evidence_custody_interval_s)
          }

          env {
            name  = "EVIDENCE_VERIFY_INTERVAL_S"
            value = tostring(var.evidence_verify_interval_s)
          }

          env {
            name  = "EVIDENCE_VERIFY_PREFIX"
            value = var.evidence_verify_prefix
          }

          env {
            name  = "OSCAL_REQUIRE_VERIFIED_CUSTODY"
            value = tostring(var.oscal_require_verified_custody != null ? var.oscal_require_verified_custody : contains(["staging", "prod", "production"], lower(var.cage_env)))
          }

          dynamic "env" {
            for_each = var.evidence_trust_anchors_file != "" ? [1] : []
            content {
              name  = "EVIDENCE_TRUST_ANCHORS_FILE"
              value = var.evidence_trust_anchors_file
            }
          }

          env {
            name  = "REDIS_TLS"
            value = tostring(var.enable_redis_tls)
          }

          dynamic "env" {
            for_each = var.redis_ca_pem != "" ? [1] : []
            content {
              name  = "REDIS_CA_CERT_PATH"
              value = "/etc/cage/tls/redis/ca.pem"
            }
          }

          dynamic "env" {
            for_each = var.redis_auth_mode != "" ? [1] : []
            content {
              name  = "REDIS_AUTH_MODE"
              value = var.redis_auth_mode
            }
          }

          # §2.6: ClickHouse is the analytical query plane fed by clickhouse_sink.py
          env {
            name  = "CLICKHOUSE_ENABLED"
            value = tostring(var.clickhouse_enabled)
          }

          env {
            name  = "CLICKHOUSE_HOST"
            value = var.clickhouse_host
          }

          env {
            name  = "CLICKHOUSE_PORT"
            value = var.clickhouse_port
          }

          env {
            name  = "CLICKHOUSE_DATABASE"
            value = var.clickhouse_database
          }

          env {
            name  = "CLICKHOUSE_USERNAME"
            value = var.clickhouse_username
          }

          env {
            name = "CLICKHOUSE_PASSWORD"
            value_from {
              secret_key_ref {
                name = var.clickhouse_password_secret_name
                key  = var.clickhouse_password_secret_key
              }
            }
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

          dynamic "volume_mount" {
            for_each = var.redis_ca_pem != "" ? [1] : []
            content {
              name       = "redis-ca"
              mount_path = "/etc/cage/tls/redis"
              read_only  = true
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
              memory = "512Mi"
            }
            limits = {
              cpu    = "200m"
              memory = "1Gi"
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

        dynamic "volume" {
          for_each = var.redis_ca_pem != "" ? [1] : []
          content {
            name = "redis-ca"
            config_map {
              name = kubernetes_config_map_v1.redis_ca[0].metadata[0].name
            }
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
