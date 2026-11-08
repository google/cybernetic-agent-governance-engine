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
    name      = "reconciliation-worker-redis-ca"
    namespace = var.namespace
    labels = {
      app = "reconciliation-worker"
    }
  }

  data = {
    "ca.pem" = var.redis_ca_pem
  }
}

# Holds the non-secret KMS CryptoKeyVersion URI under the canonical secret key
# expected by kubernetes_deployment.reconciliation_worker below (POAM-2026-096).
resource "kubernetes_secret" "reconciliation_worker" {
  metadata {
    name      = "reconciliation-worker-secrets"
    namespace = var.namespace
    labels = {
      app                       = "reconciliation-worker"
      "cage.io/account-purpose" = "ledger-reconciliation"
    }
  }

  type = "Opaque"

  data = {
    "reconciler-kms-key" = var.reconciler_kms_key
  }
}

# Single-writer continuous ground-truth reconciliation daemon (POAM-2026-096,
# CA-7, SI-10, G8). Recreate strategy prevents two reconcilers from publishing
# overlapping sequence counters during a rollout.
resource "kubernetes_deployment" "reconciliation_worker" {
  lifecycle {
    precondition {
      condition     = var.ttl_seconds >= 2 * var.poll_interval_seconds
      error_message = "CAGE Invariant (POAM-2026-096): reconciliation_worker ttl_seconds must be >= 2 * poll_interval_seconds so verified CBF snapshots never expire between ticks."
    }
    precondition {
      condition     = !var.enable_redis_tls || trimspace(var.redis_ca_pem) != ""
      error_message = "CAGE Invariant (SC-8 / POAM-2026-086): when enable_redis_tls=true, redis_ca_pem must be non-empty so reconciliation-worker pins /etc/cage/tls/redis/ca.pem."
    }
  }

  metadata {
    name      = "reconciliation-worker"
    namespace = var.namespace
    labels = {
      app                         = "reconciliation-worker"
      "app.kubernetes.io/version" = "2.1.0"
      "cage.io/account-purpose"   = "ledger-reconciliation"
    }
  }

  wait_for_rollout = false

  spec {
    replicas               = 1
    revision_history_limit = 3

    strategy {
      type = "Recreate"
    }

    selector {
      match_labels = {
        app = "reconciliation-worker"
      }
    }

    template {
      metadata {
        labels = {
          app                       = "reconciliation-worker"
          "cage.io/account-purpose" = "ledger-reconciliation"
        }
        annotations = merge(
          var.redis_ca_pem != "" ? {
            "cage.io/redis-ca-sha256" = sha256(var.redis_ca_pem)
          } : {},
          var.network_policy_hash != "" ? {
            "cage.io/network-policy-sha256" = var.network_policy_hash
          } : {},
        )
      }

      spec {
        service_account_name            = var.service_account_name
        automount_service_account_token = false

        # Governance-critical pod: explicit anti-Spot nodeAffinity (§3).
        affinity {
          node_affinity {
            required_during_scheduling_ignored_during_execution {
              node_selector_term {
                match_expressions {
                  key      = "cloud.google.com/gke-spot"
                  operator = "NotIn"
                  values   = ["true"]
                }
              }
            }
          }
        }

        security_context {
          run_as_non_root = true
          seccomp_profile {
            type = "RuntimeDefault"
          }
        }

        container {
          name              = "reconciliation-worker"
          image             = var.image
          image_pull_policy = "IfNotPresent"
          command           = ["python", "-m", "src.gateway.governance.reconciliation.daemon"]

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

          env {
            name  = "CAGE_ENV"
            value = var.cage_env
          }
          env {
            name  = "CAGE_KMS_PROVIDER"
            value = var.cage_kms_provider
          }
          env {
            name  = "RECONCILIATION_PROVIDER"
            value = "simulated"
          }
          env {
            name  = "CAGE_SIM_LEDGER_BACKEND"
            value = "redis"
          }
          env {
            name  = "CAGE_SIM_SETTLEMENT_LAG_SECONDS"
            value = tostring(var.settlement_lag_seconds)
          }
          env {
            name = "RECONCILER_KMS_KEY"
            value_from {
              secret_key_ref {
                name = kubernetes_secret.reconciliation_worker.metadata[0].name
                key  = "reconciler-kms-key"
              }
            }
          }
          env {
            name = "CAGE_DEPLOYMENT_REGION"
            value_from {
              config_map_key_ref {
                name     = var.deployment_config_map_name
                key      = "CAGE_DEPLOYMENT_REGION"
                optional = false
              }
            }
          }
          env {
            name  = "REDIS_URL"
            value = var.redis_url
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
            name  = "RECONCILIATION_POLL_INTERVAL_SECONDS"
            value = tostring(var.poll_interval_seconds)
          }
          env {
            name  = "RECONCILIATION_TTL_SECONDS"
            value = tostring(var.ttl_seconds)
          }
          env {
            name  = "LANGSMITH_TRACING"
            value = "false"
          }
          env {
            name  = "LANGCHAIN_TRACING_V2"
            value = "false"
          }
          env {
            name  = "OTEL_TRACES_EXPORTER"
            value = var.otel_endpoint != "" ? "otlp" : "none"
          }
          dynamic "env" {
            for_each = var.otel_endpoint != "" ? [1] : []
            content {
              name  = "OTEL_EXPORTER_OTLP_ENDPOINT"
              value = var.otel_endpoint
            }
          }
          dynamic "env" {
            for_each = var.otel_endpoint != "" ? [1] : []
            content {
              name  = "OTEL_EXPORTER_OTLP_PROTOCOL"
              value = "http/protobuf"
            }
          }

          volume_mount {
            name       = "tmp-dir"
            mount_path = "/tmp"
          }

          dynamic "volume_mount" {
            for_each = var.redis_ca_pem != "" ? [1] : []
            content {
              name       = "redis-ca"
              mount_path = "/etc/cage/tls/redis"
              read_only  = true
            }
          }

          resources {
            requests = {
              cpu    = "25m"
              memory = "128Mi"
            }
            limits = {
              cpu    = "100m"
              memory = "256Mi"
            }
          }
        }

        volume {
          name = "tmp-dir"
          empty_dir {}
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
