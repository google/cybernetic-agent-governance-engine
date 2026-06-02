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
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }
}

# Generate Langfuse secrets
resource "random_id" "nextauth_secret" {
  byte_length = 32
}

resource "random_id" "salt" {
  byte_length = 32
}

resource "random_id" "encryption_key" {
  byte_length = 32
}

resource "random_id" "public_key" {
  byte_length = 16
  prefix      = "pk-lf-"
}

resource "random_id" "secret_key" {
  byte_length = 16
  prefix      = "sk-lf-"
}

# Langfuse secrets
resource "kubernetes_secret" "langfuse_secrets" {
  metadata {
    name      = "langfuse-secrets"
    namespace = var.namespace
  }

  data = {
    "nextauth-secret" = random_id.nextauth_secret.hex
    "salt"            = random_id.salt.hex
    "encryption-key"  = random_id.encryption_key.hex
    "public-key"      = coalesce(var.langfuse_public_key, random_id.public_key.hex)
    "secret-key"      = coalesce(var.langfuse_secret_key, random_id.secret_key.hex)
  }
}

# Langfuse Web Deployment
resource "kubernetes_deployment" "langfuse_web" {
  metadata {
    name      = "langfuse-web"
    namespace = var.namespace
    labels = {
      app       = "langfuse-web"
      component = "observability"
    }
  }

  wait_for_rollout = false

  spec {
    replicas = var.web_replicas

    selector {
      match_labels = {
        app = "langfuse-web"
      }
    }

    template {
      metadata {
        labels = {
          app = "langfuse-web"
        }
      }

      spec {
        container {
          name  = "langfuse-web"
          image = var.langfuse_image

          port {
            container_port = 3000
            name           = "http"
          }

          env {
            name  = "DATABASE_URL"
            value = var.database_url
          }

          dynamic "env" {
            for_each = var.langfuse_init_user_email != "" ? [1] : []
            content {
              name  = "LANGFUSE_INIT_USER_EMAIL"
              value = var.langfuse_init_user_email
            }
          }

          dynamic "env" {
            for_each = var.langfuse_init_user_password != "" ? [1] : []
            content {
              name  = "LANGFUSE_INIT_USER_PASSWORD"
              value = var.langfuse_init_user_password
            }
          }

          dynamic "env" {
            for_each = var.langfuse_init_project_name != "" ? [1] : []
            content {
              name  = "LANGFUSE_INIT_PROJECT_NAME"
              value = var.langfuse_init_project_name
            }
          }

          dynamic "env" {
            for_each = var.langfuse_init_project_id != "" ? [1] : []
            content {
              name  = "LANGFUSE_INIT_PROJECT_ID"
              value = var.langfuse_init_project_id
            }
          }

          dynamic "env" {
            for_each = var.langfuse_init_org_id != "" ? [1] : []
            content {
              name  = "LANGFUSE_INIT_ORG_ID"
              value = var.langfuse_init_org_id
            }
          }

          dynamic "env" {
            for_each = var.langfuse_init_org_name != "" ? [1] : []
            content {
              name  = "LANGFUSE_INIT_ORG_NAME"
              value = var.langfuse_init_org_name
            }
          }

          dynamic "env" {
            for_each = var.langfuse_public_key != "" ? [1] : []
            content {
              name  = "LANGFUSE_INIT_PROJECT_PUBLIC_KEY"
              value = var.langfuse_public_key
            }
          }

          dynamic "env" {
            for_each = var.langfuse_secret_key != "" ? [1] : []
            content {
              name  = "LANGFUSE_INIT_PROJECT_SECRET_KEY"
              value = var.langfuse_secret_key
            }
          }

          # ClickHouse URL (required for Langfuse v3)
          dynamic "env" {
            for_each = var.clickhouse_url != "" ? [1] : []
            content {
              name  = "CLICKHOUSE_URL"
              value = var.clickhouse_url
            }
          }

          dynamic "env" {
            for_each = var.clickhouse_migration_url != "" ? [1] : []
            content {
              name  = "CLICKHOUSE_MIGRATION_URL"
              value = var.clickhouse_migration_url
            }
          }

          dynamic "env" {
            for_each = var.clickhouse_user != "" ? [1] : []
            content {
              name  = "CLICKHOUSE_USER"
              value = var.clickhouse_user
            }
          }

          dynamic "env" {
            for_each = var.clickhouse_password != "" ? [1] : []
            content {
              name  = "CLICKHOUSE_PASSWORD"
              value = var.clickhouse_password
            }
          }

          env {
            name  = "CLICKHOUSE_PORT"
            value = "8123"
          }

          env {
            name  = "LANGFUSE_INGESTION_CLICKHOUSE_WRITE_INTERVAL_MS"
            value = "1000"
          }

          env {
            name  = "LANGFUSE_INGESTION_CLICKHOUSE_WRITE_BATCH_SIZE"
            value = "1"
          }

          # Redis (required for Langfuse v3 queuing/caching)
          dynamic "env" {
            for_each = var.redis_connection_string != "" ? [1] : []
            content {
              name  = "REDIS_CONNECTION_STRING"
              value = var.redis_connection_string
            }
          }

          dynamic "env" {
            for_each = var.redis_connection_string != "" ? [1] : []
            content {
              name  = "REDIS_URL"
              value = var.redis_connection_string
            }
          }

          env {
            name  = "REDIS_HOST"
            value = var.redis_host
          }

          env {
            name  = "REDIS_PORT"
            value = var.redis_port
          }

          env {
            name  = "LOG_LEVEL"
            value = "debug"
          }

          env {
            name  = "LANGFUSE_LOG_LEVEL"
            value = "debug"
          }

          # S3 Blob Storage via GCS HMAC S3-interop (required for web→worker event queue).
          # Force path-style addressing: GCS S3-interop does not support virtual-hosted-style
          # (https://bucket.storage.googleapis.com) reliably inside GKE — use path-style
          # (https://storage.googleapis.com/bucket) which is the documented GCS S3 API form.
          env {
            name  = "LANGFUSE_S3_EVENT_UPLOAD_ENABLED"
            value = "true"
          }

          env {
            name  = "LANGFUSE_S3_EVENT_UPLOAD_FORCE_PATH_STYLE"
            value = "true"
          }

          dynamic "env" {
            for_each = var.s3_endpoint != "" ? [1] : []
            content {
              name  = "LANGFUSE_S3_EVENT_UPLOAD_ENDPOINT"
              value = var.s3_endpoint
            }
          }

          dynamic "env" {
            for_each = var.s3_bucket != "" ? [1] : []
            content {
              name  = "LANGFUSE_S3_EVENT_UPLOAD_BUCKET"
              value = var.s3_bucket
            }
          }

          # GCS S3-interop ignores region but AWS SDK requires a non-empty value;
          # "auto" is accepted by the SDK and ignored by GCS.
          env {
            name  = "LANGFUSE_S3_EVENT_UPLOAD_REGION"
            value = "auto"
          }

          dynamic "env" {
            for_each = var.s3_access_key != "" ? [1] : []
            content {
              name  = "AWS_ACCESS_KEY_ID"
              value = var.s3_access_key
            }
          }

          dynamic "env" {
            for_each = var.s3_secret_key != "" ? [1] : []
            content {
              name  = "AWS_SECRET_ACCESS_KEY"
              value = var.s3_secret_key
            }
          }

          dynamic "env" {
            for_each = var.s3_access_key != "" ? [1] : []
            content {
              name  = "LANGFUSE_S3_EVENT_UPLOAD_ACCESS_KEY_ID"
              value = var.s3_access_key
            }
          }

          dynamic "env" {
            for_each = var.s3_secret_key != "" ? [1] : []
            content {
              name  = "LANGFUSE_S3_EVENT_UPLOAD_SECRET_ACCESS_KEY"
              value = var.s3_secret_key
            }
          }

          env {
            name = "NEXTAUTH_SECRET"
            value_from {
              secret_key_ref {
                name = kubernetes_secret.langfuse_secrets.metadata[0].name
                key  = "nextauth-secret"
              }
            }
          }

          env {
            name = "SALT"
            value_from {
              secret_key_ref {
                name = kubernetes_secret.langfuse_secrets.metadata[0].name
                key  = "salt"
              }
            }
          }

          env {
            name = "ENCRYPTION_KEY"
            value_from {
              secret_key_ref {
                name = kubernetes_secret.langfuse_secrets.metadata[0].name
                key  = "encryption-key"
              }
            }
          }

          env {
            name  = "NEXTAUTH_URL"
            value = var.nextauth_url
          }

          env {
            name  = "HOSTNAME"
            value = "0.0.0.0"
          }

          env {
            name  = "PORT"
            value = "3000"
          }

          env {
            name  = "CLICKHOUSE_CLUSTER_ENABLED"
            value = "false"
          }

          resources {
            requests = {
              memory = var.web_memory_request
              cpu    = var.web_cpu_request
            }
            limits = {
              memory = var.web_memory_limit
              cpu    = var.web_cpu_limit
            }
          }

          liveness_probe {
            http_get {
              path = "/api/public/health"
              port = 3000
            }
            initial_delay_seconds = 60
            period_seconds        = 10
            failure_threshold     = 10
          }

          readiness_probe {
            http_get {
              path = "/api/public/health"
              port = 3000
            }
            initial_delay_seconds = 15
            period_seconds        = 10
            failure_threshold     = 30
          }
        }
      }
    }
  }
}

# Langfuse Web Service
resource "kubernetes_service" "langfuse_web" {
  metadata {
    name      = "langfuse-web"
    namespace = var.namespace
    labels = {
      app = "langfuse-web"
    }
  }

  spec {
    type = var.service_type

    port {
      port        = 3000
      target_port = 3000
      protocol    = "TCP"
      name        = "http"
    }

    selector = {
      app = "langfuse-web"
    }
  }
}

# Langfuse Worker Deployment
resource "kubernetes_deployment" "langfuse_worker" {
  metadata {
    name      = "langfuse-worker"
    namespace = var.namespace
    labels = {
      app       = "langfuse-worker"
      component = "observability"
    }
  }

  wait_for_rollout = false

  spec {
    replicas = var.worker_replicas

    selector {
      match_labels = {
        app = "langfuse-worker"
      }
    }

    template {
      metadata {
        labels = {
          app = "langfuse-worker"
        }
      }

      spec {
        container {
          name  = "langfuse-worker"
          image = var.langfuse_worker_image

          env {
            name  = "DATABASE_URL"
            value = var.database_url
          }

          dynamic "env" {
            for_each = var.clickhouse_url != "" ? [1] : []
            content {
              name  = "CLICKHOUSE_URL"
              value = var.clickhouse_url
            }
          }

          dynamic "env" {
            for_each = var.clickhouse_user != "" ? [1] : []
            content {
              name  = "CLICKHOUSE_USER"
              value = var.clickhouse_user
            }
          }

          dynamic "env" {
            for_each = var.clickhouse_password != "" ? [1] : []
            content {
              name  = "CLICKHOUSE_PASSWORD"
              value = var.clickhouse_password
            }
          }

          env {
            name  = "CLICKHOUSE_PORT"
            value = "8123"
          }

          env {
            name  = "LANGFUSE_INGESTION_CLICKHOUSE_WRITE_INTERVAL_MS"
            value = "1000"
          }

          env {
            name  = "LANGFUSE_INGESTION_CLICKHOUSE_WRITE_BATCH_SIZE"
            value = "1"
          }

          dynamic "env" {
            for_each = var.redis_connection_string != "" ? [1] : []
            content {
              name  = "REDIS_CONNECTION_STRING"
              value = var.redis_connection_string
            }
          }

          dynamic "env" {
            for_each = var.redis_connection_string != "" ? [1] : []
            content {
              name  = "REDIS_URL"
              value = var.redis_connection_string
            }
          }

          env {
            name  = "REDIS_HOST"
            value = var.redis_host
          }

          env {
            name  = "REDIS_PORT"
            value = var.redis_port
          }

          env {
            name  = "LOG_LEVEL"
            value = "debug"
          }

          env {
            name  = "CLICKHOUSE_CLUSTER_ENABLED"
            value = "false"
          }

          env {
            name  = "LANGFUSE_LOG_LEVEL"
            value = "debug"
          }

          # S3 Blob Storage via GCS HMAC S3-interop (required for web→worker event queue).
          # Force path-style addressing: GCS S3-interop does not support virtual-hosted-style
          # (https://bucket.storage.googleapis.com) reliably inside GKE — use path-style
          # (https://storage.googleapis.com/bucket) which is the documented GCS S3 API form.
          env {
            name  = "LANGFUSE_S3_EVENT_UPLOAD_ENABLED"
            value = "true"
          }

          env {
            name  = "LANGFUSE_S3_EVENT_UPLOAD_FORCE_PATH_STYLE"
            value = "true"
          }

          dynamic "env" {
            for_each = var.s3_endpoint != "" ? [1] : []
            content {
              name  = "LANGFUSE_S3_EVENT_UPLOAD_ENDPOINT"
              value = var.s3_endpoint
            }
          }

          dynamic "env" {
            for_each = var.s3_bucket != "" ? [1] : []
            content {
              name  = "LANGFUSE_S3_EVENT_UPLOAD_BUCKET"
              value = var.s3_bucket
            }
          }

          # GCS S3-interop ignores region but AWS SDK requires a non-empty value;
          # "auto" is accepted by the SDK and ignored by GCS.
          env {
            name  = "LANGFUSE_S3_EVENT_UPLOAD_REGION"
            value = "auto"
          }

          dynamic "env" {
            for_each = var.s3_access_key != "" ? [1] : []
            content {
              name  = "AWS_ACCESS_KEY_ID"
              value = var.s3_access_key
            }
          }

          dynamic "env" {
            for_each = var.s3_secret_key != "" ? [1] : []
            content {
              name  = "AWS_SECRET_ACCESS_KEY"
              value = var.s3_secret_key
            }
          }

          dynamic "env" {
            for_each = var.s3_access_key != "" ? [1] : []
            content {
              name  = "LANGFUSE_S3_EVENT_UPLOAD_ACCESS_KEY_ID"
              value = var.s3_access_key
            }
          }

          dynamic "env" {
            for_each = var.s3_secret_key != "" ? [1] : []
            content {
              name  = "LANGFUSE_S3_EVENT_UPLOAD_SECRET_ACCESS_KEY"
              value = var.s3_secret_key
            }
          }

          env {
            name = "SALT"
            value_from {
              secret_key_ref {
                name = kubernetes_secret.langfuse_secrets.metadata[0].name
                key  = "salt"
              }
            }
          }

          env {
            name = "ENCRYPTION_KEY"
            value_from {
              secret_key_ref {
                name = kubernetes_secret.langfuse_secrets.metadata[0].name
                key  = "encryption-key"
              }
            }
          }

          resources {
            requests = {
              memory = var.worker_memory_request
              cpu    = var.worker_cpu_request
            }
            limits = {
              memory = var.worker_memory_limit
              cpu    = var.worker_cpu_limit
            }
          }
        }
      }
    }
  }
}
