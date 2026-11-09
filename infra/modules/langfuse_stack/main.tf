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

locals {
  # For Cloud SQL IAM authentication via proxy:
  # The database user name for service accounts in Postgres is the SA email without .gserviceaccount.com.
  # When constructing the DATABASE_URL, '@' in the username must be URL-encoded as '%40' for Prisma parsing.
  encoded_iam_user       = replace(var.cloudsql_iam_user, "@", "%40")
  effective_database_url = var.enable_cloudsql_proxy ? "postgresql://${local.encoded_iam_user}:unused@127.0.0.1:5432/${var.cloudsql_database_name}?sslmode=disable" : var.database_url
  seed_compliance_project = (
    trimspace(var.langfuse_compliance_project_id) != "" &&
    trimspace(var.langfuse_compliance_public_key) != "" &&
    trimspace(var.langfuse_compliance_secret_key) != ""
  )
  compliance_seed_js = <<-JS
    const crypto = require("crypto");
    const { spawnSync } = require("child_process");
    const net = require("net");

    const orgId = (process.env.LANGFUSE_INIT_ORG_ID || "CAGE").trim();
    const orgName = (process.env.LANGFUSE_INIT_ORG_NAME || "CAGE").trim();
    const projId = (process.env.LANGFUSE_COMPLIANCE_INIT_PROJECT_ID || "").trim();
    const pk = (process.env.LANGFUSE_COMPLIANCE_INIT_PUBLIC_KEY || "").trim();
    const sk = (process.env.LANGFUSE_COMPLIANCE_INIT_SECRET_KEY || "").trim();
    const salt = (process.env.SALT || "").trim();
    const dbUrl = (process.env.DIRECT_URL || process.env.DATABASE_URL || "").trim();

    if (!projId || !pk || !sk) {
      process.exit(0);
    }
    if (!salt || !dbUrl) {
      console.error("[CAGE Langfuse Init] Missing SALT or DATABASE_URL for compliance project seed.");
      process.exit(1);
    }
    const safeId = /^[A-Za-z0-9_.:-]+$/;
    if (!safeId.test(orgId) || !safeId.test(orgName) || !safeId.test(projId) || !safeId.test(pk)) {
      console.error("[CAGE Langfuse Init] Unsafe identifier characters in org/project/publicKey.");
      process.exit(1);
    }

    const saltHex = crypto.createHash("sha256").update(salt, "utf8").digest("hex");
    const fastHash = crypto.createHash("sha256").update(sk).update(saltHex).digest("hex");
    const hashedSk = "sha256-fast:" + fastHash;
    const displaySk = (sk.length >= 10 ? sk.slice(0, 6) + "..." + sk.slice(-4) : "sk-lf-...****").replace(/'/g, "");

    const sql = [
      "INSERT INTO organizations (id, name, created_at, updated_at)",
      "VALUES ('" + orgId + "', '" + orgName + "', NOW(), NOW())",
      "ON CONFLICT (id) DO NOTHING;",
      "INSERT INTO projects (id, name, org_id, created_at, updated_at, has_traces)",
      "VALUES ('" + projId + "', '" + projId + "', '" + orgId + "', NOW(), NOW(), false)",
      "ON CONFLICT (id) DO NOTHING;",
      "DELETE FROM api_keys",
      "WHERE (fast_hashed_secret_key = '" + fastHash + "' OR hashed_secret_key = '" + hashedSk + "')",
      "  AND public_key <> '" + pk + "';",
      "INSERT INTO api_keys (",
      "  id, created_at, note, public_key, hashed_secret_key, fast_hashed_secret_key,",
      "  display_secret_key, project_id, scope, is_in_app_agent_key",
      ") VALUES (",
      "  'cage_comp_apikey_00000001', NOW(), 'Provisioned CAGE Compliance Tenant Key',",
      "  '" + pk + "', '" + hashedSk + "', '" + fastHash + "', '" + displaySk + "',",
      "  '" + projId + "', 'PROJECT'::\"ApiKeyScope\", false",
      ") ON CONFLICT (public_key) DO UPDATE SET",
      "  hashed_secret_key      = EXCLUDED.hashed_secret_key,",
      "  fast_hashed_secret_key = EXCLUDED.fast_hashed_secret_key,",
      "  display_secret_key     = EXCLUDED.display_secret_key,",
      "  project_id             = EXCLUDED.project_id,",
      "  scope                  = EXCLUDED.scope;"
    ].join("\n");

    const res = spawnSync("prisma", ["db", "execute", "--stdin", "--url", dbUrl], {
      input: sql,
      encoding: "utf8",
      stdio: ["pipe", "inherit", "inherit"]
    });
    if (res.status !== 0) {
      console.error("[CAGE Langfuse Init] prisma db execute failed with status", res.status);
      process.exit(res.status || 1);
    }

    const redisHost = (process.env.REDIS_HOST || "").trim();
    const redisPort = parseInt(process.env.REDIS_PORT || "6379", 10);
    if (redisHost && Number.isFinite(redisPort)) {
      const sock = net.createConnection({ host: redisHost, port: redisPort }, () => {
        const key = "api-key:" + fastHash;
        sock.write("*2\r\n$3\r\nDEL\r\n$" + Buffer.byteLength(key) + "\r\n" + key + "\r\n*1\r\n$4\r\nQUIT\r\n");
      });
      sock.setTimeout(1500, () => sock.destroy());
      sock.on("error", () => sock.destroy());
      sock.on("close", () => {
        console.log("[CAGE Langfuse Init] Provisioned isolated compliance project '" + projId + "'.");
        process.exit(0);
      });
    } else {
      console.log("[CAGE Langfuse Init] Provisioned isolated compliance project '" + projId + "'.");
    }
  JS
}

resource "kubernetes_config_map_v1" "langfuse_compliance_init" {
  count = local.seed_compliance_project ? 1 : 0

  metadata {
    name      = "langfuse-compliance-init"
    namespace = var.namespace
  }

  data = {
    "seed_compliance_project.js" = local.compliance_seed_js
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

  data = merge(
    {
      "nextauth-secret"          = random_id.nextauth_secret.hex
      "salt"                     = random_id.salt.hex
      "encryption-key"           = random_id.encryption_key.hex
      "public-key"               = coalesce(var.langfuse_public_key, random_id.public_key.hex)
      "secret-key"               = coalesce(var.langfuse_secret_key, random_id.secret_key.hex)
      "init-user-password"       = var.langfuse_init_user_password
      "clickhouse-password"      = var.clickhouse_password
      "clickhouse-migration-url" = var.clickhouse_migration_url
      "s3-access-key"            = var.s3_access_key
      "s3-secret-key"            = var.s3_secret_key
      "redis-connection-string"  = var.redis_connection_string
    },
    local.seed_compliance_project ? {
      "compliance-public-key" = var.langfuse_compliance_public_key
      "compliance-secret-key" = var.langfuse_compliance_secret_key
    } : {},
  )
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
        annotations = merge(
          {
            # Keep ClickHouse native TCP (9000) inside Linkerd mTLS so ClickHouse
            # Server/AuthorizationPolicy enforces langfuse-sa caller identity.
            # Skip only external managed endpoints: Cloud SQL Auth Proxy loopback (5432),
            # Memorystore Valkey (6379), and Cloud SQL server port (3307).
            "config.linkerd.io/skip-outbound-ports" = "5432,6379,3307"
          },
          local.seed_compliance_project ? {
            "cage.io/compliance-seed-sha256" = sha256(local.compliance_seed_js)
          } : {},
        )
      }

      spec {
        service_account_name = var.service_account_name != "" ? var.service_account_name : null

        security_context {
          run_as_non_root = true
          run_as_user     = 1001
          seccomp_profile {
            type = "RuntimeDefault"
          }
        }

        container {
          name  = "langfuse-web"
          image = var.langfuse_image
          args = local.seed_compliance_project ? [
            "/bin/sh",
            "-c",
            "node /etc/cage/langfuse-init/seed_compliance_project.js && if [ -n \"$NEXT_PUBLIC_LANGFUSE_CLOUD_REGION\" ]; then exec node --import dd-trace/initialize.mjs ./web/server.js --keepAliveTimeout 110000; else exec node ./web/server.js --keepAliveTimeout 110000; fi",
          ] : null

          security_context {
            allow_privilege_escalation = false
            run_as_non_root            = true
            run_as_user                = 1001
            capabilities {
              drop = ["ALL"]
            }
            seccomp_profile {
              type = "RuntimeDefault"
            }
          }

          port {
            container_port = 3000
            name           = "http"
          }

          env {
            name  = "DATABASE_URL"
            value = local.effective_database_url
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
              name = "LANGFUSE_INIT_USER_PASSWORD"
              value_from {
                secret_key_ref {
                  name = kubernetes_secret.langfuse_secrets.metadata[0].name
                  key  = "init-user-password"
                }
              }
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
              name = "LANGFUSE_INIT_PROJECT_PUBLIC_KEY"
              value_from {
                secret_key_ref {
                  name = kubernetes_secret.langfuse_secrets.metadata[0].name
                  key  = "public-key"
                }
              }
            }
          }

          dynamic "env" {
            for_each = var.langfuse_secret_key != "" ? [1] : []
            content {
              name = "LANGFUSE_INIT_PROJECT_SECRET_KEY"
              value_from {
                secret_key_ref {
                  name = kubernetes_secret.langfuse_secrets.metadata[0].name
                  key  = "secret-key"
                }
              }
            }
          }

          dynamic "env" {
            for_each = local.seed_compliance_project ? [1] : []
            content {
              name  = "LANGFUSE_COMPLIANCE_INIT_PROJECT_ID"
              value = trimspace(var.langfuse_compliance_project_id)
            }
          }

          dynamic "env" {
            for_each = local.seed_compliance_project ? [1] : []
            content {
              name = "LANGFUSE_COMPLIANCE_INIT_PUBLIC_KEY"
              value_from {
                secret_key_ref {
                  name = kubernetes_secret.langfuse_secrets.metadata[0].name
                  key  = "compliance-public-key"
                }
              }
            }
          }

          dynamic "env" {
            for_each = local.seed_compliance_project ? [1] : []
            content {
              name = "LANGFUSE_COMPLIANCE_INIT_SECRET_KEY"
              value_from {
                secret_key_ref {
                  name = kubernetes_secret.langfuse_secrets.metadata[0].name
                  key  = "compliance-secret-key"
                }
              }
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
              name = "CLICKHOUSE_MIGRATION_URL"
              value_from {
                secret_key_ref {
                  name = kubernetes_secret.langfuse_secrets.metadata[0].name
                  key  = "clickhouse-migration-url"
                }
              }
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
              name = "CLICKHOUSE_PASSWORD"
              value_from {
                secret_key_ref {
                  name = kubernetes_secret.langfuse_secrets.metadata[0].name
                  key  = "clickhouse-password"
                }
              }
            }
          }

          env {
            name  = "CLICKHOUSE_DB"
            value = var.clickhouse_db
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
              name = "REDIS_CONNECTION_STRING"
              value_from {
                secret_key_ref {
                  name = kubernetes_secret.langfuse_secrets.metadata[0].name
                  key  = "redis-connection-string"
                }
              }
            }
          }

          dynamic "env" {
            for_each = var.redis_connection_string != "" ? [1] : []
            content {
              name = "REDIS_URL"
              value_from {
                secret_key_ref {
                  name = kubernetes_secret.langfuse_secrets.metadata[0].name
                  key  = "redis-connection-string"
                }
              }
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
              name = "AWS_ACCESS_KEY_ID"
              value_from {
                secret_key_ref {
                  name = kubernetes_secret.langfuse_secrets.metadata[0].name
                  key  = "s3-access-key"
                }
              }
            }
          }

          dynamic "env" {
            for_each = var.s3_secret_key != "" ? [1] : []
            content {
              name = "AWS_SECRET_ACCESS_KEY"
              value_from {
                secret_key_ref {
                  name = kubernetes_secret.langfuse_secrets.metadata[0].name
                  key  = "s3-secret-key"
                }
              }
            }
          }

          dynamic "env" {
            for_each = var.s3_access_key != "" ? [1] : []
            content {
              name = "LANGFUSE_S3_EVENT_UPLOAD_ACCESS_KEY_ID"
              value_from {
                secret_key_ref {
                  name = kubernetes_secret.langfuse_secrets.metadata[0].name
                  key  = "s3-access-key"
                }
              }
            }
          }

          dynamic "env" {
            for_each = var.s3_secret_key != "" ? [1] : []
            content {
              name = "LANGFUSE_S3_EVENT_UPLOAD_SECRET_ACCESS_KEY"
              value_from {
                secret_key_ref {
                  name = kubernetes_secret.langfuse_secrets.metadata[0].name
                  key  = "s3-secret-key"
                }
              }
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

          dynamic "volume_mount" {
            for_each = local.seed_compliance_project ? [1] : []
            content {
              name       = "langfuse-compliance-init"
              mount_path = "/etc/cage/langfuse-init"
              read_only  = true
            }
          }
        }

        dynamic "container" {
          for_each = var.enable_cloudsql_proxy ? [1] : []
          content {
            name  = "cloud-sql-proxy"
            image = var.cloudsql_proxy_image
            args = [
              "--structured-logs",
              "--port=5432",
              "--private-ip",
              "--auto-iam-authn",
              var.cloudsql_connection_name,
            ]

            security_context {
              allow_privilege_escalation = false
              capabilities {
                drop = ["ALL"]
              }
              run_as_non_root = true
              run_as_user     = 65532
            }

            resources {
              requests = {
                cpu    = "50m"
                memory = "64Mi"
              }
              limits = {
                cpu    = "200m"
                memory = "256Mi"
              }
            }
          }
        }

        dynamic "volume" {
          for_each = local.seed_compliance_project ? [1] : []
          content {
            name = "langfuse-compliance-init"
            config_map {
              name = kubernetes_config_map_v1.langfuse_compliance_init[0].metadata[0].name
            }
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
        annotations = {
          # Keep ClickHouse native TCP (9000) inside Linkerd mTLS so ClickHouse
          # Server/AuthorizationPolicy enforces langfuse-sa caller identity.
          # Skip only external managed endpoints: Cloud SQL Auth Proxy loopback (5432),
          # Memorystore Valkey (6379), and Cloud SQL server port (3307).
          "config.linkerd.io/skip-outbound-ports" = "5432,6379,3307"
        }
      }

      spec {
        service_account_name = var.service_account_name != "" ? var.service_account_name : null

        security_context {
          run_as_non_root = true
          run_as_user     = 1001
          seccomp_profile {
            type = "RuntimeDefault"
          }
        }

        container {
          name  = "langfuse-worker"
          image = var.langfuse_worker_image

          security_context {
            allow_privilege_escalation = false
            run_as_non_root            = true
            run_as_user                = 1001
            capabilities {
              drop = ["ALL"]
            }
            seccomp_profile {
              type = "RuntimeDefault"
            }
          }

          env {
            name  = "DATABASE_URL"
            value = local.effective_database_url
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
              name = "CLICKHOUSE_PASSWORD"
              value_from {
                secret_key_ref {
                  name = kubernetes_secret.langfuse_secrets.metadata[0].name
                  key  = "clickhouse-password"
                }
              }
            }
          }

          env {
            name  = "CLICKHOUSE_DB"
            value = var.clickhouse_db
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
              name = "REDIS_CONNECTION_STRING"
              value_from {
                secret_key_ref {
                  name = kubernetes_secret.langfuse_secrets.metadata[0].name
                  key  = "redis-connection-string"
                }
              }
            }
          }

          dynamic "env" {
            for_each = var.redis_connection_string != "" ? [1] : []
            content {
              name = "REDIS_URL"
              value_from {
                secret_key_ref {
                  name = kubernetes_secret.langfuse_secrets.metadata[0].name
                  key  = "redis-connection-string"
                }
              }
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
              name = "AWS_ACCESS_KEY_ID"
              value_from {
                secret_key_ref {
                  name = kubernetes_secret.langfuse_secrets.metadata[0].name
                  key  = "s3-access-key"
                }
              }
            }
          }

          dynamic "env" {
            for_each = var.s3_secret_key != "" ? [1] : []
            content {
              name = "AWS_SECRET_ACCESS_KEY"
              value_from {
                secret_key_ref {
                  name = kubernetes_secret.langfuse_secrets.metadata[0].name
                  key  = "s3-secret-key"
                }
              }
            }
          }

          dynamic "env" {
            for_each = var.s3_access_key != "" ? [1] : []
            content {
              name = "LANGFUSE_S3_EVENT_UPLOAD_ACCESS_KEY_ID"
              value_from {
                secret_key_ref {
                  name = kubernetes_secret.langfuse_secrets.metadata[0].name
                  key  = "s3-access-key"
                }
              }
            }
          }

          dynamic "env" {
            for_each = var.s3_secret_key != "" ? [1] : []
            content {
              name = "LANGFUSE_S3_EVENT_UPLOAD_SECRET_ACCESS_KEY"
              value_from {
                secret_key_ref {
                  name = kubernetes_secret.langfuse_secrets.metadata[0].name
                  key  = "s3-secret-key"
                }
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

        dynamic "container" {
          for_each = var.enable_cloudsql_proxy ? [1] : []
          content {
            name  = "cloud-sql-proxy"
            image = var.cloudsql_proxy_image
            args = [
              "--structured-logs",
              "--port=5432",
              "--private-ip",
              "--auto-iam-authn",
              var.cloudsql_connection_name,
            ]

            security_context {
              allow_privilege_escalation = false
              capabilities {
                drop = ["ALL"]
              }
              run_as_non_root = true
              run_as_user     = 65532
            }

            resources {
              requests = {
                cpu    = "50m"
                memory = "64Mi"
              }
              limits = {
                cpu    = "200m"
                memory = "256Mi"
              }
            }
          }
        }
      }
    }
  }
}
