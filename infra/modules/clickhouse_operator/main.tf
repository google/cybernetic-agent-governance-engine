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

# ─────────────────────────────────────────────────────────────────────────────
# ClickHouse Operator & Query-Plane Module (Track 6e / §1.1, §2.6, §3, §7)
# ─────────────────────────────────────────────────────────────────────────────
# Architectural invariant (§2.6 / F-108):
#   The retention-locked GCS WORM bucket (`infra/modules/worm_bucket`) and the
#   governance Redis Stream are the sole live evidence stores. ClickHouse serves
#   strictly as the OLAP trace store for Langfuse v3 (`langfuse_app` scoped to
#   `langfuse.*`). Losing ClickHouse nodes causes zero evidence loss.
#
# Posture matrix (§1.1, §2.6):
#   - dev / staging: 1 node on local SSD (`MergeTree`), no Keeper quorum.
#   - prod (or HA):  Altinity ClickHouse Operator + 3-node `ReplicatedMergeTree`
#                    cluster + 3-node ClickHouse Keeper quorum, local SSD for
#                    hot parts, and GCS disk (`cold_gcs`) for the cold tier.
#
# Cold-tier invariant (§2.6):
#   ClickHouse deletes S3-disk objects on merge and TTL. `cold_gcs` therefore
#   points at a dedicated, non-retention-locked, CMEK-encrypted tiering bucket
#   (never the WORM bucket) that only the ClickHouse service account can use.
#
# Node Isolation Invariant (§3, §7):
#   All ClickHouse and Keeper pods tolerate `workload=clickhouse:NoSchedule`
#   and enforce `nodeAffinity` requiring `workload=clickhouse` and
#   `cloud.google.com/gke-spot NotIn ["true"]` so stateful query-plane pods
#   never land on general or Spot nodes.
# ─────────────────────────────────────────────────────────────────────────────

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.23"
    }
    helm = {
      source  = "hashicorp/helm"
      version = ">= 2.11"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.5"
    }
  }
}

resource "random_password" "clickhouse" {
  length  = 32
  special = false
}

resource "kubernetes_secret" "clickhouse_admin" {
  metadata {
    name      = var.password_secret_name
    namespace = var.namespace
    labels = {
      app                         = "clickhouse"
      component                   = "query-plane"
      "cage.io/sensitivity-level" = "high"
    }
    annotations = {
      "cage.io/rotation-schedule" = "90d"
      "cage.io/rotation-owner"    = "platform-team"
    }
  }

  data = {
    (var.password_secret_key) = random_password.clickhouse.result
  }
}

# Dedicated credential for Langfuse v3 web, worker, and golang-migrate, scoped
# exclusively to `langfuse.*` with zero superuser or cross-database privileges (F-108).
resource "random_password" "langfuse_app" {
  length  = 32
  special = false
}

resource "kubernetes_secret" "langfuse_app" {
  metadata {
    name      = var.langfuse_secret_name
    namespace = var.namespace
    labels = {
      app                         = "clickhouse"
      component                   = "query-plane"
      "cage.io/sensitivity-level" = "high"
    }
    annotations = {
      "cage.io/rotation-schedule" = "90d"
      "cage.io/rotation-owner"    = "platform-team"
    }
  }

  data = {
    "CLICKHOUSE_PASSWORD" = random_password.langfuse_app.result
  }
}

locals {
  is_prod         = var.environment == "prod"
  is_ha           = local.is_prod || var.enable_high_availability
  enable_operator = var.enable_operator != null ? var.enable_operator : local.is_ha
  replicas        = local.is_ha ? 3 : 1
  keeper_replicas = local.is_ha ? 3 : 0
  table_engine    = local.is_ha ? "ReplicatedMergeTree('/clickhouse/tables/{shard}/{database}/{table}', '{replica}')" : "MergeTree()"
  storage_policy  = local.is_ha && var.cold_tier_bucket != "" ? "hot_to_cold" : "default"
  cold_tier_on    = local.is_ha && var.cold_tier_bucket != ""
}


# ─── Altinity ClickHouse Operator (Prod / HA Posture) ─────────────────────────

resource "helm_release" "clickhouse_operator" {
  count = local.enable_operator ? 1 : 0

  name       = "clickhouse-operator"
  repository = "https://docs.altinity.com/clickhouse-operator/"
  chart      = "altinity-clickhouse-operator"
  version    = var.operator_chart_version
  namespace  = var.namespace

  values = [
    yamlencode({
      operator = {
        tolerations = [
          {
            key      = "workload"
            operator = "Equal"
            value    = "clickhouse"
            effect   = "NoSchedule"
          }
        ]
        affinity = {
          nodeAffinity = {
            requiredDuringSchedulingIgnoredDuringExecution = {
              nodeSelectorTerms = [
                {
                  matchExpressions = [
                    {
                      key      = "workload"
                      operator = "In"
                      values   = ["clickhouse"]
                    },
                    {
                      key      = "cloud.google.com/gke-spot"
                      operator = "NotIn"
                      values   = ["true"]
                    }
                  ]
                }
              ]
            }
          }
        }
      }
    })
  ]
}

# ─── ClickHouse Keeper (3-Node Quorum for ReplicatedMergeTree in Prod) ────────

resource "kubernetes_service" "clickhouse_keeper" {
  count = local.is_ha ? 1 : 0

  metadata {
    name      = "clickhouse-keeper"
    namespace = var.namespace
    labels = {
      app       = "clickhouse-keeper"
      component = "query-plane-coordination"
    }
  }

  spec {
    cluster_ip = "None"
    selector = {
      app = "clickhouse-keeper"
    }

    port {
      name        = "client"
      port        = 9181
      target_port = 9181
    }

    port {
      name        = "raft"
      port        = 9234
      target_port = 9234
    }
  }
}

resource "kubernetes_stateful_set" "clickhouse_keeper" {
  count = local.is_ha ? 1 : 0

  metadata {
    name      = "clickhouse-keeper"
    namespace = var.namespace
    labels = {
      app       = "clickhouse-keeper"
      component = "query-plane-coordination"
    }
  }

  wait_for_rollout = false

  spec {
    service_name          = "clickhouse-keeper"
    replicas              = local.keeper_replicas
    pod_management_policy = "Parallel"

    selector {
      match_labels = {
        app = "clickhouse-keeper"
      }
    }

    template {
      metadata {
        labels = {
          app       = "clickhouse-keeper"
          component = "query-plane-coordination"
        }
      }

      spec {
        service_account_name = var.keeper_service_account_name != "" ? var.keeper_service_account_name : null

        # §3, §7: Schedule strictly onto tainted clickhouse node pool (never general or Spot)
        toleration {
          key      = "workload"
          operator = "Equal"
          value    = "clickhouse"
          effect   = "NoSchedule"
        }

        affinity {
          node_affinity {
            required_during_scheduling_ignored_during_execution {
              node_selector_term {
                match_expressions {
                  key      = "workload"
                  operator = "In"
                  values   = ["clickhouse"]
                }
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
          run_as_user     = 101
          fs_group        = 101
          seccomp_profile {
            type = "RuntimeDefault"
          }
        }

        container {
          name  = "clickhouse-keeper"
          image = var.keeper_image

          security_context {
            allow_privilege_escalation = false
            run_as_non_root            = true
            run_as_user                = 101
            capabilities {
              drop = ["ALL"]
            }
            seccomp_profile {
              type = "RuntimeDefault"
            }
          }

          port {
            name           = "client"
            container_port = 9181
          }

          port {
            name           = "raft"
            container_port = 9234
          }

          resources {
            requests = {
              cpu    = "250m"
              memory = "512Mi"
            }
            limits = {
              cpu    = "1000m"
              memory = "1Gi"
            }
          }

          volume_mount {
            name       = "keeper-storage"
            mount_path = "/var/lib/clickhouse-keeper"
          }
        }
      }
    }

    volume_claim_template {
      metadata {
        name = "keeper-storage"
      }

      spec {
        access_modes       = ["ReadWriteOnce"]
        storage_class_name = var.storage_class

        resources {
          requests = {
            storage = var.keeper_storage_size
          }
        }
      }
    }
  }
}

resource "kubernetes_pod_disruption_budget_v1" "clickhouse_keeper" {
  count = local.is_ha ? 1 : 0

  metadata {
    name      = "clickhouse-keeper-pdb"
    namespace = var.namespace
  }

  spec {
    min_available = 2
    selector {
      match_labels = {
        app = "clickhouse-keeper"
      }
    }
  }
}

# ─── ClickHouse Server Configuration (Hot Local SSD + GCS Cold Tier + RBAC) ──

resource "kubernetes_config_map" "clickhouse_config" {
  lifecycle {
    precondition {
      condition = (
        var.langfuse_username != "default" &&
        !contains(["default", "system"], var.langfuse_database)
      )
      error_message = "ClickHouse RBAC invariant (F-108): langfuse_username must be distinct from default, and langfuse_database must not be default or system."
    }
  }

  metadata {
    name      = "clickhouse-users-config"
    namespace = var.namespace
    labels = {
      app       = "clickhouse"
      component = "query-plane"
    }
  }

  data = {
    # F-108: Restrict the built-in `default` superuser strictly to container
    # loopback (127.0.0.1 / ::1) with `replace="replace"` so ClickHouse's XML
    # merger overwrites `/etc/clickhouse-server/users.xml`'s `::/0` instead of
    # appending to it, and keep `access_management = 0` so even loopback `default`
    # holds zero SQL RBAC-grant privileges while `/entrypoint.sh` creates `langfuse`.
    "networks.xml" = <<-EOT
      <clickhouse>
        <users>
          <default>
            <access_management>0</access_management>
            <networks replace="replace">
              <ip>127.0.0.1</ip>
              <ip>::1</ip>
            </networks>
          </default>
        </users>
      </clickhouse>
    EOT

    # F-108: Dedicated Langfuse v3 application & migration identity scoped
    # strictly to `langfuse.*` (`default_database = langfuse`). Holds zero
    # privileges on `default.*` or `system` user management.
    "langfuse_user.xml" = <<-EOT
      <clickhouse>
        <profiles>
          <langfuse_app_profile>
            <readonly>0</readonly>
            <allow_ddl>1</allow_ddl>
            <max_execution_time>120</max_execution_time>
          </langfuse_app_profile>
        </profiles>
        <users>
          <${var.langfuse_username}>
            <password from_env="CLICKHOUSE_LANGFUSE_PASSWORD"/>
            <profile>langfuse_app_profile</profile>
            <default_database>${var.langfuse_database}</default_database>
            <quota>default</quota>
            <access_management>0</access_management>
            <networks>
              <ip>::/0</ip>
            </networks>
            <grants>
              <query>GRANT SHOW, SELECT, INSERT, ALTER, CREATE TABLE, CREATE VIEW, DROP TABLE, DROP VIEW, TRUNCATE, OPTIMIZE ON ${var.langfuse_database}.*</query>
            </grants>
          </${var.langfuse_username}>
        </users>
      </clickhouse>
    EOT

    # §1.1, §2.6: Local SSD for hot parts; GCS disk for cold tier in prod.
    "storage_configuration.xml" = <<-EOT
      <clickhouse>
        <storage_configuration>
          <disks>
            <hot_local_ssd>
              <path>/var/lib/clickhouse/data/</path>
            </hot_local_ssd>
            %{if local.is_ha && var.cold_tier_bucket != ""}
            <cold_gcs>
              <type>s3</type>
              <endpoint>${var.cold_tier_endpoint}/${var.cold_tier_bucket}/clickhouse-cold/</endpoint>
              <use_environment_credentials>true</use_environment_credentials>
              <metadata_path>/var/lib/clickhouse/disks/cold_gcs/</metadata_path>
            </cold_gcs>
            %{endif}
          </disks>
          <policies>
            <hot_to_cold>
              <volumes>
                <hot>
                  <disk>hot_local_ssd</disk>
                </hot>
                %{if local.is_ha && var.cold_tier_bucket != ""}
                <cold>
                  <disk>cold_gcs</disk>
                </cold>
                %{endif}
              </volumes>
              <move_factor>${var.hot_to_cold_move_factor}</move_factor>
            </hot_to_cold>
          </policies>
        </storage_configuration>
      </clickhouse>
    EOT

    # §2.6: ReplicatedMergeTree + 3-node ClickHouse Keeper coordination in prod.
    "remote_servers_and_keeper.xml" = local.is_ha ? (<<-EOT
      <clickhouse>
        <remote_servers>
          <cage_cluster>
            <shard>
              <internal_replication>true</internal_replication>
              <replica>
                <host>clickhouse-0.clickhouse.${var.namespace}.svc.cluster.local</host>
                <port>9000</port>
              </replica>
              <replica>
                <host>clickhouse-1.clickhouse.${var.namespace}.svc.cluster.local</host>
                <port>9000</port>
              </replica>
              <replica>
                <host>clickhouse-2.clickhouse.${var.namespace}.svc.cluster.local</host>
                <port>9000</port>
              </replica>
            </shard>
          </cage_cluster>
        </remote_servers>
        <zookeeper>
          <node index="1">
            <host>clickhouse-keeper-0.clickhouse-keeper.${var.namespace}.svc.cluster.local</host>
            <port>9181</port>
          </node>
          <node index="2">
            <host>clickhouse-keeper-1.clickhouse-keeper.${var.namespace}.svc.cluster.local</host>
            <port>9181</port>
          </node>
          <node index="3">
            <host>clickhouse-keeper-2.clickhouse-keeper.${var.namespace}.svc.cluster.local</host>
            <port>9181</port>
          </node>
        </zookeeper>
        <macros>
          <shard>01</shard>
          <replica from_env="HOSTNAME" />
        </macros>
      </clickhouse>
    EOT
      ) : (<<-EOT
      <clickhouse>
        <!-- Single-node dev/staging query plane on local SSD (no Keeper required) -->
      </clickhouse>
    EOT
    )
  }
}

# Declarative `/docker-entrypoint-initdb.d/` database bootstrap (F-108).
# ClickHouse executes `01_databases.sql` over 127.0.0.1 on fresh bootstrap so
# the dedicated `langfuse` database exists out-of-the-box before `langfuse_app`
# runs golang-migrate, without granting `langfuse_app` global CREATE DATABASE.
resource "kubernetes_config_map" "clickhouse_init_sql" {
  metadata {
    name      = "clickhouse-init-sql"
    namespace = var.namespace
    labels = {
      app       = "clickhouse"
      component = "query-plane-ddl"
    }
  }

  data = {
    "01_databases.sql" = <<-EOT
      CREATE DATABASE IF NOT EXISTS ${var.langfuse_database};
    EOT
  }
}

# ─── ClickHouse Query-Plane Headless Service ──────────────────────────────────

resource "kubernetes_service" "clickhouse" {
  metadata {
    name      = "clickhouse"
    namespace = var.namespace
    labels = {
      app       = "clickhouse"
      component = "query-plane"
    }
  }

  spec {
    cluster_ip = "None"
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

    port {
      name        = "interserver"
      port        = 9009
      target_port = 9009
    }
  }
}

# ─── ClickHouse Query-Plane StatefulSet ───────────────────────────────────────

resource "kubernetes_stateful_set" "clickhouse" {
  lifecycle {
    precondition {
      condition     = !local.cold_tier_on || var.cold_tier_credentials_secret_name != ""
      error_message = "cold_tier_credentials_secret_name is required when the GCS cold tier (cold_tier_bucket) is active."
    }
  }

  metadata {
    name      = "clickhouse"
    namespace = var.namespace
    labels = {
      app       = "clickhouse"
      component = "query-plane"
      posture   = var.environment
    }
  }

  wait_for_rollout = false

  spec {
    service_name          = "clickhouse"
    replicas              = local.replicas
    pod_management_policy = "Parallel"

    selector {
      match_labels = {
        app = "clickhouse"
      }
    }

    template {
      metadata {
        labels = {
          app       = "clickhouse"
          component = "query-plane"
          posture   = var.environment
        }
        annotations = {
          "cage.io/clickhouse-config-sha256" = sha256(jsonencode({
            users = kubernetes_config_map.clickhouse_config.data
            init  = kubernetes_config_map.clickhouse_init_sql.data
          }))
        }
      }

      spec {
        service_account_name = var.service_account_name != "" ? var.service_account_name : null

        # §3, §7: Taint toleration and node affinity for dedicated clickhouse
        # local-SSD node pool; strictly prohibit scheduling onto Spot or general nodes.
        toleration {
          key      = "workload"
          operator = "Equal"
          value    = "clickhouse"
          effect   = "NoSchedule"
        }

        affinity {
          node_affinity {
            required_during_scheduling_ignored_during_execution {
              node_selector_term {
                match_expressions {
                  key      = "workload"
                  operator = "In"
                  values   = ["clickhouse"]
                }
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
          run_as_user     = 101
          fs_group        = 101
          seccomp_profile {
            type = "RuntimeDefault"
          }
        }

        container {
          name  = "clickhouse"
          image = var.image

          security_context {
            allow_privilege_escalation = false
            run_as_non_root            = true
            run_as_user                = 101
            capabilities {
              drop = ["ALL"]
            }
            seccomp_profile {
              type = "RuntimeDefault"
            }
          }

          # GCE ext4 Persistent Disks mount with `lost+found` inside
          # /var/lib/clickhouse, causing ClickHouse /entrypoint.sh to skip
          # /docker-entrypoint-initdb.d unless this flag is set. Every statement
          # in 01_databases.sql uses IF NOT EXISTS so re-execution is idempotent.
          env {
            name  = "CLICKHOUSE_ALWAYS_RUN_INITDB_SCRIPTS"
            value = "true"
          }

          env {
            name = "CLICKHOUSE_PASSWORD"
            value_from {
              secret_key_ref {
                name = kubernetes_secret.clickhouse_admin.metadata[0].name
                key  = var.password_secret_key
              }
            }
          }

          # Read by users.d/langfuse_user.xml (<password from_env=...>).
          env {
            name = "CLICKHOUSE_LANGFUSE_PASSWORD"
            value_from {
              secret_key_ref {
                name = kubernetes_secret.langfuse_app.metadata[0].name
                key  = "CLICKHOUSE_PASSWORD"
              }
            }
          }

          # cold_gcs S3 disk credentials (use_environment_credentials): the HMAC
          # key of the ClickHouse service account, the only identity with IAM
          # on the dedicated tiering bucket.
          dynamic "env" {
            for_each = local.cold_tier_on ? ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"] : []
            content {
              name = env.value
              value_from {
                secret_key_ref {
                  name = var.cold_tier_credentials_secret_name
                  key  = env.value
                }
              }
            }
          }

          port {
            name           = "http"
            container_port = 8123
          }

          port {
            name           = "tcp"
            container_port = 9000
          }

          port {
            name           = "interserver"
            container_port = 9009
          }

          liveness_probe {
            http_get {
              path = "/ping"
              port = "http"
            }
            initial_delay_seconds = 30
            period_seconds        = 10
          }

          readiness_probe {
            http_get {
              path = "/ping"
              port = "http"
            }
            initial_delay_seconds = 10
            period_seconds        = 5
          }

          resources {
            requests = {
              cpu    = var.cpu_request
              memory = var.memory_request
            }
            limits = {
              cpu    = var.cpu_limit
              memory = var.memory_limit
            }
          }

          volume_mount {
            name       = "clickhouse-storage"
            mount_path = "/var/lib/clickhouse"
          }

          volume_mount {
            name       = "clickhouse-users-config"
            mount_path = "/etc/clickhouse-server/users.d/networks.xml"
            sub_path   = "networks.xml"
          }

          volume_mount {
            name       = "clickhouse-users-config"
            mount_path = "/etc/clickhouse-server/users.d/langfuse_user.xml"
            sub_path   = "langfuse_user.xml"
          }

          volume_mount {
            name       = "clickhouse-users-config"
            mount_path = "/etc/clickhouse-server/config.d/storage_configuration.xml"
            sub_path   = "storage_configuration.xml"
          }

          volume_mount {
            name       = "clickhouse-users-config"
            mount_path = "/etc/clickhouse-server/config.d/remote_servers_and_keeper.xml"
            sub_path   = "remote_servers_and_keeper.xml"
          }

          volume_mount {
            name       = "clickhouse-init-sql"
            mount_path = "/docker-entrypoint-initdb.d"
            read_only  = true
          }
        }

        volume {
          name = "clickhouse-users-config"
          config_map {
            name = kubernetes_config_map.clickhouse_config.metadata[0].name
          }
        }

        volume {
          name = "clickhouse-init-sql"
          config_map {
            name = kubernetes_config_map.clickhouse_init_sql.metadata[0].name
          }
        }
      }
    }

    # Hot-tier local SSD volume claim per ClickHouse pod (§1.1, §2.6)
    volume_claim_template {
      metadata {
        name = "clickhouse-storage"
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

# ─── Pod Disruption Budget (Prod / HA Posture) ────────────────────────────────

resource "kubernetes_pod_disruption_budget_v1" "clickhouse" {
  count = local.is_ha ? 1 : 0

  metadata {
    name      = "clickhouse-pdb"
    namespace = var.namespace
  }

  spec {
    min_available = local.replicas > 1 ? 2 : 1
    selector {
      match_labels = {
        app = "clickhouse"
      }
    }
  }
}
