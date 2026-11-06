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

# F-108 (AU-9 / AC-6): plan-time RBAC contracts of the clickhouse_operator module:
# 1. Dedicated non-admin `langfuse_app` identity and `langfuse` database, with
#    `default` restricted strictly to container loopback (`replace="replace"`).
# 2. `/docker-entrypoint-initdb.d/` ConfigMap (`clickhouse-init-sql`) creates
#    the `langfuse` database before Langfuse migrations run.
# 3. `default` or `system` collisions fail closed at plan time.

mock_provider "kubernetes" {}
mock_provider "helm" {}
mock_provider "random" {}

variables {
  namespace   = "governance-stack"
  environment = "staging"
  image       = "clickhouse/clickhouse-server@sha256:0000000000000000000000000000000000000000000000000000000000000001"
}

run "defaults_plan_scoped_langfuse_identity_and_database_init" {
  command = plan

  assert {
    condition     = output.langfuse_database == "langfuse"
    error_message = "langfuse_database must default to langfuse"
  }
  assert {
    condition     = output.langfuse_username == "langfuse_app"
    error_message = "langfuse_username must default to langfuse_app"
  }
  assert {
    condition     = strcontains(kubernetes_config_map.clickhouse_init_sql.data["01_databases.sql"], "CREATE DATABASE IF NOT EXISTS langfuse;")
    error_message = "01_databases.sql must create langfuse database"
  }
  assert {
    condition     = strcontains(kubernetes_config_map.clickhouse_config.data["networks.xml"], "replace=\"replace\"")
    error_message = "networks.xml must set replace=\"replace\" on default user networks"
  }
}

run "langfuse_username_default_is_refused" {
  command = plan
  variables {
    langfuse_username = "default"
  }
  expect_failures = [var.langfuse_username]
}

run "langfuse_database_default_is_refused" {
  command = plan
  variables {
    langfuse_database = "default"
  }
  expect_failures = [var.langfuse_database]
}

run "langfuse_database_system_is_refused" {
  command = plan
  variables {
    langfuse_database = "system"
  }
  expect_failures = [var.langfuse_database]
}
