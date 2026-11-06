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

# F-108 (AU-9 / AC-6): plan-time contracts of the langfuse_stack module:
# 1. `clickhouse_user` defaults to `langfuse_app` and rejects `default`.
# 2. `clickhouse_db` defaults to `langfuse` and rejects `default` and `system`.
# 3. `clickhouse_migration_url` rejects `default` user, missing `/database`
#    path, or `/default` / `/system` target database.

mock_provider "kubernetes" {}
mock_provider "random" {}

variables {
  namespace                = "governance-stack"
  langfuse_image           = "langfuse/langfuse@sha256:0000000000000000000000000000000000000000000000000000000000000001"
  langfuse_worker_image    = "langfuse/langfuse-worker@sha256:0000000000000000000000000000000000000000000000000000000000000002"
  cloudsql_proxy_image     = "gcr.io/cloud-sql-connectors/cloud-sql-proxy@sha256:0000000000000000000000000000000000000000000000000000000000000003"
  database_url             = "postgresql://fixture:fixture@127.0.0.1:5432/langfuse"
  clickhouse_url           = "http://clickhouse:8123"
  clickhouse_migration_url = "clickhouse://langfuse_app:fixture@clickhouse:9000/langfuse"
  redis_connection_string  = "redis://127.0.0.1:6379"
}

run "scoped_langfuse_clickhouse_configuration_passes" {
  command = plan

  assert {
    condition     = var.clickhouse_user == "langfuse_app"
    error_message = "clickhouse_user must default to langfuse_app"
  }
  assert {
    condition     = var.clickhouse_db == "langfuse"
    error_message = "clickhouse_db must default to langfuse"
  }
}

run "clickhouse_user_default_is_refused" {
  command = plan
  variables {
    clickhouse_user = "default"
  }
  expect_failures = [var.clickhouse_user]
}

run "clickhouse_db_default_is_refused" {
  command = plan
  variables {
    clickhouse_db = "default"
  }
  expect_failures = [var.clickhouse_db]
}

run "clickhouse_db_system_is_refused" {
  command = plan
  variables {
    clickhouse_db = "system"
  }
  expect_failures = [var.clickhouse_db]
}

run "migration_url_without_database_path_is_refused" {
  command = plan
  variables {
    clickhouse_migration_url = "clickhouse://langfuse_app:fixture@clickhouse:9000"
  }
  expect_failures = [var.clickhouse_migration_url]
}

run "migration_url_with_default_superuser_is_refused" {
  command = plan
  variables {
    clickhouse_migration_url = "clickhouse://default:fixture@clickhouse:9000/langfuse"
  }
  expect_failures = [var.clickhouse_migration_url]
}

run "migration_url_targeting_default_database_is_refused" {
  command = plan
  variables {
    clickhouse_migration_url = "clickhouse://langfuse_app:fixture@clickhouse:9000/default"
  }
  expect_failures = [var.clickhouse_migration_url]
}
