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

# F-108 (AU-9 / AC-6): root gcp-gke integration test verifying that
# module.clickhouse_operator, module.langfuse, and module.app_secrets plan
# together using the scoped `langfuse_app` principal and `langfuse` database,
# never sharing ClickHouse `default` superuser credentials.

mock_provider "google" {}
mock_provider "helm" {}
mock_provider "kubernetes" {}
mock_provider "random" {}

override_module {
  target = module.memorystore_governance
  outputs = {
    managed_server_ca     = ["-----BEGIN CERTIFICATE-----test-----END CERTIFICATE-----"]
    primary_endpoint_ip   = "10.10.0.5"
    primary_endpoint_port = 6379
    replica_count         = 1
  }
}

override_module {
  target = module.memorystore_app
  outputs = {
    primary_endpoint_ip   = "10.10.0.6"
    primary_endpoint_port = 6379
  }
}

variables {
  project_id                     = "clickhouse-rbac-test-project"
  authorized_networks            = [{ cidr = "203.0.113.7/32", display_name = "test" }]
  langfuse_compliance_public_key = "fake-compliance-public-key"
  langfuse_compliance_secret_key = "fake-compliance-secret-key"
}

run "staging_plans_scoped_langfuse_clickhouse_principal_and_database" {
  command = plan

  assert {
    condition     = module.clickhouse_operator.langfuse_database == "langfuse"
    error_message = "clickhouse_operator must provision dedicated langfuse database"
  }
  assert {
    condition     = module.clickhouse_operator.langfuse_username == "langfuse_app"
    error_message = "langfuse identity must be langfuse_app, never default"
  }
}
