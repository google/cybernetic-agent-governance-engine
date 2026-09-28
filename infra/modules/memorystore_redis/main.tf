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
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.43"
    }
  }
}

locals {
  instance_name = var.name != "" ? var.name : "cage-redis-${var.environment}"
  effective_tier = var.replica_count > 0 ? "STANDARD_HA" : var.redis_tier
}

resource "google_redis_instance" "redis" {
  name               = local.instance_name
  tier               = local.effective_tier
  memory_size_gb     = var.memory_size_gb
  region             = var.region
  authorized_network = var.authorized_network
  connect_mode       = "PRIVATE_SERVICE_ACCESS"
  project            = var.project_id

  redis_version = "REDIS_7_0"

  # CAGE Invariant: never evict governance state.
  # The static gate test_redis_noeviction_policy.py enforces that noeviction
  # is hard-coded in the configuration and not exposed as a variable.
  redis_configs = {
    "maxmemory-policy" = "noeviction"
  }

  customer_managed_key = var.enable_cmek ? var.kms_key_id : null

  replica_count      = var.replica_count
  read_replicas_mode = var.replica_count > 0 ? "READ_REPLICAS_ENABLED" : "READ_REPLICAS_DISABLED"

  auth_enabled            = var.enable_auth
  transit_encryption_mode = var.enable_transit_encryption ? "SERVER_AUTHENTICATION" : "DISABLED"

  dynamic "persistence_config" {
    for_each = var.persistence_mode != "DISABLED" ? [1] : []
    content {
      persistence_mode    = var.persistence_mode
      rdb_snapshot_period = var.rdb_snapshot_period
    }
  }

  maintenance_policy {
    weekly_maintenance_window {
      day = "SUNDAY"
      start_time {
        hours   = 2
        minutes = 0
        seconds = 0
        nanos   = 0
      }
    }
  }
}
