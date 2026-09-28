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
  instance_id = var.instance_id != "" ? var.instance_id : "cage-valkey-${var.environment}"
  # Ensure network format is projects/{project_id}/global/networks/{network_name}
  network_link = can(regex("^projects/", var.network_id)) ? var.network_id : "projects/${var.project_id}/global/networks/${var.network_id}"
}

resource "google_memorystore_instance" "instance" {
  instance_id = local.instance_id
  location    = var.region
  project     = var.project_id

  shard_count   = var.shard_count
  replica_count = var.replica_count
  node_type     = var.node_type
  mode          = var.mode

  authorization_mode      = var.authorization_mode
  transit_encryption_mode = var.transit_encryption_mode

  # CAGE Invariant: never evict governance state.
  # The static gate test_redis_noeviction_policy.py enforces that noeviction
  # is hard-coded in the configuration and not exposed as a variable.
  engine_configs = {
    "maxmemory-policy" = "noeviction"
  }

  kms_key                     = var.enable_cmek ? var.kms_key_id : null
  deletion_protection_enabled = var.deletion_protection_enabled

  desired_psc_auto_connections {
    network    = local.network_link
    project_id = var.project_id
  }
}
