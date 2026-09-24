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

# ─── VPC Service Controls Perimeter (Production Only) ──────────────────────────
#
# SC-7: Boundary Protection via VPC Service Controls
# Creates a security perimeter around Google Cloud services to prevent data exfiltration
# and enforce least-privilege access policies.
#
# Only enabled when:
# - var.environment == "prod"
# - var.enable_nist_compliance == true
#
# Cost impact: ~$200/month in production (no cost in dev/staging)

resource "google_access_context_manager_access_policy" "cage_policy" {
  count  = var.environment == "prod" && var.enable_nist_compliance ? 1 : 0
  parent = "organizations/${var.organization_id}"
  title  = "CAGE Production Security Policy"
}

resource "google_access_context_manager_service_perimeter" "cage_perimeter" {
  count  = var.environment == "prod" && var.enable_nist_compliance ? 1 : 0
  parent = "accessPolicies/${google_access_context_manager_access_policy.cage_policy[0].name}"
  name   = "accessPolicies/${google_access_context_manager_access_policy.cage_policy[0].name}/servicePerimeters/cage_prod_perimeter"
  title  = "CAGE Production Perimeter"

  status {
    restricted_services = [
      "run.googleapis.com",
      "sqladmin.googleapis.com",
      "redis.googleapis.com",
      "secretmanager.googleapis.com",
      "storage.googleapis.com",
    ]

    resources = [
      "projects/${data.google_project.current.number}"
    ]

    # Allow access from Cloud Run subnet
    vpc_accessible_services {
      enable_restriction = true
      allowed_services = [
        "run.googleapis.com",
        "sqladmin.googleapis.com",
        "redis.googleapis.com",
        "secretmanager.googleapis.com",
        "storage.googleapis.com",
      ]
    }
  }
}
