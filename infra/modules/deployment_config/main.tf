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

# The one place a deployment declares its jurisdiction.
#
# Every CAGE workload (gateway, governed advisor, compliance bridge,
# reconciliation worker, Lula audit cron) reads CAGE_DEPLOYMENT_REGION from
# this ConfigMap via configMapKeyRef (optional: false). No workload carries
# its own copy, so a deployment cannot run the gateway under one jurisdiction
# while auditing it under another. The region is not sensitive, so it lives
# in a ConfigMap rather than a Secret; integration tests read the same
# ConfigMap to discover the region they must run in.

terraform {
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.23"
    }
  }
}

resource "kubernetes_config_map" "cage_deployment" {
  metadata {
    name      = "cage-deployment"
    namespace = var.namespace
    labels = {
      "app.kubernetes.io/managed-by" = "terraform"
      "app.kubernetes.io/part-of"    = "cage"
    }
  }

  data = {
    "CAGE_DEPLOYMENT_REGION" = var.cage_deployment_region
  }
}
