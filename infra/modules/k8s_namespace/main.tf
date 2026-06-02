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
  }
}

resource "kubernetes_namespace" "this" {
  metadata {
    name = var.name

    labels = merge(
      {
        "app.kubernetes.io/managed-by" = "terraform"
        "cage.io/component"            = "governance-stack"
        "environment"                  = var.environment
      },
      var.enable_pod_security_standards ? {
        "pod-security.kubernetes.io/enforce" = var.pod_security_level
        "pod-security.kubernetes.io/audit"   = var.pod_security_level
        "pod-security.kubernetes.io/warn"    = var.pod_security_level
      } : {},
      var.labels
    )

    annotations = var.annotations
  }
}
