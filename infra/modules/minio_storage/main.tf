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
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.11"
    }
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

# Generate secure password if not provided
resource "random_password" "minio_root_password" {
  count   = var.root_password == "" ? 1 : 0
  length  = 24
  special = true
}

locals {
  minio_password = var.root_password != "" ? var.root_password : random_password.minio_root_password[0].result
}

# MinIO Helm release
resource "helm_release" "minio" {
  name       = var.release_name
  repository = "https://charts.min.io/"
  chart      = "minio"
  namespace  = var.namespace
  version    = var.chart_version

  # Core configuration
  set {
    name  = "rootUser"
    value = var.root_user
  }

  set {
    name  = "rootPassword"
    value = local.minio_password
  }

  # Persistence
  set {
    name  = "persistence.enabled"
    value = "true"
  }

  set {
    name  = "persistence.storageClass"
    value = var.storage_class
  }

  set {
    name  = "persistence.size"
    value = var.storage_size
  }

  # Mode
  set {
    name  = "mode"
    value = var.mode
  }

  # Resources
  set {
    name  = "resources.requests.memory"
    value = var.resources_requests_memory
  }

  set {
    name  = "resources.requests.cpu"
    value = var.resources_requests_cpu
  }

  # Limits (only in prod)
  dynamic "set" {
    for_each = var.resources_limits_memory != "" ? [1] : []
    content {
      name  = "resources.limits.memory"
      value = var.resources_limits_memory
    }
  }

  dynamic "set" {
    for_each = var.resources_limits_cpu != "" ? [1] : []
    content {
      name  = "resources.limits.cpu"
      value = var.resources_limits_cpu
    }
  }

  # Service configuration
  set {
    name  = "service.type"
    value = var.service_type
  }

  set {
    name  = "service.port"
    value = var.service_port
  }

  # Console
  set {
    name  = "consoleService.port"
    value = var.console_port
  }

  # Replicas
  set {
    name  = "replicas"
    value = var.replicas
  }

  # Security context (prod only)
  dynamic "set" {
    for_each = var.enable_security_context ? [1] : []
    content {
      name  = "securityContext.runAsNonRoot"
      value = "true"
    }
  }

  dynamic "set" {
    for_each = var.enable_security_context ? [1] : []
    content {
      name  = "securityContext.runAsUser"
      value = "1000"
    }
  }
}

# Store credentials in Kubernetes secret for other services
resource "kubernetes_secret" "minio_credentials" {
  metadata {
    name      = "${var.release_name}-credentials"
    namespace = var.namespace
  }

  data = {
    access-key = var.root_user
    secret-key = local.minio_password
  }

  type = "Opaque"
}
