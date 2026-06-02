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

# Generate secure database password
resource "random_password" "db_password" {
  length  = 24
  special = false
}

# Deploy PostgreSQL via Helm
resource "helm_release" "postgresql" {
  name       = var.release_name
  repository = "oci://registry-1.docker.io/bitnamicharts"
  chart      = "postgresql"
  version    = var.chart_version
  # resilience flags
  atomic          = true
  cleanup_on_fail = true
  replace         = true
  namespace       = var.namespace

  set {
    name  = "auth.database"
    value = var.database_name
  }

  set {
    name  = "auth.username"
    value = var.database_user
  }

  set_sensitive {
    name  = "auth.password"
    value = random_password.db_password.result
  }

  set {
    name  = "primary.persistence.enabled"
    value = var.enable_persistence
  }

  set {
    name  = "primary.persistence.size"
    value = var.storage_size
  }

  set {
    name  = "primary.persistence.storageClass"
    value = var.storage_class
  }

  # Resource limits (optional)
  dynamic "set" {
    for_each = var.resources_limits_memory != "" ? [1] : []
    content {
      name  = "primary.resources.limits.memory"
      value = var.resources_limits_memory
    }
  }

  dynamic "set" {
    for_each = var.resources_limits_cpu != "" ? [1] : []
    content {
      name  = "primary.resources.limits.cpu"
      value = var.resources_limits_cpu
    }
  }

  set {
    name  = "primary.resources.requests.cpu"
    value = var.resources_requests_cpu
  }

  set {
    name  = "primary.resources.requests.memory"
    value = var.resources_requests_memory
  }

  # Backup configuration (for production)
  set {
    name  = "backup.enabled"
    value = var.enable_backup
  }

  dynamic "set" {
    for_each = var.enable_backup ? [1] : []
    content {
      name  = "backup.cronjob.schedule"
      value = var.backup_schedule
    }
  }
}

# Create Kubernetes Secret with connection details
resource "kubernetes_secret" "db_credentials" {
  metadata {
    name      = var.credentials_secret_name
    namespace = var.namespace
  }

  data = {
    DATABASE_URL      = "postgresql://${var.database_user}:${random_password.db_password.result}@${var.release_name}.${var.namespace}.svc.cluster.local:5432/${var.database_name}"
    POSTGRES_PASSWORD = random_password.db_password.result
    POSTGRES_USER     = var.database_user
    POSTGRES_DB       = var.database_name
    POSTGRES_HOST     = "${var.release_name}.${var.namespace}.svc.cluster.local"
    POSTGRES_PORT     = "5432"
  }

  depends_on = [helm_release.postgresql]
}
