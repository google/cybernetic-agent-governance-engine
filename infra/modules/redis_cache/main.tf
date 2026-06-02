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

# Generate secure Redis password
resource "random_password" "redis_password" {
  length  = 24
  special = false
}

# Deploy Redis via Helm
resource "helm_release" "redis" {
  name       = var.release_name
  repository = "oci://registry-1.docker.io/bitnamicharts"
  chart      = "redis"
  version    = var.chart_version

  # resilience flags
  atomic          = true
  cleanup_on_fail = true
  replace         = true

  namespace = var.namespace

  # Authentication
  set_sensitive {
    name  = "auth.password"
    value = var.password != "" ? var.password : random_password.redis_password.result
  }

  set {
    name  = "auth.enabled"
    value = var.enable_auth
  }

  set {
    name  = "commonConfiguration"
    value = <<-EOT
      maxmemory ${var.maxmemory}
      maxmemory-policy ${var.maxmemory_policy}
      appendonly yes
      appendfsync everysec
      no-appendfsync-on-rewrite yes
    EOT
  }

  # Architecture (standalone vs. replicated)
  set {
    name  = "architecture"
    value = var.architecture
  }

  # Master configuration
  set {
    name  = "master.persistence.enabled"
    value = var.enable_persistence
  }

  set {
    name  = "master.persistence.size"
    value = var.storage_size
  }

  dynamic "set" {
    for_each = var.storage_class != "" ? [1] : []
    content {
      name  = "master.persistence.storageClass"
      value = var.storage_class
    }
  }

  # Resource limits
  dynamic "set" {
    for_each = var.resources_limits_memory != "" ? [1] : []
    content {
      name  = "master.resources.limits.memory"
      value = var.resources_limits_memory
    }
  }

  dynamic "set" {
    for_each = var.resources_limits_cpu != "" ? [1] : []
    content {
      name  = "master.resources.limits.cpu"
      value = var.resources_limits_cpu
    }
  }

  set {
    name  = "master.resources.requests.cpu"
    value = var.resources_requests_cpu
  }

  set {
    name  = "master.resources.requests.memory"
    value = var.resources_requests_memory
  }

  # Replica configuration (if replicated architecture)
  dynamic "set" {
    for_each = var.architecture == "replication" ? [1] : []
    content {
      name  = "replica.replicaCount"
      value = var.replica_count
    }
  }

  dynamic "set" {
    for_each = var.architecture == "replication" ? [1] : []
    content {
      name  = "replica.persistence.enabled"
      value = var.enable_persistence
    }
  }

  # Sentinel (for HA)
  set {
    name  = "sentinel.enabled"
    value = var.enable_sentinel
  }

  # Redis Stack Server (optional - includes RedisJSON, RedisSearch, etc.)
  set {
    name  = "image.repository"
    value = var.use_redis_stack ? "redis/redis-stack-server" : "bitnami/redis"
  }
}

# Create Kubernetes Secret with connection details
resource "kubernetes_secret" "redis_credentials" {
  count = var.create_credentials_secret ? 1 : 0

  metadata {
    name      = var.credentials_secret_name
    namespace = var.namespace
  }

  data = {
    REDIS_PASSWORD = var.password != "" ? var.password : random_password.redis_password.result
    REDIS_HOST     = var.enable_sentinel ? "${var.release_name}.${var.namespace}.svc.cluster.local" : "${var.release_name}-master.${var.namespace}.svc.cluster.local"
    REDIS_PORT     = "6379"
    REDIS_URL      = "redis://:${var.password != "" ? var.password : random_password.redis_password.result}@${var.enable_sentinel ? var.release_name : "${var.release_name}-master"}.${var.namespace}.svc.cluster.local:6379"
  }

  depends_on = [helm_release.redis]
}
