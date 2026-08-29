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
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.23"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.11"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }

  # Store Terraform state in the Kubernetes cluster itself
  # No external cloud dependencies required
  backend "kubernetes" {
    secret_suffix = "tfstate-agnostic"
    namespace     = "terraform-state"

    # These will be set via -backend-config or environment variables
    # config_path    = var.kubeconfig_path
    # config_context = var.kubeconfig_context
  }
}

# ─── Create Namespace ─────────────────────────────────────────────────────────

module "namespace" {
  source = "../../modules/k8s_namespace"

  name        = var.namespace
  environment = var.environment

  # Dev: No Pod Security Standards
  # Prod: Enable restricted mode
  enable_pod_security_standards = var.enable_pod_security_standards
  pod_security_level            = var.pod_security_level
}

# ─── Deploy MinIO Object Storage ──────────────────────────────────────────────

module "minio" {
  source = "../../modules/minio_storage"

  namespace     = module.namespace.name
  storage_class = var.storage_class
  storage_size  = var.minio_storage_size
  root_user     = var.minio_root_user
  root_password = var.minio_root_password

  # Dev: No resource limits
  # POAM-024: Resource limits and security context now controlled by enable_high_availability
  resources_limits_memory = var.enable_high_availability ? "4Gi" : ""
  resources_limits_cpu    = var.enable_high_availability ? "2000m" : ""

  # Security context remains environment-dependent (not HA-related)
  enable_security_context = var.environment == "prod"
}

# ─── Deploy PostgreSQL Database ───────────────────────────────────────────────

module "postgres" {
  source = "../../modules/postgres_db"

  namespace               = module.namespace.name
  storage_size            = var.postgres_storage_size
  storage_class           = var.storage_class
  enable_persistence      = true
  enable_backup           = var.enable_high_availability
  resources_limits_memory = var.enable_high_availability ? "4Gi" : ""
  resources_limits_cpu    = var.enable_high_availability ? "2000m" : ""
}

# ─── Deploy Redis Cache ────────────────────────────────────────────────────────

module "redis" {
  source = "../../modules/redis_cache"

  namespace               = module.namespace.name
  storage_size            = var.redis_storage_size
  storage_class           = var.storage_class
  architecture            = var.enable_high_availability ? "replication" : "standalone"
  replica_count           = var.enable_high_availability ? 3 : 1
  enable_persistence      = var.enable_high_availability
  resources_limits_memory = var.enable_high_availability ? "2Gi" : ""
  resources_limits_cpu    = var.enable_high_availability ? "1000m" : ""
}

# ─── Deploy vLLM Inference Engine ──────────────────────────────────────────────

module "vllm" {
  count = var.enable_vllm ? 1 : 0

  source = "../../modules/vllm_inference"

  namespace       = module.namespace.name
  deployment_name = "vllm-inference"
  model_path      = var.vllm_model_path
  gpu_count       = var.vllm_gpu_count
  replicas        = var.vllm_replicas
  enable_pdb      = var.enable_high_availability

  # Node selector and tolerations for GPU nodes
  node_selector = var.vllm_node_selector
  tolerations   = var.vllm_tolerations
}

# ─── Deploy Langfuse Observability ─────────────────────────────────────────────

module "langfuse" {
  source = "../../modules/langfuse_stack"

  namespace       = module.namespace.name
  database_url    = module.postgres.connection_string
  nextauth_url    = var.langfuse_nextauth_url
  web_replicas    = var.enable_high_availability ? 2 : 1
  worker_replicas = var.enable_high_availability ? 2 : 1

  depends_on = [module.postgres]
}

# ─── Deploy Compliance Bridge ──────────────────────────────────────────────────

module "compliance_bridge" {
  count = var.enable_compliance_bridge ? 1 : 0

  source = "../../modules/compliance_bridge"

  namespace     = module.namespace.name
  image         = var.compliance_bridge_image
  langfuse_host = module.langfuse.web_url
  replicas      = var.enable_high_availability ? 2 : 1

  depends_on = [module.langfuse]
}

# ─── Deploy OPA Policy Engine ──────────────────────────────────────────────────

module "opa" {
  source = "../../modules/opa_policy"

  namespace = module.namespace.name
  replicas  = var.enable_high_availability ? 2 : 1

  # Optional: Add custom policies
  policy_files = var.opa_policy_files
}
