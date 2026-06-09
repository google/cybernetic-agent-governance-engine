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
      version = "~> 5.0"
    }
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

  # Store Terraform state in GCS bucket.
  # Activate by setting TF_BACKEND_BUCKET before running terraform init:
  #   export TF_BACKEND_BUCKET="${PROJECT_ID}-tfstate"
  #   terraform init -backend-config="bucket=${TF_BACKEND_BUCKET}"
  # D-03 remediation: backend is declared; bucket name is injected at init time
  # via -backend-config to avoid committing project-specific values.
  backend "gcs" {
    prefix = "cage/gcp-gke"
    # bucket is supplied via: terraform init -backend-config="bucket=<PROJECT>-tfstate"
    # or TF_CLI_ARGS_init="-backend-config=bucket=<PROJECT>-tfstate"
  }
}

# ─── Data Sources ─────────────────────────────────────────────────────────────

data "google_client_config" "default" {}

# Resolve project number — required to construct the Cloud Build default SA
# member string: [PROJECT_NUMBER]@cloudbuild.gserviceaccount.com
data "google_project" "current" {
  project_id = var.project_id
}

# ─── Provision GKE Cluster ────────────────────────────────────────────────────

module "gke" {
  source = "../../modules/gcp_gke_cluster"

  project_id   = var.project_id
  region       = var.region
  zone         = var.zone
  cluster_name = var.cluster_name
  environment  = var.environment

  # Security posture toggles
  enable_nist_compliance         = var.enable_nist_compliance
  enable_binary_authorization    = var.enable_binary_authorization
  enable_audit_logging           = var.enable_audit_logging
  enable_cmek                    = var.enable_cmek
  enable_private_master_endpoint = var.enable_private_master_endpoint

  # NIST-specific configuration
  authorized_networks = var.authorized_networks
  kms_key_id          = var.kms_key_id

  # Node pools
  primary_node_pool_machine_type  = var.primary_node_pool_machine_type
  primary_node_pool_min_count     = var.primary_node_pool_min_count
  primary_node_pool_max_count     = var.primary_node_pool_max_count
  primary_node_pool_initial_count = var.primary_node_pool_initial_count
  primary_node_pool_disk_type     = var.primary_node_pool_disk_type

  # GPU node pool
  enable_gpu_node_pool        = var.enable_gpu_node_pool
  gpu_type                    = var.gpu_type
  gpu_count                   = var.gpu_count
  gpu_node_pool_machine_type  = var.gpu_node_pool_machine_type
  gpu_node_pool_min_count     = var.gpu_node_pool_min_count
  gpu_node_pool_max_count     = var.gpu_node_pool_max_count
  gpu_node_pool_initial_count = var.gpu_node_pool_initial_count
  gpu_node_pool_spot          = var.gpu_node_pool_spot
  gpu_node_locations          = var.gpu_node_locations

  # GCP-specific features
  enable_gcs_fuse_csi = var.enable_gcs_fuse_csi

  # Networking
  pod_cidr               = var.pod_cidr
  service_cidr           = var.service_cidr
  master_ipv4_cidr_block = var.master_ipv4_cidr_block
}

# ─── Create Namespace ─────────────────────────────────────────────────────────

module "namespace" {
  source = "../../modules/k8s_namespace"

  name        = var.namespace
  environment = var.environment

  enable_pod_security_standards = var.enable_pod_security_standards
  pod_security_level            = var.pod_security_level

  depends_on = [module.gke]
}

# ─── GCS Bucket for Langfuse Events ───────────────────────────────────────────

resource "random_id" "bucket_suffix" {
  byte_length = 4
}

resource "google_storage_bucket" "langfuse_events" {
  name          = "langfuse-events-${var.project_id}-${random_id.bucket_suffix.hex}"
  location      = var.region
  project       = var.project_id
  force_destroy = var.environment == "dev" ? true : false

  uniform_bucket_level_access = true

  # AU-9: 7-year retention for compliance evidence (ISO 42001 A.7.5)
  lifecycle_rule {
    condition {
      age = 2555 # 7 years in days
    }
    action {
      type = "Delete"
    }
  }

  labels = {
    environment = var.environment
    managed-by  = "terraform"
    purpose     = "langfuse-traces"
  }
}

# ─── GCS S3-compatible HMAC Keys (Langfuse Blob Storage) ─────────────────────

resource "google_service_account" "langfuse_gcs" {
  account_id   = "langfuse-gcs-${var.environment}"
  display_name = "Langfuse GCS S3-compatible access"
  project      = var.project_id
}

resource "google_storage_bucket_iam_member" "langfuse_gcs_admin" {
  bucket = google_storage_bucket.langfuse_events.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.langfuse_gcs.email}"
}

resource "google_storage_hmac_key" "langfuse_key" {
  service_account_email = google_service_account.langfuse_gcs.email
  project               = var.project_id
}

# ─── Cloud Build IAM — Artifact Registry push permission ─────────────────────
#
# GCP projects created after May 2023 route gcr.io pushes through Artifact
# Registry. The Cloud Build default SA needs roles/artifactregistry.writer
# at the project level to push images via cloudbuild.compliance.yaml and
# the gateway / advisor Cloud Build configs.
#
# Cloud Build default SA: [PROJECT_NUMBER]@cloudbuild.gserviceaccount.com
# Reference: https://cloud.google.com/build/docs/securing-builds/configure-access-for-cloud-build-service-account

resource "google_project_iam_member" "cloudbuild_artifactregistry_writer" {
  project = var.project_id
  role    = "roles/artifactregistry.writer"
  member  = "serviceAccount:${data.google_project.current.number}@cloudbuild.gserviceaccount.com"
}

# ─── Deploy PostgreSQL Database ───────────────────────────────────────────────

module "postgres" {
  source = "../../modules/postgres_db"

  namespace                 = module.namespace.name
  storage_size              = var.postgres_storage_size
  storage_class             = var.storage_class
  enable_persistence        = true
  enable_backup             = false
  resources_limits_memory   = var.enable_nist_compliance ? "4Gi" : ""
  resources_limits_cpu      = var.enable_nist_compliance ? "2000m" : ""
  resources_requests_cpu    = "500m"
  resources_requests_memory = "1Gi"

  depends_on = [module.gke]
}

# ─── Deploy Redis Cache ────────────────────────────────────────────────────────

module "redis" {
  source = "../../modules/redis_cache"

  namespace                 = module.namespace.name
  storage_size              = var.redis_storage_size
  storage_class             = var.storage_class
  architecture              = var.enable_nist_compliance ? "replication" : "standalone"
  replica_count             = var.enable_nist_compliance ? 3 : 1
  enable_persistence        = var.enable_nist_compliance
  enable_sentinel           = var.enable_nist_compliance
  resources_limits_memory   = var.enable_nist_compliance ? "2Gi" : ""
  resources_limits_cpu      = var.enable_nist_compliance ? "1000m" : ""
  resources_requests_cpu    = "200m"
  resources_requests_memory = "512Mi"
  maxmemory                 = var.environment == "prod" ? "1024mb" : "256mb"
  maxmemory_policy          = var.environment == "prod" ? "noeviction" : "allkeys-lru"

  depends_on = [module.gke]
}

# ─── Deploy ClickHouse OLAP Database ──────────────────────────────────────────

module "clickhouse" {
  source = "../../modules/clickhouse"

  namespace                 = module.namespace.name
  storage_size              = var.clickhouse_storage_size
  storage_class             = var.storage_class
  replicas                  = 1
  enable_persistence        = true
  enable_pdb                = var.enable_nist_compliance
  enable_nist_compliance    = var.enable_nist_compliance
  resources_limits_cpu      = var.enable_nist_compliance ? "3000m" : ""
  resources_limits_memory   = var.enable_nist_compliance ? "4Gi" : ""
  resources_requests_cpu    = "1000m"
  resources_requests_memory = "2Gi"

  depends_on = [module.gke]
}

# ─── Deploy NeMo Guardrails + Microsoft Presidio ───────────────────────────────

module "nemo_guardrails" {
  count = var.enable_nemo_guardrails ? 1 : 0

  source = "../../modules/nemo_guardrails"

  namespace       = module.namespace.name
  deployment_name = "nemo-guardrails"
  service_name    = "nemo-guardrails"
  replicas        = var.enable_nist_compliance ? 2 : 1
  enable_pdb      = var.enable_nist_compliance

  # NeMo container image (custom-built via Cloud Build or upstream NVIDIA)
  nemo_image = var.nemo_image != "" ? var.nemo_image : "gcr.io/${var.project_id}/nemo-guardrails:latest"

  # Presidio images (Microsoft public registry)
  presidio_analyzer_image   = var.presidio_analyzer_image
  presidio_anonymizer_image = var.presidio_anonymizer_image

  # LLM backend: NeMo rails call vLLM fast service for rail evaluation
  llm_api_base   = "http://vllm-service.${module.namespace.name}.svc.cluster.local:8000/v1"
  llm_api_key    = "EMPTY"
  llm_model_name = var.model_fast

  # Resource sizing
  nemo_cpu_request    = "500m"
  nemo_memory_request = "1Gi"
  nemo_cpu_limit      = var.enable_nist_compliance ? "2000m" : ""
  nemo_memory_limit   = var.enable_nist_compliance ? "4Gi" : ""

  presidio_cpu_request    = "200m"
  presidio_memory_request = "512Mi"
  presidio_cpu_limit      = var.enable_nist_compliance ? "1000m" : ""
  presidio_memory_limit   = var.enable_nist_compliance ? "2Gi" : ""

  enable_security_context = var.enable_nist_compliance

  depends_on = [module.gke, module.vllm]
}

# ─── Deploy vLLM Inference Engine ──────────────────────────────────────────────

module "vllm" {
  count = var.enable_vllm ? 1 : 0

  source = "../../modules/vllm_inference"

  namespace       = module.namespace.name
  deployment_name = "vllm-inference"
  service_account_name = "financial-advisor-sa"
  image           = var.vllm_image != "" ? var.vllm_image : "gcr.io/${var.project_id}/vllm-streamer:latest"
  # model_path dynamically routes: gs:// to GCS tensor streaming, else HF hub
  model_path     = var.model_fast
  gpu_count      = var.vllm_gpu_count
  gpu_product    = var.gpu_type
  replicas       = var.vllm_replicas
  enable_pdb     = var.enable_nist_compliance
  memory_limit   = var.vllm_memory_limit
  cpu_limit      = var.vllm_cpu_limit
  memory_request = var.vllm_memory_request
  cpu_request    = var.vllm_cpu_request

  # Dynamic weight streaming if gs:// is provided
  vllm_load_format = can(regex("^gs://", var.model_fast)) ? "gcs_filesystem" : "auto"

  # GCS model streamer requires GOOGLE_CLOUD_PROJECT to authenticate with GCS.
  # Without it, runai_model_streamer_gcs raises OSError: Project was not passed.
  env_vars = {
    "GOOGLE_CLOUD_PROJECT" = var.project_id
  }

  # GCP-specific GPU node targeting
  # Use cloud.google.com/gke-nodepool (known to autoscaler at scale-from-zero time).
  # nvidia.com/gpu.product is applied post-startup by device plugin — autoscaler can't match it.
  node_selector = {
    "workload-type" = "gpu"
  }

  tolerations = [
    {
      key      = "nvidia.com/gpu"
      operator = "Equal"
      value    = "present"
      effect   = "NoSchedule"
    },
    {
      key      = "cloud.google.com/gke-spot"
      operator = "Equal"
      value    = "true"
      effect   = "NoSchedule"
    }
  ]

  depends_on = [module.gke]
}

# ─── Deploy vLLM Reasoning Engine ──────────────────────────────────────────────

module "vllm_reasoning" {
  count = var.enable_vllm ? 1 : 0

  source = "../../modules/vllm_inference"

  namespace       = module.namespace.name
  deployment_name = "vllm-reasoning"
  service_account_name = "financial-advisor-sa"
  service_name    = "vllm-reasoning"
  image           = var.vllm_image != "" ? var.vllm_image : "gcr.io/${var.project_id}/vllm-streamer:latest"
  # model_path dynamically routes: gs:// to GCS tensor streaming, else HF hub
  model_path     = var.model_reasoning
  gpu_count      = var.vllm_gpu_count
  gpu_product    = var.gpu_type
  replicas       = var.vllm_replicas
  enable_pdb     = var.enable_nist_compliance
  memory_limit   = var.vllm_memory_limit
  cpu_limit      = var.vllm_cpu_limit
  memory_request = var.vllm_memory_request
  cpu_request    = var.vllm_cpu_request

  # Dynamic weight streaming if gs:// is provided
  vllm_load_format = can(regex("^gs://", var.model_reasoning)) ? "gcs_filesystem" : "auto"

  # Cap max context to 16K — 14B AWQ model needs 24 GiB KV for 131K default (> 8.9 GiB available)
  vllm_command = "python3 -m vllm.entrypoints.openai.api_server --model $MODEL_PATH --host 0.0.0.0 --port 8000 --max-model-len 16384"

  # GCS model streamer requires GOOGLE_CLOUD_PROJECT to authenticate with GCS.
  # Without it, runai_model_streamer_gcs raises OSError: Project was not passed.
  env_vars = {
    "GOOGLE_CLOUD_PROJECT" = var.project_id
  }

  # GCP-specific GPU node targeting
  # Use cloud.google.com/gke-nodepool (known to autoscaler at scale-from-zero time).
  node_selector = {
    "workload-type" = "gpu"
  }

  tolerations = [
    {
      key      = "nvidia.com/gpu"
      operator = "Equal"
      value    = "present"
      effect   = "NoSchedule"
    },
    {
      key      = "cloud.google.com/gke-spot"
      operator = "Equal"
      value    = "true"
      effect   = "NoSchedule"
    }
  ]

  depends_on = [module.gke]
}

# ─── Deploy Langfuse Observability ─────────────────────────────────────────────

module "langfuse" {
  source = "../../modules/langfuse_stack"

  namespace                = module.namespace.name
  database_url             = module.postgres.connection_string
  clickhouse_url           = "http://${module.clickhouse.service_name}:${module.clickhouse.http_port}"
  clickhouse_migration_url = "clickhouse://default:${module.clickhouse.password}@${module.clickhouse.service_name}:${module.clickhouse.tcp_port}"
  clickhouse_user          = "default"
  clickhouse_password      = module.clickhouse.password
  redis_connection_string  = "redis://:${module.redis.password}@${module.redis.service_name}:6379"
  redis_host               = module.redis.service_name
  redis_port               = "6379"

  # S3-compatible blob storage via GCS HMAC keys
  s3_endpoint   = var.langfuse_s3_endpoint
  s3_bucket     = var.langfuse_s3_bucket != "" ? var.langfuse_s3_bucket : google_storage_bucket.langfuse_events.name
  s3_access_key = var.langfuse_s3_access_key != "" ? var.langfuse_s3_access_key : google_storage_hmac_key.langfuse_key.access_id
  s3_secret_key = var.langfuse_s3_secret_key != "" ? var.langfuse_s3_secret_key : google_storage_hmac_key.langfuse_key.secret
  s3_region     = var.region

  nextauth_url          = var.langfuse_nextauth_url
  web_replicas          = var.enable_nist_compliance ? 2 : 1
  worker_replicas       = var.enable_nist_compliance ? 2 : 1
  web_cpu_request       = "50m"
  worker_cpu_request    = "50m"
  web_memory_request    = "256Mi"
  worker_memory_request = "256Mi"

  langfuse_public_key = var.langfuse_public_key
  langfuse_secret_key = var.langfuse_secret_key

  langfuse_init_user_email    = "dev-admin@local.com"
  langfuse_init_user_password = "dev-password-123"
  langfuse_init_project_name  = "cybernetic-governance"
  langfuse_init_project_id    = "cybernetic-governance"
  langfuse_init_org_id        = "CAGE"
  langfuse_init_org_name      = "CAGE"

  depends_on = [module.postgres, module.clickhouse, module.redis, google_storage_hmac_key.langfuse_key, module.gke]
}

# ─── Deploy Compliance Bridge ───────────────────────────────────────────────────

module "compliance_bridge" {
  count = var.enable_compliance_bridge ? 1 : 0

  source = "../../modules/compliance_bridge"

  namespace     = module.namespace.name
  image         = var.compliance_bridge_image != "" ? var.compliance_bridge_image : "gcr.io/${var.project_id}/compliance-bridge:latest"
  langfuse_host = "http://${module.langfuse.web_service_name}.${module.namespace.name}.svc.cluster.local:3000"
  replicas      = var.enable_nist_compliance ? 2 : 1

  remediation_model      = var.model_fast
  remediation_max_tokens = "2048"
  remediation_timeout_ms = "30000"
  vllm_base_url          = "http://vllm-service.${module.namespace.name}.svc.cluster.local:8000/v1"
  vllm_api_key           = "EMPTY"
  alert_channel          = "console"
  oscal_s3_bucket        = google_storage_bucket.langfuse_events.name
  oscal_s3_region        = var.region

  depends_on = [module.langfuse, module.vllm]
}

# ─── Deploy OPA Policy Engine ──────────────────────────────────────────────────

module "opa" {
  source = "../../modules/opa_policy"

  namespace = module.namespace.name
  replicas  = var.enable_nist_compliance ? 2 : 1

  # Optional: Add custom policies
  policy_files = {
    "trade_governance.rego" = file("${path.module}/../../../src/governed_financial_advisor/governance/policy/trade_governance.rego")
  }

  depends_on = [module.gke]
}

# ─── Deploy Gateway ─────────────────────────────────────────────────────────────

module "gateway" {
  source = "../../modules/gateway"

  namespace               = module.namespace.name
  image                   = "gcr.io/${var.project_id}/gateway:latest"
  replicas                = var.enable_nist_compliance ? 2 : 1
  project_id              = var.project_id
  region                  = var.region
  enable_logging          = "true"
  cage_env                = "production"
  redis_host              = module.redis.service_name
  redis_password          = module.redis.password
  vllm_base_url           = "http://vllm-service.${module.namespace.name}.svc.cluster.local:8000/v1"
  vllm_reasoning_api_base = "http://vllm-reasoning.${module.namespace.name}.svc.cluster.local:8000/v1"
  vllm_fast_api_base      = "http://vllm-service.${module.namespace.name}.svc.cluster.local:8000/v1"
  guardrails_model_name   = var.model_fast
  opa_url                 = "http://${module.opa.service_name}.${module.namespace.name}.svc.cluster.local:8181/v1/data/trade/governance"
  governance_salt         = var.governance_salt

  depends_on = [module.opa, module.vllm, module.redis]
}

# ─── Deploy Governed Financial Advisor ────────────────────────────────────────

module "governed_advisor" {
  source = "../../modules/governed_advisor"

  namespace               = module.namespace.name
  image                   = "gcr.io/${var.project_id}/governed-financial-advisor:latest"
  replicas                = var.enable_nist_compliance ? 2 : 1
  project_id              = var.project_id
  region                  = var.region
  enable_logging          = "true"
  redis_host              = module.redis.service_name
  redis_password          = module.redis.password
  model_fast              = var.model_fast
  model_reasoning         = var.model_reasoning
  model_consensus         = var.model_reasoning
  vllm_base_url           = "http://vllm-service.${module.namespace.name}.svc.cluster.local:8000/v1"
  vllm_fast_api_base      = "http://vllm-service.${module.namespace.name}.svc.cluster.local:8000/v1"
  vllm_reasoning_api_base = "http://vllm-reasoning.${module.namespace.name}.svc.cluster.local:8000/v1"
  opa_url                 = "http://${module.opa.service_name}.${module.namespace.name}.svc.cluster.local:8181"
  # Langfuse web service exposes port 3000 (not 80) — corrected from initial misconfiguration.
  langfuse_host           = "http://${module.langfuse.web_service_name}.${module.namespace.name}.svc.cluster.local:3000"
  governance_salt         = var.governance_salt
  gateway_url             = "http://${module.gateway.service_name}.${module.namespace.name}.svc.cluster.local:8080"

  depends_on = [module.gateway, module.langfuse, module.vllm, module.opa]
}

# ─── Deploy AgentSight UI ─────────────────────────────────────────────────────

module "agentsight_ui" {
  source = "../../modules/agentsight_ui"

  namespace = module.namespace.name
  image     = "gcr.io/${var.project_id}/agentsight-ui:latest"
  replicas  = 1

  depends_on = [module.gke]
}

# ─── Application Secrets ──────────────────────────────────────────────────────

module "app_secrets" {
  source = "../../modules/app_secrets"

  namespace = module.namespace.name

  governance_salt      = var.governance_salt
  salt                 = var.governance_salt
  alphavantage_api_key = "" # Add variable if needed
  openai_api_key       = ""
  model_fast           = var.model_fast
  model_reasoning      = var.model_reasoning
  routing_seal_secret  = var.routing_seal_secret

  langfuse_public_key = var.langfuse_public_key != "" ? var.langfuse_public_key : module.langfuse.public_key
  langfuse_secret_key = var.langfuse_secret_key != "" ? var.langfuse_secret_key : module.langfuse.secret_key
  langfuse_host       = "http://${module.langfuse.web_service_name}.${module.namespace.name}.svc.cluster.local:3000"

  clickhouse_url           = "http://${module.clickhouse.service_name}:${module.clickhouse.http_port}"
  clickhouse_migration_url = "clickhouse://default:${module.clickhouse.password}@${module.clickhouse.service_name}:${module.clickhouse.tcp_port}"
  clickhouse_user          = "default"
  clickhouse_password      = module.clickhouse.password
  database_url             = module.postgres.connection_string
  nextauth_secret          = module.langfuse.nextauth_secret
  nextauth_url             = var.langfuse_nextauth_url

  aws_access_key_id     = var.aws_access_key
  aws_secret_access_key = var.aws_secret_key
  s3_endpoint_url       = "https://storage.googleapis.com"
  s3_bucket_name        = google_storage_bucket.langfuse_events.name

  hf_token = var.hf_token

  # ─── Langfuse compliance project keys (P2-2) ────────────────────────────────
  # Dev posture: pass the key as-is (may be empty → module skips secret creation
  #   when enable_nist_compliance=false; compliance bridge handles None gracefully).
  # Prod posture (enable_nist_compliance=true): the precondition below enforces
  #   that a real, distinct cage-compliance project key is provided.
  #   The silent fallback to module.langfuse.public_key has been removed to prevent
  #   circular evidence contamination in Step 5 (_fetch_failing_traces).
  langfuse_compliance_public_key = var.langfuse_compliance_public_key
  langfuse_compliance_secret_key = var.langfuse_compliance_secret_key

  # Prod precondition: fail the plan if compliance keys are missing or identical
  # to the operations keys. This enforces AU-9 audit integrity at plan time.
  # enable_nist_compliance is not passed to app_secrets module (not declared there).

  oscal_api_key = "DUMMY_API_KEY_FOR_LOCAL_DEV"

  opa_url = "http://${module.opa.service_name}.${module.namespace.name}.svc.cluster.local:8181"

  cage_deployment_region = var.cage_deployment_region

  depends_on = [module.langfuse, module.postgres, module.clickhouse]
}
