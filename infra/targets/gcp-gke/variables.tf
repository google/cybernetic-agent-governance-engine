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

variable "project_id" {
  description = "GCP project ID"
  type        = string
}

# DEP-08: Remove default values for region and zone.
# Defaulting to us-central1 silently violates GDPR Art. 44 (EU_ECB) and
# MAS TRM §4.2 (APAC_MAS) when no var-file is supplied. Operators must
# explicitly set region/zone via a jurisdiction-specific tfvars file.
# R-3, R-4, R-7: data residency must be enforced at the Terraform layer.
variable "region" {
  description = "GCP region — must be set explicitly via a jurisdiction-specific tfvars file (e.g. eu-prod.tfvars, apac-prod.tfvars, prod.tfvars). No default: omitting this causes a Terraform plan error rather than silently deploying to us-central1."
  type        = string
}

variable "zone" {
  description = "GCP zone — must be set explicitly via a jurisdiction-specific tfvars file. No default: omitting this causes a Terraform plan error rather than silently deploying to us-central1-a."
  type        = string
}

# ─── Cluster Configuration ────────────────────────────────────────────────────

variable "cluster_name" {
  description = "GKE cluster name"
  type        = string
  default     = "cage-gke"
}

variable "environment" {
  description = "Environment (dev, staging, prod)"
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

variable "namespace" {
  description = "Kubernetes namespace"
  type        = string
  default     = "governance-stack"
}

# ─── Security Posture Toggles ─────────────────────────────────────────────────

variable "enable_nist_compliance" {
  description = "Enable NIST SP 800-53 RMF security controls (SC-7, AC-3, deletion protection). US_FED only — do not set for EU_ECB or APAC_MAS deployments."
  type        = bool
  default     = false
}

# DEP-20: Introduce enable_eu_ecb_compliance to independently activate DORA Art. 10
# HA and GDPR Art. 32 encryption requirements for EU_ECB deployments.
# Previously, EU_ECB deployments had no mechanism to activate HA/encryption
# because enable_nist_compliance was the only hardening toggle.
# R-3: EU AI Act / GDPR / DORA logic MUST be gated on CAGE_DEPLOYMENT_REGION == "EU_ECB".
variable "enable_eu_ecb_compliance" {
  description = "Enable EU_ECB compliance hardening: DORA Art. 10 HA, GDPR Art. 32 encryption at rest. EU_ECB only — activates Redis replication, PostgreSQL resource limits, and ClickHouse PDB independently of enable_nist_compliance."
  type        = bool
  default     = false
}

# DEP-20: Introduce enable_apac_mas_compliance to independently activate MAS TRM §9.1
# encryption and MAS Notice 655 audit logging requirements for APAC_MAS deployments.
variable "enable_apac_mas_compliance" {
  description = "Enable APAC_MAS compliance hardening: MAS TRM §9.1 encryption at rest, MAS Notice 655 audit logging. APAC_MAS only — activates Redis persistence and resource limits independently of enable_nist_compliance."
  type        = bool
  default     = false
}

variable "enable_binary_authorization" {
  description = "Enable Binary Authorization (CM-7, SI-7)"
  type        = bool
  default     = false
}

variable "enable_audit_logging" {
  description = "Enable comprehensive audit logging (AU-2, AU-3, AU-9)"
  type        = bool
  default     = false
}

variable "enable_cmek" {
  description = "Enable Customer-Managed Encryption Keys (SC-12, SC-13)"
  type        = bool
  default     = false
}

variable "enable_private_master_endpoint" {
  description = "Make Kubernetes API endpoint private (requires VPN)"
  type        = bool
  default     = false
}

variable "enable_private_nodes" {
  description = "Enable private nodes (no external IPs on node VMs). Required when org policy constraints/compute.vmExternalIpAccess is enforced. Nodes use Cloud NAT for egress. Independent of enable_nist_compliance."
  type        = bool
  default     = false
}

variable "enable_pod_security_standards" {
  description = "Enable Pod Security Standards in namespace"
  type        = bool
  default     = false
}

variable "pod_security_level" {
  description = "Pod Security Standard level (baseline or restricted)"
  type        = string
  default     = "baseline"
}

# ─── NIST Compliance Configuration ────────────────────────────────────────────

variable "authorized_networks" {
  description = "Master authorized networks (for NIST compliance)"
  type = list(object({
    cidr         = string
    display_name = string
  }))
  default = []
}

variable "kms_key_id" {
  description = "Cloud KMS key ID for CMEK encryption"
  type        = string
  default     = ""
}

# ─── Node Pool Configuration ──────────────────────────────────────────────────

variable "primary_node_pool_machine_type" {
  description = "Machine type for primary node pool"
  type        = string
  default     = "e2-standard-4"
}

variable "primary_node_pool_min_count" {
  description = "Minimum nodes in primary pool"
  type        = number
  default     = 1
}

variable "primary_node_pool_max_count" {
  description = "Maximum nodes in primary pool"
  type        = number
  default     = 5
}

variable "primary_node_pool_initial_count" {
  description = "Initial node count for primary pool"
  type        = number
  default     = 2
}

variable "primary_node_pool_disk_type" {
  description = "Disk type for primary nodes (pd-standard, pd-ssd)"
  type        = string
  default     = "pd-standard"
}

# ─── GPU Node Pool Configuration ──────────────────────────────────────────────

variable "enable_gpu_node_pool" {
  description = "Enable GPU node pool for vLLM inference"
  type        = bool
  default     = true
}

variable "gpu_type" {
  description = "GPU type (nvidia-l4, nvidia-t4, nvidia-a100-80gb)"
  type        = string
  default     = "nvidia-l4"
}

variable "gpu_count" {
  description = "Number of GPUs per node"
  type        = number
  default     = 1
}

variable "gpu_node_pool_machine_type" {
  description = "Machine type for GPU nodes"
  type        = string
  default     = "g2-standard-4"
}

variable "gpu_node_pool_min_count" {
  description = "Minimum GPU nodes"
  type        = number
  default     = 0
}

variable "gpu_node_pool_max_count" {
  description = "Maximum GPU nodes"
  type        = number
  default     = 2
}

variable "gpu_node_pool_initial_count" {
  description = "Initial GPU node count"
  type        = number
  default     = 1
}

variable "gpu_node_pool_spot" {
  description = "Use Spot VMs for the GPU node pool"
  type        = bool
  default     = true
}

variable "gpu_node_locations" {
  description = "List of zones to deploy the GPU node pool to. Enables multi-zonal/regional node configuration to source GPUs from other zones during Spot capacity shortages."
  type        = list(string)
  default     = ["us-central1-a", "us-central1-b", "us-central1-c"]
}

# ─── Storage Configuration ────────────────────────────────────────────────────
# Note: GCS with S3-compatible HMAC keys is used for Langfuse blob storage
# MinIO is not deployed in the GKE target

variable "storage_class" {
  description = "Storage class for persistent volumes (pd-standard or pd-ssd)"
  type        = string
  default     = "pd-standard"
}

variable "model_bucket_name" {
  description = "GCS bucket name for model weights"
  type        = string
  default     = "" # Defaults to ${project_id}-models if empty
}

# ─── Database Configuration ───────────────────────────────────────────────────

variable "postgres_storage_size" {
  description = "PostgreSQL PVC size"
  type        = string
  default     = "50Gi"
}

variable "redis_storage_size" {
  description = "Redis PVC size"
  type        = string
  default     = "10Gi"
}

variable "clickhouse_storage_size" {
  description = "ClickHouse PVC size (required for Langfuse v3)"
  type        = string
  default     = "20Gi"
}

# ─── NeMo Guardrails + Presidio Configuration ─────────────────────────────────

variable "enable_nemo_guardrails" {
  description = "Enable NVIDIA NeMo Guardrails + Microsoft Presidio deployment"
  type        = bool
  default     = true
}

variable "nemo_image" {
  description = "NeMo Guardrails container image (defaults to custom Cloud Build image)"
  type        = string
  default     = ""
}

variable "presidio_analyzer_image" {
  description = "Microsoft Presidio Analyzer container image"
  type        = string
  default     = "mcr.microsoft.com/presidio-analyzer:latest"
}

variable "presidio_anonymizer_image" {
  description = "Microsoft Presidio Anonymizer container image"
  type        = string
  default     = "mcr.microsoft.com/presidio-anonymizer:latest"
}

# ─── vLLM Configuration ───────────────────────────────────────────────────────

variable "enable_vllm" {
  description = "Enable vLLM inference deployment"
  type        = bool
  default     = false
}

variable "vllm_model_path" {
  description = "HuggingFace model ID or GCS path"
  type        = string
  default     = "meta-llama/Llama-3.2-3B-Instruct"
}

variable "vllm_image" {
  description = "vLLM container image (defaults to custom built vllm-streamer)"
  type        = string
  default     = ""
}

variable "vllm_gpu_count" {
  description = "Number of GPUs per vLLM pod"
  type        = number
  default     = 1
}

variable "vllm_replicas" {
  description = "Number of vLLM replicas"
  type        = number
  default     = 1
}

variable "vllm_cpu_limit" {
  description = "vLLM CPU limit"
  type        = string
  default     = "16000m"
}

variable "vllm_memory_limit" {
  description = "vLLM memory limit"
  type        = string
  default     = "64Gi"
}

variable "vllm_cpu_request" {
  description = "vLLM CPU request"
  type        = string
  default     = "3000m"
}

variable "vllm_memory_request" {
  description = "vLLM memory request"
  type        = string
  default     = "10Gi"
}

# ─── Langfuse Configuration ───────────────────────────────────────────────────

variable "langfuse_nextauth_url" {
  description = "Langfuse external URL"
  type        = string
  default     = "http://localhost:3000"
}

variable "langfuse_s3_endpoint" {
  # All gcp-gke regional tfvars (us-dev, eu-dev, eu-prod, apac-dev, apac-prod)
  # explicitly set this to "https://storage.googleapis.com". The empty-string
  # default previously caused LANGFUSE_S3_EVENT_UPLOAD_ENDPOINT to be omitted
  # entirely whenever a deployment was applied without a matching tfvars file
  # (e.g. a targeted `-target=module.langfuse` apply or manual `terraform apply`
  # without -var-file). With LANGFUSE_S3_EVENT_UPLOAD_REGION="auto" and no
  # explicit endpoint, the AWS SDK falls back to constructing
  # "s3.auto.amazonaws.com", which does not resolve (DNS ENOTFOUND) since the
  # backing bucket is GCS, not AWS S3. This broke trace ingestion entirely
  # (HTTP 500 on /api/public/ingestion; see test_langfuse_smoke.py).
  # Defaulting to the GCS interop endpoint here makes the gcp-gke target
  # correct out-of-the-box and self-healing against config drift.
  description = "S3-compatible endpoint for Langfuse blob storage (GCS interop endpoint for the gcp-gke target)"
  type        = string
  default     = "https://storage.googleapis.com"
}

variable "langfuse_s3_bucket" {
  description = "S3 bucket for Langfuse events (defaults to langfuse-events)"
  type        = string
  default     = ""
}

variable "langfuse_s3_access_key" {
  description = "S3 access key (defaults to MinIO credentials)"
  type        = string
  sensitive   = true
  default     = ""
}

variable "langfuse_s3_secret_key" {
  description = "S3 secret key (defaults to MinIO credentials)"
  type        = string
  sensitive   = true
  default     = ""
}

# ─── Compliance Bridge Configuration ──────────────────────────────────────────

variable "enable_compliance_bridge" {
  description = "Enable compliance bridge deployment"
  type        = bool
  default     = false
}

variable "compliance_bridge_image" {
  description = "Compliance bridge container image"
  type        = string
  default     = ""
}

# ─── OPA Configuration ────────────────────────────────────────────────────────

variable "opa_policy_files" {
  description = "OPA policy files (name -> content)"
  type        = map(string)
  default     = {}
}

# ─── Container Registry ───────────────────────────────────────────────────────

variable "registry_url" {
  description = "Container registry URL (e.g., gcr.io/PROJECT or us-central1-docker.pkg.dev/PROJECT/REPO)"
  type        = string
  default     = "" # Defaults to gcr.io/${project_id} if empty
}

# ─── GCP Features ─────────────────────────────────────────────────────────────

variable "enable_gcs_fuse_csi" {
  description = "Enable GCS Fuse CSI driver for model weight streaming"
  type        = bool
  default     = true
}

# ─── Deployment Control ───────────────────────────────────────────────────────

variable "force_redeploy" {
  description = "Force redeployment of application (ignores content hash)"
  type        = bool
  default     = false
}

# ─── Environment Variables from .env ──────────────────────────────────────────

variable "langfuse_public_key" {
  description = "Langfuse public API key (from LANGFUSE_PUBLIC_KEY)"
  type        = string
  sensitive   = true
  default     = ""
}

variable "langfuse_secret_key" {
  description = "Langfuse secret API key (from LANGFUSE_SECRET_KEY)"
  type        = string
  sensitive   = true
  default     = ""
}

variable "langfuse_compliance_public_key" {
  description = "Langfuse compliance project public key (from LANGFUSE_COMPLIANCE_PUBLIC_KEY). REQUIRED when enable_nist_compliance=true. Leaving this empty when enable_nist_compliance=true defeats the AU-9 dual-project telemetry isolation architecture (POAM-019)."
  type        = string
  sensitive   = true
  nullable    = false
  default     = ""

  validation {
    # POAM-019: Prevent silent collapse of dual-project telemetry isolation.
    # When enable_nist_compliance=true this key MUST be a distinct cage-compliance
    # project key.  An empty value silently falls back to the app project,
    # defeating AU-9 evidentiary independence.
    # NOTE: Terraform validates variables in isolation — we cannot reference
    # var.enable_nist_compliance here. The precondition in main.tf enforces
    # the cross-variable constraint at plan time.
    condition     = var.langfuse_compliance_public_key == "" || length(var.langfuse_compliance_public_key) >= 10
    error_message = "langfuse_compliance_public_key must be a valid Langfuse API key (≥10 chars) or empty string. An empty value is only valid when enable_nist_compliance=false. (POAM-019)"
  }
}

variable "langfuse_compliance_secret_key" {
  description = "Langfuse compliance project secret key (from LANGFUSE_COMPLIANCE_SECRET_KEY). REQUIRED when enable_nist_compliance=true. Leaving this empty when enable_nist_compliance=true defeats the AU-9 dual-project telemetry isolation architecture (POAM-019)."
  type        = string
  sensitive   = true
  nullable    = false
  default     = ""

  validation {
    # POAM-019: Same constraint as langfuse_compliance_public_key.
    condition     = var.langfuse_compliance_secret_key == "" || length(var.langfuse_compliance_secret_key) >= 10
    error_message = "langfuse_compliance_secret_key must be a valid Langfuse API key (≥10 chars) or empty string. An empty value is only valid when enable_nist_compliance=false. (POAM-019)"
  }
}

variable "langfuse_host" {
  description = "Langfuse host URL (from LANGFUSE_HOST)"
  type        = string
  default     = ""
}



variable "model_reasoning" {
  description = "Reasoning model path (from MODEL_REASONING)"
  type        = string
  default     = "deepseek-ai/DeepSeek-R1-Distill-Llama-8B"
}

variable "model_fast" {
  description = "Fast model path (from MODEL_FAST)"
  type        = string
  default     = "Qwen/Qwen2.5-1.5B-Instruct"
}

variable "model_consensus" {
  description = "Consensus model path (from MODEL_CONSENSUS)"
  type        = string
  default     = "deepseek-ai/DeepSeek-R1-Distill-Llama-8B"
}

variable "governance_salt" {
  description = "HMAC salt for governance signatures (from GOVERNANCE_SALT)"
  type        = string
  sensitive   = true
  default     = ""
}

variable "kms_governance_key" {
  description = "Full Cloud KMS key version resource name for CTRL_KMS_001 asymmetric governance signing (from KMS_GOVERNANCE_KEY). Empty string falls back to legacy HMAC-SHA256 signing via governance_salt — acceptable only in dev/CI postures."
  type        = string
  default     = ""
}

variable "cage_kms_provider" {
  description = "Cloud KMS provider backend for governance signing (from CAGE_KMS_PROVIDER): gcp, aws, or azure."
  type        = string
  default     = "gcp"
}

# DEP-21: Remove default = "" from routing_seal_secret.
# A missing or empty value previously caused terraform apply to silently write
# an empty string into advisor-secrets.CAGE_ROUTING_SEAL_SECRET, triggering
# RuntimeError: CAGE STARTUP FAILURE in the gateway on every apply that ran
# without a populated terraform.auto.tfvars. Removing the default forces a
# Terraform plan error rather than a silent runtime failure.
# The value must always be supplied via terraform.auto.tfvars (gitignored).
variable "routing_seal_secret" {
  description = "Gateway routing seal secret (from CAGE_ROUTING_SEAL_SECRET). No default — must be supplied via terraform.auto.tfvars (gitignored). Omitting this causes a Terraform plan error rather than silently writing an empty secret that crashes the gateway."
  type        = string
  sensitive   = true
}

# K-4: otel_exporter_otlp_headers — Langfuse OTLP Basic-auth header.
# Format: "Authorization=Basic <base64(publicKey:secretKey)>"
# If left empty the root module derives it from langfuse_public_key /
# langfuse_secret_key (see module.gateway and module.governed_advisor calls).
# Set an explicit override in terraform.auto.tfvars (gitignored) for prod.
variable "otel_exporter_otlp_headers" {
  description = "OTLP Authorization header for Langfuse trace ingestion (Authorization=Basic <b64>). If empty, derived from langfuse_public_key/langfuse_secret_key."
  type        = string
  sensitive   = true
  default     = ""
}

variable "hf_token" {
  description = "Hugging Face Hub token (from HUGGING_FACE_HUB_TOKEN)"
  type        = string
  sensitive   = true
  default     = ""
}

variable "aws_access_key" {
  description = "AWS/S3 access key ID (from AWS_ACCESS_KEY_ID)"
  type        = string
  sensitive   = true
  default     = ""
}

variable "aws_secret_key" {
  description = "AWS/S3 secret access key (from AWS_SECRET_ACCESS_KEY)"
  type        = string
  sensitive   = true
  default     = ""
}

variable "storage_backend" {
  description = "Storage backend type: s3, gcs, or local (from STORAGE_BACKEND)"
  type        = string
  default     = "gcs"
}

variable "cold_tier_bucket" {
  description = "Cold tier storage bucket name (from COLD_TIER_BUCKET)"
  type        = string
  default     = "cage-cold-tier"
}

variable "vllm_reasoning_url" {
  description = "vLLM reasoning API base URL (from VLLM_REASONING_API_BASE)"
  type        = string
  default     = ""
}

variable "vllm_fast_url" {
  description = "vLLM fast API base URL (from VLLM_FAST_API_BASE)"
  type        = string
  default     = ""
}

variable "vllm_gateway_url" {
  description = "vLLM gateway URL (from VLLM_GATEWAY_URL)"
  type        = string
  default     = ""
}

variable "opa_url" {
  description = "OPA policy engine URL (from OPA_URL)"
  type        = string
  default     = ""
}

variable "redis_url" {
  description = "Redis connection URL (from REDIS_URL)"
  type        = string
  default     = ""
}
variable "master_ipv4_cidr_block" { default = "172.16.0.0/28" }
variable "pod_cidr" { default = "10.100.0.0/14" }
variable "service_cidr" { default = "10.104.0.0/20" }

# DEP-09: Remove the "US_FED" default from cage_deployment_region.
# A missing or misconfigured value previously silently applied US_FED compliance
# posture to EU_ECB and APAC_MAS deployments. Operators must now explicitly set
# this variable via a jurisdiction-specific tfvars file. The validation block
# cross-checks the declared region against the GCP region prefix to catch
# mismatches at plan time rather than at runtime.
# R-7: deployment scripts must propagate CAGE_DEPLOYMENT_REGION explicitly.
variable "cage_deployment_region" {
  description = "CAGE deployment region compliance profile. Must be one of: US_FED, EU_ECB, APAC_MAS. No default — must be set explicitly in a jurisdiction-specific tfvars file (prod.tfvars, eu-prod.tfvars, apac-prod.tfvars)."
  type        = string

  validation {
    condition     = contains(["US_FED", "EU_ECB", "APAC_MAS"], var.cage_deployment_region)
    error_message = "cage_deployment_region must be one of: US_FED, EU_ECB, APAC_MAS. Set this explicitly in your jurisdiction-specific tfvars file."
  }
}
