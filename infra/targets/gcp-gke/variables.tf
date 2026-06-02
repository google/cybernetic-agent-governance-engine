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

variable "region" {
  description = "GCP region"
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "GCP zone for zonal cluster"
  type        = string
  default     = "us-central1-a"
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
  description = "Enable NIST RMF security controls (SC-7, AC-3, deletion protection)"
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

variable "gpu_node_pool_name" {
  description = "Name of the GPU node pool — used as cloud.google.com/gke-nodepool nodeSelector so the cluster autoscaler can match it at scale-from-zero time (nvidia.com/gpu.product is only applied post-startup by the device plugin)"
  type        = string
  default     = "gpu-node-pool-nvidia-tesla-t4"
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
  description = "S3 endpoint for Langfuse blob storage (defaults to MinIO)"
  type        = string
  default     = ""
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
  description = "Langfuse compliance project public key (from LANGFUSE_COMPLIANCE_PUBLIC_KEY)"
  type        = string
  sensitive   = true
  default     = ""
}

variable "langfuse_compliance_secret_key" {
  description = "Langfuse compliance project secret key (from LANGFUSE_COMPLIANCE_SECRET_KEY)"
  type        = string
  sensitive   = true
  default     = ""
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

variable "routing_seal_secret" {
  description = "Gateway routing seal secret (from CAGE_ROUTING_SEAL_SECRET)"
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

variable "cage_deployment_region" {
  description = "CAGE deployment region compliance profile (US_FED, EU_ECB, APAC_MAS)"
  type        = string
  default     = "US_FED"
}
