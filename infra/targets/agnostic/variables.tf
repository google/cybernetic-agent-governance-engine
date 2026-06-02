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

variable "kubeconfig_path" {
  description = "Path to kubeconfig file"
  type        = string
  default     = "~/.kube/config"
}

variable "kubeconfig_context" {
  description = "Kubernetes context to use (empty = current context)"
  type        = string
  default     = ""
}

# ─── Environment Configuration ────────────────────────────────────────────────

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
  description = "Kubernetes namespace for all governance stack resources"
  type        = string
  default     = "governance-stack"
}

# ─── Storage Configuration ────────────────────────────────────────────────────

variable "storage_class" {
  description = "Storage class for PVCs (local-path for k3s, gp2 for EKS, default for AKS)"
  type        = string
  default     = "standard"
}

variable "minio_storage_size" {
  description = "MinIO PVC size"
  type        = string
  default     = "50Gi"
}

variable "minio_root_user" {
  description = "MinIO root username"
  type        = string
  default     = "minio-admin"
}

variable "minio_root_password" {
  description = "MinIO root password (auto-generated if empty)"
  type        = string
  sensitive   = true
  default     = ""
}

variable "model_bucket_name" {
  description = "S3/MinIO bucket name for model weights"
  type        = string
  default     = "vllm-models"
}

# ─── PostgreSQL Configuration ─────────────────────────────────────────────────

variable "postgres_storage_size" {
  description = "PostgreSQL PVC size"
  type        = string
  default     = "50Gi"
}

# ─── Redis Configuration ──────────────────────────────────────────────────────

variable "redis_storage_size" {
  description = "Redis PVC size"
  type        = string
  default     = "10Gi"
}

# ─── vLLM Configuration ───────────────────────────────────────────────────────

variable "enable_vllm" {
  description = "Enable vLLM inference deployment"
  type        = bool
  default     = false
}

variable "vllm_model_path" {
  description = "HuggingFace model ID or local path"
  type        = string
  default     = "meta-llama/Llama-3.2-3B-Instruct"
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

variable "vllm_node_selector" {
  description = "Node selector for vLLM pods"
  type        = map(string)
  default     = {}
}

variable "vllm_tolerations" {
  description = "Tolerations for vLLM pods"
  type = list(object({
    key      = string
    operator = string
    value    = optional(string)
    effect   = string
  }))
  default = [{
    key      = "nvidia.com/gpu"
    operator = "Equal"
    value    = "present"
    effect   = "NoSchedule"
  }]
}

# ─── Langfuse Configuration ───────────────────────────────────────────────────

variable "langfuse_nextauth_url" {
  description = "Langfuse external URL"
  type        = string
  default     = "http://localhost:3000"
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

# ─── Container Registry ──────────────────────────────────────────────────────

variable "registry_url" {
  description = "Container registry URL (e.g., ghcr.io/your-org/cage)"
  type        = string
  default     = "ghcr.io/your-org/cybernetic-governance-engine"
}

variable "registry_server" {
  description = "Registry server hostname (e.g., ghcr.io)"
  type        = string
  default     = "ghcr.io"
}

variable "registry_username" {
  description = "Registry username (leave empty for public registries)"
  type        = string
  default     = ""
}

variable "registry_password" {
  description = "Registry password/token"
  type        = string
  sensitive   = true
  default     = ""
}

# ─── Security Configuration ───────────────────────────────────────────────────

variable "enable_pod_security_standards" {
  description = "Enable Pod Security Standards (PSS)"
  type        = bool
  default     = false
}

variable "pod_security_level" {
  description = "Pod Security Standard level (privileged, baseline, restricted)"
  type        = string
  default     = "baseline"
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
  default     = "s3"
}

variable "cold_tier_bucket" {
  description = "Cold tier storage bucket name (from COLD_TIER_BUCKET)"
  type        = string
  default     = "cage-cold-tier"
}

variable "minio_endpoint" {
  description = "MinIO/S3 endpoint URL (from S3_ENDPOINT_URL)"
  type        = string
  default     = ""
}

variable "minio_bucket" {
  description = "MinIO/S3 bucket name (from S3_BUCKET_NAME)"
  type        = string
  default     = "cage-artifacts"
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
