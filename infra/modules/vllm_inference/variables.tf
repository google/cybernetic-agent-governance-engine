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

variable "namespace" {
  description = "Kubernetes namespace to deploy vLLM"
  type        = string
}

variable "deployment_name" {
  description = "Name of the deployment"
  type        = string
  default     = "vllm-inference"
}

variable "service_name" {
  description = "Name of the service"
  type        = string
  default     = "vllm-service"
}

variable "image" {
  description = "vLLM container image"
  type        = string
  default     = "vllm/vllm-openai:latest"
}

variable "image_pull_policy" {
  description = "Image pull policy"
  type        = string
  default     = "IfNotPresent"
}

variable "replicas" {
  description = "Number of replicas"
  type        = number
  default     = 1
}

variable "service_account_name" {
  description = "Kubernetes service account name"
  type        = string
  default     = "default"
}

# GPU Configuration
variable "gpu_count" {
  description = "Number of GPUs per pod"
  type        = number
  default     = 1
}

variable "gpu_product" {
  description = "GPU product type (e.g., NVIDIA-L4, NVIDIA-T4, NVIDIA-A100)"
  type        = string
  default     = ""
}

# Resource Limits
variable "memory_limit" {
  description = "Memory limit"
  type        = string
  default     = "64Gi"
}

variable "cpu_limit" {
  description = "CPU limit"
  type        = string
  default     = "16000m"
}

variable "memory_request" {
  description = "Memory request"
  type        = string
  default     = "10Gi"
}

variable "cpu_request" {
  description = "CPU request"
  type        = string
  default     = "3000m"
}

variable "shared_memory_size" {
  description = "Shared memory size for /dev/shm"
  type        = string
  default     = "16Gi"
}

# Model Configuration
variable "model_path" {
  description = "Path to the model (HuggingFace ID or local path)"
  type        = string
  default     = "meta-llama/Llama-3.2-3B-Instruct"
}

variable "vllm_load_format" {
  description = "vLLM load format (auto, safetensors, pt, etc.)"
  type        = string
  default     = "auto"
}

variable "enable_model_volume" {
  description = "Enable model volume mount"
  type        = bool
  default     = false
}

variable "model_pvc_name" {
  description = "PVC name for model storage"
  type        = string
  default     = "model-storage"
}

# vLLM Command
variable "vllm_command" {
  description = "vLLM startup command"
  type        = string
  default     = "python3 -m vllm.entrypoints.openai.api_server --model $MODEL_PATH --host 0.0.0.0 --port 8000"
}

# Environment Variables
variable "env_vars" {
  description = "Additional environment variables"
  type        = map(string)
  default     = {}
}

# S3/MinIO Configuration
variable "enable_s3_credentials" {
  description = "Enable S3/MinIO credentials"
  type        = bool
  default     = false
}

variable "s3_endpoint_url" {
  description = "S3 endpoint URL"
  type        = string
  default     = ""
}

variable "s3_credentials_secret" {
  description = "Kubernetes Secret name for S3 credentials"
  type        = string
  default     = "minio-credentials"
}

# Service Configuration
variable "service_type" {
  description = "Kubernetes service type"
  type        = string
  default     = "ClusterIP"
}

# Pod Disruption Budget
variable "enable_pdb" {
  description = "Enable Pod Disruption Budget"
  type        = bool
  default     = false
}

variable "pdb_min_available" {
  description = "Minimum available pods for PDB"
  type        = number
  default     = 1
}

# Scheduling
variable "enable_pod_anti_affinity" {
  description = "Enable pod anti-affinity for GPU distribution"
  type        = bool
  default     = true
}

variable "node_selector" {
  description = "Node selector for GPU nodes"
  type        = map(string)
  default     = {}
}

variable "tolerations" {
  description = "Tolerations for GPU nodes"
  type = list(object({
    key      = string
    operator = string
    value    = optional(string)
    effect   = string
  }))
  default = [
    {
      key      = "nvidia.com/gpu"
      operator = "Equal"
      value    = "present"
      effect   = "NoSchedule"
    }
  ]
}

# Health Checks
variable "readiness_initial_delay" {
  description = "Readiness probe initial delay (seconds)"
  type        = number
  default     = 120
}

variable "liveness_initial_delay" {
  description = "Liveness probe initial delay (seconds)"
  type        = number
  default     = 600
}
