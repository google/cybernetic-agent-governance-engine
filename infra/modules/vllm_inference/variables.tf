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
  default     = "vllm/vllm-openai:v0.7.3@sha256:4f4037303e8c7b69439db1077bb849a0823517c0f785b894dc8e96d58ef3a0c2"
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

# Resource Limits (sized for g2-standard-8: 8 vCPU / 7910m allocatable, 32 GB RAM / ~28.25Gi allocatable)
variable "memory_limit" {
  description = "Memory limit on g2-standard-8 (32 GB RAM / 28928Mi GKE allocatable)"
  type        = string
  default     = "24Gi"

  validation {
    condition = (
      can(regex("^[0-9]+(Mi|Gi)$", var.memory_limit)) &&
      (
        endswith(var.memory_limit, "Gi")
        ? tonumber(trimsuffix(var.memory_limit, "Gi")) * 1024
        : tonumber(trimsuffix(var.memory_limit, "Mi"))
      ) > 0 &&
      (
        endswith(var.memory_limit, "Gi")
        ? tonumber(trimsuffix(var.memory_limit, "Gi")) * 1024
        : tonumber(trimsuffix(var.memory_limit, "Mi"))
      ) <= 28928
    )
    error_message = "memory_limit must be a valid Mi/Gi quantity (e.g. '24Gi') and must not exceed g2-standard-8 GKE allocatable memory (28928Mi / ~28.25Gi)."
  }
}

variable "cpu_limit" {
  description = "CPU limit on g2-standard-8 (8 vCPU / 7910m GKE allocatable)"
  type        = string
  default     = "6000m"

  validation {
    condition = (
      can(regex("^[0-9]+(\\.[0-9]+)?m?$", var.cpu_limit)) &&
      (
        endswith(var.cpu_limit, "m")
        ? tonumber(trimsuffix(var.cpu_limit, "m"))
        : tonumber(var.cpu_limit) * 1000
      ) > 0 &&
      (
        endswith(var.cpu_limit, "m")
        ? tonumber(trimsuffix(var.cpu_limit, "m"))
        : tonumber(var.cpu_limit) * 1000
      ) <= 7910
    )
    error_message = "cpu_limit must be a valid CPU quantity (e.g. '6000m' or '6') and must not exceed g2-standard-8 GKE allocatable CPU (7910m)."
  }
}

variable "memory_request" {
  description = "Memory request on g2-standard-8 (32 GB RAM / 28928Mi GKE allocatable)"
  type        = string
  default     = "10Gi"

  validation {
    condition = (
      can(regex("^[0-9]+(Mi|Gi)$", var.memory_request)) &&
      (
        endswith(var.memory_request, "Gi")
        ? tonumber(trimsuffix(var.memory_request, "Gi")) * 1024
        : tonumber(trimsuffix(var.memory_request, "Mi"))
      ) > 0 &&
      (
        endswith(var.memory_request, "Gi")
        ? tonumber(trimsuffix(var.memory_request, "Gi")) * 1024
        : tonumber(trimsuffix(var.memory_request, "Mi"))
      ) <= 28928
    )
    error_message = "memory_request must be a valid Mi/Gi quantity (e.g. '10Gi') and must not exceed g2-standard-8 GKE allocatable memory (28928Mi / ~28.25Gi)."
  }
}

variable "cpu_request" {
  description = "CPU request on g2-standard-8 (8 vCPU / 7910m GKE allocatable)"
  type        = string
  default     = "3000m"

  validation {
    condition = (
      can(regex("^[0-9]+(\\.[0-9]+)?m?$", var.cpu_request)) &&
      (
        endswith(var.cpu_request, "m")
        ? tonumber(trimsuffix(var.cpu_request, "m"))
        : tonumber(var.cpu_request) * 1000
      ) > 0 &&
      (
        endswith(var.cpu_request, "m")
        ? tonumber(trimsuffix(var.cpu_request, "m"))
        : tonumber(var.cpu_request) * 1000
      ) <= 7910
    )
    error_message = "cpu_request must be a valid CPU quantity (e.g. '3000m' or '3') and must not exceed g2-standard-8 GKE allocatable CPU (7910m)."
  }
}

variable "shared_memory_size" {
  description = "Shared memory size for /dev/shm on g2-standard-8 (32 GB RAM / 28928Mi GKE allocatable)"
  type        = string
  default     = "2Gi"

  validation {
    condition = (
      can(regex("^[0-9]+(Mi|Gi)$", var.shared_memory_size)) &&
      (
        endswith(var.shared_memory_size, "Gi")
        ? tonumber(trimsuffix(var.shared_memory_size, "Gi")) * 1024
        : tonumber(trimsuffix(var.shared_memory_size, "Mi"))
      ) > 0 &&
      (
        endswith(var.shared_memory_size, "Gi")
        ? tonumber(trimsuffix(var.shared_memory_size, "Gi")) * 1024
        : tonumber(trimsuffix(var.shared_memory_size, "Mi"))
      ) <= 28928
    )
    error_message = "shared_memory_size must be a valid Mi/Gi quantity (e.g. '2Gi') and must not exceed g2-standard-8 GKE allocatable memory (28928Mi / ~28.25Gi)."
  }
}

# Model Configuration
variable "model_path" {
  description = "Path to the model (must be a GCS gs:// URI in the model bucket)"
  type        = string
  default     = "gs://cage-models/Qwen/Qwen2.5-1.5B-Instruct"

  validation {
    condition     = can(regex("^gs://[a-z0-9][a-z0-9_.-]{1,61}[a-z0-9]/", var.model_path))
    error_message = "model_path must be a valid GCS URI starting with 'gs://<bucket>/' to prevent pulling unvetted models from Hugging Face or public repositories."
  }
}

variable "served_model_name" {
  description = "Model ID advertised by the vLLM OpenAI-compatible API (--served-model-name). Defaults to model_path when empty."
  type        = string
  default     = ""
}

variable "vllm_load_format" {
  description = "vLLM load format (runai_streamer, auto, safetensors, pt, etc.)"
  type        = string
  default     = "runai_streamer"
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
  default     = "python3 -m vllm.entrypoints.openai.api_server --model $MODEL_PATH --served-model-name $SERVED_MODEL_NAME --load-format $VLLM_LOAD_FORMAT --host 0.0.0.0 --port 8000"
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
