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
  description = "Kubernetes namespace to deploy NeMo Guardrails + Presidio"
  type        = string
}

variable "deployment_name" {
  description = "Name of the NeMo Guardrails deployment"
  type        = string
  default     = "nemo-guardrails"
}

variable "service_name" {
  description = "Name of the NeMo Guardrails ClusterIP service"
  type        = string
  default     = "nemo-guardrails"
}

variable "replicas" {
  description = "Number of pod replicas"
  type        = number
  default     = 1
}

variable "image_pull_policy" {
  description = "Image pull policy for all containers in the pod"
  type        = string
  default     = "IfNotPresent"
}

# ─── NeMo Guardrails ──────────────────────────────────────────────────────────

variable "nemo_image" {
  description = "NVIDIA NeMo Guardrails server container image"
  type        = string
  default     = "nvcr.io/nvidia/nemo:24.05"
}

variable "nemo_config_yaml" {
  description = "Raw Colang/YAML config for NeMo Guardrails (overrides built-in default)"
  type        = string
  default     = ""
}

variable "nemo_cpu_request" {
  description = "CPU request for the NeMo container"
  type        = string
  default     = "500m"
}

variable "nemo_memory_request" {
  description = "Memory request for the NeMo container"
  type        = string
  default     = "1Gi"
}

variable "nemo_cpu_limit" {
  description = "CPU limit for the NeMo container (empty string = no limit)"
  type        = string
  default     = "2000m"
}

variable "nemo_memory_limit" {
  description = "Memory limit for the NeMo container"
  type        = string
  default     = "4Gi"
}

# ─── LLM Backend for NeMo ─────────────────────────────────────────────────────

variable "llm_api_base" {
  description = "OpenAI-compatible API base URL used by NeMo rails (typically vLLM fast service)"
  type        = string
  default     = "http://vllm-service.governance-stack.svc.cluster.local:8000/v1"
}

variable "llm_api_key" {
  description = "API key for the LLM backend (vLLM accepts any non-empty string)"
  type        = string
  sensitive   = true
  default     = "EMPTY"
}

variable "llm_model_name" {
  description = "Logical model name sent to the LLM backend by NeMo"
  type        = string
  default     = "Qwen/Qwen2.5-7B-Instruct"
}

# ─── Microsoft Presidio ───────────────────────────────────────────────────────

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

variable "presidio_recognizers" {
  description = "Comma-separated list of Presidio entity recognizers to enable"
  type        = string
  default     = "PERSON,EMAIL_ADDRESS,PHONE_NUMBER,CREDIT_CARD,IBAN_CODE,US_SSN,US_PASSPORT,US_DRIVER_LICENSE,US_BANK_NUMBER,IP_ADDRESS,CRYPTO,DATE_TIME,NRP,LOCATION,MEDICAL_LICENSE,URL"
}

variable "presidio_cpu_request" {
  description = "CPU request for each Presidio container"
  type        = string
  default     = "200m"
}

variable "presidio_memory_request" {
  description = "Memory request for each Presidio container"
  type        = string
  default     = "512Mi"
}

variable "presidio_cpu_limit" {
  description = "CPU limit for each Presidio container (empty string = no limit)"
  type        = string
  default     = "1000m"
}

variable "presidio_memory_limit" {
  description = "Memory limit for each Presidio container"
  type        = string
  default     = "2Gi"
}

# ─── Security & Scheduling ────────────────────────────────────────────────────

variable "enable_security_context" {
  description = "Enable non-root security context on all containers"
  type        = bool
  default     = false
}

variable "enable_pdb" {
  description = "Enable Pod Disruption Budget (for HA / maintenance windows)"
  type        = bool
  default     = false
}

variable "node_selector" {
  description = "Node selector labels for pod placement"
  type        = map(string)
  default     = {}
}

variable "tolerations" {
  description = "Toleration rules for pod scheduling"
  type        = list(map(string))
  default     = []
}
