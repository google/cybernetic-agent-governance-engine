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
  description = "GCP Project ID"
  type        = string
}

variable "organization_id" {
  description = "GCP Organization ID used to construct the GEAP Agent Identity (ID-2) principal URI"
  type        = string
  default     = "cage-sovereign"
}

variable "region" {
  description = "GCP sovereign region for GEAP Agent Runtime and Vertex AI Sessions/Memory Bank (DEP-10)"
  type        = string
}

variable "agent_id" {
  description = "Canonical GEAP Agent Runtime identifier"
  type        = string
  default     = "governed-financial-advisor"
}

variable "image" {
  description = "Container image URI (pinned by @sha256 digest) for the Governed Financial Advisor"
  type        = string
}

variable "vpc_network" {
  description = "VPC network self-link or name for Direct VPC Egress (SC-7)"
  type        = string
}

variable "vpc_subnetwork" {
  description = "VPC subnetwork self-link or name for Direct VPC Egress (SC-7)"
  type        = string
}

variable "kms_key_name" {
  description = "Regional CMEK CryptoKey resource ID for encrypting Vertex AI Sessions and Memory Bank at rest"
  type        = string
  default     = ""
}

variable "enable_logging" {
  description = "Enable structured logging"
  type        = string
  default     = "true"
}

variable "redis_host" {
  description = "Memorystore App instance primary IP address"
  type        = string
}

variable "redis_port" {
  description = "Memorystore App instance port"
  type        = string
  default     = "6379"
}

variable "model_fast" {
  description = "Fast model name routed via CAGE Gateway"
  type        = string
}

variable "model_reasoning" {
  description = "Reasoning model name routed via CAGE Gateway"
  type        = string
}

variable "model_consensus" {
  description = "Consensus model name routed via CAGE Gateway"
  type        = string
}

variable "vllm_base_url" {
  description = "Internal vLLM service URL"
  type        = string
}

variable "vllm_fast_api_base" {
  description = "Internal vLLM fast pool URL"
  type        = string
}

variable "vllm_reasoning_api_base" {
  description = "Internal vLLM reasoning pool URL"
  type        = string
}

variable "opa_url" {
  description = "Internal OPA service URL"
  type        = string
}

variable "langfuse_host" {
  description = "Internal regional Langfuse web service URL (DEP-10)"
  type        = string
}

variable "gateway_url" {
  description = "Internal GKE CAGE Hybrid Gateway URL"
  type        = string
}

variable "cage_env" {
  description = "CAGE runtime environment posture (dev | staging | prod)"
  type        = string
  default     = "prod"
}

variable "otel_exporter_otlp_headers" {
  description = "W3C OTLP Authorization header for Langfuse trace ingestion"
  type        = string
  default     = ""
  sensitive   = true
}

variable "psc_network_attachment" {
  description = "Private Service Connect Interface (PSC-I) network attachment URI for private egress into GKE VPC (scale/runtime/deploy-an-agent)"
  type        = string
  default     = ""
}

variable "dns_peering_configs" {
  description = "Private Cloud DNS peering configurations for resolving internal GKE and Memorystore FQDNs over PSC-I"
  type = list(object({
    domain         = string
    target_project = string
    target_network = string
  }))
  default = []
}

variable "min_instances" {
  description = "Minimum warm GEAP Agent Runtime instances ([0, 10], default 1 per GEAP spec)"
  type        = number
  default     = 1
}

variable "max_instances" {
  description = "Maximum GEAP Agent Runtime instances ([1, 100] when VPC-SC or PSC-I is enabled per GEAP spec)"
  type        = number
  default     = 100
}

variable "cpu_limit" {
  description = "CPU cores allocated per GEAP Agent Runtime container instance ('1', '2', '4', '6', or '8')"
  type        = string
  default     = "4"
}

variable "memory_limit" {
  description = "Memory allocated per GEAP Agent Runtime container instance (e.g., '4Gi', '8Gi', '16Gi')"
  type        = string
  default     = "8Gi"
}

variable "container_concurrency" {
  description = "Maximum concurrent requests per GEAP container instance (recommended 2 * cpu + 1 = 9)"
  type        = number
  default     = 9
}

