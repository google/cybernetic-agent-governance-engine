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

# ─── Project Configuration ────────────────────────────────────────────────────

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

variable "environment" {
  description = "Environment (dev, staging, prod)"
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

# DEP-09: Remove the "US_FED" default from cage_deployment_region.
# A missing or misconfigured value previously silently applied US_FED compliance
# posture to EU_ECB and APAC_MAS deployments. Operators must now explicitly set
# this variable via a jurisdiction-specific tfvars file.
variable "cage_deployment_region" {
  description = "CAGE deployment region compliance profile. Must be one of: US_FED, EU_ECB, APAC_MAS. No default — must be set explicitly in a jurisdiction-specific tfvars file (prod.tfvars, eu-prod.tfvars, apac-prod.tfvars)."
  type        = string

  validation {
    condition     = contains(["US_FED", "EU_ECB", "APAC_MAS"], var.cage_deployment_region)
    error_message = "cage_deployment_region must be one of: US_FED, EU_ECB, APAC_MAS. Set this explicitly in your jurisdiction-specific tfvars file."
  }
}

# ─── Container Images ─────────────────────────────────────────────────────────

variable "gateway_image" {
  description = "Gateway service container image URL"
  type        = string
  default     = ""
}

variable "opa_sidecar_image" {
  description = "OPA sidecar container image"
  type        = string
  default     = ""
}

variable "governed_advisor_image" {
  description = "Governed Financial Advisor container image URL"
  type        = string
  default     = ""
}

variable "agentsight_ui_image" {
  description = "AgentSight UI container image URL"
  type        = string
  default     = ""
}

variable "compliance_bridge_image" {
  description = "Compliance Bridge container image URL"
  type        = string
  default     = ""
}

variable "langfuse_web_image" {
  description = "Langfuse Web container image URL"
  type        = string
  default     = "langfuse/langfuse:latest"
}

variable "langfuse_worker_image" {
  description = "Langfuse Worker container image URL"
  type        = string
  default     = "langfuse/langfuse-worker:latest"
}

# ─── Feature Toggles ──────────────────────────────────────────────────────────

variable "enable_high_availability" {
  description = "Enable high availability: multi-region Redis replica, Cloud SQL HA failover, min instance count ≥ 2 for all services. Independent of security compliance flags. Set true for production workloads requiring fault tolerance; false for dev/staging cost optimization."
  type        = bool
  default     = false
}

variable "enable_nist_compliance" {
  description = "Enable NIST SP 800-53 RMF security controls (SC-7, AC-3, VPC Service Controls). US_FED only — do not set for EU_ECB or APAC_MAS deployments."
  type        = bool
  default     = false
}

variable "enable_load_balancer" {
  description = "Enable external HTTPS load balancer + Cloud Armor WAF. When enabled, gateway ingress is restricted to INTERNAL_AND_CLOUD_LOAD_BALANCING. When disabled (default), gateway accepts all traffic."
  type        = bool
  default     = false
}

variable "gateway_domain" {
  description = "Custom domain for gateway managed SSL certificate (e.g., gateway.example.com). Leave empty to skip SSL certificate provisioning."
  type        = string
  default     = ""
}

variable "enable_cloud_dns" {
  description = "Enable DNS record creation in an existing Cloud DNS managed zone"
  type        = bool
  default     = false
}

variable "dns_zone_name" {
  description = "The name of your existing Cloud DNS managed zone (e.g., my-company-zone). Zone must exist prior to apply."
  type        = string
  default     = ""
}

variable "enable_iap" {
  description = "Enable Identity-Aware Proxy for additional authentication layer. Requires OAuth2 client configuration."
  type        = bool
  default     = false
}

variable "iap_client_id" {
  description = "IAP OAuth2 client ID. Required when enable_iap=true."
  type        = string
  sensitive   = true
  default     = ""
}

variable "iap_client_secret" {
  description = "IAP OAuth2 client secret. Required when enable_iap=true."
  type        = string
  sensitive   = true
  default     = ""
}

variable "enable_vllm_gpu" {
  description = "Enable vLLM GPU inference deployment (future phase — reserved for sidecar vLLM integration)"
  type        = bool
  default     = false
}

variable "enable_nemo_guardrails" {
  description = "Enable NVIDIA NeMo Guardrails deployment (future phase — reserved for sidecar NeMo integration)"
  type        = bool
  default     = false
}

# ─── Networking Configuration ─────────────────────────────────────────────────

variable "vpc_cidr" {
  description = "VPC CIDR block"
  type        = string
  default     = "10.0.0.0/16"
}

variable "subnet_cidr" {
  description = "Subnet CIDR block"
  type        = string
  default     = "10.0.1.0/24"
}

# ─── Database Configuration ───────────────────────────────────────────────────

variable "postgres_tier" {
  description = "Cloud SQL PostgreSQL machine tier"
  type        = string
  default     = "db-f1-micro"
}

variable "postgres_disk_size" {
  description = "Cloud SQL PostgreSQL disk size in GB"
  type        = number
  default     = 10
}

variable "redis_tier" {
  description = "Cloud Memorystore Redis tier (BASIC or STANDARD_HA)"
  type        = string
  default     = "BASIC"

  validation {
    condition     = contains(["BASIC", "STANDARD_HA"], var.redis_tier)
    error_message = "redis_tier must be BASIC or STANDARD_HA."
  }
}

variable "redis_memory_size_gb" {
  description = "Cloud Memorystore Redis memory size in GB"
  type        = number
  default     = 1
}

# ─── Storage Configuration ────────────────────────────────────────────────────

variable "traces_bucket_name" {
  description = "GCS bucket name for Langfuse traces (defaults to {project_id}-langfuse-traces)"
  type        = string
  default     = ""
}

variable "artifacts_bucket_name" {
  description = "GCS bucket name for compliance artifacts (defaults to {project_id}-compliance-artifacts)"
  type        = string
  default     = ""
}

# ─── Secrets Configuration ────────────────────────────────────────────────────

variable "routing_seal_secret" {
  description = "Gateway routing seal secret (from CAGE_ROUTING_SEAL_SECRET). No default — must be supplied via terraform.auto.tfvars (gitignored). Omitting this causes a Terraform plan error rather than silently writing an empty secret that crashes the gateway."
  type        = string
  sensitive   = true
}

variable "routing_seal_salt" {
  description = "Gateway routing seal salt (from CAGE_ROUTING_SEAL_SALT). No default — must be supplied via terraform.auto.tfvars (gitignored)."
  type        = string
  sensitive   = true
}

variable "langfuse_nextauth_secret" {
  description = "Langfuse NextAuth secret (from NEXTAUTH_SECRET)"
  type        = string
  sensitive   = true
}

variable "langfuse_salt" {
  description = "Langfuse encryption salt (from SALT)"
  type        = string
  sensitive   = true
}

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
    condition     = var.langfuse_compliance_secret_key == "" || length(var.langfuse_compliance_secret_key) >= 10
    error_message = "langfuse_compliance_secret_key must be a valid Langfuse API key (≥10 chars) or empty string. An empty value is only valid when enable_nist_compliance=false. (POAM-019)"
  }
}

# ─── Cloud Run Configuration ──────────────────────────────────────────────────

variable "gateway_cpu" {
  description = "Gateway service CPU allocation"
  type        = string
  default     = "2"
}

variable "gateway_memory" {
  description = "Gateway service memory allocation"
  type        = string
  default     = "2Gi"
}

variable "gateway_min_instances" {
  description = "Gateway service minimum instance count"
  type        = number
  default     = 0
}

variable "gateway_max_instances" {
  description = "Gateway service maximum instance count"
  type        = number
  default     = 10
}

variable "advisor_cpu" {
  description = "Governed Advisor service CPU allocation"
  type        = string
  default     = "1"
}

variable "advisor_memory" {
  description = "Governed Advisor service memory allocation"
  type        = string
  default     = "1Gi"
}

variable "advisor_min_instances" {
  description = "Governed Advisor service minimum instance count"
  type        = number
  default     = 0
}

variable "advisor_max_instances" {
  description = "Governed Advisor service maximum instance count"
  type        = number
  default     = 5
}
