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

# ─── High Availability Toggle ─────────────────────────────────────────────────
# Introduced to decouple redundancy from security compliance (POAM-024).
# Previously, enable_nist_compliance controlled both security hardening AND
# replica scaling (gateway ×2, Redis replication, PDBs, resource limits).
# This prevented testing full security posture at dev scale.
# enable_high_availability now drives redundancy independently, allowing:
#   - dev: secure=false, ha=false (cheap iteration)
#   - staging: secure=true, ha=false (cheap full-security validation)
#   - prod: secure=true, ha=true (production HA + security)

variable "enable_high_availability" {
  description = "Enable high availability redundancy: multi-replica deployments (gateway ×2, advisor ×2, OPA ×2, NeMo ×2, Langfuse web/worker ×2, compliance bridge ×2), Redis replication (3 replicas + sentinel), PodDisruptionBudgets, and production resource limits. Independent of security compliance flags. Set true for production workloads requiring fault tolerance; false for dev/staging cost optimization."
  type        = bool
  default     = false
}

# POAM-024: Decoupled from enable_nist_compliance to allow ephemeral staging clusters.
variable "enable_deletion_protection" {
  description = "Enable deletion protection on the GKE cluster. Set false for ephemeral environments (staging) that need terraform destroy capability. Set true for production to prevent accidental cluster deletion."
  type        = bool
  default     = false
}

variable "enable_binary_authorization" {
  description = "Enable Binary Authorization (CM-7, SI-7)"
  type        = bool
  default     = false
}

variable "binary_authorization_enforcement_mode" {
  description = "Binary authorization enforcement mode: ENFORCED_BLOCK_AND_AUDIT_LOG or DRYRUN_AUDIT_LOG_ONLY"
  type        = string
  default     = "ENFORCED_BLOCK_AND_AUDIT_LOG"
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

variable "database_encryption_state" {
  description = "Database encryption state (ENCRYPTED or ALL_OBJECTS_ENCRYPTION_ENABLED). If null, defaults to ENCRYPTED."
  type        = string
  default     = null
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

variable "regional_cluster" {
  description = "When true, provisions a regional GKE cluster (location = var.region). Defaults to true when environment == 'prod', false (zonal) in dev and staging (§1.1)."
  type        = bool
  default     = null
}

variable "enable_dataplane_v2" {
  description = <<-EOT
    Enable GKE Dataplane V2 (Cilium/eBPF via anetd). Required for GKE FQDNNetworkPolicy
    enforcement (§1.1, §5.3). When true, the legacy Calico network_policy addon is removed
    (they are mutually exclusive). Enabled at cluster creation in every posture (dev, staging, prod).
  EOT
  type        = bool
  default     = true
}

variable "enable_fqdn_network_policy" {
  description = "Enable GKE FQDNNetworkPolicy (networking.gke.io/v1alpha1) enforcement at cluster creation alongside Dataplane V2 (§5.3, §7)."
  type        = bool
  default     = true
}

variable "release_channel" {
  description = "GKE release channel (REGULAR, STABLE, RAPID) to guarantee control-plane version >= 1.27.1-gke.400 for FQDNNetworkPolicy (§5.3)."
  type        = string
  default     = "REGULAR"
}

variable "min_master_version" {
  description = "Minimum GKE control-plane version (>= 1.27.1-gke.400 required for FQDNNetworkPolicy — §5.3)."
  type        = string
  default     = "1.28"
}

variable "cluster_dns_provider" {
  description = "Cluster DNS provider. FQDNNetworkPolicy requires kube-dns (PROVIDER_UNSPECIFIED) or CLOUD_DNS; custom CoreDNS is forbidden (§5.3, §7)."
  type        = string
  default     = "PROVIDER_UNSPECIFIED"

  validation {
    condition     = contains(["PROVIDER_UNSPECIFIED", "CLOUD_DNS"], var.cluster_dns_provider)
    error_message = "cluster_dns_provider must be PROVIDER_UNSPECIFIED (kube-dns) or CLOUD_DNS. Custom CoreDNS is unsupported by GKE FQDNNetworkPolicy (§5.3, §7)."
  }
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

# ─── Node Pool Configuration (§3: general, general-spot, gpu-l4, clickhouse) ─

variable "primary_node_pool_machine_type" {
  description = "Machine type for general (primary) node pool"
  type        = string
  default     = "e2-standard-4"
}

variable "primary_node_pool_min_count" {
  description = "Minimum nodes in general (primary) pool"
  type        = number
  default     = 1
}

variable "primary_node_pool_max_count" {
  description = "Maximum nodes in general (primary) pool"
  type        = number
  default     = 5
}

variable "primary_node_pool_initial_count" {
  description = "Initial node count for general (primary) pool"
  type        = number
  default     = 2
}

variable "primary_node_pool_disk_type" {
  description = "Disk type for general (primary) nodes (pd-standard, pd-ssd)"
  type        = string
  default     = "pd-standard"
}

# ─── General-Spot Node Pool Configuration (§3: general-spot) ──────────────────

variable "enable_general_spot_node_pool" {
  description = "Enable general-spot node pool (c3-highcpu-4, Spot, 0-5 in staging only — §3)"
  type        = bool
  default     = null
}

variable "general_spot_machine_type" {
  description = "Machine type for general-spot node pool (§3)"
  type        = string
  default     = "c3-highcpu-4"
}

variable "general_spot_min_count" {
  description = "Minimum nodes in general-spot pool (§3: 0 in staging)"
  type        = number
  default     = 0
}

variable "general_spot_max_count" {
  description = "Maximum nodes in general-spot pool (§3: 5 in staging)"
  type        = number
  default     = 5
}

variable "general_spot_initial_count" {
  description = "Initial node count for general-spot pool"
  type        = number
  default     = 0
}

# ─── GPU Node Pool Configuration (§3: gpu-l4) ─────────────────────────────────

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
  description = "Machine type for GPU nodes (g2-standard-8, 1x L4 — §3)"
  type        = string
  default     = "g2-standard-8"
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
  description = "Name of the GPU node pool"
  type        = string
  default     = "gpu-node-pool-nvidia-l4"
}

variable "gpu_node_pool_spot" {
  description = "GPU Spot must remain false in every posture (§3, §7): measurement runs must not be preempted."
  type        = bool
  default     = false

  validation {
    condition     = var.gpu_node_pool_spot == false
    error_message = "GPU Spot must stay false in every posture (§3, §7): measurement runs must not be preempted."
  }
}

variable "gpu_node_locations" {
  description = "List of zones to deploy the GPU node pool to. Enables multi-zonal/regional node configuration."
  type        = list(string)
  default     = ["us-central1-a", "us-central1-b", "us-central1-c"]
}

# ─── ClickHouse Node Pool Configuration (§3, §7: clickhouse) ──────────────────

variable "enable_clickhouse_node_pool" {
  description = "Enable dedicated ClickHouse node pool with local SSD and workload=clickhouse:NoSchedule taint (§3, §7)"
  type        = bool
  default     = true
}

variable "clickhouse_node_pool_machine_type" {
  description = "Machine type for ClickHouse node pool (local-SSD machine type)"
  type        = string
  default     = "n2-standard-4"
}

variable "clickhouse_node_pool_min_count" {
  description = "Minimum nodes in ClickHouse pool (1 in dev/staging, 3 in prod — §3)"
  type        = number
  default     = null
}

variable "clickhouse_node_pool_max_count" {
  description = "Maximum nodes in ClickHouse pool (1 in dev/staging, 3 in prod — §3)"
  type        = number
  default     = null
}

variable "clickhouse_node_pool_initial_count" {
  description = "Initial node count for ClickHouse pool (1 in dev/staging, 3 in prod — §3)"
  type        = number
  default     = null
}

variable "clickhouse_node_pool_local_ssd_count" {
  description = "Number of raw-block local NVMe SSDs attached to each ClickHouse node for hot-tier storage"
  type        = number
  default     = 1
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
  description = "PostgreSQL PVC size (legacy parameter kept for backward compatibility)"
  type        = string
  default     = "50Gi"
}

variable "postgres_tier" {
  description = "Cloud SQL machine tier for dev posture (staging and prod use posture matrix defaults)"
  type        = string
  default     = "db-f1-micro"
}

variable "postgres_disk_size" {
  description = "Cloud SQL disk size in GB"
  type        = number
  default     = 10
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

variable "image_digests" {
  description = "Immutable container image references pinned by @sha256: digest (name -> repo@sha256:<64-hex>). Required for Binary Authorization enforcement (CM-7, SI-7, POAM-2026-083)."
  type        = map(string)
  default = {
    "gateway"                    = "gcr.io/cage-reference/gateway@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    "governed-financial-advisor" = "gcr.io/cage-reference/governed-financial-advisor@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    "vllm-streamer"              = "gcr.io/cage-reference/vllm-streamer@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    "nemo-guardrails"            = "gcr.io/cage-reference/nemo-guardrails@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    "compliance-bridge"          = "gcr.io/cage-reference/compliance-bridge@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    "agentsight-ui"              = "gcr.io/cage-reference/agentsight-ui@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    "presidio-analyzer"          = "gcr.io/cage-reference/presidio-analyzer@sha256:7d3c6513bc188a92c67ca068346bf2ef042d3726c243217ce9fb3a57960d3234"
    "presidio-anonymizer"        = "gcr.io/cage-reference/presidio-anonymizer@sha256:562be3cb2e5c15f17c10935721459ef0d10cc2f28209f1f925b86dc7d40a2146"
    "opa"                        = "gcr.io/cage-reference/opa@sha256:cc4efcabce6d6ebfa2dc8efdb2edaf4dbdeaa4e11f2be5a4a01a6661c82fc1b8"
    "langfuse"                   = "gcr.io/cage-reference/langfuse@sha256:6b21a5086a07d9df332f7ecfc46778b3eb098b34df602ab80a0cd32a5f6c1134"
    "langfuse-worker"            = "gcr.io/cage-reference/langfuse-worker@sha256:41f5785e862bf7e114cdbd8342be524c78dc8c88f6df5bd2c7debb3de98ec43b"
    "cloud-sql-proxy"            = "gcr.io/cage-reference/cloud-sql-proxy@sha256:a77c72c56747cf2f431a4ed5e4a45e62003ca0fb94dc9f0c9cd390e84be2fa0e"
    "clickhouse-server"          = "gcr.io/cage-reference/clickhouse-server@sha256:93f94e0c86d78c1ef8be33339d7dc8dc8c8e27c1b30d828ffab3893bf950d895"
    "clickhouse-keeper"          = "gcr.io/cage-reference/clickhouse-keeper@sha256:77026fa37cc6922d10a25a8cd827cf3682e3fb0942dc162e490fa991bdbf0224"
    "redis"                      = "gcr.io/cage-reference/redis@sha256:1f885a1088573222b2b34614878726658c71ff7f68db3b8ef07bd0ca57a2909e"
  }

  validation {
    condition = !var.enable_binary_authorization || (
      alltrue([
        for name, ref in var.image_digests :
        can(regex("^[^@\\s]+@sha256:[0-9a-f]{64}$", ref)) && !can(regex(":latest(@|$)", ref))
        ]) && alltrue([
        for req in [
          "gateway",
          "governed-financial-advisor",
          "vllm-streamer",
          "nemo-guardrails",
          "compliance-bridge",
          "agentsight-ui",
          "presidio-analyzer",
          "presidio-anonymizer",
          "opa",
          "langfuse",
          "langfuse-worker",
          "cloud-sql-proxy",
          "clickhouse-server",
          "clickhouse-keeper",
        ] : contains(keys(var.image_digests), req)
      ])
    )
    error_message = "When enable_binary_authorization = true, image_digests must include all workload images and every reference must be pinned by an immutable @sha256:<64-hex> digest (tag-only and :latest references are rejected — CM-7, SI-7, POAM-2026-083)."
  }

  validation {
    condition = alltrue([
      for name, ref in var.image_digests :
      can(regex("^[^@\\s]+@sha256:[0-9a-f]{64}$", ref)) && !can(regex(":latest(@|$)", ref))
    ])
    error_message = "Every entry in image_digests must be a digest-pinned image reference (repo@sha256:<64-hex>); tag-only and :latest references are prohibited."
  }
}

variable "nemo_image" {
  description = "NeMo Guardrails container image override (defaults to var.image_digests[\"nemo-guardrails\"])"
  type        = string
  default     = ""

  validation {
    condition = var.nemo_image == "" || (
      !can(regex(":latest(@|$)", var.nemo_image)) &&
      (!var.enable_binary_authorization || can(regex("^[^@\\s]+@sha256:[0-9a-f]{64}$", var.nemo_image)))
    )
    error_message = "nemo_image must not use :latest and, when enable_binary_authorization = true, must be pinned by @sha256:<64-hex> digest."
  }
}

variable "presidio_analyzer_image" {
  description = "Microsoft Presidio Analyzer container image override (defaults to var.image_digests[\"presidio-analyzer\"])"
  type        = string
  default     = ""

  validation {
    condition = var.presidio_analyzer_image == "" || (
      !can(regex(":latest(@|$)", var.presidio_analyzer_image)) &&
      (!var.enable_binary_authorization || can(regex("^[^@\\s]+@sha256:[0-9a-f]{64}$", var.presidio_analyzer_image)))
    )
    error_message = "presidio_analyzer_image must not use :latest and, when enable_binary_authorization = true, must be pinned by @sha256:<64-hex> digest."
  }
}

variable "presidio_anonymizer_image" {
  description = "Microsoft Presidio Anonymizer container image override (defaults to var.image_digests[\"presidio-anonymizer\"])"
  type        = string
  default     = ""

  validation {
    condition = var.presidio_anonymizer_image == "" || (
      !can(regex(":latest(@|$)", var.presidio_anonymizer_image)) &&
      (!var.enable_binary_authorization || can(regex("^[^@\\s]+@sha256:[0-9a-f]{64}$", var.presidio_anonymizer_image)))
    )
    error_message = "presidio_anonymizer_image must not use :latest and, when enable_binary_authorization = true, must be pinned by @sha256:<64-hex> digest."
  }
}

# ─── vLLM Configuration ───────────────────────────────────────────────────────

variable "enable_vllm" {
  description = "Enable vLLM inference deployment"
  type        = bool
  default     = false
}

variable "vllm_model_path" {
  description = "GCS path in the model bucket for vLLM weights"
  type        = string
  default     = "gs://cage-models/Qwen/Qwen2.5-1.5B-Instruct"
}

variable "vllm_image" {
  description = "vLLM container image override (defaults to var.image_digests[\"vllm-streamer\"])"
  type        = string
  default     = ""

  validation {
    condition = var.vllm_image == "" || (
      !can(regex(":latest(@|$)", var.vllm_image)) &&
      (!var.enable_binary_authorization || can(regex("^[^@\\s]+@sha256:[0-9a-f]{64}$", var.vllm_image)))
    )
    error_message = "vllm_image must not use :latest and, when enable_binary_authorization = true, must be pinned by @sha256:<64-hex> digest."
  }
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
  description = "vLLM CPU limit on g2-standard-8 (8 vCPU / 7910m GKE allocatable)"
  type        = string
  default     = "6000m"

  validation {
    condition = (
      can(regex("^[0-9]+(\\.[0-9]+)?m?$", var.vllm_cpu_limit)) &&
      (
        endswith(var.vllm_cpu_limit, "m")
        ? tonumber(trimsuffix(var.vllm_cpu_limit, "m"))
        : tonumber(var.vllm_cpu_limit) * 1000
      ) > 0 &&
      (
        endswith(var.vllm_cpu_limit, "m")
        ? tonumber(trimsuffix(var.vllm_cpu_limit, "m"))
        : tonumber(var.vllm_cpu_limit) * 1000
      ) <= 7910
    )
    error_message = "vllm_cpu_limit must be a valid CPU quantity (e.g. '6000m' or '6') and must not exceed g2-standard-8 GKE allocatable CPU (7910m)."
  }
}

variable "vllm_memory_limit" {
  description = "vLLM memory limit on g2-standard-8 (32 GB RAM / 28928Mi GKE allocatable)"
  type        = string
  default     = "24Gi"

  validation {
    condition = (
      can(regex("^[0-9]+(Mi|Gi)$", var.vllm_memory_limit)) &&
      (
        endswith(var.vllm_memory_limit, "Gi")
        ? tonumber(trimsuffix(var.vllm_memory_limit, "Gi")) * 1024
        : tonumber(trimsuffix(var.vllm_memory_limit, "Mi"))
      ) > 0 &&
      (
        endswith(var.vllm_memory_limit, "Gi")
        ? tonumber(trimsuffix(var.vllm_memory_limit, "Gi")) * 1024
        : tonumber(trimsuffix(var.vllm_memory_limit, "Mi"))
      ) <= 28928
    )
    error_message = "vllm_memory_limit must be a valid Mi/Gi quantity (e.g. '24Gi') and must not exceed g2-standard-8 GKE allocatable memory (28928Mi / ~28.25Gi)."
  }
}

variable "vllm_cpu_request" {
  description = "vLLM CPU request on g2-standard-8 (8 vCPU / 7910m GKE allocatable)"
  type        = string
  default     = "3000m"

  validation {
    condition = (
      can(regex("^[0-9]+(\\.[0-9]+)?m?$", var.vllm_cpu_request)) &&
      (
        endswith(var.vllm_cpu_request, "m")
        ? tonumber(trimsuffix(var.vllm_cpu_request, "m"))
        : tonumber(var.vllm_cpu_request) * 1000
      ) > 0 &&
      (
        endswith(var.vllm_cpu_request, "m")
        ? tonumber(trimsuffix(var.vllm_cpu_request, "m"))
        : tonumber(var.vllm_cpu_request) * 1000
      ) <= 7910
    )
    error_message = "vllm_cpu_request must be a valid CPU quantity (e.g. '3000m' or '3') and must not exceed g2-standard-8 GKE allocatable CPU (7910m)."
  }
}

variable "vllm_memory_request" {
  description = "vLLM memory request on g2-standard-8 (32 GB RAM / 28928Mi GKE allocatable)"
  type        = string
  default     = "10Gi"

  validation {
    condition = (
      can(regex("^[0-9]+(Mi|Gi)$", var.vllm_memory_request)) &&
      (
        endswith(var.vllm_memory_request, "Gi")
        ? tonumber(trimsuffix(var.vllm_memory_request, "Gi")) * 1024
        : tonumber(trimsuffix(var.vllm_memory_request, "Mi"))
      ) > 0 &&
      (
        endswith(var.vllm_memory_request, "Gi")
        ? tonumber(trimsuffix(var.vllm_memory_request, "Gi")) * 1024
        : tonumber(trimsuffix(var.vllm_memory_request, "Mi"))
      ) <= 28928
    )
    error_message = "vllm_memory_request must be a valid Mi/Gi quantity (e.g. '10Gi') and must not exceed g2-standard-8 GKE allocatable memory (28928Mi / ~28.25Gi)."
  }
}

variable "vllm_shared_memory_size" {
  description = "Shared memory size for /dev/shm on g2-standard-8 (32 GB RAM / 28928Mi GKE allocatable)"
  type        = string
  default     = "2Gi"

  validation {
    condition = (
      can(regex("^[0-9]+(Mi|Gi)$", var.vllm_shared_memory_size)) &&
      (
        endswith(var.vllm_shared_memory_size, "Gi")
        ? tonumber(trimsuffix(var.vllm_shared_memory_size, "Gi")) * 1024
        : tonumber(trimsuffix(var.vllm_shared_memory_size, "Mi"))
      ) > 0 &&
      (
        endswith(var.vllm_shared_memory_size, "Gi")
        ? tonumber(trimsuffix(var.vllm_shared_memory_size, "Gi")) * 1024
        : tonumber(trimsuffix(var.vllm_shared_memory_size, "Mi"))
      ) <= 28928
    )
    error_message = "vllm_shared_memory_size must be a valid Mi/Gi quantity (e.g. '2Gi') and must not exceed g2-standard-8 GKE allocatable memory (28928Mi / ~28.25Gi)."
  }
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
  description = "Compliance bridge container image override (defaults to var.image_digests[\"compliance-bridge\"])"
  type        = string
  default     = ""

  validation {
    condition = var.compliance_bridge_image == "" || (
      !can(regex(":latest(@|$)", var.compliance_bridge_image)) &&
      (!var.enable_binary_authorization || can(regex("^[^@\\s]+@sha256:[0-9a-f]{64}$", var.compliance_bridge_image)))
    )
    error_message = "compliance_bridge_image must not use :latest and, when enable_binary_authorization = true, must be pinned by @sha256:<64-hex> digest."
  }
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
  description = "Reasoning model GCS path in the model bucket (from MODEL_REASONING)"
  type        = string
  default     = "gs://cage-models/deepseek-ai/DeepSeek-R1-Distill-Llama-8B"
}

variable "model_fast" {
  description = "Fast model GCS path in the model bucket (from MODEL_FAST)"
  type        = string
  default     = "gs://cage-models/Qwen/Qwen2.5-1.5B-Instruct"
}

variable "served_model_reasoning" {
  description = "Served model ID for the reasoning vLLM pool (--served-model-name), used by gateway and advisor"
  type        = string
  default     = "deepseek-ai/DeepSeek-R1-Distill-Llama-8B"
}

variable "served_model_fast" {
  description = "Served model ID for the fast vLLM pool (--served-model-name), used by gateway, NeMo, compliance bridge, and advisor"
  type        = string
  default     = "Qwen/Qwen2.5-1.5B-Instruct"
}

variable "served_model_name" {
  description = "Optional override for vLLM --served-model-name"
  type        = string
  default     = ""
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

variable "kms_signing_protection_level" {
  description = "Protection level for the Terraform-provisioned signing keys in kms_signing.tf (gateway-seal, reconciler-snapshot, compliance-evidence). HSM for staging/prod; SOFTWARE only in dev postures (POAM-2026-079 / SC-12)."
  type        = string
  default     = "HSM"

  validation {
    condition     = contains(["SOFTWARE", "HSM"], var.kms_signing_protection_level)
    error_message = "kms_signing_protection_level must be SOFTWARE or HSM."
  }
}

variable "cage_kms_provider" {
  description = "Cloud KMS provider backend for governance signing (from CAGE_KMS_PROVIDER): gcp, aws, or azure."
  type        = string
  default     = "gcp"
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

# ─── Track 6b Memorystore Configuration (§2.1, D5, D6) ────────────────────────

variable "enable_memorystore_iam_auth" {
  description = "Enable IAM authentication on Memorystore instances (default true per D5)"
  type        = bool
  default     = true
}

variable "enable_memorystore_tls" {
  description = "Enable in-transit encryption on Memorystore instances (default true per §2.1)"
  type        = bool
  default     = true
}

variable "memorystore_governance_instance_id" {
  description = "Optional override for governance Memorystore instance ID"
  type        = string
  default     = ""
}

variable "memorystore_app_instance_id" {
  description = "Optional override for application Memorystore instance ID"
  type        = string
  default     = ""
}

# ─── Track 6f VPC & Perimeter Configuration (§5.4) ────────────────────────────

variable "network" {
  description = "VPC network name or self_link for GKE, Cloud SQL, and Memorystore (§5.4)"
  type        = string
  default     = "default"
}

variable "subnetwork" {
  description = "VPC subnetwork name or self_link for GKE (§5.4)"
  type        = string
  default     = "default"
}

variable "subnet_cidr" {
  description = "Primary CIDR range for the VPC subnetwork (§5.4)"
  type        = string
  default     = "10.0.0.0/20"
}

variable "create_vpc_network" {
  description = "Provision dedicated VPC network with GKE pod/service secondary ranges via module.vpc_network (§5.4)"
  type        = bool
  default     = true
}

variable "enable_vpc_sc" {
  description = "Enable VPC Service Controls perimeter around GCP services (SC-7, AC-4, §5.4)"
  type        = bool
  default     = false
}

variable "organization_id" {
  description = "GCP Organization ID for VPC Service Controls access policy (required when enable_vpc_sc=true and access_policy_id is empty)"
  type        = string
  default     = ""
}

variable "access_policy_id" {
  description = "Existing Access Context Manager policy ID (optional; if empty and enable_vpc_sc=true, creates a new policy)"
  type        = string
  default     = ""
}

variable "enable_cloud_armor" {
  description = "Enable Cloud Armor WAF security policy attached to GKE Ingress backend via BackendConfig (SC-5, SC-7, SI-10, §5.4)"
  type        = bool
  default     = true
}

variable "enable_cloud_dns" {
  description = "Enable Cloud DNS A-record binding to GKE Ingress global IP (§5.4)"
  type        = bool
  default     = false
}

variable "dns_managed_zone_name" {
  description = "Existing persistent Cloud DNS managed zone name (§5.4)"
  type        = string
  default     = ""
}

variable "dns_domain_name" {
  description = "FQDN for the GKE Ingress DNS A-record (e.g., gateway.laah.altostrat.com. — §5.4)"
  type        = string
  default     = ""
}

# ─── Track 6f Network Policy & FQDN Policy Configuration (§5.3, §7) ──────────
# The policy set is identical in every posture; only CIDRs and FQDNs differ via tfvars.

variable "memorystore_governance_psc_cidr" {
  description = "PSC endpoint CIDR block for the governance Memorystore instance on TLS port 6379 (§5.3)"
  type        = string
  default     = "10.0.16.0/28"
}

variable "memorystore_app_psc_cidr" {
  description = "PSC endpoint CIDR block for the app Memorystore instance on TLS port 6379 (§5.3)"
  type        = string
  default     = "10.0.16.16/28"
}

variable "cloud_sql_cidr" {
  description = "VPC peering CIDR block for Cloud SQL private IP connection (§5.3)"
  type        = string
  default     = "10.6.80.0/20"
}

variable "cage_domain" {
  description = "CAGE domain configuration (e.g. 'finance')"
  type        = string
  default     = "finance"
}

variable "kube_dns_cidr" {
  description = "Cloud DNS / node-local metadata DNS resolver IP block (169.254.169.254/32 — §5.3)"
  type        = string
  default     = "169.254.169.254/32"
}

variable "gateway_egress_allowed_fqdns" {
  description = "FQDNs allowed for gateway external HTTPS (443) egress via GKE FQDNNetworkPolicy (§5.3)"
  type        = list(string)
  default = [
    "api.openai.com",
    "api.anthropic.com",
    "generativelanguage.googleapis.com",
    "*.googleapis.com",
    "metadata.google.internal",
    "us.i.posthog.com",
    "cloud.langfuse.com",
    "api.trade.gov",
    "www.treasury.gov",
  ]
}

variable "reconciler_egress_allowed_fqdns" {
  description = "FQDNs allowed for reconciliation-worker HTTPS (443) egress via GKE FQDNNetworkPolicy (§5.3)"
  type        = list(string)
  default = [
    "cloudkms.googleapis.com",
  ]
}

variable "trivy_egress_allowed_fqdns" {
  description = "FQDNs allowed for Trivy vulnerability scanner HTTPS (443) egress via GKE FQDNNetworkPolicy (§5.3)"
  type        = list(string)
  default = [
    "ghcr.io",
    "*.ghcr.io",
    "pkg.dev",
    "*.pkg.dev",
  ]
}

variable "vllm_egress_allowed_fqdns" {
  description = "FQDNs allowed for vLLM model weight streaming and Workload Identity token exchange over HTTPS (443) via GKE FQDNNetworkPolicy (§5.3)"
  type        = list(string)
  default = [
    "storage.googleapis.com",
    "oauth2.googleapis.com",
  ]
}

variable "compliance_bridge_egress_allowed_fqdns" {
  description = "FQDNs allowed for compliance-bridge HTTPS (443) egress via GKE FQDNNetworkPolicy: WORM bucket writes (GCS), per-batch evidence attestation signing (Cloud KMS) and Workload Identity token exchange (§5.3)"
  type        = list(string)
  default = [
    "storage.googleapis.com",
    "cloudkms.googleapis.com",
    "oauth2.googleapis.com",
  ]
}


