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

variable "project_id" { # No default and no committed value: set GOOGLE_CLOUD_PROJECT in .env, or pass --var project_id=<project>.
  description = "GCP project ID. No profile commits one (POAM-2026-131): a placeholder in a -var-file outranks TF_VAR_project_id, so it would defeat deploy_all.sh's GOOGLE_CLOUD_PROJECT -> TF_VAR_project_id mapping (DEP-22). Set GOOGLE_CLOUD_PROJECT in .env, or pass --var project_id=<project>."
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

# ─── Security Posture Toggle ──────────────────────────────────────────────────

# POAM-2026-130: enforce_in_dev replaces enable_nist_compliance,
# enable_eu_ecb_compliance and enable_apac_mas_compliance, which all did the
# same thing and selected nothing jurisdiction-specific. The posture follows the
# tier (local.enforcing_posture in main.tf):
#   tier      enforcing
#   dev       only with enforce_in_dev = true
#   staging   always, whatever enforce_in_dev says
#   prod      always, whatever enforce_in_dev says
# Enforcing means the retention lock on both evidence buckets, governance Valkey
# AOF, control_plane_access_guard and the two POAM-019 compliance key guards,
# the cluster's control-plane allowlist, Cloud SQL PITR and the NeMo server's
# securityContext (POAM-2026-181). The jurisdiction is cage_deployment_region,
# which OSCAL and the workloads read. A tfvars file that still sets a removed
# flag gets Terraform's "Value for undeclared variable" warning and the value is
# ignored, so a dev profile that used one to enforce must set enforce_in_dev =
# true instead. A -var for a removed flag fails. Every committed dev profile
# states enforce_in_dev; no staging or prod profile sets it.
#
#
variable "enforce_in_dev" {
  description = "Give a dev deployment the enforcing posture that staging and prod always have (POAM-2026-130, POAM-2026-181). Staging and prod ignore it."
  type        = bool
  default     = false
  nullable    = false
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
  description = "Enable high availability redundancy: multi-replica deployments (gateway ×2, advisor ×2, OPA ×2, NeMo ×2, Langfuse web/worker ×2, compliance bridge ×2), Redis replication (3 replicas + sentinel), PodDisruptionBudgets, and production resource limits. Independent of the security posture. Set true for production workloads requiring fault tolerance; false for dev/staging cost optimization."
  type        = bool
  default     = false
}

# POAM-024: Decoupled from the security posture to allow ephemeral staging clusters.
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

variable "enable_private_master_endpoint" {
  description = "Make Kubernetes API endpoint private (requires VPN)"
  type        = bool
  default     = false
}

variable "enable_private_nodes" {
  description = "Enable private nodes (no external IPs on node VMs). Required when org policy constraints/compute.vmExternalIpAccess is enforced. Nodes use Cloud NAT for egress. Set independently of the posture; an enforcing plan turns private nodes on anyway."
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

variable "enable_network_policy_logging" {
  description = <<-EOT
    Enable GKE Dataplane V2 network policy verdict logging (`NetworkLogging/default` allow+deny
    in `projects/<PROJECT_ID>/logs/policy-action`) and cluster `advanced_datapath_observability_config`
    (`D-195-4`, `R-5`, `F-78`, `F-87`). When null (default), follows `local.enforcing_posture`
    (always on in staging and prod, and in dev with `enforce_in_dev = true`). Note GKE enforces
    a 500 connections/s per-node drop logging floor before shedding policy log records while
    continuing to enforce every NetworkPolicy.
  EOT
  type        = bool
  default     = null
}

variable "release_channel" {
  description = "GKE release channel (REGULAR, STABLE, RAPID) to guarantee control-plane version >= 1.27.1-gke.400 for FQDNNetworkPolicy (§5.3)."
  type        = string
  default     = "REGULAR"
}

variable "min_master_version" {
  description = "Minimum GKE control-plane version (>= 1.27.1-gke.400 required for FQDNNetworkPolicy — §5.3)."
  type        = string
  default     = null
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
  description = "Total minimum GPU nodes across gpu_node_locations (total_min_node_count; 0 scales to zero when idle)"
  type        = number
  default     = 0
}

variable "gpu_node_pool_max_count" {
  description = "Total maximum GPU nodes across gpu_node_locations (total_max_node_count)"
  type        = number
  default     = 2
}

variable "gpu_node_pool_initial_count" {
  description = "Initial GPU node count per zone at pool creation (0 avoids requesting GPUs at create time)"
  type        = number
  default     = 0
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
  description = "Zones for the GPU node pool. Autoscaling min and max are pool-wide totals (location_policy = ANY), so extra zones provide capacity fallback without multiplying counts; initial_node_count remains per-zone and defaults to 0."
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

variable "image_digests" { # No default. Render it: PROJECT_ID=<project> scripts/render_image_digests.sh [short_sha], then pass the file it writes with -var-file.
  description = <<-EOT
    Container images pinned by digest (name -> repo@sha256:<64-hex>), required for
    Binary Authorization (CM-7, SI-7, POAM-2026-083). There is no default and no
    committed value (POAM-2026-131): a digest names an image in one registry, so
    every deployment renders its own. deploy_all.sh builds, renders and passes it.
    By hand, after scripts/build_images.sh:
      PROJECT_ID=<project> scripts/render_image_digests.sh [short_sha]
      terraform plan -var-file=staging.tfvars -var-file=image_digests.<short_sha>.tfvars.json
  EOT
  type        = map(string)

  # Every image the profile deploys, whatever the Binary Authorization mode:
  # main.tf indexes this map for each deployed workload (local.required_image_digests).
  validation {
    condition     = length(setsubtract(local.required_image_digests, keys(var.image_digests))) == 0
    error_message = "image_digests lacks images this profile deploys: ${join(", ", sort(setsubtract(local.required_image_digests, keys(var.image_digests))))}. Build them and render the digests for that SHA: PROJECT_ID=<project> scripts/render_image_digests.sh [short_sha]."
  }

  validation {
    condition = alltrue([
      for name, ref in var.image_digests :
      can(regex("^[^@\\s]+@sha256:[0-9a-f]{64}$", ref)) && !can(regex(":latest(@|$)", ref))
    ])
    error_message = "Every entry in image_digests must be a digest-pinned image reference (repo@sha256:<64-hex>); tag-only and :latest references are prohibited (CM-7, SI-7, POAM-2026-083)."
  }

  # sha256:e3b0c442... is the SHA-256 of empty input. No image manifest hashes to
  # it, so a reference that carries it is a placeholder, not a pin.
  validation {
    condition = alltrue([
      for name, ref in var.image_digests :
      !endswith(ref, "@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    ])
    error_message = "image_digests contains sha256:e3b0c442...b855, the SHA-256 of empty input, which no image has: a placeholder, not a pin (POAM-2026-131). Render real digests: PROJECT_ID=<project> scripts/render_image_digests.sh [short_sha]."
  }
}

# ─── vLLM Configuration ───────────────────────────────────────────────────────

variable "inference_backend" {
  description = "Where model inference comes from: \"none\" (no model; no vLLM, advisor or NeMo server; the governance core runs alone) or \"vllm\" (in-cluster vLLM on the GPU pool, plus the advisor). Sets CAGE_INFERENCE_BACKEND on the gateway and compliance bridge. \"external\" is compose-only and refused here."
  type        = string
  default     = "none"

  validation {
    condition     = contains(["none", "vllm"], var.inference_backend)
    error_message = "inference_backend must be \"none\" or \"vllm\" on GKE. \"external\" is compose-only: the cluster denies external egress by default and the advisor's egress is internal-only, so reaching a third-party model provider would mean weakening that control."
  }
}

variable "enable_e2e_advisor" {
  description = "Opt-in non-production verification switch (POAM-2026-191, S-12): deploys the in-cluster governed-financial-advisor routed through the gateway /v1/chat/completions proxy alongside the deterministic inference-stub backend when inference_backend = \"none\", without provisioning GPU vLLM pods. Never set in committed .tfvars profiles; refused in prod/production."
  type        = bool
  default     = false
}

variable "e2e_operator_jwks_json" {
  description = "Optional non-production out-of-band public JWKS JSON ({kid: public_pem}) for ephemeral E2E human HITL verification when enable_e2e_advisor = true (POAM-2026-191 / POAM-2026-196). Never set in committed .tfvars profiles; refused in prod/production or when enable_e2e_advisor = false."
  type        = string
  default     = ""

  validation {
    condition     = trimspace(var.e2e_operator_jwks_json) == "" || (var.enable_e2e_advisor && !contains(["prod", "production"], lower(var.environment)))
    error_message = "e2e_operator_jwks_json is only valid when enable_e2e_advisor = true in non-production postures (never prod/production)."
  }
}

# Replaced by inference_backend. Kept only so that a profile still setting it
# fails with a migration message rather than Terraform's undeclared-variable error.
variable "enable_vllm" {
  description = "Removed: replaced by inference_backend. Setting it to any value fails the plan."
  type        = bool
  default     = null

  validation {
    condition     = var.enable_vllm == null
    error_message = "enable_vllm is replaced by inference_backend: remove it and set inference_backend = \"vllm\" (or \"none\" for no model)."
  }
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
  description = "S3 bucket for Langfuse event uploads. Empty selects the managed bucket, langfuse-event-upload-<project>-<suffix>."
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

variable "langfuse_init_user_email" {
  description = "Initial Langfuse admin user email (set via gitignored terraform.auto.tfvars in dev only; leave empty in staging/prod)"
  type        = string
  default     = ""
}

variable "langfuse_init_user_password" {
  description = "Initial Langfuse admin user password (set via gitignored terraform.auto.tfvars in dev only; leave empty in staging/prod)"
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

variable "enable_lula_cron" {
  description = "Deploy the periodic in-cluster Lula compliance auditor CronJob (CA-2 / CA-7)."
  type        = bool
  default     = true
}

variable "lula_image" {
  description = "Lula auditor container image override (defaults to var.image_digests[\"lula\"])."
  type        = string
  default     = ""

  validation {
    condition = var.lula_image == "" || (
      !can(regex(":latest(@|$)", var.lula_image)) &&
      (!var.enable_binary_authorization || can(regex("^[^@\\s]+@sha256:[0-9a-f]{64}$", var.lula_image)))
    )
    error_message = "lula_image must not use :latest and, when enable_binary_authorization = true, must be pinned by @sha256:<64-hex> digest."
  }
}

variable "lula_schedule" {
  description = "Cron schedule for the in-cluster Lula compliance auditor CronJob."
  type        = string
  default     = "*/15 * * * *"
}

variable "lula_alert_notification_channels" {
  description = "Cloud Monitoring notification channel resource names attached to the Lula compliance audit AlertPolicy (CA-7 / IR-4)."
  type        = list(string)
  default     = []
}

variable "lula_alert_owner" {
  description = "Named on-call team or owner label responsible for triaging Lula compliance audit alerts (CA-7 / IR-4)."
  type        = string
  default     = "platform-compliance-oncall"

  validation {
    condition = (
      trimspace(var.lula_alert_owner) != "" &&
      can(regex("^[a-z0-9][a-z0-9_-]{0,62}$", trimspace(var.lula_alert_owner)))
    )
    error_message = "lula_alert_owner must be a non-empty lowercase GCP label identifier (1-63 chars matching ^[a-z0-9][a-z0-9_-]{0,62}$)."
  }
}

variable "trusted_operator_identities" {
  description = "Allowlisted human OIDC operator sub claims permitted to approve HITL deferrals on compliance-bridge (CAGE_TRUSTED_OPERATOR_IDENTITIES; POAM-2026-196)."
  type        = list(string)
  default     = []
}

variable "operator_oidc_issuer" {
  description = "Expected OIDC issuer URL for human HITL operator JWTs on compliance-bridge (CAGE_OPERATOR_OIDC_ISSUER; POAM-2026-196)."
  type        = string
  default     = ""
}

variable "operator_oidc_audience" {
  description = "Expected OIDC audience claim for human HITL operator JWTs on compliance-bridge (CAGE_OPERATOR_OIDC_AUDIENCE; POAM-2026-196)."
  type        = string
  default     = "cage-compliance-bridge"
}

variable "operator_jwks_uri" {
  description = "Out-of-band HTTPS JWKS URI used by compliance-bridge to verify kid-pinned human operator OIDC JWTs (CAGE_OPERATOR_JWKS_URI; POAM-2026-196)."
  type        = string
  default     = ""
}

variable "gateway_langfuse_public_key" {
  description = "Dedicated telemetry public key for gateway-secrets (TELEMETRY_PUBLIC_KEY; R-2, F-84). When empty, gcp-gke generates an independent key distinct from advisor-secrets."
  type        = string
  sensitive   = true
  default     = ""
}

variable "gateway_langfuse_secret_key" {
  description = "Dedicated telemetry secret key for gateway-secrets (TELEMETRY_SECRET_KEY; R-2, F-84). When empty, gcp-gke generates an independent key distinct from advisor-secrets."
  type        = string
  sensitive   = true
  default     = ""
}

variable "gateway_otel_exporter_otlp_headers" {
  description = "Dedicated OTLP Authorization header override for gateway-secrets (OTEL_EXPORTER_OTLP_HEADERS; R-2, F-84)."
  type        = string
  sensitive   = true
  default     = ""
}

variable "gateway_redis_password" {
  description = "Dedicated governance Redis password for gateway-secrets when password auth is used (REDIS_PASSWORD; R-2, F-84)."
  type        = string
  sensitive   = true
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
  description = "Langfuse compliance project public key (from LANGFUSE_COMPLIANCE_PUBLIC_KEY). REQUIRED under an enforcing posture: every staging and prod plan, and dev with enforce_in_dev. Leaving it empty there defeats the AU-9 dual-project telemetry isolation architecture (POAM-019)."
  type        = string
  sensitive   = true
  nullable    = false
  default     = ""

  validation {
    # POAM-019: Prevent silent collapse of dual-project telemetry isolation.
    # Under an enforcing posture this key MUST be a distinct cage-compliance
    # project key.  An empty value silently falls back to the app project,
    # defeating AU-9 evidentiary independence.
    # NOTE: the posture check stays in the precondition in main.tf, not here: a
    # variable validation would also block terraform destroy (POAM-2026-174).
    # The precondition enforces the cross-variable constraint at plan time.
    condition     = var.langfuse_compliance_public_key == "" || length(var.langfuse_compliance_public_key) >= 10
    error_message = "langfuse_compliance_public_key must be a valid Langfuse API key (≥10 chars) or empty string. An empty value is only valid when the posture does not enforce. (POAM-019)"
  }
}

variable "langfuse_compliance_secret_key" {
  description = "Langfuse compliance project secret key (from LANGFUSE_COMPLIANCE_SECRET_KEY). REQUIRED under an enforcing posture: every staging and prod plan, and dev with enforce_in_dev. Leaving it empty there defeats the AU-9 dual-project telemetry isolation architecture (POAM-019)."
  type        = string
  sensitive   = true
  nullable    = false
  default     = ""

  validation {
    # POAM-019: Same constraint as langfuse_compliance_public_key.
    condition     = var.langfuse_compliance_secret_key == "" || length(var.langfuse_compliance_secret_key) >= 10
    error_message = "langfuse_compliance_secret_key must be a valid Langfuse API key (≥10 chars) or empty string. An empty value is only valid when the posture does not enforce. (POAM-019)"
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

  validation {
    condition     = can(regex("^gs://[a-z0-9][a-z0-9_.-]{1,61}[a-z0-9]/", var.model_reasoning))
    error_message = "model_reasoning must be a valid GCS URI starting with 'gs://<bucket>/' to prevent pulling unvetted models from Hugging Face or public repositories."
  }
}

variable "model_fast" {
  description = "Fast model GCS path in the model bucket (from MODEL_FAST)"
  type        = string
  default     = "gs://cage-models/Qwen/Qwen2.5-1.5B-Instruct"

  validation {
    condition     = can(regex("^gs://[a-z0-9][a-z0-9_.-]{1,61}[a-z0-9]/", var.model_fast))
    error_message = "model_fast must be a valid GCS URI starting with 'gs://<bucket>/' to prevent pulling unvetted models from Hugging Face or public repositories."
  }
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

variable "cage_api_key" {
  description = "Bearer API key for governed-financial-advisor in non-dev environments (generated independently when empty)"
  type        = string
  sensitive   = true
  default     = ""
}

variable "cage_internal_token" {
  description = "Internal bearer token for compliance-bridge endpoints in non-dev environments (generated independently when empty)"
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

  validation {
    condition     = contains(["gcp", "aws", "azure"], var.cage_kms_provider)
    error_message = "cage_kms_provider must be gcp, aws, or azure for gcp-gke deployments."
  }
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

variable "redis_url" {
  description = "Redis connection URL (from REDIS_URL)"
  type        = string
  default     = ""
}

variable "evidence_previous_chain_head_hash" {
  description = "Optional 64-hex SHA-256 record_hash of the prior chain's final custodied record for bound genesis rotation across cluster rebuilds (F-94 / R-10). Must be paired with evidence_previous_batch_attestation_digest."
  type        = string
  default     = ""
}

variable "evidence_previous_batch_attestation_digest" {
  description = "Optional 64-hex SHA-256 digest of the prior chain's final signed batch attestation for bound genesis rotation across cluster rebuilds (F-94 / R-10). Must be paired with evidence_previous_chain_head_hash."
  type        = string
  default     = ""
}

variable "master_ipv4_cidr_block" { default = "172.16.0.0/28" }

variable "pod_cidr" {
  description = "Secondary CIDR range for GKE pods. In create mode (create_vpc_network = true), module.vpc_network allocates this range on the subnetwork and module.gke attaches to it by name. In BYO mode (create_vpc_network = false) with existing named secondary ranges (cluster_secondary_range_name != null), set pod_cidr = null so the value is not silently discarded (POAM-2026-173)."
  type        = string
  default     = "10.100.0.0/14"
  nullable    = true
}

variable "service_cidr" {
  description = "Secondary CIDR range for GKE services. In create mode (create_vpc_network = true), module.vpc_network allocates this range on the subnetwork and module.gke attaches to it by name. In BYO mode (create_vpc_network = false) with existing named secondary ranges (services_secondary_range_name != null), set service_cidr = null so the value is not silently discarded (POAM-2026-173)."
  type        = string
  default     = "10.104.0.0/20"
  nullable    = true
}

variable "cluster_secondary_range_name" {
  description = "Secondary IP range name for GKE pods. In create mode (create_vpc_network = true), overrides the default 'gke-pods' range name created by module.vpc_network. In BYO mode (create_vpc_network = false), names an existing secondary range on var.subnetwork (requires pod_cidr = null; when null, GKE allocates pod_cidr)."
  type        = string
  default     = null
  nullable    = true
}

variable "services_secondary_range_name" {
  description = "Secondary IP range name for GKE services. In create mode (create_vpc_network = true), overrides the default 'gke-services' range name created by module.vpc_network. In BYO mode (create_vpc_network = false), names an existing secondary range on var.subnetwork (requires service_cidr = null; when null, GKE allocates service_cidr)."
  type        = string
  default     = null
  nullable    = true
}

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
  description = "VPC network name for GKE, the Linkerd webhook firewall, Cloud SQL, and Memorystore (§5.4, POAM-2026-173). When create_vpc_network = true, overrides 'cage-vpc-<environment>' if set to a non-'default' value. When create_vpc_network = false (BYO VPC), names the existing VPC network, which must already have Private Services Access (PSA) peering for Cloud SQL and a gcp-memorystore Network Connectivity Service Connection Policy covering var.subnetwork."
  type        = string
  default     = "default"
}

variable "subnetwork" {
  description = "VPC subnetwork name for GKE (§5.4, POAM-2026-173). When create_vpc_network = true, overrides 'cage-subnet-<environment>' if set to a non-'default' value. When create_vpc_network = false (BYO VPC), names the existing subnetwork in var.region, which must be listed in the BYO VPC's gcp-memorystore Service Connection Policy psc_config.subnetworks."
  type        = string
  default     = "default"
}

variable "subnet_cidr" {
  description = "Primary CIDR range for the VPC subnetwork (§5.4)"
  type        = string
  default     = "10.0.0.0/20"
}

variable "create_vpc_network" {
  description = "Provision dedicated VPC network with GKE pod/service secondary ranges, Private Services Access (PSA) peering for Cloud SQL, and a gcp-memorystore Network Connectivity Service Connection Policy via module.vpc_network (§5.4, POAM-2026-173). When false (BYO VPC), var.network and var.subnetwork must already provide PSA peering and a gcp-memorystore Service Connection Policy covering var.subnetwork."
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
  description = "FQDN for the GKE Ingress DNS A-record (e.g., gateway.cage.example.com. — §5.4)"
  type        = string
  default     = ""
}

# ─── Track 6f Network Policy & FQDN Policy Configuration (§5.3, §7) ──────────
# The policy set is identical in every posture; data-store /32 CIDRs are derived
# from the live resource endpoints in network_policy.tf (POAM-2026-190).

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
  description = "FQDNs allowed for gateway external HTTPS (443) egress via GKE FQDNNetworkPolicy (§5.3). No model provider is listed: on GKE inference stays in the cluster (POAM-2026-152)."
  type        = list(string)
  default = [
    "*.googleapis.com",
    "metadata.google.internal",
    "us.i.posthog.com",
    "cloud.langfuse.com",
    "api.trade.gov",
    "www.treasury.gov",
  ]
}

variable "reconciler_egress_allowed_fqdns" {
  description = "FQDNs allowed for reconciliation-worker HTTPS (443) egress via GKE FQDNNetworkPolicy: reconciler-snapshot signing (Cloud KMS) and Workload Identity token exchange (§5.3, POAM-2026-096)"
  type        = list(string)
  default = [
    "cloudkms.googleapis.com",
    "oauth2.googleapis.com",
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

# ─── Workload Identity Federation & Deployer / Partner-Harness Isolation (POAM-2026-165) ─

variable "github_repository" {
  description = "GitHub <owner>/<repo> bound by the Workload Identity Federation OIDC provider condition (POAM-2026-165)."
  type        = string
  default     = "google/cybernetic-agent-governance-engine"
}

variable "github_deployer_ref" {
  description = "Git ref principal allowed to impersonate sa-cage-deployer via Workload Identity Federation (POAM-2026-165)."
  type        = string
  default     = "refs/heads/main"

  validation {
    condition     = startswith(var.github_deployer_ref, "refs/heads/") && !endswith(var.github_deployer_ref, "*")
    error_message = "github_deployer_ref must be an exact branch ref under refs/heads/ (no wildcards)."
  }
}

variable "partner_harness_kms_keyring" {
  description = "Cloud KMS KeyRing name in var.region containing the partner harness signing key (POAM-2026-165)."
  type        = string
  default     = "cybernetics-keyring"
}

variable "partner_harness_kms_key" {
  description = "Cloud KMS CryptoKey name granted to cage-partner-harness for CI partner integration signing (POAM-2026-165). Empty string skips the key binding."
  type        = string
  default     = ""
}

# ─── Pre-W Evidence Survival: Reconciler & GMP PodMonitoring (PR-11) ──────────

variable "enable_reconciliation_worker" {
  description = "Deploy the in-state continuous reconciliation-worker Deployment, Secret, and KSA so CA-7/SI-10 reconciler-snapshot signing survives cluster rebuilds (POAM-2026-096, F-86)."
  type        = bool
  default     = true
}

variable "enable_service_monitor" {
  description = "Deploy Prometheus Operator ServiceMonitor/stera-gateway-monitor alongside GKE Managed Prometheus PodMonitoring/gateway-metrics when monitoring.coreos.com/v1 CRDs are installed (R-6, F-91)."
  type        = bool
  default     = false
}

variable "inference_stub_image" {
  description = "Optional container image override for the deterministic E2E inference stub. When empty (default), var.image_digests[\"inference-stub\"] is used."
  type        = string
  default     = ""

  validation {
    condition     = var.inference_stub_image == "" || !can(regex(":latest$", var.inference_stub_image))
    error_message = "inference_stub_image must not use the mutable :latest tag."
  }

  validation {
    condition     = var.inference_stub_image == "" || !var.enable_binary_authorization || can(regex("@sha256:[0-9a-f]{64}$", var.inference_stub_image))
    error_message = "Under Binary Authorization, inference_stub_image must be pinned by @sha256: digest."
  }
}

# ─── Persistent Evidence Domain Configuration (§10a, R-10, F-66, F-94, F-97) ─

variable "kms_protection_level" {
  description = "Cloud KMS CryptoKey protection level (SOFTWARE or HSM). When empty, defaults to SOFTWARE in dev and HSM in staging/prod."
  type        = string
  default     = ""

  validation {
    condition     = contains(["", "SOFTWARE", "HSM"], var.kms_protection_level)
    error_message = "kms_protection_level must be empty (auto-select by environment), SOFTWARE, or HSM."
  }
}

variable "evidence_project_id" {
  description = "Optional dedicated GCP project ID for the persistent evidence custody domain (e.g. '<PROJECT_ID>-evidence'). When null, defaults to var.project_id via coalesce(var.evidence_project_id, var.project_id)."
  type        = string
  default     = null
  nullable    = true
}

variable "external_evidence_domain_enabled" {
  description = "When true, the persistent evidence domain is managed in an external Terraform root (<PROJECT_ID>-evidence) and adopted read-only so workload cluster teardown (W) holds zero destroy path over WORM evidence buckets, Cloud Audit Logs buckets, or evidence CMEK keys (AU-9(4), F-66, F-94, F-97)."
  type        = bool
  default     = false
}

variable "external_evidence_cmek_key_id" {
  description = "Resource ID of the externally managed evidence CMEK CryptoKey when external_evidence_domain_enabled = true and enable_cmek = true (F-97)."
  type        = string
  default     = ""
}

variable "require_separate_evidence_project" {
  description = "When true (defaults to true in prod, false in dev/staging when null), enforces at plan time that external_evidence_domain_enabled = true or evidence_project_id != var.project_id so the workload deployer SA holds zero storage/KMS admin roles in the evidence domain (AU-9(4), F-66, F-97)."
  type        = bool
  default     = null
  nullable    = true
}

variable "evidence_bucket_name" {
  description = "Optional override for the WORM evidence bucket name (defaults to '<evidence_project_id>-evidence-worm-<environment>')."
  type        = string
  default     = ""
}

variable "audit_logs_bucket_name" {
  description = "Optional override for the retention-locked Cloud Audit Logs WORM bucket name (audit-logs-worm, R-4)."
  type        = string
  default     = ""
}

variable "audit_log_sink_writer_identities" {
  description = "Additional static sink names mapped to Cloud Logging sink writer identities granted roles/storage.objectCreator on the retention-locked audit-logs-worm bucket (R-4). The AS-6 sinks in kms_signing.tf are granted automatically under the kms_signing_audit and admin_activity_audit keys, which this map cannot override."
  type        = map(string)
  default     = {}
}

variable "offline_verifier_principal" {
  description = "Optional IAM principal for the out-of-cluster CustodyVerifier granted roles/storage.objectViewer in the evidence domain."
  type        = string
  default     = ""
}

variable "enable_kms_audit_logs" {
  description = "Enable Cloud KMS Data Access audit logging (DATA_READ records AsymmetricSign) and the Cloud Logging sinks that export KMS signing and Admin Activity records into the evidence domain's retention-locked audit-logs bucket (AS-6, POAM-2026-169 Instance 11). Always on in enforcing postures (staging, prod, or dev with enforce_in_dev = true); set true to opt a permissive dev stack in."
  type        = bool
  default     = false
  nullable    = false
}

variable "startup_grace_hours" {
  description = "Cold-start grace window in hours for compliance-bridge metrics (STARTUP_GRACE_HOURS). Defaults to 6 for normal rollouts; Gate W sets 0 so Lula API-domain validations evaluate outside grace."
  type        = number
  default     = 6

  validation {
    condition     = var.startup_grace_hours >= 0 && floor(var.startup_grace_hours) == var.startup_grace_hours
    error_message = "startup_grace_hours must be a non-negative integer."
  }
}

variable "bootstrap_without_cluster" {
  description = "Set true only during foundational GCP state import and Stage 1 GKE cluster creation before module.gke exists in state (EF4 / EF6, POAM-2026-164)."
  type        = bool
  default     = false
  nullable    = false
}

