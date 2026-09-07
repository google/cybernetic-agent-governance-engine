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

# ─── APAC MAS Production Environment Configuration (GCP-GKE Target) ───────────
#
# DEP-12: This file defines the APAC_MAS production deployment posture.
# Previously absent — APAC_MAS production deployments were architecturally
# undefined at the Terraform layer (only apac-dev.tfvars existed).
#
# Jurisdiction: Singapore / APAC
# Primary framework: MAS FEAT Principles (Fairness, Ethics, Accountability,
#   Transparency) — November 2019
# Co-frameworks: MAS Notice 655, MAS TRM Guidelines §4.2/§6.3/§9.1, ISO 42001
# Universal baseline: ISO 42001 (always active for all regions)
#
# Activate:
#   CAGE_DEPLOYMENT_REGION=APAC_MAS ./deploy_all.sh --target gcp-gke --env prod \
#     --var-file=infra/targets/gcp-gke/apac-prod.tfvars
#
# Data residency: asia-southeast1 (Singapore) — MAS TRM Guidelines §4.2.
# The Terraform precondition on the langfuse_events bucket (DEP-10) validates
# that region starts with "asia-" for APAC_MAS deployments.
# DO NOT change region without a formal MAS outsourcing arrangement notification.
#
# External legal requirements (not automated — must be completed separately):
#   1. MAS FEAT Fairness Impact Assessment (FIA) — quantitative bias metrics
#   2. MAS Notice 655 material AI system deployment notification
#   3. MAS TRM §6.3 AI governance framework submission
#   4. MAS FEAT Transparency Report (T2) — 6-month cycle
#   5. SGX Securities and Futures Act compliance review

# ─── GCP Project ──────────────────────────────────────────────────────────────
# REPLACE with your APAC production project ID
project_id = "your-apac-production-project"

# MAS TRM §4.2 data residency — Singapore
# asia-southeast1 = Singapore (MAS-approved jurisdiction)
region = "asia-southeast1"
zone   = "asia-southeast1-a"

# ─── Cluster ──────────────────────────────────────────────────────────────────
cluster_name = "cage-apac-prod"
environment  = "prod"
namespace    = "governance-stack"

# APAC CIDR ranges — non-overlapping with US prod (10.100.0.0/14) and EU prod (10.108.0.0/14)
pod_cidr               = "10.116.0.0/14"
service_cidr           = "10.120.0.0/20"
master_ipv4_cidr_block = "172.16.2.0/28"

# ─── Jurisdiction (DEP-12: explicit APAC_MAS scope) ───────────────────────────
# This must always be set explicitly — no default in variables.tf (DEP-09).
# Activates APAC_MAS_BASELINE.json compliance posture.
# The Terraform precondition on the langfuse_events bucket (DEP-10) will validate
# that region starts with "asia-" for APAC_MAS deployments.
cage_deployment_region = "APAC_MAS"

# ─── Security Posture (APAC_MAS Prod: MAS FEAT + MAS TRM + ISO 42001) ─────────
# DEP-20: enable_apac_mas_compliance activates MAS TRM §9.1 encryption at rest
# and MAS Notice 655 audit logging independently of enable_nist_compliance.
# DEP-01: enable_nist_compliance must be false for APAC_MAS deployments.
enable_nist_compliance     = false
enable_eu_ecb_compliance   = false
enable_apac_mas_compliance = true
# POAM-024: HA decoupled from compliance — set explicitly true for production
enable_high_availability       = true
enable_deletion_protection     = true
enable_binary_authorization    = true
enable_audit_logging           = true  # MAS Notice 655 §10 — mandatory
enable_cmek                    = false # Enable when KMS key is configured
enable_private_master_endpoint = false # Enable when VPN is configured
enable_pod_security_standards  = true
pod_security_level             = "restricted"
enable_dataplane_v2            = true

# Prod: Lock down to corporate VPN only (REPLACE with your SG VPN CIDR)
authorized_networks = [
  {
    cidr         = "10.0.0.0/8"
    display_name = "Corporate SG VPN (restrict to actual VPN CIDR in prod)"
  }
]

# ─── High Availability (APAC Prod: Multi-Zone, MAS TRM §7.2 availability) ─────

# Primary pool: Production-grade nodes in asia-southeast1
primary_node_pool_machine_type  = "e2-standard-8"
primary_node_pool_min_count     = 3 # HA requires 3+ nodes (MAS TRM §7.2)
primary_node_pool_max_count     = 10
primary_node_pool_initial_count = 3
primary_node_pool_disk_type     = "pd-ssd"

# GPU pool: L4 available in asia-southeast1-b, asia-southeast1-c
enable_gpu_node_pool        = true
gpu_type                    = "nvidia-l4"
gpu_count                   = 1
gpu_node_pool_machine_type  = "g2-standard-8"
gpu_node_pool_min_count     = 2 # Always-on for production
gpu_node_pool_max_count     = 5
gpu_node_pool_initial_count = 2
gpu_node_pool_name          = "gpu-node-pool-nvidia-l4"
gpu_node_pool_spot          = false # No spot VMs in APAC prod (MAS TRM §7.2 availability)
gpu_node_locations          = ["asia-southeast1-a", "asia-southeast1-b", "asia-southeast1-c"]

# ─── Storage (APAC Prod: Singapore-resident, MAS TRM §4.2) ────────────────────
storage_class           = "pd-ssd"
postgres_storage_size   = "50Gi"
redis_storage_size      = "10Gi"
clickhouse_storage_size = "20Gi"
model_bucket_name       = "" # Defaults to ${project_id}-models (created in asia-southeast1)

# ─── Container Registry ───────────────────────────────────────────────────────
registry_url = "" # Defaults to gcr.io/${project_id}

# ─── GCP Features ─────────────────────────────────────────────────────────────
enable_gcs_fuse_csi = true

# ─── Deployment ───────────────────────────────────────────────────────────────
force_redeploy = false

# ─── Services ─────────────────────────────────────────────────────────────────
enable_vllm              = true
enable_compliance_bridge = true
enable_nemo_guardrails   = true

vllm_gpu_count = 1
vllm_replicas  = 2 # HA for production (MAS TRM §7.2)

# ─── Langfuse (APAC: NextAuth URL reflects APAC cluster endpoint) ─────────────
# Update langfuse_nextauth_url to the actual APAC cluster ingress URL after deploy
langfuse_nextauth_url = "http://localhost:3000"

# ─── Langfuse S3-compatible storage (APAC: GCS bucket in asia-southeast1) ─────
# GCS HMAC keys and bucket are created in asia-southeast1 via var.region above.
# The bucket name is auto-generated: langfuse-events-${project_id}-${random_hex}
langfuse_s3_endpoint   = "https://storage.googleapis.com"
langfuse_s3_bucket     = "" # Auto-generated from GCS bucket resource
langfuse_s3_access_key = "" # Auto-generated from google_storage_hmac_key
langfuse_s3_secret_key = "" # Auto-generated from google_storage_hmac_key
