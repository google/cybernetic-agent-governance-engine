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

# ─── EU ECB Production Environment Configuration (GCP-GKE Target) ─────────────
#
# DEP-12: This file defines the EU_ECB production deployment posture.
# Previously absent — EU_ECB production deployments were architecturally
# undefined at the Terraform layer (only eu-dev.tfvars existed).
#
# Jurisdiction: European Union
# Primary framework: EU AI Act (Regulation (EU) 2024/1689) — High-Risk AI
#   classification under Art. 6 + Annex III §5(b)
# Co-frameworks: DORA Art. 10, GDPR Art. 32/44, EBA/GL/2023/02, ISO 42001
# Universal baseline: ISO 42001 (always active for all regions)
#
# Activate:
#   CAGE_DEPLOYMENT_REGION=EU_ECB ./deploy_all.sh --target gcp-gke --env prod \
#     --var-file=infra/targets/gcp-gke/eu-prod.tfvars
#
# Data residency: europe-west1 (Belgium, EEA) — GDPR Art. 44 compliance.
# The Terraform precondition on the langfuse_events bucket (DEP-10) validates
# that region starts with "europe-" for EU_ECB deployments.
# DO NOT change region to a non-EEA location without a GDPR Art. 46 transfer
# mechanism (SCCs, adequacy decision, or BCRs).
#
# External legal requirements (not automated — must be completed separately):
#   1. GDPR Art. 35 Data Protection Impact Assessment (DPIA)
#   2. EU AI Act Art. 29a Fundamental Rights Impact Assessment (FRIA)
#   3. EU AI Office registration (High-Risk AI — Annex III §5(b))
#   4. DORA Art. 11 ICT Business Continuity Plan
#   5. EBA/GL/2023/02 independent model validation report

# ─── GCP Project ──────────────────────────────────────────────────────────────
# REPLACE with your EU production project ID
project_id = "your-eu-production-project"

# EEA data residency — GDPR Art. 44
# europe-west1 = Belgium (EEA) | europe-west4 = Netherlands (EEA)
region = "europe-west1"
zone   = "europe-west1-b"

# ─── Cluster ──────────────────────────────────────────────────────────────────
cluster_name = "cage-eu-prod"
environment  = "prod"
namespace    = "governance-stack"

# EU CIDR ranges — non-overlapping with US prod (10.100.0.0/14)
pod_cidr               = "10.108.0.0/14"
service_cidr           = "10.112.0.0/20"
master_ipv4_cidr_block = "172.16.1.0/28"

# ─── Jurisdiction (DEP-12: explicit EU_ECB scope) ─────────────────────────────
# This must always be set explicitly — no default in variables.tf (DEP-09).
# Activates EU_ECB_BASELINE.json compliance posture.
# The Terraform precondition on the langfuse_events bucket (DEP-10) will validate
# that region starts with "europe-" for EU_ECB deployments.
cage_deployment_region = "EU_ECB"

# ─── Security Posture (EU_ECB Prod: EU AI Act + DORA + GDPR + ISO 42001) ──────
# DEP-20: enable_eu_ecb_compliance activates DORA Art. 10 HA and GDPR Art. 32
# encryption at rest independently of enable_nist_compliance.
# DEP-01: enable_nist_compliance must be false for EU_ECB deployments.
enable_nist_compliance     = false
enable_eu_ecb_compliance   = true
enable_apac_mas_compliance = false
# POAM-024: HA decoupled from compliance — set explicitly true for production
enable_high_availability       = true
enable_deletion_protection     = true
enable_binary_authorization    = true
enable_audit_logging           = true  # DORA Art. 10 — mandatory for EU
enable_cmek                    = false # Enable when KMS key is configured
enable_private_master_endpoint = false # Enable when VPN is configured
enable_pod_security_standards  = true
pod_security_level             = "restricted"
enable_dataplane_v2            = true

# Prod: Lock down to corporate VPN only (REPLACE with your EU VPN CIDR)
authorized_networks = [
  {
    cidr         = "10.0.0.0/8"
    display_name = "Corporate EU VPN (restrict to actual VPN CIDR in prod)"
  }
]

# ─── High Availability (EU Prod: Multi-Zone, DORA Art. 10 resilience) ─────────

# Primary pool: Production-grade nodes in europe-west1
primary_node_pool_machine_type  = "e2-standard-8"
primary_node_pool_min_count     = 3 # HA requires 3+ nodes (DORA Art. 10)
primary_node_pool_max_count     = 10
primary_node_pool_initial_count = 3
primary_node_pool_disk_type     = "pd-ssd"

# GPU pool: L4 available in europe-west1-b, europe-west1-c
enable_gpu_node_pool        = true
gpu_type                    = "nvidia-l4"
gpu_count                   = 1
gpu_node_pool_machine_type  = "g2-standard-8"
gpu_node_pool_min_count     = 2 # Always-on for production
gpu_node_pool_max_count     = 5
gpu_node_pool_initial_count = 2
gpu_node_pool_name          = "gpu-node-pool-nvidia-l4"
gpu_node_pool_spot          = false # No spot VMs in EU prod (DORA Art. 10 availability)
gpu_node_locations          = ["europe-west1-b", "europe-west1-c", "europe-west1-d"]

# ─── Storage (EU Prod: EEA-resident, GDPR Art. 44) ────────────────────────────
storage_class           = "pd-ssd"
postgres_storage_size   = "50Gi"
redis_storage_size      = "10Gi"
clickhouse_storage_size = "20Gi"
model_bucket_name       = "" # Defaults to ${project_id}-models (created in europe-west1)

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
vllm_replicas  = 2 # HA for production (DORA Art. 10)

# ─── Langfuse (EU: NextAuth URL reflects EU cluster endpoint) ─────────────────
# Update langfuse_nextauth_url to the actual EU cluster ingress URL after deploy
langfuse_nextauth_url = "http://localhost:3000"

# ─── Langfuse S3-compatible storage (EU: GCS bucket in europe-west1) ──────────
# GCS HMAC keys and bucket are created in europe-west1 via var.region above.
# The bucket name is auto-generated: langfuse-events-${project_id}-${random_hex}
langfuse_s3_endpoint   = "https://storage.googleapis.com"
langfuse_s3_bucket     = "" # Auto-generated from GCS bucket resource
langfuse_s3_access_key = "" # Auto-generated from google_storage_hmac_key
langfuse_s3_secret_key = "" # Auto-generated from google_storage_hmac_key
