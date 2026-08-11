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

# ─── EU ECB Development Environment Configuration (GCP-GKE Target) ────────────
#
# Jurisdiction: European Union
# Primary framework: EU AI Act (Regulation (EU) 2024/1689) — High-Risk AI
#   classification under Art. 6 + Annex III §5(b)
# Co-frameworks: DORA, GDPR, EBA/GL/2023/02, ISO 42001
#
# Activate: ./deploy_all.sh --target gcp-gke --env eu-dev --auto-approve
#
# What changes automatically vs US_FED (no code changes required):
#   - Confidence threshold: 0.97 (vs 0.95 US) — EU AI Act Art. 9 High-Risk AI
#   - Drawdown limit: 4% (vs 5% US) — EBA adverse scenario calibration
#   - CBF gamma: 0.6 (vs 0.5 US) — more aggressive safety filter
#   - Consensus threshold: $7,500 (vs $10,000 US) — GDPR Art. 22 human oversight
#   - UCA-5 drawdown block: 3.5% (vs 4.5% US) — EBA cushion requirement
#   - UCA-6 max order volume: 0.5% daily vol (vs 1% US) — MiFID II MAR Art. 12
#   - Max sell fraction: 8% portfolio (vs 10% US) — ESMA best execution
#   - Max latency: 150ms (vs 200ms US) — DORA Art. 10 operational resilience
#   - FRIA attestation: ENABLED — EU AI Act Art. 29a (EU-only control)
#   - SR 26-2 on OTel spans: SUPPRESSED — "no legal force" sentinel active
#   - OSCAL framework: EU_AI_ACT (vs NIST_SP800_53 US)
#   - Prompt injection keywords: +GDPR OVERRIDE, +BYPASS FRIA
#
# Data residency: europe-west1 (Belgium, EEA) — GDPR Art. 44 compliance.
# All Langfuse traces, GCS audit buckets, and PostgreSQL data remain within EEA.
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
# REPLACE with your EU GCP project ID (may be same project as US dev)
project_id = "YOUR_GCP_PROJECT_ID"

# EEA data residency — GDPR Art. 44
# europe-west1 = Belgium (EEA) | europe-west4 = Netherlands (EEA)
region = "europe-west1"
zone   = "europe-west1-b"

# ─── Cluster ──────────────────────────────────────────────────────────────────
cluster_name = "cage-eu-dev"
environment  = "dev"
namespace    = "governance-stack"

# EU CIDR ranges — non-overlapping with US dev (10.100.0.0/14)
pod_cidr               = "10.108.0.0/14"
service_cidr           = "10.112.0.0/20"
master_ipv4_cidr_block = "172.16.1.0/28"

# ─── Jurisdiction ─────────────────────────────────────────────────────────────
# Activates EU_ECB_BASELINE.json (compliance) + EU_ECB_BASELINE.json (thresholds)
# Injected into advisor-secrets K8s Secret → all pods via envFrom
cage_deployment_region = "EU_ECB"

# ─── Security Posture (EU Dev: Stricter than US Dev) ──────────────────────────
# EU AI Act Art. 9 mandates a documented risk management system for High-Risk AI.
# DORA Art. 10 mandates continuous ICT monitoring. These cannot be disabled.
enable_nist_compliance         = false
enable_eu_ecb_compliance       = true  # DEP-20: activates DORA Art. 10 + GDPR Art. 32 controls
enable_apac_mas_compliance     = false
enable_binary_authorization    = false
enable_audit_logging           = true  # DORA Art. 10 — mandatory for EU
enable_cmek                    = false
enable_private_master_endpoint = false
enable_pod_security_standards  = false # Apply manually via pod-security-admission.yaml

# SECURITY (C-06): Restrict to RFC 1918 private ranges only.
# Never use 0.0.0.0/0 — it exposes the GKE API server to the internet.
# Replace 10.0.0.0/8 with your VPN/office CIDR ranges before deploying.
# Example: authorized_networks = [{ cidr = "203.0.113.0/24", display_name = "EU VPN" }]
# GDPR Art. 32 — appropriate technical measures; restrict in prod
authorized_networks = [
  {
    cidr         = "10.0.0.0/8"
    display_name = "RFC-1918 private range (restrict to VPN CIDR in prod)"
  }
]

# ─── Cost Optimization (Dev: Same node types as US dev) ───────────────────────
primary_node_pool_machine_type  = "e2-standard-4"
primary_node_pool_min_count     = 1
primary_node_pool_max_count     = 5
primary_node_pool_initial_count = 1
primary_node_pool_disk_type     = "pd-standard"

# GPU pool: L4 required for 7B+ model weights
# Note: g2-standard-8 (L4) available in europe-west1-b, europe-west1-c
enable_gpu_node_pool        = true
gpu_type                    = "nvidia-l4"
gpu_count                   = 1
gpu_node_pool_machine_type  = "g2-standard-8"
gpu_node_pool_min_count     = 0  # cost-opt: scale to zero when idle; cluster autoscaler removes node after ~10 min of no GPU pod
gpu_node_pool_max_count     = 2
gpu_node_pool_initial_count = 1
gpu_node_pool_name          = "gpu-node-pool-nvidia-l4"
gpu_node_pool_spot          = true
gpu_node_locations          = ["europe-west1-b", "europe-west1-c", "europe-west1-d"]

# ─── Storage (Dev: Smaller, EEA-resident) ─────────────────────────────────────
storage_class           = "standard-rwo"
postgres_storage_size   = "10Gi"
redis_storage_size      = "2Gi"
clickhouse_storage_size = "10Gi"
model_bucket_name       = "" # Defaults to ${project_id}-models (created in europe-west1)

# ─── Container Registry ───────────────────────────────────────────────────────
registry_url = "" # Defaults to gcr.io/${project_id}

# ─── GCP Features ─────────────────────────────────────────────────────────────
enable_gcs_fuse_csi = true

# ─── Deployment ───────────────────────────────────────────────────────────────
force_redeploy = true

# ─── Services ─────────────────────────────────────────────────────────────────
enable_vllm              = true
enable_compliance_bridge = true
enable_nemo_guardrails   = true

vllm_gpu_count = 1
vllm_replicas  = 1

nemo_image = ""

presidio_analyzer_image   = "mcr.microsoft.com/presidio-analyzer:latest"
presidio_anonymizer_image = "mcr.microsoft.com/presidio-anonymizer:latest"

# ─── Langfuse (EU: NextAuth URL reflects EU cluster endpoint) ─────────────────
# Update langfuse_nextauth_url to the actual EU cluster ingress URL after deploy
langfuse_nextauth_url = "http://localhost:3000"

# ─── Langfuse S3-compatible storage (EU: GCS bucket in europe-west1) ──────────
# GCS HMAC keys and bucket are created in europe-west1 via var.region above.
# The bucket name is auto-generated: langfuse-events-${project_id}-${random_hex}
langfuse_s3_endpoint = "https://storage.googleapis.com"
langfuse_s3_bucket   = "" # Auto-generated from GCS bucket resource
langfuse_s3_access_key = "" # Auto-generated from google_storage_hmac_key
langfuse_s3_secret_key = "" # Auto-generated from google_storage_hmac_key
