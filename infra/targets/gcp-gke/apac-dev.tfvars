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

# ─── APAC MAS Development Environment Configuration (GCP-GKE Target) ──────────
#
# Jurisdiction: Singapore / APAC
# Primary framework: MAS FEAT Principles (Fairness, Ethics, Accountability,
#   Transparency) — November 2019
# Co-frameworks: MAS Notice 655, MAS TRM Guidelines, ISO 42001, NIST AI RMF
#
# Activate: ./deploy_all.sh --target gcp-gke --env apac-dev --auto-approve
#
# What changes automatically vs US_FED (no code changes required):
#   - Confidence threshold: 0.96 (vs 0.95 US) — MAS FEAT F1 reliability
#   - Drawdown limit: 4.5% (vs 5% US) — MAS ICAAP calibration
#   - CBF gamma: 0.55 (vs 0.5 US) — intermediate safety filter
#   - Consensus threshold: $8,500 (vs $10,000 US) — MAS FEAT A1 human oversight
#   - UCA-5 drawdown block: 4.0% (vs 4.5% US)
#   - UCA-6 max order volume: 0.8% daily vol (vs 1% US) — SGX Securities Act
#   - Max sell fraction: 9% portfolio (vs 10% US) — MAS orderly market conduct
#   - Max latency: 175ms (vs 200ms US) — MAS TRM §7.2
#   - FIA (Fairness Impact Assessment): ENABLED — MAS FEAT F1/F2 (6-month cycle)
#   - SR 26-2 on OTel spans: SUPPRESSED — "no legal force" sentinel active
#   - OSCAL framework: MAS_FEAT (vs NIST_SP800_53 US)
#   - Prompt injection keywords: +BYPASS FEAT CHECKS, +IGNORE FAIRNESS ASSESSMENT
#
# Data residency: asia-southeast1 (Singapore) — MAS TRM Guidelines §4.2.
# MAS expects financial data to be processed within Singapore or an approved
# jurisdiction. asia-southeast1 is the MAS-approved GCP region.
# DO NOT change region without a formal MAS outsourcing arrangement notification.
#
# External legal requirements (not automated — must be completed separately):
#   1. MAS FEAT Fairness Impact Assessment (FIA) — quantitative bias metrics
#   2. MAS Notice 655 material AI system deployment notification
#   3. MAS TRM §6.3 AI governance framework submission
#   4. MAS FEAT Transparency Report (T2) — 6-month cycle
#   5. SGX Securities and Futures Act compliance review

# ─── GCP Project ──────────────────────────────────────────────────────────────
# REPLACE with your APAC GCP project ID (may be same project as US dev)
project_id = "YOUR_GCP_PROJECT_ID"

# MAS TRM §4.2 data residency — Singapore
# asia-southeast1 = Singapore (MAS-approved jurisdiction)
region = "asia-southeast1"
zone   = "asia-southeast1-a"

# ─── Cluster ──────────────────────────────────────────────────────────────────
cluster_name = "cage-apac-dev"
environment  = "dev"
namespace    = "governance-stack"

# APAC CIDR ranges — non-overlapping with US dev (10.100.0.0/14) and EU dev (10.108.0.0/14)
pod_cidr               = "10.116.0.0/14"
service_cidr           = "10.120.0.0/20"
master_ipv4_cidr_block = "172.16.2.0/28"

# ─── Jurisdiction ─────────────────────────────────────────────────────────────
# Activates APAC_MAS_BASELINE.json (compliance) + APAC_MAS_BASELINE.json (thresholds)
# Injected into advisor-secrets K8s Secret → all pods via envFrom
cage_deployment_region = "APAC_MAS"

# ─── Security Posture (APAC Dev: Audit logging required by MAS Notice 655) ────
# MAS Notice 655 §10 mandates audit logging for all AI system operations.
# MAS TRM Guidelines §6.4 requires continuous monitoring of AI model performance.
enable_binary_authorization    = false
enable_audit_logging           = true  # MAS Notice 655 §10 — mandatory
enable_cmek                    = false
enable_private_master_endpoint = false
enable_pod_security_standards  = false # Apply manually via pod-security-admission.yaml

# SECURITY (C-06): Restrict to RFC 1918 private ranges only.
# Never use 0.0.0.0/0 — it exposes the GKE API server to the internet.
# Replace 10.0.0.0/8 with your VPN/office CIDR ranges before deploying.
# Example: authorized_networks = [{ cidr = "203.0.113.0/24", display_name = "SG VPN" }]
# MAS TRM §4.2 — access controls for financial data systems
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
# Note: g2-standard-8 (L4) available in asia-southeast1-b, asia-southeast1-c
enable_gpu_node_pool        = true
gpu_type                    = "nvidia-l4"
gpu_count                   = 1
gpu_node_pool_machine_type  = "g2-standard-8"
gpu_node_pool_min_count     = 1
gpu_node_pool_max_count     = 2
gpu_node_pool_initial_count = 1
gpu_node_pool_name          = "gpu-node-pool-nvidia-l4"
gpu_node_pool_spot          = true
gpu_node_locations          = ["asia-southeast1-a", "asia-southeast1-b", "asia-southeast1-c"]

# ─── Storage (Dev: Smaller, Singapore-resident) ────────────────────────────────
storage_class           = "standard-rwo"
postgres_storage_size   = "10Gi"
redis_storage_size      = "2Gi"
clickhouse_storage_size = "10Gi"
model_bucket_name       = "" # Defaults to ${project_id}-models (created in asia-southeast1)

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
