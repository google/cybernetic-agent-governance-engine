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

# ─── US FED Development Environment Configuration (GCP-GKE Target) ─────────────
#
# Jurisdiction: United States
# Primary framework: SR 26-2 (Model Risk Management for Agentic AI Systems)
# Co-frameworks: SR 11-7 (legacy MRM baseline), ISO/IEC 42001:2023,
#   NIST AI RMF 1.0, NIST SP 800-53 Rev 5
#
# Activate: ./deploy_all.sh --target gcp-gke --env us-dev --auto-approve
#
# What this profile enforces automatically (no code changes required):
#   - Confidence threshold: 0.95 — SR 26-2 §IV.B / ISO 42001 §A.5.2
#   - Drawdown limit: 5% — SR 26-2 Non-Determinism Containment
#   - CBF gamma: 0.5 — NIST AI RMF GOVERN-5 safety filter
#   - Consensus threshold: $10,000 — SR 26-2 §IV human-in-the-loop
#   - UCA-5 drawdown block: 4.5% — SR 26-2 STPA unsafe control action
#   - UCA-6 max order volume: 1% daily vol — SR 26-2 market impact limit
#   - Max sell fraction: 10% portfolio — SR 26-2 concentration risk
#   - Max latency: 200ms — NIST SP 800-53 SI-17 operational resilience
#   - FRIA attestation: DISABLED — EU-only control (EU AI Act Art. 29a)
#   - SR 26-2 on OTel spans: ACTIVE — primary US prudential framework
#   - OSCAL framework: NIST_SP800_53 (vs EU_AI_ACT / MAS_FEAT)
#   - Prompt injection keywords: BYPASS GOVERNANCE, IGNORE POLICY
#
# Data residency: us-central1 (Iowa, USA) — SR 26-2 / OCC data localisation.
# All Langfuse traces, GCS audit buckets, and PostgreSQL data remain within US.
# DO NOT change region to a non-US location without OCC/Fed approval and a
# revised data governance attestation.
#
# External legal requirements (not automated — must be completed separately):
#   1. SR 26-2 Model Inventory registration (MRM team sign-off)
#   2. SR 11-7 independent model validation report (non-agentic components)
#   3. ISO 42001 §A.9 AI system performance monitoring plan
#   4. NIST AI RMF GOVERN-1 organisational AI risk policy attestation
#   5. OCC Bulletin 2021-38 third-party risk management review (vLLM / NeMo)

# ─── GCP Project ──────────────────────────────────────────────────────────────
# REPLACE with your US GCP project ID (may be same project as generic dev)
project_id = "YOUR_GCP_PROJECT_ID"

# US data residency — SR 26-2 / OCC data localisation
# us-central1 = Iowa (USA) | us-east1 = South Carolina (USA)
region = "us-central1"
zone   = "us-central1-a"

# ─── Cluster ──────────────────────────────────────────────────────────────────
# cluster_name MUST match the existing GKE cluster in Terraform state ("cage-dev").
# Changing this value forces a destroy+recreate of the cluster — explicitly
# prohibited by the "no GKE hardware changes" constraint.
# The existing cluster was provisioned by dev.tfvars as "cage-dev"; keep it.
cluster_name = "cage-dev"
environment  = "dev"
namespace    = "governance-stack"

# US CIDR ranges — match the existing cluster's provisioned ranges exactly.
# Changing these would also force cluster replacement.
# Non-overlapping with EU dev (10.108.0.0/14) and APAC dev (10.116.0.0/14).
pod_cidr               = "10.100.0.0/14"
service_cidr           = "10.104.0.0/20"
master_ipv4_cidr_block = "172.16.0.0/28"

# ─── Jurisdiction ─────────────────────────────────────────────────────────────
# Activates US_FED_BASELINE.json (compliance) + US_FED_BASELINE.json (thresholds)
# Injected into advisor-secrets K8s Secret → all pods via envFrom
cage_deployment_region = "US_FED"

# ─── Security Posture (Dev: Minimal — fast iteration, low cost) ───────────────
# Dev posture intentionally disables ALL hardening flags to reduce cost and friction.
# SR 26-2 §IV.C requires these controls in PROD; they are NOT required in dev.
# enable_nist_compliance MUST be explicitly false here to prevent Redis replication,
# replica scale-out, and PDB creation that the NIST path triggers automatically.
enable_nist_compliance         = false  # Dev posture — standalone Redis, 1 replica
enable_binary_authorization    = false
enable_audit_logging           = false  # Enable in prod: SR 26-2 §IV.D / AU-2
enable_cmek                    = false  # Enable in prod: SC-12 / SC-13
enable_private_master_endpoint = false  # Enable in prod: SC-7 / AC-17
# GCP org policy constraints/compute.vmExternalIpAccess blocks external IPs on
# node VMs. Enable private nodes so nodes use Cloud NAT (nat-router-us-central1)
# for egress instead. Master endpoint remains public (kubectl access preserved).
enable_private_nodes           = true
enable_pod_security_standards  = false  # Apply manually via pod-security-admission.yaml

# US Dev: open access (prod must restrict to corporate VPN CIDR)
# SR 26-2 §IV.C — access controls; restrict to known CIDRs in prod
authorized_networks = [
  {
    cidr         = "0.0.0.0/0"
    display_name = "Allow All (US Dev Only — restrict in prod)"
  }
]

# ─── Node Pool Configuration (NO hardware changes — matches existing cluster) ──
# These values are intentionally identical to dev.tfvars to prevent GKE node
# pool replacement on existing infrastructure.  Change only in a new cluster.
primary_node_pool_machine_type  = "e2-standard-4"
primary_node_pool_min_count     = 1
primary_node_pool_max_count     = 5
primary_node_pool_initial_count = 1
primary_node_pool_disk_type     = "pd-standard"

# GPU pool: L4 (24 GiB VRAM) — required for 7B+ model weights.
# T4 (16 GiB) cannot fit model weights (14.25 GiB) + KV cache.
# g2-standard-8 (32 GB RAM) prevents OOM eviction during 15 GB weight loading.
enable_gpu_node_pool        = true
gpu_type                    = "nvidia-l4"
gpu_count                   = 1
gpu_node_pool_machine_type  = "g2-standard-8"
gpu_node_pool_min_count     = 1
gpu_node_pool_max_count     = 2
gpu_node_pool_initial_count = 1
gpu_node_pool_spot          = true  # Spot VMs for dev cost optimisation
gpu_node_locations          = ["us-central1-a", "us-central1-b", "us-central1-c"]

# ─── Storage (Dev: Smaller, US-resident) ──────────────────────────────────────
storage_class           = "standard-rwo"
postgres_storage_size   = "10Gi"   # Dev: small; prod default is 50Gi
redis_storage_size      = "2Gi"    # Dev: small; prod default is 10Gi
clickhouse_storage_size = "10Gi"   # Dev: small; prod default is 20Gi
model_bucket_name       = ""       # Defaults to ${project_id}-models (us-central1)

# ─── Container Registry ───────────────────────────────────────────────────────
registry_url = "" # Defaults to gcr.io/${project_id}

# ─── GCP Features ─────────────────────────────────────────────────────────────
enable_gcs_fuse_csi = true # Required for GCS tensor streaming (gs:// model paths)

# ─── Deployment ───────────────────────────────────────────────────────────────
# force_redeploy = true ensures Terraform always re-runs the app deployment
# (null_resource.app_deployment provisioner) on every apply, even when no
# infrastructure has changed.  Correct behaviour for dev iteration.
force_redeploy = true

# ─── Services ─────────────────────────────────────────────────────────────────
enable_vllm              = true
enable_compliance_bridge = true
enable_nemo_guardrails   = true
# SLM runs as a sidecar inside the governed-financial-advisor pod (no standalone module)

# vLLM configuration — model names pulled from .env via TF_VAR_model_fast / TF_VAR_model_reasoning
# DO NOT hardcode model names here — use .env MODEL_FAST and MODEL_REASONING instead
vllm_gpu_count = 1
vllm_replicas  = 1

# NeMo Guardrails — use Cloud Build custom image (auto-built by deploy_sw.py)
# Override via TF_VAR_nemo_image if you want a specific tag
nemo_image = ""

# Presidio — use Microsoft public images
presidio_analyzer_image   = "mcr.microsoft.com/presidio-analyzer:latest"
presidio_anonymizer_image = "mcr.microsoft.com/presidio-anonymizer:latest"

# ─── Langfuse (US: NextAuth URL reflects US cluster endpoint) ─────────────────
# Update langfuse_nextauth_url to the actual US cluster ingress URL after deploy
langfuse_nextauth_url = "http://localhost:3000"

# ─── Langfuse S3-compatible storage (US: GCS bucket in us-central1) ───────────
# GCS HMAC keys and bucket are created in us-central1 via var.region above.
# The bucket name is auto-generated: langfuse-events-${project_id}-${random_hex}
langfuse_s3_endpoint   = "https://storage.googleapis.com"
langfuse_s3_bucket     = "" # Auto-generated from GCS bucket resource
langfuse_s3_access_key = "" # Auto-generated from google_storage_hmac_key
langfuse_s3_secret_key = "" # Auto-generated from google_storage_hmac_key

# ─── Langfuse Project Configuration (Dev: single project is sufficient) ────────
# Dev posture intentionally uses ONE Langfuse project ("cybernetic-governance")
# for both operations traces and compliance audit scores.
#
# Rationale (P1-2):
#   - US_FED_BASELINE.json controls (CTRL_AGT_001–CTRL_OPA_005) do NOT mandate
#     Langfuse project isolation in dev. AU-9 / SR 26-2 §IV.D are prod-only controls.
#   - enable_nist_compliance=false → the compliance_secrets precondition is skipped.
#   - The compliance bridge _make_compliance_langfuse() guard in audit_workflow.py
#     detects when LANGFUSE_COMPLIANCE_PUBLIC_KEY == LANGFUSE_PUBLIC_KEY and skips
#     Step 3 (OSCAL score ingestion) to prevent circular evidence contamination.
#   - LANGFUSE_COMPLIANCE_PUBLIC_KEY and LANGFUSE_COMPLIANCE_SECRET_KEY are injected
#     from .env via TF_VAR_* exports in deploy_all.sh. If the cage-compliance project
#     keys are set in .env (as they are in this deployment), the compliance bridge
#     will use the real cage-compliance project even in dev — providing full isolation.
#
# For prod posture: set LANGFUSE_COMPLIANCE_PUBLIC_KEY to a DIFFERENT key than
# LANGFUSE_PUBLIC_KEY. The Terraform precondition in app_secrets/main.tf will
# FAIL the plan if they are the same or empty when enable_nist_compliance=true.
#
# Keys are NOT hardcoded here — they are injected via TF_VAR_* from .env.
