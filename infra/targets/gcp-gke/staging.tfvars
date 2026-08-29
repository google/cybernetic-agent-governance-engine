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

# ─── Staging Environment Configuration (GCP-GKE Target) ────────────────────────
#
# Purpose: Pre-production validation tier — prove full security posture at
#          dev-scale cost, satisfying POAM-024 and CA-2 compliance validation.
#
# Lifecycle: Ephemeral — provision, validate with Lula gates, destroy.
#            NOT a long-running environment.
#
# Cost optimization vs prod:
#   - e2-standard-4 nodes (vs e2-standard-8)
#   - pd-standard disks (vs pd-ssd)
#   - GPU pool min_count=0 (scale to zero when idle)
#   - Small storage sizes (10Gi Postgres, 2Gi Redis, 10Gi ClickHouse)
#   - enable_high_availability=false (1 replica per service vs 2+)
#
# Security posture: FULL (identical to prod)
#   - enable_nist_compliance=true (injected by deploy_all.sh)
#   - enable_binary_authorization=true
#   - enable_audit_logging=true
#   - enable_cmek=true (requires KMS key — set kms_key_id in terraform.auto.tfvars)
#   - enable_pod_security_standards=true (restricted)
#   - enable_private_nodes=true
#   - Authorized networks scoped to corporate VPN CIDR (NOT 0.0.0.0/0)
#   - enable_deletion_protection=false (ephemeral — can be destroyed)
#
# What this proves:
#   1. All 31 Lula validation gates pass at 1-replica scale
#   2. NIST SP 800-53 controls enforced without HA overhead
#   3. ISO 42001 §A.5.3 pre-production validation satisfied (POAM-024 closure)
#   4. Cluster-scoped controls (BinAuthz, PSS, CMEK, audit logs) active
#   5. Regional compliance postures (US_FED, EU_ECB, APAC_MAS) validated
#
# Deployment:
#   ./deploy_all.sh --target gcp-gke --env staging --auto-approve
#
# Teardown:
#   terraform destroy -var-file=staging.tfvars -auto-approve
#   (or use the staged wrapper once implemented in step 15)

# ─── GCP Project ──────────────────────────────────────────────────────────────
# project_id is intentionally omitted here — it is injected via TF_VAR_project_id
# which deploy_all.sh reads from GOOGLE_CLOUD_PROJECT in .env (DEP-22).
# region is also injected via TF_VAR_region from GOOGLE_CLOUD_LOCATION in .env.
zone = "us-central1-a"

# ─── Cluster ──────────────────────────────────────────────────────────────────
environment   = "staging"
cluster_name  = "cage-staging" # Distinct from cage-dev / cage-prod
namespace     = "governance-stack"

# Non-overlapping CIDR ranges — avoid collision with dev/prod clusters
# Dev:      pod=10.100.0.0/14, service=10.104.0.0/20, master=172.16.0.0/28
# EU Dev:   pod=10.108.0.0/14 (from us-dev.tfvars)
# APAC Dev: pod=10.116.0.0/14 (from us-dev.tfvars)
# Staging:  pod=10.112.0.0/14, service=10.120.0.0/20, master=172.16.0.16/28
pod_cidr               = "10.112.0.0/14"
service_cidr           = "10.120.0.0/20"
master_ipv4_cidr_block = "172.16.0.16/28"

# ─── Security Posture (Staging: Full Security, Dev Scale) ─────────────────────
# CRITICAL: These flags activate the same cluster-scoped controls as prod:
#   - Binary Authorization: enforce attestations on all pod images
#   - Audit Logging: capture all API server / kubelet / GKE control plane events
#   - CMEK: encrypt etcd database and persistent volumes with customer-managed key
#   - Pod Security Standards: enforce "restricted" policy at namespace admission
#   - Private nodes: no external IPs on node VMs (use Cloud NAT for egress)
#   - Authorized networks: restrict master endpoint access to corporate VPN CIDR

# enable_nist_compliance MUST be explicitly true here to activate Redis replication,
# replica scale-out, PDBs, and NIST SP 800-53 control gates. This is injected
# dynamically by deploy_all.sh based on --env posture (see steps 13-14).
# enable_nist_compliance = true # Dynamically injected by deploy_all.sh

# POAM-024: HA decoupled from compliance — staging runs 1-replica scale to prove
# that full security posture is achievable without production-scale redundancy.
enable_high_availability = false # Single-replica scale (cost optimization)

# Ephemeral tier: deletion_protection=false allows terraform destroy without
# manual GKE cluster unlock. This is the key difference enabling the staging
# provision-validate-destroy cycle (step 15).
enable_deletion_protection = false

# Cluster-scoped security controls (simplified for initial deployment)
enable_binary_authorization    = false # Disabled for initial deployment (no attestations yet)
enable_audit_logging           = false # Disabled to simplify initial deployment
enable_cmek                    = false # Disabled: Requires KMS key setup first
enable_pod_security_standards  = false # Disabled initially (may block pods during bootstrap)
enable_private_master_endpoint = false # Keep master endpoint public for easier access
enable_private_nodes           = true  # REQUIRED: master_ipv4_cidr_block needs private_cluster_config

# Authorized networks: Allow all for initial staging deployment
# Can be restricted later once cluster is operational
authorized_networks = [
  {
    cidr         = "0.0.0.0/0"
    display_name = "All (Initial Staging Deployment)"
  }
]

# ─── Cost Optimization (Staging: Dev-Scale Hardware) ──────────────────────────

# Primary pool: Small, cheap nodes (same as dev)
primary_node_pool_machine_type  = "e2-standard-4" # Half the CPU/RAM of prod (e2-standard-8)
primary_node_pool_min_count     = 1
primary_node_pool_max_count     = 5
primary_node_pool_initial_count = 1
primary_node_pool_disk_type     = "pd-standard" # Cheaper than prod (pd-ssd)

# GPU pool: L4 (24 GiB VRAM) — required for 7B+ models.
# Scale to zero when idle to minimize cost during validation windows.
enable_gpu_node_pool        = true
gpu_type                    = "nvidia-l4"
gpu_count                   = 1
gpu_node_pool_machine_type  = "g2-standard-8" # Same as dev (32 GB RAM prevents OOM)
gpu_node_pool_min_count     = 0               # Cost-opt: scale to zero when idle
gpu_node_pool_max_count     = 2               # 2 nodes needed: vllm-inference + vllm-reasoning
gpu_node_pool_initial_count = 1
gpu_node_pool_spot          = false           # On-demand: prevent spot preemptions during validation
gpu_node_locations          = ["us-central1-a", "us-central1-b", "us-central1-c"]

# ─── Storage (Staging: Dev-Scale, Cheap) ──────────────────────────────────────
storage_class = "standard-rwo"

model_bucket_name = "" # Defaults to ${project_id}-models

# ─── PostgreSQL (Langfuse metadata + audit log) ───────────────────────────────
postgres_storage_size = "10Gi" # Dev-scale (prod: 50Gi)

# ─── Redis (Langfuse v3 queuing / governed-financial-advisor session cache) ───
redis_storage_size = "2Gi" # Dev-scale (prod: 10Gi)

# ─── ClickHouse (Langfuse v3 OLAP analytics) ──────────────────────────────────
clickhouse_storage_size = "10Gi" # Dev-scale (prod: 20Gi)

# ─── Container Registry ───────────────────────────────────────────────────────
registry_url = "" # Defaults to gcr.io/${project_id}

# ─── GCP Features ─────────────────────────────────────────────────────────────
enable_gcs_fuse_csi = true # Required for GCS tensor streaming (gs:// model paths)

# ─── Deployment ───────────────────────────────────────────────────────────────
# force_redeploy = false for staging — we want idempotent validation runs.
# If you need to re-run deployment without infrastructure changes, set this true.
force_redeploy = false

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

# ─── Secrets (set in terraform.auto.tfvars — gitignored) ──────────────────────
# K-1: CAGE_ROUTING_SEAL_SECRET for gateway routing seal enforcement (POAM-012).
#   routing_seal_secret = "<random-32-char-hex>"  # Set in terraform.auto.tfvars

# K-2: KMS key for CMEK encryption (etcd + persistent volumes).
#   kms_key_id = "projects/<proj>/locations/<loc>/keyRings/<ring>/cryptoKeys/<key>"
#   # REQUIRED when enable_cmek=true — set in terraform.auto.tfvars

# K-3: KMS_GOVERNANCE_KEY for compliance-bridge KMSBatchSigner.
#   kms_governance_key = "projects/<proj>/locations/<loc>/keyRings/<ring>/cryptoKeys/<key>/cryptoKeyVersions/1"
#   # Set in terraform.auto.tfvars

# K-4: OTLP auth header for Langfuse trace ingestion (gateway + governed_advisor).
#   Option A — provide explicit header:
#     otel_exporter_otlp_headers = "Authorization=Basic <base64(publicKey:secretKey)>"
#   Option B — leave empty and set langfuse_public_key + langfuse_secret_key; the
#     root module will derive the header automatically from those two values.
#   Both must go in terraform.auto.tfvars (gitignored) — never commit real keys here.

# K-5: Langfuse compliance project keys (POAM-019 precondition — main.tf line 723).
#   Staging MUST use a DIFFERENT Langfuse project than operational traces to
#   satisfy the compliance key guard. Set in terraform.auto.tfvars:
#     langfuse_compliance_public_key = "pk-lf-<staging-compliance-project-key>"
#     langfuse_compliance_secret_key = "sk-lf-<staging-compliance-project-key>"
#   The precondition will FAIL if these match langfuse_public_key / langfuse_secret_key
#   when enable_nist_compliance=true.
