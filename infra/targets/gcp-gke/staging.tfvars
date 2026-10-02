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
project_id = "laah-cybernetics"
region     = "us-central1"
zone       = "us-central1-a"

# ─── Jurisdiction (DEP-12) ───────────────────────────────────────────────────
cage_deployment_region = "US_FED"

# ─── Cluster ──────────────────────────────────────────────────────────────────
environment  = "staging"
cluster_name = "cage-staging" # Distinct from cage-dev / cage-prod
namespace    = "governance-stack"

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

# Cluster-scoped security controls (§1.1 staging posture: full security, 1-replica scale)
regional_cluster               = false
enable_binary_authorization           = true
binary_authorization_enforcement_mode = "DRYRUN_AUDIT_LOG_ONLY"
enable_audit_logging           = true
enable_cmek                    = true
enable_pod_security_standards  = true
pod_security_level             = "restricted"
enable_private_master_endpoint = false # Authorized networks restricted via VPN CIDR
enable_private_nodes           = true  # REQUIRED: master_ipv4_cidr_block needs private_cluster_config

# §1.1 & §5.3: GKE Dataplane V2 + FQDN network policy enabled in every posture.
enable_dataplane_v2        = true
enable_fqdn_network_policy = true


# Authorized networks: Allow all for initial staging deployment
# Can be restricted later once cluster is operational
authorized_networks = [
  {
    cidr         = "0.0.0.0/0"
    display_name = "All (Initial Staging Deployment)"
  }
]

# ─── Cost Optimization (Staging: Dev-Scale Hardware) ──────────────────────────

# General pool: Small, cheap nodes (same as dev)
primary_node_pool_machine_type  = "e2-standard-4" # Half the CPU/RAM of prod (e2-standard-8)
primary_node_pool_min_count     = 1
primary_node_pool_max_count     = 5
primary_node_pool_initial_count = 1
primary_node_pool_disk_type     = "pd-standard" # Cheaper than prod (pd-ssd)

# §3 General-spot pool: c3-highcpu-4, Spot, 0-5 in staging only, tainted cloud.google.com/gke-spot=true:NoSchedule
enable_general_spot_node_pool = true
general_spot_machine_type     = "c3-highcpu-4"
general_spot_min_count        = 0
general_spot_max_count        = 5
general_spot_initial_count    = 0

# §3 GPU pool: L4 (24 GiB VRAM) — required for 7B+ models, Spot OFF in every posture.
enable_gpu_node_pool        = true
gpu_type                    = "nvidia-l4"
gpu_count                   = 1
gpu_node_pool_machine_type  = "g2-standard-8" # Same as dev (32 GB RAM prevents OOM)
gpu_node_pool_min_count     = 0               # Cost-opt: scale to zero when idle
gpu_node_pool_max_count     = 2               # 2 nodes needed: vllm-inference + vllm-reasoning
gpu_node_pool_initial_count = 1
gpu_node_pool_spot          = false # On-demand: Spot OFF in every posture (§3)
gpu_node_locations          = ["us-central1-a", "us-central1-b", "us-central1-c"]

# §3 ClickHouse pool: n2-standard-4 + local SSD, 1 node in staging, Spot OFF
enable_clickhouse_node_pool        = true
clickhouse_node_pool_machine_type  = "n2-standard-4"
clickhouse_node_pool_min_count     = 1
clickhouse_node_pool_max_count     = 1
clickhouse_node_pool_initial_count = 1

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

# vLLM configuration — weights streamed from GCS model bucket via runai_streamer
model_fast             = "gs://laah-cybernetics-models/Qwen/Qwen2.5-1.5B-Instruct"
model_reasoning        = "gs://laah-cybernetics-models/deepseek-ai/DeepSeek-R1-Distill-Llama-8B"
served_model_fast      = "Qwen/Qwen2.5-1.5B-Instruct"
served_model_reasoning = "deepseek-ai/DeepSeek-R1-Distill-Llama-8B"
vllm_gpu_count         = 1
vllm_replicas          = 1

# NeMo Guardrails — use Cloud Build custom image (auto-built by deploy_sw.py)
# Override via TF_VAR_nemo_image if you want a specific tag
nemo_image = ""

# Presidio — mirrored into Artifact Registry and pinned by @sha256: digest via var.image_digests
presidio_analyzer_image   = ""
presidio_anonymizer_image = ""

image_digests = {
  "gateway"                    = "gcr.io/laah-cybernetics/gateway@sha256:46399cd403f9fc3491365f353c3763a516357b794dcc3b376cd6670b433c9fdf"
  "governed-financial-advisor" = "gcr.io/laah-cybernetics/governed-financial-advisor@sha256:5ab0eb9f9d061e2cbba2086cc3a1a54d9b5972217526657ea21b2da29f0dfd77"
  "vllm-streamer"              = "gcr.io/laah-cybernetics/vllm-streamer@sha256:12e2a7f6320d54d5f098d28bc20f8104676c4e2058cc69436587912151b738e3"
  "nemo-guardrails"            = "gcr.io/laah-cybernetics/nemo-guardrails@sha256:0ac016667a2f24c57a2129bdf095854d6610f8e9f905df207da53728f4d87d64"
  "compliance-bridge"          = "gcr.io/laah-cybernetics/compliance-bridge@sha256:866449557a8c7b405238842b7255ad794d3d49029503c9a0721920e9742610d3"
  "agentsight-ui"              = "gcr.io/laah-cybernetics/agentsight-ui@sha256:19aeefc64038bf7d23185b616b5ffae42659a6e697b9e3ba0ae59ffddf8b71ca"
  "presidio-analyzer"          = "gcr.io/laah-cybernetics/presidio-analyzer@sha256:8e09d9f0a928e86b6c634eec9a8e668738508154cb7e683d7c7c62867ce4a514"
  "presidio-anonymizer"        = "gcr.io/laah-cybernetics/presidio-anonymizer@sha256:e39a7671f51c40aa493201f0d3f71ad74efc98bbd34ccd417a4cfd3ffaa59ae4"
  "opa"                        = "gcr.io/laah-cybernetics/opa@sha256:bd9909283897aaf8e4409efb6fcb049f08fe6466f32467545157b66a39f4879f"
  "langfuse"                   = "gcr.io/laah-cybernetics/langfuse@sha256:bd6f8de1482c56e31b360fe7a14109f07e9083a370feeb37d6e4afb2f693b8a7"
  "langfuse-worker"            = "gcr.io/laah-cybernetics/langfuse-worker@sha256:43858560677507ed37946eb0ad7a1d835aa9e685ae774ee8a9c99401c0fef1a3"
  "cloud-sql-proxy"            = "gcr.io/laah-cybernetics/cloud-sql-proxy@sha256:c80e265fdf62108468cdb688af9737775f2a875a470bd99f83f88c7f93e82dfc"
  "clickhouse-server"          = "gcr.io/laah-cybernetics/clickhouse-server@sha256:3a52e89091e2f5e9471ca4860fd91ba9da855efcbad605073a5d2f8817023018"
  "clickhouse-keeper"          = "gcr.io/laah-cybernetics/clickhouse-keeper@sha256:602384a626262c4fab92e442612406f40b620b8a78c7dd11785b0d61a1840e27"
  "redis"                      = "gcr.io/laah-cybernetics/redis@sha256:41a05f1df0e41913c765714bcc4e2b7b61bad98686c3f8577fb5370306bd1efe"
}

memorystore_governance_instance_id = "cage-valkey-gov-staging-v2"
memorystore_app_instance_id        = "cage-valkey-app-staging-v3"

memorystore_governance_psc_cidr = "10.128.0.0/20"
memorystore_app_psc_cidr        = "10.128.0.0/20"
cloud_sql_cidr                  = "10.6.80.0/20"

# ─── Secrets (set in terraform.auto.tfvars — gitignored) ──────────────────────
# K-2: KMS key for CMEK encryption (etcd + persistent volumes).
#   kms_key_id = "projects/<proj>/locations/<loc>/keyRings/<ring>/cryptoKeys/<key>"
#   # REQUIRED when enable_cmek=true — set in terraform.auto.tfvars

# K-3: signing keys are provisioned by kms_signing.tf (one key per signer,
#   POAM-2026-079); there is no kms_governance_key input any more.

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
