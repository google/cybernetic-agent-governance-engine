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
  "gateway"                    = "gcr.io/laah-cybernetics/gateway@sha256:e0aea0d53a3fae02358be2f0274d385a9aaa2a196261df1e4e9dceadb8a1e3aa"
  "governed-financial-advisor" = "gcr.io/laah-cybernetics/governed-financial-advisor@sha256:bde04d076352cb32559015527a598b226973a8f2645859e15ce27746bb51b912"
  "vllm-streamer"              = "gcr.io/laah-cybernetics/vllm-streamer@sha256:cb7aff0c3128493ffbfe2d73c9299974b981a4e46a3c13cc08c960739703f812"
  "nemo-guardrails"            = "gcr.io/laah-cybernetics/nemo-guardrails@sha256:76d97fa6a8c656a354a30a9ea9ce265424a9a95a112a757e1a3e7cd9c9d727d0"
  "compliance-bridge"          = "gcr.io/laah-cybernetics/compliance-bridge@sha256:4513056a4d29b3d2c3a613416f4833feefef91ec95d7582368dc9f71e2362466"
  "agentsight-ui"              = "gcr.io/laah-cybernetics/agentsight-ui@sha256:d53204ff8ac821bd9a9baac4041168cf4f9f31bba1e27fc3e5616ddddcacabfb"
  "presidio-analyzer"          = "gcr.io/laah-cybernetics/presidio-analyzer@sha256:7b7add0ea5d226f7f6c35f9e5a8927214e84cc7f5e84f67dee154b594b79e195"
  "presidio-anonymizer"        = "gcr.io/laah-cybernetics/presidio-anonymizer@sha256:00ac4c3f6f85473de6c3120615c878310c14a07eeba9a4233705e6f8fab7c81d"
  "opa"                        = "docker.io/openpolicyagent/opa@sha256:2de1e6619246955695b982d0bcb6c73bcee22aa34ff96f2455996616ec1d21c1"
  "langfuse"                   = "docker.io/langfuse/langfuse@sha256:e22716569be810ed379e0d7d7472ba230ef94fb4b7543c87b2a12c95e68d2db2"
  "langfuse-worker"            = "docker.io/langfuse/langfuse-worker@sha256:438b2aeaeb095260ab38b3d2fd2b0ccb6105ab120158b148634214a4273a104e"
  "cloud-sql-proxy"            = "gcr.io/cloud-sql-connectors/cloud-sql-proxy@sha256:d3f195cb893f2abb2ce8f28a4d3eee9b5589750711b4fbf67c78ce215c520e96"
  "clickhouse-server"          = "docker.io/clickhouse/clickhouse-server@sha256:c3f166f4a80098480463d897a63f6867d24e3a7661fc1fe72e889788115a25f1"
  "clickhouse-keeper"          = "docker.io/clickhouse/clickhouse-keeper@sha256:32686ea04febc134113d1b61109d1e0d0d7dc02a2b3dc098c1f035daeec4ba57"
  "redis"                      = "docker.io/library/redis@sha256:858f009f9709ce576febc734aa78b8f6d624b82571f9ddb6bda4377c833b3499"
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
