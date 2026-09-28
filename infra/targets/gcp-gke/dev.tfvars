# Development Environment Configuration (GCP-GKE Target)
# Fast iteration, minimal costs, low security posture

# ─── GCP Project ──────────────────────────────────────────────────────────────
# project_id is intentionally omitted here — it is injected via TF_VAR_project_id
# which deploy_all.sh reads from GOOGLE_CLOUD_PROJECT in .env (DEP-22).
# region is also injected via TF_VAR_region from GOOGLE_CLOUD_LOCATION in .env.
zone       = "us-central1-a" # Current cluster location

# ─── Cluster ──────────────────────────────────────────────────────────────────
environment = "dev"

# Matches existing governance-cluster to prevent replacement
pod_cidr               = "10.100.0.0/14"
service_cidr           = "10.104.0.0/20"
master_ipv4_cidr_block = "172.16.0.0/28"


# ─── Security Posture (Dev: Enabled to satisfy Org Policy) ──────────────────────
# enable_nist_compliance         = true # Dynamically injected by deploy_all.sh based on --env posture
# POAM-024: HA decoupled from compliance — set explicitly false for dev cost optimization
enable_high_availability       = false
enable_deletion_protection     = false
enable_binary_authorization    = false
enable_audit_logging           = false
enable_cmek                    = false
enable_private_master_endpoint = false
enable_pod_security_standards  = false
# Required: org policy constraints/compute.vmExternalIpAccess blocks nodes with external IPs.
# Private nodes use NAT egress (Cloud NAT) instead of external IPs.
enable_private_nodes           = true
enable_dataplane_v2            = true
enable_fqdn_network_policy     = true

# Authorized networks for private cluster access
authorized_networks = [
  {
    cidr         = "0.0.0.0/0"
    display_name = "Allow All (Dev Only)"
  }
]

# ─── Cost Optimization (Dev: Cheap Nodes, Scale to Zero) ─────────────────────

# Pool 1: General pool: Small, cheap nodes
primary_node_pool_machine_type  = "e2-standard-4"
primary_node_pool_min_count     = 1
primary_node_pool_max_count     = 5
primary_node_pool_initial_count = 1
primary_node_pool_disk_type     = "pd-standard" # Cheaper

# Pool 2: General-spot pool disabled in dev (§3: staging only)
enable_general_spot_node_pool = false

# Pool 3: GPU pool: L4 (24 GiB VRAM) — required for 7B+ models.
# T4 (16 GiB) cannot fit model weights (14.25 GiB) + KV cache.
enable_gpu_node_pool        = true
gpu_type                    = "nvidia-l4"
gpu_count                   = 1
gpu_node_pool_machine_type  = "g2-standard-8" # Upgraded from g2-standard-4 (32 GB RAM) to prevent OOM eviction during 15 GB weight loading
gpu_node_pool_min_count     = 0               # cost-opt: scale to zero when idle; cluster autoscaler removes node after ~10 min of no GPU pod
gpu_node_pool_max_count     = 2               # 2 nodes needed: vllm-inference + vllm-reasoning
gpu_node_pool_initial_count = 1
gpu_node_pool_name          = "gpu-node-pool-nvidia-l4" # used as cloud.google.com/gke-nodepool nodeSelector
gpu_node_pool_spot          = false                      # §3, §7: GPU Spot stays off in every posture
gpu_node_locations          = ["us-central1-a", "us-central1-b", "us-central1-c"]

# Pool 4: ClickHouse pool: 1 local-SSD node in dev (§3)
enable_clickhouse_node_pool        = true
clickhouse_node_pool_machine_type  = "n2-standard-4"
clickhouse_node_pool_min_count     = 1
clickhouse_node_pool_max_count     = 1
clickhouse_node_pool_initial_count = 1

# ─── Storage (Dev: Smaller, Cheaper) ──────────────────────────────────────────
storage_class = "standard-rwo" # Correct GKE storage class

model_bucket_name = "" # Defaults to ${project_id}-models

# ─── PostgreSQL (Langfuse metadata + audit log) ────────────────────────────────
# Always deployed — Langfuse v3 requires PostgreSQL.
postgres_storage_size = "10Gi" # Dev: small, prod default is 50Gi

# ─── Redis (Langfuse v3 queuing / governed-financial-advisor session cache) ────
# Always deployed — required by Langfuse worker and advisor session management.
redis_storage_size = "2Gi" # Dev: small, prod default is 10Gi

# ─── ClickHouse (Langfuse v3 OLAP analytics) ──────────────────────────────────
# Always deployed — Langfuse v3 requires ClickHouse for trace storage.
clickhouse_storage_size = "10Gi" # Dev: small, prod default is 20Gi

# ─── Container Registry ───────────────────────────────────────────────────────
registry_url = "" # Defaults to gcr.io/${project_id}

# ─── GCP Features ─────────────────────────────────────────────────────────────
enable_gcs_fuse_csi = true

# ─── Deployment ───────────────────────────────────────────────────────────────
# force_redeploy = true ensures Terraform always re-runs the app deployment
# (null_resource.app_deployment provisioner) on every apply, even when no
# infrastructure has changed.  This is the correct behaviour for dev iteration.
force_redeploy = true

# ─── Services ─────────────────────────────────────────────────────────────────
enable_vllm              = true
enable_compliance_bridge = true
enable_nemo_guardrails   = true

# vLLM configuration — weights streamed from GCS model bucket via runai_streamer
model_fast             = "gs://cage-models/Qwen/Qwen2.5-1.5B-Instruct"
model_reasoning        = "gs://cage-models/deepseek-ai/DeepSeek-R1-Distill-Llama-8B"
served_model_fast      = "Qwen/Qwen2.5-1.5B-Instruct"
served_model_reasoning = "deepseek-ai/DeepSeek-R1-Distill-Llama-8B"
vllm_gpu_count         = 1
vllm_replicas          = 1

# NeMo Guardrails — use Cloud-Build custom image (auto-built by deploy_sw.py)
# Override via TF_VAR_nemo_image if you want a specific tag
nemo_image = ""

# Presidio — use Microsoft public images
presidio_analyzer_image   = "mcr.microsoft.com/presidio-analyzer:latest"
presidio_anonymizer_image = "mcr.microsoft.com/presidio-anonymizer:latest"

# ─── Secrets (set in terraform.auto.tfvars — gitignored) ──────────────────────
# K-3: signing keys are provisioned by kms_signing.tf (one key per signer,
#   POAM-2026-079); there is no kms_governance_key input any more.

# K-4: OTLP auth header for Langfuse trace ingestion (gateway + governed_advisor).
#   Option A — provide explicit header:
#     otel_exporter_otlp_headers = "Authorization=Basic <base64(publicKey:secretKey)>"
#   Option B — leave empty and set langfuse_public_key + langfuse_secret_key; the
#     root module will derive the header automatically from those two values.
#   Both must go in terraform.auto.tfvars (gitignored) — never commit real keys here.

# ─── Signing keys (POAM-2026-079) ─────────────────────────────────────────────
# Dev posture only: SOFTWARE protection. Staging/prod keep the HSM default.
kms_signing_protection_level = "SOFTWARE"
