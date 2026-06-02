# Development Environment Configuration (GCP-GKE Target)
# Fast iteration, minimal costs, low security posture

# ─── GCP Project ──────────────────────────────────────────────────────────────
# REPLACE with your actual project ID
project_id = "YOUR_GCP_PROJECT_ID"
region     = "us-central1"
zone       = "us-central1-a" # Current cluster location

# ─── Cluster ──────────────────────────────────────────────────────────────────
environment = "dev"

# Matches existing governance-cluster to prevent replacement
pod_cidr               = "10.100.0.0/14"
service_cidr           = "10.104.0.0/20"
master_ipv4_cidr_block = "172.16.0.0/28"


# ─── Security Posture (Dev: Enabled to satisfy Org Policy) ──────────────────────
# enable_nist_compliance         = true # Dynamically injected by deploy_all.sh based on --env posture
enable_binary_authorization    = false
enable_audit_logging           = false
enable_cmek                    = false
enable_private_master_endpoint = false
enable_pod_security_standards  = false

# Authorized networks for private cluster access
authorized_networks = [
  {
    cidr         = "0.0.0.0/0"
    display_name = "Allow All (Dev Only)"
  }
]

# ─── Cost Optimization (Dev: Cheap Nodes, Scale to Zero) ─────────────────────

# Primary pool: Small, cheap nodes
primary_node_pool_machine_type  = "e2-standard-4"
primary_node_pool_min_count     = 1
primary_node_pool_max_count     = 5
primary_node_pool_initial_count = 1
primary_node_pool_disk_type     = "pd-standard" # Cheaper

# GPU pool: L4 (24 GiB VRAM) — required for 7B+ models.
# T4 (16 GiB) cannot fit model weights (14.25 GiB) + KV cache.
enable_gpu_node_pool        = true
gpu_type                    = "nvidia-l4"
gpu_count                   = 1
gpu_node_pool_machine_type  = "g2-standard-8" # Upgraded from 4 to 8 (32 GB RAM) to prevent OOM eviction during 15GB weight loading
gpu_node_pool_min_count     = 1               # Provision 1 node immediately for faster deployment
gpu_node_pool_max_count     = 2               # 2 nodes needed: vllm-inference + vllm-reasoning
gpu_node_pool_initial_count = 1
gpu_node_pool_name          = "gpu-node-pool-nvidia-l4" # used as cloud.google.com/gke-nodepool nodeSelector
gpu_node_pool_spot          = true                      # Enable spot instances for dev posture capacity
gpu_node_locations          = ["us-central1-a", "us-central1-b", "us-central1-c"]

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
# SLM runs as a sidecar inside the governed-financial-advisor pod (no standalone module)

# vLLM configuration — model names pulled from .env via TF_VAR_model_fast / TF_VAR_model_reasoning
# DO NOT hardcode model names here — use .env MODEL_FAST and MODEL_REASONING instead
vllm_gpu_count = 1
vllm_replicas  = 1

# NeMo Guardrails — use Cloud-Build custom image (auto-built by deploy_sw.py)
# Override via TF_VAR_nemo_image if you want a specific tag
nemo_image = ""

# Presidio — use Microsoft public images
presidio_analyzer_image   = "mcr.microsoft.com/presidio-analyzer:latest"
presidio_anonymizer_image = "mcr.microsoft.com/presidio-anonymizer:latest"

