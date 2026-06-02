# Production Environment Configuration (GCP-GKE Target)
# NIST RMF compliance, high availability, locked down

# ─── GCP Project ──────────────────────────────────────────────────────────────
# REPLACE with your production project ID
project_id = "your-production-project"
region     = "us-central1"
zone       = "us-central1-a"

# ─── Cluster ──────────────────────────────────────────────────────────────────
cluster_name = "cage-prod"
environment  = "prod"
namespace    = "governance-stack"

# ─── Security Posture (Prod: NIST RMF Compliance) ─────────────────────────────
enable_nist_compliance         = true
enable_binary_authorization    = true
enable_audit_logging           = true
enable_cmek                    = false # Enable when KMS key is configured
enable_private_master_endpoint = false # Enable when VPN is configured
enable_pod_security_standards  = true
pod_security_level             = "restricted"

# Prod: Lock down to corporate VPN only (REPLACE with your CIDR)
authorized_networks = [
  {
    cidr         = "10.0.0.0/8"
    display_name = "Corporate VPN"
  }
]

# CMEK: Uncomment when Cloud KMS key is created
# kms_key_id = "projects/your-project/locations/us-central1/keyRings/cage-prod/cryptoKeys/gke-disk"

# ─── High Availability (Prod: Multi-Zone, Larger Nodes) ──────────────────────

# Primary pool: Production-grade nodes
primary_node_pool_machine_type  = "e2-standard-8"
primary_node_pool_min_count     = 3 # HA requires 3+ nodes
primary_node_pool_max_count     = 10
primary_node_pool_initial_count = 3
primary_node_pool_disk_type     = "pd-ssd" # Faster

# GPU pool: Production L4 GPUs, always available
enable_gpu_node_pool        = true
gpu_type                    = "nvidia-l4" # Better than T4
gpu_count                   = 1
gpu_node_pool_machine_type  = "g2-standard-8"
gpu_node_pool_min_count     = 2 # Always-on for production
gpu_node_pool_max_count     = 5
gpu_node_pool_initial_count = 2

# ─── Storage (Prod: Larger, Faster) ───────────────────────────────────────────
minio_storage_class = "pd-ssd"
minio_storage_size  = "500Gi"

model_bucket_name = "" # Defaults to ${project_id}-models

# ─── Container Registry ───────────────────────────────────────────────────────
registry_url = "" # Defaults to gcr.io/${project_id}

# ─── GCP Features ─────────────────────────────────────────────────────────────
enable_gcs_fuse_csi = true

# ─── Deployment ───────────────────────────────────────────────────────────────
force_redeploy = false

# ─── MinIO Credentials ────────────────────────────────────────────────────────
minio_root_user = "minio-admin"
# minio_root_password: Use GCP Secret Manager or SOPS for production
