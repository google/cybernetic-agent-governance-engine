# Production Environment Configuration (Agnostic Target)
# Production-grade settings for any Kubernetes cluster

# ─── Kubernetes Connection ────────────────────────────────────────────────────
kubeconfig_path    = "~/.kube/config"
kubeconfig_context = "production-cluster" # Specify exact context for safety

# ─── Environment ──────────────────────────────────────────────────────────────
environment = "prod"
namespace   = "governance-stack"

# ─── Storage (Production: Larger Sizes, Fast Storage) ─────────────────────────
storage_class = "pd-ssd" # Or gp3 for EKS, managed-premium for AKS

minio_storage_size = "500Gi"

# ─── Container Registry ───────────────────────────────────────────────────────
registry_url      = "ghcr.io/your-org/cybernetic-governance-engine"
registry_server   = "ghcr.io"
registry_username = "" # Set if using private registry
# registry_password: Pass via TF_VAR_registry_password

# ─── Security (Prod: Maximum Security) ────────────────────────────────────────
enable_pod_security_standards = true
pod_security_level            = "restricted"

# ─── MinIO Configuration ──────────────────────────────────────────────────────
minio_root_user = "minio-admin"
# minio_root_password: Pass via TF_VAR_minio_root_password or use SOPS

# ─── Model Storage ────────────────────────────────────────────────────────────
model_bucket_name = "vllm-models"
