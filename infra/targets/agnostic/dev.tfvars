# Development Environment Configuration (Agnostic Target)
# Works with any Kubernetes cluster: k3s, minikube, kind, EKS, AKS, or GKE

# ─── Kubernetes Connection ────────────────────────────────────────────────────
kubeconfig_path    = "~/.kube/config"
kubeconfig_context = "" # Use current context

# ─── Environment ──────────────────────────────────────────────────────────────
environment = "dev"
namespace   = "governance-stack-dev"

# ─── Storage Class by Platform ────────────────────────────────────────────────
# k3s:       "local-path"
# minikube:  "standard"
# kind:      "standard"
# EKS:       "gp2" or "gp3"
# AKS:       "default" or "managed-premium"
# GKE:       "standard" or "pd-ssd"

storage_class = "standard" # Change based on your cluster

# ─── Storage Sizes (Dev: Smaller for Cost) ────────────────────────────────────
minio_storage_size = "10Gi"

# ─── Container Registry ───────────────────────────────────────────────────────
registry_url      = "ghcr.io/your-org/cybernetic-governance-engine"
registry_server   = "ghcr.io"
registry_username = "" # Leave empty for public registry
registry_password = ""

# ─── Security (Dev: Disabled for Fast Iteration) ──────────────────────────────
enable_pod_security_standards = false
pod_security_level            = "baseline"

# ─── MinIO Configuration ──────────────────────────────────────────────────────
minio_root_user = "minio-admin"
# minio_root_password is sensitive - pass via TF_VAR_minio_root_password or -var flag

# ─── Model Storage ────────────────────────────────────────────────────────────
model_bucket_name = "vllm-models"
