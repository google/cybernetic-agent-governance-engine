#!/usr/bin/env bash
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

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

# ─── Colour helpers ───────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

info()    { echo -e "${CYAN}ℹ️  $*${RESET}"; }
success() { echo -e "${GREEN}✅ $*${RESET}"; }
warn()    { echo -e "${YELLOW}⚠️  $*${RESET}"; }
error()   { echo -e "${RED}❌ $*${RESET}" >&2; }
header()  { echo -e "\n${BOLD}${CYAN}═══ $* ═══${RESET}\n"; }

# ─── Usage ────────────────────────────────────────────────────────────────────
usage() {
  cat <<EOF
${BOLD}Cybernetic Governance Engine - Deployment Script${RESET}

${BOLD}Usage${RESET}
  ./deploy_all.sh --target TARGET --env ENV [OPTIONS]

${BOLD}Targets${RESET}
  agnostic     Deploy to any existing Kubernetes cluster (k3s, EKS, AKS, GKE)
  gcp-gke      Provision and deploy to Google Cloud GKE cluster

${BOLD}Environments${RESET}
  dev          Development (fast iteration, minimal security)
  prod         Production (NIST compliance, full security)

${BOLD}Options${RESET}
  --auto-approve          Skip Terraform confirmation prompts
  --var-file=PATH         Additional .tfvars file to load
  --skip-build            Skip container image builds
  --kubeconfig=PATH       Kubeconfig path (agnostic target only)
  --var KEY=VALUE         Override any Terraform variable

${BOLD}Examples${RESET}
  # Deploy to local k3s cluster
  ./deploy_all.sh --target agnostic --env dev

  # Deploy to GCP GKE (dev mode - fast iteration)
  ./deploy_all.sh --target gcp-gke --env dev --auto-approve

  # Deploy to GCP GKE (prod mode - NIST compliance)
  ./deploy_all.sh --target gcp-gke --env prod

  # Override specific variables
  ./deploy_all.sh --target gcp-gke --env dev \
    --var project_id=my-test-project \
    --var gpu_type=nvidia-t4

EOF
  exit 0
}

# ─── .env loader ─────────────────────────────────────────────────────────────
load_env() {
  if [[ -f "$REPO_ROOT/.env" ]]; then
    info "Loading environment from .env and exporting as TF_VAR_* variables"
    
    # First, load all variables normally
    set -o allexport
    # shellcheck disable=SC1090
    source "$REPO_ROOT/.env"
    set +o allexport
    
    # Then map common .env variables to TF_VAR_* format for Terraform
    # Authentication & Secrets
    [[ -n "${AWS_ACCESS_KEY_ID:-}" ]] && export TF_VAR_aws_access_key="$AWS_ACCESS_KEY_ID"
    [[ -n "${AWS_SECRET_ACCESS_KEY:-}" ]] && export TF_VAR_aws_secret_key="$AWS_SECRET_ACCESS_KEY"
    [[ -n "${HUGGING_FACE_HUB_TOKEN:-}" ]] && export TF_VAR_hf_token="$HUGGING_FACE_HUB_TOKEN"
    [[ -n "${GOVERNANCE_SALT:-}" ]] && export TF_VAR_governance_salt="$GOVERNANCE_SALT"
    [[ -n "${CAGE_ROUTING_SEAL_SECRET:-}" ]] && export TF_VAR_routing_seal_secret="$CAGE_ROUTING_SEAL_SECRET"
    
    # Langfuse
    [[ -n "${LANGFUSE_HOST:-}" ]] && export TF_VAR_langfuse_host="$LANGFUSE_HOST"
    [[ -n "${LANGFUSE_PUBLIC_KEY:-}" ]] && export TF_VAR_langfuse_public_key="$LANGFUSE_PUBLIC_KEY"
    [[ -n "${LANGFUSE_SECRET_KEY:-}" ]] && export TF_VAR_langfuse_secret_key="$LANGFUSE_SECRET_KEY"
    [[ -n "${LANGFUSE_COMPLIANCE_PUBLIC_KEY:-}" ]] && export TF_VAR_langfuse_compliance_public_key="$LANGFUSE_COMPLIANCE_PUBLIC_KEY"
    [[ -n "${LANGFUSE_COMPLIANCE_SECRET_KEY:-}" ]] && export TF_VAR_langfuse_compliance_secret_key="$LANGFUSE_COMPLIANCE_SECRET_KEY"
    
    # Models
    [[ -n "${MODEL_REASONING:-}" ]] && export TF_VAR_model_reasoning="$MODEL_REASONING"
    [[ -n "${MODEL_FAST:-}" ]] && export TF_VAR_model_fast="$MODEL_FAST"
    [[ -n "${MODEL_CONSENSUS:-}" ]] && export TF_VAR_model_consensus="$MODEL_CONSENSUS"
    # Infrastructure
    [[ -n "${VLLM_REASONING_API_BASE:-}" ]] && export TF_VAR_vllm_reasoning_url="$VLLM_REASONING_API_BASE"
    [[ -n "${VLLM_FAST_API_BASE:-}" ]] && export TF_VAR_vllm_fast_url="$VLLM_FAST_API_BASE"
    [[ -n "${VLLM_GATEWAY_URL:-}" ]] && export TF_VAR_vllm_gateway_url="$VLLM_GATEWAY_URL"
    [[ -n "${OPA_URL:-}" ]] && export TF_VAR_opa_url="$OPA_URL"
    [[ -n "${REDIS_URL:-}" ]] && export TF_VAR_redis_url="$REDIS_URL"
    [[ -n "${S3_ENDPOINT_URL:-}" ]] && export TF_VAR_minio_endpoint="$S3_ENDPOINT_URL"
    [[ -n "${S3_BUCKET_NAME:-}" ]] && export TF_VAR_minio_bucket="$S3_BUCKET_NAME"
    
    # General
    [[ -n "${ENVIRONMENT:-}" ]] && export TF_VAR_environment="$ENVIRONMENT"
    [[ -n "${K8S_CLUSTER_NAME:-}" ]] && export TF_VAR_cluster_name="$K8S_CLUSTER_NAME"
    [[ -n "${K8S_NAMESPACE:-}" ]] && export TF_VAR_namespace="$K8S_NAMESPACE"
    [[ -n "${REGISTRY_URL:-}" ]] && export TF_VAR_registry_url="$REGISTRY_URL"
    [[ -n "${STORAGE_BACKEND:-}" ]] && export TF_VAR_storage_backend="$STORAGE_BACKEND"
    [[ -n "${COLD_TIER_BUCKET:-}" ]] && export TF_VAR_cold_tier_bucket="$COLD_TIER_BUCKET"
    
    success "Environment loaded: ${TF_VAR_environment:-dev} | Namespace: ${TF_VAR_namespace:-governance-stack}"
  else
    warn ".env not found — relying on shell environment variables"
    info "Copy .env.example to .env: cp .env.example .env"
  fi
}

# ─── Terraform Target Deployment ─────────────────────────────────────────────

deploy_terraform_target() {
  local target="$1"
  local env="$2"
  shift 2
  
  local tf_dir="$REPO_ROOT/infra/targets/$target"
  local var_file="$tf_dir/${env}.tfvars"
  local tf_args=()
  local backend_config_args=()
  
  # Validate target
  if [[ ! -d "$tf_dir" ]]; then
    error "Unknown target: $target"
    echo "Available targets: agnostic, gcp-gke"
    echo "Run './deploy_all.sh --help' for usage."
    exit 1
  fi
  
  header "Infrastructure Deployment: $target ($env)"
  
  # Load environment variables
  load_env
  
  # Set environment-specific banners
  if [[ "$env" == "prod" ]]; then
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${GREEN}║  🔒  PROD MODE: Full security posture enabled.                   ║${RESET}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════╝${RESET}"
    echo ""
    tf_args+=("-var=enable_nist_compliance=true")
  else
    echo ""
    echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${YELLOW}║  ⚠️   DEV MODE: Reduced security posture.                        ║${RESET}"
    echo -e "${YELLOW}║      DO NOT use in production.                                   ║${RESET}"
    echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════════╝${RESET}"
    echo ""
    tf_args+=("-var=enable_nist_compliance=false")
  fi
  
  info "Target directory: $tf_dir"
  
  # Load environment-specific var file
  if [[ -f "$var_file" ]]; then
    tf_args+=("-var-file=$var_file")
    info "Using var file: $var_file"
  else
    warn "Var file not found: $var_file (will use defaults)"
  fi
  
  # Parse remaining arguments
  local kubeconfig_path=""
  local kubeconfig_context=""
  
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --auto-approve)
        tf_args+=("-auto-approve")
        shift
        ;;
      --var-file=*)
        tf_args+=("-var-file=${1#--var-file=}")
        shift
        ;;
      --var)
        tf_args+=("-var")
        tf_args+=("$2")
        shift 2
        ;;
      --kubeconfig=*)
        kubeconfig_path="${1#--kubeconfig=}"
        shift
        ;;
      --skip-build)
        export SKIP_BUILD=true
        shift
        ;;
      *)
        warn "Unknown option: $1 (ignored)"
        shift
        ;;
    esac
  done
  
  # Target-specific backend configuration
  if [[ "$target" == "agnostic" ]]; then
    # Kubernetes backend: Store state in cluster
    if [[ -n "$kubeconfig_path" ]]; then
      backend_config_args+=("-backend-config=config_path=$kubeconfig_path")
      export KUBECONFIG="$kubeconfig_path"
    else
      backend_config_args+=("-backend-config=config_path=~/.kube/config")
    fi
    
    info "Using Kubernetes backend (state stored in cluster)"
    info "Ensure 'terraform-state' namespace exists: kubectl create namespace terraform-state"
  elif [[ "$target" == "gcp-gke" ]]; then
    # GCS backend configuration commented in providers.tf
    info "GCS backend configuration in providers.tf (optional)"
    info "Uncomment backend block to use remote state"
  fi
  
  # Initialize Terraform
  info "Initializing Terraform..."
  if [[ ${#backend_config_args[@]} -gt 0 ]]; then
    terraform -chdir="$tf_dir" init "${backend_config_args[@]}"
  else
    terraform -chdir="$tf_dir" init
  fi
  
  # Run Terraform plan
  header "Terraform Plan"
  # Filter out -auto-approve from plan args (it's only for apply)
  plan_args=()
  auto_approve=false
  for arg in "${tf_args[@]}"; do
    if [[ "$arg" == "-auto-approve" ]]; then
      auto_approve=true
    else
      plan_args+=("$arg")
    fi
  done
  terraform -chdir="$tf_dir" plan "${plan_args[@]}" -out=tfplan

  # ─── PRE-BUILD STEP (Fix Race Conditions) ────────────────────────────────────
  # Build images BEFORE Terraform apply to ensure they exist for K8s deployments.
  if [[ "${SKIP_BUILD:-false}" != "true" && "$target" == "gcp-gke" ]]; then
    header "Pre-building Container Images"
    
    # Extract project_id from tf_vars or env
    local project_id="${TF_VAR_project_id:-${GOOGLE_CLOUD_PROJECT:-}}"
    if [[ -z "$project_id" ]]; then
      # Try to grep it from .env as fallback
      project_id=$(grep -E "^GOOGLE_CLOUD_PROJECT=" "$REPO_ROOT/.env" | cut -d= -f2 | tr -d '"' || true)
    fi
    
    if [[ -n "$project_id" ]]; then
      info "Building images for project: $project_id"
      export PROJECT_ID="$project_id"
      
      # Execute the new bash script for building images
      if [[ -x "$REPO_ROOT/scripts/build_images.sh" ]]; then
        "$REPO_ROOT/scripts/build_images.sh"
      else
        bash "$REPO_ROOT/scripts/build_images.sh"
      fi
      
      # Set SKIP_BUILD=true so the inner call (inside Terraform) doesn't rebuild
      export TF_VAR_skip_build=true
      # Also export for the local-exec provisioner
      export SKIP_BUILD=true
    else
      warn "Could not determine project_id for pre-build. Skipping."
    fi
  fi
  
  # Apply Terraform configuration
  if [[ "$auto_approve" == "true" ]]; then
    header "Terraform Apply (auto-approved)"
    terraform -chdir="$tf_dir" apply -parallelism=1 tfplan
  else
    header "Terraform Apply"
    echo ""
    echo "Review the plan above. Press Enter to apply or Ctrl+C to cancel."
    read -r
    terraform -chdir="$tf_dir" apply tfplan
  fi
  
  success "Infrastructure deployment complete!"
  
  # Show outputs
  echo ""
  header "Deployment Summary"
  terraform -chdir="$tf_dir" output deployment_summary
  
  echo ""
  info "To access the cluster:"
  if [[ "$target" == "gcp-gke" ]]; then
    echo "  gcloud container clusters get-credentials <CLUSTER_NAME> --zone=<ZONE> --project=<PROJECT>"
    echo "  Or run: terraform -chdir=$tf_dir output -raw kubectl_command | bash"
  else
    echo "  kubectl get pods -n <NAMESPACE>"
  fi
  
  echo ""
  info "To view MinIO console:"
  echo "  kubectl port-forward svc/minio 9001:9001 -n <NAMESPACE>"
  echo "  Open: http://localhost:9001"
}

# ─── Entry point ──────────────────────────────────────────────────────────────

main() {
  # Show help
  if [[ $# -eq 0 ]] || [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]]; then
    usage
  fi
  
  # Require --target flag
  if [[ "$1" != "--target" ]]; then
    error "Missing required --target flag"
    echo ""
    echo "Usage: ./deploy_all.sh --target TARGET --env ENV [OPTIONS]"
    echo ""
    echo "Run './deploy_all.sh --help' for full documentation."
    exit 1
  fi
  
  local target="$2"
  shift 2
  
  local env="dev"  # Default to dev
  
  # Check for --env flag
  if [[ "$1" == "--env" ]]; then
    env="$2"
    shift 2
  fi
  
  deploy_terraform_target "$target" "$env" "$@"
}

main "$@"
