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
  prod         Production (ISO 42001 baseline hardening + jurisdictional compliance
               posture controlled by CAGE_DEPLOYMENT_REGION and --var-file)

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

  # Deploy to GCP GKE (US_FED prod — ISO 42001 + NIST SP 800-53 hardening)
  CAGE_DEPLOYMENT_REGION=US_FED ./deploy_all.sh --target gcp-gke --env prod \
    --var-file=infra/targets/gcp-gke/prod.tfvars

  # Deploy to GCP GKE (EU_ECB prod — ISO 42001 + EU AI Act / GDPR / DORA)
  CAGE_DEPLOYMENT_REGION=EU_ECB ./deploy_all.sh --target gcp-gke --env prod \
    --var-file=infra/targets/gcp-gke/eu-prod.tfvars

  # Deploy to GCP GKE (APAC_MAS prod — ISO 42001 + MAS FEAT / Notice 655 / TRM)
  CAGE_DEPLOYMENT_REGION=APAC_MAS ./deploy_all.sh --target gcp-gke --env prod \
    --var-file=infra/targets/gcp-gke/apac-prod.tfvars

  # Override specific variables
  ./deploy_all.sh --target gcp-gke --env dev \
    --var project_id=my-test-project \
    --var gpu_type=nvidia-t4

EOF
  exit 0
}

# ─── .env loader ─────────────────────────────────────────────────────────────
# H-16: Load .env WITHOUT set -a / set -o allexport.
# Using allexport exports ALL variables (including secrets) to every child
# process spawned by this script.  Secrets then appear in /proc/<pid>/environ
# for terraform, gcloud, kubectl, etc., and may be logged in Cloud Build logs.
#
# Instead: source .env into a subshell, read only the variables we need, and
# export them selectively.  Secrets are mapped directly to TF_VAR_* names so
# they are never present as bare env vars in child process environments.
_read_env_var() {
  # Read a single variable from .env without exporting it to the environment.
  # Usage: _read_env_var VAR_NAME
  local var_name="$1"
  local value
  # grep for the line, strip comments, strip surrounding quotes
  value=$(grep -E "^${var_name}=" "$REPO_ROOT/.env" 2>/dev/null \
    | head -1 \
    | sed "s/^${var_name}=//" \
    | sed "s/^['\"]//;s/['\"]$//" \
    | sed 's/[[:space:]]*#.*//')
  printf '%s' "$value"
}

load_env() {
  if [[ -f "$REPO_ROOT/.env" ]]; then
    info "Loading environment from .env (selective export — H-16)"

    # ── Non-secret infrastructure variables (safe to export broadly) ──────
    local _env _cluster _namespace _registry _storage _cold_tier
    local _vllm_reasoning _vllm_fast _vllm_gateway _opa _redis _s3_ep _s3_bkt
    local _model_reasoning _model_fast _model_consensus
    local _project _region

    _env=$(_read_env_var ENVIRONMENT)
    _cluster=$(_read_env_var K8S_CLUSTER_NAME)
    _namespace=$(_read_env_var K8S_NAMESPACE)
    _registry=$(_read_env_var REGISTRY_URL)
    _storage=$(_read_env_var STORAGE_BACKEND)
    _cold_tier=$(_read_env_var COLD_TIER_BUCKET)
    _vllm_reasoning=$(_read_env_var VLLM_REASONING_API_BASE)
    _vllm_fast=$(_read_env_var VLLM_FAST_API_BASE)
    _vllm_gateway=$(_read_env_var VLLM_GATEWAY_URL)
    _opa=$(_read_env_var OPA_URL)
    _redis=$(_read_env_var REDIS_URL)
    _s3_ep=$(_read_env_var S3_ENDPOINT_URL)
    _s3_bkt=$(_read_env_var S3_BUCKET_NAME)
    _model_reasoning=$(_read_env_var MODEL_REASONING)
    _model_fast=$(_read_env_var MODEL_FAST)
    _model_consensus=$(_read_env_var MODEL_CONSENSUS)
    # DEP-22: Propagate GOOGLE_CLOUD_PROJECT → TF_VAR_project_id.
    # variables.tf declares project_id with no default (DEP-08 data-residency
    # guard). Without this mapping the chain relies solely on terraform.auto.tfvars
    # or dev.tfvars, breaking programmatic use (e.g. CI without a tfvars file).
    _project=$(_read_env_var GOOGLE_CLOUD_PROJECT)
    # DEP-22: Propagate GOOGLE_CLOUD_LOCATION → TF_VAR_region.
    # Same rationale as project_id — region has no default in variables.tf.
    _region=$(_read_env_var GOOGLE_CLOUD_LOCATION)

    [[ -n "$_env" ]]            && export TF_VAR_environment="$_env"
    [[ -n "$_cluster" ]]        && export TF_VAR_cluster_name="$_cluster"
    [[ -n "$_namespace" ]]      && export TF_VAR_namespace="$_namespace"
    [[ -n "$_registry" ]]       && export TF_VAR_registry_url="$_registry"
    [[ -n "$_storage" ]]        && export TF_VAR_storage_backend="$_storage"
    [[ -n "$_cold_tier" ]]      && export TF_VAR_cold_tier_bucket="$_cold_tier"
    [[ -n "$_vllm_reasoning" ]] && export TF_VAR_vllm_reasoning_url="$_vllm_reasoning"
    [[ -n "$_vllm_fast" ]]      && export TF_VAR_vllm_fast_url="$_vllm_fast"
    [[ -n "$_vllm_gateway" ]]   && export TF_VAR_vllm_gateway_url="$_vllm_gateway"
    [[ -n "$_opa" ]]            && export TF_VAR_opa_url="$_opa"
    [[ -n "$_redis" ]]          && export TF_VAR_redis_url="$_redis"
    [[ -n "$_s3_ep" ]]          && export TF_VAR_minio_endpoint="$_s3_ep"
    [[ -n "$_s3_bkt" ]]         && export TF_VAR_minio_bucket="$_s3_bkt"
    [[ -n "$_model_reasoning" ]] && export TF_VAR_model_reasoning="$_model_reasoning"
    [[ -n "$_model_fast" ]]     && export TF_VAR_model_fast="$_model_fast"
    [[ -n "$_model_consensus" ]] && export TF_VAR_model_consensus="$_model_consensus"
    [[ -n "$_project" ]]        && export TF_VAR_project_id="$_project"
    [[ -n "$_region" ]]         && export TF_VAR_region="$_region"

    # ── DEP-02: Propagate CAGE_DEPLOYMENT_REGION to Terraform ─────────────
    # Without this, Terraform defaults cage_deployment_region to "US_FED"
    # silently, causing EU_ECB and APAC_MAS deployments to apply the wrong
    # compliance posture. R-7: deployment scripts MUST propagate the region.
    local _cage_region
    _cage_region=$(_read_env_var CAGE_DEPLOYMENT_REGION)
    [[ -n "$_cage_region" ]] && export TF_VAR_cage_deployment_region="$_cage_region"

    # ── Langfuse host (non-secret) ─────────────────────────────────────────
    local _lf_host
    _lf_host=$(_read_env_var LANGFUSE_HOST)
    [[ -n "$_lf_host" ]] && export TF_VAR_langfuse_host="$_lf_host"

    # ── Cloud KMS governance signing (CTRL_KMS_001) ───────────────────────
    # CAGE_KMS_PROVIDER is non-secret (gcp/aws/azure). KMS_GOVERNANCE_KEY is
    # a resource name (not a private key), but is read via _read_env_var
    # alongside the other secret-adjacent vars to keep a single propagation
    # path. Empty means HMAC fallback (dev/CI only).
    local _cage_kms_provider
    _cage_kms_provider=$(_read_env_var CAGE_KMS_PROVIDER)
    [[ -n "$_cage_kms_provider" ]] && export TF_VAR_cage_kms_provider="$_cage_kms_provider"

    _secret_val=$(_read_env_var KMS_GOVERNANCE_KEY)
    [[ -n "$_secret_val" ]] && export TF_VAR_kms_governance_key="$_secret_val"
    unset _secret_val

    # ── Secrets — mapped directly to TF_VAR_* (never exported as bare vars) ─
    # These are read and immediately assigned to TF_VAR_* names.  The raw
    # secret values are never exported as standalone env vars, preventing them
    # from leaking into child process /proc/<pid>/environ entries under their
    # original names.
    local _secret_val
    _secret_val=$(_read_env_var AWS_ACCESS_KEY_ID)
    [[ -n "$_secret_val" ]] && export TF_VAR_aws_access_key="$_secret_val"
    unset _secret_val

    _secret_val=$(_read_env_var AWS_SECRET_ACCESS_KEY)
    [[ -n "$_secret_val" ]] && export TF_VAR_aws_secret_key="$_secret_val"
    unset _secret_val

    _secret_val=$(_read_env_var HUGGING_FACE_HUB_TOKEN)
    [[ -n "$_secret_val" ]] && export TF_VAR_hf_token="$_secret_val"
    unset _secret_val

    _secret_val=$(_read_env_var GOVERNANCE_SALT)
    [[ -n "$_secret_val" ]] && export TF_VAR_governance_salt="$_secret_val"
    unset _secret_val

    _secret_val=$(_read_env_var CAGE_ROUTING_SEAL_SECRET)
    [[ -n "$_secret_val" ]] && export TF_VAR_routing_seal_secret="$_secret_val"
    unset _secret_val

    _secret_val=$(_read_env_var LANGFUSE_PUBLIC_KEY)
    [[ -n "$_secret_val" ]] && export TF_VAR_langfuse_public_key="$_secret_val"
    unset _secret_val

    _secret_val=$(_read_env_var LANGFUSE_SECRET_KEY)
    [[ -n "$_secret_val" ]] && export TF_VAR_langfuse_secret_key="$_secret_val"
    unset _secret_val

    _secret_val=$(_read_env_var LANGFUSE_COMPLIANCE_PUBLIC_KEY)
    [[ -n "$_secret_val" ]] && export TF_VAR_langfuse_compliance_public_key="$_secret_val"
    unset _secret_val

    _secret_val=$(_read_env_var LANGFUSE_COMPLIANCE_SECRET_KEY)
    [[ -n "$_secret_val" ]] && export TF_VAR_langfuse_compliance_secret_key="$_secret_val"
    unset _secret_val

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
  
  # Reject staging — defined in Terraform schema but not yet provisioned (POAM-024, target v2.1.0)
  if [[ "$env" == "staging" ]]; then
    error "The 'staging' deployment posture is defined in the Terraform schema but not yet provisioned."
    echo "  Staging is deferred to v2.1.0 (POAM-024, target 2026-12-31)."
    echo "  See docs/CHANGE_MANAGEMENT_PROCESS.md §3.5 and docs/POAM_ISO42001.md#POAM-024."
    echo "  Use '--env dev' or '--env prod'."
    exit 1
  fi

  # DEP-01: Gate enable_nist_compliance on CAGE_DEPLOYMENT_REGION, not just --env prod.
  # A prod deployment to EU_ECB or APAC_MAS must NOT activate NIST-specific
  # infrastructure hardening (SC-7, AC-3, deletion protection, Redis replication).
  # ISO 42001 baseline hardening is always active in prod regardless of region.
  # R-2: NIST SP 800-53 logic MUST be gated on CAGE_DEPLOYMENT_REGION == "US_FED".
  _cage_region="${CAGE_DEPLOYMENT_REGION:-${TF_VAR_cage_deployment_region:-}}"

  # Set environment-specific banners
  if [[ "$env" == "prod" ]]; then
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${GREEN}║  🔒  PROD MODE: ISO 42001 baseline hardening enabled.            ║${RESET}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════╝${RESET}"
    echo ""
    # DEP-01: Only activate NIST-specific hardening for US_FED deployments.
    if [[ "$_cage_region" == "US_FED" ]]; then
      info "CAGE_DEPLOYMENT_REGION=US_FED — activating NIST SP 800-53 hardening"
      tf_args+=("-var=enable_nist_compliance=true")
    else
      info "CAGE_DEPLOYMENT_REGION=${_cage_region:-unset} — NIST hardening suppressed (not US_FED)"
      tf_args+=("-var=enable_nist_compliance=false")
    fi
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
