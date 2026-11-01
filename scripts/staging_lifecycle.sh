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

# ─── Staging Lifecycle Manager (Release-Validation Gate) ──────────────────────
#
# Purpose: Provision, validate, and destroy the ephemeral staging environment
#          in a single fail-closed automated cycle (POAM-024 / POAM-2026-131 /
#          POAM-2026-159).
#
# --fresh-project is the automation for Track A's Step A3 (POAM-2026-164). It
# has run only against stubs, and Step A3 is not done: it waits for the manual
# Step A2 walk, and then for this script to match what the walk found.
#
# Usage:
#   ./scripts/staging_lifecycle.sh [OPTIONS]
#
# Flags:
#   --fresh-project[=<id>]  Run full clean-project bootstrap (create/link project
#                           if needed, run scripts/bootstrap_gcp_project.sh,
#                           auto-populate deployer /32 authorized_networks, and
#                           verify zero surviving workload resources after destroy)
#   --billing-account=<id>  GCP billing account ID to link when creating a fresh project
#   --project=<id>          Explicit GCP project ID (overrides GOOGLE_CLOUD_PROJECT)
#   --skip-lula             Skip Lula validation (faster iteration, not for release gate)
#   --skip-posture          Skip region posture tests
#   --no-destroy            Leave staging running (still exits non-zero on gate failure)
#   -h, --help              Show this help message

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TF_DIR="$REPO_ROOT/infra/targets/gcp-gke"

# ─── Color codes ──────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RESET='\033[0m'

# ─── Parse arguments ──────────────────────────────────────────────────────────
SKIP_LULA=false
SKIP_POSTURE=false
NO_DESTROY=false
FRESH_PROJECT=false
PROJECT_ID="${GOOGLE_CLOUD_PROJECT:-}"
BILLING_ACCOUNT_ID="${BILLING_ACCOUNT_ID:-}"
REGION="${GOOGLE_CLOUD_LOCATION:-us-central1}"
ZONE="${GOOGLE_CLOUD_ZONE:-${REGION}-a}"

usage() {
  cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Provision, validate, and destroy the ephemeral GKE staging environment.

Options:
  --fresh-project[=<id>]   Bootstrap a clean or throwaway GCP project before
                           provisioning and verify post-destroy cleanliness
  --billing-account=<id>   Billing account ID to link when creating a fresh project
  --project=<id>           GCP project ID (default: \$GOOGLE_CLOUD_PROJECT)
  --skip-lula              Skip Lula validation
  --skip-posture           Skip region posture tests
  --no-destroy             Skip Phase 6 teardown
  -h, --help               Show this help message
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-lula)
      SKIP_LULA=true
      shift
      ;;
    --skip-posture)
      SKIP_POSTURE=true
      shift
      ;;
    --no-destroy)
      NO_DESTROY=true
      shift
      ;;
    --fresh-project)
      FRESH_PROJECT=true
      shift
      ;;
    --fresh-project=*)
      FRESH_PROJECT=true
      PROJECT_ID="${1#*=}"
      shift
      ;;
    --billing-account=*)
      BILLING_ACCOUNT_ID="${1#*=}"
      shift
      ;;
    --billing-account)
      BILLING_ACCOUNT_ID="${2:-}"
      shift 2
      ;;
    --project=*)
      PROJECT_ID="${1#*=}"
      shift
      ;;
    --project)
      PROJECT_ID="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo -e "${RED}Unknown argument: $1${RESET}" >&2
      usage >&2
      exit 1
      ;;
  esac
done

# ─── Helper functions ─────────────────────────────────────────────────────────
info() {
  echo -e "${CYAN}[INFO]${RESET} $*"
}

success() {
  echo -e "${GREEN}[SUCCESS]${RESET} $*"
}

warn() {
  echo -e "${YELLOW}[WARN]${RESET} $*"
}

error() {
  echo -e "${RED}[ERROR]${RESET} $*" >&2
}

if [[ -z "$PROJECT_ID" ]]; then
  PROJECT_ID="$(gcloud config get-value project 2>/dev/null || true)"
fi

if [[ -z "$PROJECT_ID" ]]; then
  error "No GCP project specified. Set GOOGLE_CLOUD_PROJECT, pass --project=<id>, or pass --fresh-project=<id>."
  exit 1
fi

export GOOGLE_CLOUD_PROJECT="$PROJECT_ID"
export TF_VAR_project_id="$PROJECT_ID"

READINESS_FAILED=false
LULA_FAILURES=0
POSTURE_FAILURES=0

# ─── Phase 0 (Optional): Fresh-Project Bootstrap ──────────────────────────────
if [[ "$FRESH_PROJECT" == "true" ]]; then
  echo ""
  echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════╗${RESET}"
  echo -e "${CYAN}║  Phase 0: Fresh-project bootstrap (${PROJECT_ID})                ║${RESET}"
  echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${RESET}"
  echo ""

  if ! gcloud projects describe "$PROJECT_ID" >/dev/null 2>&1; then
    info "Creating GCP project '$PROJECT_ID'..."
    gcloud projects create "$PROJECT_ID" --name="CAGE Ephemeral Staging" --quiet
  fi

  if [[ -n "$BILLING_ACCOUNT_ID" ]]; then
    info "Linking billing account '$BILLING_ACCOUNT_ID' to '$PROJECT_ID'..."
    gcloud billing projects link "$PROJECT_ID" --billing-account="$BILLING_ACCOUNT_ID" --quiet
  fi

  info "Running clean-project bootstrap script..."
  bash "$REPO_ROOT/scripts/bootstrap_gcp_project.sh" \
    --project="$PROJECT_ID" \
    --env="staging" \
    --region="$REGION"
fi

# PF5: Ensure control-plane authorized_networks is populated so staging compliance
# posture (enable_private_nodes=true) does not fail plan or lock out kubectl/helm.
if [[ -z "${TF_VAR_authorized_networks:-}" ]]; then
  EGRESS_IP="${DEPLOYER_EGRESS_IP:-}"
  if [[ -z "$EGRESS_IP" ]]; then
    EGRESS_IP="$(curl -fsSL --max-time 5 https://checkip.amazonaws.com 2>/dev/null | tr -d '[:space:]' || true)"
  fi
  if [[ -n "$EGRESS_IP" ]]; then
    export TF_VAR_authorized_networks="[{\"cidr\":\"${EGRESS_IP}/32\",\"display_name\":\"deployer-egress\"}]"
    info "Configured TF_VAR_authorized_networks for deployer egress (${EGRESS_IP}/32)"
  fi
fi

# ─── Phase 1: Provision ───────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${CYAN}║  Phase 1: Provisioning staging environment                       ║${RESET}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${RESET}"
echo ""

info "Deploying staging with full security posture..."
if ! "$REPO_ROOT/deploy_all.sh" --target gcp-gke --env staging --auto-approve; then
  error "Staging provision failed. Check Terraform output above."
  exit 1
fi

success "Staging environment provisioned successfully"

# ─── Phase 2: Wait for cluster & workload readiness (FAIL CLOSED) ─────────────
echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${CYAN}║  Phase 2: Waiting for cluster & workload readiness               ║${RESET}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${RESET}"
echo ""

info "Fetching kubectl credentials for cage-staging..."
gcloud container clusters get-credentials cage-staging \
  --zone="$ZONE" \
  --project="$PROJECT_ID"

info "Waiting for all pods in governance-stack to be Ready (timeout: 5 minutes)..."
if ! kubectl wait --for=condition=Ready pods --all \
  -n governance-stack \
  --timeout=300s; then
  error "Timed out waiting for pods in governance-stack to become Ready."
  kubectl get pods -n governance-stack || true
  READINESS_FAILED=true
fi

REQUIRED_DEPLOYMENTS=(
  "gateway"
  "agentsight-ui"
  "opa-service"
  "langfuse-web"
  "langfuse-worker"
  "compliance-bridge"
)

for deploy_name in "${REQUIRED_DEPLOYMENTS[@]}"; do
  ready_replicas="$(kubectl get deployment "$deploy_name" -n governance-stack -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")"
  ready_replicas="${ready_replicas:-0}"
  if [[ ! "$ready_replicas" =~ ^[0-9]+$ ]] || (( ready_replicas < 1 )); then
    error "Workload readiness check failed: deployment/${deploy_name} has readyReplicas=${ready_replicas} (expected >= 1)."
    READINESS_FAILED=true
  fi
done

ch_ready="$(kubectl get statefulset clickhouse -n governance-stack -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")"
ch_ready="${ch_ready:-0}"
if [[ ! "$ch_ready" =~ ^[0-9]+$ ]] || (( ch_ready < 1 )); then
  error "Workload readiness check failed: statefulset/clickhouse has readyReplicas=${ch_ready} (expected >= 1)."
  READINESS_FAILED=true
fi

if [[ "$READINESS_FAILED" == "false" ]]; then
  success "Cluster and all required governance-stack workloads are Ready"
else
  error "Cluster readiness gate FAILED — skipping validation phases and proceeding to teardown."
fi

# ─── Phase 3: Lula Validation (FAIL CLOSED) ───────────────────────────────────
if [[ "$READINESS_FAILED" == "false" ]]; then
  if [[ "$SKIP_LULA" == "false" ]]; then
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${CYAN}║  Phase 3: Lula validation (universal ISO 42001 gates)            ║${RESET}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${RESET}"
    echo ""

    info "Running all Lula validation files..."
    shopt -s nullglob
    validation_files=("$REPO_ROOT"/compliance/lula/lula-validation-*.yaml)
    shopt -u nullglob

    if [[ ${#validation_files[@]} -eq 0 ]]; then
      error "No Lula validation files found in compliance/lula/"
      ((LULA_FAILURES++)) || true
    else
      for validation_file in "${validation_files[@]}"; do
        info "Validating: $(basename "$validation_file")"
        if ! lula validate -f "$validation_file"; then
          error "Lula validation failed: $(basename "$validation_file")"
          ((LULA_FAILURES++)) || true
        fi
      done
    fi

    if [[ $LULA_FAILURES -eq 0 ]]; then
      success "All Lula validation gates passed at 1-replica scale"
    else
      error "$LULA_FAILURES Lula validation file(s) failed"
      error "POAM-024 is NOT satisfied — security posture incomplete"
    fi
  else
    warn "Lula validation skipped (--skip-lula flag)"
  fi

  # ─── Phase 4: Region Posture Tests (FAIL CLOSED) ────────────────────────────
  if [[ "$SKIP_POSTURE" == "false" ]]; then
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${CYAN}║  Phase 4: Region posture tests (US_FED, EU_ECB, APAC_MAS)        ║${RESET}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${RESET}"
    echo ""

    info "Running US_FED posture tests..."
    if ! CAGE_DEPLOYMENT_REGION=US_FED uv run pytest "$REPO_ROOT/tests/" -m us_fed -v --tb=short; then
      error "US_FED posture tests failed"
      ((POSTURE_FAILURES++)) || true
    fi

    info "Running EU_ECB posture tests..."
    if ! CAGE_DEPLOYMENT_REGION=EU_ECB uv run pytest "$REPO_ROOT/tests/" -m eu_ecb -v --tb=short; then
      error "EU_ECB posture tests failed"
      ((POSTURE_FAILURES++)) || true
    fi

    info "Running APAC_MAS posture tests..."
    if ! CAGE_DEPLOYMENT_REGION=APAC_MAS uv run pytest "$REPO_ROOT/tests/" -m apac_mas -v --tb=short; then
      error "APAC_MAS posture tests failed"
      ((POSTURE_FAILURES++)) || true
    fi

    if [[ $POSTURE_FAILURES -eq 0 ]]; then
      success "Region posture validation complete"
    else
      error "$POSTURE_FAILURES region posture test suite(s) failed"
    fi
  else
    warn "Region posture tests skipped (--skip-posture flag)"
  fi

  # ─── Phase 5: Cluster-Scoped Control Verification ───────────────────────────
  echo ""
  echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════╗${RESET}"
  echo -e "${CYAN}║  Phase 5: Verify cluster-scoped controls                         ║${RESET}"
  echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${RESET}"
  echo ""

  info "Checking Binary Authorization enforcement..."
  if kubectl get deploy -n governance-stack -o json | \
     jq -e '.items[].spec.template.metadata.annotations["image-policy.k8s.io/breakglass"]' > /dev/null 2>&1; then
    success "Binary Authorization annotations present on deployments"
  else
    warn "Binary Authorization annotations not detected (may be expected if disabled)"
  fi

  info "Checking Pod Security Standards admission..."
  if kubectl get ns governance-stack -o json | \
     jq -e '.metadata.labels["pod-security.kubernetes.io/enforce"] == "restricted"' > /dev/null 2>&1; then
    success "Pod Security Standards set to 'restricted' on governance-stack namespace"
  else
    warn "Pod Security Standards label not found on governance-stack namespace"
  fi
fi

check_gate_failures() {
  if [[ "$READINESS_FAILED" == "true" ]] || [[ $LULA_FAILURES -gt 0 ]] || [[ $POSTURE_FAILURES -gt 0 ]]; then
    error "Staging lifecycle gate FAILED (readiness_failed=${READINESS_FAILED}, lula_failures=${LULA_FAILURES}, posture_failures=${POSTURE_FAILURES})."
    return 1
  fi
  return 0
}

# ─── Phase 6: Teardown ────────────────────────────────────────────────────────
if [[ "$NO_DESTROY" == "true" ]]; then
  echo ""
  echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════════╗${RESET}"
  echo -e "${YELLOW}║  Staging environment left running (--no-destroy flag)             ║${RESET}"
  echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════════╝${RESET}"
  echo ""
  check_gate_failures
  exit 0
fi

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${CYAN}║  Phase 6: Tearing down staging environment                        ║${RESET}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${RESET}"
echo ""

SHORT_SHA="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo "")"
DIGESTS_FILE=""
if [[ -n "$SHORT_SHA" && -f "$TF_DIR/image_digests.${SHORT_SHA}.tfvars.json" ]]; then
  DIGESTS_FILE="$TF_DIR/image_digests.${SHORT_SHA}.tfvars.json"
elif [[ -f "$TF_DIR/tests/fixtures/image_digests.tfvars" ]]; then
  DIGESTS_FILE="$TF_DIR/tests/fixtures/image_digests.tfvars"
fi

# PF8: GCP KMS keyrings and keys cannot be deleted and carry lifecycle.prevent_destroy = true
# in kms_signing.tf (and destroying a CryptoKey destroys cryptoKeyVersions/1, which is
# pinned by perimeter.tf and kms_signing.tf). Detach them from Terraform state prior to
# `terraform destroy`; scripts/bootstrap_gcp_project.sh --import-state re-imports them on
# the next lifecycle run.
info "Detaching persistent KMS keyrings and signing keys from Terraform state before destroy (PF8)..."
PERSISTENT_KMS_STATE_ADDRS=(
  "google_kms_crypto_key_iam_policy.signing_key"
  "google_kms_crypto_key.gateway_seal"
  "google_kms_crypto_key.reconciler_snapshot"
  "google_kms_crypto_key.compliance_evidence"
  "google_kms_crypto_key.benchmark_signing"
  "google_kms_crypto_key.binauthz_attestor"
  "google_kms_key_ring.signing"
  "module.kms"
)
for kms_addr in "${PERSISTENT_KMS_STATE_ADDRS[@]}"; do
  terraform -chdir="$TF_DIR" state rm "$kms_addr" >/dev/null 2>&1 || true
done

info "Destroying staging cluster (enable_deletion_protection=false)..."
DESTROY_ARGS=(
  "-var=enable_nist_compliance=true"
  "-var-file=staging.tfvars"
  "-auto-approve"
  "-var=project_id=${PROJECT_ID}"
  "-var=region=${REGION}"
  "-var=cage_deployment_region=${CAGE_DEPLOYMENT_REGION:-US_FED}"
)
if [[ -n "$DIGESTS_FILE" ]]; then
  DESTROY_ARGS+=("-var-file=${DIGESTS_FILE}")
fi

if ! terraform -chdir="$TF_DIR" destroy "${DESTROY_ARGS[@]}"; then
  error "Staging teardown failed. Manual cleanup required in $TF_DIR"
  exit 1
fi

success "Staging environment destroyed successfully"

# PF9: In --fresh-project mode, verify that no workload resources or deletion liens
# survived `terraform destroy` (confirming POAM-2026-159 bucket teardown and clean
# project deletion readiness).
if [[ "$FRESH_PROJECT" == "true" ]]; then
  info "Verifying zero surviving workload resources or deletion liens in '$PROJECT_ID'..."
  SURVIVORS=0

  remaining_clusters="$(gcloud container clusters list --project="$PROJECT_ID" --format='value(name)' 2>/dev/null || true)"
  if [[ -n "$remaining_clusters" ]]; then
    error "Surviving GKE cluster(s) after destroy: $remaining_clusters"
    ((SURVIVORS++)) || true
  fi

  remaining_sql="$(gcloud sql instances list --project="$PROJECT_ID" --format='value(name)' 2>/dev/null || true)"
  if [[ -n "$remaining_sql" ]]; then
    error "Surviving Cloud SQL instance(s) after destroy: $remaining_sql"
    ((SURVIVORS++)) || true
  fi

  remaining_buckets="$(gcloud storage buckets list --project="$PROJECT_ID" --format='value(name)' 2>/dev/null | grep -Ev "^(${PROJECT_ID}-tfstate|${PROJECT_ID}_cloudbuild)$" || true)"
  if [[ -n "$remaining_buckets" ]]; then
    error "Surviving workload GCS bucket(s) after destroy: $remaining_buckets"
    ((SURVIVORS++)) || true
  fi

  remaining_liens="$(gcloud alpha resource-manager liens list --project="$PROJECT_ID" --format='value(name)' 2>/dev/null || true)"
  if [[ -n "$remaining_liens" ]]; then
    error "Surviving project deletion lien(s) after destroy: $remaining_liens"
    ((SURVIVORS++)) || true
  fi

  if [[ $SURVIVORS -gt 0 ]]; then
    error "Fresh-project post-destroy cleanliness verification FAILED ($SURVIVORS survivor category(s))."
    exit 1
  fi
  success "Fresh-project post-destroy verification passed (zero workload survivors or deletion liens)"
fi

check_gate_failures

# ─── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${GREEN}║  ✅  Staging lifecycle complete                                   ║${RESET}"
echo -e "${GREEN}║                                                                   ║${RESET}"
echo -e "${GREEN}║  POAM-024 / POAM-2026-131 / POAM-2026-159 validation:             ║${RESET}"
echo -e "${GREEN}║    ✅  All governance-stack workloads reached Ready               ║${RESET}"
if [[ "$SKIP_LULA" == "false" ]]; then
  echo -e "${GREEN}║    ✅  All Lula gates passed at 1-replica scale                   ║${RESET}"
fi
if [[ "$SKIP_POSTURE" == "false" ]]; then
  echo -e "${GREEN}║    ✅  All region posture suites passed                           ║${RESET}"
fi
echo -e "${GREEN}║    ✅  Ephemeral staging cluster destroyed cleanly                ║${RESET}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════╝${RESET}"
echo ""
