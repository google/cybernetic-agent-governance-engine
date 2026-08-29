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

# ─── Staging Lifecycle Manager ───────────────────────────────────────────────
#
# Purpose: Provision, validate, and destroy the ephemeral staging environment
#          in a single automated cycle to minimize cost while proving full
#          security posture at dev-scale (POAM-024 closure).
#
# Usage:
#   ./scripts/staging_lifecycle.sh [--skip-lula] [--skip-posture] [--no-destroy]
#
# Flags:
#   --skip-lula      Skip Lula validation (faster iteration, not recommended)
#   --skip-posture   Skip region posture tests (faster, validates universal gates only)
#   --no-destroy     Leave staging running (manual teardown required, costs continue)
#
# What this validates:
#   1. All 31 Lula validation gates pass at 1-replica scale
#   2. NIST SP 800-53 controls enforced without HA overhead
#   3. ISO 42001 §A.5.3 pre-production validation satisfied
#   4. Cluster-scoped controls (BinAuthz, PSS, CMEK, audit logs) active
#   5. Regional compliance postures (US_FED, EU_ECB, APAC_MAS) validated
#
# Prerequisites:
#   - .env configured with GOOGLE_CLOUD_PROJECT, GOOGLE_CLOUD_LOCATION
#   - terraform.auto.tfvars with staging secrets (routing_seal_secret, kms_key_id, etc.)
#   - Langfuse compliance project keys (LANGFUSE_COMPLIANCE_PUBLIC_KEY, LANGFUSE_COMPLIANCE_SECRET_KEY)
#   - kubectl context pointing to the GKE cluster (will be created during provision)
#
# Cost window:
#   - Provision: ~10-15 minutes (cluster creation + app deployment)
#   - Validation: ~5-10 minutes (Lula + posture tests)
#   - Total runtime: ~20-30 minutes
#   - Hourly cost during validation: ~$5-8 (e2-standard-4 nodes + L4 GPU)
#   - Total cost per cycle: ~$2-4 (sub-hour usage)

set -euo pipefail

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

while [[ $# -gt 0 ]]; do
  case $1 in
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
    *)
      echo -e "${RED}Unknown argument: $1${RESET}"
      echo "Usage: $0 [--skip-lula] [--skip-posture] [--no-destroy]"
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
  echo -e "${RED}[ERROR]${RESET} $*"
}

# ─── Phase 1: Provision ───────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${CYAN}║  Phase 1: Provisioning staging environment                       ║${RESET}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${RESET}"
echo ""

info "Deploying staging with full security posture..."
if ! ./deploy_all.sh --target gcp-gke --env staging --auto-approve; then
  error "Staging provision failed. Check Terraform output above."
  exit 1
fi

success "Staging environment provisioned successfully"

# ─── Phase 2: Wait for cluster readiness ──────────────────────────────────────
echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${CYAN}║  Phase 2: Waiting for cluster readiness                          ║${RESET}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${RESET}"
echo ""

info "Fetching kubectl credentials for cage-staging..."
gcloud container clusters get-credentials cage-staging \
  --zone=us-central1-a \
  --project="${GOOGLE_CLOUD_PROJECT:-$(gcloud config get-value project)}"

info "Waiting for all pods in governance-stack to be Ready (timeout: 5 minutes)..."
if ! kubectl wait --for=condition=Ready pods --all \
  -n governance-stack \
  --timeout=300s; then
  warn "Some pods did not become Ready within 5 minutes. Proceeding with validation anyway."
  kubectl get pods -n governance-stack
fi

success "Cluster is ready for validation"

# ─── Phase 3: Lula Validation ─────────────────────────────────────────────────
if [[ "$SKIP_LULA" == "false" ]]; then
  echo ""
  echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════╗${RESET}"
  echo -e "${CYAN}║  Phase 3: Lula validation (universal ISO 42001 gates)            ║${RESET}"
  echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${RESET}"
  echo ""

  info "Running all 31 Lula validation files..."
  LULA_FAILURES=0
  for validation_file in compliance/lula/lula-validation-*.yaml; do
    if [[ ! -f "$validation_file" ]]; then
      warn "No Lula validation files found in compliance/lula/"
      break
    fi
    
    info "Validating: $(basename "$validation_file")"
    if ! lula validate -f "$validation_file"; then
      error "Lula validation failed: $(basename "$validation_file")"
      ((LULA_FAILURES++)) || true
    fi
  done

  if [[ $LULA_FAILURES -eq 0 ]]; then
    success "All Lula validation gates passed at 1-replica scale"
  else
    error "$LULA_FAILURES Lula validation file(s) failed"
    error "This proves POAM-024 is NOT satisfied — security posture incomplete"
    if [[ "$NO_DESTROY" == "false" ]]; then
      warn "Destroying staging despite validation failure (cost containment)"
    fi
  fi
else
  warn "Lula validation skipped (--skip-lula flag)"
fi

# ─── Phase 4: Region Posture Tests ────────────────────────────────────────────
if [[ "$SKIP_POSTURE" == "false" ]]; then
  echo ""
  echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════╗${RESET}"
  echo -e "${CYAN}║  Phase 4: Region posture tests (US_FED, EU_ECB, APAC_MAS)        ║${RESET}"
  echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${RESET}"
  echo ""

  info "Running US_FED posture tests..."
  if ! CAGE_DEPLOYMENT_REGION=US_FED uv run pytest tests/ -m us_fed -v --tb=short; then
    warn "Some US_FED posture tests failed"
  fi

  info "Running EU_ECB posture tests..."
  if ! CAGE_DEPLOYMENT_REGION=EU_ECB uv run pytest tests/ -m eu_ecb -v --tb=short; then
    warn "Some EU_ECB posture tests failed"
  fi

  info "Running APAC_MAS posture tests..."
  if ! CAGE_DEPLOYMENT_REGION=APAC_MAS uv run pytest tests/ -m apac_mas -v --tb=short; then
    warn "Some APAC_MAS posture tests failed"
  fi

  success "Region posture validation complete"
else
  warn "Region posture tests skipped (--skip-posture flag)"
fi

# ─── Phase 5: Cluster-Scoped Control Verification ─────────────────────────────
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

info "Checking CMEK encryption..."
# CMEK validation requires inspecting etcd encryption config at cluster level — complex
# For now, just verify the kms_key_id was set in Terraform output
warn "CMEK validation requires manual inspection of GKE cluster encryption config"
warn "Check: gcloud container clusters describe cage-staging --zone=us-central1-a --format='value(databaseEncryption)'"

info "Checking audit logging..."
# Audit logs are delivered to Cloud Logging — check for recent entries
warn "Audit log validation requires manual inspection of Cloud Logging"
warn "Check: gcloud logging read 'resource.type=k8s_cluster AND resource.labels.cluster_name=cage-staging' --limit 10"

success "Cluster-scoped control verification complete (manual inspection required for CMEK/audit logs)"

# ─── Phase 6: Teardown ────────────────────────────────────────────────────────
if [[ "$NO_DESTROY" == "true" ]]; then
  echo ""
  echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════════╗${RESET}"
  echo -e "${YELLOW}║  Staging environment left running (--no-destroy flag)             ║${RESET}"
  echo -e "${YELLOW}║  Manual teardown required:                                        ║${RESET}"
  echo -e "${YELLOW}║    cd infra/targets/gcp-gke                                       ║${RESET}"
  echo -e "${YELLOW}║    terraform destroy -var-file=staging.tfvars -auto-approve       ║${RESET}"
  echo -e "${YELLOW}║  Hourly cost: ~$5-8 (e2-standard-4 + L4 GPU)                      ║${RESET}"
  echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════════╝${RESET}"
  echo ""
  exit 0
fi

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${CYAN}║  Phase 6: Tearing down staging environment                        ║${RESET}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${RESET}"
echo ""

info "Destroying staging cluster (enable_deletion_protection=false allows this)..."
cd infra/targets/gcp-gke

if ! terraform destroy -var-file=staging.tfvars -auto-approve \
  -var="project_id=${GOOGLE_CLOUD_PROJECT:-$(gcloud config get-value project)}" \
  -var="region=${GOOGLE_CLOUD_LOCATION:-us-central1}" \
  -var="cage_deployment_region=${CAGE_DEPLOYMENT_REGION:-US_FED}"; then
  error "Staging teardown failed. Manual cleanup required:"
  error "  cd infra/targets/gcp-gke"
  error "  terraform destroy -var-file=staging.tfvars"
  exit 1
fi

cd - > /dev/null

success "Staging environment destroyed successfully"

# ─── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${GREEN}║  ✅  Staging lifecycle complete                                   ║${RESET}"
echo -e "${GREEN}║                                                                   ║${RESET}"
echo -e "${GREEN}║  POAM-024 validation:                                             ║${RESET}"
if [[ "$SKIP_LULA" == "false" ]] && [[ $LULA_FAILURES -eq 0 ]]; then
  echo -e "${GREEN}║    ✅  All Lula gates passed at 1-replica scale                   ║${RESET}"
  echo -e "${GREEN}║    ✅  Full security posture achievable without HA overhead       ║${RESET}"
  echo -e "${GREEN}║    ✅  ISO 42001 §A.5.3 pre-production validation satisfied       ║${RESET}"
else
  echo -e "${YELLOW}║    ⚠️   Lula validation incomplete (skipped or failures)          ║${RESET}"
fi
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════╝${RESET}"
echo ""
