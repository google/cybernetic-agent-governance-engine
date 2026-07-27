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
#
# run_matrix_tests.sh — CAGE 2×3 compliance matrix orchestrator
#
# Usage:
#   ./scripts/run_matrix_tests.sh [dev|prod] [US_FED|EU_ECB|APAC_MAS]
#
# Runs the full compliance gate suite for the given environment and region:
#   Phase 0 — Universal ISO 42001 gates (always run, all regions)
#   Phase 1 — Regional posture gates (region-specific)
#
# Exit codes:
#   0  — all gates passed
#   1  — parameter validation failure
#   2  — Phase 0 (universal) gate failure
#   3  — Phase 1 (regional) gate failure
#
# Source of truth for gate requirements: docs/RELEASE_PLAN.md §5.1–§5.4

set -euo pipefail

# ---------------------------------------------------------------------------
# Colour helpers (no-op when not a TTY)
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
  RED='\033[0;31m'
  GREEN='\033[0;32m'
  YELLOW='\033[1;33m'
  CYAN='\033[0;36m'
  BOLD='\033[1m'
  RESET='\033[0m'
else
  RED='' GREEN='' YELLOW='' CYAN='' BOLD='' RESET=''
fi

info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
success() { echo -e "${GREEN}[PASS]${RESET}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
error()   { echo -e "${RED}[FAIL]${RESET}  $*" >&2; }
header()  { echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════════════${RESET}"; \
            echo -e "${BOLD}${CYAN}  $*${RESET}"; \
            echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════${RESET}"; }

# ---------------------------------------------------------------------------
# Parameter validation
# ---------------------------------------------------------------------------
if [[ $# -ne 2 ]]; then
  error "Wrong number of arguments."
  echo ""
  echo "  Usage: $0 [dev|prod] [US_FED|EU_ECB|APAC_MAS]"
  echo ""
  echo "  Examples:"
  echo "    $0 dev  US_FED"
  echo "    $0 prod EU_ECB"
  echo "    $0 dev  APAC_MAS"
  exit 1
fi

CAGE_ENV="${1}"
CAGE_REGION="${2}"

# Validate environment
case "${CAGE_ENV}" in
  dev|prod) ;;
  *)
    error "Invalid environment '${CAGE_ENV}'. Must be one of: dev, prod"
    exit 1
    ;;
esac

# Validate region
case "${CAGE_REGION}" in
  US_FED|EU_ECB|APAC_MAS) ;;
  *)
    error "Invalid region '${CAGE_REGION}'. Must be one of: US_FED, EU_ECB, APAC_MAS"
    exit 1
    ;;
esac

# Export for child processes
export CAGE_ENV
export CAGE_REGION

# ---------------------------------------------------------------------------
# Load .env if present — secrets (LANGFUSE_*, GOVERNANCE_SALT, etc.) live
# there and must NOT be hardcoded in this script.
# ---------------------------------------------------------------------------
if [[ -f ".env" ]]; then
  # Export only lines that are valid KEY=VALUE assignments; skip comments and blanks.
  set -o allexport
  # shellcheck source=/dev/null
  source .env
  set +o allexport
fi

# ---------------------------------------------------------------------------
# Override GOOGLE_CLOUD_LOCATION based on deployment region.
# .env sets GOOGLE_CLOUD_LOCATION=us-central1 (US_FED default); EU_ECB and
# APAC_MAS must override to their authoritative GCP regions so that
# data-residency tests and telemetry sinks resolve to the correct location.
# ---------------------------------------------------------------------------
case "$CAGE_REGION" in
  EU_ECB)   export GOOGLE_CLOUD_LOCATION="europe-west1" ;;
  APAC_MAS) export GOOGLE_CLOUD_LOCATION="asia-southeast1" ;;
  US_FED)   export GOOGLE_CLOUD_LOCATION="${GOOGLE_CLOUD_LOCATION:-us-central1}" ;;
esac

info "CAGE compliance matrix test run"
info "  Environment : ${CAGE_ENV}"
info "  Region      : ${CAGE_REGION}"
info "  Timestamp   : $(date -u '+%Y-%m-%dT%H:%M:%SZ')"

# ---------------------------------------------------------------------------
# Phase 0 — Universal ISO 42001 Gates
# These gates ALWAYS run regardless of region or environment.
# Source: docs/RELEASE_PLAN.md §5.1
# ---------------------------------------------------------------------------
header "Phase 0 — Universal ISO 42001 Gates"

PHASE0_FAILURES=0

# ---------------------------------------------------------------------------
# Phase: Pytest unit tests (region-scoped, -m local)
# Runs before Lula/OPA checks so fast unit failures surface first.
# ---------------------------------------------------------------------------
echo "=== Phase: Pytest unit tests (CAGE_DEPLOYMENT_REGION=${CAGE_REGION}) ==="
mkdir -p pytest-results
CAGE_DEPLOYMENT_REGION="${CAGE_REGION}" \
  uv run pytest tests/ -m local \
    --tb=short -q \
    --junitxml="pytest-results/pytest-${CAGE_REGION}-${CAGE_ENV}.xml" \
  || { echo "Pytest failed for region ${CAGE_REGION}"; exit 1; }

# Gate 0.1 — Core unit tests (skip gracefully if directory absent)
echo ""
info "Gate 0.1 — Core unit tests (tests/core/)"
if [[ -d "tests/core" ]]; then
  if uv run pytest tests/core/ -v; then
    success "Gate 0.1 passed — core unit tests"
  else
    error "Gate 0.1 FAILED — core unit tests"
    PHASE0_FAILURES=$((PHASE0_FAILURES + 1))
  fi
else
  warn "Gate 0.1 SKIPPED — tests/core/ directory not found"
fi

# Gate 0.2 — STPA freshness check
echo ""
info "Gate 0.2 — STPA freshness check"
if python3 scripts/check_stpa_freshness.py; then
  success "Gate 0.2 passed — STPA artifacts are fresh"
else
  error "Gate 0.2 FAILED — STPA freshness check"
  PHASE0_FAILURES=$((PHASE0_FAILURES + 1))
fi

# Gate 0.3 — Langfuse posture verification
echo ""
info "Gate 0.3 — Langfuse posture verification"
# Non-secret GCP context vars — safe to default here.
export GOOGLE_CLOUD_PROJECT="${GOOGLE_CLOUD_PROJECT:-mock-project}"
export GOOGLE_CLOUD_LOCATION="${GOOGLE_CLOUD_LOCATION:-mock-location}"
# All LANGFUSE_* vars (HOST, PUBLIC_KEY, SECRET_KEY, COMPLIANCE_*) are loaded
# from .env above. Do NOT set fallback values here — missing vars must surface
# as a real Gate 0.3 failure so operators know to populate .env.
if python3 scripts/verify_langfuse_posture.py --dry-run --posture development; then
  success "Gate 0.3 passed — Langfuse posture verified"
else
  error "Gate 0.3 FAILED — Langfuse posture verification"
  PHASE0_FAILURES=$((PHASE0_FAILURES + 1))
fi

# Gate 0.4 — ISO 42001 Lula validations (all 4 manifests)
echo ""
info "Gate 0.4 — ISO 42001 Lula validations"

ISO_MANIFESTS=(
  "compliance/lula/lula-validation-a52.yaml"
  "compliance/lula/lula-validation-a53.yaml"
  "compliance/lula/lula-validation-a92.yaml"
  "compliance/lula/lula-validation-aarm-vectors.yaml"
)

for manifest in "${ISO_MANIFESTS[@]}"; do
  info "  Validating: ${manifest}"
  if lula validate -f "${manifest}"; then
    success "  Passed: ${manifest}"
  else
    error "  FAILED: ${manifest}"
    PHASE0_FAILURES=$((PHASE0_FAILURES + 1))
  fi
done

if [[ ${PHASE0_FAILURES} -gt 0 ]]; then
  error "Phase 0 completed with ${PHASE0_FAILURES} failure(s). Aborting."
  exit 2
fi

success "Phase 0 — All universal ISO 42001 gates passed"

# ---------------------------------------------------------------------------
# Phase 1 — Regional Posture Gates
# Source: docs/RELEASE_PLAN.md §5.2–§5.4
# ---------------------------------------------------------------------------
header "Phase 1 — Regional Posture Gates (${CAGE_REGION} / ${CAGE_ENV})"

PHASE1_FAILURES=0

case "${CAGE_REGION}" in

  # -------------------------------------------------------------------------
  # US_FED — NIST SP 800-53 posture
  # Source: docs/RELEASE_PLAN.md §5.2
  # -------------------------------------------------------------------------
  US_FED)
    echo ""
    info "Gate 1.1 — OPA unit tests (US_FED posture)"
    if opa test compliance/postures/us_fed/opa/ src/governed_financial_advisor/governance/policy/trade_governance.rego -v; then
      success "Gate 1.1 passed — OPA unit tests"
    else
      error "Gate 1.1 FAILED — OPA unit tests"
      PHASE1_FAILURES=$((PHASE1_FAILURES + 1))
    fi

    if [[ "${CAGE_ENV}" == "prod" ]]; then
      echo ""
      info "Gate 1.2 — NIST SP 800-53 Lula validations (prod only)"

      NIST_MANIFESTS=(
        "compliance/lula/lula-validation-ac2.yaml"
        "compliance/lula/lula-validation-ac3.yaml"
        "compliance/lula/lula-validation-au12.yaml"
        "compliance/lula/lula-validation-cm6.yaml"
        "compliance/lula/lula-validation-ia3.yaml"
        "compliance/lula/lula-validation-ir6.yaml"
        "compliance/lula/lula-validation-ra5.yaml"
        "compliance/lula/lula-validation-sc4.yaml"
        "compliance/lula/lula-validation-sc8.yaml"
        "compliance/lula/lula-validation-si2.yaml"
      )

      for manifest in "${NIST_MANIFESTS[@]}"; do
        info "  Validating: ${manifest}"
        if lula validate -f "${manifest}"; then
          success "  Passed: ${manifest}"
        else
          error "  FAILED: ${manifest}"
          PHASE1_FAILURES=$((PHASE1_FAILURES + 1))
        fi
      done
    else
      info "Gate 1.2 — NIST SP 800-53 Lula validations SKIPPED (dev environment)"
    fi
    ;;

  # -------------------------------------------------------------------------
  # EU_ECB — EU AI Act / GDPR / DORA posture
  # Source: docs/RELEASE_PLAN.md §5.3
  # -------------------------------------------------------------------------
  EU_ECB)
    echo ""
    info "Gate 1.1 — EU AI Act Art. 10 bias evaluation pipeline"
    if uv run pytest compliance/postures/eu_ecb/llm_eval/ -v; then
      success "Gate 1.1 passed — EU AI Act bias eval pipeline"
    else
      error "Gate 1.1 FAILED — EU AI Act bias eval pipeline"
      PHASE1_FAILURES=$((PHASE1_FAILURES + 1))
    fi

    if [[ "${CAGE_ENV}" == "prod" ]]; then
      echo ""
      info "Gate 1.2 — Data residency validation (europe-west1, prod only)"

      RESIDENCY_TEST="tests/infrastructure/test_data_residency.py"
      if [[ -f "${RESIDENCY_TEST}" ]]; then
        if uv run pytest "${RESIDENCY_TEST}" --region=europe-west1 -v; then
          success "Gate 1.2 passed — EU data residency confirmed"
        else
          error "Gate 1.2 FAILED — EU data residency validation"
          PHASE1_FAILURES=$((PHASE1_FAILURES + 1))
        fi
      else
        warn "Gate 1.2 SKIPPED — ${RESIDENCY_TEST} not found"
      fi
    else
      info "Gate 1.2 — Data residency validation SKIPPED (dev environment)"
    fi
    ;;

  # -------------------------------------------------------------------------
  # APAC_MAS — MAS FEAT / MAS Notice 655 / MAS TRM posture
  # Source: docs/RELEASE_PLAN.md §5.4
  # -------------------------------------------------------------------------
  APAC_MAS)
    echo ""
    info "Gate 1.1 — MAS FEAT Lula validation"
    if lula validate -f compliance/lula/lula-validation-mas-feat.yaml; then
      success "Gate 1.1 passed — MAS FEAT validation"
    else
      error "Gate 1.1 FAILED — MAS FEAT validation"
      PHASE1_FAILURES=$((PHASE1_FAILURES + 1))
    fi

    if [[ "${CAGE_ENV}" == "prod" ]]; then
      echo ""
      info "Gate 1.2 — MAS Notice 655 Lula validation (prod only)"
      if lula validate -f compliance/lula/lula-validation-mas-notice655.yaml; then
        success "Gate 1.2 passed — MAS Notice 655 validation"
      else
        error "Gate 1.2 FAILED — MAS Notice 655 validation"
        PHASE1_FAILURES=$((PHASE1_FAILURES + 1))
      fi

      echo ""
      info "Gate 1.3 — MAS TRM §6 Lula validation (prod only)"
      if lula validate -f compliance/lula/lula-validation-mas-trm-s6.yaml; then
        success "Gate 1.3 passed — MAS TRM §6 validation"
      else
        error "Gate 1.3 FAILED — MAS TRM §6 validation"
        PHASE1_FAILURES=$((PHASE1_FAILURES + 1))
      fi
    else
      info "Gate 1.2/1.3 — MAS Notice 655 / TRM §6 validations SKIPPED (dev environment)"
    fi
    ;;

esac

if [[ ${PHASE1_FAILURES} -gt 0 ]]; then
  error "Phase 1 completed with ${PHASE1_FAILURES} failure(s)."
  exit 3
fi

success "Phase 1 — All regional posture gates passed (${CAGE_REGION} / ${CAGE_ENV})"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
header "Compliance Matrix Run Complete"
success "All gates passed for ${CAGE_REGION} / ${CAGE_ENV}"
info "  Phase 0 (Universal ISO 42001) : PASSED"
info "  Phase 1 (Regional ${CAGE_REGION})    : PASSED"
echo ""
exit 0
