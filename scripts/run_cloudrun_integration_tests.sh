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

# ─── Cloud Run Live Integration Test Runner ──────────────────────────────────
#
# Purpose: Orchestrates pre-flight validation, IAM authentication, live service
#          smoke testing, serverless GPU/agent warm-up, and concurrency-constrained
#          integration test execution with visible skip reason reporting (-ra -rs).
#
# Usage:
#   ./scripts/run_cloudrun_integration_tests.sh
#   ./scripts/run_cloudrun_integration_tests.sh -k test_agent_accuracy
#   ./scripts/run_cloudrun_integration_tests.sh --skip-smoke --skip-warmup
#   make test-cloudrun
#
# Environment variables:
#   CLOUDRUN_TEST_SERVICE_ACCOUNT  Test automation SA email for IAM impersonation
#   CLOUDRUN_IDENTITY_TOKEN         Direct OIDC token (fallback)
#   GATEWAY_URL                     Cloud Run Gateway endpoint
#   BACKEND_URL                     Cloud Run Governed Financial Advisor endpoint
#   COMPLIANCE_BRIDGE_URL           Cloud Run Compliance Bridge endpoint
#   LANGFUSE_HOST                   Cloud Run Langfuse endpoint
#   VLLM_FAST_URL                   Cloud Run vLLM GPU inference endpoint

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

CYAN='\033[0;36m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
RESET='\033[0m'

PYTEST_ARGS=()
SKIP_SMOKE=false
SKIP_WARMUP=false

for arg in "$@"; do
  case "$arg" in
    --skip-smoke)
      SKIP_SMOKE=true
      ;;
    --skip-warmup)
      SKIP_WARMUP=true
      ;;
    *)
      PYTEST_ARGS+=("$arg")
      ;;
  esac
done

echo -e "${CYAN}${BOLD}======================================================================${RESET}"
echo -e "${CYAN}${BOLD}       CAGE Cloud Run Live Integration Test Orchestrator              ${RESET}"
echo -e "${CYAN}${BOLD}======================================================================${RESET}"

# ── Step 1: Discover Endpoints & IAM Credentials ──────────────────────────────
echo -e "\n${CYAN}[1/5] Discovering Cloud Run Endpoints & IAM Credentials...${RESET}"

if [[ -f .env ]]; then
  set -a; source .env; set +a
fi

TF_DIR="infra/targets/gcp-cloudrun"
if [[ -d "$TF_DIR" ]] && terraform -chdir="$TF_DIR" output -raw gateway_url >/dev/null 2>&1; then
  echo -e "  ✓ Discovered endpoints from Terraform state in ${TF_DIR}"
  export GATEWAY_URL="${GATEWAY_URL:-$(terraform -chdir="$TF_DIR" output -raw gateway_url 2>/dev/null || echo "")}"
  export BACKEND_URL="${BACKEND_URL:-$(terraform -chdir="$TF_DIR" output -raw governed_advisor_url 2>/dev/null || echo "")}"
  export COMPLIANCE_BRIDGE_URL="${COMPLIANCE_BRIDGE_URL:-$(terraform -chdir="$TF_DIR" output -raw compliance_bridge_url 2>/dev/null || echo "")}"
  export LANGFUSE_HOST="${LANGFUSE_HOST:-$(terraform -chdir="$TF_DIR" output -raw langfuse_web_url 2>/dev/null || echo "")}"
  export VLLM_FAST_URL="${VLLM_FAST_URL:-$(terraform -chdir="$TF_DIR" output -raw vllm_fast_url 2>/dev/null || echo "")}"
fi

export CAGE_TEST_TARGET=cloudrun
export CAGE_ENV=test

# Authentication resolution
if [[ -n "${CLOUDRUN_TEST_SERVICE_ACCOUNT:-}" ]]; then
  echo -e "  ✓ IAM Impersonation: ${CLOUDRUN_TEST_SERVICE_ACCOUNT}"
elif [[ -n "${CLOUDRUN_IDENTITY_TOKEN:-}" ]]; then
  echo -e "  ✓ IAM Identity Token provided via CLOUDRUN_IDENTITY_TOKEN"
elif command -v gcloud >/dev/null 2>&1; then
  echo -e "  ℹ️  Minting identity token fallback via 'gcloud auth print-identity-token'..."
  export CLOUDRUN_IDENTITY_TOKEN="$(gcloud auth print-identity-token 2>/dev/null || true)"
else
  echo -e "${YELLOW}  ⚠️  No service account or gcloud token detected. Requests to private Cloud Run endpoints may receive 401/403.${RESET}"
fi

if [[ -z "${GATEWAY_URL:-}" || -z "${BACKEND_URL:-}" ]]; then
  echo -e "\n${RED}[ERROR] Cloud Run endpoints could not be resolved.${RESET}"
  echo -e "  Either apply ${TF_DIR} or export GATEWAY_URL and BACKEND_URL."
  echo -e "  Example:"
  echo -e "    export GATEWAY_URL=https://cage-gateway-dev-xyz.a.run.app"
  echo -e "    export BACKEND_URL=https://cage-governed-advisor-dev-xyz.a.run.app"
  exit 1
fi

echo -e "  • Gateway URL:           ${GATEWAY_URL}"
echo -e "  • Advisor Backend URL:   ${BACKEND_URL}"
echo -e "  • Compliance Bridge URL: ${COMPLIANCE_BRIDGE_URL:-'(not set)'}"
echo -e "  • Langfuse Host:         ${LANGFUSE_HOST:-'(not set)'}"
echo -e "  • vLLM GPU Fast URL:     ${VLLM_FAST_URL:-'(not set)'}"

# ── Step 2: Pre-Flight Smoke Test (Fail-Closed) ───────────────────────────────
echo -e "\n${CYAN}[2/5] Running Pre-Flight Service Smoke Checks (Fail-Closed)...${RESET}"
if [[ "$SKIP_SMOKE" == "true" ]]; then
  echo -e "${YELLOW}  ℹ️  Pre-flight smoke checks skipped (--skip-smoke set).${RESET}"
elif [[ -f scripts/test_live_cloudrun_services.py ]]; then
  uv run python scripts/test_live_cloudrun_services.py || {
    echo -e "\n${RED}[FAIL] Live service smoke check failed.${RESET}"
    echo -e "  Halting test execution before running pytest to prevent false skips or flaky assertions."
    echo -e "  Verify Cloud Run service health and VPC routing before re-running (or pass --skip-smoke if testing subset)."
    exit 1
  }
  echo -e "  ${GREEN}✓ All live services responsive and reachable.${RESET}"
else
  echo -e "  ℹ️  Checking Gateway health directly..."
  curl -sSf "${GATEWAY_URL}/health" >/dev/null || {
    echo -e "${RED}[FAIL] Gateway /health is unreachable at ${GATEWAY_URL}${RESET}"
    exit 1
  }
  echo -e "  ${GREEN}✓ Gateway responsive.${RESET}"
fi

# ── Step 3: Deep GPU & Multi-Agent Warm-Up Flow ───────────────────────────────
echo -e "\n${CYAN}[3/5] Warming Up Multi-Agent Graph & Serverless GPU (vLLM)...${RESET}"
if [[ "$SKIP_WARMUP" == "true" ]]; then
  echo -e "${YELLOW}  ℹ️  Warm-up flow skipped (--skip-warmup set).${RESET}"
elif [[ -f scripts/test_cloudrun_e2e_flow.py ]]; then
  echo -e "  ℹ️  Executing end-to-end synthetic query to absorb cold-start penalty (3-5 min if scaling from zero)..."
  uv run python scripts/test_cloudrun_e2e_flow.py || {
    echo -e "${YELLOW}  ⚠️  Warm-up flow completed with warnings; continuing to integration suite...${RESET}"
  }
else
  echo -e "  ℹ️  Sending ping to Advisor /health..."
  curl -sSf "${BACKEND_URL}/health" >/dev/null || true
fi

# ── Step 4: Execute Concurrency-Constrained Pytest with Visible Skip Reasons ───
echo -e "\n${CYAN}[4/5] Executing Cloud Run Integration Suite...${RESET}"
echo -e "  Parameters: -n 2 --dist loadscope --no-cov -ra -rs (unmasking skip reasons)"

set +e
uv run pytest tests/ \
  -m "integration and not gke" \
  --run-integration \
  -n 2 --dist loadscope \
  --no-cov \
  -p no:langsmith -p no:langsmith_plugin \
  -ra -rs \
  --tb=short \
  "${PYTEST_ARGS[@]}"
TEST_EXIT_CODE=$?
set -e

# ── Step 5: Summary and Evaluation ────────────────────────────────────────────
echo -e "\n${CYAN}[5/5] Test Run Evaluation...${RESET}"
if [[ $TEST_EXIT_CODE -eq 0 ]]; then
  echo -e "${GREEN}${BOLD}✓ All Cloud Run integration tests passed successfully!${RESET}"
else
  echo -e "${RED}${BOLD}✗ Cloud Run integration tests failed or had errors (exit code: ${TEST_EXIT_CODE}).${RESET}"
  echo -e "  Review the skip reasons (-rs) and failure tracebacks above."
fi

exit $TEST_EXIT_CODE
