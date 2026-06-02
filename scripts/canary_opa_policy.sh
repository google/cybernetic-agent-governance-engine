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

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

POLICY_FILE="${1:-deployment/system_authz.rego}"
TRAFFIC_SNAPSHOT_DIR="${2:-tests/opa_snapshots}"
OPA_BUNDLE_ROOT="${OPA_BUNDLE_ROOT:-policies}"
NAMESPACE="${NAMESPACE:-governance-stack}"
SECRET_NAME="${SECRET_NAME:-system-authz-policy}"
SECRET_KEY="${SECRET_KEY:-latest}"
DRY_RUN="${DRY_RUN:-false}"

PASS=0
FAIL=0
TOTAL=0

# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'  # No Colour

info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[FAIL]${NC}  $*"; }

# ---------------------------------------------------------------------------
# Dependency checks
# ---------------------------------------------------------------------------

if ! command -v opa &>/dev/null; then
    error "OPA CLI not found. Install from https://www.openpolicyagent.org/docs/latest/#running-opa"
    exit 2
fi

if ! command -v jq &>/dev/null; then
    error "jq not found. Install with: apt-get install jq / brew install jq"
    exit 2
fi

# ---------------------------------------------------------------------------
# Validate the candidate policy file exists
# ---------------------------------------------------------------------------

if [ ! -f "${POLICY_FILE}" ]; then
    error "Policy file not found: ${POLICY_FILE}"
    exit 1
fi

info "Canary OPA Policy Test"
info "  Candidate policy  : ${POLICY_FILE}"
info "  Traffic snapshots : ${TRAFFIC_SNAPSHOT_DIR}"
info "  OPA bundle root   : ${OPA_BUNDLE_ROOT}"
echo ""

# ---------------------------------------------------------------------------
# Step 1: OPA format check
# ---------------------------------------------------------------------------

info "Step 1/4 — Checking Rego syntax..."
if opa fmt --diff "${POLICY_FILE}" 2>/dev/null | grep -q .; then
    warn "Rego formatting issues found. Run: opa fmt -w ${POLICY_FILE}"
fi

if ! opa check "${POLICY_FILE}" 2>&1; then
    error "OPA syntax check FAILED for ${POLICY_FILE}"
    exit 1
fi
info "  ✅ Syntax OK"

# ---------------------------------------------------------------------------
# Step 2: OPA unit tests (if tests exist alongside the policy)
# ---------------------------------------------------------------------------

info "Step 2/4 — Running OPA unit tests..."
OPA_TEST_DIR="$(dirname "${POLICY_FILE}")"
if ls "${OPA_TEST_DIR}"/*_test.rego &>/dev/null 2>&1; then
    if ! opa test "${OPA_TEST_DIR}" --bundle "${OPA_BUNDLE_ROOT}" -v 2>&1; then
        error "OPA unit tests FAILED."
        exit 1
    fi
    info "  ✅ Unit tests passed"
else
    warn "  No *_test.rego files found in ${OPA_TEST_DIR} — skipping unit tests."
fi

# ---------------------------------------------------------------------------
# Step 3: Replay historical traffic snapshots
# ---------------------------------------------------------------------------

info "Step 3/4 — Replaying traffic snapshots..."

if [ ! -d "${TRAFFIC_SNAPSHOT_DIR}" ]; then
    warn "  Snapshot directory '${TRAFFIC_SNAPSHOT_DIR}' does not exist — creating it."
    mkdir -p "${TRAFFIC_SNAPSHOT_DIR}"
    warn "  No snapshots to replay. Seed snapshots by capturing OPA decision logs."
    warn "  Expected format: { \"input\": {...}, \"expected_allow\": true|false }"
fi

SNAPSHOT_FILES=("${TRAFFIC_SNAPSHOT_DIR}"/*.json 2>/dev/null || true)

if [ ${#SNAPSHOT_FILES[@]} -eq 0 ] || [ ! -f "${SNAPSHOT_FILES[0]}" ]; then
    warn "  No JSON snapshots found in ${TRAFFIC_SNAPSHOT_DIR}. Skipping replay."
else
    for snapshot in "${TRAFFIC_SNAPSHOT_DIR}"/*.json; do
        TOTAL=$((TOTAL + 1))

        # Extract fields from snapshot
        INPUT_JSON=$(jq '.input' "${snapshot}")
        EXPECTED_ALLOW=$(jq '.expected_allow' "${snapshot}")
        SNAPSHOT_NAME=$(basename "${snapshot}")

        # Evaluate candidate policy
        RESULT=$(echo "${INPUT_JSON}" | \
            opa eval \
                --bundle "${OPA_BUNDLE_ROOT}" \
                --data "${POLICY_FILE}" \
                --stdin-input \
                --format raw \
                "data.system.authz.allow" 2>/dev/null || echo "false")

        # Normalise result
        RESULT_BOOL="${RESULT//[[:space:]]/}"
        RESULT_BOOL="${RESULT_BOOL,,}"  # lowercase

        if [ "${RESULT_BOOL}" = "${EXPECTED_ALLOW}" ]; then
            info "  ✅ PASS — ${SNAPSHOT_NAME} (allow=${RESULT_BOOL})"
            PASS=$((PASS + 1))
        else
            error "  ❌ FAIL — ${SNAPSHOT_NAME}: expected allow=${EXPECTED_ALLOW}, got allow=${RESULT_BOOL}"
            FAIL=$((FAIL + 1))
        fi
    done
fi

# ---------------------------------------------------------------------------
# Step 4: Summary and optional kubectl apply
# ---------------------------------------------------------------------------

echo ""
info "Step 4/4 — Summary"
info "  Total: ${TOTAL} | Pass: ${PASS} | Fail: ${FAIL}"

if [ "${FAIL}" -gt 0 ]; then
    error "❌ Canary FAILED — ${FAIL} regression(s) detected. Aborting Secret update."
    exit 1
fi

info "✅ All canary checks passed."

if [ "${DRY_RUN}" = "true" ]; then
    warn "DRY_RUN=true — skipping kubectl Secret update."
    exit 0
fi

# ---------------------------------------------------------------------------
# Update the live Kubernetes Secret with the validated policy
# ---------------------------------------------------------------------------

if command -v kubectl &>/dev/null; then
    info "Updating Kubernetes Secret '${SECRET_NAME}' in namespace '${NAMESPACE}'..."
    kubectl create secret generic "${SECRET_NAME}" \
        --from-file="${SECRET_KEY}=${POLICY_FILE}" \
        --namespace="${NAMESPACE}" \
        --dry-run=client -o yaml \
        | kubectl apply -f -
    info "✅ Secret '${SECRET_NAME}/${SECRET_KEY}' updated successfully."
else
    warn "kubectl not found — skipping live Secret update."
    warn "Deploy manually:"
    warn "  kubectl create secret generic ${SECRET_NAME} \\"
    warn "    --from-file=${SECRET_KEY}=${POLICY_FILE} \\"
    warn "    --namespace=${NAMESPACE} --dry-run=client -o yaml | kubectl apply -f -"
fi
