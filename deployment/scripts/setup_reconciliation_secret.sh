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

# Color output for better visibility
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
echo_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
echo_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Validate required environment variables
NAMESPACE="${NAMESPACE:-governance-stack}"
SECRET_NAME="reconciliation-worker-secrets"
KMS_KEY="${KMS_KEY:?ERROR: KMS_KEY env var is required. Example: KMS_KEY=projects/my-project/locations/us-central1/keyRings/cage-signing-dev/cryptoKeys/reconciler-snapshot/cryptoKeyVersions/1}"

echo_info "Reconciliation Worker Secret Setup (POAM-2026-038 Activation)"
echo_info "============================================================"
echo_info "Namespace:  ${NAMESPACE}"
echo_info "Secret:     ${SECRET_NAME}"
echo_info "KMS Key:    ${KMS_KEY}"
echo ""

# Validate KMS key format
if [[ ! "${KMS_KEY}" =~ ^projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+(/cryptoKeyVersions/[0-9]+)?$ ]]; then
  echo_error "KMS_KEY format is invalid. Expected: projects/<project>/locations/<region>/keyRings/<ring>/cryptoKeys/<key>[/cryptoKeyVersions/<n>]"
  exit 1
fi

# Check if namespace exists
if ! kubectl get namespace "${NAMESPACE}" &>/dev/null; then
  echo_error "Namespace '${NAMESPACE}' does not exist. Create it first or check your kubectl context."
  exit 1
fi

echo_info "Checking prerequisites..."

# Verify KMS key exists (requires gcloud)
if command -v gcloud &>/dev/null; then
  # Extract project and key details from the full resource name
  KMS_PROJECT=$(echo "${KMS_KEY}" | cut -d'/' -f2)
  KMS_LOCATION=$(echo "${KMS_KEY}" | cut -d'/' -f4)
  KMS_KEYRING=$(echo "${KMS_KEY}" | cut -d'/' -f6)
  KMS_KEYNAME=$(echo "${KMS_KEY}" | cut -d'/' -f8)
  
  if gcloud kms keys describe "${KMS_KEYNAME}" \
      --project="${KMS_PROJECT}" \
      --location="${KMS_LOCATION}" \
      --keyring="${KMS_KEYRING}" &>/dev/null; then
    echo_info "✓ KMS key exists and is accessible"
  else
    echo_warn "⚠ Cannot verify KMS key - ensure it exists and service account has roles/cloudkms.signer role"
  fi
else
  echo_warn "⚠ gcloud not found - skipping KMS key verification"
fi

echo ""
echo_info "Creating/updating secret '${SECRET_NAME}' in namespace '${NAMESPACE}'..."

# Create or update the secret with all required keys
kubectl create secret generic "${SECRET_NAME}" \
  --namespace="${NAMESPACE}" \
  --from-literal=reconciler-kms-key="${KMS_KEY}" \
  --dry-run=client -o yaml | kubectl apply -f -

echo ""
echo_info "Secret created/updated successfully!"
echo ""

# Verify the secret
echo_info "Verifying secret contents..."
SECRET_KEYS=$(kubectl get secret "${SECRET_NAME}" -n "${NAMESPACE}" -o jsonpath='{.data}' 2>/dev/null | jq -r 'keys[]' 2>/dev/null || echo "")

if echo "${SECRET_KEYS}" | grep -q "reconciler-kms-key"; then
  echo_info "✓ reconciler-kms-key key present"
else
  echo_error "✗ reconciler-kms-key key missing"
fi

echo ""
echo_info "============================================================"
echo_info "NEXT STEPS:"
echo_info "1. Verify the reconciliation-worker Deployment is running:"
echo_info "   kubectl rollout status deployment/reconciliation-worker -n ${NAMESPACE}"
echo ""
echo_info "2. Restart it to pick up the new secret:"
echo_info "   kubectl rollout restart deployment/reconciliation-worker -n ${NAMESPACE}"
echo ""
echo_info "3. Check logs:"
echo_info "   kubectl logs -l app=reconciliation-worker -n ${NAMESPACE} --tail=100"
echo ""
echo_info "4. Verify Redis has the signed balance:"
echo_info "   kubectl exec -it redis-stack-0 -n ${NAMESPACE} -- redis-cli GET cage:ground_truth:finance.cash_balance"
echo ""
echo_info "5. Once verified, update POAM-2026-038 status in docs/POAM.md"
echo_info "============================================================"
