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
GCS_BUCKET="${GCS_BUCKET:?ERROR: GCS_BUCKET env var is required. Example: GCS_BUCKET=my-reconciliation-bucket}"
KMS_KEY="${KMS_KEY:?ERROR: KMS_KEY env var is required. Example: KMS_KEY=projects/my-project/locations/us-central1/keyRings/governance/cryptoKeys/balance-signer}"
GCS_OBJECT="${GCS_OBJECT:-reconciliation/latest.json}"

echo_info "Reconciliation Worker Secret Setup (POAM-2026-038 Activation)"
echo_info "============================================================"
echo_info "Namespace:  ${NAMESPACE}"
echo_info "Secret:     ${SECRET_NAME}"
echo_info "GCS Bucket: ${GCS_BUCKET}"
echo_info "GCS Object: ${GCS_OBJECT}"
echo_info "KMS Key:    ${KMS_KEY}"
echo ""

# Validate KMS key format
if [[ ! "${KMS_KEY}" =~ ^projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+$ ]]; then
  echo_error "KMS_KEY format is invalid. Expected: projects/<project>/locations/<region>/keyRings/<ring>/cryptoKeys/<key>"
  exit 1
fi

# Check if namespace exists
if ! kubectl get namespace "${NAMESPACE}" &>/dev/null; then
  echo_error "Namespace '${NAMESPACE}' does not exist. Create it first or check your kubectl context."
  exit 1
fi

echo_info "Checking prerequisites..."

# Verify GCS bucket exists and is accessible (requires gsutil)
if command -v gsutil &>/dev/null; then
  if gsutil ls "gs://${GCS_BUCKET}/" &>/dev/null; then
    echo_info "✓ GCS bucket '${GCS_BUCKET}' exists and is accessible"
  else
    echo_warn "⚠ Cannot verify GCS bucket '${GCS_BUCKET}' - ensure it exists and service account has access"
  fi
else
  echo_warn "⚠ gsutil not found - skipping GCS bucket verification"
fi

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
    echo_warn "⚠ Cannot verify KMS key - ensure it exists and service account has signerVerifier role"
  fi
else
  echo_warn "⚠ gcloud not found - skipping KMS key verification"
fi

echo ""
echo_info "Creating/updating secret '${SECRET_NAME}' in namespace '${NAMESPACE}'..."

# Create or update the secret with all required keys
kubectl create secret generic "${SECRET_NAME}" \
  --namespace="${NAMESPACE}" \
  --from-literal=gcs-reconciliation-bucket="${GCS_BUCKET}" \
  --from-literal=gcs-reconciliation-object="${GCS_OBJECT}" \
  --from-literal=kms-governance-key="${KMS_KEY}" \
  --dry-run=client -o yaml | kubectl apply -f -

echo ""
echo_info "Secret created/updated successfully!"
echo ""

# Verify the secret
echo_info "Verifying secret contents..."
SECRET_KEYS=$(kubectl get secret "${SECRET_NAME}" -n "${NAMESPACE}" -o jsonpath='{.data}' 2>/dev/null | jq -r 'keys[]' 2>/dev/null || echo "")

if echo "${SECRET_KEYS}" | grep -q "gcs-reconciliation-bucket"; then
  echo_info "✓ gcs-reconciliation-bucket key present"
else
  echo_error "✗ gcs-reconciliation-bucket key missing"
fi

if echo "${SECRET_KEYS}" | grep -q "kms-governance-key"; then
  echo_info "✓ kms-governance-key key present"
else
  echo_error "✗ kms-governance-key key missing"
fi

echo ""
echo_info "============================================================"
echo_info "NEXT STEPS:"
echo_info "1. Verify the reconciliation-worker CronJob is deployed:"
echo_info "   kubectl get cronjob reconciliation-worker -n ${NAMESPACE}"
echo ""
echo_info "2. Trigger a manual run to test:"
echo_info "   kubectl create job --from=cronjob/reconciliation-worker test-reconciliation -n ${NAMESPACE}"
echo ""
echo_info "3. Check logs:"
echo_info "   kubectl logs -l app=reconciliation-worker -n ${NAMESPACE} --tail=100"
echo ""
echo_info "4. Verify Redis has the signed balance:"
echo_info "   kubectl exec -it redis-stack-0 -n ${NAMESPACE} -- redis-cli GET safety:verified_balance"
echo ""
echo_info "5. Once verified, update POAM-2026-038 status in docs/POAM.md"
echo_info "============================================================"
