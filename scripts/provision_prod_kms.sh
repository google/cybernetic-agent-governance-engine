#!/bin/bash
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
# provision_prod_kms.sh — Production KMS Key Provisioning for FTRA Registry Signing
# ===================================================================================
#
# Provisions a GCP Cloud KMS asymmetric signing key for governance plan signatures.
# This script is part of the FTRA registry signing pipeline (VEC-005, VEC-008).
#
# Prerequisites:
#   - gcloud CLI authenticated with project-level IAM permissions
#   - Role: roles/cloudkms.admin (or equivalent)
#   - Target GCP project configured via `gcloud config set project <PROJECT_ID>`
#
# Reference Architecture Note:
#   This script demonstrates the provisioning pattern for a reference KMS deployment.
#   Adopters should adapt key location, algorithm, and IAM bindings to match their
#   compliance posture (e.g., CMEK region requirements, HSM tier selection).
#
# Usage:
#   ./scripts/provision_prod_kms.sh
#
# Outputs:
#   - KeyRing: cage-governance-ring (us-central1)
#   - CryptoKey: ftra-registry-signer (EC_SIGN_P256_SHA256)
#   - Public key PEM: ./config/kms_public_key.pem
#   - Key version resource name printed to stdout
#

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

PROJECT_ID="${GCP_PROJECT_ID:-$(gcloud config get-value project 2>/dev/null)}"
LOCATION="${KMS_LOCATION:-us-central1}"
KEYRING_NAME="cage-governance-ring"
KEY_NAME="ftra-registry-signer"
KEY_PURPOSE="ASYMMETRIC_SIGN"
KEY_ALGORITHM="EC_SIGN_P256_SHA256"
SERVICE_ACCOUNT="${CLOUD_BUILD_SA:-}" # e.g., 12345@cloudbuild.gserviceaccount.com

# Output paths
CONFIG_DIR="./config"
PUBLIC_KEY_PATH="${CONFIG_DIR}/kms_public_key.pem"

# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

if [ -z "$PROJECT_ID" ]; then
    echo "ERROR: GCP_PROJECT_ID is not set and no active gcloud project found."
    echo "Set the project with: gcloud config set project <PROJECT_ID>"
    exit 1
fi

echo "==================================================================="
echo "  GCP Cloud KMS Provisioning for FTRA Registry Signing"
echo "==================================================================="
echo "Project:      $PROJECT_ID"
echo "Location:     $LOCATION"
echo "KeyRing:      $KEYRING_NAME"
echo "CryptoKey:    $KEY_NAME"
echo "Algorithm:    $KEY_ALGORITHM"
echo "==================================================================="
echo ""

# ---------------------------------------------------------------------------
# Step 1: Create KeyRing (idempotent)
# ---------------------------------------------------------------------------

echo "[1/5] Creating KeyRing: ${KEYRING_NAME}..."
if gcloud kms keyrings describe "$KEYRING_NAME" \
    --location="$LOCATION" \
    --project="$PROJECT_ID" &>/dev/null; then
    echo "      ✓ KeyRing already exists: ${KEYRING_NAME}"
else
    gcloud kms keyrings create "$KEYRING_NAME" \
        --location="$LOCATION" \
        --project="$PROJECT_ID"
    echo "      ✓ KeyRing created: ${KEYRING_NAME}"
fi
echo ""

# ---------------------------------------------------------------------------
# Step 2: Create CryptoKey (idempotent)
# ---------------------------------------------------------------------------

echo "[2/5] Creating CryptoKey: ${KEY_NAME}..."
if gcloud kms keys describe "$KEY_NAME" \
    --keyring="$KEYRING_NAME" \
    --location="$LOCATION" \
    --project="$PROJECT_ID" &>/dev/null; then
    echo "      ✓ CryptoKey already exists: ${KEY_NAME}"
else
    gcloud kms keys create "$KEY_NAME" \
        --keyring="$KEYRING_NAME" \
        --location="$LOCATION" \
        --purpose="$KEY_PURPOSE" \
        --default-algorithm="$KEY_ALGORITHM" \
        --project="$PROJECT_ID"
    echo "      ✓ CryptoKey created: ${KEY_NAME}"
fi
echo ""

# ---------------------------------------------------------------------------
# Step 3: Get CryptoKeyVersion resource name
# ---------------------------------------------------------------------------

echo "[3/5] Retrieving CryptoKeyVersion resource name..."
KEY_VERSION=$(gcloud kms keys versions list \
    --key="$KEY_NAME" \
    --keyring="$KEYRING_NAME" \
    --location="$LOCATION" \
    --project="$PROJECT_ID" \
    --filter="state=ENABLED" \
    --format="value(name)" \
    --limit=1)

if [ -z "$KEY_VERSION" ]; then
    echo "ERROR: No ENABLED CryptoKeyVersion found for key: ${KEY_NAME}"
    echo "This may occur immediately after key creation. Wait 30 seconds and retry."
    exit 1
fi

# Convert to full resource name
FULL_KEY_VERSION="projects/${PROJECT_ID}/locations/${LOCATION}/keyRings/${KEYRING_NAME}/cryptoKeys/${KEY_NAME}/cryptoKeyVersions/${KEY_VERSION##*/}"

echo "      ✓ CryptoKeyVersion: ${FULL_KEY_VERSION}"
echo ""

# ---------------------------------------------------------------------------
# Step 4: Add IAM policy binding for Cloud Build service account (optional)
# ---------------------------------------------------------------------------

echo "[4/5] Adding IAM policy binding for Cloud Build..."
if [ -n "$SERVICE_ACCOUNT" ]; then
    gcloud kms keys add-iam-policy-binding "$KEY_NAME" \
        --keyring="$KEYRING_NAME" \
        --location="$LOCATION" \
        --project="$PROJECT_ID" \
        --member="serviceAccount:${SERVICE_ACCOUNT}" \
        --role="roles/cloudkms.signerVerifier"
    echo "      ✓ IAM binding added for: ${SERVICE_ACCOUNT}"
else
    echo "      ⚠ CLOUD_BUILD_SA not set — skipping IAM binding"
    echo "      Manual step required: Grant 'roles/cloudkms.signerVerifier' to the service account"
fi
echo ""

# ---------------------------------------------------------------------------
# Step 5: Extract public key to PEM
# ---------------------------------------------------------------------------

echo "[5/5] Extracting public key to PEM..."
mkdir -p "$CONFIG_DIR"

gcloud kms keys versions get-public-key "$KEY_VERSION" \
    --key="$KEY_NAME" \
    --keyring="$KEYRING_NAME" \
    --location="$LOCATION" \
    --project="$PROJECT_ID" \
    --output-file="$PUBLIC_KEY_PATH"

echo "      ✓ Public key written to: ${PUBLIC_KEY_PATH}"
echo ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo "==================================================================="
echo "  ✅ KMS Provisioning Complete"
echo "==================================================================="
echo ""
echo "Set the following environment variables in your deployment:"
echo ""
echo "  export KMS_GOVERNANCE_KEY=\"${FULL_KEY_VERSION}\""
echo "  export KMS_GOVERNANCE_PUBLIC_PEM=\"${PUBLIC_KEY_PATH}\""
echo ""
echo "For Kubernetes deployments, create a Secret:"
echo ""
echo "  kubectl create secret generic kms-governance-config \\"
echo "    --from-literal=key-version=\"${FULL_KEY_VERSION}\" \\"
echo "    --from-file=public-key=\"${PUBLIC_KEY_PATH}\" \\"
echo "    --namespace=governance-stack"
echo ""
echo "For Cloud Build, add to substitutions in cloudbuild.gateway.yaml:"
echo ""
echo "  substitutions:"
echo "    _KMS_GOVERNANCE_KEY: \"${FULL_KEY_VERSION}\""
echo ""
echo "==================================================================="
