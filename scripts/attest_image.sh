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

# Single canonical Binary Authorization attestation script (SI-7 / CM-7 / POAM-2026-083).
#
# Resolves <image:tag> to its immutable @sha256 digest, signs and creates a
# Binary Authorization attestation using `gcloud beta container binauthz
# attestations sign-and-create` (no GA fallback), and fails closed by listing
# attestations for the digest and exiting non-zero if none exist.
#
# Usage:
#   PROJECT_ID=<project> scripts/attest_image.sh <image:tag> [environment] [kms_location] [kms_key_version]

set -euo pipefail

if [[ -z "${PROJECT_ID:-}" ]]; then
  echo "❌ Error: PROJECT_ID environment variable is not set." >&2
  exit 1
fi

if [[ $# -lt 1 || -z "${1:-}" ]]; then
  echo "❌ Usage: $0 <image:tag> [environment] [kms_location] [kms_key_version]" >&2
  exit 1
fi

IMAGE_TAG="$1"
ENVIRONMENT="${2:-${ENVIRONMENT:-staging}}"
KMS_LOCATION="${3:-${KMS_LOCATION:-us-central1}}"
KMS_KEY_VERSION="${4:-${KMS_KEY_VERSION:-1}}"

IMAGE_REPO="${IMAGE_TAG%:*}"
TAG_PART="${IMAGE_TAG##*:}"
if [[ -z "${IMAGE_REPO}" || "${IMAGE_REPO}" == "${IMAGE_TAG}" || -z "${TAG_PART}" ]]; then
  echo "❌ Error: expected <image:tag>, got '${IMAGE_TAG}'." >&2
  exit 1
fi

if [[ "${TAG_PART}" == "latest" ]]; then
  echo "❌ Error: refusing to attest mutable ':latest' tag ('${IMAGE_TAG}')." >&2
  exit 1
fi

echo "🔍 Resolving immutable digest for ${IMAGE_TAG}..."
DIGEST="$(gcloud container images describe "${IMAGE_TAG}" --format='get(image_summary.digest)')"
if [[ -z "${DIGEST}" || ! "${DIGEST}" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo "❌ Error: failed to resolve sha256 digest for ${IMAGE_TAG} (got: '${DIGEST}')." >&2
  exit 1
fi

ARTIFACT_URL="${IMAGE_REPO}@${DIGEST}"
ATTESTOR="projects/${PROJECT_ID}/attestors/cage-build-attestor-${ENVIRONMENT}"

echo "🔏 Signing Binary Authorization attestation for ${ARTIFACT_URL} via ${ATTESTOR}..."
gcloud beta container binauthz attestations sign-and-create \
  --project="${PROJECT_ID}" \
  --artifact-url="${ARTIFACT_URL}" \
  --attestor="${ATTESTOR}" \
  --keyversion-project="${PROJECT_ID}" \
  --keyversion-location="${KMS_LOCATION}" \
  --keyversion-keyring="cage-signing-${ENVIRONMENT}" \
  --keyversion-key="binauthz-attestor" \
  --keyversion="${KMS_KEY_VERSION}" || true

echo "✅ Verifying attestation occurrence exists for ${ARTIFACT_URL}..."
MAX_ATTEMPTS="${ATTESTATION_LIST_MAX_ATTEMPTS:-6}"
SLEEP_SECONDS="${ATTESTATION_LIST_SLEEP_SECONDS:-2}"
ATTESTATION_URIS=""
for ((attempt = 1; attempt <= MAX_ATTEMPTS; attempt++)); do
  ATTESTATION_URIS="$(gcloud beta container binauthz attestations list \
    --project="${PROJECT_ID}" \
    --attestor="${ATTESTOR}" \
    --artifact-url="${ARTIFACT_URL}" \
    --format='value(name)')"
  if [[ -n "${ATTESTATION_URIS}" ]]; then
    break
  fi
  if (( attempt < MAX_ATTEMPTS )) && [[ "${SLEEP_SECONDS}" != "0" ]]; then
    sleep "${SLEEP_SECONDS}"
  fi
done

if [[ -z "${ATTESTATION_URIS}" ]]; then
  echo "❌ Error: fail-closed attestation check failed — no attestation found for ${ARTIFACT_URL}." >&2
  exit 1
fi

echo "🔒 Verified Binary Authorization attestation for ${ARTIFACT_URL}: ${ATTESTATION_URIS}"
