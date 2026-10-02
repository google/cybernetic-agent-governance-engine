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

# Build, push, and attest all CAGE first-party container images in parallel via
# Cloud Build using `deployment/docker/cloudbuild.image.yaml` (and
# `deployment/docker/cloudbuild.vllm.yaml` for the high-CPU vLLM streamer image).
#
# Every build executes under the dedicated Cloud Build service account
# `cage-cloudbuild-${ENVIRONMENT}@${PROJECT_ID}.iam.gserviceaccount.com` and
# invokes `scripts/attest_image.sh` (SI-7 / CM-7 / POAM-2026-083).

set -euo pipefail

if [[ -z "${PROJECT_ID:-}" ]]; then
  echo "❌ Error: PROJECT_ID environment variable is not set." >&2
  exit 1
fi

# Capture the short git SHA once so every build is tagged identically.
# Refuse to build outside a git checkout — mutable/fallback tags ("v1", "latest")
# are prohibited under Binary Authorization (SI-7 / CM-7 / POAM-2026-083).
if ! SHORT_SHA="$(git rev-parse --short HEAD 2>/dev/null)" || [[ -z "${SHORT_SHA}" ]]; then
  echo "❌ Error: refusing to build outside a git checkout (immutable git SHA required)." >&2
  exit 1
fi

ENVIRONMENT="${ENVIRONMENT:-staging}"
KMS_LOCATION="${KMS_LOCATION:-us-central1}"
KMS_KEY_VERSION="${KMS_KEY_VERSION:-1}"
CLOUDBUILD_SA="projects/${PROJECT_ID}/serviceAccounts/cage-cloudbuild-${ENVIRONMENT}@${PROJECT_ID}.iam.gserviceaccount.com"

echo "📌 Short SHA: ${SHORT_SHA} | Environment: ${ENVIRONMENT} | KMS Location: ${KMS_LOCATION}"
echo "🔐 Cloud Build SA: ${CLOUDBUILD_SA}"

FIRST_PARTY_IMAGES=(
  "governed-financial-advisor|Dockerfile"
  "gateway|src/gateway/Dockerfile"
  "agentsight-ui|src/agentsight-ui/Dockerfile"
  "compliance-bridge|src/compliance_bridge/Dockerfile"
  "nemo-guardrails|deployment/docker/Dockerfile.nemo"
)

wait_for_pids=()
build_names=()

for entry in "${FIRST_PARTY_IMAGES[@]}"; do
  IFS='|' read -r image_name dockerfile <<< "${entry}"
  if [[ -n "${ONLY_IMAGE:-}" && "${ONLY_IMAGE}" != "${image_name}" ]]; then
    continue
  fi
  if [[ ! -f "${dockerfile}" ]]; then
    echo "❌ Error: Dockerfile not found for ${image_name}: ${dockerfile}" >&2
    exit 1
  fi
  echo "🏗️  Starting build & attestation for ${image_name} (${SHORT_SHA}) using ${dockerfile}..."
  gcloud builds submit \
    --config "deployment/docker/cloudbuild.image.yaml" \
    --project "${PROJECT_ID}" \
    --service-account "${CLOUDBUILD_SA}" \
    --substitutions="_IMAGE_NAME=${image_name},_DOCKERFILE=${dockerfile},_SHORT_SHA=${SHORT_SHA},_ENVIRONMENT=${ENVIRONMENT},_KMS_LOCATION=${KMS_LOCATION},_KMS_KEY_VERSION=${KMS_KEY_VERSION}" \
    . > "/tmp/build_${image_name}.log" 2>&1 &
  wait_for_pids+=("$!")
  build_names+=("${image_name}")
done

# vLLM Streamer uses its dedicated high-CPU / 40-minute config
if [[ "${SKIP_VLLM:-false}" == "true" ]]; then
  echo "⏩ Skipping vLLM Streamer build (SKIP_VLLM=true)."
elif [[ -n "${ONLY_IMAGE:-}" && "${ONLY_IMAGE}" != "vllm-streamer" ]]; then
  :
elif [[ -f "deployment/docker/cloudbuild.vllm.yaml" ]]; then
  echo "🏗️  Starting build & attestation for vllm-streamer (${SHORT_SHA})..."
  gcloud builds submit \
    --config "deployment/docker/cloudbuild.vllm.yaml" \
    --project "${PROJECT_ID}" \
    --service-account "${CLOUDBUILD_SA}" \
    --substitutions="_SHORT_SHA=${SHORT_SHA},_ENVIRONMENT=${ENVIRONMENT},_KMS_LOCATION=${KMS_LOCATION},_KMS_KEY_VERSION=${KMS_KEY_VERSION}" \
    . > "/tmp/build_vllm-streamer.log" 2>&1 &
  wait_for_pids+=("$!")
  build_names+=("vllm-streamer")
else
  echo "⚠️  deployment/docker/cloudbuild.vllm.yaml not found. Skipping vLLM Streamer build."
fi

# Third-party images (Presidio, OPA, Redis, ClickHouse, Langfuse, Cloud SQL Proxy)
if [[ "${MIRROR_THIRD_PARTY_IMAGES:-true}" == "true" && -z "${ONLY_IMAGE:-}" ]]; then
  echo "🪞 Mirroring and attesting third-party images into gcr.io/${PROJECT_ID}..."
  PROJECT_ID="${PROJECT_ID}" ENVIRONMENT="${ENVIRONMENT}" KMS_LOCATION="${KMS_LOCATION}" KMS_KEY_VERSION="${KMS_KEY_VERSION}" \
    bash scripts/mirror_and_attest_images.sh > "/tmp/build_mirror-third-party.log" 2>&1 &
  wait_for_pids+=("$!")
  build_names+=("mirror-third-party")
fi

echo "⏳ Waiting for ${#wait_for_pids[@]} Cloud Build job(s) to finish..."
fail=0
for idx in "${!wait_for_pids[@]}"; do
  pid="${wait_for_pids[$idx]}"
  name="${build_names[$idx]}"
  if ! wait "${pid}"; then
    echo "❌ Cloud Build job failed for ${name} (see /tmp/build_${name}.log)" >&2
    fail=1
  else
    echo "✅ Cloud Build job succeeded for ${name}"
  fi
done

if [[ "${fail}" -eq 1 ]]; then
  echo "❌ One or more image builds failed." >&2
  exit 1
fi

echo "✅ All images built and attested successfully! SHA: ${SHORT_SHA}"
if [[ -z "${ONLY_IMAGE:-}" ]]; then
  echo ""
  echo "📋 Resolved image_digests block for ${SHORT_SHA}:"
  PROJECT_ID="${PROJECT_ID}" SKIP_VLLM="${SKIP_VLLM:-false}" bash scripts/render_image_digests.sh "${SHORT_SHA}"
fi
