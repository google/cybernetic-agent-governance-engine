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

set -eo pipefail

if [[ -z "$PROJECT_ID" ]]; then
  echo "❌ Error: PROJECT_ID environment variable is not set."
  exit 1
fi

# Capture the short git SHA once so every build is tagged identically.
# $SHORT_SHA is a Cloud Build built-in substitution that only exists inside a
# Cloud Build execution context; when submitting via gcloud we must supply it
# ourselves from the local git state.
SHORT_SHA="$(git rev-parse --short HEAD 2>/dev/null || echo "v1")"
ENVIRONMENT="${ENVIRONMENT:-staging}"
KMS_LOCATION="${KMS_LOCATION:-us-central1}"
KMS_KEY_VERSION="${KMS_KEY_VERSION:-1}"
echo "📌 Short SHA: ${SHORT_SHA} | Environment: ${ENVIRONMENT} | KMS Location: ${KMS_LOCATION}"

wait_for_pids=()

# build_image IMAGE_NAME DOCKERFILE CONTEXT_DIR
#
# Generates an ephemeral Cloud Build config that:
#   - Builds with --no-cache (prevents stale-layer cache poisoning)
#   - Tags with :<short-sha> (never mutable floating tags — SI-7 / CM-7 / POAM-2026-083)
#   - Pushes the immutable digest and signs it via Binary Authorization
#   - Uses E2_HIGHCPU_8 and a 20-minute timeout (matches cloudbuild.compliance.yaml)
#   - Routes logs to Cloud Logging only
build_image() {
  local image_name=$1
  local dockerfile=$2
  local context_dir=$3

  local registry="gcr.io/${PROJECT_ID}"
  local full_image_sha="${registry}/${image_name}:${SHORT_SHA}"

  echo "🏗️  Starting build & attestation for ${image_name} (${SHORT_SHA}) using ${dockerfile}..."

  local cb_file
  cb_file=$(mktemp -t cloudbuild.XXXXXX)

  cat <<EOF > "$cb_file"
steps:
- name: 'gcr.io/cloud-builders/docker'
  id: build-${image_name}
  args:
    - 'build'
    - '--no-cache'
    - '--file=${dockerfile}'
    - '--tag=${full_image_sha}'
    - '${context_dir}'
- name: 'gcr.io/cloud-builders/docker'
  id: push-${image_name}
  args: ['push', '${full_image_sha}']
- name: 'gcr.io/google.com/cloudsdktool/cloud-sdk:slim'
  id: attest-${image_name}
  entrypoint: 'bash'
  args:
    - '-ceu'
    - |
      DIGEST=\$\$(gcloud container images describe "${full_image_sha}" --format='get(image_summary.digest)')
      gcloud container binauthz attestations sign-and-create \\
        --project="${PROJECT_ID}" \\
        --artifact-url="${registry}/${image_name}@\$\${DIGEST}" \\
        --attestor="projects/${PROJECT_ID}/attestors/cage-build-attestor-${ENVIRONMENT}" \\
        --keyversion-project="${PROJECT_ID}" \\
        --keyversion-location="${KMS_LOCATION}" \\
        --keyversion-keyring="cage-signing-${ENVIRONMENT}" \\
        --keyversion-key="binauthz-attestor" \\
        --keyversion="${KMS_KEY_VERSION}"
images:
  - '${full_image_sha}'
timeout: '1200s'
options:
  machineType: 'E2_HIGHCPU_8'
  logging: CLOUD_LOGGING_ONLY
EOF

  # Fire and forget (in the background)
  gcloud builds submit --config "$cb_file" --project "$PROJECT_ID" "$context_dir" > "/tmp/build_${image_name}.log" 2>&1 &
  local pid=$!
  wait_for_pids+=("$pid")

  # Register cleanup
  trap 'rm -f "$cb_file"' EXIT
}

# 1. Backend / Governed Financial Advisor
echo "🏗️  Starting build & attestation for governed-financial-advisor (${SHORT_SHA})..."
cb_backend=$(mktemp -t cloudbuild_backend.XXXXXX)
cat <<EOF > "$cb_backend"
steps:
- name: 'gcr.io/cloud-builders/docker'
  id: build-governed-financial-advisor
  args:
    - 'build'
    - '--no-cache'
    - '-t'
    - 'gcr.io/${PROJECT_ID}/governed-financial-advisor:${SHORT_SHA}'
    - '-f'
    - 'Dockerfile'
    - '.'
- name: 'gcr.io/cloud-builders/docker'
  id: push-governed-financial-advisor
  args: ['push', 'gcr.io/${PROJECT_ID}/governed-financial-advisor:${SHORT_SHA}']
- name: 'gcr.io/google.com/cloudsdktool/cloud-sdk:slim'
  id: attest-governed-financial-advisor
  entrypoint: 'bash'
  args:
    - '-ceu'
    - |
      DIGEST=\$\$(gcloud container images describe "gcr.io/${PROJECT_ID}/governed-financial-advisor:${SHORT_SHA}" --format='get(image_summary.digest)')
      gcloud container binauthz attestations sign-and-create \\
        --project="${PROJECT_ID}" \\
        --artifact-url="gcr.io/${PROJECT_ID}/governed-financial-advisor@\$\${DIGEST}" \\
        --attestor="projects/${PROJECT_ID}/attestors/cage-build-attestor-${ENVIRONMENT}" \\
        --keyversion-project="${PROJECT_ID}" \\
        --keyversion-location="${KMS_LOCATION}" \\
        --keyversion-keyring="cage-signing-${ENVIRONMENT}" \\
        --keyversion-key="binauthz-attestor" \\
        --keyversion="${KMS_KEY_VERSION}"
images:
  - 'gcr.io/${PROJECT_ID}/governed-financial-advisor:${SHORT_SHA}'
timeout: '1200s'
options:
  machineType: 'E2_HIGHCPU_8'
  logging: CLOUD_LOGGING_ONLY
EOF
gcloud builds submit --config "$cb_backend" --project "$PROJECT_ID" . > "/tmp/build_backend.log" 2>&1 &
wait_for_pids+=("$!")
trap 'rm -f "$cb_backend"' EXIT

# 2. vLLM Streamer
if [[ "${SKIP_VLLM:-false}" == "true" ]]; then
  echo "⏩ Skipping vLLM Streamer build (SKIP_VLLM=true)."
elif [[ -f "deployment/docker/cloudbuild.vllm.yaml" ]]; then
  echo "🏗️  Starting build & attestation for vllm-streamer..."
  gcloud builds submit --config "deployment/docker/cloudbuild.vllm.yaml" \
    --project "$PROJECT_ID" \
    --substitutions="_SHORT_SHA=${SHORT_SHA},_ENVIRONMENT=${ENVIRONMENT},_KMS_LOCATION=${KMS_LOCATION},_KMS_KEY_VERSION=${KMS_KEY_VERSION}" . > "/tmp/build_vllm.log" 2>&1 &
  wait_for_pids+=("$!")
else
  echo "⚠️  deployment/docker/cloudbuild.vllm.yaml not found. Skipping vLLM Streamer build."
fi

# 3. Gateway
if [[ -d "src/gateway" ]]; then
  build_image "gateway" "src/gateway/Dockerfile" "."
else
  echo "⚠️  src/gateway directory not found. Skipping Gateway build."
fi

# 4. AgentSight UI
build_image "agentsight-ui" "src/agentsight-ui/Dockerfile" "."

# 5. Compliance Bridge
if [[ -d "src/compliance_bridge" ]]; then
  build_image "compliance-bridge" "src/compliance_bridge/Dockerfile" "."
else
  echo "⚠️  src/compliance_bridge directory not found. Skipping Compliance Bridge build."
fi

# 6. NeMo Guardrails
build_image "nemo-guardrails" "deployment/docker/Dockerfile.nemo" "."

# 7. Third-party images (Presidio, vLLM base, OPA, Redis, ClickHouse, Langfuse, Cloud SQL Proxy)
if [[ "${MIRROR_THIRD_PARTY_IMAGES:-false}" == "true" ]]; then
  echo "🪞 Mirroring and attesting third-party images into gcr.io/${PROJECT_ID}..."
  PROJECT_ID="$PROJECT_ID" ENVIRONMENT="$ENVIRONMENT" KMS_LOCATION="$KMS_LOCATION" KMS_KEY_VERSION="$KMS_KEY_VERSION" \
    bash scripts/mirror_and_attest_images.sh &
  wait_for_pids+=("$!")
fi

echo "⏳ Waiting for all Cloud Build jobs to finish..."
fail=0
for pid in "${wait_for_pids[@]}"; do
  if ! wait "$pid"; then
    echo "❌ A Cloud Build job failed!"
    fail=1
  fi
done

if [[ $fail -eq 1 ]]; then
  echo "❌ One or more image builds failed."
  exit 1
fi

echo "✅ All images built and attested successfully! SHA: ${SHORT_SHA}"
