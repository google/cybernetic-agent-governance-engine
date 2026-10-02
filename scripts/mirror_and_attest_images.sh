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

# Mirror third-party container images by immutable @sha256: digest into the
# project's Artifact Registry (gcr.io/${PROJECT_ID}/...) via Cloud Build and
# attest each mirrored digest with Binary Authorization via scripts/attest_image.sh
# (CM-7, SI-7, POAM-2026-083).
# No admission_whitelist_patterns are added for third-party registries.

set -euo pipefail

if [[ -z "${PROJECT_ID:-}" ]]; then
  echo "❌ Error: PROJECT_ID environment variable is not set." >&2
  exit 1
fi

ENVIRONMENT="${ENVIRONMENT:-staging}"
KMS_LOCATION="${KMS_LOCATION:-us-central1}"
KMS_KEY_VERSION="${KMS_KEY_VERSION:-1}"
REGISTRY="gcr.io/${PROJECT_ID}"
CLOUDBUILD_SA="projects/${PROJECT_ID}/serviceAccounts/cage-cloudbuild-${ENVIRONMENT}@${PROJECT_ID}.iam.gserviceaccount.com"

# Canonical digest-pinned upstream images mirrored into Artifact Registry.
THIRD_PARTY_IMAGES=(
  "presidio-analyzer|mcr.microsoft.com/presidio-analyzer@sha256:8e09d9f0a928e86b6c634eec9a8e668738508154cb7e683d7c7c62867ce4a514|2.2.357"
  "presidio-anonymizer|mcr.microsoft.com/presidio-anonymizer@sha256:e39a7671f51c40aa493201f0d3f71ad74efc98bbd34ccd417a4cfd3ffaa59ae4|2.2.357"
  "opa|openpolicyagent/opa@sha256:2636af0937bf7c5ab7f79271399c53c45d4b4d2af8a2b9cc43f65c6598b49064|1.2.0-static"
  "redis|redis@sha256:858f009f9709ce576febc734aa78b8f6d624b82571f9ddb6bda4377c833b3499|7.4-alpine"
  "clickhouse-server|docker.io/clickhouse/clickhouse-server@sha256:c3f166f4a80098480463d897a63f6867d24e3a7661fc1fe72e889788115a25f1|24.3-alpine"
  "clickhouse-keeper|docker.io/clickhouse/clickhouse-keeper@sha256:32686ea04febc134113d1b61109d1e0d0d7dc02a2b3dc098c1f035daeec4ba57|24.3-alpine"
  "langfuse|langfuse/langfuse@sha256:a343f64e035eb01aeea358703a0428945d909d01e19452509a5a830862dda878|3"
  "langfuse-worker|langfuse/langfuse-worker@sha256:8a28c946bb5401eef488153fa294db5a79bd99dd5c90db8e4d39559374c9ebd3|3"
  "cloud-sql-proxy|gcr.io/cloud-sql-connectors/cloud-sql-proxy@sha256:d3f195cb893f2abb2ce8f28a4d3eee9b5589750711b4fbf67c78ce215c520e96|2.14.2"
)

cb_dir=$(mktemp -d -t cloudbuild_mirror.XXXXXX)
trap 'rm -rf "$cb_dir"' EXIT

mkdir -p "${cb_dir}/scripts"
cp "scripts/attest_image.sh" "${cb_dir}/scripts/attest_image.sh"
chmod +x "${cb_dir}/scripts/attest_image.sh"

wait_for_pids=()
mirror_names=()

for entry in "${THIRD_PARTY_IMAGES[@]}"; do
  IFS='|' read -r name upstream_ref version_tag <<< "$entry"
  target_tag="${REGISTRY}/${name}:${version_tag}"
  cb_file="${cb_dir}/cloudbuild.${name}.yaml"

  if [[ "${name}" == "presidio-analyzer" || "${name}" == "presidio-anonymizer" ]]; then
    # Upstream Presidio images place the Poetry virtualenv under /root (0700).
    # Make /root world-readable and set POETRY_VIRTUALENVS_PATH + USER 1000 so
    # containers start cleanly under Pod Security Standards "restricted".
    venv_dir="presidio-analyzer-QRDmRfzT-py3.9"
    if [[ "${name}" == "presidio-anonymizer" ]]; then
      venv_dir="presidio-anonymizer-MJsbXgPE-py3.9"
    fi
    cat > "${cb_dir}/Dockerfile.${name}" <<DOCKERFILE
FROM ${upstream_ref}
USER root
RUN chmod -R a+rX /root
ENV POETRY_VIRTUALENVS_PATH=/root/.cache/pypoetry/virtualenvs
ENV PATH="/root/.cache/pypoetry/virtualenvs/${venv_dir}/bin:\$PATH"
USER 1000
DOCKERFILE
    cat > "$cb_file" <<EOF
substitutions:
  _IMAGE_NAME: '${name}'
serviceAccount: '${CLOUDBUILD_SA}'
steps:
- name: 'gcr.io/cloud-builders/docker'
  id: build-${name}
  args: ['build', '-t', '${target_tag}', '-f', 'Dockerfile.${name}', '.']
- name: 'gcr.io/cloud-builders/docker'
  id: push-${name}
  args: ['push', '${target_tag}']
- name: 'gcr.io/google.com/cloudsdktool/cloud-sdk:slim'
  id: attest-${name}
  entrypoint: 'bash'
  env:
    - 'PROJECT_ID=${PROJECT_ID}'
    - 'IMAGE_NAME=\${_IMAGE_NAME}'
  args:
    - 'scripts/attest_image.sh'
    - '${target_tag}'
    - '${ENVIRONMENT}'
    - '${KMS_LOCATION}'
    - '${KMS_KEY_VERSION}'
timeout: '1200s'
options:
  machineType: 'E2_HIGHCPU_8'
  logging: CLOUD_LOGGING_ONLY
EOF
  else
    cat > "$cb_file" <<EOF
substitutions:
  _IMAGE_NAME: '${name}'
serviceAccount: '${CLOUDBUILD_SA}'
steps:
- name: 'gcr.io/cloud-builders/docker'
  id: pull-${name}
  args: ['pull', '${upstream_ref}']
- name: 'gcr.io/cloud-builders/docker'
  id: tag-${name}
  args: ['tag', '${upstream_ref}', '${target_tag}']
- name: 'gcr.io/cloud-builders/docker'
  id: push-${name}
  args: ['push', '${target_tag}']
- name: 'gcr.io/google.com/cloudsdktool/cloud-sdk:slim'
  id: attest-${name}
  entrypoint: 'bash'
  env:
    - 'PROJECT_ID=${PROJECT_ID}'
    - 'IMAGE_NAME=\${_IMAGE_NAME}'
  args:
    - 'scripts/attest_image.sh'
    - '${target_tag}'
    - '${ENVIRONMENT}'
    - '${KMS_LOCATION}'
    - '${KMS_KEY_VERSION}'
timeout: '1200s'
options:
  machineType: 'E2_HIGHCPU_8'
  logging: CLOUD_LOGGING_ONLY
EOF
  fi

  if [[ "${DRY_RUN:-false}" == "true" ]]; then
    cat "$cb_file"
    continue
  fi

  echo "🪞 Starting Cloud Build mirror & attestation for ${name} (${version_tag})..."
  gcloud builds submit \
    --config "$cb_file" \
    --project "$PROJECT_ID" \
    --service-account "$CLOUDBUILD_SA" \
    --substitutions="_IMAGE_NAME=${name}" \
    "$cb_dir" > "/tmp/mirror_${name}.log" 2>&1 &
  wait_for_pids+=("$!")
  mirror_names+=("${name}")
done

if [[ "${DRY_RUN:-false}" == "true" ]]; then
  exit 0
fi

echo "⏳ Waiting for ${#wait_for_pids[@]} mirror Cloud Build job(s) to finish..."
fail=0
for idx in "${!wait_for_pids[@]}"; do
  pid="${wait_for_pids[$idx]}"
  name="${mirror_names[$idx]}"
  if ! wait "${pid}"; then
    echo "❌ Mirror Cloud Build job failed for ${name} (see /tmp/mirror_${name}.log)" >&2
    fail=1
  else
    echo "✅ Mirror Cloud Build job succeeded for ${name}"
  fi
done

if [[ "${fail}" -eq 1 ]]; then
  echo "❌ One or more third-party image mirror jobs failed." >&2
  exit 1
fi

echo "✅ Mirrored and attested all ${#THIRD_PARTY_IMAGES[@]} third-party images into ${REGISTRY}."
