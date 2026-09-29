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
# attest each mirrored digest with Binary Authorization (CM-7, SI-7, POAM-2026-083).
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

# Canonical digest-pinned upstream images mirrored into Artifact Registry.
THIRD_PARTY_IMAGES=(
  "presidio-analyzer|mcr.microsoft.com/presidio-analyzer@sha256:7d3c6513bc188a92c67ca068346bf2ef042d3726c243217ce9fb3a57960d3234|2.2.357"
  "presidio-anonymizer|mcr.microsoft.com/presidio-anonymizer@sha256:562be3cb2e5c15f17c10935721459ef0d10cc2f28209f1f925b86dc7d40a2146|2.2.357"
  "vllm-openai|vllm/vllm-openai@sha256:9bd4d87aa1e1650d5f5b9e0ca2bb070a32404f8b92f3b85e8d8ca30fc04ab6a3|v0.7.3"
  "opa|openpolicyagent/opa@sha256:cc4efcabce6d6ebfa2dc8efdb2edaf4dbdeaa4e11f2be5a4a01a6661c82fc1b8|1.2.0-static"
  "redis|redis@sha256:1f885a1088573222b2b34614878726658c71ff7f68db3b8ef07bd0ca57a2909e|7.4-alpine"
  "clickhouse-server|docker.io/clickhouse/clickhouse-server@sha256:93f94e0c86d78c1ef8be33339d7dc8dc8c8e27c1b30d828ffab3893bf950d895|24.3-alpine"
  "clickhouse-keeper|docker.io/clickhouse/clickhouse-keeper@sha256:77026fa37cc6922d10a25a8cd827cf3682e3fb0942dc162e490fa991bdbf0224|24.3-alpine"
  "langfuse|langfuse/langfuse@sha256:6b21a5086a07d9df332f7ecfc46778b3eb098b34df602ab80a0cd32a5f6c1134|3"
  "langfuse-worker|langfuse/langfuse-worker@sha256:41f5785e862bf7e114cdbd8342be524c78dc8c88f6df5bd2c7debb3de98ec43b|3"
  "cloud-sql-proxy|gcr.io/cloud-sql-connectors/cloud-sql-proxy@sha256:a77c72c56747cf2f431a4ed5e4a45e62003ca0fb94dc9f0c9cd390e84be2fa0e|2.14.2"
)

cb_file=$(mktemp -t cloudbuild_mirror.XXXXXX)
trap 'rm -f "$cb_file"' EXIT

{
  echo "steps:"
  for entry in "${THIRD_PARTY_IMAGES[@]}"; do
    IFS='|' read -r name upstream_ref version_tag <<< "$entry"
    target_tag="${REGISTRY}/${name}:${version_tag}"
    cat <<EOF
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
  args:
    - '-ceu'
    - |
      DIGEST=\$\$(gcloud container images describe "${target_tag}" --format='get(image_summary.digest)')
      gcloud container binauthz attestations sign-and-create \\
        --project="${PROJECT_ID}" \\
        --artifact-url="${REGISTRY}/${name}@\$\${DIGEST}" \\
        --attestor="projects/${PROJECT_ID}/attestors/cage-build-attestor-${ENVIRONMENT}" \\
        --keyversion-project="${PROJECT_ID}" \\
        --keyversion-location="${KMS_LOCATION}" \\
        --keyversion-keyring="cage-signing-${ENVIRONMENT}" \\
        --keyversion-key="binauthz-attestor" \\
        --keyversion="${KMS_KEY_VERSION}"
EOF
  done
  cat <<EOF
timeout: '2400s'
options:
  machineType: 'E2_HIGHCPU_8'
  logging: CLOUD_LOGGING_ONLY
EOF
} > "$cb_file"

if [[ "${DRY_RUN:-false}" == "true" ]]; then
  cat "$cb_file"
  exit 0
fi

echo "🪞 Submitting Cloud Build job to mirror and attest ${#THIRD_PARTY_IMAGES[@]} third-party images..."
gcloud builds submit --no-source --config "$cb_file" --project "$PROJECT_ID"
echo "✅ Mirrored and attested all third-party images into ${REGISTRY}."
