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

# Resolve gcr.io/${PROJECT_ID}/<name>:<sha> for every first-party image (and
# mirrored third-party images when present) and emit a ready-to-paste HCL
# `image_digests = { ... }` map for infra/targets/gcp-gke/*.tfvars.
#
# Usage:
#   PROJECT_ID=<project> scripts/render_image_digests.sh [short_sha]

set -euo pipefail

if [[ -z "${PROJECT_ID:-}" ]]; then
  echo "❌ Error: PROJECT_ID environment variable is not set." >&2
  exit 1
fi

SHORT_SHA="${1:-}"
if [[ -z "${SHORT_SHA}" ]]; then
  if ! SHORT_SHA="$(git rev-parse --short HEAD 2>/dev/null)" || [[ -z "${SHORT_SHA}" ]]; then
    echo "❌ Error: short SHA argument omitted and current directory is not a git checkout." >&2
    exit 1
  fi
fi

REGISTRY="gcr.io/${PROJECT_ID}"

FIRST_PARTY_IMAGES=(
  "gateway"
  "governed-financial-advisor"
  "vllm-streamer"
  "nemo-guardrails"
  "compliance-bridge"
  "agentsight-ui"
)

THIRD_PARTY_TAGGED_IMAGES=(
  "presidio-analyzer|2.2.357"
  "presidio-anonymizer|2.2.357"
  "opa|1.2.0-static"
  "langfuse|3"
  "langfuse-worker|3"
  "cloud-sql-proxy|2.14.2"
  "clickhouse-server|24.3-alpine"
  "clickhouse-keeper|24.3-alpine"
  "redis|7.4-alpine"
)

echo "image_digests = {"
for name in "${FIRST_PARTY_IMAGES[@]}"; do
  tag_ref="${REGISTRY}/${name}:${SHORT_SHA}"
  digest="$(gcloud container images describe "${tag_ref}" --format='get(image_summary.digest)' 2>/dev/null || true)"
  if [[ -z "${digest}" && "${name}" == "vllm-streamer" && "${SKIP_VLLM:-false}" == "true" ]]; then
    digest="$(gcloud container images list-tags "${REGISTRY}/${name}" --limit=1 --format='get(digest)' 2>/dev/null || true)"
  fi
  if [[ -z "${digest}" || ! "${digest}" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    echo "❌ Error: could not resolve @sha256 digest for ${tag_ref}." >&2
    exit 1
  fi
  printf '  %-28s = "%s/%s@%s"\n' "\"${name}\"" "${REGISTRY}" "${name}" "${digest}"
done

for entry in "${THIRD_PARTY_TAGGED_IMAGES[@]}"; do
  IFS='|' read -r name version_tag <<< "${entry}"
  tag_ref="${REGISTRY}/${name}:${version_tag}"
  digest="$(gcloud container images describe "${tag_ref}" --format='get(image_summary.digest)' 2>/dev/null || true)"
  if [[ -n "${digest}" && "${digest}" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    printf '  %-28s = "%s/%s@%s"\n' "\"${name}\"" "${REGISTRY}" "${name}" "${digest}"
  fi
done
echo "}"
