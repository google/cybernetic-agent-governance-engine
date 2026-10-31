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

# Render var.image_digests for one build into a Terraform var file.
#
# No digest and no registry path is committed (POAM-2026-131): a digest names an
# image in one registry, so every deployment renders its own. This resolves each
# image in gcr.io/${PROJECT_ID} to its @sha256: digest and writes
#   {"image_digests": {"<name>": "gcr.io/<project>/<name>@sha256:<64-hex>", ...}}
# to a gitignored file that terraform reads with -var-file. deploy_all.sh calls it
# between building the images and planning.
#
#   First-party images resolve by the exact tag <short_sha> (scripts/build_images.sh
#   tags every build with it). There is no fallback to another build's image: an
#   image not built for this SHA is left out, never substituted.
#   Third-party images resolve by the version tag scripts/mirror_and_attest_images.sh
#   mirrors them under.
#
# An image that does not resolve is left out and named on stderr. The plan then
# decides: var.image_digests' validation refuses a map that lacks an image the
# profile deploys (local.required_image_digests in infra/targets/gcp-gke/main.tf).
#
# Usage:
#   PROJECT_ID=<project> scripts/render_image_digests.sh [--output PATH|-] [short_sha]
#
#   short_sha  defaults to `git rev-parse --short HEAD`
#   --output   defaults to infra/targets/gcp-gke/image_digests.<short_sha>.tfvars.json;
#              "-" writes to stdout

set -euo pipefail

usage() {
  sed -n 's/^#   \{0,1\}//p' "$0" | sed -n '/^Usage:/,$p' >&2
  exit 2
}

OUTPUT=""
SHORT_SHA=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output)
      [[ $# -ge 2 ]] || usage
      OUTPUT="$2"
      shift 2
      ;;
    --output=*)
      OUTPUT="${1#--output=}"
      shift
      ;;
    -h|--help)
      usage
      ;;
    -*)
      echo "❌ Error: unknown option: $1" >&2
      usage
      ;;
    *)
      [[ -z "${SHORT_SHA}" ]] || usage
      SHORT_SHA="$1"
      shift
      ;;
  esac
done

if [[ -z "${PROJECT_ID:-}" ]]; then
  echo "❌ Error: PROJECT_ID environment variable is not set." >&2
  exit 1
fi
# The project ID becomes part of a registry path and of JSON output.
if [[ ! "${PROJECT_ID}" =~ ^[a-z][a-z0-9-]{4,28}[a-z0-9]$ ]]; then
  echo "❌ Error: PROJECT_ID '${PROJECT_ID}' is not a GCP project ID." >&2
  exit 1
fi

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [[ -z "${SHORT_SHA}" ]]; then
  if [[ -z "${REPO_ROOT}" ]] || ! SHORT_SHA="$(git rev-parse --short HEAD 2>/dev/null)"; then
    echo "❌ Error: no short SHA given and this is not a git checkout." >&2
    exit 1
  fi
fi
if [[ ! "${SHORT_SHA}" =~ ^[0-9a-f]{7,40}$ ]]; then
  echo "❌ Error: '${SHORT_SHA}' is not a git commit SHA." >&2
  exit 1
fi

if [[ -z "${OUTPUT}" ]]; then
  if [[ -z "${REPO_ROOT}" ]]; then
    echo "❌ Error: --output is required outside a git checkout." >&2
    exit 1
  fi
  OUTPUT="${REPO_ROOT}/infra/targets/gcp-gke/image_digests.${SHORT_SHA}.tfvars.json"
fi

REGISTRY="gcr.io/${PROJECT_ID}"

# Every image var.image_digests can hold. Keep in step with
# local.required_image_digests in infra/targets/gcp-gke/main.tf.
FIRST_PARTY_IMAGES=(
  "gateway"
  "agentsight-ui"
  "compliance-bridge"
  "governed-financial-advisor"
  "nemo-guardrails"
  "vllm-streamer"
)

THIRD_PARTY_TAGGED_IMAGES=(
  "opa|1.2.0-static"
  "langfuse|3"
  "langfuse-worker|3"
  "cloud-sql-proxy|2.14.2"
  "clickhouse-server|24.3-alpine"
  "clickhouse-keeper|24.3-alpine"
  "presidio-analyzer|2.2.357"
  "presidio-anonymizer|2.2.357"
)

entries=()
missing=()

resolve() {
  local name="$1" tag="$2" ref digest
  ref="${REGISTRY}/${name}:${tag}"
  digest="$(gcloud container images describe "${ref}" --format='get(image_summary.digest)' 2>/dev/null || true)"
  if [[ "${digest}" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    entries+=("$(printf '    "%s": "%s/%s@%s"' "${name}" "${REGISTRY}" "${name}" "${digest}")")
    return 0
  fi
  missing+=("${ref}")
  return 1
}

first_party_found=0
for name in "${FIRST_PARTY_IMAGES[@]}"; do
  if resolve "${name}" "${SHORT_SHA}"; then
    first_party_found=$(( first_party_found + 1 ))
  fi
done
for entry in "${THIRD_PARTY_TAGGED_IMAGES[@]}"; do
  IFS='|' read -r name version_tag <<< "${entry}"
  resolve "${name}" "${version_tag}" || true
done

for ref in "${missing[@]+"${missing[@]}"}"; do
  echo "⚠️  Not found, left out: ${ref}" >&2
done
# Third-party tags resolve whatever the SHA, so judge the build by its own images.
if [[ "${first_party_found}" -eq 0 ]]; then
  echo "❌ Error: no first-party image is tagged ${SHORT_SHA} in ${REGISTRY}. Build it first (scripts/build_images.sh), or name a SHA that was built; check PROJECT_ID." >&2
  exit 1
fi

render() {
  local i last=$(( ${#entries[@]} - 1 ))
  printf '{\n  "image_digests": {\n'
  for i in "${!entries[@]}"; do
    if [[ "${i}" -lt "${last}" ]]; then
      printf '%s,\n' "${entries[$i]}"
    else
      printf '%s\n' "${entries[$i]}"
    fi
  done
  printf '  }\n}\n'
}

if [[ "${OUTPUT}" == "-" ]]; then
  render
else
  tmp="$(mktemp "${OUTPUT}.XXXXXX")"
  trap 'rm -f "${tmp}"' EXIT
  render > "${tmp}"
  mv "${tmp}" "${OUTPUT}"
  trap - EXIT
  echo "✅ Rendered ${#entries[@]} image digest(s) for ${SHORT_SHA}: ${OUTPUT}" >&2
fi
