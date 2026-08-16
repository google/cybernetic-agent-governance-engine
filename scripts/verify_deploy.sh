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

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
NAMESPACE="governance-stack"
PROJECT=""

# ---------------------------------------------------------------------------
# CLI argument parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --namespace)
      NAMESPACE="$2"
      shift 2
      ;;
    --project)
      PROJECT="$2"
      shift 2
      ;;
    *)
      echo "Unknown argument: $1" >&2
      echo "Usage: $0 [--namespace <ns>] [--project <project>]" >&2
      exit 1
      ;;
  esac
done

# Auto-detect project if not provided
if [[ -z "$PROJECT" ]]; then
  PROJECT=$(gcloud config get-value project 2>/dev/null || echo "")
  if [[ -z "$PROJECT" ]]; then
    echo "❌ Cannot determine GCP project. Set --project or configure gcloud." >&2
    exit 1
  fi
fi

echo "🔍 CAGE Deployment Verification"
echo "   Namespace : $NAMESPACE"
echo "   Project   : $PROJECT"
echo ""

# ---------------------------------------------------------------------------
# Result tracking
# ---------------------------------------------------------------------------
FAIL_COUNT=0
WARN_COUNT=0
RESULTS=()

record() {
  local status="$1"  # OK | WARN | FAIL
  local label="$2"
  local detail="$3"
  case "$status" in
    OK)   RESULTS+=("✅  $label — $detail") ;;
    WARN) RESULTS+=("⚠️   $label — $detail"); ((WARN_COUNT++)) || true ;;
    FAIL) RESULTS+=("❌  $label — $detail"); ((FAIL_COUNT++)) || true ;;
  esac
}

# ---------------------------------------------------------------------------
# Helper: get running image for a deployment
# ---------------------------------------------------------------------------
get_image() {
  local deployment="$1"
  kubectl get deployment "$deployment" \
    -n "$NAMESPACE" \
    -o jsonpath='{.spec.template.spec.containers[0].image}' 2>/dev/null || echo ""
}

# ---------------------------------------------------------------------------
# Helper: get latest Cloud Build image digest for a given image name
# ---------------------------------------------------------------------------
get_latest_build_digest() {
  local image_name="$1"
  # List the 5 most recent successful builds and extract the image from the
  # substitutions or images list. This is a best-effort check.
  gcloud builds list \
    --project="$PROJECT" \
    --filter="status=SUCCESS" \
    --limit=5 \
    --format="value(images)" 2>/dev/null \
    | grep -o "${image_name}@sha256:[a-f0-9]*" \
    | head -1 || echo ""
}

# ---------------------------------------------------------------------------
# Check 1: Core deployment images
# ---------------------------------------------------------------------------
CORE_DEPLOYMENTS=("gateway" "compliance-bridge" "governed-financial-advisor")

for deployment in "${CORE_DEPLOYMENTS[@]}"; do
  image=$(get_image "$deployment")

  if [[ -z "$image" ]]; then
    record FAIL "Image check: $deployment" "deployment not found in namespace $NAMESPACE"
    continue
  fi

  echo "  📦 $deployment → $image"

  # Check for :latest tag
  if [[ "$image" == *":latest" ]]; then
    record WARN "Image check: $deployment" \
      "image uses :latest tag — digest comparison not possible for :latest"
    continue
  fi

  # Check for SHA digest in image reference
  if [[ "$image" == *"@sha256:"* ]]; then
    running_digest="${image##*@}"
    image_name="${image%%@*}"

    latest_digest=$(get_latest_build_digest "$image_name")

    if [[ -z "$latest_digest" ]]; then
      record WARN "Image check: $deployment" \
        "running digest $running_digest — no Cloud Build result found for comparison"
    elif [[ "$running_digest" == "$latest_digest" ]] || [[ "$image" == *"$latest_digest"* ]]; then
      record OK "Image check: $deployment" \
        "digest matches latest Cloud Build ($running_digest)"
    else
      record FAIL "Image check: $deployment" \
        "digest mismatch — running: $running_digest, latest build: $latest_digest"
    fi
  else
    # Tagged image without digest — warn that digest comparison is not possible
    record WARN "Image check: $deployment" \
      "image uses a mutable tag without SHA digest — cannot verify against Cloud Build"
  fi
done

echo ""

# ---------------------------------------------------------------------------
# Check 2: reconciliation-worker-secrets has gcs-reconciliation-bucket key
# ---------------------------------------------------------------------------
echo "  🔑 Checking reconciliation-worker-secrets..."

bucket_val=$(kubectl get secret reconciliation-worker-secrets \
  -n "$NAMESPACE" \
  -o jsonpath='{.data.gcs-reconciliation-bucket}' 2>/dev/null | base64 -d 2>/dev/null || echo "")

if [[ -z "$bucket_val" ]]; then
  record FAIL "Secret: gcs-reconciliation-bucket" \
    "key missing or empty in reconciliation-worker-secrets — reconciliation worker will fail"
else
  # Mask the value before logging (secret hygiene)
  masked="${bucket_val:0:4}****"
  record OK "Secret: gcs-reconciliation-bucket" "key present (value: $masked)"
fi

echo ""

# ---------------------------------------------------------------------------
# Check 3: reconciliation-worker CronJob has at least one successful Job run
# ---------------------------------------------------------------------------
echo "  ⏰ Checking reconciliation-worker CronJob successful runs..."

successful_runs=$(kubectl get jobs \
  -n "$NAMESPACE" \
  -l app=reconciliation-worker 2>/dev/null | grep -c "1/1" || echo "0")

if [[ "$successful_runs" -eq 0 ]]; then
  record WARN "CronJob: reconciliation-worker" \
    "no successful Job runs found yet — may be expected on first deploy"
else
  record OK "CronJob: reconciliation-worker" \
    "$successful_runs successful run(s) found"
fi

echo ""

# ---------------------------------------------------------------------------
# Summary table
# ---------------------------------------------------------------------------
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  CAGE Deployment Verification — Summary"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
for result in "${RESULTS[@]}"; do
  echo "  $result"
done
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

if [[ "$FAIL_COUNT" -gt 0 ]]; then
  echo "❌ Verification FAILED ($FAIL_COUNT failure(s), $WARN_COUNT warning(s))"
  exit 1
elif [[ "$WARN_COUNT" -gt 0 ]]; then
  echo "⚠️  Verification PASSED with $WARN_COUNT warning(s) — review above"
  exit 0
else
  echo "✅ Verification PASSED — all checks OK"
  exit 0
fi
