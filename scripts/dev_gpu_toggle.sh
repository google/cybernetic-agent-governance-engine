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

# =============================================================================
# dev_gpu_toggle.sh — Developer helper to manually scale vLLM GPU Deployments
# =============================================================================
#
# Usage:
#   ./scripts/dev_gpu_toggle.sh up    # Scale vllm-fast and vllm-reasoning to 1
#   ./scripts/dev_gpu_toggle.sh down  # Scale vllm-fast and vllm-reasoning to 0
#
# Targets:
#   Namespace:  governance-stack
#   Deployments: vllm-fast, vllm-reasoning
#
# Notes:
#   • "up"   triggers GKE GPU node provisioning; allow ~5–10 min for node
#             provision + model weight loading before inference is available.
#   • "down" triggers GPU node drain ~10 min after both pods are evicted
#             (gpu_node_pool_min_count=0 in dev.tfvars).
#   • Requires a valid kubectl context pointing at the dev cluster.
#     Run: gcloud container clusters get-credentials governance-cluster-2 \
#              --zone us-central1-a --project <YOUR_PROJECT>
# =============================================================================

set -euo pipefail

NAMESPACE="governance-stack"
DEPLOY_FAST="vllm-fast"
DEPLOY_REASONING="vllm-reasoning"

usage() {
  echo "Usage: $0 [up|down]"
  echo ""
  echo "  up    Scale vllm-fast and vllm-reasoning to 1 replica each"
  echo "  down  Scale vllm-fast and vllm-reasoning to 0 replicas each"
  exit 1
}

if [[ $# -ne 1 ]]; then
  usage
fi

CMD="${1}"

case "${CMD}" in
  up)
    REPLICAS=1
    echo "=== GPU Scale-Up — $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
    echo "Scaling ${DEPLOY_FAST} to ${REPLICAS} replica..."
    kubectl scale deployment "${DEPLOY_FAST}" -n "${NAMESPACE}" --replicas="${REPLICAS}"
    echo "  ✅ ${DEPLOY_FAST} → ${REPLICAS}"

    echo "Scaling ${DEPLOY_REASONING} to ${REPLICAS} replica..."
    kubectl scale deployment "${DEPLOY_REASONING}" -n "${NAMESPACE}" --replicas="${REPLICAS}"
    echo "  ✅ ${DEPLOY_REASONING} → ${REPLICAS}"

    echo ""
    echo "Scale-up complete. Allow ~5–10 min for GPU node provision + model weight loading."
    ;;

  down)
    REPLICAS=0
    echo "=== GPU Scale-Down — $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
    echo "Scaling ${DEPLOY_FAST} to ${REPLICAS} replicas..."
    kubectl scale deployment "${DEPLOY_FAST}" -n "${NAMESPACE}" --replicas="${REPLICAS}"
    echo "  ✅ ${DEPLOY_FAST} → ${REPLICAS}"

    echo "Scaling ${DEPLOY_REASONING} to ${REPLICAS} replicas..."
    kubectl scale deployment "${DEPLOY_REASONING}" -n "${NAMESPACE}" --replicas="${REPLICAS}"
    echo "  ✅ ${DEPLOY_REASONING} → ${REPLICAS}"

    echo ""
    echo "Scale-down complete. GPU node drain will follow in ~10 min."
    ;;

  *)
    echo "Error: unknown subcommand '${CMD}'"
    usage
    ;;
esac
