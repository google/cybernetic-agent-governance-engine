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

NAMESPACE="${K8S_NAMESPACE:-governance-stack}"
DEPLOY_FAST="vllm-inference"
DEPLOY_REASONING="vllm-reasoning"
COLD_START_TIMEOUT="${GPU_COLD_START_TIMEOUT:-900}"

usage() {
  echo "Usage: $0 [up|down|wait|status] [--wait]"
  echo ""
  echo "  up [--wait]  Scale vllm-inference and vllm-reasoning to 1 replica each (optionally wait up to ${COLD_START_TIMEOUT}s for GPU cold start)"
  echo "  down         Scale vllm-inference and vllm-reasoning to 0 replicas each (triggers GKE GPU node pool scale-to-zero)"
  echo "  wait         Wait for vllm-inference and vllm-reasoning to finish cold start and reach Ready"
  echo "  status       Show GPU node pool and vLLM deployment status"
  exit 1
}

if [[ $# -lt 1 ]]; then
  usage
fi

CMD="${1}"
WAIT_FLAG="${2:-}"

wait_for_gpus() {
  echo ""
  echo "Waiting up to ${COLD_START_TIMEOUT}s for GPU node scale-up + Run:ai GCS weight streaming..."
  for dep in "${DEPLOY_FAST}" "${DEPLOY_REASONING}"; do
    if kubectl get deployment "${dep}" -n "${NAMESPACE}" >/dev/null 2>&1; then
      echo "  ⏳ Waiting for deployment/${dep} rollout (timeout=${COLD_START_TIMEOUT}s)..."
      kubectl rollout status "deployment/${dep}" -n "${NAMESPACE}" --timeout="${COLD_START_TIMEOUT}s"
      echo "  ✅ ${dep} Ready"
    fi
  done
}

case "${CMD}" in
  up)
    REPLICAS=1
    echo "=== GPU Scale-Up — $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
    for dep in "vllm-fast" "${DEPLOY_FAST}" "${DEPLOY_REASONING}"; do
      if kubectl get deployment "${dep}" -n "${NAMESPACE}" >/dev/null 2>&1; then
        echo "Scaling ${dep} to ${REPLICAS} replica..."
        kubectl scale deployment "${dep}" -n "${NAMESPACE}" --replicas="${REPLICAS}"
        echo "  ✅ ${dep} → ${REPLICAS}"
      fi
    done

    if [[ "${WAIT_FLAG}" == "--wait" ]]; then
      wait_for_gpus
    else
      echo ""
      echo "Scale-up initiated. Allow ~5–10 min for GPU node provision + model weight loading (or run '$0 wait')."
    fi
    ;;

  wait)
    wait_for_gpus
    ;;

  status)
    echo "=== GPU Nodes (gpu-node-pool-nvidia-l4) ==="
    kubectl get nodes -l workload-type=gpu -o wide || true
    echo ""
    echo "=== vLLM Deployments (${NAMESPACE}) ==="
    kubectl get deploy -n "${NAMESPACE}" "${DEPLOY_FAST}" "${DEPLOY_REASONING}" -o wide 2>/dev/null || true
    echo ""
    echo "=== vLLM Pods (${NAMESPACE}) ==="
    kubectl get pods -n "${NAMESPACE}" -l "app in (${DEPLOY_FAST},${DEPLOY_REASONING})" -o wide 2>/dev/null || true
    ;;

  down)
    REPLICAS=0
    echo "=== GPU Scale-Down — $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
    for dep in "vllm-fast" "${DEPLOY_FAST}" "${DEPLOY_REASONING}"; do
      if kubectl get deployment "${dep}" -n "${NAMESPACE}" >/dev/null 2>&1; then
        echo "Scaling ${dep} to ${REPLICAS} replicas..."
        kubectl scale deployment "${dep}" -n "${NAMESPACE}" --replicas="${REPLICAS}"
        echo "  ✅ ${dep} → ${REPLICAS}"
      fi
    done

    echo ""
    echo "Scale-down complete. GKE Cluster Autoscaler will drain idle GPU nodes to 0 in ~10 min."
    ;;

  *)
    echo "Error: unknown subcommand '${CMD}'"
    usage
    ;;
esac
