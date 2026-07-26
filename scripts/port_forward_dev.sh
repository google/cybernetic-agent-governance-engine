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

# ── Load .env for K8S_NAMESPACE and other env vars ───────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
if [[ -f "$REPO_ROOT/.env" ]]; then
  # Export only lines that look like VAR=VALUE (skip comments and blanks)
  set -o allexport
  # shellcheck disable=SC1090
  source "$REPO_ROOT/.env"
  set +o allexport
fi

NS="${K8S_NAMESPACE:-governance-stack}"
LOG_DIR=/tmp/cage-pf
PF_PIDS_FILE=/tmp/pf_pids.txt

mkdir -p "$LOG_DIR"

echo "[port-forward] Killing stale port-forwards and reconnect loops..."
# Kill previously tracked reconnect loops
if [[ -f "${PF_PIDS_FILE}" ]]; then
  while IFS= read -r pid; do
    kill "${pid}" 2>/dev/null || true
  done < "${PF_PIDS_FILE}"
  rm -f "${PF_PIDS_FILE}"
fi
pkill -f "kubectl port-forward" 2>/dev/null || true
sleep 0.3

# ── Auto-reconnect wrapper ────────────────────────────────────────────────────
# Spawns a while-loop in the background that restarts kubectl port-forward
# whenever it exits (connection drops, pod restart, etc.).
# The loop PID is appended to PF_PIDS_FILE for clean teardown.
#
# Usage: start_pf <log-name> <svc> <local_port> <remote_port>
start_pf() {
  local name="$1"
  local svc="$2"
  local local_port="$3"
  local remote_port="$4"
  local log_path="$LOG_DIR/${name}.log"

  echo "[port-forward] Starting $name ($svc ${local_port}→${remote_port}) with auto-reconnect..."
  (
    while true; do
      kubectl port-forward -n "$NS" "svc/$svc" "${local_port}:${remote_port}" \
        --pod-running-timeout=5m \
        >>"$log_path" 2>&1 || true
      echo "$(date -u '+%H:%M:%S')  ⚠️  port-forward $svc (${local_port}:${remote_port}) dropped — restarting in 2s…" \
        | tee -a "$log_path" >&2
      sleep 2
    done
  ) &
  local loop_pid=$!
  echo "${loop_pid}" >> "${PF_PIDS_FILE}"
  echo "[port-forward]   $name loop pid: ${loop_pid}"
}

# ── Core services required by tests ──────────────────────────────────────────
: > "${PF_PIDS_FILE}"   # truncate / create

start_pf opa          opa                       8181  8181  # OPA policy engine
start_pf langfuse     langfuse-web              3001  3000  # Langfuse API (LLM judge evaluation)
start_pf langfuse-web langfuse-web              3000  3000  # Langfuse UI (NextAuth)
start_pf vllm-fast    vllm-service              8001  8000  # Fast vLLM (Qwen2.5-7B) — primary (:8001)
start_pf vllm-fast2   vllm-service             18081  8000  # Fast vLLM — VLLM_FAST_API_BASE (:18081)
start_pf vllm-reason  vllm-reasoning            8000  8000  # Reasoning vLLM (DeepSeek R1) — primary (:8000)
start_pf vllm-reason2 vllm-reasoning           18082  8000  # Reasoning vLLM — VLLM_REASONING_API_BASE (:18082)
# otel-collector has been deprecated — telemetry is now collected natively by Langfuse.
# The port-forward is intentionally omitted.
start_pf gateway      gateway                   8080  8080  # Gateway gRPC/HTTP
start_pf backend      governed-financial-advisor 18080   80  # Governed FA backend — BACKEND_URL (:18080)
start_pf redis        redis-master              6379  6379  # Redis (redis-master svc)
start_pf compliance   compliance-bridge          3002    80  # Compliance bridge — BASE_URL (:3002)

echo "[port-forward] Waiting for readiness (3s)..."
sleep 3

echo "[port-forward] Status checks:"
for port in 8181 3001 3000 8001 8000 8080 3002; do
  if nc -z localhost "$port" 2>/dev/null; then
    echo "  ✅ localhost:$port reachable"
  else
    echo "  ⚠️  localhost:$port not reachable yet"
  fi
done

echo ""
echo "[port-forward] Done. Auto-reconnect loops active."
echo "  Logs  : $LOG_DIR/"
echo "  PIDs  : ${PF_PIDS_FILE}"
echo "  Stop  : xargs kill < ${PF_PIDS_FILE} 2>/dev/null; pkill -f 'kubectl port-forward' || true"
