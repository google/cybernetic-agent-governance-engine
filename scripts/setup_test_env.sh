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

# ── Source .env early so K8S_NAMESPACE and other vars are available ───────────
# Must happen before NAMESPACE default is evaluated below.
if [[ -f .env ]]; then
  echo "📂  Loading .env …"
  # Use set -a / set +a so the vars become available to child processes
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
else
  echo "⚠️   .env not found — using defaults. Copy .env.example to .env and fill in your values."
fi

# ── Configurable defaults ─────────────────────────────────────────────────────
# K8S_NAMESPACE from .env is now in scope; fall back to governance-stack if unset.
NAMESPACE="${K8S_NAMESPACE:-governance-stack}"
DRY_RUN=false
WAIT_SECONDS=6      # time to let port-forwards stabilise before health checks
PF_PIDS_FILE="/tmp/pf_pids.txt"   # tracks reconnect-loop PIDs for clean teardown

# ── Parse arguments ───────────────────────────────────────────────────────────
# CLI --namespace overrides the .env-sourced value above.
while [[ $# -gt 0 ]]; do
  case "$1" in
    --namespace|-n)
      NAMESPACE="$2"; shift 2 ;;
    --dry-run)
      DRY_RUN=true; shift ;;
    --wait)
      WAIT_SECONDS="$2"; shift 2 ;;
    -h|--help)
      head -40 "$0" | grep '^#' | sed 's/^# \?//'
      exit 0 ;;
    *)
      echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

# ── Helper ────────────────────────────────────────────────────────────────────
log() { echo "$(date -u '+%H:%M:%S')  $*"; }
run() {
  if $DRY_RUN; then
    echo "[dry-run] $*"
  else
    "$@"
  fi
}

# ── Kill stale port-forwards ──────────────────────────────────────────────────
log "🔪  Stopping any existing kubectl port-forward processes …"
# Kill previously tracked reconnect loops
if [[ -f "${PF_PIDS_FILE}" ]]; then
  while IFS= read -r pid; do
    kill "${pid}" 2>/dev/null || true
  done < "${PF_PIDS_FILE}"
  rm -f "${PF_PIDS_FILE}"
fi
if pgrep -f "kubectl port-forward" &>/dev/null; then
  pkill -f "kubectl port-forward" || true
  sleep 0.5
fi

if $DRY_RUN; then
  echo "[dry-run] Would kill existing port-forwards and start new ones."
fi

# ── Auto-reconnect wrapper ────────────────────────────────────────────────────
# Runs kubectl port-forward in a while-loop so it restarts automatically if the
# connection drops mid-test.  The loop itself runs in the background; its PID is
# appended to PF_PIDS_FILE for clean teardown.
#
# Usage: port_forward_with_retry <log-stem> <svc> <local:remote> [extra kubectl args...]
port_forward_with_retry() {
  local log_stem="$1"; shift
  local svc="$1";      shift
  local ports="$1";    shift
  # Remaining args (e.g. -n namespace) are passed straight through.
  local log_path="${LOG_DIR}/pf-${log_stem}.log"

  if $DRY_RUN; then
    echo "[dry-run] port_forward_with_retry ${log_stem} svc/${svc} ${ports} $*"
    return
  fi

  (
    while true; do
      kubectl port-forward "${svc}" "${ports}" \
        --pod-running-timeout=5m \
        "$@" \
        >>"${log_path}" 2>&1 || true
      echo "$(date -u '+%H:%M:%S')  ⚠️  port-forward ${svc} (${ports}) dropped — restarting in 2s…" \
        | tee -a "${log_path}" >&2
      sleep 2
    done
  ) </dev/null >/dev/null 2>&1 &
  local loop_pid=$!
  echo "${loop_pid}" >> "${PF_PIDS_FILE}"
  echo "${loop_pid}"   # caller can capture for display
}

# ── Start port-forwards ───────────────────────────────────────────────────────
LOG_DIR="${TMPDIR:-/tmp}"
: > "${PF_PIDS_FILE}"   # truncate / create

log "🚀  Starting port-forwards (namespace: ${NAMESPACE}) …"

# Backend (governed-financial-advisor)
PF_BACKEND_PID=$(port_forward_with_retry backend svc/governed-financial-advisor 8081:80 -n "${NAMESPACE}")
log "    Backend          localhost:8081  →  svc/governed-financial-advisor :80   (loop pid ${PF_BACKEND_PID})"

# vLLM pods live in the dedicated vllm-inference namespace (not governance-stack).
# Port numbers match VLLM_REASONING_API_BASE (18082) and VLLM_FAST_API_BASE (18081) in .env.
VLLM_NAMESPACE="${VLLM_K8S_NAMESPACE:-vllm-inference}"

# vLLM reasoning (DeepSeek R1) → 18082
# Try pod-level forward first (avoids service-level load-balancing latency); fall back to svc.
VLLM_REASONING_POD=$(kubectl get pods -n "${VLLM_NAMESPACE}" -l app=vllm-reasoning -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
if [[ -n "${VLLM_REASONING_POD}" ]]; then
  PF_VLLM_PID=$(port_forward_with_retry vllm pod/"${VLLM_REASONING_POD}" 18082:8000 -n "${VLLM_NAMESPACE}")
  log "    vLLM reasoning   localhost:18082 →  pod/${VLLM_REASONING_POD}        :8000 (loop pid ${PF_VLLM_PID})"
else
  PF_VLLM_PID=$(port_forward_with_retry vllm svc/vllm-reasoning 18082:8000 -n "${VLLM_NAMESPACE}")
  log "    vLLM reasoning   localhost:18082 →  svc/vllm-reasoning              :8000 (loop pid ${PF_VLLM_PID}) [fallback]"
fi

# vLLM fast inference (Qwen2.5-7B-Instruct) → 18081
VLLM_INFERENCE_POD=$(kubectl get pods -n "${VLLM_NAMESPACE}" -l app=vllm-inference -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
if [[ -n "${VLLM_INFERENCE_POD}" ]]; then
  PF_VLLM_FAST_PID=$(port_forward_with_retry vllm-fast pod/"${VLLM_INFERENCE_POD}" 18081:8000 -n "${VLLM_NAMESPACE}")
  log "    vLLM fast        localhost:18081 →  pod/${VLLM_INFERENCE_POD}       :8000 (loop pid ${PF_VLLM_FAST_PID})"
else
  PF_VLLM_FAST_PID=$(port_forward_with_retry vllm-fast svc/vllm-service 18081:8000 -n "${VLLM_NAMESPACE}")
  log "    vLLM fast        localhost:18081 →  svc/vllm-service                :8000 (loop pid ${PF_VLLM_FAST_PID}) [fallback]"
fi

# Langfuse web UI — governance-stack-2 exposes :3000, governance-stack uses :80
LANGFUSE_SVC_PORT=$(kubectl get svc/langfuse-web -n "${NAMESPACE}" -o jsonpath='{.spec.ports[0].port}' 2>/dev/null || echo "80")
PF_LANGFUSE_PID=$(port_forward_with_retry langfuse svc/langfuse-web "3001:${LANGFUSE_SVC_PORT}" -n "${NAMESPACE}")
log "    Langfuse UI      localhost:3001  →  svc/langfuse-web                :${LANGFUSE_SVC_PORT}   (loop pid ${PF_LANGFUSE_PID})"

# Compliance Bridge → 3002
PF_BRIDGE_PID=$(port_forward_with_retry compliance-bridge svc/compliance-bridge 3002:80 -n "${NAMESPACE}")
log "    Compliance Bridge localhost:3002 →  svc/compliance-bridge          :80   (loop pid ${PF_BRIDGE_PID})"


# NOTE: otel-collector port-forward intentionally omitted — the standalone OTel
# Collector is deprecated (2026-05-31). Traces route directly to Langfuse's native
# OTLP endpoint (langfuse-web:3000/api/public/otel/v1/traces). No svc/otel-collector
# exists in the cluster.

# OPA policy engine → 8181  (required by integration + red-team tests)
PF_OPA_PID=$(port_forward_with_retry opa svc/opa 8181:8181 -n "${NAMESPACE}")
log "    OPA              localhost:8181  →  svc/opa                         :8181 (loop pid ${PF_OPA_PID})"

# Inference Gateway → 8080
PF_GATEWAY_PID=$(port_forward_with_retry gateway svc/gateway 8080:8080 -n "${NAMESPACE}")
log "    Gateway          localhost:8080  →  svc/gateway                     :8080 (loop pid ${PF_GATEWAY_PID})"

# Redis → 6379 (best-effort; may fail if redis pod is in CrashLoopBackOff)
PF_REDIS_PID=$(port_forward_with_retry redis svc/redis-master 6379:6379 -n "${NAMESPACE}")
log "    Redis            localhost:6379  →  svc/redis-master                :6379 (loop pid ${PF_REDIS_PID}) [best-effort]"

# ── Wait for port-forwards to stabilise ──────────────────────────────────────
log "⏳  Waiting ${WAIT_SECONDS}s for port-forwards to stabilise …"
sleep "${WAIT_SECONDS}"

# ── Health checks ─────────────────────────────────────────────────────────────
echo ""
log "🔍  Health checks:"

check_http() {
  local label="$1"
  local url="$2"
  local code
  code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 4 "${url}" 2>/dev/null || echo "000")
  if [[ "${code}" =~ ^[23] ]]; then
    echo "    ✅  ${label}: HTTP ${code}  (${url})"
  else
    echo "    ❌  ${label}: HTTP ${code}  (${url}) — check ${LOG_DIR}/pf-*.log for details"
  fi
}

# TCP-level reachability check (for gRPC/HTTP2 endpoints that return 4xx on GET /).
check_tcp() {
  local label="$1"
  local host="$2"
  local port="$3"
  if nc -z -w 4 "${host}" "${port}" 2>/dev/null; then
    echo "    ✅  ${label}: TCP port ${port} reachable  (${host}:${port})"
  else
    echo "    ❌  ${label}: TCP port ${port} not reachable  (${host}:${port}) — check ${LOG_DIR}/pf-*.log for details"
  fi
}

check_http "Backend              " "http://localhost:8081/health"
check_http "vLLM reasoning       " "http://localhost:18082/v1/models"
check_http "vLLM fast inference  " "http://localhost:18081/v1/models"
check_http "Langfuse             " "http://localhost:3001"
check_http "OPA                  " "http://localhost:8181/health"
check_http "Gateway              " "http://localhost:8080/health"
check_http "Compliance Bridge    " "http://localhost:3002/health"
# NOTE: otel-collector health check intentionally omitted — the standalone OTel
# Collector is deprecated (2026-05-31). Traces route directly to Langfuse's native
# OTLP endpoint (langfuse-web:3000/api/public/otel/v1/traces).

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " ✅  Port-forwards started (auto-reconnect enabled).  Run tests with:"
echo ""
echo "     # Unit + local tests only (no services required):"
echo "     uv run pytest tests/ -m 'not load'"
echo ""
echo "     # Full test suite (unit + integration + red-team, no load):"
echo "     uv run pytest tests/ --run-integration -m 'not load' -v --tb=short"
echo ""
echo "     # Failed/skipped integration tests only:"
echo "     uv run pytest tests/ --run-integration -m 'integration or red_team' -v --tb=short"
echo ""
echo " 📋  Port-forward logs (each loop appends on reconnect):"
echo "     Backend       : ${LOG_DIR}/pf-backend.log"
echo "     vLLM reasoning: ${LOG_DIR}/pf-vllm.log        (localhost:18082 → vllm-inference/svc/vllm-reasoning:8000)"
echo "     vLLM fast     : ${LOG_DIR}/pf-vllm-fast.log   (localhost:18081 → vllm-inference/svc/vllm-service:8000)"
echo "     Langfuse      : ${LOG_DIR}/pf-langfuse.log"
echo "     OPA           : ${LOG_DIR}/pf-opa.log"
echo "     Gateway       : ${LOG_DIR}/pf-gateway.log"
echo "     Redis         : ${LOG_DIR}/pf-redis.log"
echo "     Compliance Br : ${LOG_DIR}/pf-compliance-bridge.log"
echo "     (OTel collector deprecated — no pf-otel.log; traces go directly to Langfuse)"
echo ""
echo " 🛑  To stop all port-forward loops:"
echo "     xargs kill < ${PF_PIDS_FILE} 2>/dev/null; pkill -f 'kubectl port-forward' || true"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
