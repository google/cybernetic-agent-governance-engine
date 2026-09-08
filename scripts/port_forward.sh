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

# ── Unified Port-Forward Manager ─────────────────────────────────────────────
# Manages resilient auto-reconnecting kubectl port-forwards to target GKE
# clusters (staging, dev, or local testbeds).
#
# Safety Invariant:
#   Port-forwarding against production clusters is blocked by default to
#   prevent accidental operational or state corruption.
#
# Usage:
#   ./scripts/port_forward.sh [--env staging|dev] [--daemon] [--force]
#   ./scripts/port_forward.sh --status
#   ./scripts/port_forward.sh --stop

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ── Load .env if present ─────────────────────────────────────────────────────
if [[ -f "$REPO_ROOT/.env" ]]; then
  set -o allexport
  # shellcheck disable=SC1090
  source "$REPO_ROOT/.env"
  set +o allexport
fi

TARGET_ENV="${CAGE_ENV:-staging}"
DAEMON=false
FORCE=false
ACTION="start"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --env)
      TARGET_ENV="$2"
      shift 2
      ;;
    --env=*)
      TARGET_ENV="${1#*=}"
      shift
      ;;
    --daemon|--foreground)
      DAEMON=true
      shift
      ;;
    --force)
      FORCE=true
      shift
      ;;
    --status)
      ACTION="status"
      shift
      ;;
    --stop)
      ACTION="stop"
      shift
      ;;
    -h|--help)
      echo "Usage: $0 [--env staging|dev] [--daemon] [--force] [--status] [--stop]"
      echo ""
      echo "Options:"
      echo "  --env <name>     Target environment ('staging' or 'dev', default: staging)"
      echo "  --daemon         Keep process in foreground"
      echo "  --force          Bypass non-matching context checks"
      echo "  --status         Check health of port-forwards"
      echo "  --stop           Stop active port-forward loops"
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

NS="${K8S_NAMESPACE:-governance-stack}"
LOG_DIR="/tmp/cage-pf-${TARGET_ENV}"
PF_PIDS_FILE="/tmp/pf_${TARGET_ENV}_pids.txt"

# ── Action: Stop ─────────────────────────────────────────────────────────────
if [[ "$ACTION" == "stop" ]]; then
  echo "[port-forward] Stopping port-forward tunnels for environment: $TARGET_ENV..."
  if [[ -f "${PF_PIDS_FILE}" ]]; then
    while IFS= read -r pid; do
      kill "${pid}" 2>/dev/null || true
    done < "${PF_PIDS_FILE}"
    rm -f "${PF_PIDS_FILE}"
  fi
  pkill -f "kubectl port-forward.*$NS" 2>/dev/null || true
  echo "[port-forward] Stopped."
  exit 0
fi

# ── Cluster & Context Safety Validation ──────────────────────────────────────
CURRENT_CONTEXT=$(kubectl config current-context 2>/dev/null || echo "none")

if [[ "$CURRENT_CONTEXT" == "none" ]]; then
  echo "❌ Error: Unable to determine current kubectl context. Is kubectl configured?" >&2
  exit 1
fi

# Safety check: Prevent accidental port-forwarding to production
if [[ "$CURRENT_CONTEXT" =~ prod && "$FORCE" != "true" ]]; then
  echo "❌ ERROR: Current kubectl context is '$CURRENT_CONTEXT' (production)." >&2
  echo "   Port-forwarding to production is blocked by default to prevent state pollution." >&2
  echo "   Switch context to staging or pass --force if deliberately intended." >&2
  exit 1
fi

# Context validation for target environment
if [[ "$TARGET_ENV" == "staging" ]]; then
  if [[ ! "$CURRENT_CONTEXT" =~ staging && "$FORCE" != "true" ]]; then
    echo "❌ Error: Current kubectl context is '$CURRENT_CONTEXT'" >&2
    echo "   Expected a staging cluster context (containing 'staging')." >&2
    echo "   Pass --force to override or switch context with:" >&2
    echo "   kubectl config use-context <staging-cluster-context>" >&2
    exit 1
  fi
fi

# ── Action: Status ───────────────────────────────────────────────────────────
if [[ "$ACTION" == "status" ]]; then
  echo "[port-forward] Checking port reachability for context $CURRENT_CONTEXT (env: $TARGET_ENV):"
  for port in 8181 3001 3000 8001 8000 8080 3002 8081 6379; do
    if nc -z localhost "$port" 2>/dev/null; then
      echo "  ✅ localhost:$port reachable"
    else
      echo "  ❌ localhost:$port not reachable"
    fi
  done
  exit 0
fi

# ── Teardown Stale Loops ─────────────────────────────────────────────────────
mkdir -p "$LOG_DIR"
echo "[port-forward] Context: $CURRENT_CONTEXT | Namespace: $NS | Env: $TARGET_ENV"
echo "[port-forward] Clearing previous port-forwards and reconnect loops..."

if [[ -f "${PF_PIDS_FILE}" ]]; then
  while IFS= read -r pid; do
    kill "${pid}" 2>/dev/null || true
  done < "${PF_PIDS_FILE}"
  rm -f "${PF_PIDS_FILE}"
fi
pkill -f "kubectl port-forward.*$NS" 2>/dev/null || true
sleep 0.3

# ── Auto-Reconnect Function ──────────────────────────────────────────────────
start_pf() {
  local name="$1"
  local svc="$2"
  local local_port="$3"
  local remote_port="$4"
  local log_path="$LOG_DIR/${name}.log"

  nohup bash -c "
    while true; do
      kubectl port-forward -n '$NS' 'svc/$svc' '${local_port}:${remote_port}' \
        --pod-running-timeout=5m \
        >>'$log_path' 2>&1 || true
      echo \"\$(date -u '+%H:%M:%S')  ⚠️  port-forward $svc (${local_port}:${remote_port}) dropped — restarting in 2s…\" \
        | tee -a '$log_path' >&2
      sleep 2
    done
  " >/dev/null 2>&1 &
  local loop_pid=$!
  disown "${loop_pid}" 2>/dev/null || true
  echo "${loop_pid}" >> "${PF_PIDS_FILE}"
  echo "[port-forward]   $name loop pid: ${loop_pid}"
}

# ── Core Services Required by Tests ──────────────────────────────────────────
: > "${PF_PIDS_FILE}"

start_pf opa          opa                       8181  8181  # OPA policy engine
start_pf langfuse     langfuse-web              3001  3000  # Langfuse API (LLM judge evaluation)
start_pf langfuse-web langfuse-web              3000  3000  # Langfuse UI (NextAuth)
start_pf vllm-fast    vllm-service              8001  8000  # Fast vLLM (Qwen2.5-7B) — primary (:8001)
start_pf vllm-fast2   vllm-service             18081  8000  # Fast vLLM — VLLM_FAST_API_BASE (:18081)
start_pf vllm-reason  vllm-reasoning            8000  8000  # Reasoning vLLM (DeepSeek R1) — primary (:8000)
start_pf vllm-reason2 vllm-reasoning           18082  8000  # Reasoning vLLM — VLLM_REASONING_API_BASE (:18082)
start_pf gateway      gateway                   8080  8080  # Gateway gRPC/HTTP

if kubectl get svc -n "$NS" redis-master &>/dev/null; then
  start_pf redis        redis-master              6379  6379  # Redis (redis-master svc)
else
  start_pf redis        redis                     6379  6379  # Redis (redis svc)
fi

if kubectl get svc -n "$NS" compliance-bridge &>/dev/null; then
  start_pf compliance   compliance-bridge          3002    80  # Compliance bridge — BASE_URL (:3002)
fi

if kubectl get svc -n "$NS" governed-financial-advisor &>/dev/null; then
  start_pf backend      governed-financial-advisor 8081    80  # Governed Financial Advisor backend (:8081)
fi

echo "[port-forward] Waiting for readiness (3s)..."
sleep 3

echo "[port-forward] Status checks:"
for port in 8181 3001 3000 8001 8000 8080 3002 8081 6379; do
  if nc -z localhost "$port" 2>/dev/null; then
    echo "  ✅ localhost:$port reachable"
  else
    echo "  ⚠️  localhost:$port not reachable yet"
  fi
done

echo ""
echo "[port-forward] Done. Auto-reconnect loops active."
echo "  Context : $CURRENT_CONTEXT"
echo "  Env     : $TARGET_ENV"
echo "  Logs    : $LOG_DIR/"
echo "  PIDs    : ${PF_PIDS_FILE}"
echo "  Stop    : $0 --env $TARGET_ENV --stop"
echo ""
echo "To run integration tests:"
echo "  source .env"
echo "  export CAGE_ENV=$TARGET_ENV"
echo "  export CAGE_DEPLOYMENT_REGION=\${CAGE_DEPLOYMENT_REGION:-US_FED}"
echo "  uv run pytest tests/ --run-integration -v --tb=short"

if [[ "$DAEMON" == "true" || "${FOREGROUND:-false}" == "true" ]]; then
  echo "[port-forward] Running in foreground/daemon mode. Keeping tunnels active..."
  while true; do sleep 3600; done
fi
