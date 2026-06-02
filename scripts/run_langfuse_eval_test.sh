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

NS="${K8S_NAMESPACE:-governance-stack}"
OUTPUT_FILE="${1:-/tmp/langfuse_eval_output.txt}"
LOG_DIR=/tmp/cage-pf
PF_PIDS_FILE=/tmp/pf_pids.txt
SLM_PORT="${SLM_PORT:-5000}"

# Maximum seconds to wait for pods / ports before aborting
POD_WAIT_TIMEOUT=300   # 5 minutes — GPU pods can be slow to schedule
PORT_WAIT_TIMEOUT=180  # 3 minutes — port-forwards need time to tunnel
PORT_INTERVAL=3        # poll interval in seconds

# ── Colour helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*"; }
hr()    { echo "────────────────────────────────────────────────────────────"; }

# ── Source .env ───────────────────────────────────────────────────────────────
if [[ -f .env ]]; then
  info "Loading .env …"
  set -a; source .env; set +a
else
  warn ".env not found — using defaults. LANGFUSE credentials may be missing."
fi

# ── Step 1: wait for required pods to be Running ──────────────────────────────
echo ""
info "=== STEP 1: Waiting for required GKE pods to be Running (timeout: ${POD_WAIT_TIMEOUT}s) ==="

# Pods that MUST be Running before the test can proceed.
# vllm-fast (vllm-service) and gateway are optional/best-effort.
REQUIRED_POD_SELECTORS=(
  "governed-financial-advisor"
  "vllm-reasoning"
  "opa-service"
  "otel-collector"
  "langfuse-web"
  "redis"
)

wait_for_pod() {
  local selector="$1"
  local elapsed=0
  while true; do
    # Match pods whose name starts with the selector (handles generated suffixes)
    status=$(kubectl get pods -n "$NS" --no-headers 2>/dev/null \
      | awk -v sel="$selector" '$1 ~ "^"sel { print $3 }' | head -1)
    if [[ "$status" == "Running" ]]; then
      return 0
    fi
    if [[ $elapsed -ge $POD_WAIT_TIMEOUT ]]; then
      return 1
    fi
    sleep 5
    elapsed=$((elapsed + 5))
    echo -ne "\r  Waiting for pod ${selector} … status=${status:-<none>} (${elapsed}s/${POD_WAIT_TIMEOUT}s)   "
  done
}

pod_failures=()
for selector in "${REQUIRED_POD_SELECTORS[@]}"; do
  echo -n "  Checking pod: ${selector} … "
  if wait_for_pod "$selector"; then
    echo -e "${GREEN}Running${NC}"
  else
    # Get actual status for the error message
    actual=$(kubectl get pods -n "$NS" --no-headers 2>/dev/null \
      | awk -v sel="$selector" '$1 ~ "^"sel { print $3 }' | head -1)
    echo -e "${RED}TIMEOUT (status: ${actual:-not found})${NC}"
    pod_failures+=("$selector (${actual:-not found})")
  fi
done

if [[ ${#pod_failures[@]} -gt 0 ]]; then
  err "The following required pods did not reach Running within ${POD_WAIT_TIMEOUT}s:"
  for p in "${pod_failures[@]}"; do err "  - $p"; done
  err "Cannot proceed — fix the pods above and re-run."
  exit 1
fi

ok "All required pods are Running."

# Print full pod list for context
echo ""
info "Full pod status in namespace ${NS}:"
kubectl get pods -n "$NS" 2>/dev/null | sed 's/^/  /' || true

# ── Step 2: start stable port-forwards ──────────────────────────────────────
echo ""
info "=== STEP 2: Starting stable auto-reconnecting port-forwards ==="

# Kill any existing port-forward processes cleanly
if [[ -f "${PF_PIDS_FILE}" ]]; then
  info "Stopping tracked port-forward loops from previous run …"
  while IFS= read -r pid; do
    kill "${pid}" 2>/dev/null || true
  done < "${PF_PIDS_FILE}"
  rm -f "${PF_PIDS_FILE}"
fi
pkill -f "kubectl port-forward" 2>/dev/null || true
# Also stop any stale SLM sidecar from a previous run
pkill -f "mock_slm\|slm_server" 2>/dev/null || true
sleep 1

mkdir -p "$LOG_DIR"
: > "${PF_PIDS_FILE}"

# Auto-reconnect wrapper — keeps the forward alive even if the pod restarts.
# Each forward runs in an infinite loop in the background; its PID is tracked
# in PF_PIDS_FILE for clean teardown.
start_pf() {
  local name="$1"
  local svc="$2"
  local local_port="$3"
  local remote_port="$4"
  local required="${5:-required}"   # pass "best-effort" to skip health gating
  local log_path="$LOG_DIR/${name}.log"

  info "  pf: ${name}  localhost:${local_port} → svc/${svc}:${remote_port}  [${required}]"
  (
    while true; do
      kubectl port-forward -n "$NS" "svc/$svc" "${local_port}:${remote_port}" \
        --pod-running-timeout=5m \
        >>"$log_path" 2>&1 || true
      echo "$(date -u '+%H:%M:%S')  port-forward ${name} (${local_port}→${remote_port}) dropped — restarting in 2s…" \
        >> "$log_path"
      sleep 2
    done
  ) &
  local loop_pid=$!
  echo "$loop_pid" >> "${PF_PIDS_FILE}"
  echo "      loop PID: ${loop_pid}  |  log: ${log_path}"
}

# ── Required port-forwards (test will fail without these) ─────────────────
# IMPORTANT: Langfuse on :3000 — test default is LANGFUSE_HOST=http://localhost:3000
start_pf backend     governed-financial-advisor  8081 80     required
start_pf vllm-reason vllm-reasoning              8000 8000   required
start_pf langfuse    langfuse-web                3000 80     required
start_pf otel        otel-collector              4318 4318   required
start_pf opa         opa-service                 8181 8181   required

# ── Best-effort port-forwards (test degrades gracefully without these) ─────
start_pf gateway     gateway                     8080 8080   best-effort
start_pf vllm-fast   vllm-service                8001 8000   best-effort
start_pf redis       redis                       6379 6379   best-effort

# ── Step 3: start SLM sidecar ────────────────────────────────────────────────
echo ""
info "=== STEP 3: Starting local SLM sidecar (mock_slm) on localhost:${SLM_PORT} ==="

if pgrep -f "mock_slm\|slm_server" &>/dev/null; then
  ok "SLM sidecar already running — skipping."
else
  export SLM_PORT
  uv run python -m src.gateway.slm.mock_slm \
    >"${LOG_DIR}/slm.log" 2>&1 &
  SLM_PID=$!
  ok "SLM sidecar started (PID ${SLM_PID})  |  log: ${LOG_DIR}/slm.log"
fi

# ── Step 4: health-gate — wait for required services ─────────────────────────
echo ""
info "=== STEP 4: Health-gating required ports (timeout: ${PORT_WAIT_TIMEOUT}s each) ==="

# Wait first with TCP so we know the port-forward tunnel is up, then use HTTP
# for the services that support it to confirm the backend process is healthy.
wait_for_tcp() {
  local port="$1"
  local desc="$2"
  local elapsed=0
  while ! nc -z localhost "$port" 2>/dev/null; do
    if [[ $elapsed -ge $PORT_WAIT_TIMEOUT ]]; then
      err "Timeout: localhost:${port} (${desc}) not reachable after ${PORT_WAIT_TIMEOUT}s"
      return 1
    fi
    sleep "$PORT_INTERVAL"
    elapsed=$((elapsed + PORT_INTERVAL))
    echo -ne "\r  ${desc} (port ${port}) … ${elapsed}s/${PORT_WAIT_TIMEOUT}s   "
  done
  echo -ne "\r"
  return 0
}

wait_for_http() {
  local url="$1"
  local desc="$2"
  local elapsed=0
  while true; do
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 4 "$url" 2>/dev/null || echo "000")
    if [[ "$code" =~ ^[2345] ]] && [[ "$code" != "000" ]]; then
      ok "${desc}: HTTP ${code}  (${url})"
      return 0
    fi
    if [[ $elapsed -ge $PORT_WAIT_TIMEOUT ]]; then
      err "Timeout: ${desc} HTTP not responding at ${url} after ${PORT_WAIT_TIMEOUT}s (last code: ${code})"
      return 1
    fi
    sleep "$PORT_INTERVAL"
    elapsed=$((elapsed + PORT_INTERVAL))
    echo -ne "\r  ${desc} HTTP ${url} … ${elapsed}s/${PORT_WAIT_TIMEOUT}s (code=${code})   "
  done
}

health_failures=()

check_service() {
  local port="$1"
  local desc="$2"
  local http_url="${3:-}"

  # TCP first
  if ! wait_for_tcp "$port" "$desc"; then
    health_failures+=("TCP ${port} (${desc})")
    return
  fi
  ok "TCP:  localhost:${port} (${desc}) reachable"

  # HTTP if URL provided
  if [[ -n "$http_url" ]]; then
    if ! wait_for_http "$http_url" "$desc"; then
      health_failures+=("HTTP ${http_url} (${desc})")
    fi
  fi
}

# Required services with HTTP gating where possible
check_service 8081 "Backend (governed-financial-advisor)" "http://localhost:8081/health"
check_service 8000 "vLLM reasoning (judge LLM)"          "http://localhost:8000/v1/models"
check_service 8181 "OPA policy engine"                   "http://localhost:8181/health"
check_service 3000 "Langfuse web"                        "http://localhost:3000"
check_service 4318 "OTel collector (TCP only — gRPC/H2)" ""   # OTel is gRPC; TCP check only
check_service "$SLM_PORT" "SLM sidecar"                  "http://localhost:${SLM_PORT}/health"

if [[ ${#health_failures[@]} -gt 0 ]]; then
  err "One or more required services failed health checks:"
  for f in "${health_failures[@]}"; do err "  - $f"; done
  err "Check port-forward logs in ${LOG_DIR}/"
  echo ""
  for log in "${LOG_DIR}"/*.log; do
    [[ -f "$log" ]] || continue
    echo "  --- last 5 lines of $(basename "$log") ---"
    tail -5 "$log" | sed 's/^/    /'
  done
  exit 1
fi

# Seed Redis CBF balance so the $200k senior-trade scenario passes
if command -v redis-cli &>/dev/null && nc -z localhost 6379 2>/dev/null; then
  if redis-cli -h localhost -p 6379 set safety:current_cash 10000000 &>/dev/null; then
    ok "Redis CBF seed: safety:current_cash = 10000000"
  else
    warn "Redis CBF seed failed — CBF will bootstrap from its own default."
  fi
else
  warn "redis-cli not available or Redis port-forward not up — skipping CBF seed."
fi

echo ""
ok "All required services are healthy. Starting test."
info "Port-forward loop PIDs saved in ${PF_PIDS_FILE}"
info "  To stop all forwards:  xargs kill < ${PF_PIDS_FILE} 2>/dev/null; pkill -f 'kubectl port-forward' || true"

# ── Step 5: run the test and capture output ───────────────────────────────────
echo ""
info "=== STEP 5: Running test — output → ${OUTPUT_FILE} ==="
echo ""

# Explicitly pass --run-integration because the test is marked @pytest.mark.integration
# and the default pytest.ini addopts does not include it.
set +e
uv run pytest \
  tests/test_langfuse_evaluation.py::test_langfuse_llm_judge_evaluation \
  --run-integration \
  -v \
  --tb=short \
  -s \
  2>&1 | tee "${OUTPUT_FILE}"
PYTEST_EXIT=$?
set -e

echo ""
if [[ $PYTEST_EXIT -eq 0 ]]; then
  ok "pytest exited 0 (all assertions PASSED)"
elif [[ $PYTEST_EXIT -eq 5 ]]; then
  warn "pytest exited 5 (no tests collected / all SKIPPED)"
else
  warn "pytest exited ${PYTEST_EXIT}"
fi

# ── Step 6: analyze the captured output ──────────────────────────────────────
echo ""
info "=== STEP 6: Test output analysis ==="
echo ""
hr

if [[ ! -f "${OUTPUT_FILE}" ]]; then
  err "Output file not found: ${OUTPUT_FILE}"; exit 1
fi

# ── Overall verdict ────────────────────────────────────────────────────────
echo -e "${BOLD}  OVERALL VERDICT${NC}"
if grep -qE "1 passed" "${OUTPUT_FILE}"; then
  echo -e "  ${GREEN}✅  PASSED${NC}"
elif grep -qE "SKIPPED|no tests ran" "${OUTPUT_FILE}"; then
  echo -e "  ${YELLOW}⚠️   SKIPPED — test could not run (see skip reason below)${NC}"
elif grep -qE "FAILED|ERROR|error" "${OUTPUT_FILE}"; then
  echo -e "  ${RED}❌  FAILED or ERRORED${NC}"
else
  echo -e "  ${YELLOW}?   Unknown outcome (exit code: ${PYTEST_EXIT})${NC}"
fi

# ── Skip reason (if skipped) ──────────────────────────────────────────────
if grep -qE "SKIPPED|Skipped" "${OUTPUT_FILE}"; then
  echo ""
  echo -e "${BOLD}  SKIP REASON:${NC}"
  grep -E "skip|SKIP|Skipped" "${OUTPUT_FILE}" | head -5 | sed 's/^/    /'
fi

# ── Mean scores ───────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}  MEAN SCORES (from test output):${NC}"
if grep -q "MEAN SCORES:" "${OUTPUT_FILE}"; then
  grep -A 6 "MEAN SCORES:" "${OUTPUT_FILE}" | sed 's/^/    /'
else
  echo "    (section not found — test may have been skipped or errored before scoring)"
fi

# ── Per-query results ─────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}  PER-QUERY RESULTS:${NC}"
grep -E "^\[|governance_compliance|response_quality|risk_appropriateness|SKIPPED|⚠️" \
  "${OUTPUT_FILE}" 2>/dev/null | head -60 | sed 's/^/    /' || echo "    (none found)"

# ── Governance blocks ─────────────────────────────────────────────────────
BLOCK_COUNT=$(grep -c "Governance-blocked response detected" "${OUTPUT_FILE}" 2>/dev/null || echo 0)
echo ""
echo -e "${BOLD}  GOVERNANCE BLOCKS:${NC}  ${BLOCK_COUNT}"

# ── Backend / judge errors ────────────────────────────────────────────────
echo ""
echo -e "${BOLD}  BACKEND / JUDGE ERRORS:${NC}"
grep -iE "\[ERROR\]|Backend call failed|Judge error|judge returned no valid" \
  "${OUTPUT_FILE}" 2>/dev/null | head -10 | sed 's/^/    /' || echo "    (none)"

# ── Langfuse score posting issues ─────────────────────────────────────────
echo ""
echo -e "${BOLD}  LANGFUSE SCORE POSTING:${NC}"
grep -iE "langfuse|create_score|HTTP.*posting score|FAILED to post" \
  "${OUTPUT_FILE}" 2>/dev/null | grep -v "^--" | head -10 | sed 's/^/    /' || echo "    (none)"

# ── Assertion failures ────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}  ASSERTION FAILURES (if any):${NC}"
if grep -qE "FAILURES|below threshold|AssertionError" "${OUTPUT_FILE}" 2>/dev/null; then
  grep -A 15 "FAILURES\|below threshold\|AssertionError" "${OUTPUT_FILE}" \
    | head -25 | sed 's/^/    /'
else
  echo "    (none)"
fi

# ── Skipped query count ───────────────────────────────────────────────────
SKIP_Q=$(grep -c "Skipping scoring\|⚠️ Skipping" "${OUTPUT_FILE}" 2>/dev/null || echo 0)
echo ""
echo -e "${BOLD}  Queries skipped during evaluation:${NC}  ${SKIP_Q}"

# ── File references ───────────────────────────────────────────────────────
echo ""
hr
echo "  Full captured output:  ${OUTPUT_FILE}"
echo "  Port-forward logs:     ${LOG_DIR}/"
echo "  SLM sidecar log:       ${LOG_DIR}/slm.log"
echo "  Stop all forwards:     xargs kill < ${PF_PIDS_FILE} 2>/dev/null; pkill -f 'kubectl port-forward' || true"
hr
echo ""

exit $PYTEST_EXIT
