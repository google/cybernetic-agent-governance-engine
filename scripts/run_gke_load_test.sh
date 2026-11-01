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

set -eo pipefail

# ANSI color codes
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

NAMESPACE="${NAMESPACE:-governance-stack}"

# ============================================================
# LOAD TEST SAFETY LIMITS — DO NOT REMOVE
# These limits prevent service degradation on live GKE.
# Adjust only with coordinator sign-off.
# ============================================================
MAX_USERS="${LOAD_TEST_MAX_USERS:-50}"
SPAWN_RATE="${LOAD_TEST_SPAWN_RATE:-5}"
RUN_TIME="${LOAD_TEST_RUN_TIME:-5m}"
GATEWAY_URL="${LOAD_TEST_GATEWAY_URL:-http://localhost:8080}"
MAX_ALLOWED_AVG=200

# The gateway keeps pod-local state (MCP SSE sessions, quarantine records,
# NeMo refinement proposals). With more than one replica, an MCP session's
# SSE stream and its POSTs land on different pods, so the load test runs
# exactly one replica with no autoscaler. Multi-replica load tests wait for
# the stateless gateway.
readonly GATEWAY_REPLICAS=1

echo -e "${CYAN}🚀 [Locust Load Test] Initializing GKE load validation...${NC}"

# 1. Refuse production contexts: this script rescales the gateway.
CURRENT_CONTEXT="$(kubectl config current-context 2>/dev/null || echo none)"
if [[ -z "${CURRENT_CONTEXT}" || "${CURRENT_CONTEXT}" == "none" ]]; then
  echo -e "${RED}❌ Unable to determine the current kubectl context. Is kubectl configured?${NC}" >&2
  exit 1
fi
if [[ "${CURRENT_CONTEXT}" =~ prod && "${LOAD_TEST_FORCE:-false}" != "true" ]]; then
  echo -e "${RED}❌ kubectl context '${CURRENT_CONTEXT}' looks like production; the load test rescales the gateway.${NC}" >&2
  echo -e "${RED}   Switch context, or set LOAD_TEST_FORCE=true if this is deliberate.${NC}" >&2
  exit 1
fi
# Every later call is pinned to this context, so a context switch in another
# shell during the run cannot redirect the rescale or the restore.
KUBECTL=(kubectl --context "${CURRENT_CONTEXT}" -n "${NAMESPACE}")

# 2. Ensure locust is installed
if ! command -v locust &>/dev/null; then
  echo -e "${YELLOW}⚠️  Locust not found in PATH. Attempting installation via uv...${NC}"
  uv pip install locust || pip install locust
fi

# 3. Pin one gateway replica for the run; restore the original count on exit.
echo -e "${CYAN}🎛️  Removing any gateway HPA left by earlier runs...${NC}"
"${KUBECTL[@]}" delete hpa gateway-hpa --ignore-not-found
HPA_TARGETS="$("${KUBECTL[@]}" get hpa --no-headers \
  -o custom-columns=KIND:.spec.scaleTargetRef.kind,NAME:.spec.scaleTargetRef.name)"
if grep -Eq '^Deployment[[:space:]]+gateway$' <<<"${HPA_TARGETS}"; then
  echo -e "${RED}❌ An autoscaler still targets deployment/gateway in ${NAMESPACE}; remove it before load testing.${NC}" >&2
  exit 1
fi

ORIGINAL_REPLICAS="$("${KUBECTL[@]}" get deployment/gateway -o jsonpath='{.spec.replicas}')"
if ! [[ "${ORIGINAL_REPLICAS}" =~ ^[0-9]+$ ]]; then
  echo -e "${RED}❌ Could not read the gateway replica count (got '${ORIGINAL_REPLICAS}').${NC}" >&2
  exit 1
fi

LOCUST_PID=""
cleanup() {
  local rc=$?
  # Disable errexit and ignore signals during cleanup so a broken stdout pipe
  # (e.g. `run_gke_load_test.sh | tee` interrupted with Ctrl-C), hangup, or
  # second Ctrl-C cannot abort the trap before the restore runs. Go binaries
  # (`kubectl`) preserve inherited SIG_IGN for SIGINT and SIGHUP; a process-group
  # SIGTERM still terminates `kubectl`, which lands in the manual-restore branch.
  set +e
  trap '' INT TERM HUP PIPE
  if [[ -n "${LOCUST_PID}" ]]; then
    kill "${LOCUST_PID}" 2>/dev/null || true
  fi
  echo -e "${CYAN}↩️  Restoring deployment/gateway to ${ORIGINAL_REPLICAS} replica(s)...${NC}"
  # Bounded, so an unreachable API server ends in the manual-restore message
  # instead of a hang. Redirect stdout to /dev/null so a broken pipe cannot
  # raise SIGPIPE inside kubectl after the API call succeeds.
  if ! "${KUBECTL[@]}" scale deployment/gateway --request-timeout=30s --replicas="${ORIGINAL_REPLICAS}" >/dev/null; then
    echo -e "${RED}❌ Could not restore deployment/gateway to ${ORIGINAL_REPLICAS} replica(s); restore it manually.${NC}" >&2
    if [[ "${rc}" -eq 0 ]]; then
      rc=1
    fi
  fi
  exit "${rc}"
}
trap cleanup EXIT
# Every terminating signal the script can receive while it runs ends through
# cleanup. A closed stdout (a `| tee` or `| head` reader gone, a dropped SSH
# session) raises SIGPIPE on the script's next write. Untrapped, SIGPIPE kills
# bash outright, the EXIT trap never runs, and the gateway stays pinned at
# GATEWAY_REPLICAS; the closed-stdout test died that way under load on
# 2026-11-01. Bash happens to run the EXIT trap for an untrapped SIGHUP, but
# only through its own signal handling, so HUP is trapped explicitly as well.
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 141' PIPE
trap 'exit 143' TERM

echo -e "${CYAN}🎛️  Pinning deployment/gateway to ${GATEWAY_REPLICAS} replica (was ${ORIGINAL_REPLICAS})...${NC}"
"${KUBECTL[@]}" scale deployment/gateway --replicas="${GATEWAY_REPLICAS}"
"${KUBECTL[@]}" rollout status deployment/gateway --timeout=300s
# Replica count and spec generation once pinned; any change to the
# deployment's spec during the run (even one reverted before the end) moves
# the generation.
PINNED_STATE="$("${KUBECTL[@]}" get deployment/gateway -o jsonpath='{.spec.replicas}/{.metadata.generation}')"

# 4. Launch Locust in background. The locustfile drives
# POST /governance/validate-action (weight 5) and GET /health (weight 1);
# the latency gate reads the GET /health row. Each run writes its report and
# Locust log to a fresh directory, so files left by an earlier run can never
# stand in for this one.
RUN_DIR="$(mktemp -d "${TMPDIR:-/tmp}/cage-load-test.XXXXXX")"
CSV_PREFIX="${RUN_DIR}/locust_report"
LOCUST_LOG="${RUN_DIR}/locust_run.log"

# Report why the run produced no valid measurement, show the end of the
# Locust log, and fail.
fail_measurement() {
  echo -e "${RED}❌ $1${NC}" >&2
  echo -e "${YELLOW}Last lines of ${LOCUST_LOG}:${NC}" >&2
  tail -n 20 "${LOCUST_LOG}" >&2 || true
  exit 1
}

echo -e "${CYAN}⚡ Starting headless Locust load test against ${GATEWAY_URL} (POST /governance/validate-action, GET /health; users=${MAX_USERS}, spawn-rate=${SPAWN_RATE}, run-time=${RUN_TIME})...${NC}"
echo -e "${CYAN}   Report and Locust log: ${RUN_DIR}${NC}"
locust -f tests/load/locustfile.py \
  --host "${GATEWAY_URL}" \
  --headless \
  --users "${MAX_USERS}" \
  --spawn-rate "${SPAWN_RATE}" \
  --run-time "${RUN_TIME}" \
  --csv "${CSV_PREFIX}" \
  --only-summary \
  >"${LOCUST_LOG}" 2>&1 &
LOCUST_PID=$!

# 5. Poll gateway pods during the run
echo -e "${CYAN}⏳ Monitoring gateway pods for 60 seconds...${NC}"
for i in {1..12}; do
  sleep 5
  echo -e "\n${GREEN}--- Monitoring Poll #$i (after $((i*5))s) ---${NC}"
  
  echo -e "${YELLOW}Gateway Pods Status:${NC}"
  "${KUBECTL[@]}" get pods -l app=gateway -o wide || echo "No gateway pods found"
done

# Wait for Locust. Status 0 and 1 proceed to the GET /health CSV validation
# below (Locust's default --exit-code-on-error is 1 when any request or task
# failed; a startup error that exited 1 still fails the CSV /health checks).
# Any other status (e.g. 2 for argparse usage errors or unhandled greenlets,
# or >128 on signals) fails immediately.
LOCUST_RC=0
wait "${LOCUST_PID}" || LOCUST_RC=$?
LOCUST_PID=""
if [[ "${LOCUST_RC}" -ne 0 && "${LOCUST_RC}" -ne 1 ]]; then
  fail_measurement "Locust exited with status ${LOCUST_RC}; nothing was measured."
fi

# The deployment must not have been rescaled or edited during the run.
FINAL_STATE="$("${KUBECTL[@]}" get deployment/gateway -o jsonpath='{.spec.replicas}/{.metadata.generation}')"
if [[ "${FINAL_STATE}" != "${PINNED_STATE}" ]]; then
  echo -e "${RED}❌ deployment/gateway changed during the run (replicas/generation ${PINNED_STATE} → ${FINAL_STATE}); results are invalid.${NC}" >&2
  exit 1
fi
echo -e "\n${GREEN}✅ Locust run finished; deployment/gateway stayed pinned.${NC}"

# 6. Display reports and assert latency
echo -e "${CYAN}📊 Performance Report Summary:${NC}"
STATS_FILE="${CSV_PREFIX}_stats.csv"

if [ ! -f "${STATS_FILE}" ]; then
  fail_measurement "Locust stats CSV not found at ${STATS_FILE}; nothing was measured."
fi
cat "${STATS_FILE}" | column -s, -t || cat "${STATS_FILE}"
if [[ "${LOCUST_RC}" -eq 1 ]]; then
  echo -e "${YELLOW}⚠️  Locust reported failed requests (exit status 1); see ${CSV_PREFIX}_failures.csv and ${CSV_PREFIX}_exceptions.csv. Only GET /health failures fail this run.${NC}"
fi

# Parse the GET /health row; the latency gate reads only this row.
HEALTH_ROW=$(grep "/health" "${STATS_FILE}" | head -n 1 || true)
if [ -z "${HEALTH_ROW}" ]; then
  fail_measurement "Could not find a /health row in ${STATS_FILE}; nothing was measured."
fi
# In locust stats CSV, fields are:
# 0: Type, 1: Name, 2: Request Count, 3: Failure Count, 4: Median response time,
# 5: Average response time, 6: Min response time, 7: Max response time, 8: Average Content Size,
# 9: Requests/s, 10: Failures/s, 11: 50%, 12: 66%, 13: 75%, 14: 80%, 15: 90%, 16: 95%, 17: 98%, 18: 99%, 19: 99.9%, 20: 99.99%, 21: 100%
REQUEST_COUNT=$(echo "${HEALTH_ROW}" | cut -d',' -f3 | xargs)
FAILURE_COUNT=$(echo "${HEALTH_ROW}" | cut -d',' -f4 | xargs)
AVG_LATENCY=$(echo "${HEALTH_ROW}" | cut -d',' -f6 | xargs)
P95_LATENCY=$(echo "${HEALTH_ROW}" | cut -d',' -f17 | xargs)
if ! [[ "${REQUEST_COUNT}" =~ ^[0-9]+$ && "${FAILURE_COUNT}" =~ ^[0-9]+$ ]]; then
  fail_measurement "Could not parse the /health request counts (got '${REQUEST_COUNT}' requests, '${FAILURE_COUNT}' failures)."
fi
if [[ "${REQUEST_COUNT}" -eq 0 ]]; then
  fail_measurement "No /health request was recorded; nothing was measured."
fi
# Locust averages failed requests in with the rest, so fast failures (e.g. a
# dropped port-forward) would pull the average under the threshold.
if [[ "${FAILURE_COUNT}" -gt 0 ]]; then
  fail_measurement "${FAILURE_COUNT} of ${REQUEST_COUNT} /health requests failed; the average latency is not a valid measurement."
fi
if ! [[ "${AVG_LATENCY}" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
  fail_measurement "Could not parse the average /health latency (got '${AVG_LATENCY}')."
fi

echo -e "\n${CYAN}⏱️  Key Metrics Summary:${NC}"
echo -e "   - Average Latency: ${AVG_LATENCY} ms"
echo -e "   - 95th Percentile Latency: ${P95_LATENCY} ms"

# Assert latency boundaries (average latency must be < MAX_ALLOWED_AVG ms)
if awk -v avg="${AVG_LATENCY}" -v max="${MAX_ALLOWED_AVG}" 'BEGIN { exit !(avg < max) }'; then
  echo -e "${GREEN}🎉 PASS: Average latency is within limits (< ${MAX_ALLOWED_AVG}ms).${NC}"
else
  echo -e "${RED}❌ FAIL: Average latency exceeded threshold of ${MAX_ALLOWED_AVG}ms (got ${AVG_LATENCY}ms).${NC}" >&2
  exit 1
fi

echo -e "\n${GREEN}🌟 GKE Load and stress validation successfully completed!${NC}"
