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
LOG_DIR="${TMPDIR:-/tmp}"
CSV_PREFIX="${LOG_DIR}/locust_report"

# ============================================================
# LOAD TEST SAFETY LIMITS — DO NOT REMOVE
# These limits prevent service degradation on live GKE.
# Adjust only with coordinator sign-off.
# ============================================================
MAX_USERS="${LOAD_TEST_MAX_USERS:-50}"
SPAWN_RATE="${LOAD_TEST_SPAWN_RATE:-5}"
RUN_TIME="${LOAD_TEST_RUN_TIME:-5m}"
GATEWAY_URL="${LOAD_TEST_GATEWAY_URL:-http://localhost:8080}"

# The gateway keeps pod-local state (MCP SSE sessions, quarantine records,
# NeMo refinement proposals). With more than one replica, an MCP session's
# SSE stream and its POSTs land on different pods, so the load test runs
# exactly one replica with no autoscaler. Multi-replica load tests wait for
# the stateless gateway.
readonly GATEWAY_REPLICAS=1

echo -e "${CYAN}🚀 [Locust Load Test] Initializing GKE load validation...${NC}"

# 1. Refuse production contexts: this script rescales the gateway.
CURRENT_CONTEXT="$(kubectl config current-context 2>/dev/null || echo none)"
if [[ "${CURRENT_CONTEXT}" == "none" ]]; then
  echo -e "${RED}❌ Unable to determine the current kubectl context. Is kubectl configured?${NC}" >&2
  exit 1
fi
if [[ "${CURRENT_CONTEXT}" =~ prod && "${LOAD_TEST_FORCE:-false}" != "true" ]]; then
  echo -e "${RED}❌ kubectl context '${CURRENT_CONTEXT}' looks like production; the load test rescales the gateway.${NC}" >&2
  echo -e "${RED}   Switch context, or set LOAD_TEST_FORCE=true if this is deliberate.${NC}" >&2
  exit 1
fi

# 2. Ensure locust is installed
if ! command -v locust &>/dev/null; then
  echo -e "${YELLOW}⚠️  Locust not found in PATH. Attempting installation via uv...${NC}"
  uv pip install locust || pip install locust
fi

# 3. Pin one gateway replica for the run; restore the original count on exit.
echo -e "${CYAN}🎛️  Removing any gateway HPA left by earlier runs...${NC}"
kubectl delete hpa gateway-hpa -n "${NAMESPACE}" --ignore-not-found
HPA_TARGETS="$(kubectl get hpa -n "${NAMESPACE}" --no-headers \
  -o custom-columns=KIND:.spec.scaleTargetRef.kind,NAME:.spec.scaleTargetRef.name)"
if grep -Eq '^Deployment[[:space:]]+gateway$' <<<"${HPA_TARGETS}"; then
  echo -e "${RED}❌ An autoscaler still targets deployment/gateway in ${NAMESPACE}; remove it before load testing.${NC}" >&2
  exit 1
fi

ORIGINAL_REPLICAS="$(kubectl get deployment/gateway -n "${NAMESPACE}" -o jsonpath='{.spec.replicas}')"
if ! [[ "${ORIGINAL_REPLICAS}" =~ ^[0-9]+$ ]]; then
  echo -e "${RED}❌ Could not read the gateway replica count (got '${ORIGINAL_REPLICAS}').${NC}" >&2
  exit 1
fi

LOCUST_PID=""
cleanup() {
  if [[ -n "${LOCUST_PID}" ]]; then
    kill "${LOCUST_PID}" 2>/dev/null || true
  fi
  echo -e "${CYAN}↩️  Restoring deployment/gateway to ${ORIGINAL_REPLICAS} replica(s)...${NC}"
  kubectl scale deployment/gateway --replicas="${ORIGINAL_REPLICAS}" -n "${NAMESPACE}" ||
    echo -e "${RED}❌ Could not restore deployment/gateway to ${ORIGINAL_REPLICAS} replica(s); restore it manually.${NC}" >&2
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

echo -e "${CYAN}🎛️  Pinning deployment/gateway to ${GATEWAY_REPLICAS} replica (was ${ORIGINAL_REPLICAS})...${NC}"
kubectl scale deployment/gateway --replicas="${GATEWAY_REPLICAS}" -n "${NAMESPACE}"
kubectl rollout status deployment/gateway -n "${NAMESPACE}" --timeout=300s

# 4. Launch Locust in background
echo -e "${CYAN}⚡ Starting headless Locust load test against ${GATEWAY_URL}/health (users=${MAX_USERS}, spawn-rate=${SPAWN_RATE}, run-time=${RUN_TIME})...${NC}"
locust -f tests/load/locustfile.py \
  --host "${GATEWAY_URL}" \
  --headless \
  --users "${MAX_USERS}" \
  --spawn-rate "${SPAWN_RATE}" \
  --run-time "${RUN_TIME}" \
  --agent-endpoint /health \
  --csv "${CSV_PREFIX}" \
  --only-summary \
  >/dev/null 2>&1 &
LOCUST_PID=$!

# 5. Poll gateway pods during the run
echo -e "${CYAN}⏳ Monitoring gateway pods for 60 seconds...${NC}"
for i in {1..12}; do
  sleep 5
  echo -e "\n${GREEN}--- Monitoring Poll #$i (after $((i*5))s) ---${NC}"
  
  echo -e "${YELLOW}Gateway Pods Status:${NC}"
  kubectl get pods -l app=gateway -n "${NAMESPACE}" -o wide || echo "No gateway pods found"
done

# Wait for Locust to finish if still running
wait "${LOCUST_PID}" 2>/dev/null || true
LOCUST_PID=""

# The pin must have held for the whole run, or the results are invalid.
FINAL_REPLICAS="$(kubectl get deployment/gateway -n "${NAMESPACE}" -o jsonpath='{.spec.replicas}')"
if [[ "${FINAL_REPLICAS}" != "${GATEWAY_REPLICAS}" ]]; then
  echo -e "${RED}❌ deployment/gateway was rescaled to ${FINAL_REPLICAS} during the run; results are invalid.${NC}" >&2
  exit 1
fi
echo -e "\n${GREEN}✅ Locust load test run completed successfully.${NC}"

# 6. Display reports and assert latency
echo -e "${CYAN}📊 Performance Report Summary:${NC}"
STATS_FILE="${CSV_PREFIX}_stats.csv"

if [ -f "${STATS_FILE}" ]; then
  cat "${STATS_FILE}" | column -s, -t || cat "${STATS_FILE}"
  
  # Parse average and 95th percentile latency from HTTP /health requests
  # Skip header line, get row matching "GET /health" or "/health"
  HEALTH_ROW=$(grep "/health" "${STATS_FILE}" | head -n 1 || true)
  if [ -n "${HEALTH_ROW}" ]; then
    # In locust stats CSV, fields are:
    # 0: Type, 1: Name, 2: Request Count, 3: Failure Count, 4: Median response time,
    # 5: Average response time, 6: Min response time, 7: Max response time, 8: Average Content Size,
    # 9: Requests/s, 10: Failures/s, 11: 50%, 12: 66%, 13: 75%, 14: 80%, 15: 90%, 16: 95%, 17: 98%, 18: 99%, 19: 99.9%, 20: 99.99%, 21: 100%
    AVG_LATENCY=$(echo "${HEALTH_ROW}" | cut -d',' -f6 | xargs || echo "0")
    P95_LATENCY=$(echo "${HEALTH_ROW}" | cut -d',' -f17 | xargs || echo "0")
    
    echo -e "\n${CYAN}⏱️  Key Metrics Summary:${NC}"
    echo -e "   - Average Latency: ${AVG_LATENCY} ms"
    echo -e "   - 95th Percentile Latency: ${P95_LATENCY} ms"
    
    # Assert latency boundaries (e.g., average latency should be < 200ms)
    MAX_ALLOWED_AVG=200
    if (( $(echo "$AVG_LATENCY < $MAX_ALLOWED_AVG" | bc -l) )); then
      echo -e "${GREEN}🎉 PASS: Average latency is within limits (< ${MAX_ALLOWED_AVG}ms).${NC}"
    else
      echo -e "${RED}❌ FAIL: Average latency exceeded threshold of ${MAX_ALLOWED_AVG}ms (got ${AVG_LATENCY}ms).${NC}"
      exit 1
    fi
  else
    echo -e "${YELLOW}⚠️  Could not parse /health row from stats CSV.${NC}"
  fi
else
  echo -e "${RED}❌ Locust stats CSV not found at ${STATS_FILE}${NC}"
fi

echo -e "\n${GREEN}🌟 GKE Load and stress validation successfully completed!${NC}"
