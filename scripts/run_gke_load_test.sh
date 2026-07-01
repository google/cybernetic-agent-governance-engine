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

echo -e "${CYAN}🚀 [Locust Load Test] Initializing GKE load validation...${NC}"

# 1. Ensure locust is installed
if ! command -v locust &>/dev/null; then
  echo -e "${YELLOW}⚠️  Locust not found in PATH. Attempting installation via uv...${NC}"
  uv pip install locust || pip install locust
fi

# 2. Apply the HPA manifest
echo -e "${CYAN}🎛️  Applying HorizontalPodAutoscaler to GKE...${NC}"
kubectl apply -f deployment/k8s/gateway-hpa.yaml -n "${NAMESPACE}"

# 3. Launch Locust in background
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

# 4. Poll HPA and scaling reactivity
echo -e "${CYAN}⏳ Monitoring HorizontalPodAutoscaler (HPA) and pods for 60 seconds...${NC}"
for i in {1..12}; do
  sleep 5
  echo -e "\n${GREEN}--- Monitoring Poll #$i (after $((i*5))s) ---${NC}"
  
  echo -e "${YELLOW}HPA Status:${NC}"
  kubectl get hpa gateway-hpa -n "${NAMESPACE}" || echo "HPA not ready yet"
  
  echo -e "${YELLOW}Gateway Pods Status:${NC}"
  kubectl get pods -l app=gateway -n "${NAMESPACE}" -o wide || echo "No gateway pods found"
done

# Wait for Locust to finish if still running
wait "${LOCUST_PID}" 2>/dev/null || true
echo -e "\n${GREEN}✅ Locust load test run completed successfully.${NC}"

# 5. Display reports and assert latency
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
