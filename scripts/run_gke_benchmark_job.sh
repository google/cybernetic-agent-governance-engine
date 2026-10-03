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

# Manual report tool: runs the paper benchmark as an in-cluster Job and copies
# its artifacts to docs/paper/measurements/<date>-<sha>/. Not run in CI.
#
# The Job runs against a throwaway Redis (deployment/k8s/benchmark-redis.yaml,
# one primary + one replica) that this script creates first and always deletes
# on exit. It never touches the shared redis-master.
#
# Required env: REGISTRY_URL, GOOGLE_CLOUD_PROJECT (substituted into the Job).

set -eo pipefail

# ANSI color codes
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

: "${REGISTRY_URL:?REGISTRY_URL must be set (Artifact Registry path of the advisor image)}"
: "${GOOGLE_CLOUD_PROJECT:?GOOGLE_CLOUD_PROJECT must be set}"
export REGISTRY_URL GOOGLE_CLOUD_PROJECT

NAMESPACE="${NAMESPACE:-governance-stack}"
JOB_NAME="cage-paper-benchmark"
REDIS_MANIFEST="deployment/k8s/benchmark-redis.yaml"
JOB_MANIFEST="deployment/k8s/benchmark-job.yaml"
GIT_SHA=$(git rev-parse --short HEAD)
OUTPUT_DIR="docs/paper/measurements/$(date -u +%Y-%m-%d)-${GIT_SHA}"
DONE_TIMEOUT_S="${DONE_TIMEOUT_S:-1800}"

if ! git diff --quiet HEAD -- src scripts config; then
  echo -e "${YELLOW}⚠️  Working tree differs from ${GIT_SHA} under src/ scripts/ config/; PROVENANCE will record it as dirty.${NC}"
  GIT_SHA="${GIT_SHA}-dirty"
fi

cleanup() {
  echo -e "${CYAN}🧹 Deleting Job ${JOB_NAME} and the throwaway benchmark Redis...${NC}"
  kubectl delete job "${JOB_NAME}" -n "${NAMESPACE}" --ignore-not-found=true --wait=false || true
  kubectl delete -f "${REDIS_MANIFEST}" -n "${NAMESPACE}" --ignore-not-found=true --wait=false || true
}
trap cleanup EXIT

echo -e "${CYAN}=================================================================${NC}"
echo -e "${CYAN}🚀 [CAGE In-Cluster GKE Benchmark Runner] Starting execution...${NC}"
echo -e "${CYAN}=================================================================${NC}"
echo -e "Namespace:   ${YELLOW}${NAMESPACE}${NC}"
echo -e "Job Name:    ${YELLOW}${JOB_NAME}${NC}"
echo -e "Git SHA:     ${YELLOW}${GIT_SHA}${NC}"
echo -e "Target Dir:  ${YELLOW}${OUTPUT_DIR}${NC}"
echo ""

# 1. Clean up any previous benchmark job and Redis (a stale Redis would hold
#    CBF state from the last run and make the reconciliation step refuse).
echo -e "${CYAN}🧹 [Step 1/6] Removing any previous benchmark Job and Redis...${NC}"
kubectl delete job "${JOB_NAME}" -n "${NAMESPACE}" --ignore-not-found=true --wait=true
kubectl delete -f "${REDIS_MANIFEST}" -n "${NAMESPACE}" --ignore-not-found=true --wait=true

# 2. Throwaway Redis primary + replica
echo -e "${CYAN}🧱 [Step 2/6] Starting throwaway Redis (${REDIS_MANIFEST})...${NC}"
kubectl apply -f "${REDIS_MANIFEST}" -n "${NAMESPACE}"
kubectl rollout status deployment/benchmark-redis-primary -n "${NAMESPACE}" --timeout=180s
kubectl rollout status deployment/benchmark-redis-replica -n "${NAMESPACE}" --timeout=180s
REDIS_IMAGE=$(kubectl get deployment benchmark-redis-primary -n "${NAMESPACE}" \
  -o jsonpath='{.spec.template.spec.containers[0].image}')

# 3. ConfigMaps and the Job (envsubst limited to the two deployment variables
#    so the Job's own ${BACKEND_URL}-style shell references survive).
echo -e "${CYAN}📦 [Step 3/6] Refreshing ConfigMaps and applying ${JOB_MANIFEST}...${NC}"
kubectl create configmap red-team-datasets \
  --from-file=tests/red_team/adversarial_dataset.json \
  --from-file=tests/red_team/benign_dataset.json \
  -n "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -

kubectl create configmap benchmark-scripts \
  --from-file=scripts/measure_paper_metrics.py \
  --from-file=scripts/measure_reconciliation_metrics.py \
  -n "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -

# shellcheck disable=SC2016  # literal variable names for envsubst
envsubst '${REGISTRY_URL} ${GOOGLE_CLOUD_PROJECT}' < "${JOB_MANIFEST}" \
  | kubectl apply -n "${NAMESPACE}" -f -

echo -e "${CYAN}⏳ [Step 4/6] Waiting for benchmark pod to start...${NC}"
kubectl wait --for=condition=Ready pod -l app=cage-paper-benchmark -n "${NAMESPACE}" --timeout=300s
POD_NAME=$(kubectl get pods -l app=cage-paper-benchmark -n "${NAMESPACE}" -o jsonpath='{.items[0].metadata.name}')
JOB_IMAGE=$(kubectl get pod "${POD_NAME}" -n "${NAMESPACE}" \
  -o jsonpath='{.status.containerStatuses[?(@.name=="benchmark-runner")].imageID}')
echo -e "Active pod: ${GREEN}${POD_NAME}${NC}"
echo ""

# 5. Stream logs until the Job writes its completion marker. The container
#    then stays up for HARVEST_WINDOW_S so kubectl cp can reach /tmp.
echo -e "${CYAN}📡 [Step 5/6] Streaming benchmark logs...${NC}"
kubectl logs -f "${POD_NAME}" -c benchmark-runner -n "${NAMESPACE}" &
LOGS_PID=$!
elapsed=0
until kubectl exec "${POD_NAME}" -c benchmark-runner -n "${NAMESPACE}" -- test -f /tmp/cage_benchmark_done 2>/dev/null; do
  phase=$(kubectl get pod "${POD_NAME}" -n "${NAMESPACE}" -o jsonpath='{.status.phase}')
  if [ "${phase}" = "Failed" ] || [ "${phase}" = "Succeeded" ]; then
    kill "${LOGS_PID}" 2>/dev/null || true
    echo -e "${RED}❌ Benchmark container exited (${phase}) before writing its completion marker.${NC}"
    exit 1
  fi
  if [ "${elapsed}" -ge "${DONE_TIMEOUT_S}" ]; then
    kill "${LOGS_PID}" 2>/dev/null || true
    echo -e "${RED}❌ Benchmark did not finish within ${DONE_TIMEOUT_S}s.${NC}"
    exit 1
  fi
  sleep 10
  elapsed=$((elapsed + 10))
done
kill "${LOGS_PID}" 2>/dev/null || true

# 6. Copy artifacts and write PROVENANCE.md
echo ""
echo -e "${CYAN}💾 [Step 6/6] Copying measurement artifacts to ${OUTPUT_DIR}...${NC}"
mkdir -p "${OUTPUT_DIR}"
for artifact in cage_paper_metrics.json cage_paper_metrics.txt \
                cage_reconciliation_metrics.json cage_reconciliation_metrics.txt; do
  if kubectl cp -c benchmark-runner "${NAMESPACE}/${POD_NAME}:/tmp/${artifact}" "${OUTPUT_DIR}/${artifact}" 2>/dev/null; then
    echo -e "  ${GREEN}✓${NC} Saved ${OUTPUT_DIR}/${artifact}"
  else
    echo -e "  ${YELLOW}⚠️  /tmp/${artifact} not found on pod.${NC}"
  fi
done

LATENCY_MODE=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("latency_mode","unknown"))' \
  "${OUTPUT_DIR}/cage_paper_metrics.json" 2>/dev/null || echo "unknown (cage_paper_metrics.json missing)")

cat <<EOF > "${OUTPUT_DIR}/PROVENANCE.md"
# Measurement Provenance — In-Cluster GKE Benchmark Run

| Field | Value |
|---|---|
| Generated | $(date -u +%Y-%m-%dT%H:%M:%SZ) |
| Git SHA | ${GIT_SHA} |
| Benchmark image | ${JOB_IMAGE} |
| Pod | ${POD_NAME} |
| Namespace | ${NAMESPACE} |
| Job | ${JOB_NAME} |
| Redis | Throwaway \`benchmark-redis\` (${REDIS_MANIFEST}): 1 primary + 1 replica, no persistence, \`${REDIS_IMAGE}\` |
| Replication wait | \`CAGE_REDIS_WAIT_REPLICAS=1\` |
| Latency mode | ${LATENCY_MODE} |
| Output Directory | ${OUTPUT_DIR} |

## Run Artifacts
- \`cage_paper_metrics.json\`
- \`cage_paper_metrics.txt\`
- \`cage_reconciliation_metrics.json\`
- \`cage_reconciliation_metrics.txt\`
EOF

echo -e "\n${GREEN}=================================================================${NC}"
echo -e "${GREEN}✅ Benchmark execution and artifact harvesting complete!${NC}"
echo -e "Artifacts directory: ${CYAN}${OUTPUT_DIR}${NC}"
echo -e "${GREEN}=================================================================${NC}"
