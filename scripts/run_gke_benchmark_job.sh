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
JOB_NAME="cage-paper-benchmark"
TIMESTAMP=$(date -u +%Y-%m-%d-%H%M%S)
OUTPUT_DIR="docs/paper/measurements/${TIMESTAMP}-gke-incluster"

echo -e "${CYAN}=================================================================${NC}"
echo -e "${CYAN}🚀 [CAGE In-Cluster GKE Benchmark Runner] Starting execution...${NC}"
echo -e "${CYAN}=================================================================${NC}"
echo -e "Namespace:   ${YELLOW}${NAMESPACE}${NC}"
echo -e "Job Name:    ${YELLOW}${JOB_NAME}${NC}"
echo -e "Target Dir:  ${YELLOW}${OUTPUT_DIR}${NC}"
echo ""

# 1. Clean up any previous completed or failed benchmark job
echo -e "${CYAN}🧹 [Step 1/5] Cleaning up existing benchmark job (if any)...${NC}"
kubectl delete job "${JOB_NAME}" -n "${NAMESPACE}" --ignore-not-found=true

# 2. Apply ConfigMaps and the Kubernetes Job manifest
echo -e "${CYAN}📦 [Step 2/5] Refreshing ConfigMaps and applying deployment/k8s/benchmark-job.yaml...${NC}"
kubectl create configmap red-team-datasets \
  --from-file=tests/red_team/adversarial_dataset.json \
  --from-file=tests/red_team/benign_dataset.json \
  -n "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -

kubectl create configmap benchmark-scripts \
  --from-file=scripts/measure_paper_metrics.py \
  --from-file=scripts/measure_reconciliation_metrics.py \
  -n "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -

kubectl apply -f deployment/k8s/benchmark-job.yaml -n "${NAMESPACE}"

# 3. Wait for pod creation and readiness
echo -e "${CYAN}⏳ [Step 3/5] Waiting for benchmark pod to start...${NC}"
kubectl wait --for=condition=Ready pod -l app=cage-paper-benchmark -n "${NAMESPACE}" --timeout=180s || {
  echo -e "${YELLOW}⚠️  Pod readiness wait timed out or completed immediately. Inspecting pods...${NC}"
}

POD_NAME=$(kubectl get pods -l app=cage-paper-benchmark -n "${NAMESPACE}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
if [ -z "${POD_NAME}" ]; then
  echo -e "${RED}❌ Error: Benchmark pod not found in namespace ${NAMESPACE}.${NC}"
  exit 1
fi
echo -e "Active pod: ${GREEN}${POD_NAME}${NC}"
echo ""

# 4. Stream logs from the running job
echo -e "${CYAN}📡 [Step 4/5] Streaming benchmark logs from GKE...${NC}"
kubectl logs -f "${POD_NAME}" -n "${NAMESPACE}" || {
  echo -e "${YELLOW}⚠️  Log stream ended (waiting for container completion)...${NC}"
}

echo -e "${CYAN}⏳ Waiting for Job ${JOB_NAME} to complete execution...${NC}"
kubectl wait --for=condition=complete "job/${JOB_NAME}" -n "${NAMESPACE}" --timeout=1800s || {
  echo -e "${YELLOW}⚠️  Job wait condition timed out or finished.${NC}"
}

# 5. Extract output measurement JSON/TXT artifacts
echo ""
echo -e "${CYAN}💾 [Step 5/5] Extracting measurement artifacts to local workspace...${NC}"
mkdir -p "${OUTPUT_DIR}"

if kubectl cp "${NAMESPACE}/${POD_NAME}:/tmp/cage_paper_metrics.json" "${OUTPUT_DIR}/cage_paper_metrics.json" 2>/dev/null; then
  echo -e "  ${GREEN}✓${NC} Saved ${OUTPUT_DIR}/cage_paper_metrics.json"
else
  echo -e "  ${YELLOW}⚠️  /tmp/cage_paper_metrics.json not found on pod.${NC}"
fi

if kubectl cp "${NAMESPACE}/${POD_NAME}:/tmp/cage_paper_metrics.txt" "${OUTPUT_DIR}/cage_paper_metrics.txt" 2>/dev/null; then
  echo -e "  ${GREEN}✓${NC} Saved ${OUTPUT_DIR}/cage_paper_metrics.txt"
fi

if kubectl cp "${NAMESPACE}/${POD_NAME}:/tmp/cage_reconciliation_metrics.json" "${OUTPUT_DIR}/cage_reconciliation_metrics.json" 2>/dev/null; then
  echo -e "  ${GREEN}✓${NC} Saved ${OUTPUT_DIR}/cage_reconciliation_metrics.json"
fi

if kubectl cp "${NAMESPACE}/${POD_NAME}:/tmp/cage_reconciliation_metrics.txt" "${OUTPUT_DIR}/cage_reconciliation_metrics.txt" 2>/dev/null; then
  echo -e "  ${GREEN}✓${NC} Saved ${OUTPUT_DIR}/cage_reconciliation_metrics.txt"
fi

# Write PROVENANCE.md manifest
cat <<EOF > "${OUTPUT_DIR}/PROVENANCE.md"
# Measurement Provenance — In-Cluster GKE Benchmark Run

| Field | Value |
|---|---|
| Generated | $(date -u +%Y-%m-%dT%H:%M:%SZ) |
| Pod | ${POD_NAME} |
| Namespace | ${NAMESPACE} |
| Job | ${JOB_NAME} |
| Output Directory | ${OUTPUT_DIR} |
| Execution Mode | In-Cluster VPC-Native Kubernetes Job |

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
