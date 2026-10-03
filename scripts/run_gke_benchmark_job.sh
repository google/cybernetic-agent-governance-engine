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
# Optional env: IMAGE_TAG (default: short SHA of HEAD; build it first with
# deployment/docker/cloudbuild.image.yaml, _IMAGE_NAME=governed-financial-advisor).
#               BENCHMARK_REDIS_IMAGE (default: the Docker Hub redis pin; set an
#               attested mirror, e.g. gcr.io/<project>/redis@sha256:..., when the
#               cluster enforces Binary Authorization).
#
# The paper metrics run --unmocked, so OPA and vllm-reasoning must be serving.
# Scale vllm-reasoning up before the run and back to 0 afterwards:
#   kubectl scale deployment/vllm-reasoning -n governance-stack --replicas=1

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
IMAGE_TAG="${IMAGE_TAG:-${GIT_SHA}}"
BENCHMARK_REDIS_IMAGE="${BENCHMARK_REDIS_IMAGE:-redis:7.2-alpine@sha256:29e8589c3f9ba699b5f7aa4b3c7733c58852a3626439e619aa0ee78de08c6ca0}"
export IMAGE_TAG BENCHMARK_REDIS_IMAGE

# Render a manifest, substituting only the named variables (python3, so the
# runner does not depend on gettext's envsubst; the Job's own ${BACKEND_URL}-
# style shell references survive).
render() {
  python3 - "$@" <<'PY'
import os, sys
text = open(sys.argv[1]).read()
for name in sys.argv[2:]:
    text = text.replace("${" + name + "}", os.environ[name])
sys.stdout.write(text)
PY
}
OUTPUT_DIR="docs/paper/measurements/$(date -u +%Y-%m-%d)-${GIT_SHA}"
DONE_TIMEOUT_S="${DONE_TIMEOUT_S:-1800}"

if ! git diff --quiet HEAD -- src scripts config; then
  echo -e "${YELLOW}⚠️  Working tree differs from ${GIT_SHA} under src/ scripts/ config/; PROVENANCE will record it as dirty.${NC}"
  GIT_SHA="${GIT_SHA}-dirty"
fi

cleanup() {
  echo -e "${CYAN}🧹 Deleting Job ${JOB_NAME} and the throwaway benchmark Redis...${NC}"
  kubectl delete job "${JOB_NAME}" -n "${NAMESPACE}" --ignore-not-found=true --wait=false || true
  render "${REDIS_MANIFEST}" BENCHMARK_REDIS_IMAGE | kubectl delete -f - -n "${NAMESPACE}" --ignore-not-found=true --wait=false || true
}
trap cleanup EXIT

for dep in opa-service vllm-reasoning; do
  ready=$(kubectl get deployment "${dep}" -n "${NAMESPACE}" -o jsonpath='{.status.readyReplicas}' 2>/dev/null || true)
  if [ -z "${ready}" ] || [ "${ready}" = "0" ]; then
    echo -e "${RED}❌ ${dep} has no ready replicas; --unmocked needs it serving.${NC}"
    echo -e "   kubectl scale deployment/${dep} -n ${NAMESPACE} --replicas=1"
    exit 1
  fi
done

echo -e "${CYAN}=================================================================${NC}"
echo -e "${CYAN}🚀 [CAGE In-Cluster GKE Benchmark Runner] Starting execution...${NC}"
echo -e "${CYAN}=================================================================${NC}"
echo -e "Namespace:   ${YELLOW}${NAMESPACE}${NC}"
echo -e "Job Name:    ${YELLOW}${JOB_NAME}${NC}"
echo -e "Git SHA:     ${YELLOW}${GIT_SHA}${NC}"
echo -e "Image tag:   ${YELLOW}${IMAGE_TAG}${NC}"
echo -e "Target Dir:  ${YELLOW}${OUTPUT_DIR}${NC}"
echo ""

# 1. Clean up any previous benchmark job and Redis (a stale Redis would hold
#    CBF state from the last run and make the reconciliation step refuse).
echo -e "${CYAN}🧹 [Step 1/6] Removing any previous benchmark Job and Redis...${NC}"
kubectl delete job "${JOB_NAME}" -n "${NAMESPACE}" --ignore-not-found=true --wait=true
render "${REDIS_MANIFEST}" BENCHMARK_REDIS_IMAGE | kubectl delete -f - -n "${NAMESPACE}" --ignore-not-found=true --wait=true

# 2. Throwaway Redis primary + replica
echo -e "${CYAN}🧱 [Step 2/6] Starting throwaway Redis (${REDIS_MANIFEST})...${NC}"
render "${REDIS_MANIFEST}" BENCHMARK_REDIS_IMAGE | kubectl apply -n "${NAMESPACE}" -f -
# 600 s: the pods may wait for the cluster autoscaler to add a node.
kubectl rollout status deployment/benchmark-redis-primary -n "${NAMESPACE}" --timeout=600s
kubectl rollout status deployment/benchmark-redis-replica -n "${NAMESPACE}" --timeout=600s
REDIS_IMAGE=$(kubectl get deployment benchmark-redis-primary -n "${NAMESPACE}" \
  -o jsonpath='{.spec.template.spec.containers[0].image}')

# 3. ConfigMaps and the Job.
echo -e "${CYAN}📦 [Step 3/6] Refreshing ConfigMaps and applying ${JOB_MANIFEST}...${NC}"
kubectl create configmap red-team-datasets \
  --from-file=tests/red_team/adversarial_dataset.json \
  --from-file=tests/red_team/benign_dataset.json \
  -n "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -

kubectl create configmap benchmark-scripts \
  --from-file=scripts/measure_paper_metrics.py \
  --from-file=scripts/measure_reconciliation_metrics.py \
  -n "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -

render "${JOB_MANIFEST}" REGISTRY_URL IMAGE_TAG GOOGLE_CLOUD_PROJECT \
  | kubectl apply -n "${NAMESPACE}" -f -

echo -e "${CYAN}⏳ [Step 4/6] Waiting for benchmark pod to start...${NC}"
# kubectl wait fails at once if no pod matches yet, so first wait for the Job
# controller to create one.
for _ in $(seq 1 60); do
  [ -n "$(kubectl get pods -l app=cage-paper-benchmark -n "${NAMESPACE}" -o name 2>/dev/null)" ] && break
  sleep 2
done
kubectl wait --for=condition=Ready pod -l app=cage-paper-benchmark -n "${NAMESPACE}" --timeout=600s
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

OPA_IMAGE=$(kubectl get pods -l app=opa -n "${NAMESPACE}" \
  -o jsonpath='{.items[0].status.containerStatuses[?(@.name=="opa")].imageID}' 2>/dev/null || echo unknown)
VLLM_IMAGE=$(kubectl get pods -l app=vllm-reasoning -n "${NAMESPACE}" \
  -o jsonpath='{.items[0].status.containerStatuses[?(@.name=="vllm")].imageID}' 2>/dev/null || echo unknown)
VLLM_MODEL=$(kubectl get deployment vllm-reasoning -n "${NAMESPACE}" \
  -o jsonpath='{.spec.template.spec.containers[0].env[?(@.name=="SERVED_MODEL_NAME")].value}' 2>/dev/null || echo unknown)

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
| OPA | ${OPA_IMAGE} |
| Consensus backend | vllm-reasoning \`${VLLM_MODEL}\` (${VLLM_IMAGE}) |
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
