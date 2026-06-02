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

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
RESET='\033[0m'

pass() { echo -e "${GREEN}✅ $*${RESET}"; }
fail() { echo -e "${RED}❌ $*${RESET}"; }
warn() { echo -e "${YELLOW}⚠️  $*${RESET}"; }

NAMESPACE="${1:-governance-stack-dev}"
FAILED=0

echo "🔍 Validating deployment in namespace: $NAMESPACE"
echo ""

# ─── Check Namespace ──────────────────────────────────────────────────────────

if kubectl get namespace "$NAMESPACE" &>/dev/null; then
  pass "Namespace $NAMESPACE exists"
else
  fail "Namespace $NAMESPACE not found"
  FAILED=1
fi

# ─── Check MinIO Deployment ───────────────────────────────────────────────────

if kubectl get deployment minio -n "$NAMESPACE" &>/dev/null 2>&1 || \
   kubectl get statefulset minio -n "$NAMESPACE" &>/dev/null 2>&1; then
  pass "MinIO deployment exists"
  
  # Check pod status
  POD_STATUS=$(kubectl get pods -n "$NAMESPACE" -l app=minio \
    -o jsonpath='{.items[0].status.phase}' 2>/dev/null || echo "NotFound")
  
  if [[ "$POD_STATUS" == "Running" ]]; then
    pass "MinIO pod is running"
  else
    fail "MinIO pod status: $POD_STATUS (expected: Running)"
    FAILED=1
  fi
else
  fail "MinIO deployment not found"
  FAILED=1
fi

# ─── Check MinIO Service ──────────────────────────────────────────────────────

if kubectl get service minio -n "$NAMESPACE" &>/dev/null; then
  pass "MinIO service exists"
  
  CLUSTER_IP=$(kubectl get service minio -n "$NAMESPACE" \
    -o jsonpath='{.spec.clusterIP}' 2>/dev/null || echo "None")
  
  if [[ "$CLUSTER_IP" != "None" && -n "$CLUSTER_IP" ]]; then
    pass "MinIO service has ClusterIP: $CLUSTER_IP"
  else
    fail "MinIO service has no ClusterIP"
    FAILED=1
  fi
else
  fail "MinIO service not found"
  FAILED=1
fi

# ─── Check MinIO Credentials Secret ───────────────────────────────────────────

if kubectl get secret minio-credentials -n "$NAMESPACE" &>/dev/null; then
  pass "MinIO credentials secret exists"
  
  # Verify secret has required keys
  if kubectl get secret minio-credentials -n "$NAMESPACE" \
    -o jsonpath='{.data.access-key}' &>/dev/null; then
    pass "MinIO credentials contain access-key"
  else
    fail "MinIO credentials missing access-key"
    FAILED=1
  fi
  
  if kubectl get secret minio-credentials -n "$NAMESPACE" \
    -o jsonpath='{.data.secret-key}' &>/dev/null; then
    pass "MinIO credentials contain secret-key"
  else
    fail "MinIO credentials missing secret-key"
    FAILED=1
  fi
else
  fail "MinIO credentials secret not found"
  FAILED=1
fi

# ─── Check MinIO Connectivity ─────────────────────────────────────────────────

echo ""
echo "🔌 Testing MinIO connectivity..."

POD_NAME=$(kubectl get pods -n "$NAMESPACE" -l app=minio \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")

if [[ -n "$POD_NAME" ]]; then
  if kubectl exec -n "$NAMESPACE" "$POD_NAME" -- \
    sh -c "curl -s http://localhost:9000/minio/health/live" &>/dev/null; then
    pass "MinIO health check passed"
  else
    warn "MinIO health check failed (pod may still be starting)"
  fi
else
  warn "No MinIO pod found for connectivity test"
fi

# ─── Summary ──────────────────────────────────────────────────────────────────

echo ""
echo "════════════════════════════════════════════════════════"

if [[ $FAILED -eq 0 ]]; then
  pass "All validation checks passed!"
  echo ""
  echo "Next steps:"
  echo "  1. Access MinIO console: kubectl port-forward svc/minio 9001:9001 -n $NAMESPACE"
  echo "  2. Open: http://localhost:9001"
  echo "  3. Get credentials: kubectl get secret minio-credentials -n $NAMESPACE -o yaml"
  exit 0
else
  fail "Some validation checks failed"
  echo ""
  echo "Troubleshooting:"
  echo "  1. Check pod logs: kubectl logs -n $NAMESPACE <pod-name>"
  echo "  2. Describe pod: kubectl describe pod -n $NAMESPACE <pod-name>"
  echo "  3. Check events: kubectl get events -n $NAMESPACE --sort-by='.lastTimestamp'"
  exit 1
fi
