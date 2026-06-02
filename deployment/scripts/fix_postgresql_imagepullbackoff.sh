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

NS="governance-stack"
DRY_RUN=false

for arg in "$@"; do
  [[ "$arg" == "--dry-run" ]] && DRY_RUN=true
done

run() {
  if $DRY_RUN; then
    echo "[DRY-RUN] $*"
  else
    "$@"
  fi
}

echo "=== postgresql ImagePullBackOff remediation ==="
echo "Namespace: $NS"
$DRY_RUN && echo "(DRY-RUN mode — no changes will be made)"
echo ""

# 1. Show the current state so the operator can confirm before deletion.
echo "--- Current postgresql StatefulSet image ---"
kubectl get statefulset postgresql -n "$NS" \
  -o jsonpath='{.spec.template.spec.containers[*].image}' 2>/dev/null \
  && echo "" \
  || echo "(StatefulSet not found — already cleaned up)"

# 2. Check whether a PVC exists that needs to be preserved / migrated.
echo ""
echo "--- Associated PVCs ---"
kubectl get pvc -n "$NS" -l app=postgresql 2>/dev/null || echo "(no PVCs labelled app=postgresql)"

# 3. Delete the broken StatefulSet (preservePVCs by default — PVCs are NOT deleted).
echo ""
echo "--- Deleting postgresql StatefulSet ---"
run kubectl delete statefulset postgresql -n "$NS" --ignore-not-found=true

# 4. Delete any stuck pods whose ownerReference is gone.
echo ""
echo "--- Cleaning up orphaned postgresql pods ---"
run kubectl delete pod -l app=postgresql -n "$NS" --ignore-not-found=true

echo ""
echo "✅ Done. Langfuse connects via Cloud SQL Auth Proxy sidecars in"
echo "   langfuse-web and langfuse-worker; no in-cluster postgresql is needed."
echo ""
echo "If you intentionally need an in-cluster PostgreSQL, deploy the official"
echo "Bitnami Helm chart and update DATABASE_URL in advisor-secrets accordingly:"
echo "  helm upgrade --install postgresql bitnami/postgresql -n $NS \\"
echo "    --set auth.existingSecret=advisor-secrets \\"
echo "    --set auth.secretKeys.adminPasswordKey=POSTGRES_PASSWORD"
