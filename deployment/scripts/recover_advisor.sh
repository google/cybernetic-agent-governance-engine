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

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
NAMESPACE="${NAMESPACE:-cage}"

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --namespace)
      NAMESPACE="$2"
      shift 2
      ;;
    -h|--help)
      sed -n '/^# Usage:/,/^[^#]/p' "$0" | head -n -1
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
header() {
  echo ""
  echo "======================================================================"
  echo "  $*"
  echo "======================================================================"
}

ok()   { echo "  [OK]  $*"; }
info() { echo "  [-->] $*"; }
warn() { echo "  [!!]  $*"; }

# ---------------------------------------------------------------------------
# Step 1: Show pod status
# ---------------------------------------------------------------------------
header "Step 1 — governed-financial-advisor pod status (namespace: $NAMESPACE)"
kubectl get pods -n "$NAMESPACE" -l app=governed-financial-advisor

# ---------------------------------------------------------------------------
# Step 2: Optionally roll back
# ---------------------------------------------------------------------------
echo ""
read -r -p "Is the advisor in CrashLoopBackOff? (y/N): " ANSWER
case "$ANSWER" in
  [yY]|[yY][eE][sS])
    header "Step 2 — Rolling back deployment"
    kubectl rollout undo deployment/governed-financial-advisor -n "$NAMESPACE"
    ok "Rollback command issued."

    header "Step 3 — Waiting for rollout to complete (timeout: 120 s)"
    if kubectl rollout status deployment/governed-financial-advisor \
         -n "$NAMESPACE" --timeout=120s; then
      ok "Rollout completed successfully."
    else
      warn "Rollout did not complete within 120 s. Check pod events:"
      kubectl describe pods -n "$NAMESPACE" -l app=governed-financial-advisor | \
        grep -A 10 "Events:" || true
      exit 1
    fi
    ;;
  *)
    info "Skipping rollback."
    ;;
esac

# ---------------------------------------------------------------------------
# Step 4: Show updated pod status
# ---------------------------------------------------------------------------
header "Step 4 — Current pod status after action"
kubectl get pods -n "$NAMESPACE" -l app=governed-financial-advisor

# ---------------------------------------------------------------------------
# Step 5: Verify environment variables
# ---------------------------------------------------------------------------
header "Step 5 — Environment variables in governed-financial-advisor"
if kubectl exec -n "$NAMESPACE" deploy/governed-financial-advisor -- env | sort; then
  ok "Env vars printed above."
else
  warn "Could not exec into deployment — pod may still be starting."
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
header "Recovery complete"
echo ""
echo "  Next steps:"
echo "    • Monitor pods:        make advisor-watch"
echo "    • Port-forward (8080): make advisor-port-forward   (separate terminal)"
echo "    • Health check:        make advisor-health"
echo "    • Run local tests:     make test-integration"
echo ""
