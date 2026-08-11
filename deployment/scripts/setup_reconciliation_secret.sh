#!/usr/bin/env bash
# setup_reconciliation_secret.sh — Populate reconciliation-worker-secrets
# Run this once after deploying the reconciliation-worker CronJob manifest.
# Never commit real values — this script is a runbook, not an automation.
#
# Usage:
#   GCS_BUCKET=<your-gcs-bucket-name> ./deployment/scripts/setup_reconciliation_secret.sh
#
set -euo pipefail

NAMESPACE="${NAMESPACE:-governance-stack}"
SECRET_NAME="reconciliation-worker-secrets"
GCS_BUCKET="${GCS_BUCKET:?GCS_BUCKET env var is required}"

kubectl create secret generic "${SECRET_NAME}" \
  --namespace="${NAMESPACE}" \
  --from-literal=gcs-reconciliation-bucket="${GCS_BUCKET}" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "Secret ${SECRET_NAME} updated in namespace ${NAMESPACE}."
echo "Verify: kubectl get secret ${SECRET_NAME} -n ${NAMESPACE} -o jsonpath='{.data}' | base64 -d"
