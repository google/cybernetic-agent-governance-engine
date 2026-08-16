# Reconciliation Worker Activation Checklist (POAM-2026-038)

**Document:** Operator Runbook for Reconciliation Worker Activation
**POAM Reference:** POAM-2026-038 (Reopened 2026-08-09)
**Target Closure:** 2026-08-16
**Last Updated:** 2026-08-15

---

## Overview

The `reconciliation-worker` CronJob runs every 5 minutes in the `governance-stack`
namespace. It reads balance snapshots from a GCS bucket (WORM ledger) and writes
KMS-signed balance records to Redis. The `FiscalLimitGuard` in the gateway reads
these signed balances via `read_verified_balance()` to enforce accurate fiscal limits.

**Root Cause (POAM-2026-038):**
1. ✅ FIXED: `RECONCILIATION_PROVIDER` was set to `"s3"` — now corrected to `"gcs"`
2. ⚠️ OUTSTANDING: `gcs-reconciliation-bucket` secret key never populated post-deploy

---

## Prerequisites

Before running this checklist, ensure:

- [ ] `kubectl` is authenticated to the target GKE cluster (`governance-cluster-2`)
- [ ] You have `secretKeyRef` permissions in the `governance-stack` namespace
- [ ] A GCS bucket exists with the ledger snapshot (see [Ledger Bucket Setup](#ledger-bucket-setup))
- [ ] A Cloud KMS key exists for balance signing (see [KMS Key Setup](#kms-key-setup))

---

## Phase 1: Verify Current Secret State

### 1.1 Check if `reconciliation-worker-secrets` exists

```bash
kubectl get secret reconciliation-worker-secrets \
  -n governance-stack \
  -o jsonpath='{.metadata.name}' 2>/dev/null \
  && echo " ✓ Secret exists" \
  || echo " ✗ Secret does not exist"
```

### 1.2 List existing keys in the secret (if it exists)

```bash
kubectl get secret reconciliation-worker-secrets \
  -n governance-stack \
  -o jsonpath='{.data}' 2>/dev/null | jq -r 'keys[]'
```

Expected keys for `RECONCILIATION_PROVIDER=gcs`:
- `gcs-reconciliation-bucket` (REQUIRED)
- `gcs-reconciliation-object` (OPTIONAL, defaults to `reconciliation/latest.json`)
- `kms-governance-key` (REQUIRED)

### 1.3 Verify the `gcs-reconciliation-bucket` key is populated

```bash
kubectl get secret reconciliation-worker-secrets \
  -n governance-stack \
  -o jsonpath='{.data.gcs-reconciliation-bucket}' | base64 -d
```

If this returns empty or the command fails, the key is not populated — proceed to Phase 2.

### 1.4 Verify `redis-credentials` secret exists

The reconciliation worker also requires the `redis-credentials` secret (shared with other components):

```bash
kubectl get secret redis-credentials \
  -n governance-stack \
  -o jsonpath='{.data.REDIS_URL}' 2>/dev/null | base64 -d && echo " ✓ REDIS_URL set"
kubectl get secret redis-credentials \
  -n governance-stack \
  -o jsonpath='{.data.REDIS_PASSWORD}' 2>/dev/null | base64 -d && echo " ✓ REDIS_PASSWORD set"
```

### 1.5 Verify `RECONCILIATION_PROVIDER` is set to `gcs` in the CronJob

```bash
kubectl get cronjob reconciliation-worker \
  -n governance-stack \
  -o jsonpath='{.spec.jobTemplate.spec.template.spec.containers[0].env[?(@.name=="RECONCILIATION_PROVIDER")].value}'
```

Expected output: `gcs`

---

## Phase 2: Populate Missing Secrets

### 2.1 Required Values

| Key | Source | Example |
|-----|--------|---------|
| `gcs-reconciliation-bucket` | Your GCS bucket name | `cage-ledger-prod-us-central1` |
| `gcs-reconciliation-object` | Object path (optional) | `reconciliation/latest.json` |
| `kms-governance-key` | Cloud KMS key resource name | `projects/my-project/locations/us-central1/keyRings/cage-governance/cryptoKeys/balance-signer` |

### 2.2 Create or Update the Secret (GCS Provider)

**DO NOT commit real values. Execute these commands interactively.**

Using the helper script ([`deployment/scripts/setup_reconciliation_secret.sh`](../../deployment/scripts/setup_reconciliation_secret.sh)):

```bash
# Set your actual bucket name
export GCS_BUCKET="<YOUR_GCS_BUCKET_NAME>"

# Run the setup script (creates or updates the secret)
./deployment/scripts/setup_reconciliation_secret.sh
```

Or manually with `kubectl`:

```bash
# Create the secret with all required keys
kubectl create secret generic reconciliation-worker-secrets \
  --namespace=governance-stack \
  --from-literal=gcs-reconciliation-bucket="<YOUR_GCS_BUCKET_NAME>" \
  --from-literal=gcs-reconciliation-object="reconciliation/latest.json" \
  --from-literal=kms-governance-key="projects/<PROJECT>/locations/<REGION>/keyRings/<RING>/cryptoKeys/<KEY>" \
  --dry-run=client -o yaml | kubectl apply -f -
```

### 2.3 Verify Secret Population

```bash
# Confirm all required keys are present
kubectl get secret reconciliation-worker-secrets \
  -n governance-stack \
  -o jsonpath='{.data}' | jq -r 'keys[]'

# Expected output:
# gcs-reconciliation-bucket
# gcs-reconciliation-object
# kms-governance-key
```

---

## Phase 3: Verify CronJob Execution

### 3.1 Trigger an Immediate Run (Optional)

The CronJob runs every 5 minutes. To trigger an immediate run for testing:

```bash
kubectl create job --from=cronjob/reconciliation-worker \
  -n governance-stack \
  reconciliation-worker-manual-$(date +%s)
```

### 3.2 Check Job Status

```bash
# List recent jobs from the CronJob
kubectl get jobs -n governance-stack -l app=reconciliation-worker --sort-by=.metadata.creationTimestamp

# Check the most recent job's status
kubectl get jobs -n governance-stack -l app=reconciliation-worker -o jsonpath='{.items[-1].status.conditions[0].type}'
```

Expected: `Complete`

### 3.3 Check Pod Logs for Errors

```bash
# Get the most recent pod from the CronJob
POD=$(kubectl get pods -n governance-stack -l app=reconciliation-worker \
  --sort-by=.metadata.creationTimestamp -o jsonpath='{.items[-1].metadata.name}')

# View logs
kubectl logs -n governance-stack "$POD"
```

**Success indicators in logs:**
- `Reconciliation cycle complete`
- `Signed balance written to Redis`
- No `CreateContainerConfigError` or `ValueError: GcsLedgerProvider requires GCS_RECONCILIATION_BUCKET`

**Failure indicators:**
- `CreateContainerConfigError` — secret key not found
- `ValueError: Unknown reconciliation provider` — provider misconfiguration
- `google.api_core.exceptions.NotFound` — bucket or object does not exist
- `google.api_core.exceptions.Forbidden` — Workload Identity or IAM permissions issue

### 3.4 Verify ≥3 Consecutive Successful Runs

Wait 15-20 minutes after secret population, then verify:

```bash
# Count successful jobs in the last 30 minutes
kubectl get jobs -n governance-stack -l app=reconciliation-worker \
  -o jsonpath='{range .items[*]}{.status.conditions[0].type}{"\n"}{end}' | grep -c Complete
```

Expected: `≥3`

Alternatively, check the CronJob status:

```bash
kubectl get cronjob reconciliation-worker -n governance-stack \
  -o jsonpath='{.status.lastSuccessfulTime}'
```

### 3.5 Verify Signed Balance in Redis

```bash
# Port-forward to Redis (if not already forwarded)
kubectl port-forward -n governance-stack svc/redis-master 6379:6379 &

# Check for the signed balance key
redis-cli GET "reconciliation:balance:latest"
```

Expected: A JSON payload with `balance`, `currency`, `provider`, `fetched_at`, `kms_signature`, `account_id`.

---

## Phase 4: Post-Activation Verification

### 4.1 Verify FiscalLimitGuard Uses Reconciled Balances

After the reconciliation worker writes a signed balance to Redis, the gateway's
`FiscalLimitGuard` should read it via [`read_verified_balance()`](../../src/compliance_bridge/reconciliation_worker.py).

Check gateway logs for:
- `Using reconciled balance from Redis` (success)
- `Falling back to un-reconciled counters` (failure — indicates stale or missing signed balance)

### 4.2 POAM Closure Criteria

Before closing POAM-2026-038, confirm:

- [ ] `reconciliation-worker-secrets` contains `gcs-reconciliation-bucket` and `kms-governance-key`
- [ ] CronJob `reconciliation-worker` has ≥3 consecutive successful runs
- [ ] Pod logs show no `CreateContainerConfigError` or `ValueError`
- [ ] Redis contains a valid signed balance at `reconciliation:balance:latest`
- [ ] Gateway logs confirm `Using reconciled balance from Redis`

---

## Appendix A: Ledger Bucket Setup

The GCS bucket must contain a WORM (Write-Once-Read-Many) ledger snapshot in the format:

```json
{
  "balance": 50000.00,
  "currency": "USD",
  "provider": "gcs",
  "fetched_at": "2026-08-15T12:00:00+00:00",
  "kms_signature": "<base64-encoded-signature>",
  "account_id": "primary-operating"
}
```

**Bucket configuration recommendations:**
- Enable Object Versioning
- Enable Retention Policy (regulatory compliance)
- Configure IAM: Grant `roles/storage.objectViewer` to the `financial-advisor-sa` Workload Identity

---

## Appendix B: KMS Key Setup

The Cloud KMS key is used to sign balance records before writing to Redis.

**Key creation (if not already created):**

```bash
# Create keyring (once per region)
gcloud kms keyrings create cage-governance \
  --location=us-central1 \
  --project=<PROJECT_ID>

# Create signing key
gcloud kms keys create balance-signer \
  --location=us-central1 \
  --keyring=cage-governance \
  --purpose=mac \
  --default-algorithm=hmac-sha256 \
  --project=<PROJECT_ID>
```

**Grant access to the ServiceAccount:**

```bash
gcloud kms keys add-iam-policy-binding balance-signer \
  --location=us-central1 \
  --keyring=cage-governance \
  --member="serviceAccount:<PROJECT_ID>.svc.id.goog[governance-stack/financial-advisor-sa]" \
  --role=roles/cloudkms.signerVerifier \
  --project=<PROJECT_ID>
```

---

## Appendix C: Expected Secret Structure

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: reconciliation-worker-secrets
  namespace: governance-stack
  labels:
    app: reconciliation-worker
    cage.io/account-purpose: "ledger-reconciliation"
type: Opaque
stringData:
  # Required for RECONCILIATION_PROVIDER=gcs
  gcs-reconciliation-bucket: "cage-ledger-prod-us-central1"
  gcs-reconciliation-object: "reconciliation/latest.json"
  # Required for KMS signing
  kms-governance-key: "projects/<PROJECT>/locations/<REGION>/keyRings/<RING>/cryptoKeys/<KEY>"
```

**NEVER commit this file with real values.**

---

## Appendix D: Troubleshooting

| Symptom | Cause | Resolution |
|---------|-------|------------|
| `CreateContainerConfigError` | Secret key missing | Populate secret per Phase 2 |
| `ValueError: GcsLedgerProvider requires GCS_RECONCILIATION_BUCKET` | Empty bucket value | Verify secret contains non-empty value |
| `google.api_core.exceptions.NotFound` | Bucket/object does not exist | Create bucket and upload ledger snapshot |
| `google.api_core.exceptions.Forbidden` | IAM permissions | Grant `objectViewer` to ServiceAccount |
| `ConnectionRefusedError` (Redis) | Redis not running | Check `redis-stack` StatefulSet |
| `kms_signer: signature verification failed` | KMS key mismatch | Ensure same key for sign and verify |

---

## References

- [`deployment/k8s/reconciliation-worker.yaml`](../../deployment/k8s/reconciliation-worker.yaml) — CronJob manifest
- [`deployment/scripts/setup_reconciliation_secret.sh`](../../deployment/scripts/setup_reconciliation_secret.sh) — Secret setup helper
- [`src/compliance_bridge/reconciliation_worker.py`](../../src/compliance_bridge/reconciliation_worker.py) — Worker implementation
- [`docs/POAM.md`](../POAM.md) — Security posture tracking (POAM-2026-038)
