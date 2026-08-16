# Reconciliation Worker Activation Runbook

**POAM Reference:** POAM-2026-038
**Last Updated:** 2026-08-16
**Status:** Activation Runbook Ready

---

## Overview

The Reconciliation Worker is a Kubernetes CronJob that synchronizes external ledger
balances with the CAGE governance system's Redis cache. It ensures that the
`FiscalLimitGuard` operates on verified, KMS-signed balance data rather than
potentially stale or manipulated in-memory counters.

### Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   GCS Bucket    │───▶│  Reconciliation │───▶│     Redis       │
│ (Ledger Snap)   │    │     Worker      │    │ (Signed Balance)│
└─────────────────┘    └────────┬────────┘    └─────────────────┘
                                │
                                ▼
                       ┌─────────────────┐
                       │   Cloud KMS     │
                       │ (HMAC Signing)  │
                       └─────────────────┘
```

### Components

| Component | Location | Purpose |
|-----------|----------|---------|
| Worker Code | `src/compliance_bridge/reconciliation_worker.py` | GcsLedgerProvider + ExternalLedgerReconciler |
| K8s Manifest | `deployment/k8s/reconciliation-worker.yaml` | CronJob (every 5 min) + CiliumNetworkPolicy |
| Setup Script | `deployment/scripts/setup_reconciliation_secret.sh` | Secret population automation |
| Consumer | `src/gateway/governance/cbf.py` | `read_verified_balance()` |

---

## Prerequisites

### 1. GCS Bucket Setup

Create a GCS bucket to store ledger snapshots:

```bash
# Set variables
PROJECT_ID="your-gcp-project"
BUCKET_NAME="cage-reconciliation-${PROJECT_ID}"
REGION="us-central1"

# Create bucket with uniform bucket-level access
gsutil mb -p "${PROJECT_ID}" -l "${REGION}" -b on "gs://${BUCKET_NAME}"

# Enable versioning for audit trail
gsutil versioning set on "gs://${BUCKET_NAME}"
```

### 2. Ledger Snapshot Format

The worker expects a JSON snapshot at `reconciliation/latest.json`:

```json
{
  "timestamp": "2026-08-16T03:00:00Z",
  "balances": {
    "account_001": 1000000.00,
    "account_002": 500000.00
  },
  "metadata": {
    "source": "anchorage-digital",
    "snapshot_id": "snap-20260816-0300"
  }
}
```

Upload initial snapshot:

```bash
gsutil cp ledger_snapshot.json "gs://${BUCKET_NAME}/reconciliation/latest.json"
```

### 3. Cloud KMS Key Setup

Create a KMS key for HMAC signing:

```bash
# Create key ring (if not exists)
gcloud kms keyrings create governance \
  --location="${REGION}" \
  --project="${PROJECT_ID}"

# Create signing key
gcloud kms keys create balance-signer \
  --location="${REGION}" \
  --keyring=governance \
  --purpose=mac \
  --default-algorithm=hmac-sha256 \
  --project="${PROJECT_ID}"

# Note the full key resource name:
# projects/${PROJECT_ID}/locations/${REGION}/keyRings/governance/cryptoKeys/balance-signer
```

### 4. Service Account Permissions

Grant the financial-advisor-sa service account access:

```bash
SA_EMAIL="financial-advisor-sa@${PROJECT_ID}.iam.gserviceaccount.com"

# GCS read access
gsutil iam ch "serviceAccount:${SA_EMAIL}:roles/storage.objectViewer" "gs://${BUCKET_NAME}"

# KMS signing access
gcloud kms keys add-iam-policy-binding balance-signer \
  --location="${REGION}" \
  --keyring=governance \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/cloudkms.signerVerifier" \
  --project="${PROJECT_ID}"
```

---

## Activation Steps

### Step 1: Verify Prerequisites

```bash
# Check cluster access
kubectl config current-context

# Verify namespace exists
kubectl get namespace governance-stack

# Verify service account exists
kubectl get serviceaccount financial-advisor-sa -n governance-stack
```

### Step 2: Populate Secrets

Use the setup script:

```bash
export GCS_BUCKET="cage-reconciliation-${PROJECT_ID}"
export KMS_KEY="projects/${PROJECT_ID}/locations/${REGION}/keyRings/governance/cryptoKeys/balance-signer"

./deployment/scripts/setup_reconciliation_secret.sh
```

Or manually:

```bash
kubectl create secret generic reconciliation-worker-secrets \
  --namespace=governance-stack \
  --from-literal=gcs-reconciliation-bucket="${GCS_BUCKET}" \
  --from-literal=gcs-reconciliation-object="reconciliation/latest.json" \
  --from-literal=kms-governance-key="${KMS_KEY}" \
  --dry-run=client -o yaml | kubectl apply -f -
```

### Step 3: Deploy CronJob (if not already deployed)

```bash
kubectl apply -f deployment/k8s/reconciliation-worker.yaml
```

### Step 4: Trigger Manual Test Run

```bash
# Create a one-off job from the CronJob
kubectl create job --from=cronjob/reconciliation-worker test-reconciliation-$(date +%s) -n governance-stack

# Watch the job
kubectl get jobs -n governance-stack -w

# Check logs
kubectl logs -l app=reconciliation-worker -n governance-stack --tail=100
```

### Step 5: Verify Redis State

```bash
# Port-forward to Redis
kubectl port-forward svc/redis-master 6379:6379 -n governance-stack &

# Check for signed balance
redis-cli GET safety:verified_balance

# Expected output: JSON with signature field
# {"balance": 1500000.00, "timestamp": "2026-08-16T03:05:00Z", "signature": "...", "ttl": 300}
```

---

## Verification Checklist

| Check | Command | Expected |
|-------|---------|----------|
| CronJob exists | `kubectl get cronjob reconciliation-worker -n governance-stack` | SCHEDULE: */5 * * * * |
| Secret populated | `kubectl get secret reconciliation-worker-secrets -n governance-stack -o jsonpath='{.data}'` | 3 keys present |
| Job succeeds | `kubectl get jobs -n governance-stack -l app=reconciliation-worker` | COMPLETIONS: 1/1 |
| Redis has balance | `redis-cli GET safety:verified_balance` | JSON with signature |
| CBF reads verified | Check gateway logs for "verified_balance" | No "fallback" warnings |

---

## Troubleshooting

### Job Fails with CreateContainerConfigError

**Cause:** Secret keys missing

```bash
# Check which keys are present
kubectl get secret reconciliation-worker-secrets -n governance-stack -o jsonpath='{.data}' | jq 'keys'

# Re-run setup script with all required vars
GCS_BUCKET=... KMS_KEY=... ./deployment/scripts/setup_reconciliation_secret.sh
```

### Job Fails with Permission Denied

**Cause:** Service account lacks IAM bindings

```bash
# Verify GCS access
gcloud storage buckets get-iam-policy "gs://${GCS_BUCKET}" --format=json | jq '.bindings'

# Verify KMS access
gcloud kms keys get-iam-policy balance-signer \
  --location="${REGION}" \
  --keyring=governance \
  --project="${PROJECT_ID}"
```

### Redis Key Expires Before Next Reconciliation

**Cause:** TTL (300s) shorter than CronJob interval (300s) + job duration

**Fix:** Reduce CronJob interval or increase TTL:

```bash
# Option 1: Run more frequently (every 3 minutes)
kubectl patch cronjob reconciliation-worker -n governance-stack \
  -p '{"spec":{"schedule":"*/3 * * * *"}}'

# Option 2: Increase TTL (env var)
kubectl set env cronjob/reconciliation-worker -n governance-stack RECONCILIATION_TTL_S=600
```

### FiscalLimitGuard Falls Back to Unverified Counters

**Cause:** `safety:verified_balance` key missing or expired

```bash
# Check key TTL
redis-cli TTL safety:verified_balance

# If -2 (key doesn't exist) or < 60 (about to expire), trigger manual reconciliation
kubectl create job --from=cronjob/reconciliation-worker emergency-reconciliation -n governance-stack
```

---

## POAM Closure Criteria

POAM-2026-038 can be closed when:

1. ✅ `GcsLedgerProvider` implemented (POAM-2026-042 closed 2026-08-06)
2. ✅ CronJob manifest exists (`deployment/k8s/reconciliation-worker.yaml`)
3. ✅ Setup script includes KMS key population
4. ⬜ Secret populated on live cluster (requires deployment)
5. ⬜ At least one successful reconciliation job logged
6. ⬜ Gateway logs show `verified_balance` reads (no fallback warnings)
7. ⬜ docs/POAM.md updated with closure date and commit SHA

---

## Related Documents

- [POAM Tracking](../POAM.md) — POAM-2026-038 entry
- [Reconciliation Worker Manifest](../../deployment/k8s/reconciliation-worker.yaml)
- [CBF Implementation](../../src/gateway/governance/cbf.py) — `read_verified_balance()`
- [CAGE_IMPLEMENTATION_PLAN.md](../../plans/CAGE_IMPLEMENTATION_PLAN.md) — Phase 0 milestone
