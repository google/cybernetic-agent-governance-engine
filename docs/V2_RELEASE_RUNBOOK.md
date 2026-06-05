# v2.0.0 Release Runbook — Phases 2–6

> **Prerequisites:** Phase 1 PR (`fix/v2-p0-blockers`) must be merged into `rc-v2.0.0` before starting Phase 2.
> **Cluster:** `gke_laah-cybernetics_us-central1-a_cage-dev`, namespace `governance-stack`
> **Project:** `laah-cybernetics`

---

## Phase 2 — Credential Rotation

> **CRITICAL:** Rotate ALL credentials BEFORE the git history rewrite (Phase 3). Rewriting history does not revoke live credentials.

### 2.1 — Rotate Redis Password

```bash
# Generate new password (≥64 chars)
NEW_REDIS_PW=$(openssl rand -hex 32)
echo "New Redis password: $NEW_REDIS_PW"

# Update Kubernetes secret
kubectl patch secret redis-secret -n governance-stack \
  --type='json' \
  -p="[{\"op\":\"replace\",\"path\":\"/data/redis-password\",\"value\":\"$(echo -n $NEW_REDIS_PW | base64)\"}]"

# Restart Redis to pick up new password
kubectl rollout restart statefulset/redis -n governance-stack
kubectl rollout status statefulset/redis -n governance-stack --timeout=120s

# Update terraform.auto.tfvars (NEVER commit this file)
# Add/update: redis_password = "<NEW_REDIS_PW>"
```

**Verification:** `kubectl exec -n governance-stack statefulset/redis -- redis-cli -a "$NEW_REDIS_PW" PING` → `PONG`

---

### 2.2 — Rotate PostgreSQL Password

```bash
# Generate new password (≥64 chars)
NEW_PG_PW=$(openssl rand -hex 32)
echo "New PostgreSQL password: $NEW_PG_PW"

# Update password in PostgreSQL
kubectl exec -n governance-stack deploy/postgres -- \
  psql -U postgres -c "ALTER USER postgres PASSWORD '$NEW_PG_PW';"

# Update Kubernetes secret
kubectl patch secret pg-secret -n governance-stack \
  --type='json' \
  -p="[{\"op\":\"replace\",\"path\":\"/data/postgres-password\",\"value\":\"$(echo -n $NEW_PG_PW | base64)\"}]"

# Update DATABASE_URL in advisor-secrets
OLD_DB_URL=$(kubectl get secret advisor-secrets -n governance-stack -o jsonpath='{.data.DATABASE_URL}' | base64 -d)
NEW_DB_URL=$(echo "$OLD_DB_URL" | sed "s|:[^:@]*@|:${NEW_PG_PW}@|")
kubectl patch secret advisor-secrets -n governance-stack \
  --type='json' \
  -p="[{\"op\":\"replace\",\"path\":\"/data/DATABASE_URL\",\"value\":\"$(echo -n $NEW_DB_URL | base64)\"}]"

# Update terraform.auto.tfvars (NEVER commit this file)
# Add/update: postgres_password = "<NEW_PG_PW>"
```

**Verification:** `kubectl exec -n governance-stack deploy/postgres -- psql -U postgres -c "SELECT 1;"` → `1`

---

### 2.3 — Rotate Langfuse Keys

1. Log in to the Langfuse UI (check `deployment/langfuse/README.md` for URL)
2. Navigate to **Settings → API Keys**
3. Delete all existing `pk-lf-*` and `sk-lf-*` keys
4. Create a new key pair; copy both values immediately

```bash
NEW_LF_PUBLIC="pk-lf-<paste-here>"
NEW_LF_SECRET="sk-lf-<paste-here>"

kubectl patch secret advisor-secrets -n governance-stack \
  --type='json' \
  -p="[
    {\"op\":\"replace\",\"path\":\"/data/LANGFUSE_PUBLIC_KEY\",\"value\":\"$(echo -n $NEW_LF_PUBLIC | base64)\"},
    {\"op\":\"replace\",\"path\":\"/data/LANGFUSE_SECRET_KEY\",\"value\":\"$(echo -n $NEW_LF_SECRET | base64)\"}
  ]"

# Update terraform.auto.tfvars (NEVER commit this file)
# Add/update: langfuse_public_key = "<NEW_LF_PUBLIC>"
# Add/update: langfuse_secret_key = "<NEW_LF_SECRET>"
```

**Verification:** `curl -u "$NEW_LF_PUBLIC:$NEW_LF_SECRET" https://<langfuse-host>/api/public/health` → `{"status":"OK"}`
**Verify old keys revoked:** Same curl with old keys → HTTP 401

---

### 2.4 — Rotate GCS HMAC Key

1. Go to GCP Console → Cloud Storage → Settings → Interoperability
2. Find the existing HMAC key; click **Delete**
3. Click **Create a key for a service account**; select the appropriate service account
4. Copy the Access ID and Secret

```bash
NEW_GCS_ACCESS_ID="<paste-here>"
NEW_GCS_SECRET="<paste-here>"

kubectl patch secret oscal-artifact-secrets -n governance-stack \
  --type='json' \
  -p="[
    {\"op\":\"replace\",\"path\":\"/data/GCS_HMAC_ACCESS_ID\",\"value\":\"$(echo -n $NEW_GCS_ACCESS_ID | base64)\"},
    {\"op\":\"replace\",\"path\":\"/data/GCS_HMAC_SECRET\",\"value\":\"$(echo -n $NEW_GCS_SECRET | base64)\"}
  ]"

kubectl patch secret gcs-credentials-secret -n governance-stack \
  --type='json' \
  -p="[
    {\"op\":\"replace\",\"path\":\"/data/GCS_HMAC_ACCESS_ID\",\"value\":\"$(echo -n $NEW_GCS_ACCESS_ID | base64)\"},
    {\"op\":\"replace\",\"path\":\"/data/GCS_HMAC_SECRET\",\"value\":\"$(echo -n $NEW_GCS_SECRET | base64)\"}
  ]"
```

---

### 2.5 — Rotate HuggingFace Token

1. Go to https://huggingface.co/settings/tokens
2. Find the existing token; click **Revoke**
3. Click **New token**; select **Read** scope; copy the value

```bash
NEW_HF_TOKEN="hf_<paste-here>"

kubectl patch secret hf-token-secret -n governance-stack \
  --type='json' \
  -p="[{\"op\":\"replace\",\"path\":\"/data/token\",\"value\":\"$(echo -n $NEW_HF_TOKEN | base64)\"}]"

# Update terraform.auto.tfvars (NEVER commit this file)
# Add/update: hf_token = "<NEW_HF_TOKEN>"
```

---

### 2.6 — Generate New Seal Secrets

```bash
# Generate both new secrets (≥64 chars each)
NEW_SEAL_SECRET=$(openssl rand -hex 32)
NEW_GOVERNANCE_SALT=$(openssl rand -hex 32)

echo "CAGE_ROUTING_SEAL_SECRET=$NEW_SEAL_SECRET"
echo "GOVERNANCE_SALT=$NEW_GOVERNANCE_SALT"

# Add to terraform.auto.tfvars (NEVER commit this file):
# routing_seal_secret = "<NEW_SEAL_SECRET>"
# governance_salt     = "<NEW_GOVERNANCE_SALT>"
# These will be applied to the cluster in Phase 4 via Terraform.
```

---

### 2.7 — Verify All Rotated Secrets

```bash
# Check all secrets have values ≥64 chars
for SECRET_NAME in redis-secret pg-secret advisor-secrets hf-token-secret; do
  echo "=== $SECRET_NAME ==="
  kubectl get secret $SECRET_NAME -n governance-stack -o json | \
    jq -r '.data | to_entries[] | "\(.key): \(.value | @base64d | length) chars"'
done
```

**Expected:** All credential values ≥64 characters.

---

## Phase 3 — Git History Rewrite

> **RISK: HIGH** — This permanently rewrites all branch history. All collaborators must re-clone after this step.
> **Requires:** Repo admin access to temporarily suspend branch protection.

### 3.1 — Install git-filter-repo

```bash
pip install git-filter-repo
git filter-repo --version  # Verify installation
```

### 3.2 — Backup Repository

```bash
cd /Users/larsahlfors/Code
cp -r cybernetic-governance-engine cybernetic-governance-engine.backup-$(date +%Y%m%d-%H%M%S)
echo "Backup created at: cybernetic-governance-engine.backup-$(date +%Y%m%d-%H%M%S)"
```

### 3.3 — Prepare Expressions File

Create `/tmp/filter-repo-expressions.txt` (NEVER commit this file):

```
# Redis/PostgreSQL connection strings
regex:redis://:?[A-Za-z0-9+/=_\-]{8,}@==>redis://REDACTED@
regex:postgresql://[^:]+:[A-Za-z0-9+/=_\-]{8,}@==>postgresql://REDACTED:REDACTED@

# Langfuse keys
regex:pk-lf-[A-Za-z0-9\-_]{20,}==>pk-lf-REDACTED
regex:sk-lf-[A-Za-z0-9\-_]{20,}==>sk-lf-REDACTED

# GCS HMAC keys
regex:GOOG[A-Za-z0-9+/=_\-]{20,}==>GOOG-REDACTED

# HuggingFace tokens
regex:hf_[A-Za-z0-9]{20,}==>hf_REDACTED

# Known literal secrets
literal:REDACTED_SALT==>REDACTED_SALT
literal:REDACTED_PASSWORD==>REDACTED_PASSWORD
```

### 3.4 — Dry Run on Fresh Clone

```bash
cd /tmp
git clone /Users/larsahlfors/Code/cybernetic-governance-engine cage-filter-test
cd cage-filter-test
git filter-repo --replace-text /tmp/filter-repo-expressions.txt --dry-run 2>&1 | head -100
# Review output for unexpected replacements before proceeding
cd /tmp && rm -rf cage-filter-test
```

### 3.5 — Suspend Branch Protection (Repo Admin)

1. Go to GitHub → Repository Settings → Branches
2. Edit the `rc-v2.0.0` branch protection rule
3. Temporarily disable: "Require pull request before merging", "Require status checks", "Restrict who can push"
4. Also disable protection on `main`
5. **Record the timestamp of suspension**

### 3.6 — Run History Rewrite

```bash
cd /Users/larsahlfors/Code/cybernetic-governance-engine
git filter-repo --replace-text /tmp/filter-repo-expressions.txt --force
```

### 3.7 — Verify Rewrite Locally

```bash
# Check all patterns return zero matches
for PATTERN in "REDACTED_SALT" "REDACTED_PASSWORD" "pk-lf-" "sk-lf-" "hf_"; do
  COUNT=$(git log --all -S "$PATTERN" --oneline | wc -l)
  echo "$PATTERN: $COUNT matches (expected 0)"
done
```

### 3.8 — Force-Push Rewritten History

```bash
git remote add origin https://github.com/laah-cybernetics/cybernetic-governance-engine.git
# Or if remote already exists:
# git remote set-url origin https://github.com/laah-cybernetics/cybernetic-governance-engine.git

git push --force-with-lease origin rc-v2.0.0
git push --force-with-lease origin main
```

### 3.9 — Re-Enable Branch Protection

1. Return to GitHub → Repository Settings → Branches
2. Restore all branch protection settings on `rc-v2.0.0` and `main`
3. **Complete within 15 minutes of suspension**
4. Record timestamp of restoration

### 3.10 — Post-Rewrite Verification

```bash
# Fresh clone from remote
cd /tmp
git clone https://github.com/laah-cybernetics/cybernetic-governance-engine.git cage-verify
cd cage-verify

# Re-run all checks
for PATTERN in "REDACTED_SALT" "REDACTED_PASSWORD" "pk-lf-" "sk-lf-" "hf_"; do
  COUNT=$(git log --all -S "$PATTERN" --oneline | wc -l)
  echo "$PATTERN: $COUNT matches (expected 0)"
done

# Run tests
uv run pytest tests/ -x --timeout=60 -q
cd /tmp && rm -rf cage-verify
```

### 3.11 — Reset Local Clone

```bash
cd /Users/larsahlfors/Code/cybernetic-governance-engine
git fetch origin
git reset --hard origin/rc-v2.0.0
```

---

## Phase 4 — Terraform Apply + GKE Deployment

> **Rule:** All GKE image deployments via Cloud Build. `kubectl apply` permitted only for non-image resources (CronJobs, PSA labels, etc.).

### 4.1 — Pre-Apply Checks

```bash
# Verify GCP auth
gcloud auth application-default login
gcloud config set project laah-cybernetics
gcloud config get-value project  # Should print: laah-cybernetics

# Verify kubectl context
kubectl config use-context gke_laah-cybernetics_us-central1-a_cage-dev
kubectl config current-context  # Should print: gke_laah-cybernetics_us-central1-a_cage-dev

# Verify Terraform
cd infra/targets/gcp-gke
terraform version  # Should be ≥1.5.0
terraform init
terraform validate
```

### 4.2 — Terraform Plan

```bash
cd infra/targets/gcp-gke
terraform plan -out=v2-release.tfplan

# Review the plan output:
# Expected additions (+): advisor_secrets keys (CAGE_ROUTING_SEAL_SECRET, GOVERNANCE_SALT)
# Expected modifications (~): gateway deployment (GOVERNANCE_SALT env var), namespace labels
# STOP if you see unexpected deletions of existing resources
```

### 4.3 — Terraform Apply

```bash
cd infra/targets/gcp-gke
terraform apply v2-release.tfplan

# Verify seal secrets were created
kubectl get secret advisor-secrets -n governance-stack -o json | \
  jq -r '.data | to_entries[] | select(.key | test("SEAL|SALT")) | "\(.key): \(.value | @base64d | length) chars"'
# Expected: both values ≥64 chars
```

### 4.4 — Cloud Build Trigger — Advisor Pod Restart

```bash
# Option A: Use deploy_all.sh
./deploy_all.sh --target gcp-gke --env prod

# Option B: Direct Cloud Build submit
gcloud builds submit --config deployment/docker/cloudbuild.advisor.yaml \
  --project laah-cybernetics
```

### 4.5 — Validate D-02 Resolution

```bash
# Check rollout status
kubectl rollout status deployment/governed-financial-advisor -n governance-stack --timeout=300s

# Verify pod is healthy
kubectl get pods -n governance-stack -l app=governed-financial-advisor
# Expected: READY 1/1, STATUS Running

# Verify single container (no slm-sidecar)
kubectl get pod -n governance-stack -l app=governed-financial-advisor \
  -o jsonpath='{.items[0].spec.containers[*].name}'
# Expected: only "advisor" (not "slm-sidecar")

# Verify seal env vars present
kubectl exec -n governance-stack deploy/governed-financial-advisor -- \
  env | grep -E "CAGE_ROUTING_SEAL_SECRET|GOVERNANCE_SALT"
# Expected: both vars present with ≥64-char values
```

### 4.6 — Apply PSA Labels to langfuse + vllm Namespaces

```bash
kubectl apply -f deployment/k8s/pod-security-admission.yaml

# Verify labels on all 3 namespaces
for NS in governance-stack langfuse vllm; do
  echo "=== $NS ==="
  kubectl get namespace $NS -o jsonpath='{.metadata.labels}' | jq .
done

# Check for FailedCreate events
kubectl get events -n governance-stack --field-selector reason=FailedCreate
kubectl get events -n langfuse --field-selector reason=FailedCreate
kubectl get events -n vllm --field-selector reason=FailedCreate
# Expected: no FailedCreate events
```

### 4.7 — Deploy Security-Scan CronJob

```bash
kubectl apply -f deployment/k8s/security-scan-cronjob.yaml

# Trigger a manual test run
kubectl create job --from=cronjob/security-scanner-cronjob security-scan-test -n governance-stack

# Wait for completion
kubectl wait --for=condition=complete job/security-scan-test -n governance-stack --timeout=300s

# Check logs for Trivy JSON output
kubectl logs -n governance-stack job/security-scan-test

# Clean up test job
kubectl delete job security-scan-test -n governance-stack
```

### 4.8 — Phase 4 Health Check

```bash
# All pods Running/Ready
kubectl get pods -n governance-stack

# All 5 target secrets present
for SECRET in redis-secret pg-secret advisor-secrets hf-token-secret oscal-artifact-secrets; do
  kubectl get secret $SECRET -n governance-stack -o name && echo "✓ $SECRET" || echo "✗ MISSING: $SECRET"
done

# All 3 CronJobs present
kubectl get cronjobs -n governance-stack
# Expected: cage-lula-audit, cage-sbom-generator, security-scanner-cronjob
```

---

## Phase 5 — Seal Enforcement Verification

### 5.1 — Verify Gateway Has GOVERNANCE_SALT

```bash
kubectl exec deploy/cage-gateway -n governance-stack -- env | grep GOVERNANCE_SALT
# Expected: GOVERNANCE_SALT=<≥64-char hex string>
```

### 5.2 — Verify Seal Enforcement Mode

```bash
kubectl exec deploy/cage-gateway -n governance-stack -- env | grep CAGE_SEAL_ENFORCEMENT
# Expected: "enforce" or absent — NOT "log"
```

### 5.3 — Unsigned Request Returns 403

```bash
# Port-forward gateway
kubectl port-forward -n governance-stack deploy/cage-gateway 8080:8080 &
PF_PID=$!
sleep 2

# Send unsigned request
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST http://localhost:8080/v1/govern \
  -H "Content-Type: application/json" \
  -d '{"action":"test","payload":{}}')

echo "Unsigned request status: $HTTP_STATUS (expected: 403)"
kill $PF_PID
```

### 5.4 — Valid Signed Request Returns 200

```bash
# Get the GOVERNANCE_SALT from the cluster
SALT=$(kubectl get secret advisor-secrets -n governance-stack \
  -o jsonpath='{.data.GOVERNANCE_SALT}' | base64 -d)

# Generate a valid seal token
# Token format: <expire_ts_hex>.<action_slug>.<hmac_sha256_hex>
EXPIRE_TS=$(printf '%x' $(($(date +%s) + 300)))  # 5 minutes from now
ACTION="test"
PAYLOAD="${EXPIRE_TS}.${ACTION}"
HMAC=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$SALT" | awk '{print $2}')
TOKEN="${EXPIRE_TS}.${ACTION}.${HMAC}"

# Port-forward gateway
kubectl port-forward -n governance-stack deploy/cage-gateway 8080:8080 &
PF_PID=$!
sleep 2

# Send signed request
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST http://localhost:8080/v1/govern \
  -H "Content-Type: application/json" \
  -H "X-CAGE-Routing-Seal: $TOKEN" \
  -d '{"action":"test","payload":{}}')

echo "Signed request status: $HTTP_STATUS (expected: 200 or non-403)"
kill $PF_PID
```

### 5.5 — Run Remote Posture Scripts

```bash
cd /Users/larsahlfors/Code/cybernetic-governance-engine
python3 scripts/verify_remote.py
python3 scripts/verify_langfuse_posture.py
# Expected: all checks pass
```

---

## Phase 6 — Pre-Release Checklist + Tag

### 6.1 — Final Secret Hygiene Check

```bash
cd /Users/larsahlfors/Code/cybernetic-governance-engine

# Check git history
for PATTERN in "REDACTED_SALT" "REDACTED_PASSWORD" "pk-lf-" "sk-lf-" "hf_"; do
  COUNT=$(git log --all -S "$PATTERN" --oneline | wc -l)
  echo "$PATTERN: $COUNT matches (expected 0)"
done

# Check working tree
grep -rn "REDACTED_SALT\|REDACTED_PASSWORD\|pk-lf-\|sk-lf-\|hf_[A-Za-z0-9]\{20\}" \
  --include="*.py" --include="*.yaml" --include="*.tf" --include="*.json" \
  --exclude-dir=".git" .
# Expected: no matches (or only in comments/docs explaining the pattern)
```

### 6.2 — Confirm Pod Availability

```bash
kubectl get deployment governed-financial-advisor -n governance-stack \
  -o jsonpath='{.status.availableReplicas}'
# Expected: 1

kubectl get pods -n governance-stack -l app=governed-financial-advisor \
  -o jsonpath='{.items[0].spec.containers[*].name}'
# Expected: "advisor" only (no slm-sidecar)
```

### 6.3 — Confirm HMAC Seal Enforce Mode

```bash
kubectl exec deploy/cage-gateway -n governance-stack -- \
  env | grep -E "CAGE_SEAL_ENFORCEMENT|CAGE_ROUTING_SEAL_SECRET|GOVERNANCE_SALT"
# CAGE_SEAL_ENFORCEMENT must NOT be "log"
# CAGE_ROUTING_SEAL_SECRET must be ≥64 chars
# GOVERNANCE_SALT must be ≥64 chars
```

### 6.4 — Run Lula Validation Suite

```bash
cd /Users/larsahlfors/Code/cybernetic-governance-engine
# Run all Lula assertions
for LULA_FILE in compliance/lula/lula-validation-*.yaml; do
  echo "=== Running: $LULA_FILE ==="
  lula validate -f "$LULA_FILE"
done
# Expected: all 15 assertions pass, including RA-5 (security-scanner-cronjob present)
```

### 6.5 — Verify NIST ≥45% Coverage

```bash
cd /Users/larsahlfors/Code/cybernetic-governance-engine
python3 -c "
from src.gateway.governance.oscal_ssp_exporter import OscalSspExporter
exporter = OscalSspExporter()
report = exporter.export()
print(f'NIST SP 800-53 coverage: {report[\"coverage_pct\"]}%')
"
# Expected: ≥45%
# If below 45%, document additional implemented controls in the SSP and re-run
# Reference: docs/NIST_RMF_CHUNK*.md for control mapping guidance
```

### 6.6 — Run Full Test Suite

```bash
cd /Users/larsahlfors/Code/cybernetic-governance-engine
uv run pytest tests/ --run-integration -v --timeout=120
# Expected: 0 failures
# Note: 2 defer-queue tests correctly skip (known behavior)
```

### 6.7 — Compile and Submit ATO Package

Assemble the following documents and submit to the Authorizing Official (AO):

| Document | Source |
|----------|--------|
| System Security Plan (SSP) | Generated by `OscalSspExporter` |
| Privacy Impact Assessment (PIA) | `compliance/pia/PRIVACY_IMPACT_ASSESSMENT.md` |
| Security Assessment Report (SAR) | `compliance/sar/SAR_2026Q1.md` |
| Plan of Action & Milestones (POA&M) | Must include POAM-011 (SC-8 TLS gap), POAM-012 (SC-12 KMS incomplete), R-21 (NeMo race condition) |

### 6.8 — Create Annotated Tag

```bash
cd /Users/larsahlfors/Code/cybernetic-governance-engine
git tag -a v2.0.0 -m "chore(release): stable v2.0.0

- Resolved P0 blockers: D-01 (secrets), D-02 (pod availability), D-04 (HMAC seal), D-06 (security scan), D-07 (PSA labels)
- NIST SP 800-53 coverage ≥45%
- ATO package submitted
- All 15 Lula assertions passing
- Full test suite: 0 failures"

git push origin v2.0.0
```

### 6.9 — Publish GitHub Release

```bash
gh release create v2.0.0 \
  --notes-file CHANGELOG.md \
  --target rc-v2.0.0 \
  --verify-tag \
  --title "v2.0.0 — Stable Release"
# Mark as Latest in GitHub UI
```

### 6.10 — Post-Release Cleanup

```bash
# Delete feature branch from remote
git push origin --delete fix/v2-p0-blockers

# Confirm terraform.auto.tfvars is gitignored
grep "terraform.auto.tfvars" .gitignore
# Expected: entry present

# Confirm no secrets in working tree
git status  # Should show clean working tree
```

---

## Final Release Gate Checklist

All items must be ✅ before executing step 6.8 (tag creation):

- [ ] `git log --all -S "<any-credential>"` returns zero matches for all patterns
- [ ] `governed-financial-advisor` READY 1/1, AVAILABLE 1, no `slm-sidecar` container
- [ ] `CAGE_ROUTING_SEAL_SECRET` in `advisor-secrets` ≥64 chars
- [ ] `GOVERNANCE_SALT` in `advisor-secrets` ≥64 chars
- [ ] `GOVERNANCE_SALT` in gateway pod env ≥64 chars
- [ ] Unsigned gateway request returns HTTP 403
- [ ] Valid signed gateway request returns HTTP 200
- [ ] `security-scanner-cronjob` exists in `governance-stack` namespace
- [ ] PSA labels: `governance-stack`=restricted, `langfuse`=baseline, `vllm`=baseline
- [ ] All 15 Lula assertions pass (including RA-5)
- [ ] NIST SP 800-53 coverage ≥45%
- [ ] Full test suite: 0 failures
- [ ] ATO package submitted; POAM-011, POAM-012, R-21 documented

---

## Known Open Issues (Non-Blocking — Documented in POA&M)

| ID | Control | Issue | Planned Fix |
|----|---------|-------|-------------|
| POAM-011 | SC-8 | TLS termination gap — internal service traffic unencrypted in transit | v2.1.0 |
| POAM-012 | SC-12 | KMS integration incomplete — not all signing ops use Cloud KMS | v2.1.0 |
| R-21 | — | `NeMoOTelCallback.current_span` race condition under concurrent requests | v2.1.0 |

---

*Generated from `docs/V2_RELEASE_PLAN.md` — Phase 1 code changes are in branch `fix/v2-p0-blockers`.*
