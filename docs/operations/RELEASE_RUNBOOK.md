# Release Runbook — Phases 2–6

> **Status: ✅ COMPLETE — v0.1.0 RELEASED (GO — 2026-06-08).** All phases executed. This runbook is preserved as a historical execution record for audit traceability.
> **Prerequisites:** Phase 1 PR (`fix/v2-p0-blockers`) must be merged into `rc-v0.1.0` before starting Phase 2.
> **Cluster:** `<your-kubectl-context>`, namespace `governance-stack`
> **Project:** `<your-project-id>`

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
cd <parent-dir>
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
git clone <repo-root> cage-filter-test
cd cage-filter-test
git filter-repo --replace-text /tmp/filter-repo-expressions.txt --dry-run 2>&1 | head -100
# Review output for unexpected replacements before proceeding
cd /tmp && rm -rf cage-filter-test
```

### 3.5 — Suspend Branch Protection (Repo Admin)

1. Go to GitHub → Repository Settings → Branches
2. Edit the `rc-v0.1.0` branch protection rule
3. Temporarily disable: "Require pull request before merging", "Require status checks", "Restrict who can push"
4. Also disable protection on `main`
5. **Record the timestamp of suspension**

### 3.6 — Run History Rewrite

```bash
cd <repo-root>
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
git remote add origin https://github.com/google/cybernetic-governance-engine.git
# Or if remote already exists:
# git remote set-url origin https://github.com/google/cybernetic-governance-engine.git

git push --force-with-lease origin rc-v0.1.0
git push --force-with-lease origin main
```

### 3.9 — Re-Enable Branch Protection

1. Return to GitHub → Repository Settings → Branches
2. Restore all branch protection settings on `rc-v0.1.0` and `main`
3. **Complete within 15 minutes of suspension**
4. Record timestamp of restoration

### 3.10 — Post-Rewrite Verification

```bash
# Fresh clone from remote
cd /tmp
git clone https://github.com/google/cybernetic-governance-engine.git cage-verify
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
cd <repo-root>
git fetch origin
git reset --hard origin/rc-v0.1.0
```

---

## Phase 4 — Terraform Apply + GKE Deployment

> **Rule:** All GKE image deployments via Cloud Build. `kubectl apply` permitted only for non-image resources (CronJobs, PSA labels, etc.).

> **⚠️ Required env var — `RECONCILIATION_PROVIDER`:** The gateway composition root ([`hybrid_server.py`](../src/gateway/server/hybrid_server.py)) asserts `RECONCILIATION_PROVIDER != "stub"` when `ENVIRONMENT=production`. You **must** set `RECONCILIATION_PROVIDER=gcs` (or another non-stub provider) in the gateway deployment before applying. Failure to do so causes the gateway pod to crash-loop at startup with `RuntimeError: RECONCILIATION_PROVIDER must not be 'stub' in production`. Add or verify this value in `terraform.auto.tfvars` (gitignored) and confirm it is injected into the gateway pod via the `advisor-secrets` Kubernetes Secret.

### 4.1 — Pre-Apply Checks

```bash
# Verify GCP auth
gcloud auth application-default login
gcloud config set project <your-project-id>
gcloud config get-value project  # Should print: <your-project-id>

# Verify kubectl context
kubectl config use-context <your-kubectl-context>
kubectl config current-context  # Should print: <your-kubectl-context>

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
  --project <your-project-id>
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
cd <repo-root>
python3 scripts/verify_remote.py
python3 scripts/verify_langfuse_posture.py
# Expected: all checks pass
```

---

## Phase 6 — Pre-Release Checklist + Tag

### 6.1 — Final Secret Hygiene Check

```bash
cd <repo-root>

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
cd <repo-root>
# Run all Lula assertions
for LULA_FILE in compliance/lula/lula-validation-*.yaml; do
  echo "=== Running: $LULA_FILE ==="
  lula validate -f "$LULA_FILE"
done
# Expected: all 15 assertions pass, including RA-5 (security-scanner-cronjob present)
# NOTE: As of v0.1.0-rc.3, only 4 of 15 manifests are Active (a52, a53, a92, sc4).
# The remaining 11 are Stubs requiring cluster-specific configuration.
# All 15 must be activated and passing before the stable v0.1.0 tag is applied.
# See compliance/lula/README.md for activation instructions.
```

### 6.5 — Verify NIST ≥45% Coverage

> **NIST SP 800-53 gates apply to US_FED deployments only.** EU_ECB and APAC_MAS stable releases use their respective regional compliance gates (EU AI Act / MAS FEAT). Skip this step for non-US_FED deployments.

```bash
cd <repo-root>
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
cd <repo-root>
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
cd <repo-root>
git tag -a v0.1.0 -m "chore(release): stable v0.1.0

- Resolved P0 blockers: D-01 (secrets), D-02 (pod availability), D-04 (HMAC seal), D-06 (security scan), D-07 (PSA labels)
- NIST SP 800-53 coverage ≥45%
- ATO package submitted
- All 15 Lula assertions passing
- Full test suite: 0 failures"

git push origin v0.1.0
```

### 6.9 — Publish GitHub Release

```bash
gh release create v0.1.0 \
  --notes-file CHANGELOG.md \
  --target rc-v0.1.0 \
  --verify-tag \
  --title "v0.1.0 — Stable Release"
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

All items must be ✅ before executing step 6.8 (tag creation). Apply the gates appropriate for the target deployment region.

### Release Gate Checklist

#### ✅ Universal Gates (all regions — must pass for any stable release)

- [x] All ISO 42001 Lula assertions pass (`lula-validation-a52.yaml`, `lula-validation-a53.yaml`, `lula-validation-a92.yaml`)
- [x] CSA AARM Lula assertion passes (`lula-validation-aarm-vectors.yaml`)
- [x] All non-NIST Lula assertions pass (ISO 42001 + CSA AARM manifests)
- [x] SBOM generated and validated (`deployment/k8s/sbom-cronjob.yaml` output)
- [x] Container image vulnerability scan passes (Trivy — no CRITICAL unmitigated)
- [x] Secret detection scan passes (no secrets in codebase)
- [x] All unit and integration tests pass (`pytest`)
- [x] STPA freshness check passes (`scripts/check_stpa_freshness.py`)
- [x] Langfuse posture verified (`scripts/verify_langfuse_posture.py`)
- [x] `git log --all -S "<any-credential>"` returns zero matches for all patterns
- [x] `governed-financial-advisor` READY 1/1, AVAILABLE 1, no `slm-sidecar` container
- [x] `CAGE_ROUTING_SEAL_SECRET` in `advisor-secrets` ≥64 chars
- [x] `GOVERNANCE_SALT` in `advisor-secrets` ≥64 chars
- [x] `GOVERNANCE_SALT` in gateway pod env ≥64 chars
- [x] Unsigned gateway request returns HTTP 403
- [x] Valid signed gateway request returns HTTP 200
- [x] `security-scanner-cronjob` exists in `governance-stack` namespace
- [x] PSA labels: `governance-stack`=restricted, `langfuse`=baseline, `vllm`=baseline
- [x] Full test suite: 0 failures

#### 🇺🇸 US_FED Gates (required for US_FED stable release only)

> NIST SP 800-53 is a US Federal posture requirement. These gates apply exclusively to `CAGE_DEPLOYMENT_REGION=US_FED` deployments. EU_ECB and APAC_MAS stable releases are NOT blocked by NIST gates.

- [ ] All 10 NIST SP 800-53 Lula assertions pass (`lula-validation-ac2.yaml`, `lula-validation-ac3.yaml`, `lula-validation-au12.yaml`, `lula-validation-cm6.yaml`, `lula-validation-ia3.yaml`, `lula-validation-ia5.yaml`, `lula-validation-ir6.yaml`, `lula-validation-ra5.yaml`, `lula-validation-sc8.yaml`, `lula-validation-si2.yaml`)
- [ ] NIST SP 800-53 coverage ≥45% (checked via `oscal_ssp_exporter.py`)
- [x] `security-scanner-cronjob` deployed in `governance-stack` namespace (RA-5 Lula assertion prerequisite)
- [ ] ATO process initiated (OSCAL SSP PRE-AUTHORIZATION DRAFT → submitted)
- [ ] POAM-005 (no ATO) and POAM-009 (FIPS 199 unsigned) addressed or formally accepted
- [ ] ATO package submitted; POAM-011, POAM-012, R-21 documented

#### 🇪🇺 EU_ECB Gates (required for EU_ECB stable release only)

- [ ] EU AI Act compliance posture verified (no new High-Risk AI behaviour without FRIA attestation)
- [ ] GDPR data residency confirmed: all data paths within `europe-west1` (EEA)
- [ ] DORA Art. 10 audit logging enabled (`enable_audit_logging = true` in `eu-dev.tfvars`)
- [ ] SR 26-2 telemetry suppression active (`"no legal force"` sentinel intact)

#### 🌏 APAC_MAS Gates (required for APAC_MAS stable release only)

- [ ] MAS FEAT compliance posture verified
- [ ] MAS TRM §4.2 data residency confirmed: all data paths within `asia-southeast1` (Singapore)
- [ ] MAS Notice 655 audit logging enabled (`enable_audit_logging = true` in `apac-dev.tfvars`)
- [ ] SR 26-2 telemetry suppression active (`"no legal force"` sentinel intact)

---

## Known Open Issues (Non-Blocking — Documented in POA&M)

| ID | Control | Issue | Planned Fix |
|----|---------|-------|-------------|
| POAM-011 | SC-8 | TLS termination gap — internal service traffic unencrypted in transit | v2.1.0 |
| POAM-012 | SC-12 | KMS integration incomplete — not all signing ops use Cloud KMS | v2.1.0 |
| R-21 | — | `NeMoOTelCallback.current_span` race condition under concurrent requests | v2.1.0 |

---

*Generated from `docs/RELEASE_PLAN.md` — Phase 1 code changes are in branch `fix/v2-p0-blockers`.*

---

## Phase 7 — Production Promotion Checklist

> **Authority:** `.clinerules` §5 (Release Gate Requirements), `docs/governance/CHANGE_MANAGEMENT_PROCESS.md` §3.8, `docs/project/RELEASE_PLAN.md` §8.
>
> **When to use this checklist:** Work through every item in order before cutting any `rc-v<X.Y.Z>` branch or applying a stable annotated tag. All items must be ✅ before executing the tag step. Items marked with a region flag apply only to that deployment region.
>
> **Cluster context assumed:** `<your-kubectl-context>`, namespace `governance-stack`. Adjust for the target cluster before running any `kubectl` command.

---

### 7.1 — Pre-Promotion Environment Verification

Confirm that every production pod spec carries the correct runtime identity and that all security-relevant Terraform flags are set in the target prod tfvars file (gitignored — never committed).

- [ ] `CAGE_ENV=prod` is set in all production pod specs

  ```bash
  kubectl get deployment -n governance-stack \
    -o jsonpath='{.items[*].spec.template.spec.containers[*].env[?(@.name=="CAGE_ENV")].value}'
  # Expected: "prod" for every container listed
  ```

- [ ] `CAGE_ENV` is NOT defaulting — the value must be explicitly set via `secretKeyRef`, not a hardcoded `value:` field

  ```bash
  kubectl get deployment governed-financial-advisor -n governance-stack \
    -o jsonpath='{.spec.template.spec.containers[0].env[?(@.name=="CAGE_ENV")]}'
  # Expected: valueFrom.secretKeyRef present, NOT a bare value: field
  ```

- [ ] `CAGE_DEPLOYMENT_REGION` is set correctly for the target region (`US_FED` | `EU_ECB` | `APAC_MAS`)

  ```bash
  kubectl get deployment -n governance-stack \
    -o jsonpath='{.items[*].spec.template.spec.containers[*].env[?(@.name=="CAGE_DEPLOYMENT_REGION")].value}'
  # Expected: the correct region string for this deployment
  ```

- [ ] `langfuse_posture_dry_run = false` in the target prod tfvars file (`infra/targets/gcp-gke/terraform.auto.tfvars`)
- [ ] `enable_kms_signing = true` in the target prod tfvars file
- [ ] `enable_psa_restricted = true` in the target prod tfvars file
- [ ] `enable_audit_logging = true` in the target prod tfvars file
- [ ] `enable_network_policy = true` in the target prod tfvars file

  ```bash
  # Verify KMS signer is active in the running gateway pod
  kubectl exec -n governance-stack deploy/cage-gateway -- \
    env | grep -E "CAGE_ENV|CAGE_DEPLOYMENT_REGION|KMS_KEY_NAME"
  # CAGE_ENV must be "prod"; KMS_KEY_NAME must be non-empty
  ```

---

### 7.2 — Secret Verification

Confirm that production secrets are present, meet the minimum length requirement, and contain no dev placeholder values. These checks guard against the D-01 class of blocker that delayed v0.1.0.

- [ ] `CAGE_ROUTING_SEAL_SECRET` is present in `advisor-secrets` and is ≥64 chars

  ```bash
  kubectl get secret advisor-secrets -n governance-stack \
    -o jsonpath='{.data.CAGE_ROUTING_SEAL_SECRET}' | base64 -d | wc -c
  # Expected: ≥64
  ```

- [ ] `GOVERNANCE_SALT` is present in `advisor-secrets` and is ≥64 chars

  ```bash
  kubectl get secret advisor-secrets -n governance-stack \
    -o jsonpath='{.data.GOVERNANCE_SALT}' | base64 -d | wc -c
  # Expected: ≥64
  ```

- [ ] Neither secret contains the dev placeholder string `dev-only-insecure-placeholder`

  ```bash
  for KEY in CAGE_ROUTING_SEAL_SECRET GOVERNANCE_SALT; do
    VAL=$(kubectl get secret advisor-secrets -n governance-stack \
      -o jsonpath="{.data.$KEY}" | base64 -d)
    echo "$KEY contains placeholder: $(echo "$VAL" | grep -c 'dev-only-insecure-placeholder')"
  done
  # Expected: 0 for both keys
  ```

- [ ] `terraform.auto.tfvars` is gitignored and not present in the working tree

  ```bash
  grep "terraform.auto.tfvars" infra/targets/gcp-gke/.gitignore
  git status infra/targets/gcp-gke/terraform.auto.tfvars
  # Expected: gitignore entry present; git status shows nothing (file untracked or absent)
  ```

- [ ] `git log --all -S "dev-only-insecure-placeholder"` returns zero matches

  ```bash
  git log --all -S "dev-only-insecure-placeholder" --oneline
  # Expected: no output
  ```

---

### 7.3 — Universal Release Gates (`.clinerules` §5.1)

All items in this section are required for **every** stable release regardless of deployment region. These are the gates that blocked v0.1.0 until 2026-06-08.

#### 7.3.1 — Lula Compliance Assertions

- [ ] ISO 42001 Annex A.5.2 assertion passes:

  ```bash
  lula validate -f compliance/lula/lula-validation-a52.yaml
  # Expected: PASS
  ```

- [ ] ISO 42001 Annex A.5.3 assertion passes:

  ```bash
  lula validate -f compliance/lula/lula-validation-a53.yaml
  # Expected: PASS
  ```

- [ ] ISO 42001 Annex A.9.2 assertion passes:

  ```bash
  lula validate -f compliance/lula/lula-validation-a92.yaml
  # Expected: PASS
  ```

- [ ] CSA AARM vectors assertion passes:

  ```bash
  lula validate -f compliance/lula/lula-validation-aarm-vectors.yaml
  # Expected: PASS
  ```

- [ ] Lula stub-count gate passes (no new stubs introduced without activation plan):

  ```bash
  python scripts/check_lula_stub_count.py
  # Expected: exit 0; stub count ≤ baseline recorded in compliance/lula/.stub-baseline
  ```

#### 7.3.2 — SBOM and Vulnerability Scan

- [ ] SBOM generated and validated:

  ```bash
  python scripts/generate_sbom.py
  # Expected: exit 0; SBOM artifact written to expected output path
  ```

- [ ] Trivy scan passes — no unmitigated CRITICAL CVEs:

  ```bash
  trivy image gcr.io/YOUR_PROJECT_ID/cage-gateway:latest \
    --exit-code 1 --severity CRITICAL --ignore-unfixed
  # Expected: exit 0 (no unmitigated CRITICAL CVEs)
  # Any CRITICAL finding must have a POAM entry with risk-acceptance before this gate passes
  ```

#### 7.3.3 — Secret Detection

- [ ] Git history contains no credential strings:

  ```bash
  for PATTERN in "pk-lf-" "sk-lf-" "hf_" "GOOG" "redis://:"; do
    COUNT=$(git log --all -S "$PATTERN" --oneline | wc -l)
    echo "$PATTERN: $COUNT matches (expected 0)"
  done
  # Expected: 0 for all patterns
  ```

#### 7.3.4 — Test Suite

- [ ] All unit and integration tests pass with zero failures:

  ```bash
  uv run pytest tests/ --run-integration --tb=short -q --timeout=120
  # Expected: X passed, Y skipped, 0 failed
  # The 2 defer-queue tests correctly SKIP (Redis db=1 unavailable in test env)
  ```

#### 7.3.5 — STPA and Langfuse Posture

- [ ] STPA freshness check passes:

  ```bash
  python scripts/check_stpa_freshness.py
  # Expected: exit 0; all STPA source files within freshness window
  ```

- [ ] Langfuse posture verified in non-dry-run mode:

  ```bash
  python scripts/verify_langfuse_posture.py
  # Expected: exit 0; all posture checks pass against live Langfuse instance
  # Requires langfuse_posture_dry_run = false in terraform.auto.tfvars (§7.1)
  ```

#### 7.3.6 — Gateway Seal Enforcement

- [ ] Unsigned gateway request returns HTTP 403:

  ```bash
  kubectl port-forward -n governance-stack deploy/cage-gateway 8080:8080 &
  PF_PID=$!; sleep 2
  HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST http://localhost:8080/v1/govern \
    -H "Content-Type: application/json" \
    -d '{"action":"test","payload":{}}')
  echo "Unsigned: $HTTP_STATUS (expected 403)"
  kill $PF_PID
  ```

- [ ] Valid signed gateway request returns HTTP 200 (or non-403 application response):

  ```bash
  SALT=$(kubectl get secret advisor-secrets -n governance-stack \
    -o jsonpath='{.data.GOVERNANCE_SALT}' | base64 -d)
  SEAL_TOKEN=$(python3 -c "
  import hmac, hashlib, time
  salt = '$SALT'
  action = 'test'
  expire_ts = int(time.time()) + 300
  expire_hex = format(expire_ts, 'x')
  payload = f'{expire_hex}.{action}'
  sig = hmac.new(salt.encode(), payload.encode(), hashlib.sha256).hexdigest()
  print(f'{expire_hex}.{action}.{sig}')
  ")
  kubectl port-forward -n governance-stack deploy/cage-gateway 8080:8080 &
  PF_PID=$!; sleep 2
  HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST http://localhost:8080/v1/govern \
    -H "Content-Type: application/json" \
    -H "X-CAGE-Routing-Seal: $SEAL_TOKEN" \
    -d '{"action":"test","payload":{}}')
  echo "Signed: $HTTP_STATUS (expected 200 or non-403)"
  kill $PF_PID
  ```

#### 7.3.7 — Cluster Health

- [ ] `security-scanner-cronjob` exists in `governance-stack` namespace:

  ```bash
  kubectl get cronjob security-scanner-cronjob -n governance-stack
  # Expected: resource found; SUSPEND=False
  ```

- [ ] PSA labels applied to all three namespaces:

  ```bash
  for NS in governance-stack langfuse vllm; do
    echo "=== $NS ==="
    kubectl get namespace $NS \
      -o jsonpath='{.metadata.labels}' | python3 -m json.tool | grep pod-security
  done
  # Expected:
  #   governance-stack: enforce=restricted, enforce-version=latest
  #   langfuse:         enforce=baseline,    enforce-version=latest
  #   vllm:             enforce=baseline,    enforce-version=latest
  ```

- [ ] `governed-financial-advisor` deployment is READY 1/1, AVAILABLE 1:

  ```bash
  kubectl get deployment governed-financial-advisor -n governance-stack \
    -o jsonpath='{.status.readyReplicas}/{.status.availableReplicas}'
  # Expected: 1/1
  ```

---

### 7.4 — POAM Review

Review the Plan of Action & Milestones before tagging. The POAM is structured across five files — check the correct file for the target region.

| Scope | File |
|-------|------|
| Universal / ISO 42001 | [`docs/compliance/universal/POAM_ISO42001.md`](../compliance/universal/POAM_ISO42001.md) |
| US_FED / NIST SP 800-53 | [`docs/compliance/us_fed/POAM_US_FED.md`](../compliance/us_fed/POAM_US_FED.md) |
| EU_ECB / EU AI Act / DORA | [`docs/compliance/eu_ecb/POAM_EU_ECB.md`](../compliance/eu_ecb/POAM_EU_ECB.md) |
| APAC_MAS / MAS FEAT | [`docs/compliance/apac_mas/POAM_APAC_MAS.md`](../compliance/apac_mas/POAM_APAC_MAS.md) |
| Cross-region index | [`docs/compliance/cross-region/POAM_INDEX.md`](../compliance/cross-region/POAM_INDEX.md) |

- [ ] All OPEN findings in the relevant POAM file(s) have a documented risk-acceptance statement or a remediation timeline with a target milestone version
- [ ] No OPEN finding is marked as blocking the current release without AO sign-off on the risk acceptance
- [ ] Any finding closed in this release cycle has the following recorded in the POAM file:
  - Commit SHA of the remediation
  - Lula validation result (PASS/FAIL) from the post-remediation run
  - Closure date (ISO 8601)

  ```bash
  # Quick scan for OPEN items without a milestone
  grep -n "OPEN" docs/compliance/universal/POAM_ISO42001.md | grep -v "milestone\|v2\."
  # Review any matches manually — each must have a documented acceptance or timeline
  ```

---

### 7.5 — Region-Specific Gates

Apply only the section matching `CAGE_DEPLOYMENT_REGION`. Skip the other two sections entirely.

#### 🇺🇸 US_FED (only if `CAGE_DEPLOYMENT_REGION=US_FED`)

> These gates block US_FED deployment only. They are NOT prerequisites for the global stable tag per `.clinerules` §5.2.

- [ ] All 10 NIST SP 800-53 Lula assertions pass:

  ```bash
  for MANIFEST in \
    lula-validation-ac2.yaml lula-validation-ac3.yaml \
    lula-validation-au12.yaml lula-validation-cm6.yaml \
    lula-validation-ia3.yaml lula-validation-ia5.yaml \
    lula-validation-ir6.yaml lula-validation-ra5.yaml \
    lula-validation-sc8.yaml lula-validation-si2.yaml; do
    echo "=== $MANIFEST ==="
    lula validate -f "compliance/lula/$MANIFEST"
  done
  # Expected: PASS for all 10
  ```

- [ ] NIST SP 800-53 coverage ≥45%:

  ```bash
  python scripts/oscal_ssp_exporter.py --check-coverage
  # Expected: coverage_pct ≥ 45.0
  # If below 45%: document additional implemented controls in the SSP and re-run
  # Reference: docs/compliance/us_fed/NIST_RMF_CHUNK*.md for control mapping guidance
  ```

- [ ] ATO process initiated — OSCAL SSP submitted to the Authorizing Official (AO)
- [ ] POAM items documented for all open findings (POAM-011 SC-8, POAM-012 SC-12, R-21 at minimum)

#### 🇪🇺 EU_ECB (only if `CAGE_DEPLOYMENT_REGION=EU_ECB`)

> These gates block EU_ECB deployment only. They are NOT prerequisites for the global stable tag per `.clinerules` §5.3.

- [ ] EU AI Act compliance posture verified — no new High-Risk AI behaviour introduced without a FRIA attestation in [`docs/compliance/eu_ecb/FRIA_ATTESTATION.md`](../compliance/eu_ecb/FRIA_ATTESTATION.md)

  ```bash
  lula validate -f compliance/lula/lula-validation-eu-ai-act-art9.yaml
  lula validate -f compliance/lula/lula-validation-eu-fria.yaml
  # Expected: PASS for both
  ```

- [ ] GDPR data residency confirmed — all storage paths within `europe-west1`:

  ```bash
  lula validate -f compliance/lula/lula-validation-gdpr-art22.yaml
  # Expected: PASS
  # Also verify: OSCAL_S3_BUCKET_EU_ECB env var points to a europe-west1 bucket
  kubectl get deployment -n governance-stack \
    -o jsonpath='{.items[*].spec.template.spec.containers[*].env[?(@.name=="OSCAL_S3_BUCKET_EU_ECB")].value}'
  ```

- [ ] DORA Art. 10 audit logging enabled — `enable_audit_logging = true` in `eu-prod.tfvars`:

  ```bash
  lula validate -f compliance/lula/lula-validation-dora-art10.yaml
  # Expected: PASS
  ```

- [ ] SR 26-2 "no legal force" sentinel intact in [`config/compliance/EU_ECB_BASELINE.json`](../../config/compliance/EU_ECB_BASELINE.json):

  ```bash
  python3 -c "
  import json
  with open('config/compliance/EU_ECB_BASELINE.json') as f:
    b = json.load(f)
  sentinel = b.get('CTRL_MRM_004', {}).get('legacy_citation', '')
  assert 'no legal force' in sentinel, 'SENTINEL MISSING — telemetry suppression at risk'
  print('Sentinel intact:', sentinel)
  "
  # Expected: prints the sentinel string containing "no legal force"
  ```

#### 🌏 APAC_MAS (only if `CAGE_DEPLOYMENT_REGION=APAC_MAS`)

> These gates block APAC_MAS deployment only. They are NOT prerequisites for the global stable tag per `.clinerules` §5.4.

- [ ] MAS FEAT compliance posture verified:

  ```bash
  lula validate -f compliance/lula/lula-validation-mas-feat.yaml
  # Expected: PASS
  ```

- [ ] MAS TRM §4.2 data residency confirmed — all storage paths within `asia-southeast1`:

  ```bash
  lula validate -f compliance/lula/lula-validation-mas-trm-s6.yaml
  # Expected: PASS
  # Also verify: OSCAL_S3_BUCKET_APAC_MAS env var points to an asia-southeast1 bucket
  kubectl get deployment -n governance-stack \
    -o jsonpath='{.items[*].spec.template.spec.containers[*].env[?(@.name=="OSCAL_S3_BUCKET_APAC_MAS")].value}'
  ```

- [ ] MAS Notice 655 audit logging enabled — `enable_audit_logging = true` in `apac-prod.tfvars`:

  ```bash
  lula validate -f compliance/lula/lula-validation-mas-notice655.yaml
  # Expected: PASS
  ```

- [ ] SR 26-2 "no legal force" sentinel intact in [`config/compliance/APAC_MAS_BASELINE.json`](../../config/compliance/APAC_MAS_BASELINE.json):

  ```bash
  python3 -c "
  import json
  with open('config/compliance/APAC_MAS_BASELINE.json') as f:
    b = json.load(f)
  sentinel = b.get('CTRL_MRM_004', {}).get('legacy_citation', '')
  assert 'no legal force' in sentinel, 'SENTINEL MISSING — telemetry suppression at risk'
  print('Sentinel intact:', sentinel)
  "
  # Expected: prints the sentinel string containing "no legal force"
  ```

---

### 7.6 — Git and Release Tagging

- [ ] The working branch is `rc-v<X.Y.Z>` branched from `main` — not a feature branch, not `main` directly

  ```bash
  git branch --show-current
  # Expected: rc-v<X.Y.Z>
  git log --oneline origin/main..HEAD | wc -l
  # Expected: 0 (rc branch is at or ahead of main, not behind)
  ```

- [ ] All CI checks are green on the `rc-v<X.Y.Z>` branch — License Guard, CI suite (pytest, STPA freshness, Langfuse posture dry-run, license headers), and security scan must all pass before tagging

- [ ] `CHANGELOG.md` updated with all Cat-N and Cat-M changes since the last release, following the format in `docs/governance/CHANGE_MANAGEMENT_PROCESS.md` §9.4:

  ```bash
  head -30 CHANGELOG.md
  # Expected: [Unreleased] section is empty or contains only the current release entry
  # The new release section [X.Y.Z] — YYYY-MM-DD must be present with all CR entries
  ```

- [ ] Annotated tag created with a Conventional Commits message (`chore(release)` type):

  ```bash
  git tag -a v<X.Y.Z> \
    -m "chore(release): stable v<X.Y.Z>

  <one-paragraph summary of what changed since the previous stable tag>

  Universal gates: all ISO 42001 Lula assertions PASS, Trivy clean,
  pytest 0 failures, STPA fresh, Langfuse posture verified."
  # Tag must be annotated (git tag -a), NOT lightweight (git tag)
  ```

- [ ] Tag pushed to origin:

  ```bash
  git push origin v<X.Y.Z>
  git ls-remote --tags origin | grep "v<X.Y.Z>"
  # Expected: refs/tags/v<X.Y.Z> present on remote
  ```

- [ ] GitHub Release published as "Latest release" with `CHANGELOG.md` release notes:

  ```bash
  gh release create v<X.Y.Z> \
    --title "v<X.Y.Z> — Stable Release" \
    --notes-file CHANGELOG.md \
    --target rc-v<X.Y.Z> \
    --verify-tag
  # Then mark as Latest in GitHub UI or via: gh release edit v<X.Y.Z> --latest
  ```

---

### 7.7 — Post-Promotion Verification

Run these checks immediately after the deployment completes. Monitor for 30 minutes before closing the change record.

- [ ] Rollout completes successfully:

  ```bash
  kubectl rollout status deployment/governed-financial-advisor \
    -n governance-stack --timeout=300s
  # Expected: "deployment 'governed-financial-advisor' successfully rolled out"
  ```

- [ ] Smoke test — send a signed request through the gateway and verify a non-403 response:

  ```bash
  # Re-use the signed request from §7.3.6 or run scripts/verify_remote.py
  python scripts/verify_remote.py
  # Expected: all checks pass
  ```

- [ ] Audit log entries are being written to the correct regional storage path:

  ```bash
  # Verify the UCA logger is writing to the correct WORM bucket for the target region
  kubectl logs -n governance-stack deploy/governed-financial-advisor \
    --since=5m | grep -i "uca\|worm\|audit"
  # Expected: log lines showing successful writes to the regional bucket
  # For US_FED: OSCAL_S3_BUCKET_US_FED; EU_ECB: OSCAL_S3_BUCKET_EU_ECB;
  # APAC_MAS: OSCAL_S3_BUCKET_APAC_MAS
  ```

- [ ] Langfuse traces are appearing in the Langfuse dashboard:

  ```bash
  python scripts/verify_langfuse_posture.py
  # Expected: exit 0; traces visible in Langfuse for the current session
  ```

- [ ] Error rate monitored for 30 minutes post-deployment — no spike above baseline:

  ```bash
  # Check gateway error rate via Cloud Monitoring or kubectl logs
  kubectl logs -n governance-stack deploy/cage-gateway \
    --since=30m | grep -c "ERROR\|500\|503"
  # Compare against pre-deployment baseline; escalate if error count increases >10%
  ```

- [ ] Change record closed in `docs/governance/CHANGE_MANAGEMENT_PROCESS.md` format:
  - POAM updated for any finding closed by this release (commit SHA + Lula result + closure date)
  - OSCAL component updated if any security control implementation changed
  - `CHANGELOG.md` `[Unreleased]` section cleared

---

### 7.8 — Phase 1–4 Hardening Verification Summary

The following items reflect the specific hardening changes introduced in Phases 1–4 of the v0.1.0 implementation plan. They are incorporated into the checklist sections above but are called out here for traceability.

| Phase | Blocker | Checklist Section | Verification |
|-------|---------|-------------------|--------------|
| Phase 1 — D-01 | Committed secrets in working tree | §7.2 Secret Verification | `git log --all -S "dev-only-insecure-placeholder"` returns 0 matches; no `value:` fields for sensitive env vars |
| Phase 1 — D-04 | HMAC seal enforcement disabled | §7.3.6 Gateway Seal Enforcement | Unsigned → 403; signed → 200 |
| Phase 1 — D-06 | Security-scan CronJob missing | §7.3.7 Cluster Health | `security-scanner-cronjob` exists in `governance-stack` |
| Phase 1 — D-07 | PSA labels not applied | §7.3.7 Cluster Health | `governance-stack=restricted`, `langfuse=baseline`, `vllm=baseline` |
| Phase 2 — D-01 | Credentials in git history | §7.2 Secret Verification | `git log --all -S` returns 0 for all credential patterns |
| Phase 3 — D-01 | History rewrite verification | §7.2 Secret Verification | Fresh clone from remote; all patterns return 0 |
| Phase 4 — D-02 | Pod `MinimumReplicasUnavailable` | §7.3.7 Cluster Health | `governed-financial-advisor` READY 1/1, AVAILABLE 1 |
| Phase 4 — D-04 | Seal secrets not in cluster | §7.2 Secret Verification | `CAGE_ROUTING_SEAL_SECRET` and `GOVERNANCE_SALT` ≥64 chars in `advisor-secrets` |
| Phase 4 — CAGE_ENV | Production identity not set | §7.1 Environment Verification | `CAGE_ENV=prod` in all pod specs; no dev placeholder |
| Phase 4 — POAM | Open findings not reviewed | §7.4 POAM Review | All OPEN items have risk acceptance or remediation timeline |
