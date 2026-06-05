# Path B Deployment Plan: GKE Rollout with Pre-existing Issue Remediation

**Document status**: Planning only — no commands are to be executed until each section is reviewed and approved.
**Target cluster**: `gke_laah-cybernetics_us-central1-a_cage-dev` (Kubernetes v1.35.3-gke.1389002)
**Primary namespace**: `governance-stack`
**Container registry**: `gcr.io/laah-cybernetics/` (GCR) | Artifact Registry (lula only): `us-central1-docker.pkg.dev/laah-cybernetics/governance-stack/`
**Build script**: [`scripts/build_images.sh`](../scripts/build_images.sh) — Path B full-stack fan-out

---

## Cluster Baseline (Do Not Modify)

| Resource | Kind | State | Notes |
|---|---|---|---|
| `redis-master` | StatefulSet | 1/1 Ready | Helm-managed, bound PVC 10Gi + 3×8Gi — **DO NOT TOUCH** |
| `postgresql` | StatefulSet | 1/1 Ready | Helm-managed, bound PVC 10Gi — **DO NOT TOUCH** |
| `clickhouse` | StatefulSet | 1/1 Ready | Helm-managed, bound PVC 2×10Gi — **DO NOT TOUCH** |
| `gateway-hpa` | HPA | CPU 50%, 1/5 | Normal |
| `langfuse-worker-hpa` | HPA | CPU 70%/Mem 80%, 3 replicas | Memory at 90% — above target |

**CNI**: Calico — `CiliumNetworkPolicy` manifests in [`deployment/k8s/cilium-egress-lockdown.yaml`](../deployment/k8s/cilium-egress-lockdown.yaml) are **NOT enforced**.

---

## Pre-existing Issues Summary

| # | Issue | Severity | Scope |
|---|---|---|---|
| 1 | `lula-audit` CronJob: 5 consecutive failures (40h) | HIGH | Compliance evidence collection broken |
| 2 | `lula-sc4-watch` ImagePullBackOff — tag `0.9.0` missing | HIGH | Real-time SC-4 monitoring down |
| 3 | `governed-financial-advisor` 1/2, `nemo-guardrails` 1/2, `langfuse-worker` 2/3 | MEDIUM | Reduced capacity |
| 4 | `compliance-bridge` dual build path race condition | HIGH | Non-deterministic image state risk |

---

## Remediation + Deployment Sequence (Overview)

```
Issue 4 Gate Check  →  Issue 2 Lula Build  →  Issue 1 CronJob Fix
        ↓
scripts/build_images.sh (Path B fan-out — 6 images in parallel)
        ↓
Wave 1: vllm-inference / vllm-reasoning
        ↓
Wave 2: nemo-guardrails / nemo-service
        ↓
Wave 3: gateway
        ↓
Wave 4: compliance-bridge
        ↓
Wave 5: governed-financial-advisor
        ↓
Wave 6: agentsight-ui
        ↓
Post-Deployment Validation
```

---

## Section 1: Read-Only Diagnostic Commands

> Run ALL commands in this section before making any changes. Record outputs as your pre-change baseline.

### 1.1 Issue 1 — `lula-audit` CronJob Failures

**Risk**: LOW (read-only)

#### Step 1.1.1 — Inspect the CronJob spec and status

```bash
kubectl describe cronjob lula-audit -n governance-stack
```

**Expected output patterns**:
- `Last Schedule Time` — confirms when the last job was triggered
- `Active Jobs` — should be empty if `concurrencyPolicy: Forbid` is working
- `Events` — look for `FailedCreate`, `BackoffLimitExceeded`, or image pull errors
- `Suspend: false` — if `true`, the CronJob has been manually suspended

#### Step 1.1.2 — List all jobs spawned by the CronJob, sorted by creation time

```bash
kubectl get jobs -n governance-stack \
  --selector=app=lula \
  --sort-by=.metadata.creationTimestamp \
  -o wide
```

**Expected output patterns**:
- Jobs `lula-audit-29675520` through `lula-audit-29676960` should all show `0/1 COMPLETIONS`
- `DURATION` column will show how long each job ran before failing
- `COMPLETIONS` of `0` across all 5 confirms the 40h failure window

#### Step 1.1.3 — Get logs from the most recent failed job pod

```bash
# Identify the most recent failed job's pod
LATEST_JOB=$(kubectl get jobs -n governance-stack \
  --selector=app=lula \
  --sort-by=.metadata.creationTimestamp \
  -o jsonpath='{.items[-1].metadata.name}')

echo "Most recent job: ${LATEST_JOB}"

# Get the pod name for that job
FAILED_POD=$(kubectl get pods -n governance-stack \
  --selector=job-name=${LATEST_JOB} \
  -o jsonpath='{.items[0].metadata.name}')

echo "Failed pod: ${FAILED_POD}"

# Get logs (including previous container if it restarted)
kubectl logs ${FAILED_POD} -n governance-stack --previous 2>/dev/null \
  || kubectl logs ${FAILED_POD} -n governance-stack
```

**Expected output patterns to look for**:
- `ImagePullBackOff` or `ErrImagePull` → image tag issue (the CronJob uses `gcr.io/laah-cybernetics/compliance-bridge:latest`)
- `ModuleNotFoundError` → Python import failure inside the compliance-bridge image
- `asyncio.TimeoutError` or `ConnectionRefusedError` → compliance-bridge service unreachable
- `langfuse-compliance-secrets` not found → missing Secret
- `sys.exit(1)` with `Ingest failed` → audit_workflow returned non-ok status

#### Step 1.1.4 — Describe the failed pod for event-level detail

```bash
kubectl describe pod ${FAILED_POD} -n governance-stack
```

**Expected output patterns**:
- `Events` section: `Failed to pull image` → image issue
- `OOMKilled` → memory limit (256Mi) exceeded
- `Error` exit code → application-level failure

#### Step 1.1.5 — Verify the compliance-bridge image used by the CronJob is pullable

The CronJob at [`deployment/k8s/lula-cron.yaml`](../deployment/k8s/lula-cron.yaml) line 191 uses `gcr.io/laah-cybernetics/compliance-bridge:latest`.

```bash
# Check that the image exists and is accessible from the cluster's service account
gcloud container images list-tags gcr.io/laah-cybernetics/compliance-bridge \
  --project=laah-cybernetics \
  --limit=5 \
  --sort-by=~TIMESTAMP \
  --format="table(digest,tags,timestamp)"
```

**Expected**: At least one entry with tag `latest`. If no `latest` tag exists, the CronJob will always fail with `ErrImagePull`.

#### Step 1.1.6 — Check RBAC for the `lula-auditor` service account

The CronJob runs as `serviceAccountName: lula-auditor` (line 163 of [`deployment/k8s/lula-cron.yaml`](../deployment/k8s/lula-cron.yaml)).

```bash
# Verify the service account exists
kubectl get serviceaccount lula-auditor -n governance-stack

# Check what ClusterRoleBindings or RoleBindings reference it
kubectl get rolebindings,clusterrolebindings -n governance-stack \
  -o json | jq '.items[] | select(.subjects[]?.name == "lula-auditor") | {name: .metadata.name, role: .roleRef.name}'

# Verify it can read configmaps (needed for SC-4 validation)
kubectl auth can-i get configmaps \
  --as=system:serviceaccount:governance-stack:lula-auditor \
  -n governance-stack

# Verify it can read secrets (needed for langfuse-compliance-secrets envFrom)
kubectl auth can-i get secrets \
  --as=system:serviceaccount:governance-stack:lula-auditor \
  -n governance-stack
```

**Expected**: `yes` for both `get configmaps` and `get secrets`. If `no`, RBAC is the root cause.

#### Step 1.1.7 — Verify the required Secret exists

```bash
kubectl get secret langfuse-compliance-secrets -n governance-stack \
  -o jsonpath='{.metadata.name}' && echo " — Secret exists"
```

**Expected**: `langfuse-compliance-secrets — Secret exists`. If missing, the pod will fail at startup with `CreateContainerConfigError`.

---

### 1.2 Issue 2 — `lula-sc4-watch` ImagePullBackOff

**Risk**: LOW (read-only)

#### Step 1.2.1 — Verify which image tags exist in Artifact Registry

The deployment at [`deployment/k8s/lula-cron.yaml`](../deployment/k8s/lula-cron.yaml) line 303 references `us-central1-docker.pkg.dev/laah-cybernetics/governance-stack/lula:0.9.0`.

```bash
gcloud artifacts docker images list \
  us-central1-docker.pkg.dev/laah-cybernetics/governance-stack/lula \
  --project=laah-cybernetics \
  --include-tags \
  --format="table(package,tags,createTime,updateTime)"
```

**Decision tree**:
- If tag `0.9.0` exists → the pull failure is an auth/network issue, not a missing tag; check IAM
- If tag `0.9.0` does NOT exist → proceed to build it via [`deployment/docker/cloudbuild.lula.yaml`](../deployment/docker/cloudbuild.lula.yaml)
- Note what tags DO exist (e.g., `0.8.0`, `latest`) — these are candidates for a temporary patch if the build takes too long

#### Step 1.2.2 — Describe the failing pod

```bash
kubectl describe pod lula-sc4-watch-5bfdcb7bd4-drnls -n governance-stack
```

**Expected output patterns**:
- `Events`: `Failed to pull image "us-central1-docker.pkg.dev/laah-cybernetics/governance-stack/lula:0.9.0": ... not found` → tag missing
- `Events`: `403 Forbidden` → IAM permission issue on Artifact Registry
- `Back-off pulling image` → Kubernetes has entered exponential backoff

#### Step 1.2.3 — Check the deployment's current image spec

```bash
kubectl get deployment lula-sc4-watch -n governance-stack \
  -o jsonpath='{.spec.template.spec.containers[*].image}'
```

**Expected**: `us-central1-docker.pkg.dev/laah-cybernetics/governance-stack/lula:0.9.0`

#### Step 1.2.4 — Check the older running replica's image

```bash
# List all pods for this deployment and their images
kubectl get pods -n governance-stack \
  --selector=app=lula-sc4-watch \
  -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.phase}{"\t"}{.spec.containers[0].image}{"\n"}{end}'
```

**Expected**: One pod Running (older image), one pod in `ImagePullBackOff` (tag `0.9.0`). This confirms a failed rollout — the old ReplicaSet is still serving.

#### Step 1.2.5 — Check IAM for Artifact Registry pull access

```bash
# Check if the node service account has Artifact Registry Reader role
gcloud projects get-iam-policy laah-cybernetics \
  --format="json" \
  | jq '.bindings[] | select(.role == "roles/artifactregistry.reader") | .members'
```

---

## Section 2: Remediation Actions

> **Execution order**: Issue 4 (build gate) → Issue 2 (lula image) → Issue 1 (CronJob) → Issue 3 (addressed by rolling update in Section 4)

---

### 2.1 Issue 4 — Pause / Verify the `compliance-bridge` Standalone Trigger

**Risk**: LOW
**Dependency rationale**: Must be resolved FIRST. If the standalone `cloudbuild.compliance.yaml` trigger fires concurrently with `scripts/build_images.sh`, both will race to push `compliance-bridge:latest` with potentially different SHA values, producing a non-deterministic image. Gate this before any build activity.

#### Action 2.1.1 — Disable the standalone trigger (if active)

```bash
# Replace <trigger-name> with the name identified in step 1.4.1
gcloud builds triggers update <trigger-name> \
  --project=laah-cybernetics \
  --no-build-config \
  2>/dev/null || \
gcloud builds triggers import \
  --project=laah-cybernetics \
  --source=<(gcloud builds triggers describe <trigger-name> \
    --project=laah-cybernetics --format=json \
    | jq '.disabled = true') 2>/dev/null

# Simpler alternative — use the disable subcommand if available in your gcloud version
gcloud builds triggers disable <trigger-name> \
  --project=laah-cybernetics
```

**Rollback**:
```bash
gcloud builds triggers enable <trigger-name> \
  --project=laah-cybernetics
```

**Success criteria**:
```bash
gcloud builds triggers describe <trigger-name> \
  --project=laah-cybernetics \
  --format="value(disabled)"
# Expected output: True
```

#### Action 2.1.2 — Confirm no compliance builds are in-flight

```bash
gcloud builds list \
  --project=laah-cybernetics \
  --filter="status=WORKING AND substitutions.TRIGGER_NAME=<trigger-name>" \
  --limit=5
# Expected: empty list (no active builds)
```

---

## Section 4: Rolling Update Sequence for All 6 Application Deployments

> **Prerequisite**: All 6 images verified as pushed (Section 3.6) before starting Wave 1.
> All deployments use `RollingUpdate` strategy — no downtime expected.
> StatefulSets (`redis-master`, `postgresql`, `clickhouse`) are **NOT touched**.

### Dependency Map

```
vllm-inference / vllm-reasoning   [Wave 1 — GPU backend, no upstream deps]
        ↓
nemo-guardrails / nemo-service    [Wave 2 — guardrails, depends on vllm]
        ↓
gateway                           [Wave 3 — API gateway, depends on nemo + redis + OPA]
        ↓
compliance-bridge                 [Wave 4 — compliance layer, depends on gateway + redis + GCS]
        ↓
governed-financial-advisor        [Wave 5 — app layer, depends on gateway + compliance-bridge]
        ↓
agentsight-ui                     [Wave 6 — frontend, depends on gateway]
```

### Between-Wave Health Check Template

Before advancing to the next wave, run:
```bash
# Replace <deployment> and <namespace> with the wave's deployment name
kubectl get deployment <deployment> -n <namespace>
kubectl get pods -n <namespace> --selector=app=<deployment> -o wide
kubectl get events -n <namespace> \
  --field-selector=involvedObject.name=<deployment> \
  --sort-by=.lastTimestamp | tail -10
```

---

### Wave 1 — GPU Inference Backend

**Risk**: MEDIUM (GPU node scheduling; Spot instance preemption possible)
**Deployments**: `vllm-inference`, `vllm-reasoning`
**Image**: `gcr.io/laah-cybernetics/vllm-streamer:latest` (updated by Path B)
**Node affinity**: GPU nodes (g2-standard-8, nvidia-l4 Spot)
**Timeout**: 10 minutes (large image, GPU node scheduling latency)

```bash
# --- vllm-inference ---
kubectl rollout restart deployment/vllm-inference -n governance-stack
kubectl rollout status deployment/vllm-inference -n governance-stack --timeout=10m

# Health check
kubectl get deployment vllm-inference -n governance-stack
kubectl get pods -n governance-stack --selector=app=vllm-inference -o wide

# --- vllm-reasoning ---
kubectl rollout restart deployment/vllm-reasoning -n governance-stack
kubectl rollout status deployment/vllm-reasoning -n governance-stack --timeout=10m

# Health check
kubectl get deployment vllm-reasoning -n governance-stack
kubectl get pods -n governance-stack --selector=app=vllm-reasoning -o wide
```

**Health check criteria**:
- Both deployments show `READY` equal to `DESIRED` replicas
- No pods in `CrashLoopBackOff` or `OOMKilled`
- GPU resource allocated: `kubectl describe pod <vllm-pod> -n governance-stack | grep -A5 "nvidia.com/gpu"`

**HPA interaction**: `vllm-inference` and `vllm-reasoning` are not expected to have HPAs. Verify:
```bash
kubectl get hpa -n governance-stack | grep vllm
```

**Spot preemption risk**: If a GPU Spot node is preempted during rollout, the new pod will be `Pending` until a replacement node is provisioned. Monitor:
```bash
kubectl get events -n governance-stack \
  --field-selector=reason=FailedScheduling \
  --sort-by=.lastTimestamp | tail -5
```

**Wave 1 → Wave 2 gate**: Both `vllm-inference` and `vllm-reasoning` must be `READY` before proceeding.

---

### Wave 2 — Guardrails Layer

**Risk**: MEDIUM (depends on Wave 1 vLLM being healthy; also resolves Issue 3 replica shortfall)
**Deployments**: `nemo-guardrails`, `nemo-service`
**Image**: `gcr.io/laah-cybernetics/nemo-guardrails:latest` (updated by Path B)
**Timeout**: 5 minutes

```bash
# --- nemo-guardrails ---
kubectl rollout restart deployment/nemo-guardrails -n governance-stack
kubectl rollout status deployment/nemo-guardrails -n governance-stack --timeout=5m

# Verify replica count reaches 2/2 (resolves Issue 3)
kubectl get deployment nemo-guardrails -n governance-stack
# Expected: READY 2/2

kubectl get pods -n governance-stack --selector=app=nemo-guardrails -o wide

# --- nemo-service ---
kubectl rollout restart deployment/nemo-service -n governance-stack
kubectl rollout status deployment/nemo-service -n governance-stack --timeout=5m

kubectl get deployment nemo-service -n governance-stack
kubectl get pods -n governance-stack --selector=app=nemo-service -o wide
```

**Health check criteria**:
- `nemo-guardrails` shows `READY 2/2` — confirming Issue 3 replica shortfall is resolved
- No `CrashLoopBackOff` events
- Readiness probe passing (check via `kubectl describe pod <nemo-pod> -n governance-stack | grep -A5 "Readiness"`)

**Issue 3 resolution confirmation**:
```bash
kubectl get deployment nemo-guardrails -n governance-stack \
  -o jsonpath='{.status.readyReplicas}/{.spec.replicas}'
# Expected: 2/2
```

**Wave 2 → Wave 3 gate**: Both `nemo-guardrails` and `nemo-service` must be `READY` at desired replica count.

---

### Wave 3 — API Gateway

**Risk**: MEDIUM (central traffic routing; HPA interaction)
**Deployment**: `gateway`
**Image**: `gcr.io/laah-cybernetics/gateway:latest` (updated by Path B)
**Timeout**: 5 minutes

```bash
# --- gateway ---
kubectl rollout restart deployment/gateway -n governance-stack
kubectl rollout status deployment/gateway -n governance-stack --timeout=5m

# Health check
kubectl get deployment gateway -n governance-stack
kubectl get pods -n governance-stack --selector=app=gateway -o wide

# Verify HPA state — gateway-hpa should remain stable during rollout
kubectl get hpa gateway-hpa -n governance-stack
```

**Health check criteria**:
- `gateway` deployment `READY` at desired replica count
- `gateway-hpa` shows current replicas within min/max bounds (1–5, currently at 1)
- No `CrashLoopBackOff` or connection refused errors in pod logs:
  ```bash
  kubectl logs -n governance-stack \
    -l app=gateway \
    --tail=50 \
    --since=2m
  ```

**HPA interaction**: The `gateway-hpa` targets CPU at 50%. During rollout, the new pod will briefly have no traffic, then receive traffic as the old pod terminates. The HPA should not scale up during this brief transition. If it does:
```bash
# Check HPA events
kubectl describe hpa gateway-hpa -n governance-stack | grep -A10 "Events"
```

**Wave 3 → Wave 4 gate**: `gateway` must be `READY` and HPA stable before proceeding.

---

### Wave 4 — Compliance Bridge

**Risk**: MEDIUM (compliance evidence pipeline; also unblocks lula-audit CronJob)
**Deployment**: `compliance-bridge`
**Image**: `gcr.io/laah-cybernetics/compliance-bridge:latest` (updated by Path B; also resolves lula-audit CronJob image if that was the root cause)
**Timeout**: 5 minutes

```bash
# --- compliance-bridge ---
kubectl rollout restart deployment/compliance-bridge -n governance-stack
kubectl rollout status deployment/compliance-bridge -n governance-stack --timeout=5m

# Health check
kubectl get deployment compliance-bridge -n governance-stack
kubectl get pods -n governance-stack --selector=app=compliance-bridge -o wide

# Verify the compliance-bridge health endpoint
BRIDGE_POD=$(kubectl get pods -n governance-stack \
  --selector=app=compliance-bridge \
  -o jsonpath='{.items[0].metadata.name}')

kubectl exec ${BRIDGE_POD} -n governance-stack -- \
  curl -s http://localhost:3001/health | python3 -m json.tool
```

**Health check criteria**:
- `compliance-bridge` deployment `READY` at desired replica count
- Health endpoint returns `{"status": "ok"}` or equivalent
- No `CrashLoopBackOff` events

**lula-audit CronJob benefit**: If the CronJob failures (Issue 1) were caused by a stale `compliance-bridge:latest` image, the new image pushed by Path B will automatically fix the next CronJob run. Verify after Wave 4 completes:
```bash
# Trigger a manual test run
kubectl create job lula-audit-wave4-test \
  --from=cronjob/lula-audit \
  -n governance-stack

kubectl wait job/lula-audit-wave4-test \
  -n governance-stack \
  --for=condition=complete \
  --timeout=5m

kubectl logs -n governance-stack \
  -l job-name=lula-audit-wave4-test
```

**Wave 4 → Wave 5 gate**: `compliance-bridge` must be `READY` and health endpoint responding.

---

## Section 5: Post-Deployment Validation

> Run all commands in this section after Wave 6 completes. Record outputs as your post-change baseline.

### 5.1 All 6 Deployments at Desired Replica Count

```bash
# Single command to check all governance-stack deployments
kubectl get deployments -n governance-stack \
  -o custom-columns="NAME:.metadata.name,DESIRED:.spec.replicas,READY:.status.readyReplicas,AVAILABLE:.status.availableReplicas,IMAGE:.spec.template.spec.containers[0].image"
```

**Expected**:

| Deployment | Desired | Ready | Available |
|---|---|---|---|
| `vllm-inference` | N | N | N |
| `vllm-reasoning` | N | N | N |
| `nemo-guardrails` | 2 | 2 | 2 |
| `nemo-service` | N | N | N |
| `gateway` | N | N | N |
| `compliance-bridge` | N | N | N |
| `governed-financial-advisor` | 2 | 2 | 2 |
| `agentsight-ui` | N | N | N |

All `READY` values must equal `DESIRED`. `nemo-guardrails` and `governed-financial-advisor` must show `2/2` (Issue 3 resolved).

### 5.2 `lula-sc4-watch` ImagePullBackOff Resolved

```bash
kubectl get pods -n governance-stack \
  --selector=app=lula-sc4-watch \
  -o wide

kubectl describe deployment lula-sc4-watch -n governance-stack \
  | grep -E "Image:|Ready:|Replicas:"
```

**Expected**:
- All pods in `Running` state
- No `ImagePullBackOff` or `ErrImagePull` events
- Image shows `us-central1-docker.pkg.dev/laah-cybernetics/governance-stack/lula:0.9.0`

### 5.3 `lula-audit` CronJob — Verify Root Cause Fixed

```bash
# Check the CronJob's last schedule and active jobs
kubectl describe cronjob lula-audit -n governance-stack \
  | grep -E "Last Schedule|Active Jobs|Suspend"

# Trigger a final validation run
kubectl create job lula-audit-post-deploy-validation \
  --from=cronjob/lula-audit \
  -n governance-stack

kubectl wait job/lula-audit-post-deploy-validation \
  -n governance-stack \
  --for=condition=complete \
  --timeout=5m

kubectl logs -n governance-stack \
  -l job-name=lula-audit-post-deploy-validation
```

**Expected log output**:
```
🔍 Starting Lula ISO 42001 audit...
✅ Lula audit complete. Result: oscal-assessment-cron-<timestamp>.yaml (<N> lines)
📊 Ingest result:
{"status": "ok", ...}
✅ OSCAL results ingested into Langfuse compliance project.
```

### 5.4 No New CrashLoopBackOff or OOMKilled Events

```bash
# Check for CrashLoopBackOff across governance-stack
kubectl get pods -n governance-stack \
  --field-selector=status.phase=Running \
  -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{range .status.containerStatuses[*]}{.restartCount}{"\t"}{.state.waiting.reason}{"\n"}{end}{end}' \
  | grep -v "^$"

# Check for OOMKilled events in the last hour
kubectl get events -n governance-stack \
  --field-selector=reason=OOMKilling \
  --sort-by=.lastTimestamp \
  | tail -10

# Check for any pods not in Running state
kubectl get pods -n governance-stack \
  --field-selector=status.phase!=Running,status.phase!=Succeeded
```

**Expected**: No pods in `CrashLoopBackOff`, no new `OOMKilled` events, no pods stuck in non-Running/non-Succeeded state.

### 5.5 Gateway Connectivity Check

```bash
# Port-forward to the gateway service and test the health endpoint
kubectl port-forward svc/gateway -n governance-stack 8080:80 &
PF_PID=$!
sleep 3

curl -s http://localhost:8080/health | python3 -m json.tool
# or if no /health endpoint:
curl -s -o /dev/null -w "HTTP %{http_code}\n" http://localhost:8080/

kill ${PF_PID}
```

**Expected**: HTTP 200 with a valid JSON health response.

### 5.6 Compliance Bridge Health Check

```bash
# Port-forward to compliance-bridge and test health
kubectl port-forward svc/compliance-bridge -n governance-stack 3001:80 &
PF_PID=$!
sleep 3

curl -s http://localhost:3001/health | python3 -m json.tool

# Also test the metrics endpoint used by lula-audit
curl -s http://localhost:3001/v1/metrics/A.5.2 | python3 -m json.tool

kill ${PF_PID}
```

**Expected**: HTTP 200 from `/health`; `/v1/metrics/A.5.2` returns a JSON object with `safety_rate`, `total_traces`, and `evidence_age_seconds` fields.

### 5.7 HPA State Verification

```bash
kubectl get hpa -n governance-stack
```

**Expected**:

| HPA | Min | Max | Current | CPU/Mem Target | Status |
|---|---|---|---|---|---|
| `gateway-hpa` | 1 | 5 | 1 | CPU 50% | Normal |
| `langfuse-worker-hpa` | 2 | 10 | 3 | CPU 70%/Mem 80% | Elevated (memory at 90%) |

`langfuse-worker-hpa` remaining at 3 replicas is expected given the pre-existing memory pressure. This is a separate remediation item.

### 5.8 Pod Restart Count Baseline Comparison

```bash
# Capture restart counts for all pods post-deployment
kubectl get pods -n governance-stack \
  -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{range .status.containerStatuses[*]}{.restartCount}{"\t"}{end}{"\n"}{end}' \
  | sort
```

Compare against the pre-deployment baseline captured in Section 1.3.4. Any pod with a restart count significantly higher than baseline warrants investigation.

### 5.9 Image Tag Verification — Confirm New SHA is Running

```bash
SHORT_SHA=$(git rev-parse --short HEAD)
echo "Verifying running pods use SHA: ${SHORT_SHA}"

# Check that running pods reference the new image SHA
kubectl get pods -n governance-stack \
  -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.containers[0].image}{"\n"}{end}' \
  | grep -v "lula\|redis\|postgresql\|clickhouse\|langfuse" \
  | sort
```

**Expected**: All application pods (vllm, nemo, gateway, compliance-bridge, governed-financial-advisor, agentsight-ui) show images tagged with `:latest` (the SHA-tagged images are in GCR but deployments reference `:latest`).

### 5.10 Validation Checklist

| Check | Command | Expected Result | Status |
|---|---|---|---|
| All deployments at desired replicas | `kubectl get deployments -n governance-stack` | All READY = DESIRED | ☐ |
| `nemo-guardrails` at 2/2 | `kubectl get deployment nemo-guardrails -n governance-stack` | READY 2/2 | ☐ |
| `governed-financial-advisor` at 2/2 | `kubectl get deployment governed-financial-advisor -n governance-stack` | READY 2/2 | ☐ |
| `lula-sc4-watch` Running | `kubectl get pods -l app=lula-sc4-watch -n governance-stack` | 1/1 Running | ☐ |
| `lula-audit` manual run succeeds | `kubectl create job ... --from=cronjob/lula-audit` | Both ✅ markers in logs | ☐ |
| No CrashLoopBackOff | `kubectl get pods -n governance-stack` | No CrashLoopBackOff | ☐ |
| No OOMKilled events | `kubectl get events -n governance-stack --field-selector=reason=OOMKilling` | Empty | ☐ |
| Gateway HTTP 200 | `curl http://localhost:8080/health` | 200 OK | ☐ |
| Compliance bridge HTTP 200 | `curl http://localhost:3001/health` | 200 OK | ☐ |
| HPA stable | `kubectl get hpa -n governance-stack` | No unexpected scaling | ☐ |
| compliance trigger re-enabled | `gcloud builds triggers enable <trigger-name>` | `disabled: false` | ☐ |

---

## Section 6: Contingency Protocol — Full Rollback

### 6.1 Rollback Trigger Conditions

Initiate rollback if ANY of the following are observed:

| Condition | Observable State | Severity |
|---|---|---|
| CrashLoopBackOff on any application pod | `kubectl get pods -n governance-stack` shows `CrashLoopBackOff` | HIGH — rollback immediately |
| OOMKilled on any application pod | `kubectl get events` shows `OOMKilling` for new pods | HIGH — rollback immediately |
| `kubectl rollout status` times out | Exit code non-zero after `--timeout` | HIGH — rollback the timed-out wave |
| Gateway returns non-200 for >2 minutes | `curl /health` returns 5xx or connection refused | HIGH — rollback Wave 3+ |
| Compliance bridge health endpoint fails | `curl /health` returns non-200 | MEDIUM — rollback Wave 4+ |
| `lula-audit` manual test fails after Wave 4 | Logs show `❌ Ingest failed` | MEDIUM — investigate before rollback |
| HPA scales to max replicas unexpectedly | `kubectl get hpa` shows current = max | MEDIUM — investigate before rollback |

### 6.2 StatefulSet Protection

**EXPLICIT CONFIRMATION**: The following resources are **NEVER touched** during rollback or any other operation in this plan:

| Resource | Kind | Namespace | Protection Reason |
|---|---|---|---|
| `redis-master` | StatefulSet | `governance-stack` | Helm-managed, bound PVCs (10Gi + 3×8Gi) |
| `postgresql` | StatefulSet | `governance-stack` | Helm-managed, bound PVC (10Gi) |
| `clickhouse` | StatefulSet | `governance-stack` | Helm-managed, bound PVCs (2×10Gi) |

`kubectl rollout undo` on a StatefulSet with bound PVCs can cause data loss. These are explicitly excluded from all rollback commands below.

### 6.3 Rollback Sequence (Reverse Dependency Order: Wave 6 → Wave 1)

Execute rollback waves in reverse order. Stop at the wave where the issue was first observed.

#### Rollback Wave 6 — `agentsight-ui`

**Risk**: LOW

```bash
kubectl rollout undo deployment/agentsight-ui -n governance-stack
kubectl rollout status deployment/agentsight-ui -n governance-stack --timeout=5m
kubectl get pods -n governance-stack --selector=app=agentsight-ui -o wide
```

#### Rollback Wave 5 — `governed-financial-advisor`

**Risk**: LOW-MEDIUM

```bash
kubectl rollout undo deployment/governed-financial-advisor -n governance-stack
kubectl rollout status deployment/governed-financial-advisor -n governance-stack --timeout=5m
kubectl get pods -n governance-stack --selector=app=governed-financial-advisor -o wide
```

#### Rollback Wave 4 — `compliance-bridge`

**Risk**: MEDIUM (compliance evidence pipeline; lula-audit CronJob depends on this image)

```bash
kubectl rollout undo deployment/compliance-bridge -n governance-stack
kubectl rollout status deployment/compliance-bridge -n governance-stack --timeout=5m
kubectl get pods -n governance-stack --selector=app=compliance-bridge -o wide
```

**Note**: Rolling back `compliance-bridge` will revert to the pre-deployment `compliance-bridge:latest` image. If the CronJob failures (Issue 1) were caused by the old image, they will resume. This is acceptable — the CronJob issue must then be addressed via the targeted fixes in Section 2.3.

#### Rollback Wave 3 — `gateway`

**Risk**: HIGH (central traffic routing; rolling back will briefly disrupt all API traffic)

```bash
kubectl rollout undo deployment/gateway -n governance-stack
kubectl rollout status deployment/gateway -n governance-stack --timeout=5m
kubectl get pods -n governance-stack --selector=app=gateway -o wide

# Verify HPA returns to stable state
kubectl get hpa gateway-hpa -n governance-stack
```

#### Rollback Wave 2 — `nemo-guardrails` and `nemo-service`

**Risk**: MEDIUM

```bash
kubectl rollout undo deployment/nemo-guardrails -n governance-stack
kubectl rollout status deployment/nemo-guardrails -n governance-stack --timeout=5m

kubectl rollout undo deployment/nemo-service -n governance-stack
kubectl rollout status deployment/nemo-service -n governance-stack --timeout=5m

kubectl get pods -n governance-stack --selector=app=nemo-guardrails -o wide
kubectl get pods -n governance-stack --selector=app=nemo-service -o wide
```

**Note**: Rolling back `nemo-guardrails` will revert the replica count to 1/2 (pre-existing Issue 3 state). This is expected.

#### Rollback Wave 1 — `vllm-inference` and `vllm-reasoning`

**Risk**: MEDIUM (GPU node scheduling; Spot preemption risk during rollback)

```bash
kubectl rollout undo deployment/vllm-inference -n governance-stack
kubectl rollout status deployment/vllm-inference -n governance-stack --timeout=10m

kubectl rollout undo deployment/vllm-reasoning -n governance-stack
kubectl rollout status deployment/vllm-reasoning -n governance-stack --timeout=10m

kubectl get pods -n governance-stack --selector=app=vllm-inference -o wide
kubectl get pods -n governance-stack --selector=app=vllm-reasoning -o wide
```

### 6.4 Verify Return to Pre-Deployment Baseline Image Tags

After rollback, confirm each deployment is running the previous image revision:

```bash
# Check rollout history for each deployment
for DEPLOY in vllm-inference vllm-reasoning nemo-guardrails nemo-service gateway compliance-bridge governed-financial-advisor agentsight-ui; do
  echo "=== ${DEPLOY} ==="
  kubectl rollout history deployment/${DEPLOY} -n governance-stack
  echo "Current image: $(kubectl get deployment ${DEPLOY} -n governance-stack -o jsonpath='{.spec.template.spec.containers[0].image}')"
  echo ""
done
```

**Expected**: Each deployment shows revision N-1 as the current revision (where N was the revision created by the rolling update). The image tag should be `:latest` pointing to the pre-deployment digest.

To verify the exact image digest running:
```bash
for DEPLOY in vllm-inference vllm-reasoning nemo-guardrails nemo-service gateway compliance-bridge governed-financial-advisor agentsight-ui; do
  echo -n "${DEPLOY}: "
  kubectl get deployment ${DEPLOY} -n governance-stack \
    -o jsonpath='{.spec.template.spec.containers[0].image}'
  echo ""
done
```

### 6.5 Re-enable the `compliance-bridge` Standalone Trigger

After rollback (or after successful deployment), re-enable the trigger that was paused in Section 2.1:

```bash
gcloud builds triggers enable <trigger-name> \
  --project=laah-cybernetics

# Verify
gcloud builds triggers describe <trigger-name> \
  --project=laah-cybernetics \
  --format="value(disabled)"
# Expected: False
```

### 6.6 Escalation Path if Rollback Itself Fails

If `kubectl rollout undo` fails or a deployment is stuck in a bad state after rollback:

#### Level 1 — Force rollback to a specific revision

```bash
# List all revisions
kubectl rollout history deployment/<deployment-name> -n governance-stack

# Roll back to a specific known-good revision
kubectl rollout undo deployment/<deployment-name> \
  -n governance-stack \
  --to-revision=<N>
```

#### Level 2 — Force pod deletion to break a stuck rollout

```bash
# Delete all pods for the deployment — ReplicaSet will recreate from the current spec
kubectl delete pods -n governance-stack \
  --selector=app=<deployment-name> \
  --force \
  --grace-period=0
```

#### Level 3 — Patch the deployment image directly to a known-good SHA

```bash
# Use a previously verified SHA from GCR
KNOWN_GOOD_SHA=<previous-short-sha>

kubectl set image deployment/<deployment-name> \
  <container-name>=gcr.io/laah-cybernetics/<image-name>:${KNOWN_GOOD_SHA} \
  -n governance-stack

kubectl rollout status deployment/<deployment-name> \
  -n governance-stack \
  --timeout=5m
```

#### Level 4 — Re-apply the full manifest from git

```bash
# Check out the last known-good commit
git log --oneline -5

# Re-apply the deployment manifest (does NOT touch StatefulSets)
kubectl apply -f deployment/k8s/ \
  -n governance-stack \
  --dry-run=client  # preview first

kubectl apply -f deployment/k8s/ \
  -n governance-stack
```

#### Level 5 — Escalate to GKE cluster admin

If the cluster itself is in a degraded state (node failures, control plane issues):

```bash
# Check cluster status
gcloud container clusters describe cage-dev \
  --zone=us-central1-a \
  --project=laah-cybernetics \
  --format="value(status,currentNodeCount,currentMasterVersion)"

# Check node status
kubectl get nodes -o wide

# Check for cluster-level events
kubectl get events --all-namespaces \
  --sort-by=.lastTimestamp \
  | tail -20
```

Contact GKE support if nodes are `NotReady` and cannot be recovered via node pool repair.

---

## Appendix: Key File References

| File | Purpose |
|---|---|
| [`scripts/build_images.sh`](../scripts/build_images.sh) | Path B fan-out build script — 6 images in parallel |
| [`cloudbuild.compliance.yaml`](../cloudbuild.compliance.yaml) | Standalone compliance-bridge trigger — must be paused before Path B |
| [`deployment/docker/cloudbuild.lula.yaml`](../deployment/docker/cloudbuild.lula.yaml) | Lula image build — separate from Path B, hardcodes tag `0.9.0` |
| [`deployment/docker/cloudbuild.vllm.yaml`](../deployment/docker/cloudbuild.vllm.yaml) | vLLM streamer build — called by `build_images.sh`, uses E2_HIGHCPU_32 |
| [`deployment/k8s/lula-cron.yaml`](../deployment/k8s/lula-cron.yaml) | CronJob `lula-audit` + Deployment `lula-sc4-watch` manifests |
| [`deployment/k8s/network-policy.yaml`](../deployment/k8s/network-policy.yaml) | Calico NetworkPolicies — enforced (Cilium policies are NOT enforced) |
| [`src/compliance_bridge/Dockerfile`](../src/compliance_bridge/Dockerfile) | compliance-bridge image — built by both Path B and standalone trigger |
| [`src/gateway/Dockerfile`](../src/gateway/Dockerfile) | gateway image |
| [`src/agentsight-ui/Dockerfile`](../src/agentsight-ui/Dockerfile) | agentsight-ui image |

## Appendix: Risk Summary

| Action | Risk | Mitigation |
|---|---|---|
| Pause `cloudbuild.compliance.yaml` trigger | LOW | Re-enable immediately after build_images.sh completes |
| Build lula:0.9.0 image | LOW | Additive push; no existing state modified |
| Delete stuck lula-sc4-watch pod | LOW | ReplicaSet recreates immediately |
| Fix lula-audit CronJob | MEDIUM | Test with manual job before relying on scheduled run |
| Run `scripts/build_images.sh` | MEDIUM | All 6 builds parallel; one failure does not block others |
| Wave 1 vLLM rollout | MEDIUM | GPU Spot nodes; 10m timeout; rollback available |
| Wave 2 nemo rollout | MEDIUM | Depends on Wave 1; 5m timeout |
| Wave 3 gateway rollout | MEDIUM | Central routing; brief traffic disruption during pod swap |
| Wave 4 compliance-bridge rollout | MEDIUM | Compliance pipeline; lula-audit depends on this image |
| Wave 5 governed-financial-advisor rollout | LOW-MEDIUM | Application layer; depends on Wave 3+4 |
| Wave 6 agentsight-ui rollout | LOW | Stateless frontend |
| Full rollback | MEDIUM | Reverse order; StatefulSets explicitly excluded |

### Wave 5 — Application Layer

**Risk**: LOW-MEDIUM (also resolves Issue 3 replica shortfall for governed-financial-advisor)
**Deployment**: `governed-financial-advisor`
**Image**: `gcr.io/laah-cybernetics/governed-financial-advisor:latest` (updated by Path B)
**Timeout**: 5 minutes

```bash
# --- governed-financial-advisor ---
kubectl rollout restart deployment/governed-financial-advisor -n governance-stack
kubectl rollout status deployment/governed-financial-advisor -n governance-stack --timeout=5m

# Verify replica count reaches 2/2 (resolves Issue 3)
kubectl get deployment governed-financial-advisor -n governance-stack
# Expected: READY 2/2

kubectl get pods -n governance-stack \
  --selector=app=governed-financial-advisor \
  -o wide
```

**Health check criteria**:
- `governed-financial-advisor` shows `READY 2/2` — confirming Issue 3 replica shortfall is resolved
- No `CrashLoopBackOff` or `OOMKilled` events
- Pod logs show successful startup:
  ```bash
  kubectl logs -n governance-stack \
    -l app=governed-financial-advisor \
    --tail=30 \
    --since=2m
  ```

**Issue 3 resolution confirmation**:
```bash
kubectl get deployment governed-financial-advisor -n governance-stack \
  -o jsonpath='{.status.readyReplicas}/{.spec.replicas}'
# Expected: 2/2
```

**Wave 5 → Wave 6 gate**: `governed-financial-advisor` must be `READY 2/2`.

---

### Wave 6 — Frontend

**Risk**: LOW (stateless frontend; no persistent state)
**Deployment**: `agentsight-ui`
**Image**: `gcr.io/laah-cybernetics/agentsight-ui:latest` (updated by Path B)
**Timeout**: 5 minutes

```bash
# --- agentsight-ui ---
kubectl rollout restart deployment/agentsight-ui -n governance-stack
kubectl rollout status deployment/agentsight-ui -n governance-stack --timeout=5m

# Health check
kubectl get deployment agentsight-ui -n governance-stack
kubectl get pods -n governance-stack --selector=app=agentsight-ui -o wide

# Verify the UI is serving
AGESIGHT_POD=$(kubectl get pods -n governance-stack \
  --selector=app=agentsight-ui \
  -o jsonpath='{.items[0].metadata.name}')

kubectl exec ${AGESIGHT_POD} -n governance-stack -- \
  curl -s -o /dev/null -w "%{http_code}" http://localhost:80/
# Expected: 200
```

**Health check criteria**:
- `agentsight-ui` deployment `READY` at desired replica count
- HTTP 200 from the UI container's port 80
- No `CrashLoopBackOff` events

---

### Wave Summary Table

| Wave | Deployments | Image | Risk | Timeout | Issue Resolved |
|---|---|---|---|---|---|
| 1 | `vllm-inference`, `vllm-reasoning` | `vllm-streamer:latest` | MEDIUM | 10m | — |
| 2 | `nemo-guardrails`, `nemo-service` | `nemo-guardrails:latest` | MEDIUM | 5m | Issue 3 (nemo 1→2) |
| 3 | `gateway` | `gateway:latest` | MEDIUM | 5m | — |
| 4 | `compliance-bridge` | `compliance-bridge:latest` | MEDIUM | 5m | Issue 1 (if image was root cause) |
| 5 | `governed-financial-advisor` | `governed-financial-advisor:latest` | LOW-MEDIUM | 5m | Issue 3 (gfa 1→2) |
| 6 | `agentsight-ui` | `agentsight-ui:latest` | LOW | 5m | — |

---

### 2.2 Issue 2 — Build and Push the Lula Image, Then Patch the Deployment

**Risk**: MEDIUM
**Dependency rationale**: Must be resolved BEFORE running `scripts/build_images.sh`. The lula image is built via a separate path (`deployment/docker/cloudbuild.lula.yaml`) and is not included in the Path B fan-out. Resolving this now ensures `lula-sc4-watch` is healthy before the rolling update begins.

**Critical observation**: [`deployment/docker/cloudbuild.lula.yaml`](../deployment/docker/cloudbuild.lula.yaml) hardcodes the tag as `0.9.0` — it does not use `$SHORT_SHA`. This means the build will push exactly `us-central1-docker.pkg.dev/laah-cybernetics/governance-stack/lula:0.9.0`, which is the tag the deployment already references. No manifest patch is needed if the build succeeds.

#### Action 2.2.1 — Build and push the lula image

```bash
# Run from project root
gcloud builds submit . \
  --config=deployment/docker/cloudbuild.lula.yaml \
  --project=laah-cybernetics
```

**Expected output**: `SUCCESS` with image pushed to `us-central1-docker.pkg.dev/laah-cybernetics/governance-stack/lula:0.9.0`.

**Rollback**: No rollback needed — this is an additive push of a new image tag. If the build fails, the deployment remains in its current state (old replica running, new replica in ImagePullBackOff).

#### Action 2.2.2 — Verify the image tag now exists

```bash
gcloud artifacts docker images list \
  us-central1-docker.pkg.dev/laah-cybernetics/governance-stack/lula \
  --project=laah-cybernetics \
  --include-tags \
  --filter="tags:0.9.0" \
  --format="table(package,tags,createTime)"
# Expected: one row with tags=0.9.0
```

#### Action 2.2.3 — Force the failing pod to re-pull (delete the backoff pod)

Once the image exists, Kubernetes will eventually retry, but deleting the stuck pod accelerates recovery:

```bash
kubectl delete pod lula-sc4-watch-5bfdcb7bd4-drnls -n governance-stack
```

The ReplicaSet will immediately create a replacement pod that will successfully pull `lula:0.9.0`.

**Rollback** (if new pod also fails):
```bash
# Patch to a known-good tag identified in step 1.2.1
kubectl set image deployment/lula-sc4-watch \
  lula-watch=us-central1-docker.pkg.dev/laah-cybernetics/governance-stack/lula:<known-good-tag> \
  -n governance-stack
```

**Success criteria**:
```bash
kubectl get pods -n governance-stack \
  --selector=app=lula-sc4-watch \
  -o wide
# Expected: 1/1 Running, no ImagePullBackOff
```

---

### 2.3 Issue 1 — Diagnose and Fix the `lula-audit` CronJob

**Risk**: MEDIUM
**Dependency rationale**: Fix after Issue 2 because the CronJob uses `gcr.io/laah-cybernetics/compliance-bridge:latest` — if the compliance-bridge image is stale or missing, the CronJob will continue to fail. The Path B build (Section 3) will push a fresh `compliance-bridge:latest`, which may itself resolve the CronJob failures. Diagnose first; apply targeted fix based on root cause found in Section 1.1.

#### Root Cause Decision Tree

```
CronJob pod logs show:
├── ErrImagePull / ImagePullBackOff
│   └── compliance-bridge:latest missing → resolved by Path B build (Section 3)
├── CreateContainerConfigError
│   └── langfuse-compliance-secrets missing → Action 2.3.A
├── ModuleNotFoundError (Python import)
│   └── compliance-bridge image is stale → resolved by Path B build (Section 3)
├── asyncio.TimeoutError / ConnectionRefusedError
│   └── compliance-bridge Service unreachable → Action 2.3.B
├── Ingest failed (non-ok status from audit_workflow)
│   └── Langfuse API key invalid or quota exceeded → Action 2.3.C
└── OOMKilled
    └── 256Mi limit exceeded → Action 2.3.D
```

#### Action 2.3.A — If Secret is missing: create it

```bash
# Verify which keys are needed (from lula-cron.yaml envFrom secretRef)
# Required keys: LANGFUSE_PUBLIC_KEY, LANGFUSE_SECRET_KEY, LANGFUSE_HOST,
#                GCS_BUCKET_NAME, GOOGLE_CLOUD_PROJECT (at minimum)

kubectl create secret generic langfuse-compliance-secrets \
  -n governance-stack \
  --from-literal=LANGFUSE_PUBLIC_KEY=<value> \
  --from-literal=LANGFUSE_SECRET_KEY=<value> \
  --from-literal=LANGFUSE_HOST=<value> \
  --from-literal=GCS_BUCKET_NAME=<value> \
  --from-literal=GOOGLE_CLOUD_PROJECT=laah-cybernetics
```

**Rollback**:
```bash
kubectl delete secret langfuse-compliance-secrets -n governance-stack
```

#### Action 2.3.B — If compliance-bridge Service is unreachable: verify Service and NetworkPolicy

```bash
# Check the Service exists and has endpoints
kubectl get service compliance-bridge -n governance-stack
kubectl get endpoints compliance-bridge -n governance-stack

# Verify NetworkPolicy allows lula pod egress to compliance-bridge
kubectl get networkpolicy -n governance-stack \
  --selector=app=lula
```

The CronJob design comment in [`deployment/k8s/lula-cron.yaml`](../deployment/k8s/lula-cron.yaml) line 133 notes that `allow-lula-egress-to-compliance-bridge` permits egress to `10.96.0.0/12` on port 80. If this NetworkPolicy is missing, the CronJob cannot reach the compliance-bridge.

#### Action 2.3.C — If Langfuse ingest fails: test the API key

```bash
# Trigger a manual job to test with verbose output
kubectl create job lula-audit-manual-test \
  --from=cronjob/lula-audit \
  -n governance-stack

# Watch the job
kubectl logs -f -n governance-stack \
  -l job-name=lula-audit-manual-test
```

#### Action 2.3.D — If OOMKilled: patch memory limit

```bash
# Increase memory limit from 256Mi to 512Mi
kubectl patch cronjob lula-audit -n governance-stack \
  --type=json \
  -p='[{"op":"replace","path":"/spec/jobTemplate/spec/template/spec/containers/0/resources/limits/memory","value":"512Mi"},{"op":"replace","path":"/spec/jobTemplate/spec/template/spec/containers/0/resources/requests/memory","value":"384Mi"}]'
```

**Rollback**:
```bash
kubectl patch cronjob lula-audit -n governance-stack \
  --type=json \
  -p='[{"op":"replace","path":"/spec/jobTemplate/spec/template/spec/containers/0/resources/limits/memory","value":"512Mi"},{"op":"replace","path":"/spec/jobTemplate/spec/template/spec/containers/0/resources/requests/memory","value":"256Mi"}]'
```

#### Action 2.3.E — Trigger a manual test run after fix

```bash
kubectl create job lula-audit-post-fix-test \
  --from=cronjob/lula-audit \
  -n governance-stack

# Wait for completion
kubectl wait job/lula-audit-post-fix-test \
  -n governance-stack \
  --for=condition=complete \
  --timeout=5m

# Check result
kubectl logs -n governance-stack \
  -l job-name=lula-audit-post-fix-test
```

**Success criteria**: Logs contain both:
- `✅ Lula audit complete.`
- `✅ OSCAL results ingested into Langfuse compliance project.`

---

### 2.4 Issue 3 — Replica Shortfalls

**Risk**: LOW
**Dependency rationale**: `governed-financial-advisor` and `nemo-guardrails` replica shortfalls will be **automatically resolved** by the rolling update in Section 4 — new pods will be scheduled as part of the rollout. No pre-emptive action is required for these two.

`langfuse-worker` memory pressure is a **separate concern** not addressed by the Path B rollout (the `langfuse-worker` image is not built by `scripts/build_images.sh`). It requires independent investigation.

#### Action 2.4.A — Investigate `langfuse-worker` memory pressure (non-blocking)

```bash
# Check current memory usage per pod
kubectl top pods -n governance-stack \
  --selector=app.kubernetes.io/name=langfuse-worker

# Check for OOMKilled events
kubectl get events -n governance-stack \
  --field-selector=reason=OOMKilling \
  --sort-by=.lastTimestamp

# Check HPA current state
kubectl describe hpa langfuse-worker-hpa -n governance-stack
```

**Note**: Do NOT modify the `langfuse-worker` HPA or StatefulSet as part of this deployment. Document findings for a separate remediation ticket.

---

## Section 3: Integration of `scripts/build_images.sh` with Pre-flight Sequence

### 3.1 What `scripts/build_images.sh` Builds (and Does NOT Build)

| Image | Registry | Built by `build_images.sh`? | Build Config |
|---|---|---|---|
| `governed-financial-advisor` | `gcr.io/laah-cybernetics/` | ✅ Yes | Inline in script (lines 88–125) |
| `vllm-streamer` | `gcr.io/laah-cybernetics/` | ✅ Yes | [`deployment/docker/cloudbuild.vllm.yaml`](../deployment/docker/cloudbuild.vllm.yaml) |
| `gateway` | `gcr.io/laah-cybernetics/` | ✅ Yes | [`src/gateway/Dockerfile`](../src/gateway/Dockerfile) via `build_image()` |
| `agentsight-ui` | `gcr.io/laah-cybernetics/` | ✅ Yes | [`src/agentsight-ui/Dockerfile`](../src/agentsight-ui/Dockerfile) via `build_image()` |
| `compliance-bridge` | `gcr.io/laah-cybernetics/` | ✅ Yes | [`src/compliance_bridge/Dockerfile`](../src/compliance_bridge/Dockerfile) via `build_image()` |
| `nemo-guardrails` | `gcr.io/laah-cybernetics/` | ✅ Yes | `Dockerfile.nemo` via `build_image()` |
| `lula` | `us-central1-docker.pkg.dev/laah-cybernetics/governance-stack/` | ❌ **NO** | [`deployment/docker/cloudbuild.lula.yaml`](../deployment/docker/cloudbuild.lula.yaml) — **separate step** |

**Critical**: The lula `ImagePullBackOff` (Issue 2) MUST be resolved via `cloudbuild.lula.yaml` BEFORE running `build_images.sh`. The script has no knowledge of the lula image.

### 3.2 SHA Tagging Behavior

[`scripts/build_images.sh`](../scripts/build_images.sh) line 27 captures the git SHA once at script start:

```bash
SHORT_SHA="$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")"
```

Every image built by the script receives two tags:
- `:latest` — mutable, always updated
- `:<SHORT_SHA>` — immutable, audit-traceable

The vLLM build via [`deployment/docker/cloudbuild.vllm.yaml`](../deployment/docker/cloudbuild.vllm.yaml) uses Cloud Build's native `$SHORT_SHA` substitution, which is set by the `gcloud builds submit` invocation and will match the local SHA since the script passes the same commit context.

**Exception**: `governed-financial-advisor` pushes to BOTH `gcr.io/.../financial-advisor` AND `gcr.io/.../governed-financial-advisor` (lines 97–117 of [`scripts/build_images.sh`](../scripts/build_images.sh)) — both registries receive `:latest` and `:<SHORT_SHA>` tags.

### 3.3 Required Environment Variables

| Variable | Required | Source | Notes |
|---|---|---|---|
| `PROJECT_ID` | ✅ Mandatory | Shell env | Script exits immediately if unset (line 18–21) |
| `HUGGING_FACE_HUB_TOKEN` or `HF_TOKEN` | ⚠️ Conditional | Shell env | Required for gated HuggingFace models; script checks both (line 131) |

```bash
# Set before running build_images.sh
export PROJECT_ID=laah-cybernetics
export HUGGING_FACE_HUB_TOKEN=hf_xxxxxxxxxxxxxxxxxxxx  # if needed for vLLM
```

### 3.4 Complete Pre-flight Sequence

```
Step A: Verify/pause cloudbuild.compliance.yaml trigger (Issue 4)
    ↓
Step B: Build and push lula:0.9.0 image (Issue 2)
    ↓
Step C: Delete stuck lula-sc4-watch pod to force re-pull (Issue 2)
    ↓
Step D: Diagnose and fix lula-audit CronJob root cause (Issue 1)
    ↓
Step E: Run scripts/build_images.sh (Path B fan-out — 6 images)
    ↓
Step F: Verify all 6 images pushed successfully
    ↓
Section 4: Rolling update sequence
```

### 3.5 Running `scripts/build_images.sh`

```bash
# From project root
export PROJECT_ID=laah-cybernetics
export HUGGING_FACE_HUB_TOKEN=hf_xxxxxxxxxxxxxxxxxxxx  # omit if not needed

bash scripts/build_images.sh
```

The script fires all 6 builds in parallel as background `gcloud builds submit` processes, then waits for all PIDs. Build logs are written to `/tmp/build_<image>.log` on the local machine.

**Monitor progress** (in a separate terminal):
```bash
# Watch all active Cloud Build jobs
watch -n 30 "gcloud builds list \
  --project=laah-cybernetics \
  --filter='status=WORKING' \
  --format='table(id,status,substitutions.SHORT_SHA,createTime,logUrl)'"
```

### 3.6 Verify All 6 Images Were Successfully Pushed

```bash
SHORT_SHA=$(git rev-parse --short HEAD)
echo "Verifying images for SHA: ${SHORT_SHA}"

for IMAGE in \
  governed-financial-advisor \
  financial-advisor \
  vllm-streamer \
  gateway \
  agentsight-ui \
  compliance-bridge \
  nemo-guardrails; do
  echo -n "Checking gcr.io/laah-cybernetics/${IMAGE}:${SHORT_SHA} ... "
  gcloud container images describe \
    "gcr.io/laah-cybernetics/${IMAGE}:${SHORT_SHA}" \
    --project=laah-cybernetics \
    --format="value(image_summary.digest)" 2>/dev/null \
    && echo "✅ EXISTS" || echo "❌ MISSING"
done
```

**Success criteria**: All 7 lines (including `financial-advisor` alias) show `✅ EXISTS`.

**If any image is missing**: Check the corresponding log file:
```bash
cat /tmp/build_<image_name>.log
# e.g.:
cat /tmp/build_backend.log      # governed-financial-advisor
cat /tmp/build_vllm.log         # vllm-streamer
cat /tmp/build_gateway.log      # gateway
cat /tmp/build_agentsight-ui.log
cat /tmp/build_compliance-bridge.log
cat /tmp/build_nemo-guardrails.log
```

---

### 1.3 Issue 3 — Replica Shortfalls

**Risk**: LOW (read-only)

#### Step 1.3.1 — Check `governed-financial-advisor` replica shortfall

```bash
kubectl describe deployment governed-financial-advisor -n governance-stack
```

**Look for**:
- `Replicas: 2 desired | 1 updated | 1 ready` — confirms shortfall
- `Events`: `FailedCreate` → resource quota or node pressure
- `Events`: `Insufficient cpu/memory` → scheduling failure

```bash
# Check the non-ready pod
kubectl get pods -n governance-stack \
  --selector=app=governed-financial-advisor \
  -o wide

# Get events for any pending/failed pod
PENDING_POD=$(kubectl get pods -n governance-stack \
  --selector=app=governed-financial-advisor \
  --field-selector=status.phase!=Running \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)

if [[ -n "$PENDING_POD" ]]; then
  kubectl describe pod ${PENDING_POD} -n governance-stack
fi
```

#### Step 1.3.2 — Check `nemo-guardrails` replica shortfall

```bash
kubectl describe deployment nemo-guardrails -n governance-stack

kubectl get pods -n governance-stack \
  --selector=app=nemo-guardrails \
  -o wide
```

**Look for**: Same patterns as above. `nemo-guardrails` may be on GPU nodes — check for `Insufficient nvidia.com/gpu` in events.

#### Step 1.3.3 — Check `langfuse-worker` memory pressure

```bash
# Check HPA state
kubectl describe hpa langfuse-worker-hpa -n governance-stack

# Check current memory usage
kubectl top pods -n governance-stack \
  --selector=app.kubernetes.io/name=langfuse-worker \
  --sort-by=memory
```

**Expected**: Memory at ~90% vs 80% HPA target → HPA has already scaled to 3 replicas. The 3rd replica may be pending if nodes are under pressure.

#### Step 1.3.4 — Cluster-wide resource snapshot

```bash
# Pod-level resource usage across governance-stack
kubectl top pods -n governance-stack --sort-by=memory

# Node-level resource usage
kubectl top nodes

# Check for any Pending pods across all namespaces
kubectl get pods --all-namespaces \
  --field-selector=status.phase=Pending
```

---

### 1.4 Issue 4 — `compliance-bridge` Dual Build Path Race Condition

**Risk**: LOW (read-only)

#### Step 1.4.1 — List all Cloud Build triggers and identify the compliance trigger

```bash
gcloud builds triggers list \
  --project=laah-cybernetics \
  --format="table(name,filename,disabled,createTime)"
```

**Look for**: Any trigger with `filename=cloudbuild.compliance.yaml`. Note its `name` and `disabled` state.

#### Step 1.4.2 — Describe the specific compliance trigger

```bash
# Replace <trigger-name> with the name found in step 1.4.1
gcloud builds triggers describe <trigger-name> \
  --project=laah-cybernetics
```

**Look for**:
- `disabled: false` → trigger is active and will fire on push events
- `github.push.branch` or `pubsub` → what event fires it
- `substitutions._SHORT_SHA` → how it computes the SHA (Cloud Build native vs. manual)

#### Step 1.4.3 — Check for any currently in-progress builds

```bash
gcloud builds list \
  --project=laah-cybernetics \
  --filter="status=WORKING" \
  --limit=10 \
  --format="table(id,status,source.repoSource.repoName,substitutions.SHORT_SHA,createTime)"
```

**Expected**: No builds in `WORKING` state. If any are running against `compliance-bridge`, **do not proceed** until they complete.

#### Step 1.4.4 — Verify the race condition risk

The race condition exists because:
- [`cloudbuild.compliance.yaml`](../cloudbuild.compliance.yaml) uses Cloud Build's native `$SHORT_SHA` substitution
- [`scripts/build_images.sh`](../scripts/build_images.sh) line 27 computes `SHORT_SHA="$(git rev-parse --short HEAD)"` locally

If both fire within the same build window, they may produce different SHA values and race to push `compliance-bridge:latest`, resulting in non-deterministic image state.

```bash
# Confirm the local SHA that build_images.sh would use
git rev-parse --short HEAD
```

Compare this to the `SHORT_SHA` in any active Cloud Build trigger output.

---
