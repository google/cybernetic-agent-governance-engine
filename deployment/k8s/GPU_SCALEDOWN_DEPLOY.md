# GPU Scale-to-Zero Deployment Runbook — CAGE Dev

> **Cluster:** `governance-cluster-2`, zone `us-central1-a`
> **Changes in scope:**
> 1. **Terraform** — `infra/targets/gcp-gke/dev.tfvars`: `gpu_node_pool_min_count` `1` → `0`
> 2. **Kubernetes** — `deployment/k8s/vllm-idle-scaler.yaml`: net-new idle-detection CronJob resources
>
> **Do NOT run any of these commands on the prod cluster.** Every step below targets
> the dev cluster only. Confirm your context in Section 1 before proceeding.

---

## Table of Contents

1. [Pre-flight Checks](#section-1--pre-flight-checks)
2. [Terraform Drift Remediation + Plan](#section-2--terraform-drift-remediation--plan)
3. [Deploy Kubernetes Idle-Scaler Resources](#section-3--deploy-kubernetes-idle-scaler-resources)
4. [Smoke Test the Idle-Scaler](#section-4--smoke-test-the-idle-scaler)
5. [Rollback Procedure](#section-5--rollback-procedure)
6. [Post-Deployment Monitoring](#section-6--post-deployment-monitoring)

---

## Section 1 — Pre-flight Checks

Run each command and verify the expected output before proceeding. Do not continue
if any check fails.

### 1.1 — Confirm kubectl context is dev, not prod

```bash
kubectl config current-context
```

**Expected:** output matches `gke_*_governance-cluster-2` (contains `governance-cluster-2`).

> ⚠️ **STOP** if the context name contains `prod`, `production`, or references any
> cluster other than `governance-cluster-2`. Run `kubectl config use-context <dev-context>`
> to switch, or `kubectl config get-contexts` to list available contexts.

### 1.2 — Confirm current GPU node count

```bash
kubectl get nodes -l cloud.google.com/gke-accelerator=nvidia-l4
```

**Expected:** one node listed (the single L4 GPU node currently kept alive by
`gpu_node_pool_min_count=1`). Record the node name for comparison after Section 6.

### 1.3 — Confirm both vLLM Deployments exist and are running

```bash
kubectl get deployment -n vllm-inference vllm-inference vllm-reasoning -o wide
```

**Expected:** both deployments listed, `READY` column shows `1/1` for each.

> ⚠️ If either Deployment shows `0/1` READY, investigate before proceeding — the
> idle-scaler smoke test in Section 4 assumes both Deployments are healthy at
> deployment time.

### 1.4 — List all node pools on the cluster

```bash
gcloud container clusters describe governance-cluster-2 \
  --zone us-central1-a \
  --format="value(nodePools[].name)"
```

**Expected:** output includes `gpu-node-pool-nvidia-l4` alongside the primary CPU pool.
Record the exact pool name — it is referenced in Terraform state.

---

## Section 2 — Terraform Drift Remediation + Plan

> ⚠️ **Read the drift warning in [`infra/targets/gcp-gke/README.md`](../../infra/targets/gcp-gke/README.md)
> in full before this section.** The live GPU node pool was switched from Spot → on-demand
> out-of-band via `gcloud` (P0 fix, 2026-08-03). A `lifecycle.ignore_changes` guard is in
> place in [`infra/modules/gcp_gke_cluster/main.tf`](../../infra/modules/gcp_gke_cluster/main.tf),
> but unexpected drift may still appear. The plan review in step 2.3 is mandatory.

### 2.1 — Change to the GCP-GKE Terraform target directory

```bash
cd infra/targets/gcp-gke
```

### 2.2 — Initialise Terraform (only required if `.terraform/` is absent or providers changed)

```bash
terraform init
```

Skip this step if you have already initialised this workspace in the current session.

### 2.3 — Generate and save the plan

```bash
terraform plan -var-file=dev.tfvars -out=gpu-scaledown.tfplan
```

### 2.4 — Review the plan output — STOP condition applies

Inspect the plan output carefully before proceeding. A **safe plan** shows exactly:

```
~ resource "google_container_node_pool" "gpu_nodes" {
    ...
    ~ min_node_count = 1 -> 0
    ...
  }
```

> ⚠️ **STOP and do NOT apply** if the plan output shows **any** of the following:
>
> | Dangerous signal | What it means | Action |
> |---|---|---|
> | `spot` or `preemptible` changes | Would revert on-demand fix | Run `terraform state list \| grep gpu` and inspect |
> | `machine_type` changes | Would alter node hardware | Investigate before applying |
> | `node_config` block replacement | Possible node pool destruction | **Do not apply** — escalate |
> | `forces replacement` on the GPU pool | Node pool will be deleted and recreated | **Do not apply** — escalate |
> | Any change unrelated to `gpu_node_pool_min_count` | Unexpected drift in state | Run `terraform state list \| grep gpu` and compare |
>
> If unexpected drift is detected, remediate manually with `gcloud container node-pools update`
> to align the live pool with the desired state, then re-run the plan, before applying.

### 2.5 — Review the full saved plan (human-readable)

```bash
terraform show gpu-scaledown.tfplan
```

Confirm the diff is limited to `min_node_count: 1 → 0` on the GPU pool.

### 2.6 — Apply the plan

> ⚠️ This is a live infrastructure change. The GKE cluster autoscaler will be
> permitted to drain and remove the GPU node once all GPU pods are gone. Apply
> only after confirming the plan in steps 2.3–2.5.

```bash
terraform apply gpu-scaledown.tfplan
```

**Expected output:** `Apply complete! Resources: 0 added, 1 changed, 0 destroyed.`
(one change: the GPU node pool autoscaling `min_node_count` attribute).

After apply, the GPU node itself will **not** be immediately removed — the autoscaler
only removes it once all GPU pods are evicted. The idle-scaler CronJobs deployed in
Section 3 are responsible for scaling vLLM Deployments to 0, which triggers node drain.

---

## Section 3 — Deploy the Idle-Scaler Kubernetes Resources

The manifest [`deployment/k8s/vllm-idle-scaler.yaml`](vllm-idle-scaler.yaml) is
net-new (no existing resources will be updated or deleted). It creates 7 resources
in the `vllm-inference` namespace.

### 3.1 — Apply the manifest

Run this from the **repository root** (not from `infra/targets/gcp-gke`):

```bash
kubectl apply -f deployment/k8s/vllm-idle-scaler.yaml
```

**Expected output** (7 resources created):

```
configmap/vllm-idle-tracker created
serviceaccount/vllm-scaler-sa created
role.rbac.authorization.k8s.io/vllm-scaler-role created
rolebinding.rbac.authorization.k8s.io/vllm-scaler-rolebinding created
cronjob.batch/vllm-idle-detector created
cronjob.batch/vllm-wakeup-checker created
cronjob.batch/vllm-morning-wakeup created
```

### 3.2 — Verify all 7 resources were created

```bash
kubectl get configmap,serviceaccount,role,rolebinding,cronjob \
  -n vllm-inference \
  -l app=vllm-idle-scaler
```

**Expected:** 7 rows — one per resource listed above. All CronJobs should show a
`SCHEDULE` column and `SUSPEND` = `False`.

> ⚠️ If fewer than 7 resources appear, check for apply errors by re-running
> `kubectl apply -f deployment/k8s/vllm-idle-scaler.yaml` (idempotent) and
> reviewing the output line by line.

---

## Section 4 — Smoke Test the Idle-Scaler

The smoke test manually triggers the `vllm-idle-detector` CronJob to verify it can
reach the vLLM metrics endpoint, read/write the ConfigMap, and correctly identify
the cluster as **active** (not idle) immediately after deployment.

### 4.1 — Manually trigger the idle-detector

```bash
kubectl create job -n vllm-inference --from=cronjob/vllm-idle-detector vllm-idle-test-$(date +%s)
```

**Expected:** `job.batch/vllm-idle-test-<timestamp> created`

### 4.2 — Wait 30 seconds, then check job logs

```bash
kubectl logs -n vllm-inference -l cage.io/cronjob=vllm-idle-detector --tail=50
```

**Expected log output** (first-run bootstrap path):

```
=== vLLM Idle Detector — <timestamp> ===
[1/4] Scraping metrics from: http://vllm-inference.vllm-inference.svc.cluster.local:8000/metrics
    vllm:request_success_total = <N>
[2/4] Reading idle-tracker ConfigMap...
    stored baseline = 0
    last_active     = <not set>
[3/4] Evaluating activity...
ℹ️  Bootstrap: setting last_active to now (first run). No scale action.
```

If the metrics endpoint is reachable and `last_active` was previously empty, the
job exits with the bootstrap path. No scale-down will occur on this first run.

> ⚠️ If you see `⚠️  Could not reach vLLM metrics endpoint`, confirm the vLLM
> Deployment is running (`kubectl get pods -n vllm-inference`) and that the Service
> `vllm-inference` exists in namespace `vllm-inference`
> (`kubectl get svc -n vllm-inference`).

### 4.3 — Verify the ConfigMap was populated

```bash
kubectl get configmap -n vllm-inference vllm-idle-tracker -o yaml
```

**Expected:** `data.last_active` is now set to a Unix epoch timestamp (non-empty
string), and `data.request_baseline` reflects the counter value read from the
metrics endpoint.

### 4.4 — Confirm no premature scale-down occurred

```bash
kubectl get deployment -n vllm-inference vllm-inference vllm-reasoning
```

**Expected:** both Deployments still show `READY 1/1`. The smoke-test job sets
`last_active` to the current time, so the 2-hour idle threshold is not reached
and no scale action is triggered.

---

## Section 5 — Rollback Procedure

Use these steps if anything goes wrong after applying. All rollback operations are
safe to run at any time.

### 5.1 — Terraform rollback (restore `gpu_node_pool_min_count = 1`)

> ⚠️ Only run this if you need to restore the guaranteed minimum GPU node count.
> After rollback, the GPU node will no longer be eligible for autoscaler removal.

Revert `infra/targets/gcp-gke/dev.tfvars` line 61 to:

```hcl
gpu_node_pool_min_count     = 1
```

Then re-apply from the Terraform target directory:

```bash
cd infra/targets/gcp-gke
terraform plan -var-file=dev.tfvars -out=gpu-scaledown-rollback.tfplan
terraform show gpu-scaledown-rollback.tfplan   # confirm: min_node_count 0 -> 1
terraform apply gpu-scaledown-rollback.tfplan
```

### 5.2 — Kubernetes rollback (remove idle-scaler resources)

```bash
kubectl delete -f deployment/k8s/vllm-idle-scaler.yaml
```

**Expected:** 7 resources deleted. This is safe to run even if the CronJob is
currently executing a job — in-flight jobs will complete before the resources are
fully removed (Kubernetes garbage collection).

### 5.3 — Force scale-up if vLLM was prematurely scaled to 0

> ⚠️ Only run this if both vLLM Deployments were scaled to 0 unintentionally
> (e.g., the idle-detector fired sooner than expected). GPU node provisioning
> takes ~10 minutes after pods are scheduled; model loading takes a further 2–5
> minutes.

```bash
kubectl scale deployment -n vllm-inference vllm-inference vllm-reasoning --replicas=1
```

Verify recovery:

```bash
kubectl get pods -n vllm-inference -w
```

Wait until both `vllm-inference-*` and `vllm-reasoning-*` pods reach `Running` status.

---

## Section 6 — Post-Deployment Monitoring

After the idle-scaler is deployed, the first automatic scale-down will occur once
2 hours of consecutive idle time are detected (i.e., no increase in
`vllm:request_success_total`). GPU node drain follows ~10 minutes after both
Deployments reach 0 replicas.

Use the following commands to watch for successful scale-down on the next idle cycle.

### 6.1 — Watch GPU node removal (updates every 30 s)

```bash
watch -n30 kubectl get nodes -l cloud.google.com/gke-accelerator=nvidia-l4
```

A successful scale-down cycle ends with this command returning `No resources found`.

### 6.2 — Watch vLLM Deployment replica counts (updates every 30 s)

```bash
watch -n30 kubectl get deployment -n vllm-inference vllm-inference vllm-reasoning
```

Expect `READY 0/0` when the idle-detector has scaled both Deployments to 0.

### 6.3 — Follow idle-detector logs in real time

```bash
kubectl logs -n vllm-inference -l cage.io/cronjob=vllm-idle-detector --follow
```

The CronJob fires every 15 minutes. Each run logs the current counter, idle
duration, and the action taken (or not taken).

### 6.4 — Expected scale-down log message

When the 2-hour threshold is exceeded, the idle-detector logs:

```
🔻 SCALE TO ZERO: idle 120 min ≥ 120 min threshold.
   Scaling vllm-inference → 0...
   Scaling vllm-reasoning → 0...
✅ Both vLLM Deployments scaled to 0. GPU node drain will follow in ~10 min.
```

### 6.5 — Expected morning wake-up (daily 06:00 UTC)

The `vllm-morning-wakeup` CronJob fires at 06:00 UTC every day and unconditionally
scales both Deployments back to 1 replica. To verify it is scheduled:

```bash
kubectl get cronjob -n vllm-inference vllm-morning-wakeup -o wide
```

**Expected:** `SCHEDULE` = `0 6 * * *`, `SUSPEND` = `False`.

---

## Resource Inventory

| Resource | Kind | Namespace | Purpose |
|---|---|---|---|
| `vllm-idle-tracker` | ConfigMap | `vllm-inference` | Idle-detection state store |
| `vllm-scaler-sa` | ServiceAccount | `vllm-inference` | CronJob identity |
| `vllm-scaler-role` | Role | `vllm-inference` | Least-privilege RBAC |
| `vllm-scaler-rolebinding` | RoleBinding | `vllm-inference` | Binds SA to Role |
| `vllm-idle-detector` | CronJob | `vllm-inference` | Polls metrics every 15 min; scales to 0 after 2h idle |
| `vllm-wakeup-checker` | CronJob | `vllm-inference` | Polls Redis every 5 min; scales up on pending requests |
| `vllm-morning-wakeup` | CronJob | `vllm-inference` | Daily 06:00 UTC safety-net scale-up |

---

## Related Documents

- [`infra/targets/gcp-gke/dev.tfvars`](../../infra/targets/gcp-gke/dev.tfvars) — Terraform variable source (GPU pool config)
- [`infra/targets/gcp-gke/README.md`](../../infra/targets/gcp-gke/README.md) — Drift remediation background
- [`infra/modules/gcp_gke_cluster/main.tf`](../../infra/modules/gcp_gke_cluster/main.tf) — `lifecycle.ignore_changes` guard location
- [`deployment/k8s/vllm-idle-scaler.yaml`](vllm-idle-scaler.yaml) — Full annotated manifest
- [`docs/operations/DEPLOYMENT_RULES.md`](../../docs/operations/DEPLOYMENT_RULES.md) — Deployment policy (Terraform + Cloud Build rules)
