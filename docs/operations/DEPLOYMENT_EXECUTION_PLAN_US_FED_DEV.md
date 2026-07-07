# CAGE Deployment Execution Plan — US_FED / Dev / GCP GKE

> **Classification:** Cat-S (Standard) — Pre-approved for dev cluster deployments  
> **Jurisdiction:** US_FED (`CAGE_DEPLOYMENT_REGION=US_FED`)  
> **Posture:** dev (`enable_nist_compliance=false`)  
> **Cluster:** `<your-cluster-name>` · Project: `<your-project-id>` · Zone: `us-central1-a`  
> **Document date:** 2026-07-04  
> **Authority:** [`docs/operations/DEPLOYMENT_RULES.md`](DEPLOYMENT_RULES.md), [`docs/governance/CHANGE_MANAGEMENT_PROCESS.md`](../governance/CHANGE_MANAGEMENT_PROCESS.md)

---

## Table of Contents

1. [Overview](#1-overview)
2. [Pre-flight Checklist](#2-pre-flight-checklist)
3. [State Sync Procedure (GPU-Safe)](#3-state-sync-procedure-gpu-safe)
   - [3.1 Backup existing state](#step-31--backup-existing-state)
   - [3.2 Clean stale plan files](#step-32--clean-stale-plan-files)
   - [3.3 Terraform init](#step-33--terraform-init)
   - [3.4 Check what GCP resources already exist](#step-34--check-what-gcp-resources-already-exist)
   - [3.5 Import existing GKE resources](#step-35--import-existing-gke-resources-if-cluster_exists)
   - [3.6 Import GCS bucket](#step-36--import-gcs-bucket-if-exists)
   - [3.7 Verify state is consistent](#step-37--verify-state-is-consistent)
4. [Deployment Execution](#4-deployment-execution)
5. [GPU Pool Safety Notes](#5-gpu-pool-safety-notes)
6. [Technology-Agnostic Architecture Preservation](#6-technology-agnostic-architecture-preservation)
7. [Post-Deployment Verification](#7-post-deployment-verification)
8. [Rollback Procedure](#8-rollback-procedure)
9. [Change Management Classification](#9-change-management-classification)

---

## 1. Overview

This document is the step-by-step operator runbook for deploying CAGE to the **US_FED development environment** on Google Kubernetes Engine. It is self-contained and executable in sequence.

| Parameter | Value |
|---|---|
| **Cluster name** | `<your-cluster-name>` |
| **GCP project** | `<your-project-id>` |
| **Zone** | `us-central1-a` |
| **Terraform target** | `infra/targets/gcp-gke/` |
| **Var-file** | `infra/targets/gcp-gke/us-dev.tfvars` |
| **State location** | `infra/targets/gcp-gke/terraform.tfstate` (local) |
| **CAGE_DEPLOYMENT_REGION** | `US_FED` |
| **enable_nist_compliance** | `false` (dev posture) |
| **Data residency** | `us-central1` or approved US regions |

### Technology-Agnostic Architecture Note

CAGE maintains a cloud-neutral deployment path at [`infra/targets/agnostic/`](../../infra/targets/agnostic/). The GCP-specific components are isolated to [`infra/targets/gcp-gke/`](../../infra/targets/gcp-gke/). Runtime provider selection is controlled via `.env` variables (`CAGE_KMS_PROVIDER`, `STORAGE_BACKEND`, `AUDITOR_TRACE_SOURCE`), not by source code changes. **Do not modify `infra/targets/agnostic/` during a GCP-targeted deployment.**

---

## 2. Pre-flight Checklist

Run each check and confirm the expected output before proceeding. Do not continue if any check fails.

### 2.1 — GCP Authentication

```bash
gcloud auth list
gcloud config get-value project
```

**Expected:** Active account listed; project returns `<your-project-id>`.

### 2.2 — kubectl Context

```bash
kubectl config current-context
```

**Expected:** Context points to `<your-cluster-name>` (e.g., `<your-kubectl-context>`). If not, run:

```bash
gcloud container clusters get-credentials <your-cluster-name> \
  --zone=us-central1-a \
  --project=<your-project-id>
```

### 2.3 — `.env` File Existence

```bash
test -f .env && echo "OK" || echo "MISSING"
```

> ⚠️ **WARNING:** `deploy_all.sh` reads `.env` directly via `_read_env_var()` — it does **not** source `.env.example`. If `.env` is missing, the deployment script will silently use empty values for secrets. Copy `.env.example` to `.env` and populate all required values before proceeding.

### 2.4 — Terraform Version

```bash
terraform version
```

**Expected:** `Terraform v1.5.x` or higher. The GCP provider lock file at [`infra/targets/gcp-gke/.terraform.lock.hcl`](../../infra/targets/gcp-gke/.terraform.lock.hcl) pins provider versions — do not override.

### 2.5 — Docker Daemon

```bash
docker info
```

**Expected:** Docker daemon is running. Required for Cloud Build image submission. If not running, start Docker Desktop before proceeding.

### 2.6 — GCS Model Bucket Accessibility

```bash
gsutil ls gs://your-models-bucket/
```

**Expected:** Bucket contents listed without permission errors. This bucket is required for vLLM model loading at runtime.

---

## 3. State Sync Procedure (GPU-Safe)

> ⚠️ **WARNING:** This is the most critical section of the runbook. The `<your-cluster-name>` cluster has a GPU node pool (`gpu-pool`) using `g2-standard-8` Spot VMs with NVIDIA L4 GPUs. If Terraform state is empty or stale and the GPU pool already exists in GCP, `terraform apply` will attempt to **create** it again, resulting in a conflict error. Follow every step in order.

### Step 3.1 — Backup Existing State

Always back up before any state manipulation. These commands are safe to run even if the files do not exist.

```bash
cp infra/targets/gcp-gke/terraform.tfstate \
  infra/targets/gcp-gke/terraform.tfstate.bak.$(date +%Y%m%d_%H%M%S) \
  2>/dev/null || true

cp infra/targets/gcp-gke/errored.tfstate \
  infra/targets/gcp-gke/errored.tfstate.bak.$(date +%Y%m%d_%H%M%S) \
  2>/dev/null || true
```

> ⚠️ **WARNING:** An `errored.tfstate` file exists in the repository, indicating a prior failed apply. The backup above preserves it. Do **not** delete `errored.tfstate` without first inspecting it — it may contain resource state that is not reflected in `terraform.tfstate`.

### Step 3.2 — Clean Stale Plan Files

Multiple stale plan files exist from prior runs (`tfplan`, `tfplan_us_dev`, `tfplan_gke`, etc.). These must be removed before generating a fresh plan to avoid applying an outdated diff.

```bash
rm -f infra/targets/gcp-gke/tfplan \
      infra/targets/gcp-gke/tfplan_* \
      infra/targets/gcp-gke/*.tfplan \
      infra/targets/gcp-gke/seal-enforce.tfplan \
      infra/targets/gcp-gke/seal-enforce2.tfplan \
      infra/targets/gcp-gke/v2-release.tfplan
```

### Step 3.3 — Terraform Init

```bash
terraform -chdir=infra/targets/gcp-gke init -upgrade
```

**Expected:** `Terraform has been successfully initialized!`

The `-upgrade` flag ensures provider plugins are refreshed to match the lock file. If init fails with a backend error, confirm there is no `backend.tf` referencing a GCS bucket that does not exist — the current configuration uses **local state**.

### Step 3.4 — Check What GCP Resources Already Exist

Run these discovery commands before any import or apply. Record the output.

```bash
# Check if the GKE cluster exists
gcloud container clusters describe <your-cluster-name> \
  --zone=us-central1-a \
  --project=<your-project-id> \
  --format="value(name,status)" 2>/dev/null \
  && echo "CLUSTER_EXISTS" || echo "CLUSTER_NOT_FOUND"

# List node pools (if cluster exists)
gcloud container node-pools list \
  --cluster=<your-cluster-name> \
  --zone=us-central1-a \
  --project=<your-project-id> \
  --format="table(name,status)" 2>/dev/null

# Check if the Langfuse events GCS bucket exists
gsutil ls -b gs://your-langfuse-events-bucket 2>/dev/null \
  && echo "BUCKET_EXISTS" || echo "BUCKET_NOT_FOUND"
```

**Decision matrix:**

| Condition | Action |
|---|---|
| `CLUSTER_NOT_FOUND` | Skip Steps 3.5 and 3.6; proceed to Step 3.7 |
| `CLUSTER_EXISTS` + state is empty/stale | Execute Steps 3.5 and 3.6 |
| `CLUSTER_EXISTS` + state is current | Skip Steps 3.5 and 3.6; proceed to Step 3.7 |

### Step 3.5 — Import Existing GKE Resources (if CLUSTER_EXISTS)

> ⚠️ **WARNING:** Import commands are **idempotent in intent but not in execution** — if a resource is already tracked in Terraform state, the import command will return an error (`Resource already managed by Terraform`). This error is harmless; skip that resource and continue. If import returns `Resource not found`, the resource does not exist in GCP and will be created on first apply — this is expected for a fresh cluster.

Import resources in this exact order (cluster first, then node pools):

```bash
# 1. GKE Cluster
terraform -chdir=infra/targets/gcp-gke import \
  -var-file=us-dev.tfvars \
  module.gke.google_container_cluster.primary \
  "<your-project-id>/us-central1-a/<your-cluster-name>"
```

```bash
# 2. Primary node pool — import BEFORE GPU pool
terraform -chdir=infra/targets/gcp-gke import \
  -var-file=us-dev.tfvars \
  module.gke.google_container_node_pool.primary_pool \
  "<your-project-id>/us-central1-a/<your-cluster-name>/primary-pool"
```

```bash
# 3. GPU node pool — CRITICAL: import to prevent destroy+recreate
terraform -chdir=infra/targets/gcp-gke import \
  -var-file=us-dev.tfvars \
  module.gke.google_container_node_pool.gpu_pool \
  "<your-project-id>/us-central1-a/<your-cluster-name>/gpu-pool"
```

> ⚠️ **WARNING — GPU Pool Import:** If the GPU pool import fails with `Resource already managed by Terraform`, skip it — the pool is already in state. If it fails with `Resource not found`, the pool does not yet exist in GCP and will be created on first apply. This is expected for a fresh cluster deployment. Do **not** attempt to manually create the GPU pool outside of Terraform.

```bash
# 4. Kubernetes namespaces (if cluster is already running workloads)
terraform -chdir=infra/targets/gcp-gke import \
  -var-file=us-dev.tfvars \
  module.namespace.kubernetes_namespace.governance_stack \
  "governance-stack"

terraform -chdir=infra/targets/gcp-gke import \
  -var-file=us-dev.tfvars \
  module.namespace.kubernetes_namespace.vllm_inference \
  "vllm-inference"
```

### Step 3.6 — Import GCS Bucket (if BUCKET_EXISTS)

```bash
terraform -chdir=infra/targets/gcp-gke import \
  -var-file=us-dev.tfvars \
  module.gke.google_storage_bucket.langfuse_events \
  "<your-project-id>-langfuse-events"
```

If the bucket does not exist, skip this step — it will be created on first apply.

### Step 3.7 — Verify State Is Consistent

Generate a plan and inspect the diff before executing any apply. This is a dry-run only — no changes are made.

```bash
terraform -chdir=infra/targets/gcp-gke plan \
  -var-file=us-dev.tfvars \
  -var=enable_nist_compliance=false \
  -detailed-exitcode 2>&1 | tail -40
```

**Exit code interpretation:**

| Exit code | Meaning | Action |
|---|---|---|
| `0` | No changes — infrastructure matches state | Proceed; apply is a no-op |
| `2` | Changes pending | Review the diff carefully before applying |
| `1` | Error | Resolve the error before proceeding |

> ⚠️ **WARNING:** If the plan shows `destroy` actions on the GPU node pool (`module.gke.google_container_node_pool.gpu_pool`), **stop immediately**. This indicates a state mismatch. Re-run the GPU pool import (Step 3.5, item 3) and re-plan before proceeding.

---

## 4. Deployment Execution

> **GKE deployments MUST use Cloud Build.** Local `docker build` + `docker push` is prohibited for GKE targets. See [`docs/operations/DEPLOYMENT_RULES.md`](DEPLOYMENT_RULES.md).

Choose one of the following options based on your operational context.

### Option A — Background Deployment (Recommended for Long Runs)

Use this option when deploying over SSH, in a CI context, or when the deployment is expected to take more than a few minutes. The background script wraps `deploy_all.sh` with a PID file at `/tmp/cage-deploy.pid` and logs at `/tmp/cage-deploy-logs/`.

```bash
# Start deployment in background
bash scripts/deploy_bg.sh --env us-dev --auto-approve

# Monitor status
bash scripts/deploy_bg.sh --status

# Tail logs
bash scripts/deploy_bg.sh --logs
```

### Option B — Foreground Deployment

Use this option for interactive deployments where you want to observe output in real time.

```bash
./deploy_all.sh --env us-dev --auto-approve
```

### Option C — Skip Image Rebuild (If Images Already Pushed)

Use this option when container images have already been built and pushed to the registry in a prior run and only infrastructure changes need to be applied.

```bash
./deploy_all.sh --env us-dev --auto-approve --skip-build
```

### What `deploy_all.sh` Does

The script performs the following sequence when `--env us-dev` is passed:

1. Reads `.env` via `_read_env_var()` (grep-based, does not source the file)
2. Selects `infra/targets/gcp-gke/us-dev.tfvars` as the Terraform var-file
3. Submits container image builds via Cloud Build
4. Runs: `terraform -chdir="infra/targets/gcp-gke" plan -var-file=us-dev.tfvars -var=enable_nist_compliance=false -out=tfplan`
5. Runs: `terraform -chdir="infra/targets/gcp-gke" apply -parallelism=1 tfplan`

> **Note:** `terraform.auto.tfvars` in `infra/targets/gcp-gke/` is loaded automatically by Terraform on every plan/apply — it does not need to be passed explicitly via `-var-file`.

---

## 5. GPU Pool Safety Notes

The GPU node pool (`gpu-pool`) uses `g2-standard-8` Spot VMs with NVIDIA L4 GPUs. Its Terraform resource in [`infra/modules/gcp_gke_cluster/main.tf`](../../infra/modules/gcp_gke_cluster/main.tf) includes a lifecycle block that protects it from accidental destroy+recreate:

```hcl
lifecycle {
  ignore_changes = [
    initial_node_count,
    node_locations,
    node_config,
  ]
}
```

**What this means in practice:**

- After the first deployment, any change to GPU machine type, Spot setting, disk configuration, or node locations in `us-dev.tfvars` will be **silently ignored** by Terraform — no destroy+recreate will occur.
- `prevent_destroy` is **not** set, so `terraform destroy` targeting the GPU pool is still possible. Do not do this.

### Prohibited Commands — GPU Pool

```bash
# NEVER run these against the GPU pool:
terraform -chdir=infra/targets/gcp-gke apply \
  -replace=module.gke.google_container_node_pool.gpu_pool

terraform -chdir=infra/targets/gcp-gke destroy \
  -target=module.gke.google_container_node_pool.gpu_pool
```

### Changing GPU Pool Configuration

If the GPU pool configuration must change (e.g., machine type, disk size), the correct procedure is:

1. Make the change via GKE Console or `gcloud container node-pools update`
2. Update `us-dev.tfvars` to match the actual GCP state
3. Terraform will show no diff on next plan (because `node_config` is in `ignore_changes`)

---

## 6. Technology-Agnostic Architecture Preservation

CAGE's architecture separates cloud-neutral logic from cloud-specific infrastructure.

| Layer | Path | Rule |
|---|---|---|
| Cloud-neutral IaC | `infra/targets/agnostic/` | **Do not modify during GCP deployments** |
| GCP-specific IaC | `infra/targets/gcp-gke/` | All GCP changes go here |
| Runtime provider selection | `.env` | Controls provider at application layer |

### Runtime Provider Variables (`.env`)

| Variable | US_FED GCP value | Purpose |
|---|---|---|
| `CAGE_KMS_PROVIDER` | `gcp` | Selects Cloud KMS for envelope encryption |
| `STORAGE_BACKEND` | `gcs` | Selects GCS for evidence and event storage |
| `AUDITOR_TRACE_SOURCE` | `cloudtrace` | Selects Cloud Trace for audit telemetry |
| `CAGE_DEPLOYMENT_REGION` | `US_FED` | Gates data residency at the application layer |

### Data Residency Gate

`CAGE_DEPLOYMENT_REGION=US_FED` ensures all data paths remain within `us-central1` or approved US regions, regardless of cloud provider. This gate operates at the application layer in [`src/gateway/governance/`](../../src/gateway/governance/) and [`src/compliance_bridge/`](../../src/compliance_bridge/) — it is not enforced by Terraform alone.

### Deploying to a Different Cloud

To deploy CAGE on a non-GCP cloud:

1. Use `infra/targets/agnostic/` with appropriate tfvars
2. Update `.env` provider variables to match the target cloud
3. Do not modify `infra/targets/gcp-gke/`

---

## 7. Post-Deployment Verification

Run these checks after `deploy_all.sh` completes successfully.

### 7.1 — Pod Health

```bash
# All pods in governance-stack should be Running or Completed
kubectl get pods -n governance-stack

# All pods in vllm-inference should be Running
kubectl get pods -n vllm-inference
```

**Expected:** No pods in `CrashLoopBackOff`, `Error`, or `Pending` (beyond initial startup).

### 7.2 — Gateway Health Endpoint

```bash
kubectl port-forward svc/gateway 8080:8080 -n governance-stack &
sleep 3
curl http://localhost:8080/health
```

**Expected:** HTTP 200 with a JSON health response.

### 7.3 — CAGE_DEPLOYMENT_REGION Verification

```bash
kubectl exec -n governance-stack deploy/governed-advisor -- \
  env | grep CAGE_DEPLOYMENT_REGION
```

**Expected:** `CAGE_DEPLOYMENT_REGION=US_FED`

> ⚠️ **WARNING:** If this returns `EU_ECB` or `APAC_MAS`, the wrong `.env` was used during deployment. The SR 26-2 sentinel in EU and APAC baselines suppresses telemetry lacking legal basis under GDPR / MAS Notice 655. A US_FED pod with an EU/APAC region value will behave incorrectly. Redeploy with the correct `.env`.

### 7.4 — GPU Node Pool Health

```bash
kubectl get nodes -l cloud.google.com/gke-accelerator=nvidia-l4
```

**Expected:** Nodes in `Ready` state. If no nodes are listed, the GPU pool may still be provisioning — wait 5–10 minutes and retry.

### 7.5 — Validation Script

```bash
bash infra/validate_deployment.sh
```

**Expected:** All checks pass. Review any failures before declaring the deployment complete.

---

## 8. Rollback Procedure

For full rollback procedures, see [`infra/ROLLBACK_PROCEDURES.md`](../../infra/ROLLBACK_PROCEDURES.md).

### Quick Rollback — Restore State and Re-apply Previous Plan

Use this procedure if the deployment corrupted Terraform state or applied an incorrect configuration.

```bash
# Step 1: Identify the correct backup timestamp
ls -lt infra/targets/gcp-gke/terraform.tfstate.bak.*

# Step 2: Restore the state backup (replace <timestamp> with actual value)
cp infra/targets/gcp-gke/terraform.tfstate.bak.<timestamp> \
   infra/targets/gcp-gke/terraform.tfstate

# Step 3: Re-apply the last known-good plan
terraform -chdir=infra/targets/gcp-gke apply -parallelism=1 tfplan_us_dev
```

> ⚠️ **WARNING:** `tfplan_us_dev` is a binary plan file tied to the state at the time it was generated. If the state has diverged significantly from when the plan was created, re-applying it may produce unexpected results. When in doubt, generate a fresh plan after restoring the state backup and review the diff before applying.

### Quick Rollback — Kubernetes Only

If only Kubernetes workloads need to be rolled back (no infrastructure changes):

```bash
# Roll back a specific deployment
kubectl rollout undo deployment/gateway -n governance-stack
kubectl rollout undo deployment/governed-advisor -n governance-stack

# Check rollout status
kubectl rollout status deployment/gateway -n governance-stack
```

---

## 9. Change Management Classification

### This Deployment

| Field | Value |
|---|---|
| **Classification** | **Cat-S (Standard)** |
| **Approval required** | Pre-approved — no individual CAB review needed |
| **CHANGELOG.md required** | No |
| **Rationale** | Deploying to existing dev cluster with no new GCP services, no new external API integrations, and no new AI models beyond what is already declared in `us-dev.tfvars` |

### Escalation Triggers

The following conditions require escalation **before** proceeding with deployment:

| Condition | Escalation | Action |
|---|---|---|
| GPU pool is being created for the **first time** | **Cat-N (Normal)** | 5 business day CAB review required |
| New GCP service being added (e.g., new Cloud SQL, Pub/Sub) | **Cat-M (Major)** | AO pre-approval required; 30 calendar day minimum |
| New external API integration | **Cat-M (Major)** | AO pre-approval required |
| New AI model or inference service | **Cat-M (Major)** | AO pre-approval required |
| Changes to HIGH-impact NIST SP 800-53 controls | **Cat-M (Major)** | AO pre-approval required |

> ⚠️ **WARNING — Cat-M Obligation:** If any Cat-M trigger applies to this deployment, **stop immediately**. Do not generate or execute implementation steps until AO pre-approval is documented. See [`docs/governance/CHANGE_MANAGEMENT_PROCESS.md`](../governance/CHANGE_MANAGEMENT_PROCESS.md) for the approval workflow.

### Shared-Module Impact Statement

This deployment targets `infra/targets/gcp-gke/` only. The following shared modules are **not modified** by this deployment:

- `src/gateway/governance/` — no changes
- `src/compliance_bridge/` — no changes
- `config/compliance/` — no changes
- `config/thresholds/` — no changes
- `config/oscal/` — no changes

If any of the above paths are modified as part of this deployment, a cross-region impact assessment for EU_ECB and APAC_MAS is required before merge. See the Architect mode rules for the full assessment template.

---

*Document maintained by: CAGE Platform Engineering*  
*Next review: Before any Cat-N or Cat-M change to the US_FED dev cluster*  
*Related documents: [`docs/operations/DEPLOYMENT_RULES.md`](DEPLOYMENT_RULES.md) · [`docs/operations/RELEASE_RUNBOOK.md`](RELEASE_RUNBOOK.md) · [`infra/ROLLBACK_PROCEDURES.md`](../../infra/ROLLBACK_PROCEDURES.md) · [`docs/governance/CHANGE_MANAGEMENT_PROCESS.md`](../governance/CHANGE_MANAGEMENT_PROCESS.md)*
