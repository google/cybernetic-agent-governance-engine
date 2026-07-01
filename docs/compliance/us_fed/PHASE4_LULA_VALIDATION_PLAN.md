# Phase 4 — Post-Rename Lula Validation Plan

**System:** Cybernetic AI Governance Engine (CAGE) — Governed Financial Advisor  
**Document Type:** Operational Execution Plan  
**Phase:** 4 of 4 — Post-Rename Lula Validation (Prerequisite 4)  
**Status:** PENDING — Requires live GKE cluster access  
**Date:** 2026-06-05  
**Cluster:** `gke_laah-cybernetics_us-central1-a_cage-dev`
**Namespace:** `governance-stack`  
**Project:** `laah-cybernetics`

---

## 1. Purpose

This plan documents the execution steps, success criteria, and POAM closure guidance for Phase 4 of the v0.1.0 post-rename migration. Phase 4 validates that the `lula-audit` CronJob — which runs all active ISO 42001 / NIST SP 800-53 compliance validations — continues to pass correctly after the repository rename and GKE redeployment performed in Phases 1–3.

A successful Phase 4 run produces two POAM closure artifacts:

| Artifact | Description |
|---|---|
| `lula-poam-evidence.log` | Raw stdout from `job/lula-post-rename-validation` confirming both success markers |
| `compliance-trigger-evidence.yaml` | Pre-existing OSCAL evidence artifact from the compliance-bridge ingest pipeline |

Both artifacts must be retained together as the evidentiary record for POAM closure of any compliance-related findings affected by the rename migration.

---

## 2. Prerequisites

All of the following must be satisfied before executing Phase 4.

| # | Prerequisite | Verification |
|---|---|---|
| P-1 | Phase 1 (credential rotation) complete | `kubectl get secret advisor-secrets -n governance-stack` returns both `CAGE_ROUTING_SEAL_SECRET` and `GOVERNANCE_SALT` |
| P-2 | Phase 2 (git history rewrite) complete | `git log --oneline -5` shows no credential strings in commit messages |
| P-3 | Phase 3 (Terraform apply + GKE deployment) complete | `kubectl get pods -n governance-stack` — all pods `Running`/`Ready` |
| P-4 | `lula-audit` CronJob present in cluster | `kubectl get cronjob lula-audit -n governance-stack` returns the resource |
| P-5 | `compliance-bridge` service reachable | `kubectl get svc compliance-bridge -n governance-stack` — `ClusterIP` assigned |
| P-6 | Langfuse compliance project credentials configured | `kubectl get secret advisor-secrets -n governance-stack -o jsonpath='{.data.LANGFUSE_COMPLIANCE_PUBLIC_KEY}'` — non-empty |
| P-7 | GKE credentials available locally | `gcloud container clusters get-credentials` succeeds (see §3.1) |

> **POAM-018 Note:** If `LANGFUSE_COMPLIANCE_PUBLIC_KEY` / `LANGFUSE_COMPLIANCE_SECRET_KEY` are absent from `advisor-secrets`, the compliance-bridge will silently drop all OSCAL ingest calls and the `✅ OSCAL results ingested` marker will never appear. Verify P-6 before proceeding. See [`docs/POAM.md`](../cross-region/POAM.md) POAM-018.

---

## 3. Execution Steps

### 3.1 — Authenticate to GKE Cluster

```bash
gcloud container clusters get-credentials cage-dev \
    --region=us-central1 \
    --project=laah-cybernetics
```

**Verify:**

```bash
kubectl config current-context
# Expected: gke_laah-cybernetics_us-central1_cage-dev

kubectl get nodes
# Expected: ≥1 node in Ready state
```

---

### 3.2 — Confirm CronJob and Namespace Health

```bash
# Confirm lula-audit CronJob exists
kubectl get cronjob lula-audit -n governance-stack
# Expected: NAME=lula-audit, SCHEDULE="0 */6 * * *", SUSPEND=False

# Confirm compliance-bridge is running
kubectl get pods -n governance-stack -l app=compliance-bridge
# Expected: STATUS=Running, READY=1/1

# Confirm Langfuse web is running (AU-12 dependency)
kubectl get pods -n governance-stack -l app=langfuse-web
# Expected: STATUS=Running, READY=1/1

# Confirm lula-validation-manifests ConfigMap is present
kubectl get configmap lula-validation-manifests -n governance-stack
# Expected: resource found (contains a52, a53, a92, sc4 validation manifests)
```

---

### 3.3 — Trigger Manual Lula Assessment

```bash
kubectl create job --from=cronjob/lula-audit lula-post-rename-validation \
    -n governance-stack
```

**Expected output:**

```
job.batch/lula-post-rename-validation created
```

> **Note:** If a job with this name already exists from a prior attempt, delete it first:
> ```bash
> kubectl delete job lula-post-rename-validation -n governance-stack --ignore-not-found
> ```

---

### 3.4 — Monitor Job Completion

```bash
# Watch pod status until Completed
kubectl get pods -n governance-stack -w | grep lula-post-rename-validation
```

**Expected pod lifecycle:**

```
lula-post-rename-validation-<hash>   0/1   Pending     0   0s
lula-post-rename-validation-<hash>   0/1   Init:0/1    0   2s
lula-post-rename-validation-<hash>   1/1   Running     0   5s
lula-post-rename-validation-<hash>   0/1   Completed   0   45s
```

Alternatively, wait with a timeout:

```bash
kubectl wait --for=condition=complete \
    job/lula-post-rename-validation \
    -n governance-stack \
    --timeout=300s
```

If the job fails (`BackoffLimitExceeded`), proceed to §5 (Troubleshooting) before retrying.

---

### 3.5 — Collect POAM Evidence Artifact

```bash
kubectl logs job/lula-post-rename-validation \
    -n governance-stack > lula-poam-evidence.log
```

Confirm the file is non-empty:

```bash
wc -l lula-poam-evidence.log
# Expected: ≥10 lines
```

---

### 3.6 — Verify Success Markers

```bash
grep -E "✅|OSCAL results ingested" lula-poam-evidence.log
```

**Required output — both lines must be present:**

```
✅ Lula audit complete. Result: /results/oscal-assessment-lula-post-rename-validation-<timestamp>.yaml
✅ OSCAL results ingested into Langfuse compliance project.
```

If either marker is absent, do **not** close the POAM items. Proceed to §5 (Troubleshooting).

---

### 3.7 — Verify Ingest HTTP Status

```bash
grep -E "Ingest HTTP status|HTTP_STATUS" lula-poam-evidence.log
# Expected: 📊 Ingest HTTP status: 200
```

A non-200 status indicates the compliance-bridge rejected the OSCAL payload. See §5.3.

---

### 3.8 — Verify Individual Control Results

The Lula job validates four controls. Confirm each ran without a hard failure:

```bash
grep -E "oscal-(a52|a53|a92|sc4)" lula-poam-evidence.log
# Expected: four result file paths written to /results/parts/
```

> **Note:** Individual control `validate` failures (OPA returning `false`) do not cause the job to exit non-zero — the `|| true` in [`deployment/k8s/lula-cron.yaml`](../deployment/k8s/lula-cron.yaml) is intentional. The OSCAL result file captures pass/fail per control. The job exits non-zero only if the compliance-bridge ingest returns a non-200 HTTP status.

---

### 3.9 — Clean Up Test Job

```bash
kubectl delete job lula-post-rename-validation -n governance-stack
```

---

## 4. Success Criteria

Phase 4 is **complete** when all of the following are true:

| # | Criterion | Evidence |
|---|---|---|
| S-1 | `job/lula-post-rename-validation` reached `Completed` state | `kubectl get job lula-post-rename-validation -n governance-stack` showed `COMPLETIONS: 1/1` |
| S-2 | `✅ Lula audit complete` present in `lula-poam-evidence.log` | `grep "✅ Lula audit complete" lula-poam-evidence.log` returns a match |
| S-3 | `✅ OSCAL results ingested into Langfuse compliance project` present in `lula-poam-evidence.log` | `grep "OSCAL results ingested" lula-poam-evidence.log` returns a match |
| S-4 | Ingest HTTP status was `200` | `grep "Ingest HTTP status: 200" lula-poam-evidence.log` returns a match |
| S-5 | `lula-poam-evidence.log` retained alongside `compliance-trigger-evidence.yaml` | Both files present in the compliance evidence archive |

---

## 5. Troubleshooting

### 5.1 — Job Stuck in `Pending`

```bash
kubectl describe pod -n governance-stack -l job-name=lula-post-rename-validation
```

Common causes:
- **ImagePullBackOff:** The Lula image `us-central1-docker.pkg.dev/laah-cybernetics/governance-stack/lula:0.9.5` is not accessible. Verify Artifact Registry permissions for the `lula-auditor` ServiceAccount.
- **Insufficient resources:** Node resource pressure. Check `kubectl describe nodes`.

---

### 5.2 — `✅ Lula audit complete` Missing

The Lula binary failed to run. Check for errors:

```bash
kubectl logs job/lula-post-rename-validation -n governance-stack | head -50
```

Common causes:
- `lula-validation-manifests` ConfigMap missing or malformed — re-apply [`deployment/k8s/lula-cron.yaml`](../deployment/k8s/lula-cron.yaml):
  ```bash
  kubectl apply -f deployment/k8s/lula-cron.yaml
  ```
- RBAC insufficient — verify `lula-auditor` ServiceAccount has the required ClusterRole:
  ```bash
  kubectl auth can-i get deployments --as=system:serviceaccount:governance-stack:lula-auditor -n governance-stack
  # Expected: yes
  ```

---

### 5.3 — `✅ OSCAL results ingested` Missing / HTTP non-200

The compliance-bridge rejected the OSCAL payload. Diagnose:

```bash
# Check compliance-bridge logs
kubectl logs -n governance-stack deploy/compliance-bridge --tail=50

# Check ingest response body captured in the job log
grep -A5 "ingest-response" lula-poam-evidence.log
```

Common causes:
- **LANGFUSE credentials absent (POAM-018):** Verify `LANGFUSE_COMPLIANCE_PUBLIC_KEY` is set in `advisor-secrets`. If absent, configure per [`docs/POAM.md`](../cross-region/POAM.md) POAM-018 remediation steps.
- **compliance-bridge not running:** `kubectl rollout restart deployment/compliance-bridge -n governance-stack`
- **GCS bucket unreachable:** Check `OSCAL_S3_BUCKET` env var in the compliance-bridge deployment and verify GCS IAM permissions.

---

### 5.4 — Individual Control Validation Failures

If the OSCAL result file shows a control as `not-satisfied`, this is a compliance finding, not a Phase 4 execution failure. Document the failing control(s) and open a new POAM item per the entry criteria in [`docs/POAM.md`](../cross-region/POAM.md) §POA&M Process.

Controls and their thresholds:

| Control | Validation File | Pass Threshold |
|---|---|---|
| A.5.2 (ISO 42001) | `lula-validation-a52.yaml` | `safety_rate ≥ 0.99` |
| A.5.3 (ISO 42001) | `lula-validation-a53.yaml` | `safety_rate ≥ 0.98` |
| A.9.2 (ISO 42001) | `lula-validation-a92.yaml` | `safety_rate == 1.0` (PII leak rate = 0%) |
| SC-4 (NIST 800-53) | `lula-validation-sc4.yaml` | `opa-compliance-status` ConfigMap label `compliance.iso42001/enabled: "true"` |

---

## 6. POAM Closure Guidance

### 6.1 — Evidence Artifacts

Retain the following two files as the POAM closure artifacts for the rename migration:

| File | Source | Retention Location |
|---|---|---|
| `lula-poam-evidence.log` | Collected in §3.5 | `proof/` directory or compliance evidence archive |
| `compliance-trigger-evidence.yaml` | Pre-existing OSCAL artifact from compliance-bridge | `proof/` directory or compliance evidence archive |

### 6.2 — POAM Items Addressed by Phase 4

A successful Phase 4 run provides evidence supporting closure or status update for the following POAM items:

| POAM ID | Control | Weakness | Phase 4 Evidence |
|---|---|---|---|
| POAM-003 | AU-12 | `automated_auditor.py` uses synthetic mock traces | `✅ OSCAL results ingested` confirms live Langfuse ingest pipeline is operational post-rename |
| POAM-018 | AU-9 | Langfuse compliance credentials fail silently | HTTP 200 ingest response confirms credentials are correctly configured |
| POAM-019 | AU-9, SC-7 | Terraform fallback collapses dual-project telemetry isolation | Successful ingest into compliance project (not application project) confirms isolation is intact |

### 6.3 — Closure Procedure

Per [`docs/POAM.md`](../cross-region/POAM.md) §Closure Criteria, items are closed when:

1. Remediation actions are fully implemented ✓ (Phases 1–3 complete)
2. Implementation is verified by the ISSO or Security Control Assessor ← **Phase 4 provides this verification**
3. Supporting evidence is archived ← **`lula-poam-evidence.log` + `compliance-trigger-evidence.yaml`**
4. AO is notified of closure for HIGH/CRITICAL items

After Phase 4 succeeds:
1. Archive both evidence files to the compliance evidence store
2. Update [`docs/POAM.md`](../cross-region/POAM.md) — mark affected items `Closed` with closure date `2026-06-05` and reference `lula-poam-evidence.log`
3. Notify AO of closure for any HIGH-severity items per the monthly review cadence

---

## 7. Post-Phase-4 Steady State

After Phase 4 completes, the `lula-audit` CronJob resumes its normal schedule (`0 */6 * * *` — every 6 hours). No further manual intervention is required.

Ongoing monitoring:
- **Tier 1 controls** (A.5.2, A.9.2, SC-4): validated every 6 hours by `lula-audit` CronJob
- **SC-4 real-time**: monitored continuously by `lula-sc4-watch` Deployment (60-second poll)
- **Tier 2 controls** (A.5.3, AU-12): validated daily
- **Tier 3 controls** (CM-6, RA-5): validated weekly

See [`compliance/lula/README.md`](../compliance/lula/README.md) for the full validation coverage table and [`compliance/continuous-monitoring/ISCM_STRATEGY.md`](../compliance/continuous-monitoring/ISCM_STRATEGY.md) for the complete ISCM cadence.

---

## 8. Related Documents

| Document | Purpose |
|---|---|
| [`docs/RELEASE_RUNBOOK.md`](../../operations/RELEASE_RUNBOOK.md) | Full release runbook (Phases 1–6) |
| [`docs/RELEASE_PLAN.md`](../../project/RELEASE_PLAN.md) | Release plan and dependency ordering |
| [`docs/POAM.md`](../cross-region/POAM.md) | Plan of Action and Milestones |
| [`compliance/lula/README.md`](../compliance/lula/README.md) | Lula validation coverage and activation guide |
| [`deployment/k8s/lula-cron.yaml`](../deployment/k8s/lula-cron.yaml) | CronJob manifest (lula-audit + lula-sc4-watch) |
| [`deployment/k8s/lula-rbac.yaml`](../deployment/k8s/lula-rbac.yaml) | RBAC for lula-auditor ServiceAccount |
| [`compliance/sar/SAR_2026Q1.md`](../compliance/sar/SAR_2026Q1.md) | Security Assessment Report (pre-ATO gap assessment) |
| [`compliance/continuous-monitoring/ISCM_STRATEGY.md`](../compliance/continuous-monitoring/ISCM_STRATEGY.md) | ISCM cadence and escalation procedures |

---

_This document is UNCLASSIFIED. Distribution limited to ISSO, System Owner, and authorized assessment team members._
