# CAGE Software Quality Remediation Plan

> **Reference Architecture Note:** Per [`AGENTS.md`](../AGENTS.md), CAGE is a
> reference architecture demonstrating governance patterns for AI systems.
> The CAB windows, OSCAL update timelines, owner placeholders, and sprint
> labels below follow the same **illustrative pattern** convention used in
> [`plans/SECURITY_REMEDIATION_PLAN.md`](SECURITY_REMEDIATION_PLAN.md) and
> [`plans/CORRECTION_PLAN_2026-08-04.md`](CORRECTION_PLAN_2026-08-04.md) —
> they demonstrate how a production adopter would sequence and govern this
> work, not enforced operational obligations for this repository. The
> underlying defects (broken CronJob, bypassed coverage gate, non-blocking
> integration/compliance suites) are real and independently verifiable
> against this repository's current state.

**Date:** 2026-08-09
**Scope:** Findings from a deployment-verification pass and a local
`pytest` run against the current `main` branch, covering test-coverage
enforcement, CI gating of integration/compliance suites, live-cluster image
drift, the broken `reconciliation-worker` CronJob, and the risk of
compliance attestations diverging from actual runtime state.

---

## Executive Summary

The repository's automated quality gates currently produce a false sense of
assurance: the coverage gate declared in [`pytest.ini`](../pytest.ini)
(`--cov-fail-under=60`) is being routed around locally via `--no-cov`, and it
is unclear whether the CI [`pytest-logic`](../.github/workflows/ci.yml) job
enforces it at all since it invokes `pytest tests/ -m local -v` without an
explicit coverage flag override — actual measured coverage is closer to 19%,
concentrated almost entirely in `src/gateway/governance/` core modules while
`governed_financial_advisor/agents/`, `compliance_bridge/` integration
surfaces, and `ingress/` adapters remain thin. Compounding this, 165 tests
carrying `integration`, `slow`, `eu_ecb`, `us_fed`, `apac_mas`, or `local`
markers are skipped by default, the `integration-smoke` CI job runs with
`continue-on-error: true`, the full [`compliance/`](../compliance/) Lula/OSCAL
suite is excluded from routine test runs entirely, and
[`tests/test_nexart_integration.py`](../tests/test_nexart_integration.py) is
excluded as too slow — meaning defects in the integration and compliance
layers are structurally invisible to CI. On the operational side, the same
gap exists in reverse: `gateway`, `compliance-bridge`, and
`governed-financial-advisor` ran stale images for three days after commit
`0c38976` landed because no post-deploy step asserts that running image
digests match `main` HEAD, and the
[`reconciliation-worker`](../deployment/k8s/reconciliation-worker.yaml)
CronJob is currently broken — it references a `gcs-reconciliation-bucket` key
in `reconciliation-worker-secrets` that was never populated, and its
`RECONCILIATION_PROVIDER` default (`s3`) diverges from the gateway
manifest's `gcs` — causing
[`fiscal_limit_guard.py`](../src/gateway/governance/fiscal_limit_guard.py)
to fall back to un-reconciled Redis counters, a regression against
POAM-2026-038's SC-4 fiscal-control posture. Because
[`docs/POAM.md`](../docs/POAM.md) closure claims are not automatically
cross-checked against live cluster or Lula-assertion state, there is a
material risk of compliance attestations (for all three regional postures —
US_FED, EU_ECB, APAC_MAS) diverging from runtime truth. This plan sequences
remediation into four tiers: **P0** immediate fixes to unblock the fiscal
reconciliation control within 48 hours; **P1** Sprint 1–2 work to enforce the
coverage gate, build a post-deploy verification loop, and make integration
and compliance suites CI-blocking; **P2** Q4 2026 work to close the
remaining EU_ECB/APAC_MAS regional posture findings and stand up a
standing POAM-to-runtime reconciliation process.

---

## Priority Matrix

| Finding | Severity | Category | Owner (illustrative) | Target Timeline |
|---|---|---|---|---|
| F4 — Reconciliation worker CronJob broken (`gcs-reconciliation-bucket` unset, provider mismatch) | **P0** | Operational | Platform Eng | Immediate (48h) |
| F1 — Coverage gate bypassed / ~19% actual coverage | **P1** | Test Infrastructure | Governance Eng | Sprint 1 |
| F3 — 3-day image drift / no post-deploy verification | **P1** | Operational | Platform Eng | Sprint 1 |
| F2 — Integration/compliance suites not blocking merges | **P1** | Test Infrastructure | Governance Eng | Sprint 2 |
| F5 — Compliance-claim vs. runtime-truth divergence risk | **P1** / **P2** | Compliance | Compliance | Sprint 2 (tooling) → Ongoing (process) |
| F6 — EU_ECB / APAC_MAS regional postures under-verified | **P2** | Compliance | Compliance | Q4 2026 |

---

## P0 — Immediate Actions (within 48 hours)

These four actions unblock the SC-4 fiscal-control regression
(POAM-2026-038) caused by the broken `reconciliation-worker` CronJob. They
must land together — populating the secret without fixing the provider
mismatch (or vice versa) leaves the worker non-functional.

### P0.1 — Populate `gcs-reconciliation-bucket` key in `reconciliation-worker-secrets`

**Problem:** [`deployment/k8s/reconciliation-worker.yaml`](../deployment/k8s/reconciliation-worker.yaml:135-146)
wires `GCS_RECONCILIATION_BUCKET` from `secretKeyRef: reconciliation-worker-secrets/gcs-reconciliation-bucket`
with `optional: true`. Because the key was never created, the env var is
silently absent at container start rather than failing the pod — the
worker starts, then fails at the first GCS API call (or silently no-ops,
depending on the provider branch reached).

**Files to edit:**
- No code change required for this step — it is a cluster-state fix.
- Optionally tighten [`deployment/k8s/reconciliation-worker.yaml`](../deployment/k8s/reconciliation-worker.yaml:139-140)
  to set `optional: false` for `gcs-reconciliation-bucket` once
  `RECONCILIATION_PROVIDER=gcs` is confirmed as the standing default (see
  P0.2), so a future secret-population regression fails loudly (`CreateContainerConfigError`)
  instead of silently degrading.

**Commands to run:**
```bash
# 1. Confirm current secret contents (keys only, not values)
kubectl get secret reconciliation-worker-secrets -n governance-stack -o json \
  | python3 -c "import json,sys; d=json.load(sys.stdin); print(list(d.get('data',{}).keys()))"

# 2. Populate the missing key (bucket name is illustrative — use the
#    real GCS bucket provisioned for the WORM reconciliation ledger)
kubectl create secret generic reconciliation-worker-secrets \
  --namespace=governance-stack \
  --from-literal=gcs-reconciliation-bucket=<YOUR_RECONCILIATION_BUCKET> \
  --from-literal=gcs-reconciliation-object=reconciliation/latest.json \
  --from-literal=kms-governance-key=<KMS_KEY_RESOURCE_NAME> \
  --dry-run=client -o yaml | kubectl apply -f -

# 3. Confirm the key is now present
kubectl get secret reconciliation-worker-secrets -n governance-stack \
  -o jsonpath='{.data.gcs-reconciliation-bucket}' | base64 -d
```

**Verification:**
- `kubectl get secret reconciliation-worker-secrets -n governance-stack -o jsonpath='{.data.gcs-reconciliation-bucket}'`
  returns a non-empty base64 value.
- No IAM binding is required beyond what already exists for the
  `financial-advisor-sa` service account referenced at
  [`deployment/k8s/reconciliation-worker.yaml:102`](../deployment/k8s/reconciliation-worker.yaml:102) — confirm
  `roles/storage.objectViewer` (or equivalent) is bound if Workload
  Identity is used instead of static credentials.

---

### P0.2 — Resolve `RECONCILIATION_PROVIDER` env-var mismatch between manifests

**Problem:** [`deployment/k8s/reconciliation-worker.yaml:131-132`](../deployment/k8s/reconciliation-worker.yaml:131)
hardcodes `RECONCILIATION_PROVIDER=s3`, while
[`deployment/k8s/gateway.yaml:147-148`](../deployment/k8s/gateway.yaml:147)
sets `RECONCILIATION_PROVIDER=gcs` for the gateway's own reconciliation
read path. If the CronJob writes under the `s3`-provider code path (reading
`S3_RECONCILIATION_BUCKET`, which is also unset) while the gateway expects
`gcs`-labeled Redis keys, the two components silently disagree on the
provider identity of the data — even after P0.1 populates the GCS bucket
key, the CronJob will still default to `s3` and never read it.

**Root cause reference:** This exact class of defect was previously closed
under POAM-2026-042 ("`reconciliation_worker.py` registered providers
`stub`, `anchorage`, and `plaid` but `gateway.yaml` sets
`RECONCILIATION_PROVIDER=gcs`" — see [`docs/POAM.md:118`](../docs/POAM.md:118)).
The `gcs` provider class was added to
[`src/compliance_bridge/reconciliation_worker.py`](../src/compliance_bridge/reconciliation_worker.py),
but the CronJob manifest's hardcoded `s3` default was not updated to match
— a regression of the same root cause via a different file.

**Files to edit:**
- [`deployment/k8s/reconciliation-worker.yaml`](../deployment/k8s/reconciliation-worker.yaml:131-132):
  change the hardcoded value from `"s3"` to `"gcs"` to match
  [`deployment/k8s/gateway.yaml:147-148`](../deployment/k8s/gateway.yaml:147).

Change the `RECONCILIATION_PROVIDER` env var block from value `"s3"` to
value `"gcs"` (lines 131-132 of the CronJob manifest).

- Add a regression guard so this cannot silently drift again: extend
  [`scripts/check_stpa_freshness.py`](../scripts/check_stpa_freshness.py)-style
  freshness checking, or add a new small script
  `scripts/check_reconciliation_provider_consistency.py` that greps both
  manifests for `RECONCILIATION_PROVIDER` and fails CI if the values
  differ. Wire it into [`.github/workflows/ci.yml`](../.github/workflows/ci.yml)
  as a new lightweight job (see P1 Sprint 1 for the broader post-deploy
  verification work this feeds into).

**Commands to run:**
```bash
# After editing the manifest, redeploy via Cloud Build + kubectl per
# AGENTS.md deployment rules (never kubectl apply without a preceding
# Cloud Build step for GKE-targeted images; this is a manifest-only
# change so no image rebuild is required, but the CronJob object itself
# must still be re-applied):
kubectl apply -f deployment/k8s/reconciliation-worker.yaml

# Confirm the running CronJob's env now matches:
kubectl get cronjob reconciliation-worker -n governance-stack \
  -o jsonpath='{.spec.jobTemplate.spec.template.spec.containers[0].env[?(@.name=="RECONCILIATION_PROVIDER")].value}'
```

**Verification:**
- Both manifests report `RECONCILIATION_PROVIDER=gcs`.
- `grep -r "RECONCILIATION_PROVIDER" deployment/k8s/*.yaml` shows a single
  consistent value across `gateway.yaml` and `reconciliation-worker.yaml`.

---

### P0.3 — Verify reconciliation-worker CronJob completes one successful run

**Files to edit:** None — verification-only step, run after P0.1 and P0.2.

**Commands to run:**
```bash
# Trigger an immediate manual run instead of waiting for the next
# 5-minute schedule window (deployment/k8s/reconciliation-worker.yaml:86):
kubectl create job --from=cronjob/reconciliation-worker \
  reconciliation-worker-manual-verify -n governance-stack

# Watch the Job to completion (activeDeadlineSeconds=240, see
# deployment/k8s/reconciliation-worker.yaml:93):
kubectl get jobs -n governance-stack -w

# Inspect logs for the reconciliation cycle outcome:
kubectl logs -n governance-stack job/reconciliation-worker-manual-verify

# Confirm the verified balance key was written to Redis with a fresh TTL:
kubectl exec -n governance-stack deploy/redis-stack -- \
  redis-cli TTL reconciliation:verified_balance
kubectl exec -n governance-stack deploy/redis-stack -- \
  redis-cli GET reconciliation:verified_balance

# Clean up the manual verification job:
kubectl delete job reconciliation-worker-manual-verify -n governance-stack
```

**Verification:**
- `kubectl get jobs -n governance-stack` shows the manual job with
  `COMPLETIONS 1/1` and no `Failed` status.
- `redis-cli TTL reconciliation:verified_balance` returns a positive
  integer (≤ 300s per `RECONCILIATION_TTL_S`, see
  [`deployment/k8s/reconciliation-worker.yaml:227`](../deployment/k8s/reconciliation-worker.yaml:227)).
- The next scheduled (non-manual) run also completes successfully:
  `kubectl get jobs -n governance-stack -l app=reconciliation-worker` shows
  a `Completed` job from within the last 5 minutes.
- `fiscal_limit_guard.py`'s consumer of the verified balance (confirm the
  read path in [`src/gateway/governance/fiscal_limit_guard.py`](../src/gateway/governance/fiscal_limit_guard.py))
  no longer logs a fallback-to-self-reported-balance warning in gateway
  pod logs: `kubectl logs -n governance-stack deploy/gateway --tail=200 | grep -i reconcil`.

---

### P0.4 — Update POAM-2026-038 status to reflect current degraded state

**Problem:** [`docs/POAM.md:76`](../docs/POAM.md:76) currently describes
POAM-2026-038 as having received "Partial remediation committed
2026-08-06," which does not reflect that the reconciliation worker
supplying the very data this control depends on was non-functional. Leaving
this stale creates exactly the compliance-claim-vs-runtime-truth
divergence risk described in Finding 5.

**Files to edit:**
- [`docs/POAM.md`](../docs/POAM.md:76): update the POAM-2026-038 row to
  note the CronJob outage window, the commit/PR that fixed P0.1/P0.2, and
  the verification evidence from P0.3. Append an **Update 2026-08-09** note
  stating: the `reconciliation-worker` CronJob supplying the
  verified-balance reconciliation data was found non-functional — the
  `gcs-reconciliation-bucket` secret key was never populated and
  `RECONCILIATION_PROVIDER` diverged between `gateway.yaml` (`gcs`) and
  `reconciliation-worker.yaml` (`s3`), causing `fiscal_limit_guard.py` to
  operate on un-reconciled Redis counters only. Remediated in
  `fix/reconciliation-worker-provider-and-secret` — reference P0.1–P0.3 of
  this plan for verification evidence (CronJob `Completed`,
  `reconciliation:verified_balance` TTL confirmed).

- Add a corresponding entry to [`docs/POAM.md`](../docs/POAM.md) `Closed
  Findings` table (around [`docs/POAM.md:118`](../docs/POAM.md:118)) once
  P0.1–P0.3 are verified, following the existing `POAM-2026-0NN` numbering
  convention (next available ID after `POAM-2026-042`).

**Commands to run:** None beyond standard git commit/PR workflow. Reference
the POAM ID in the commit message per
[`docs/POAM.md:163`](../docs/POAM.md:163) contribution guidance, e.g.:
`fix(deployment): restore reconciliation-worker gcs provider consistency [POAM-2026-038]`.

**Verification:**
- `docs/POAM.md` diff reviewed in the same PR that fixes P0.1/P0.2.
- New POAM closure entry references the commit SHA and the manual
  verification evidence from P0.3, per the compliance artifact
  obligations in [`AGENTS.md`](../AGENTS.md).

---

## P1 — Sprint 1 (1–2 weeks): Enforce the Coverage Gate

**Problem:** [`pytest.ini`](../pytest.ini:7) declares
`--cov-fail-under=60` as part of `addopts`, meaning the gate is supposed to
be always-on for any bare `pytest` invocation. However, a local run
required `--no-cov` (which disables coverage measurement entirely,
bypassing the `--cov-fail-under` check per `pytest-cov`'s own documented
behavior) to pass — indicating actual coverage is far below 60%, likely
around 19%, and someone has been routing around the gate rather than fixing
it. In CI, [`.github/workflows/ci.yml:119`](../.github/workflows/ci.yml:119)
runs `uv run pytest tests/ -m local -v` — since `addopts` in `pytest.ini`
applies automatically, this **should** enforce the same 60% floor, but this
has not been empirically confirmed to be passing (or possibly the job has
been green only because it was never actually exercising un-mocked code
paths). This item also has direct precedent: POAM-2026-030
(see [`docs/POAM.md:108`](../docs/POAM.md:108)) found that
`src/gateway/governance/ftra/` had zero real test coverage until dedicated
tests were added, and a related dead-scaffold module
(`ftra_reachability.py`, POAM-2026-032) had tests that exercised only
unreachable code, producing a false impression of coverage. The current gap
likely repeats this pattern in other modules.

### Step 1 — Generate a per-module coverage baseline

```bash
uv run pytest --cov=src --cov-config=.coveragerc \
  --cov-report=term-missing --cov-report=html -m local
```

Review `htmlcov/index.html` and the terminal `--cov-report=term-missing`
output, sorted by module, to build a concrete list of modules below 60%.
Cross-reference against [`.coveragerc`](../.coveragerc) to confirm the
`omit` list (currently `src/gateway/protos/*_pb2*.py`,
`src/integrations/*/tests/*`) is still appropriate and not being used to
hide additional untested modules.

**Expected low-coverage areas** (to be confirmed by the baseline run):
- `src/governed_financial_advisor/graph/nodes/agent_nodes.py` and sibling
  agent node files under
  [`src/governed_financial_advisor/graph/nodes/`](../src/governed_financial_advisor/graph/nodes/)
- `src/compliance_bridge/` integration surfaces beyond the modules already
  covered by `tests/test_compliance_bridge_tier*.py`
  (e.g. [`src/compliance_bridge/reconciliation_worker.py`](../src/compliance_bridge/reconciliation_worker.py),
  [`src/compliance_bridge/lula_scheduler.py`](../src/compliance_bridge/lula_scheduler.py),
  [`src/compliance_bridge/audit_workflow.py`](../src/compliance_bridge/audit_workflow.py))
- `src/gateway/governance/ingress/` adapters
  ([`agw_adapter.py`](../src/gateway/governance/ingress/agw_adapter.py),
  [`agp_policy_uploader.py`](../src/gateway/governance/ingress/agp_policy_uploader.py),
  [`acs_adapter.py`](../src/gateway/governance/ingress/acs_adapter.py),
  [`aaif_adapter.py`](../src/gateway/governance/ingress/aaif_adapter.py),
  [`agent_registry_adapter.py`](../src/gateway/governance/ingress/agent_registry_adapter.py),
  [`lula_adapter.py`](../src/gateway/governance/ingress/lula_adapter.py),
  [`oscal_adapter.py`](../src/gateway/governance/ingress/oscal_adapter.py),
  [`policy_translator.py`](../src/gateway/governance/ingress/policy_translator.py)) —
  note some of these already have dedicated test files
  ([`tests/test_ingress_agw_adapter.py`](../tests/test_ingress_agw_adapter.py),
  [`tests/test_ingress_agp_policy_uploader.py`](../tests/test_ingress_agp_policy_uploader.py))
  but the baseline run will show whether branch coverage within them is
  thin.

### Step 2 — Fix the CI `pytest-logic` job to enforce the gate without bypass

**File to edit:** [`.github/workflows/ci.yml`](../.github/workflows/ci.yml:105-119)

The `Run Pytest (unit/local)` step currently runs:
```
uv run pytest tests/ -m local -v
```
Since `pytest.ini`'s `addopts` already includes `--cov-fail-under=60`, no
explicit flag needs to be added — but the step must be changed to make the
enforcement **visible and intentional** rather than incidental, and a
follow-up step must assert the job actually failed the build when coverage
regresses. Update the step to:
```
uv run pytest tests/ -m local -v --cov=src --cov-config=.coveragerc --cov-report=term-missing --cov-report=xml
```
Explicitly stating the coverage flags (even though they duplicate
`addopts`) makes the CI log self-documenting and prevents a future
`pytest.ini` edit from silently weakening the CI gate without a
corresponding CI diff. Upload the resulting `coverage.xml` as a build
artifact for trend tracking:
```yaml
      - name: Upload coverage report
        if: always()
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: coverage-${{ matrix.region }}-${{ github.sha }}
          path: coverage.xml
          retention-days: 30
```

### Step 3 — Identify and prioritize the top-10 governance-critical uncovered modules

Using the Step 1 baseline, prioritize tests for governance-critical
modules first (these gate real money movement and compliance evidence, so
regressions here are highest-impact):

1. [`src/gateway/governance/fiscal_limit_guard.py`](../src/gateway/governance/fiscal_limit_guard.py) — SC-4 fiscal control
2. [`src/gateway/governance/causal_gatekeeper.py`](../src/gateway/governance/causal_gatekeeper.py) — CA-7 causal safety check
3. [`src/gateway/governance/routing_seal.py`](../src/gateway/governance/routing_seal.py) — SC-4/AC-3 HMAC seal enforcement
4. [`src/gateway/governance/ingress/`](../src/gateway/governance/ingress/) adapters (all 8 files)
5. [`src/compliance_bridge/reconciliation_worker.py`](../src/compliance_bridge/reconciliation_worker.py) — external ledger reconciliation (directly implicated in F4/P0)
6. [`src/gateway/governance/cbf.py`](../src/gateway/governance/cbf.py) — Control Barrier Function atomicity
7. [`src/gateway/governance/kms_signer.py`](../src/gateway/governance/kms_signer.py) — evidentiary signing
8. [`src/gateway/governance/hitl_escalator.py`](../src/gateway/governance/hitl_escalator.py) — HITL SLA enforcement
9. [`src/gateway/governance/symbolic_governor.py`](../src/gateway/governance/symbolic_governor.py) — central governance orchestrator
10. [`src/compliance_bridge/audit_workflow.py`](../src/compliance_bridge/audit_workflow.py) — critical-fail alerting pipeline

For each module, write missing tests following the existing repository
convention (see [`tests/test_fiscal_limit_guard.py`](../tests/test_fiscal_limit_guard.py),
[`tests/test_causal_gatekeeper.py`](../tests/test_causal_gatekeeper.py),
[`tests/test_routing_seal.py`](../tests/test_routing_seal.py) as patterns
to extend, not replace — check existing coverage in these files before
adding new tests to avoid duplication).

**Acceptance criterion:** overall `src/` coverage ≥ 60% (matching
`pytest.ini`'s existing `--cov-fail-under=60`), and each of the 10 modules
listed above individually reports ≥ 80% line coverage in
`--cov-report=term-missing` output.

**Guard against POAM-2026-030/032 recurrence:** any new test file added
under this step must exercise a module that is actually imported and
reachable from a production entry point (`hybrid_server.py`,
`compliance_bridge/main.py`, or a LangGraph node registered in
`symbolic_governor.py`). Before merging, run:
```bash
python3 -c "import ast, sys; ..."  # or manually confirm via grep -r "import <module>" src/
```
to confirm the module under test is not dead scaffold code, mirroring the
audit performed for POAM-2026-032 (see
[`docs/POAM.md:110`](../docs/POAM.md:110)).

### Step 4 — Remove the `--no-cov` bypass from documented run commands

**Files to edit:**
- [`tests/README.md`](../tests/README.md): the "Quick Start" and "Running
  Tests" sections (lines 7-66) currently show `uv run pytest tests/` as
  the default invocation with no mention of `--no-cov`. Confirm no
  contributor-facing doc anywhere in the repository recommends `--no-cov`
  as a way to get a green local run; if found, replace with guidance to
  fix the underlying coverage gap instead. Add a new subsection under
  "Running Tests" (after line 66) documenting the coverage workflow:

  ```markdown
  ### Coverage

  The suite enforces a minimum coverage floor via `pytest.ini`'s
  `--cov-fail-under=60`. To see which lines are uncovered:

  \`\`\`bash
  uv run pytest --cov=src --cov-report=term-missing --cov-report=html
  open htmlcov/index.html
  \`\`\`

  Do not use `--no-cov` to work around a failing coverage gate — this
  disables the check entirely rather than fixing the gap. If a specific
  module cannot reasonably be covered (e.g. generated protobuf code),
  add it to the `omit` list in `.coveragerc` with a comment explaining why.
  ```

- Search the full repository for any other `--no-cov` references in
  scripts or documentation (`grep -rn "no-cov" --include="*.md" --include="*.sh" .`)
  and remove/replace each occurrence found.

**Verification:**
- `uv run pytest` (no flags) passes locally with ≥ 60% coverage and 0
  failures — this is also Acceptance Criterion #1 in the checklist below.
- `grep -rn "no-cov" tests/README.md Makefile scripts/` returns no matches.

---

## P1 — Sprint 1 (1–2 weeks): Post-Deploy Verification Loop

**Problem:** `gateway`, `compliance-bridge`, and `governed-financial-advisor`
ran stale images for three days after commit `0c38976` landed on `main`.
Nothing in the deployment pipeline asserts that the digests actually
running in the cluster match what Cloud Build most recently produced for
`main` HEAD. [`scripts/verify_remote.py`](../scripts/verify_remote.py)
currently checks HTTP-level health and routing-seal enforcement (see
[`scripts/verify_remote.py:15-30`](../scripts/verify_remote.py:15)) but has
no image-digest or CronJob-secret assertions. This gap is exactly what
allowed the 3-day drift to go unnoticed, and it is the same class of gap
that let the `reconciliation-worker` CronJob (P0/F4) run broken for an
unknown period without alerting anyone.

### Step 1 — Design `scripts/verify_deploy.sh`

Create a new script `scripts/verify_deploy.sh` (bash, following the style
of existing operational scripts like
[`scripts/deploy_bg.sh`](../scripts/deploy_bg.sh) and
[`scripts/port_forward_dev.sh`](../scripts/port_forward_dev.sh)) that
performs three checks and exits non-zero on any failure:

**Check 1 — Running image digests match latest Cloud Build output:**
```bash
NAMESPACE="${K8S_NAMESPACE:-governance-stack}"
PROJECT_ID="${GOOGLE_CLOUD_PROJECT:?GOOGLE_CLOUD_PROJECT must be set}"

for deployment in gateway compliance-bridge governed-financial-advisor; do
  running_digest=$(kubectl get deployment "${deployment}" -n "${NAMESPACE}" \
    -o jsonpath='{.spec.template.spec.containers[0].image}' | \
    awk -F'@' '{print $2}')

  latest_build_digest=$(gcloud builds list \
    --filter="images:${deployment}" \
    --limit=1 --format="value(results.images[0].digest)" \
    --project="${PROJECT_ID}")

  if [ "${running_digest}" != "${latest_build_digest}" ]; then
    echo "DRIFT DETECTED: ${deployment} running=${running_digest:-<tag-pinned, no digest>} latest_build=${latest_build_digest}"
    exit_code=1
  else
    echo "OK: ${deployment} matches latest Cloud Build digest"
  fi
done
```

Note: this requires deployments to be pinned by digest (`image@sha256:...`)
rather than by mutable tag (`:latest`) for the comparison to be meaningful
— see POAM-2026-013 ([`docs/POAM.md:69`](../docs/POAM.md:69), "Container
image tags not yet pinned to digests in all deployment manifests"). This
script surfaces exactly the gap POAM-2026-013 already tracks; closing
POAM-2026-013 is a prerequisite for this check to be fully effective and
should be sequenced alongside this work.

**Check 2 — CronJob-referenced Secrets have required keys:**
```bash
declare -A required_secret_keys=(
  ["reconciliation-worker-secrets"]="kms-governance-key"
  ["redis-credentials"]="REDIS_URL REDIS_PASSWORD"
)

for secret in "${!required_secret_keys[@]}"; do
  for key in ${required_secret_keys[$secret]}; do
    value=$(kubectl get secret "${secret}" -n "${NAMESPACE}" \
      -o jsonpath="{.data.${key}}" 2>/dev/null)
    if [ -z "${value}" ]; then
      echo "MISSING SECRET KEY: ${secret}/${key}"
      exit_code=1
    fi
  done
done
```

Extend the `required_secret_keys` map based on which provider is active
(read `RECONCILIATION_PROVIDER` from the live CronJob spec first, then
require either the `gcs-*` or `s3-*` key set accordingly) so the script
itself cannot drift from the manifest the way the manifests drifted from
each other in F4.

**Check 3 — Recently completed CronJob runs:**
```bash
for cronjob in reconciliation-worker; do
  last_run_status=$(kubectl get jobs -n "${NAMESPACE}" \
    -l "app=${cronjob}" --sort-by=.status.startTime -o json | \
    python3 -c "import json,sys; jobs=json.load(sys.stdin)['items']; print(jobs[-1]['status'].get('succeeded', 0) if jobs else 'NO_RUNS')")
  if [ "${last_run_status}" != "1" ]; then
    echo "CRONJOB NOT HEALTHY: ${cronjob} last run status=${last_run_status}"
    exit_code=1
  fi
done

exit "${exit_code:-0}"
```

### Step 2 — Wire into GitHub Actions as a required post-deploy step

Since GKE deployment in this repository is triggered manually via
`./deploy_all.sh` or `make deploy-bg` (per
[`docs/operations/DEPLOYMENT_RULES.md`](../docs/operations/DEPLOYMENT_RULES.md))
rather than by a GitHub Actions deploy workflow, add a new scheduled
workflow `.github/workflows/post-deploy-verify.yml` that runs
`scripts/verify_deploy.sh` against the live dev cluster on a schedule
(e.g. every 30 minutes) and on `workflow_dispatch`, rather than gating a
push-triggered deploy job that does not currently exist:

```yaml
name: "Post-Deploy Verification"
on:
  schedule:
    - cron: "*/30 * * * *"
  workflow_dispatch:

jobs:
  verify-deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: google-github-actions/auth@v2
        with:
          credentials_json: ${{ secrets.GCP_SA_KEY }}
      - uses: google-github-actions/get-gke-credentials@v2
        with:
          cluster_name: ${{ vars.GKE_CLUSTER_NAME }}
          location: ${{ vars.GKE_LOCATION }}
      - name: Run post-deploy verification
        run: bash scripts/verify_deploy.sh
        env:
          GOOGLE_CLOUD_PROJECT: ${{ vars.GOOGLE_CLOUD_PROJECT }}
          K8S_NAMESPACE: governance-stack
```

If/when a push-triggered GKE deploy workflow is introduced, this job
should additionally run as a blocking final step of that workflow (not
`continue-on-error`), immediately after the Cloud Build + `kubectl apply`
steps complete.

### Step 3 — Add `make verify-deploy` to the Makefile

**File to edit:** [`Makefile`](../Makefile)

```makefile
## Verify running cluster image digests match latest Cloud Build output
## and that CronJob-referenced Secrets are fully populated.
verify-deploy: scripts/verify_deploy.sh
	@chmod +x scripts/verify_deploy.sh
	@bash scripts/verify_deploy.sh
```

Add `verify-deploy` to the `.PHONY` list at the top of
[`Makefile`](../Makefile:3-22) alongside the existing targets.

**Verification:**
- `make verify-deploy` exits 0 against a healthy cluster and non-zero (with
  a clear diagnostic line identifying which deployment/secret/CronJob is
  the problem) against a deliberately drifted or misconfigured cluster
  (test by manually editing a Deployment's image tag or deleting a secret
  key in a scratch/dev namespace).
- The `post-deploy-verify` workflow run history in GitHub Actions shows
  green runs on the configured schedule.

---

## P1 — Sprint 2 (2–4 weeks): Unblock Integration Tests in CI

**Problem:** 165 tests carrying `integration`, `slow`, `eu_ecb`, `us_fed`,
`apac_mas`, or `local` markers (see marker definitions in
[`pytest.ini:8-18`](../pytest.ini:8)) are skipped in the default run, and
the one CI job that does run integration-marked tests —
[`integration-smoke`](../.github/workflows/ci.yml:384-407) — is annotated
`continue-on-error: true`, meaning it can fail indefinitely without
blocking any merge. [`tests/test_nexart_integration.py`](../tests/test_nexart_integration.py)
is additionally excluded for being too slow, despite actually being marked
`@pytest.mark.local` throughout (all 6 test classes) rather than
`integration` — suggesting the "too slow to run" exclusion is a
process/convention issue (contributors skip it manually) rather than a
marker-based CI exclusion, and should be fixed by clarifying its marker
usage and timeout budget rather than assuming it needs a live-service gate.

### Step 1 — Make `integration-smoke` a hard gate

**File to edit:** [`.github/workflows/ci.yml:384-407`](../.github/workflows/ci.yml:384)

```yaml
  integration-smoke:
    name: "Integration Smoke Tests"
    runs-on: ubuntu-latest
    needs: [pytest-logic]
    # continue-on-error: true   ← REMOVE this line entirely
    steps:
      ...
```

Before removing `continue-on-error`, run the job locally/in a scratch
branch first to confirm it currently passes reliably — if it does not
(e.g. due to missing live-service mocks), triage and fix those failures
first (see Step 2), otherwise removing the bypass will immediately start
blocking all merges on a job that was never actually validated end-to-end.

### Step 2 — Stand up a dedicated `ci-integration` workflow against a live cluster

**New file:** `.github/workflows/ci-integration.yml`

This workflow runs nightly (and on-demand) against a real test namespace,
distinct from the hermetic `pytest -m local` suite that runs on every PR:

```yaml
name: "Nightly Integration Suite"
on:
  schedule:
    - cron: "0 6 * * *"   # 06:00 UTC nightly
  workflow_dispatch:

jobs:
  integration-full:
    runs-on: ubuntu-latest
    timeout-minutes: 60
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: google-github-actions/auth@v2
        with:
          credentials_json: ${{ secrets.GCP_SA_KEY }}
      - uses: google-github-actions/get-gke-credentials@v2
        with:
          cluster_name: ${{ vars.GKE_CLUSTER_NAME }}
          location: ${{ vars.GKE_LOCATION }}
      - name: Create ephemeral test namespace
        run: kubectl create namespace ci-integration-${{ github.run_id }}
      - name: Port-forward required services
        run: |
          bash setup_test_env.sh --namespace ci-integration-${{ github.run_id }} &
          sleep 10
      - name: Install uv
        uses: astral-sh/setup-uv@37802adc94f370d6bfd71619e3f0bf239e1f3b78 # v7.6.0
      - name: Install dependencies
        run: uv sync --all-groups --all-extras
      - name: Run full integration + slow suite
        run: uv run pytest tests/ -m "integration or slow" --timeout=600 -v
      - name: Run nexart integration suite with timeout guard
        run: uv run pytest tests/test_nexart_integration.py --timeout=120 -v
      - name: Tear down ephemeral namespace
        if: always()
        run: kubectl delete namespace ci-integration-${{ github.run_id }} --ignore-not-found
```

### Step 3 — Document live-service requirements for contributors

**File to edit:** [`tests/README.md`](../tests/README.md)

The "Port-Forward Requirements" table
([`tests/README.md:132-155`](../tests/README.md:132)) already documents
which services back which ports; extend the "Pytest Markers" table
([`tests/README.md:70-81`](../tests/README.md:70)) with an explicit
"Requires" column mapping each marker to its live-service dependency:

| Marker | Requires |
|---|---|
| `integration` | Redis, OPA, vLLM (fast + reasoning), Langfuse — see Port-Forward table |
| `slow` | Varies per test; check individual test docstring |
| `eu_ecb` / `us_fed` / `apac_mas` | `CAGE_DEPLOYMENT_REGION` set; some require live Lula/OPA per region |
| `red_team` | NeMo Guardrails + vLLM (adversarial payload evaluation) |

Add a short "Running tests that require live services" section
cross-referencing `./setup_test_env.sh` and the new `ci-integration.yml`
workflow, so a contributor knows both how to run these locally and where
they run automatically in CI.

### Step 4 — Enable `test_nexart_integration.py` in the nightly suite with a timeout guard

Already included in the Step 2 workflow above
(`--timeout=120` on the dedicated invocation). Confirm the 120s budget is
sufficient by timing a local run first:
```bash
time uv run pytest tests/test_nexart_integration.py -v
```
Adjust the timeout value in the workflow to the observed runtime plus a
50% margin.

**Verification:**
- `integration-smoke` shows as a required check in the repository's branch
  protection rules for `main` (GitHub Settings → Branches).
- `ci-integration.yml` nightly run history shows consistent green runs
  over at least 5 consecutive nights before considering this item closed.
- `tests/README.md` diff reviewed to confirm the new "Requires" column and
  live-service section are present.

---

## P1 — Sprint 2 (2–4 weeks): Compliance Suite in CI

**Problem:** The [`compliance/`](../compliance/) directory's Lula
(`compliance/lula/`) and OSCAL (`compliance/oscal/`) artifacts are
currently only checked for **YAML structural validity** in CI (see
[`lula-ai600-validation`](../.github/workflows/ci.yml:322-351) job and the
per-region structure checks in
[`.github/workflows/eu-ecb-compliance.yml`](../.github/workflows/eu-ecb-compliance.yml)
and
[`.github/workflows/apac-mas-compliance.yml`](../.github/workflows/apac-mas-compliance.yml))
— none of these actually run `lula validate` against a live cluster. Per
[`compliance/lula/README.md`](../compliance/lula/README.md), the majority
of non-universal manifests are marked `🔶 Stub`, meaning even a live run
would currently only meaningfully validate the small set of `✅ Active`
controls (`a52`, `a53`, `a92`, `aarm-vectors` [stub], `tqp007`,
`iso001-token-quota`, `sc4`, `eu-fria`). This is the actual compliance
attestation gap: POAM.md and `compliance/lula/README.md` claim controls are
"Implemented," but no CI job proves it against a running cluster on every
merge.

### Step 1 — Add a `lula-validate` CI job against the dev cluster

**New/extended file:** `.github/workflows/lula2-pr-compliance.yml` (extend
existing) or a new job appended to
[`.github/workflows/ci.yml`](../.github/workflows/ci.yml):

```yaml
  lula-validate-live:
    name: "Lula Live Validation (dev cluster)"
    runs-on: ubuntu-latest
    needs: [pytest-logic]
    if: github.ref == 'refs/heads/main'
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: google-github-actions/auth@v2
        with:
          credentials_json: ${{ secrets.GCP_SA_KEY }}
      - uses: google-github-actions/get-gke-credentials@v2
        with:
          cluster_name: ${{ vars.GKE_CLUSTER_NAME }}
          location: ${{ vars.GKE_LOCATION }}
      - name: Install Lula
        run: |
          curl -fsSL -H "Authorization: token ${{ github.token }}" \
            "https://github.com/defenseunicorns-labs/lula1/releases/download/v0.16.0/lula_v0.16.0_Linux_amd64" \
            -o /usr/local/bin/lula
          chmod +x /usr/local/bin/lula
      - name: Run lula validate against all Active manifests
        run: |
          for manifest in compliance/lula/lula-validation-*.yaml; do
            echo "Validating ${manifest}..."
            lula validate -f "${manifest}" || echo "::warning::${manifest} failed — see run log"
          done
      - name: Run lula validate strict on universal + SC-4 (must pass)
        run: |
          for manifest in compliance/lula/lula-validation-a52.yaml \
                           compliance/lula/lula-validation-a53.yaml \
                           compliance/lula/lula-validation-a92.yaml \
                           compliance/lula/lula-validation-tqp007.yaml \
                           compliance/lula/lula-validation-iso001-token-quota.yaml \
                           compliance/lula/lula-validation-sc4.yaml; do
            lula validate -f "${manifest}"
          done
```

This job must run **after every merge to `main` that touches `src/`,
`deployment/k8s/`, or `compliance/lula/`** — implement this with a `paths`
filter on the workflow's `push` trigger:

```yaml
on:
  push:
    branches: [main]
    paths:
      - "src/**"
      - "deployment/k8s/**"
      - "compliance/lula/**"
```

### Step 2 — Add a `coverage-compliance` job for posture-specific suites

**File to edit:** [`.github/workflows/ci.yml`](../.github/workflows/ci.yml)
(a variant of this already exists as `eu-ecb-bias-eval`, see
[`.github/workflows/ci.yml:145-163`](../.github/workflows/ci.yml:145), but
it is conditioned on `vars.CAGE_DEPLOYMENT_REGION == 'EU_ECB'` and does not
also cover `us_fed/opa`):

```yaml
  coverage-compliance:
    name: "Regional Posture Suites (dev cluster)"
    runs-on: ubuntu-latest
    needs: [pytest-logic]
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: astral-sh/setup-uv@37802adc94f370d6bfd71619e3f0bf239e1f3b78 # v7.6.0
      - name: Install OPA
        run: |
          curl -sSL "https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static" \
            -o /usr/local/bin/opa
          chmod +x /usr/local/bin/opa
      - name: Run US_FED OPA posture tests
        run: opa test compliance/postures/us_fed/opa/ -v
      - name: Install dependencies
        run: uv sync --all-groups --all-extras
      - name: Run EU_ECB LLM bias eval posture tests
        env:
          CAGE_DEPLOYMENT_REGION: EU_ECB
          VLLM_FAST_API_BASE: ${{ vars.VLLM_FAST_API_BASE || 'http://localhost:8001/v1' }}
        run: uv run pytest compliance/postures/eu_ecb/llm_eval/ -v --timeout=300
```

### Step 3 — Add a POAM/Lula divergence check

Add an automated check: if [`docs/POAM.md`](../docs/POAM.md) marks a
finding "✅ Closed" but the corresponding Lula assertion fails, CI must
fail with a human-readable error naming the divergence. This requires a
mapping from POAM IDs / control IDs to Lula manifest filenames — the
`compliance/lula/README.md` and `docs/POAM.md` "Lula Validation Coverage"
table (see [`docs/POAM.md:121-156`](../docs/POAM.md:121)) already provide
this mapping in prose form; formalize it into a small script,
`scripts/check_poam_lula_divergence.py`, that:

1. Parses `docs/POAM.md`'s "Security Strengths" table (claims of
   "✅ Implemented") and "Closed Findings" table.
2. Cross-references each claimed control against the `compliance/lula/`
   manifest that asserts it (via the control-ID column already present in
   both documents).
3. Runs `lula validate -f <manifest>` for each mapped manifest.
4. Fails with a clear message (`DIVERGENCE: POAM.md claims SC-4 Implemented
   but lula-validation-sc4.yaml FAILED validation`) if any claimed-closed
   control's Lula assertion does not pass.

This script is the seed of the broader `poam-drift-check` described in the
P2 "Ongoing" section below — implement the core parsing/cross-reference
logic here in Sprint 2, then extend it for nightly scheduling in the P2
phase.

**Verification:**
- `lula-validate-live` job appears in the Actions history for the next
  `main`-branch merge touching `src/`, `deployment/k8s/`, or
  `compliance/lula/`.
- `coverage-compliance` job passes against the dev cluster.
- `scripts/check_poam_lula_divergence.py --dry-run` runs successfully
  against the current `docs/POAM.md` and reports zero divergences (or, if
  divergences are found, they are triaged and either the POAM entry or the
  Lula manifest is corrected before this item is marked closed).

---

## P2 — Q4 2026: Regional Posture Completion (EU_ECB / APAC_MAS)

**Problem:** [`docs/POAM.md`](../docs/POAM.md) lists five open regional
findings, all targeted `2026-12-31`:
`EU-DORA-001`, `EU-AI-ACT-001`, `EU-GDPR-001` (see
[`docs/POAM.md:82-85`](../docs/POAM.md:82)), `APAC-MAS-FEAT-001`,
`APAC-MAS-N655-001`, `APAC-MAS-TRM-001` (see
[`docs/POAM.md:91-93`](../docs/POAM.md:91)). Their corresponding Lula
manifests (`lula-validation-dora-art10.yaml`, `lula-validation-eu-ai-act-art9.yaml`,
`lula-validation-gdpr-art22.yaml`, `lula-validation-mas-feat.yaml`,
`lula-validation-mas-notice655.yaml`, `lula-validation-mas-trm-s6.yaml`)
are all marked `🔶 Stub` in
[`compliance/lula/README.md`](../compliance/lula/README.md). Tests for
these postures (`eu_ecb`, `apac_mas` markers) are skip-marked in local
runs and their CI workflows
([`.github/workflows/eu-ecb-compliance.yml`](../.github/workflows/eu-ecb-compliance.yml),
[`.github/workflows/apac-mas-compliance.yml`](../.github/workflows/apac-mas-compliance.yml))
only validate YAML structure, not live behavior.

### Per-finding remediation definition

For each open finding, define the specific code change, Lula assertion
update, and OSCAL component update required:

**`EU-DORA-001` (DORA Art. 10 — ICT operational resilience evidence):**
- Code: implement a `compliance_bridge` endpoint exposing ICT incident/
  resilience-test evidence (extend
  [`src/compliance_bridge/main.py`](../src/compliance_bridge/main.py) with
  a `GET /compliance/dora/resilience-evidence` route backed by
  [`src/compliance_bridge/audit_workflow.py`](../src/compliance_bridge/audit_workflow.py)
  data).
- Lula: replace the stub `domain`/`provider` block in
  [`compliance/lula/lula-validation-dora-art10.yaml`](../compliance/lula/lula-validation-dora-art10.yaml)
  with an `api` domain assertion against the new endpoint.
- OSCAL: update the DORA control mapping in
  [`compliance/oscal/eu-ai-act-profile.yaml`](../compliance/oscal/eu-ai-act-profile.yaml)
  or a new dedicated DORA profile file, and
  [`compliance/oscal/system-security-plan-eu-ecb.yaml`](../compliance/oscal/system-security-plan-eu-ecb.yaml).

**`EU-AI-ACT-001` (EU AI Act Art. 9 — risk management system evidence):**
- Code: extend `compliance_bridge` with a risk-management evidence
  endpoint surfacing FTRA/CBF/causal-gatekeeper decision logs (these
  already exist as governance mechanisms — this closes the evidentiary
  export gap, not a governance-logic gap).
- Lula: replace stub in
  [`compliance/lula/lula-validation-eu-ai-act-art9.yaml`](../compliance/lula/lula-validation-eu-ai-act-art9.yaml).
- OSCAL: update
  [`compliance/oscal/eu-ai-act-profile.yaml`](../compliance/oscal/eu-ai-act-profile.yaml).

**`EU-GDPR-001` (GDPR Art. 22 — human oversight of automated decisions):**
- Code: extend `compliance_bridge` with an endpoint exposing HITL
  escalation records from
  [`src/gateway/governance/hitl_escalator.py`](../src/gateway/governance/hitl_escalator.py)
  and [`src/gateway/governance/defer_queue.py`](../src/gateway/governance/defer_queue.py).
- Lula: replace stub in
  [`compliance/lula/lula-validation-gdpr-art22.yaml`](../compliance/lula/lula-validation-gdpr-art22.yaml).
- OSCAL: update EU_ECB SSP
  ([`compliance/oscal/system-security-plan-eu-ecb.yaml`](../compliance/oscal/system-security-plan-eu-ecb.yaml)).

**`APAC-MAS-FEAT-001` (MAS FEAT — fairness/ethics/accountability/transparency):**
- Code: implement the `demographic_parity_gap` metric export referenced in
  [`compliance/lula/README.md`](../compliance/lula/README.md)
  ("`demographic_parity_gap ≤ 0.08`, 180-day transparency report") —
  likely a new module under `src/compliance_bridge/` computing this from
  Langfuse trace data.
- Lula: replace stub in
  [`compliance/lula/lula-validation-mas-feat.yaml`](../compliance/lula/lula-validation-mas-feat.yaml).
- OSCAL: update
  [`compliance/oscal/mas-feat-profile.yaml`](../compliance/oscal/mas-feat-profile.yaml).

**`APAC-MAS-N655-001` / `APAC-MAS-TRM-001` (MAS Notice 655 / TRM §6.3):**
- Code: extend `compliance_bridge` with a technology-risk-management audit
  logging endpoint.
- Lula: replace stubs in
  [`compliance/lula/lula-validation-mas-notice655.yaml`](../compliance/lula/lula-validation-mas-notice655.yaml)
  and
  [`compliance/lula/lula-validation-mas-trm-s6.yaml`](../compliance/lula/lula-validation-mas-trm-s6.yaml).
- OSCAL: update
  [`compliance/oscal/system-security-plan-apac-mas.yaml`](../compliance/oscal/system-security-plan-apac-mas.yaml).

Each of the above is a **shared-module-impact change** per
[`AGENTS.md`](../AGENTS.md) if it touches `src/compliance_bridge/` — the PR
description for each must include the three-region impact statement
(US_FED / EU_ECB / APAC_MAS), even where the change is region-specific in
intent, per the existing convention in
[`plans/SECURITY_REMEDIATION_PLAN.md`](SECURITY_REMEDIATION_PLAN.md).

### Add a `regional-posture-check` CI matrix job

**New/extended file:** append to
[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) or as a
dedicated workflow:

```yaml
  regional-posture-check:
    name: "Regional Posture (${{ matrix.region }})"
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        region: [US_FED, EU_ECB, APAC_MAS]
    # Hard gate for US_FED; soft gate for EU_ECB/APAC_MAS until their
    # findings above are closed.
    continue-on-error: ${{ matrix.region != 'US_FED' }}
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: astral-sh/setup-uv@37802adc94f370d6bfd71619e3f0bf239e1f3b78 # v7.6.0
      - name: Install dependencies
        run: uv sync --all-groups --all-extras
      - name: Run regional posture tests
        env:
          CAGE_DEPLOYMENT_REGION: ${{ matrix.region }}
        run: |
          case "${{ matrix.region }}" in
            US_FED)   uv run pytest tests/ -m us_fed -v ;;
            EU_ECB)   uv run pytest tests/ -m eu_ecb -v ;;
            APAC_MAS) uv run pytest tests/ -m apac_mas -v ;;
          esac
```

### Set US_FED regional posture tests to hard-gate by end of Sprint 2

Once the P1 Sprint 2 coverage/integration work lands and US_FED-marked
tests are confirmed stable, keep `continue-on-error: false` for the
`US_FED` matrix cell unconditionally (already achieved by the
`continue-on-error: ${{ matrix.region != 'US_FED' }}` expression above);
the remaining work is validating the US_FED cell is reliably green for at
least 5 consecutive runs before treating this item as closed, matching the
verification bar used elsewhere in this plan.

**Verification:**
- Each of the five open regional findings has a merged PR referencing its
  POAM ID, with the corresponding Lula manifest changed from `🔶 Stub` to
  `✅ Active` in [`compliance/lula/README.md`](../compliance/lula/README.md).
- `regional-posture-check` matrix job shows `US_FED` as a required
  (non-`continue-on-error`) check in branch protection; `EU_ECB` and
  `APAC_MAS` remain informational until their respective findings close.

---

## P2 — Ongoing: POAM/Runtime Reconciliation Process

**Problem:** [`docs/POAM.md`](../docs/POAM.md) closure claims are
currently updated manually by whoever fixes the underlying issue, with no
automated cross-check against live cluster or Lula-assertion state before
the "✅ Closed" status is committed. This is precisely the mechanism that
allowed the reconciliation-worker CronJob (F4) to remain broken while
POAM-2026-038 described only a "residual gap" rather than a full outage,
and it is the general mechanism behind Finding 5 (compliance-claim vs.
runtime-truth divergence) across all three regional postures.

### Standing process definition

Before any POAM finding is marked "✅ Closed" in
[`docs/POAM.md`](../docs/POAM.md), the closing commit must include or
reference:
1. The commit SHA implementing the fix.
2. A `lula validate` run (or `pytest` run for findings not covered by a
   Lula manifest) executed against the **live dev cluster**, with output
   captured in the PR description or linked CI run.
3. If the finding maps to a Lula manifest per the
   Lula Validation Coverage table in [`docs/POAM.md`](../docs/POAM.md),
   that manifest's status in
   [`compliance/lula/README.md`](../compliance/lula/README.md) must be
   updated from `🔶 Stub` to `✅ Active` in the same PR, if applicable.

Document this process in [`CONTRIBUTING.md`](../CONTRIBUTING.md) alongside
the existing "Contributing to Remediation" guidance already present near
the end of [`docs/POAM.md`](../docs/POAM.md), which should be updated to
reference the new `poam-drift-check` script (below) as the automated
enforcement mechanism.

### `poam-drift-check` script

Extend `scripts/check_poam_lula_divergence.py` (introduced in P1 Sprint 2
Step 3) into the full `poam-drift-check`:

1. Parse [`docs/POAM.md`](../docs/POAM.md)'s "Closed Findings" table for
   all rows.
2. For each closed finding, resolve its control ID(s) to a Lula manifest
   via the Lula Validation Coverage table in
   [`docs/POAM.md`](../docs/POAM.md) or
   [`compliance/lula/README.md`](../compliance/lula/README.md).
3. Run `lula validate -f <manifest>` against the live dev cluster for each
   resolved manifest.
4. Report any closed finding whose manifest is missing, still `🔶 Stub`, or
   fails validation, with output formatted as:
   ```
   DRIFT: POAM-2026-031 (closed 2026-07-27) maps to no Active Lula manifest — cannot verify against live cluster.
   DRIFT: POAM-2026-001 (closed 2026-06-08) — lula-validation-ac2.yaml is still Stub, cannot verify AC-2 claim.
   ```
5. Exit non-zero if any drift is found.

### Wire into nightly CI

Add `poam-drift-check` as a step in the nightly
`.github/workflows/ci-integration.yml` workflow introduced in P1 Sprint 2
(or a new dedicated `.github/workflows/poam-drift-check.yml` running on the
same nightly schedule), against the live dev cluster:

```yaml
  poam-drift-check:
    name: "POAM / Lula Drift Check"
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: google-github-actions/auth@v2
        with:
          credentials_json: ${{ secrets.GCP_SA_KEY }}
      - uses: google-github-actions/get-gke-credentials@v2
        with:
          cluster_name: ${{ vars.GKE_CLUSTER_NAME }}
          location: ${{ vars.GKE_LOCATION }}
      - name: Install Lula
        run: |
          curl -fsSL -H "Authorization: token ${{ github.token }}" \
            "https://github.com/defenseunicorns-labs/lula1/releases/download/v0.16.0/lula_v0.16.0_Linux_amd64" \
            -o /usr/local/bin/lula
          chmod +x /usr/local/bin/lula
      - name: Run POAM drift check
        run: python3 scripts/check_poam_lula_divergence.py --strict
```

**Verification:**
- [`CONTRIBUTING.md`](../CONTRIBUTING.md) updated with the standing
  POAM-closure process.
- `poam-drift-check` runs nightly with a visible pass/fail history in
  GitHub Actions.
- A deliberately-introduced drift (e.g. temporarily reverting a manifest to
  `🔶 Stub` status in a scratch branch while the POAM entry still claims
  closure) is caught by the script in a test run before this item is
  marked closed.

---

## Acceptance Criteria

The full remediation is considered "done" when all of the following hold:

- [ ] `uv run pytest` (without `--no-cov`) passes with ≥ 60% coverage and 0 failures
- [ ] `make verify-deploy` passes after every Cloud Build run
- [ ] `integration-smoke` CI job is a hard gate (no `continue-on-error`)
- [ ] Lula assertions run in CI against dev cluster on every merge to `main` touching `src/`, `deployment/k8s/`, or `compliance/lula/`
- [ ] `reconciliation-worker` CronJob shows `Completed` in `kubectl get jobs -n governance-stack`
- [ ] POAM-2026-038 re-closed with Lula assertion evidence from live cluster
- [ ] US_FED regional posture tests pass as a hard gate in `regional-posture-check`
- [ ] `poam-drift-check` runs nightly and reports no divergences
- [ ] All 10 governance-critical modules listed in P1 Sprint 1 individually report ≥ 80% line coverage
- [ ] `tests/README.md` documents the coverage workflow and contains no `--no-cov` guidance
- [ ] `compliance/lula/README.md` shows the six EU_ECB/APAC_MAS stub manifests promoted to `✅ Active` (or explicitly re-targeted with a new date and rationale if still open)

---

## Risk Register

| Risk | If Remediation Is Delayed |
|---|---|
| **Coverage gate not fixed** | Ongoing test-coverage illusions persist; governance-logic regressions (e.g. a future `fiscal_limit_guard.py` or `routing_seal.py` defect) ship undetected, repeating the POAM-2026-030/032 pattern of false coverage confidence at larger scale. |
| **Reconciliation worker not fixed** | SC-4 fiscal-limit enforcement remains degraded indefinitely — `fiscal_limit_guard.py` continues operating on un-reconciled, self-reported Redis counters, reintroducing the recursive self-authentication vulnerability that `reconciliation_worker.py`'s own module docstring warns against (see [`src/compliance_bridge/reconciliation_worker.py:23-36`](../src/compliance_bridge/reconciliation_worker.py:23)). |
| **Integration tests not gating merges** | Integration-layer defects (webhook delivery failures, OPA/NeMo/Redis wiring regressions, MCP tool-server contract breaks) are undetected until they surface in a live deployment — exactly the class of failure that produced the 3-day image-drift incident and the broken CronJob in this plan's own source findings. |
| **POAM/runtime divergence not addressed** | `docs/POAM.md` and Lula/OSCAL evidence pulled from a degraded cluster produce false compliance attestations to regulators or auditors across all three regional postures — a reputational and (in a real production adoption) potential legal-exposure risk, since the reference architecture's entire value proposition is verifiable governance claims. |
| **Regional posture gaps not closed** | EU_ECB and APAC_MAS deployments remain either blocked from claiming compliance or exposed to undetected non-compliance with DORA, EU AI Act, GDPR Art. 22, MAS FEAT, MAS Notice 655, and MAS TRM §6.3 — all six findings share a 2026-12-31 target date, so delay compounds linearly toward that deadline with no buffer for remediation of issues discovered late. |

---

## Related Documents

- [`plans/SECURITY_REMEDIATION_PLAN.md`](SECURITY_REMEDIATION_PLAN.md) — prior remediation plan for 28 static-analysis security findings; establishes the Cat-S/Cat-N change-classification convention reused here.
- [`plans/CORRECTION_PLAN_2026-08-04.md`](CORRECTION_PLAN_2026-08-04.md) — prior remediation plan for local test-suite and live-deployment defects; establishes the P0/P1/P2 tiering convention reused here.
- [`docs/POAM.md`](../docs/POAM.md) — authoritative compliance posture statement; updated throughout this plan's execution.
- [`docs/operations/DEPLOYMENT_RULES.md`](../docs/operations/DEPLOYMENT_RULES.md) — Cloud Build / Terraform deployment rules referenced throughout P0 and P1.
- [`AGENTS.md`](../AGENTS.md) — canonical source for commit conventions, branch naming, shared-module impact declarations, and compliance artifact obligations applicable to every work item in this plan.
