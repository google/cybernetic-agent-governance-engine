# CAGE — Merge-to-Main Plan with Test Strategy

> **Generated:** 2026-07-25  
> **Context:** CAGE is an open-source reference architecture for agentic AI
> governance. The `ci/github-automation-updates` branch establishes the
> governance process for all subsequent merges and **must land first**.

---

## Why `ci/github-automation-updates` Must Merge First

`ci/github-automation-updates` (commit `77ac9e2`) adds:

| Artifact | Effect | Activates when |
|---|---|---|
| `.github/CODEOWNERS` | Requires `@lahlfors` review on `src/`, `compliance/`, `.github/`, `docs/`, `config/` | File is in `main` (GitHub reads CODEOWNERS from default branch only) |
| `.github/workflows/ref_impl_signoff.yml` | Runs lint + unit tests + license header check on every PR to `main`; publishes GitHub Releases on `v*-ref` tags | Workflow is in `main` |
| `.github/workflows/compliance-matrix.yml` additions | POAM-023 reconciliation gate (advisory, `continue-on-error: true` for live-cluster steps) | Workflow is in `main` |
| `.github/workflows/dependency-review.yml` | License allowlist for plaid-python and opentelemetry-sdk | Workflow is in `main` |
| `.github/pull_request_template.md` | Specification fidelity checklist; AO sign-off framed as structural review, not operational CAB | Used immediately on next PR |

**None of these take effect until the branch is merged to `main`.** All
subsequent PRs — including the security patches — should go through CODEOWNERS
review and the `ref_impl_signoff` CI gate. Since `@lahlfors` is both the
CODEOWNERS reviewer and the security patch author, this is not a blocker.

---

## Merge Order

| Step | Branch / PR | Type | Requires Step 1? | GKE cycle |
|---|---|---|---|---|
| **1** | `ci/github-automation-updates` | CI/Process | — | None |
| **2a** | `fix/GHSA-hfqj-24cj-693g-*` (author) | Security | Yes | Cycle 1 |
| **2b** | `fix/GHSA-v3h4-8458-5ww3-*` (author) | Security | Yes | Cycle 1 |
| **3a** | PR #22 `email-regex-redos` | Security | Yes | Cycle 2 |
| **3b** | PR #24 `content-disposition-audit-id` | Security | Yes | Cycle 2 |
| **3c** | PR #26 `slack-alert-mrkdwn-escape` | Security | Yes | Cycle 2 |
| **3d** | PR #23 `evidence-chain-metadata-binding` | Integrity | Yes | Cycle 3 |
| **4** | `feat/POAM-023-cbf-external-reconcil` | Feature | Yes | Cycle 4 |
| **5a** | `feat/CAGE-001-phase-a-ingress-adapters` | Feature | Yes | Cycle 5 |
| **5b** | `feat/CAGE-002-phase-b-agw-absorption` | Feature | Yes | Cycle 5 |
| **5c** | `feat/FTRA-001-commencement-reachability` | Feature | Yes | Cycle 6 |
| **5d** | `feat/CAGE-003-phase-c-agent-registry-integration` | Feature | Yes | Cycle 6 |
| **6a** | PR #25 github-actions bump | Deps | Yes | None |
| **6b** | PR #27 torch 2.10→2.13 | Deps | Yes | Cycle 7 (if vLLM active) |

---

## Step 1 — `ci/github-automation-updates` (merge first)

**Branch:** `ci/github-automation-updates` (commit `77ac9e2`)  
**PR:** Open against `main` — this PR is exempt from its own CODEOWNERS rule
(CODEOWNERS is not yet in `main` when this PR is reviewed).

**What it establishes for all subsequent PRs:**
- CODEOWNERS review requirement on `src/`, `compliance/`, `.github/`, `docs/`, `config/`
- `ref_impl_signoff` CI gate: lint + unit tests + license header check on every PR to `main`
- POAM-023 compliance-matrix gate
- Specification fidelity PR template (AO sign-off = structural review, not operational CAB)
- Release publisher on `v*-ref` / `v*-cage-*` tags

**CI gates (existing, before this workflow is active):** `license-check`, `lint`  
**GKE:** Not required.

**Manual GitHub config to apply alongside this merge:**
- In repo Settings → Branches → Branch protection rules for `main`:
  - Enable "Require a pull request before merging"
  - Enable "Require status checks to pass" → add `CI Gate — Lint & Tests`
    (from `ref_impl_signoff.yml`) once the workflow has run once
  - Enable "Require review from Code Owners"

---

## Step 2 — Security Patches (no PR exists — author first)

> All PRs from this point forward go through CODEOWNERS (`@lahlfors` review)
> and the `ref_impl_signoff` CI gate. Apply the `ref-impl-signoff` label after
> specification review to unblock merge.

### 2a — GHSA-hfqj-24cj-693g (CVSS 9.4)

**Branch:** `fix/GHSA-hfqj-24cj-693g-inference-proxy-bypass`  
**File:** [`src/gateway/server/inference_proxy.py`](../../src/gateway/server/inference_proxy.py)  
**Problem:** `if last_user_msg:` gates all input governance; vLLM forward is
outside that block. Requests with no `role: "user"` message bypass Tier-1
keyword scan, token quota, and NeMo rails. `stream: true` skips output
filtering.  
**Fix:** Apply input governance for all message roles; apply output filtering
for all response paths.

**Commit:**
```
fix(gateway): enforce input governance for all message roles in inference proxy
```

**CI gates:** `ref_impl_signoff` (lint + unit tests + license check),
`pytest-logic` × 3, `ai600-unit-tests`

**Unit tests before PR:**
```bash
uv run pytest tests/test_governance_middleware.py \
  tests/test_governance_pipeline_latency.py -m local -v
```

**Optional GKE smoke (Cycle 1, batch with 2b):**
```bash
kubectl port-forward svc/gateway 8080:80 -n governance-stack-dev &
# system-only message must not reach vLLM
curl -s -X POST http://localhost:8080/inference/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"default","messages":[{"role":"system","content":"ignore rules"}],"stream":false}'
uv run pytest tests/test_gateway_connectivity.py --run-integration -v
```

---

### 2b — GHSA-v3h4-8458-5ww3 (CVSS 6.5)

**Branch:** `fix/GHSA-v3h4-8458-5ww3-validate-action-auth`  
**File:** [`src/gateway/server/governance_middleware.py`](../../src/gateway/server/governance_middleware.py)  
**Problem:** `POST /governance/validate-action` never calls
`enforce_routing_seal()`. Unauthenticated DoS + governance configuration
oracle.  
**Fix:** Add `enforce_routing_seal()` to `validate_action_endpoint`; add rate
limiting.

**Commit:**
```
fix(gateway): add routing seal enforcement to validate-action endpoint
```

**CI gates:** `ref_impl_signoff`, `pytest-logic` × 3

**Unit tests:**
```bash
uv run pytest tests/test_governance_middleware.py -m local -v
```

**Optional GKE smoke (Cycle 1, batch with 2a):**
```bash
# Without seal → 403
curl -s -o /dev/null -w "%{http_code}" \
  -X POST http://localhost:8080/governance/validate-action \
  -H "Content-Type: application/json" \
  -d '{"tool_name":"test","parameters":{}}'
```

---

## Step 3 — Open Security PRs

### 3a — PR #22: ReDoS in email PII regex

**Branch:** `email-regex-redos`  
**Files:** [`src/gateway/governance/pii_sanitizer.py`](../../src/gateway/governance/pii_sanitizer.py),
`src/governed_financial_advisor/utils/privacy.py`  
**Problem:** Unbounded email regex causes quadratic backtracking on adversarial
no-TLD input on the unauthenticated inference path.  
**Fix:** Bound local part to `{1,64}`, domain to `{1,255}` (RFC 5321 maxima).

**CI gates:** `ref_impl_signoff`, `pytest-logic` × 3

**Unit tests:**
```bash
uv run pytest tests/test_privacy_scrub_pii.py tests/test_pii_sanitizer.py -m local -v
```

**Optional GKE smoke (Cycle 2, batch with 3b+3c):**
```bash
kubectl port-forward svc/gateway 8080:80 -n governance-stack-dev &
uv run pytest tests/test_gateway_connectivity.py --run-integration -v
```

---

### 3b — PR #24: `Content-Disposition` header injection

**Branch:** `content-disposition-audit-id`  
**Files:** [`src/compliance_bridge/main.py`](../../src/compliance_bridge/main.py),
[`tests/test_compliance_bridge_tier2b.py`](../../tests/test_compliance_bridge_tier2b.py)  
**Problem:** `audit_id` interpolated raw into `Content-Disposition` filename
on `GET /v1/oscal/assessment-results` and `GET /v1/aarm/conformance-report`.  
**Fix:** `_filename_token()` strips unsafe chars, caps at 128 chars.

**CI gates:** `ref_impl_signoff`, `pytest-logic` × 3

**Unit tests:**
```bash
uv run pytest tests/test_compliance_bridge_tier2b.py -m local -v
```

**Optional GKE smoke (Cycle 2, batch with 3a+3c):**
```bash
kubectl port-forward svc/compliance-bridge 3001:80 -n governance-stack-dev &
COMPLIANCE_BRIDGE_URL=http://localhost:3001 ENVIRONMENT=integration \
uv run pytest tests/test_compliance_bridge_integration.py --run-integration -v --timeout=60
```

---

### 3c — PR #26: Slack mrkdwn injection

**Branch:** `slack-alert-mrkdwn-escape`  
**Files:** [`src/compliance_bridge/notifier.py`](../../src/compliance_bridge/notifier.py)  
**Problem:** `finding_id`, `remarks`, `audit_id` injected raw into Slack Block
Kit mrkdwn in `_build_critical_alert_body`.  
**Fix:** Route all three through existing `_escape_slack_mrkdwn()`.

**CI gates:** `ref_impl_signoff`, `pytest-logic` × 3

**Unit tests:**
```bash
uv run pytest tests/test_security_medium_severity.py -m local -v
```

**Optional GKE smoke:** Batch with 3a+3b (Cycle 2, `cloudbuild.compliance.yaml`).

---

### 3d — PR #23: evidence chain `record_hash` binding (isolated cycle)

**Branch:** `evidence-chain-metadata-binding`  
**Files:** `src/compliance_bridge/context_accumulator.py`,
`src/compliance_bridge/evidence_stream.py`  
**Problem:** `record_hash` only hashed `content_json`; metadata fields not
bound, allowing post-hoc alteration without chain invalidation.  
**Fix:** Bind all metadata into `SHA-256(prev_hash ‖ content_json ‖
control_id ‖ event_type ‖ node_index ‖ audit_id)`.

> ⚠️ **Breaking change for NDJSON artifacts.** Existing audit chain artifacts
> will not re-verify under the new hash. Snapshot any existing NDJSON artifacts
> before deploying. Consider bumping schema to `cage-context-accumulator/1.1`
> with version-dispatched verification.

**CI gates:** `ref_impl_signoff`, `pytest-logic` × 3

**Unit tests:**
```bash
uv run pytest tests/test_context_accumulator.py \
  tests/test_compliance_bridge_tier2.py -m local -v
```

**Optional GKE smoke (Cycle 3 — separate from 3a/3b/3c):**
```bash
kubectl port-forward svc/compliance-bridge 3001:80 -n governance-stack-dev &
COMPLIANCE_BRIDGE_URL=http://localhost:3001 ENVIRONMENT=integration \
uv run pytest tests/test_compliance_bridge_integration.py --run-integration -v --timeout=60
```

---

## Step 4 — POAM-023 Closure

**Branch:** `feat/POAM-023-cbf-external-reconcil` (commit `88edf6b`)  
**Files:** [`src/compliance_bridge/reconciliation_worker.py`](../../src/compliance_bridge/reconciliation_worker.py),
[`src/gateway/governance/cbf.py`](../../src/gateway/governance/cbf.py),
[`src/gateway/governance/symbolic_governor.py`](../../src/gateway/governance/symbolic_governor.py)

**What it does:**
- Switches CBF read path from `safety:current_cash` to
  `reconciliation:verified_balance` (KMS-signed, 300 s TTL)
- Implements `PlaidLedgerProvider` (Plaid Production / sandbox)
- Adds OTel span attributes `safety.balance.source` and
  `safety.balance.reconciled`
- Adds `_IS_PRODUCTION` guard: raises `RuntimeError` at startup if
  `RECONCILIATION_PROVIDER=stub` and `CAGE_ENV=production`
- 6 hermetic fakeredis tests in `test_cbf_reconciliation.py`

**CI gates:** `ref_impl_signoff`, `pytest-logic` × 3, `stpa-freshness-check`,
`lula-ai600-validation`, `compliance-matrix` (POAM-023 gate — this PR closes
it; gate passes with `RECONCILIATION_PROVIDER=plaid`)

**Unit tests:**
```bash
uv run pytest tests/test_cbf_reconciliation.py \
  tests/test_fiscal_limit_guard.py -m local -v
```

**Optional GKE smoke (Cycle 4 — isolated; use `RECONCILIATION_PROVIDER=stub`
for dev/research runs without Plaid credentials):**
```bash
kubectl port-forward svc/gateway 8080:80 -n governance-stack-dev &
kubectl port-forward svc/compliance-bridge 3001:80 -n governance-stack-dev &

GATEWAY_URL=http://localhost:8080 \
uv run pytest tests/test_gateway_connectivity.py --run-integration -v

COMPLIANCE_BRIDGE_URL=http://localhost:3001 ENVIRONMENT=integration \
uv run pytest tests/test_compliance_bridge_integration.py --run-integration -v --timeout=60

uv run pytest tests/test_redis_eviction_envelope.py --run-integration -v
```

---

## Step 5 — Feature Phases (sequential: A → B → FTRA → C)

> All feature branches require CODEOWNERS review + `ref-impl-signoff` label.
> Rebase each branch onto `main` before opening a PR to remove duplicate
> commits (see Rebase Notes below).

### 5a — `feat/CAGE-001-phase-a-ingress-adapters` (commit `3bf52e7`)

**Contents:** ACS, AAIF, OSCAL, Lula, AGP policy uploader ingress adapters.

**CI gates:** `ref_impl_signoff`, `pytest-logic` × 3, `stpa-freshness-check`

**Unit tests:**
```bash
uv run pytest tests/test_acs_adapter.py tests/test_aaif_adapter.py \
  tests/test_oscal_adapter.py tests/test_lula_adapter.py -m local -v
```

**Optional GKE smoke (Cycle 5, batch with 5b):**
```bash
kubectl port-forward svc/gateway 8080:80 -n governance-stack-dev &
uv run pytest tests/test_gateway_connectivity.py \
  tests/test_acs_adapter.py tests/test_aaif_adapter.py --run-integration -v
```

---

### 5b — `feat/CAGE-002-phase-b-agw-absorption` (commit `2bc9c41`)

**Contents:** Agent Gateway adapter + OIDC middleware.

**Pre-merge:** Rebase onto `main` after 5a lands — branch contains 5a commits
`3bf52e7` + `eb5c65a`; rebase drops them.

**CI gates:** `ref_impl_signoff`, `pytest-logic` × 3

**Optional GKE smoke (Cycle 5, batch with 5a):**
```bash
kubectl port-forward svc/gateway 8080:80 -n governance-stack-dev &
uv run pytest tests/test_gateway_connectivity.py --run-integration -v
```

---

### 5c — `feat/FTRA-001-commencement-reachability` (commit `0b38dfd`)

**Contents:** FTRA Tier 0.5 gate — NetworkX reachability analysis before first
LangGraph node; verdicts: `CLEAR` / `HITL_REQUIRED` / `BLOCKED`.

**CI gates:** `ref_impl_signoff`, `pytest-logic` × 3, `stpa-freshness-check`

**Unit tests:**
```bash
uv run pytest tests/test_cage_graph.py tests/test_defer_queue.py -m local -v
```

**Optional GKE smoke (Cycle 6, batch with 5d):**
```bash
uv run pytest tests/test_agent_accuracy.py tests/test_agent_performance.py \
  --run-integration -v --timeout=120
```

---

### 5d — `feat/CAGE-003-phase-c-agent-registry-integration` (commit `f98e0e6`)

**Contents:** GEAP Agent Registry adapter, `stpa_compiler --targets registry`,
OPA push via `PUT /v1/data/agent_catalog_data`, OSCAL AC-3 extension.

**Pre-merge:** Rebase onto `main` after 5c lands — branch contains `0b38dfd`
(FTRA commit); rebase drops it.

**CI gates:** `ref_impl_signoff`, `pytest-logic` × 3, `stpa-freshness-check`

**Unit tests:**
```bash
uv run pytest tests/test_agent_registry_adapter.py -m local -v
```

**Optional GKE smoke (Cycle 6, batch with 5c):**
```bash
kubectl port-forward svc/opa 8181:8181 -n governance-stack-dev &
curl http://localhost:8181/v1/data/agent_catalog_data | python3 -m json.tool
```

---

## Step 6 — Dependency Bumps

### PR #25: github-actions-all bump

**Branch:** `dependabot/github_actions/github-actions-all-1a4669c17b`  
**CI:** `ref_impl_signoff`, `license-check` — approve and merge directly.  
**GKE:** Not required.

### PR #27: torch 2.10.0 → 2.13.0

**Branch:** `dependabot/uv/uv-c20c29ea69`  
**Note:** torch 2.13 has a ROCm regression (`torch.compile` on CPU fails
without a GPU). For CPU-only inference in this reference architecture, verify
before merging.

**CI:** `ref_impl_signoff`, `pytest-logic` × 3

**Optional GKE smoke (Cycle 7, only if vLLM is active):**
```bash
kubectl port-forward svc/vllm 8081:80 -n vllm &
curl http://localhost:8081/v1/models
uv run pytest tests/test_gateway_connectivity.py -k "chat_proxy" --run-integration -v
```

---

## GKE Deployment Cycle Summary

All GKE deployments use Cloud Build — never local `docker build`:
```bash
gcloud builds submit --config deployment/docker/cloudbuild.<service>.yaml \
  --substitutions=_GCP_PROJECT_ID=<project>
```

| Cycle | Steps | Images | Key integration tests |
|---|---|---|---|
| **1** | 2a + 2b | `gateway` | `test_gateway_connectivity.py --run-integration` |
| **2** | 3a + 3b + 3c | `gateway` + `compliance-bridge` | `test_gateway_connectivity.py` + `test_compliance_bridge_integration.py` |
| **3** | 3d | `compliance-bridge` | `test_compliance_bridge_integration.py` (full suite) |
| **4** | 4 | `gateway` + `compliance-bridge` | `test_gateway_connectivity.py` + `test_compliance_bridge_integration.py` + `test_redis_eviction_envelope.py` |
| **5** | 5a + 5b | `gateway` | `test_gateway_connectivity.py` + adapter tests |
| **6** | 5c + 5d | `gateway` + `advisor` | `test_agent_accuracy.py` + OPA catalog probe |
| **7** | 6b (if needed) | `vllm` | `test_gateway_connectivity.py -k chat_proxy` |

---

## Rebase Notes

Before opening PRs for feature branches, rebase to remove duplicate commits:

```bash
# 5b contains 5a commits — rebase after 5a merges
git checkout feat/CAGE-002-phase-b-agw-absorption
git rebase main
git push --force-with-lease origin feat/CAGE-002-phase-b-agw-absorption

# 5d contains 5c commit (0b38dfd) — rebase after 5c merges
git checkout feat/CAGE-003-phase-c-agent-registry-integration
git rebase main
git push --force-with-lease origin feat/CAGE-003-phase-c-agent-registry-integration
```
