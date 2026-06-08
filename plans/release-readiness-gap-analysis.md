# CAGE v2.0.0 Release Readiness Gap Analysis

**Version:** 1.0.0
**Date:** 2026-06-08
**Analyst:** CAGE Governance Agent
**Scope:** Token Quota Proxy Implementation Plan (`plans/token-quota-proxy-impl-plan.md`) vs. v2.0.0 Release Gates
**Authority:** `.clinerules` §5, `docs/V2_RELEASE_PLAN.md` §8.10, `.github/pull_request_template.md`

---

## Executive Summary

**Verdict: CONDITIONALLY READY**

The Token Quota Proxy implementation plan (`plans/token-quota-proxy-impl-plan.md`) is a well-structured, compliance-aware plan that correctly addresses ISO 42001 Annex A.4 evidence requirements. However, **the plan alone is insufficient to gate a stable v2.0.0 release**. The plan covers one feature PR in a larger release that has **five pre-existing P0/P1 blockers** (D-01 through D-07) documented in `docs/V2_RELEASE_PLAN.md` that must be resolved independently.

The implementation plan itself is internally compliant with `.clinerules` standards (branch naming, commit format, license headers, cross-region declarations, CHANGELOG). The critical gaps are:

1. **D-01 (P0):** Committed secrets in working tree and git history — not addressed by this plan
2. **D-02 (P0):** `governed-financial-advisor` pod `MinimumReplicasUnavailable` — not addressed by this plan
3. **D-04 (P0):** HMAC seal enforcement disabled (broken Terraform wiring) — not addressed by this plan
4. **D-06 (P1):** `security-scanner-cronjob` missing — not addressed by this plan
5. **D-07 (P1):** PSA labels not applied — not addressed by this plan
6. **Lula re-run:** The plan defers Lula validation to post-merge; this must be confirmed passing before the v2.0.0 tag
7. **STPA freshness:** The plan explicitly defers UCA-4 STPA model update; the CI `stpa-freshness-check` job must still pass

The Token Quota Proxy PR can be merged to `main` independently of the P0 blockers, but **the v2.0.0 stable tag cannot be applied until all universal gates in §5.1 of `.clinerules` are green**, including the five pre-existing blockers addressed in `docs/V2_RELEASE_PLAN.md`.

---

## Gate Evaluation — Universal (All Regions)

> Source: `.clinerules` §5.1, `docs/V2_RELEASE_PLAN.md` §8.10 Universal Gates checklist.
> These gates must ALL pass before `git tag -a v2.0.0` is executed.

| # | Gate | Plan Coverage | Existing Infrastructure | Gap? | Action Required |
|---|------|--------------|------------------------|------|-----------------|
| U-01 | ISO 42001 Lula assertion passes: `lula-validation-a52.yaml` (A.5.2 — NeMo toxicity/injection blocking ≥99%) | **Partial** — plan adds OPA `tool_approved` rule that strengthens A.5.2 evidence; does not directly modify the Lula assertion | Assertion exists; queries `compliance-bridge /v1/metrics/A.5.2`; requires live cluster with NeMo traces | **Yes — deferred** | Run `lula validate -f compliance/lula/lula-validation-a52.yaml` post-merge; confirm PASS before tagging |
| U-02 | ISO 42001 Lula assertion passes: `lula-validation-a53.yaml` (A.5.3 — logging/monitoring safety rate ≥98%) | **Partial** — plan adds `stamp_iso_control(A.4)` OTel spans that contribute to A.5.3 evidence | Assertion exists; queries `compliance-bridge /v1/metrics/A.5.3` | **Yes — deferred** | Run `lula validate -f compliance/lula/lula-validation-a53.yaml` post-merge; confirm PASS |
| U-03 | ISO 42001 Lula assertion passes: `lula-validation-a92.yaml` (A.9.2 — PII leak rate = 0.0%) | **Yes** — plan adds `pii_sanitizer.py` pre-ledger sanitization; directly strengthens A.9.2 evidence | Assertion exists; queries `compliance-bridge /v1/metrics/A.9.2`; zero-tolerance threshold | **Yes — deferred** | Run `lula validate -f compliance/lula/lula-validation-a92.yaml` post-merge; confirm PASS |
| U-04 | CSA AARM Lula assertion passes: `lula-validation-aarm-vectors.yaml` (all 11 vectors; 7 critical = NEUTRALIZED) | **Partial** — plan's PII sanitizer strengthens AARM-V10 (Data Exfiltration); quota proxy strengthens AARM-V4 (Cross-Agent Propagation) | Assertion exists; queries `compliance-bridge /v1/aarm/conformance-report`; requires `aarm_mapper.py` to report all 11 vectors | **Yes — deferred** | Run `lula validate -f compliance/lula/lula-validation-aarm-vectors.yaml` post-merge; confirm PASS |
| U-05 | SBOM generated and validated | **No** — plan does not address SBOM | `scripts/generate_sbom.py` exists; `deployment/k8s/sbom-cronjob.yaml` referenced in V2 plan | **Yes — pre-existing** | Run `python scripts/generate_sbom.py`; validate output; confirm no new unresolved dependencies from new files |
| U-06 | Container image vulnerability scan passes (Trivy — no CRITICAL unmitigated) | **No** — plan does not address Trivy scan | `security-scanner-cronjob` manifest created in D-06 remediation; Trivy image `aquasec/trivy:0.51.4` | **Yes — pre-existing (D-06)** | D-06 must be resolved first (`deployment/k8s/security-scan-cronjob.yaml` applied); then trigger manual Trivy scan |
| U-07 | Secret detection scan passes (zero secrets in codebase) | **No** — plan does not address secret scan | D-01 remediation in `docs/V2_RELEASE_PLAN.md` §3.2 covers this; git history rewrite required | **Yes — P0 blocker (D-01)** | Complete Phase 1–3 of `docs/V2_RELEASE_PLAN.md`; run `git log --all -S "<credential>"` → zero matches |
| U-08 | All unit and integration tests pass (`pytest-logic` CI job — `uv run pytest tests/ -m local -v`) | **Yes** — plan includes full test suite: `test_token_quota_proxy.py`, `test_uca_logger.py`, `test_pii_sanitizer.py`; Phase 3.5 runs full CI | CI job `pytest-logic` in `.github/workflows/ci.yml` runs `uv run pytest tests/ -m local -v` | **Yes — deferred** | New test files must pass; full `pytest tests/ -m local` must show 0 failures after merge |
| U-09 | STPA freshness check passes (`stpa-freshness-check` CI job — `scripts/check_stpa_freshness.py`) | **Partial** — plan §13.4 explicitly defers UCA-4 STPA model update; recommends NOT adding UCA-4 to `stpa_control_structure.yaml` in this PR | CI job `stpa-freshness-check` in `.github/workflows/ci.yml` runs `python scripts/check_stpa_freshness.py --verbose` | **Yes — must verify** | Confirm `config/stpa_control_structure.yaml` is NOT modified by this PR; if it is, regenerate `generated_stpa_validator.py` before merge |
| U-10 | Langfuse posture verified (`langfuse-posture-check` CI job — `scripts/verify_langfuse_posture.py --dry-run`) | **Yes** — plan §12.4 PR checklist includes `scripts/verify_langfuse_posture.py` passes | CI job `langfuse-posture-check` in `.github/workflows/ci.yml` runs `python3 scripts/verify_langfuse_posture.py --dry-run --posture development` | **Yes — deferred** | CI must pass on PR; also run `python3 scripts/verify_langfuse_posture.py` against live cluster before tagging |
| U-11 | `git log --all -S "<any-credential>"` returns zero matches | **No** — plan does not address git history | D-01 remediation (Phase 3 git history rewrite) in `docs/V2_RELEASE_PLAN.md` §5 | **Yes — P0 blocker (D-01)** | Complete Phase 3 history rewrite; verify with `git log --all -S "CYBERNETIC_GOVERNANCE_2025"` → zero output |
| U-12 | `governed-financial-advisor` READY 1/1, AVAILABLE 1 | **No** — plan does not address pod availability | D-02 remediation in `docs/V2_RELEASE_PLAN.md` §3.6 and §6.3 | **Yes — P0 blocker (D-02)** | Complete Phase 4b Cloud Build trigger; verify `kubectl get deployment governed-financial-advisor -n governance-stack` → READY 1/1 |
| U-13 | `CAGE_ROUTING_SEAL_SECRET` present in `advisor-secrets` (≥64 chars) | **No** — plan does not address seal secrets | D-04 Terraform wiring in `docs/V2_RELEASE_PLAN.md` §3.3 and §6.2 | **Yes — P0 blocker (D-04)** | Complete Phase 4a Terraform apply; verify `kubectl get secret advisor-secrets -n governance-stack -o jsonpath='{.data.CAGE_ROUTING_SEAL_SECRET}' \| base64 -d \| wc -c` → ≥64 |
| U-14 | `GOVERNANCE_SALT` present in `advisor-secrets` (≥64 chars) | **No** — plan does not address governance salt | D-04 Terraform wiring in `docs/V2_RELEASE_PLAN.md` §3.3 | **Yes — P0 blocker (D-04)** | Same as U-13; both secrets wired via same Terraform apply |
| U-15 | Unsigned gateway request returns 403 | **No** — plan does not address seal enforcement | D-04 HMAC seal enforcement; Phase 5 verification in `docs/V2_RELEASE_PLAN.md` §7.2 | **Yes — P0 blocker (D-04)** | Complete Phase 5 seal enforcement verification; `curl` unsigned request → 403 |
| U-16 | Valid signed gateway request returns 200 | **No** — plan does not address seal enforcement | Phase 5 verification in `docs/V2_RELEASE_PLAN.md` §7.3 | **Yes — P0 blocker (D-04)** | Complete Phase 5; generate valid seal token → `curl` → 200 |
| U-17 | `security-scanner-cronjob` exists in `governance-stack` namespace | **No** — plan does not address CronJob | D-06 remediation: `deployment/k8s/security-scan-cronjob.yaml` created in `docs/V2_RELEASE_PLAN.md` §3.4 | **Yes — P1 blocker (D-06)** | Apply `kubectl apply -f deployment/k8s/security-scan-cronjob.yaml`; verify `kubectl get cronjob security-scanner-cronjob -n governance-stack` |
| U-18 | PSA labels applied: `governance-stack=restricted`, `langfuse=baseline`, `vllm=baseline` | **No** — plan does not address PSA labels | D-07 remediation in `docs/V2_RELEASE_PLAN.md` §3.5 and §6.4 | **Yes — P1 blocker (D-07)** | Complete Phase 4c; apply `deployment/k8s/pod-security-admission.yaml`; verify namespace labels |
| U-19 | `git tag v2.0.0` pushed to origin (annotated tag, `chore(release)` format) | **No** — plan does not address tagging | Tag procedure in `docs/V2_RELEASE_PLAN.md` §8.8 | **Yes — final gate** | Execute only after all other universal gates pass; `git tag -a v2.0.0 -m "chore(release): stable v2.0.0 ..."` |
| U-20 | GitHub Release published as Latest | **No** — plan does not address GitHub Release | `docs/V2_RELEASE_PLAN.md` §8.9 | **Yes — final gate** | `gh release create v2.0.0 --title "v2.0.0 — Stable Release" --notes-file CHANGELOG.md --target rc-v2.0.0` |
| U-21 | `terraform.auto.tfvars` confirmed gitignored (no secrets in working tree) | **No** — plan does not address Terraform secrets | `infra/targets/gcp-gke/.gitignore` covers `*.auto.tfvars`; plan §12.4 confirms no secrets in committed files | **No — already satisfied** | Verify `git status` shows `terraform.auto.tfvars` as untracked; confirm `.gitignore` entry |
| U-22 | License headers present on all new `.py` files in `src/` (`license-check` CI job) | **Yes** — plan §3.1, §3.2, §3.3 explicitly state "Apache 2.0 required" for all three new files | CI job `license-check` in `.github/workflows/ci.yml` checks `find src/ -name '*.py'` for "Apache License" or "Copyright 2026" | **No — addressed by plan** | Implement files with headers as specified; CI will enforce |

---

## Gate Evaluation — US_FED (Region-Specific, Not a Global Blocker)

> Source: `.clinerules` §5.2. These gates apply **exclusively** to `CAGE_DEPLOYMENT_REGION=US_FED` deployments.
> **EU_ECB and APAC_MAS stable releases are NOT blocked by NIST gates.**
> The user has confirmed NIST/OSCAL/ATO gates are US_FED-only requirements.

| # | Gate | Plan Coverage | Existing Infrastructure | Gap for US_FED? | Action Required |
|---|------|--------------|------------------------|-----------------|-----------------|
| F-01 | All 10 NIST SP 800-53 Lula assertions pass (`lula-validation-ac2.yaml`, `lula-validation-ac3.yaml`, `lula-validation-au12.yaml`, `lula-validation-cm6.yaml`, `lula-validation-ia3.yaml`, `lula-validation-ia5.yaml`, `lula-validation-ir6.yaml`, `lula-validation-ra5.yaml`, `lula-validation-sc8.yaml`, `lula-validation-si2.yaml`) | **Partial** — plan's OPA additions may affect `lula-validation-ac3.yaml` (access control) | All 10 Lula files exist in `compliance/lula/`; currently only 4 of 15 total manifests are Active per `docs/V2_RELEASE_PLAN.md` §8.4 | **Yes — US_FED only** | Run all 10 NIST Lula validations; activate stub manifests per `compliance/lula/README.md` |
| F-02 | NIST SP 800-53 coverage ≥45% (via `oscal_ssp_exporter.py`) | **No** — plan does not address NIST coverage | Currently 24% at `v2.0.0-dev.1`; `src/gateway/governance/oscal_ssp_exporter.py` exists | **Yes — US_FED only** | Document additional implemented controls in OSCAL SSP; re-run exporter to verify ≥45% |
| F-03 | ATO process initiated (OSCAL SSP submitted to AO) | **No** — plan does not address ATO | ATO package components exist: `compliance/pia/`, `compliance/sar/SAR_2026Q1.md`, `docs/POAM.md` | **Yes — US_FED only** | Compile ATO package; submit to designated AO (currently TBD per `docs/V2_RELEASE_PLAN.md` §8.7) |
| F-04 | POAM items documented for all open findings (POAM-011, POAM-012, R-21) | **No** — plan does not address POAM | `docs/POAM.md` exists; POAM-011 (SC-8 TLS gap), POAM-012 (SC-12 KMS), R-21 (NeMo race) documented | **Yes — US_FED only** | Verify `docs/POAM.md` is current; add CTRL_TQP_007 if any open findings arise from the new component |

---

## Gate Evaluation — EU_ECB (Region-Specific, Not a Global Blocker)

> Source: `.clinerules` §5.3. These gates apply **exclusively** to `CAGE_DEPLOYMENT_REGION=EU_ECB` deployments.

| # | Gate | Plan Coverage | Existing Infrastructure | Gap for EU_ECB? | Action Required |
|---|------|--------------|------------------------|-----------------|-----------------|
| E-01 | EU AI Act compliance posture verified | **No** — plan does not address EU AI Act | `infra/targets/gcp-gke/eu-dev.tfvars` exists | **Yes — EU_ECB only** | Verify no new High-Risk AI behaviour introduced; FRIA attestation not required for quota enforcement |
| E-02 | GDPR data residency confirmed: all paths within `europe-west1` | **Yes** — plan §8.4 gates WORM bucket on `CAGE_DEPLOYMENT_REGION`; `_get_worm_bucket()` maps EU_ECB → `OSCAL_S3_BUCKET_EU_ECB` | `eu-dev.tfvars` configures `europe-west1` | **No — addressed by plan** | Verify `OSCAL_S3_BUCKET_EU_ECB` points to `europe-west1` bucket in deployment config |
| E-03 | DORA Art. 10 audit logging enabled (`enable_audit_logging = true` in `eu-dev.tfvars`) | **No** — plan does not address DORA | `infra/targets/gcp-gke/eu-dev.tfvars` exists | **Yes — EU_ECB only** | Verify `enable_audit_logging = true` in `eu-dev.tfvars` |
| E-04 | SR 26-2 telemetry suppression active (`"no legal force"` sentinel intact) | **No** — plan does not address SR 26-2 | EU baseline sentinel must remain intact | **Yes — EU_ECB only** | Verify `"no legal force"` sentinel not removed from EU baseline |

---

## Gate Evaluation — APAC_MAS (Region-Specific, Not a Global Blocker)

> Source: `.clinerules` §5.4. These gates apply **exclusively** to `CAGE_DEPLOYMENT_REGION=APAC_MAS` deployments.

| # | Gate | Plan Coverage | Existing Infrastructure | Gap for APAC_MAS? | Action Required |
|---|------|--------------|------------------------|-------------------|-----------------|
| A-01 | MAS FEAT compliance posture verified | **No** — plan does not address MAS FEAT | `infra/targets/gcp-gke/apac-dev.tfvars` exists | **Yes — APAC_MAS only** | Verify MAS FEAT posture unaffected by quota enforcement addition |
| A-02 | MAS TRM §4.2 data residency confirmed: all paths within `asia-southeast1` | **Yes** — plan §8.4 gates WORM bucket on `CAGE_DEPLOYMENT_REGION`; `_get_worm_bucket()` maps APAC_MAS → `OSCAL_S3_BUCKET_APAC_MAS` | `apac-dev.tfvars` configures `asia-southeast1` | **No — addressed by plan** | Verify `OSCAL_S3_BUCKET_APAC_MAS` points to `asia-southeast1` bucket |
| A-03 | MAS Notice 655 audit logging enabled (`enable_audit_logging = true` in `apac-dev.tfvars`) | **No** — plan does not address MAS Notice 655 | `infra/targets/gcp-gke/apac-dev.tfvars` exists | **Yes — APAC_MAS only** | Verify `enable_audit_logging = true` in `apac-dev.tfvars` |
| A-04 | SR 26-2 telemetry suppression active (`"no legal force"` sentinel intact) | **No** — plan does not address SR 26-2 | APAC baseline sentinel must remain intact | **Yes — APAC_MAS only** | Verify `"no legal force"` sentinel not removed from APAC baseline |

---

## Critical Gaps (Blocking v2.0.0 Stable Release)

The following gaps **must be closed** before `git tag -a v2.0.0` is executed. They are ordered by the dependency chain in `docs/V2_RELEASE_PLAN.md`.

1. **[D-01 / U-07 / U-11] Committed secrets in working tree and git history (P0)**
   - Secrets present: `CYBERNETIC_GOVERNANCE_2025` in `deployment/k8s/live_deployment.yaml`, `REDACTED_REDIS_PASSWORD` sentinel in `tests/test_redis_eviction_envelope.py`, Langfuse keys, Redis/PostgreSQL passwords, GCS HMAC key, HuggingFace token in commits `200da00`, `72f8f3d`, `6b14314`, `18c5bac`, `bf4e84c`
   - Required: Complete `docs/V2_RELEASE_PLAN.md` Phase 1 (working tree fix), Phase 2 (credential rotation), Phase 3 (git history rewrite via `git filter-repo`)
   - Gate: `git log --all -S "CYBERNETIC_GOVERNANCE_2025" --oneline` → zero output; secret detection scan passes

2. **[D-02 / U-12] `governed-financial-advisor` pod MinimumReplicasUnavailable (P0)**
   - Required: Complete `docs/V2_RELEASE_PLAN.md` Phase 4b — Cloud Build trigger for `deployment/k8s/financial-advisor.yaml`
   - Gate: `kubectl get deployment governed-financial-advisor -n governance-stack` → READY 1/1, AVAILABLE 1

3. **[D-04 / U-13 / U-14 / U-15 / U-16] HMAC seal enforcement disabled — broken Terraform wiring (P0)**
   - Required: Complete `docs/V2_RELEASE_PLAN.md` Phase 4a — Terraform apply wiring `CAGE_ROUTING_SEAL_SECRET` and `GOVERNANCE_SALT` through module chain; Phase 5 seal enforcement verification
   - Gate: Unsigned request → 403; valid signed request → 200; both secrets ≥64 chars in `advisor-secrets`

4. **[D-06 / U-17] `security-scanner-cronjob` missing in `governance-stack` namespace (P1)**
   - Required: `kubectl apply -f deployment/k8s/security-scan-cronjob.yaml` (manifest created in `docs/V2_RELEASE_PLAN.md` §3.4)
   - Gate: `kubectl get cronjob security-scanner-cronjob -n governance-stack` → exists; also required for `lula-validation-ra5.yaml` RA-5 assertion (US_FED gate)

5. **[D-07 / U-18] PSA labels not applied to namespaces (P1)**
   - Required: Complete `docs/V2_RELEASE_PLAN.md` Phase 4c — `kubectl apply -f deployment/k8s/pod-security-admission.yaml`; Terraform apply for `governance-stack` PSA version labels
   - Gate: `governance-stack` namespace has `pod-security.kubernetes.io/enforce=restricted`; `langfuse` and `vllm` namespaces have `enforce=baseline`

6. **[U-01 through U-04] Lula assertions not yet re-validated post-merge**
   - The Token Quota Proxy PR modifies `src/gateway/governance/` (shared module). Per `.clinerules` §14.8 and `docs/CHANGE_MANAGEMENT_PROCESS.md` §5.5, Lula validation must be re-run after merge.
   - Required: Run `lula validate` against all four universal Lula files (`lula-validation-a52.yaml`, `lula-validation-a53.yaml`, `lula-validation-a92.yaml`, `lula-validation-aarm-vectors.yaml`) against live cluster post-merge
   - Gate: All four return PASS

7. **[U-05] SBOM not generated for new components**
   - The three new Python files (`token_quota_proxy.py`, `uca_logger.py`, `pii_sanitizer.py`) introduce new dependencies (e.g., `fakeredis` in tests, `pyyaml` for YAML serialization). SBOM must be regenerated.
   - Required: `python scripts/generate_sbom.py`; validate output includes new files; no new unresolved CRITICAL CVEs
   - Gate: SBOM generated and validated; Trivy scan passes (no CRITICAL unmitigated)

8. **[U-08] New test files must pass in CI `pytest-logic` job**
   - CI job `pytest-logic` in `.github/workflows/ci.yml` runs `uv run pytest tests/ -m local -v`. New test files must be marked with `@pytest.mark.local` or equivalent to be picked up.
   - Required: Verify test files use correct pytest markers; confirm `uv run pytest tests/ -m local -v` → 0 failures
   - Gate: `pytest-logic` CI job green on PR

---

## Implementation Plan Compliance Review

This section evaluates the plan itself against `.clinerules` mandatory standards.

### Branch Naming (`.clinerules` §2.1–2.3)

| Check | Plan Value | Compliant? | Notes |
|-------|-----------|-----------|-------|
| Pattern | `feat/TQP-001-token-quota-proxy` | **Yes** | Matches `feat/<ticket-id>-short-description` |
| Ticket ID present | `TQP-001` | **Yes** | Required for `feat/` branches |
| Description length | `token-quota-proxy` = 18 chars | **Yes** | Within 30-char limit |
| Lowercase kebab-case | Yes | **Yes** | No underscores, no uppercase |
| Branch from latest `main` | Specified in §12.2 | **Yes** | `git checkout main && git pull origin main` before branching |

### Commit Message Format (`.clinerules` §1.1–1.6)

| Commit | Subject Line | Length | Type Valid? | Imperative? | Compliant? |
|--------|-------------|--------|------------|------------|-----------|
| Phase 1a | `feat(governance): add pii sanitizer with regex redaction pipeline` | 63 chars | Yes | Yes | **Yes** |
| Phase 1b | `feat(governance): add token quota proxy with redis atomic counters` | 66 chars | Yes | Yes | **Yes** |
| Phase 1c | `feat(governance): add uca logger with kms signing and worm persistence` | 71 chars | Yes | Yes | **Yes** |
| Phase 1d | `chore(governance): add token quota threshold config yaml` | 57 chars | Yes | Yes | **Yes** |
| Phase 2a | `feat(governance): integrate token quota proxy into inference pipeline` | 70 chars | Yes | Yes | **Yes** |
| Phase 2b | `feat(governance): pre-warm quota proxy in hybrid server lifespan` | 65 chars | Yes | Yes | **Yes** |
| Phase 2c | `feat(governance): add quota and approved-tools rego rules to system-authz` | 74 chars | **No** | Yes | **FAIL — 74 chars exceeds 72-char limit** |
| Phase 3a | `test(governance): add unit tests for pii sanitizer redaction pipeline` | 70 chars | Yes | Yes | **Yes** |
| Phase 3b | `test(governance): add unit tests for token quota proxy circuit breaker` | 71 chars | Yes | Yes | **Yes** |
| Phase 3c | `test(governance): add unit tests for uca logger compliance records` | 67 chars | Yes | Yes | **Yes** |
| Phase 4a | `docs(compliance): update changelog for token quota proxy cat-n change` | 70 chars | Yes | Yes | **Yes** |
| Phase 4b | `chore(governance): add ctrl-tqp-007 to regional compliance baselines` | 70 chars | Yes | Yes | **Yes** |
| Squash PR | `feat(governance): add token quota proxy with UCA logging and PII sanitization` | 79 chars | Yes | Yes | **FAIL — 79 chars exceeds 72-char limit** |

> **Action required:** Two commit messages exceed the 72-character limit enforced by the `commit-msg` hook (`.github/workflows/ci.yml` and `docs/GIT_WORKFLOW_STANDARDS.md` §2.4). The Phase 2c commit and the squash PR title must be shortened before the PR is opened. Suggested fixes:
> - Phase 2c: `feat(governance): add quota rego rules to system-authz` (53 chars)
> - Squash PR title: `feat(governance): add token quota proxy with UCA logging` (56 chars)

### License Headers (`.clinerules` §10.1–10.3, CI `license-check` job)

| File | Header Required? | Plan Specifies Header? | Compliant? |
|------|-----------------|----------------------|-----------|
| `src/gateway/governance/token_quota_proxy.py` | Yes (new `.py` in `src/`) | **Yes** — §3.1 states "Apache 2.0 required" | **Yes** |
| `src/gateway/governance/uca_logger.py` | Yes (new `.py` in `src/`) | **Yes** — §3.2 states "Apache 2.0 required" | **Yes** |
| `src/gateway/governance/pii_sanitizer.py` | Yes (new `.py` in `src/`) | **Yes** — §3.3 states "Apache 2.0 required" | **Yes** |
| `config/thresholds/token_quota.yaml` | No (not a `.py/.ts/.tsx/.js` file) | N/A | **Yes** |
| `tests/test_token_quota_proxy.py` | Yes (new `.py` in `src/` path? No — in `tests/`) | CI checks `find src/ -name '*.py'`; `tests/` is not scanned | **Yes — not required by CI** |

> **Note:** The CI `license-check` job scans `find src/ -name '*.py'`. Test files under `tests/` are not checked. The three new source files under `src/gateway/governance/` must have headers; the plan correctly specifies this.

### CHANGELOG.md Update (`.clinerules` §8.5, `docs/CHANGE_MANAGEMENT_PROCESS.md` §9.4)

| Check | Plan Coverage | Compliant? |
|-------|--------------|-----------|
| Cat-N change requires CHANGELOG update | **Yes** — §11.2 provides full CHANGELOG entry template with `[CR-2026-TQP-001]` | **Yes** |
| Format: `[CR-YYYY-NNN] description, reviewed-by, approved date, implemented date, Lula result` | **Yes** — §11.2 includes all required fields | **Yes** |
| Phase 4.1 explicitly updates CHANGELOG | **Yes** — Phase 4 step 4.1 | **Yes** |
| Lula validation result field | **Partial** — listed as "Pending (run after merge)" | **Acceptable** — must be updated post-merge |

### Cross-Region Impact Declaration (`.clinerules` §3.7, §12.1–12.4)

| Check | Plan Coverage | Compliant? |
|-------|--------------|-----------|
| Shared module touched (`src/gateway/governance/`) | Yes — three new files + modifications to `inference_proxy.py`, `hybrid_server.py` | Triggers §3.7 requirement |
| US_FED impact declared | **Yes** — §12.4 PR template: "CTRL_TQP_007 added to US_FED_BASELINE.json; WORM bucket uses OSCAL_S3_BUCKET_US_FED" | **Yes** |
| EU_ECB impact declared | **Yes** — §12.4 PR template: "CTRL_TQP_007 added to EU_ECB_BASELINE.json; WORM bucket uses OSCAL_S3_BUCKET_EU_ECB (europe-west1)" | **Yes** |
| APAC_MAS impact declared | **Yes** — §12.4 PR template: "CTRL_TQP_007 added to APAC_MAS_BASELINE.json; WORM bucket uses OSCAL_S3_BUCKET_APAC_MAS (asia-southeast1)" | **Yes** |
| `CAGE_DEPLOYMENT_REGION` guard on new storage paths | **Yes** — §8.4 `_get_worm_bucket()` gates on `CAGE_DEPLOYMENT_REGION` | **Yes** |

### Lula Re-Run Requirement (`.clinerules` §14.8, `docs/CHANGE_MANAGEMENT_PROCESS.md` §5.5)

| Check | Plan Coverage | Compliant? |
|-------|--------------|-----------|
| Lula re-run required post-merge for shared module changes | **Partial** — §13.5 mentions "Run `lula validate` against all four Lula validation files after merge" | **Partial** |
| Specific Lula files listed | **Yes** — §13.5 references "all four Lula validation files" | **Yes** |
| Lula re-run result must pass before production promotion | **Yes** — §13.5 states "results must pass before production promotion" | **Yes** |
| Lula re-run not gated in CI (requires live cluster) | **Acknowledged** — plan correctly notes this is a post-merge, pre-promotion step | **Acceptable** |

### STPA Freshness (`.clinerules` §11.4, CI `stpa-freshness-check` job)

| Check | Plan Coverage | Compliant? |
|-------|--------------|-----------|
| STPA freshness check CI job will pass | **Yes** — §13.4 explicitly recommends NOT modifying `config/stpa_control_structure.yaml` | **Yes — if recommendation followed** |
| Rationale documented | **Yes** — §13.4 explains UCA-4 is handled directly by `token_quota_proxy.py`, not via STPA compiler | **Yes** |
| Risk if `stpa_control_structure.yaml` is accidentally modified | **Acknowledged** — §13.4 notes regeneration procedure | **Yes** |

### PR Template Completeness (`.github/pull_request_template.md`, `.clinerules` §3.2)

| Section | Plan Coverage | Compliant? |
|---------|--------------|-----------|
| Summary | **Yes** — §12.4 provides full paragraph | **Yes** |
| Type of Change | **Yes** — `feat`, compliance/governance, tests checked | **Yes** |
| Related Issues / ADRs | **Yes** — `Closes #TQP-001`, `[CR-2026-TQP-001]` | **Yes** |
| Changes Made | **Yes** — bullet list of all 8 changed/new files | **Yes** |
| Testing | **Yes** — unit tests, 3-step audit suite, full CI, Langfuse posture | **Yes** |
| Compliance & Security Checklist (Universal) | **Yes** — all 6 items checked with notes | **Yes** |
| Cross-region impact declaration | **Yes** — US_FED, EU_ECB, APAC_MAS all declared | **Yes** |
| Deployment Notes | **Yes** — new env vars listed with defaults | **Yes** |

### Merge Strategy (`.clinerules` §3.5, `docs/GIT_WORKFLOW_STANDARDS.md` §4.5)

| Check | Plan Coverage | Compliant? |
|-------|--------------|-----------|
| Squash merge specified | **Yes** — §12.5 explicitly states "Squash merge into `main`" | **Yes** |
| PR title becomes squash commit | **Yes** — §12.5 notes this | **Yes** |
| PR title follows Conventional Commits | **Partial** — PR title is 79 chars (exceeds 72-char limit) | **FAIL — must be shortened** |

---

## Recommended Pre-Release Checklist

Ordered sequence of actions required before `git tag -a v2.0.0` can be executed. Steps are grouped by the dependency chain from `docs/V2_RELEASE_PLAN.md`.

### Track A — Token Quota Proxy PR (Independent of P0 Blockers)

- [ ] **A1.** Shorten Phase 2c commit message to ≤72 chars: `feat(governance): add quota rego rules to system-authz`
- [ ] **A2.** Shorten squash PR title to ≤72 chars: `feat(governance): add token quota proxy with UCA logging`
- [ ] **A3.** Implement `src/gateway/governance/pii_sanitizer.py` with Apache 2.0 header (`.clinerules` §10.2)
- [ ] **A4.** Implement `src/gateway/governance/token_quota_proxy.py` with Apache 2.0 header
- [ ] **A5.** Implement `src/gateway/governance/uca_logger.py` with Apache 2.0 header
- [ ] **A6.** Create `config/thresholds/token_quota.yaml`
- [ ] **A7.** Modify `src/gateway/server/inference_proxy.py` — insert quota check as step 2
- [ ] **A8.** Modify `src/gateway/server/hybrid_server.py` — add pre-warming in `_gateway_lifespan()`
- [ ] **A9.** Append Rego rules to `deployment/system_authz.rego`
- [ ] **A10.** Add `GovernanceControl.TOKEN_QUOTA_ENFORCEMENT = "CTRL_TQP_007"` to `src/gateway/governance/constants.py`
- [ ] **A11.** Add `CTRL_TQP_007` to `config/compliance/US_FED_BASELINE.json`, `EU_ECB_BASELINE.json`, `APAC_MAS_BASELINE.json`
- [ ] **A12.** Write `tests/test_pii_sanitizer.py`, `tests/test_token_quota_proxy.py`, `tests/test_uca_logger.py`
- [ ] **A13.** Verify `config/stpa_control_structure.yaml` is NOT modified (preserves `stpa-freshness-check` CI pass)
- [ ] **A14.** Run `uv run pytest tests/ -m local -v` locally → 0 failures
- [ ] **A15.** Update `CHANGELOG.md` with `[CR-2026-TQP-001]` entry (Cat-N requirement)
- [ ] **A16.** Open PR `feat/TQP-001-token-quota-proxy` → `main`; complete all `.github/pull_request_template.md` sections
- [ ] **A17.** Confirm CI passes: `license-check`, `pytest-logic`, `stpa-freshness-check`, `langfuse-posture-check` all green
- [ ] **A18.** Obtain maintainer review approval; squash merge
- [ ] **A19.** Delete `feat/TQP-001-token-quota-proxy` branch from remote

### Track B — P0/P1 Blocker Remediation (from `docs/V2_RELEASE_PLAN.md`)

- [ ] **B1.** Branch `fix/v2-p0-blockers` from `rc-v2.0.0`; apply D-01, D-02, D-04, D-06, D-07 working tree fixes
- [ ] **B2.** PR `fix/v2-p0-blockers` → `rc-v2.0.0`; CI green; squash merge
- [ ] **B3.** Rotate all exposed credentials (Redis, PostgreSQL, Langfuse, GCS HMAC, HuggingFace) — Phase 2
- [ ] **B4.** Suspend branch protection; run `git filter-repo --replace-text`; force-push; re-enable protection — Phase 3
- [ ] **B5.** Verify `git log --all -S "CYBERNETIC_GOVERNANCE_2025" --oneline` → zero output
- [ ] **B6.** `terraform plan` → review → `terraform apply` (D-04 + D-07 Terraform track) — Phase 4a
- [ ] **B7.** Cloud Build trigger for `governed-financial-advisor` pod restart — Phase 4b
- [ ] **B8.** `kubectl apply -f deployment/k8s/pod-security-admission.yaml` (D-07 Track 2) — Phase 4c
- [ ] **B9.** `kubectl apply -f deployment/k8s/security-scan-cronjob.yaml` (D-06) — Phase 4d
- [ ] **B10.** Verify `governed-financial-advisor` READY 1/1, AVAILABLE 1
- [ ] **B11.** Verify `CAGE_ROUTING_SEAL_SECRET` and `GOVERNANCE_SALT` in `advisor-secrets` (≥64 chars each)
- [ ] **B12.** Verify PSA labels on `governance-stack` (restricted), `langfuse` (baseline), `vllm` (baseline)
- [ ] **B13.** Verify `security-scanner-cronjob` exists in `governance-stack`

### Track C — Seal Enforcement Verification (depends on B6–B11)

- [ ] **C1.** Confirm `CAGE_SEAL_ENFORCEMENT` is `enforce` (not `log`) in gateway pod env
- [ ] **C2.** Send unsigned request to gateway → confirm 403
- [ ] **C3.** Generate valid seal token; send signed request → confirm 200
- [ ] **C4.** Run `python3 scripts/verify_remote.py` → all checks pass
- [ ] **C5.** Run `python3 scripts/verify_langfuse_posture.py` → Langfuse connectivity confirmed

### Track D — Compliance Validation (depends on A19 + B13)

- [ ] **D1.** Run `lula validate -f compliance/lula/lula-validation-a52.yaml` → PASS
- [ ] **D2.** Run `lula validate -f compliance/lula/lula-validation-a53.yaml` → PASS
- [ ] **D3.** Run `lula validate -f compliance/lula/lula-validation-a92.yaml` → PASS
- [ ] **D4.** Run `lula validate -f compliance/lula/lula-validation-aarm-vectors.yaml` → PASS
- [ ] **D5.** Run `python scripts/generate_sbom.py` → SBOM generated; no new CRITICAL CVEs
- [ ] **D6.** Trigger manual Trivy scan via `kubectl create job --from=cronjob/security-scanner-cronjob` → no CRITICAL unmitigated
- [ ] **D7.** Run `python scripts/check_stpa_freshness.py --verbose` → PASS
- [ ] **D8.** Run full test suite: `uv run pytest tests/ --run-integration -v --timeout=120` → 0 failures
- [ ] **D9.** Confirm `terraform.auto.tfvars` is gitignored: `git status` shows it as untracked

### Track E — Tagging and Release (depends on all prior tracks)

- [ ] **E1.** Confirm all universal gates U-01 through U-21 are green
- [ ] **E2.** `git checkout rc-v2.0.0 && git pull origin rc-v2.0.0`
- [ ] **E3.** `git tag -a v2.0.0 -m "chore(release): stable v2.0.0\n\nPromotion from v2.0.0-rc.2 after closure of D-01, D-02, D-04, D-06, D-07.\nAll P0 blockers resolved. HMAC seal enforcement active.\nFull test suite: 0 failed."` (annotated tag, `chore(release)` format per `.clinerules` §4.4)
- [ ] **E4.** `git push origin v2.0.0`
- [ ] **E5.** `gh release create v2.0.0 --title "v2.0.0 — Stable Release" --notes-file CHANGELOG.md --target rc-v2.0.0 --verify-tag`
- [ ] **E6.** Mark GitHub Release as **Latest release**
- [ ] **E7.** Delete `fix/v2-p0-blockers` branch from remote (if not already deleted)

---

## Release Decision

**Recommendation: CONDITIONALLY READY — Token Quota Proxy PR may merge; v2.0.0 tag is NOT yet ready**

### Rationale

The Token Quota Proxy implementation plan (`plans/token-quota-proxy-impl-plan.md`) is a high-quality, compliance-aware plan that:

- **Correctly addresses** ISO 42001 Annex A.4 (token quota enforcement), Clause 6.1 (UCA logging), Annex A.6 (PII sanitization), and Annex A.2 (OPA `tool_approved` rule)
- **Correctly declares** cross-region impact for US_FED, EU_ECB, and APAC_MAS per `.clinerules` §3.7 and §12.1
- **Correctly specifies** Apache 2.0 license headers for all three new source files per `.clinerules` §10.2
- **Correctly formats** branch name (`feat/TQP-001-token-quota-proxy`) and 12 of 14 commit messages per `.clinerules` §1–2
- **Correctly includes** CHANGELOG.md update, STPA freshness guidance, Lula re-run requirement, and rollback procedures
- **Correctly gates** WORM bucket paths on `CAGE_DEPLOYMENT_REGION` per `.clinerules` §12.2

**Two minor commit message violations** must be corrected before the PR is opened (Phase 2c and squash PR title exceed 72 chars).

**The v2.0.0 stable tag cannot be applied** until the five pre-existing P0/P1 blockers (D-01, D-02, D-04, D-06, D-07) documented in `docs/V2_RELEASE_PLAN.md` are resolved. These blockers are independent of the Token Quota Proxy PR and must be addressed via the `fix/v2-p0-blockers` branch described in `docs/V2_RELEASE_PLAN.md` Phase 1–5.

### Summary of Blocking Items

| Priority | ID | Description | Addressed by TQP Plan? |
|----------|----|-------------|----------------------|
| P0 | D-01 | Committed secrets in working tree + git history | No |
| P0 | D-02 | `governed-financial-advisor` MinimumReplicasUnavailable | No |
| P0 | D-04 | HMAC seal enforcement disabled | No |
| P1 | D-06 | `security-scanner-cronjob` missing | No |
| P1 | D-07 | PSA labels not applied | No |
| — | U-01–04 | Lula re-validation post-merge (deferred) | Partial |
| — | U-05 | SBOM regeneration for new components | No |
| — | Commit | Phase 2c commit message 74 chars (limit: 72) | Must fix |
| — | PR title | Squash PR title 79 chars (limit: 72) | Must fix |

### Conditions for v2.0.0 Stable Tag

The v2.0.0 stable tag may be applied when:

1. All items in Track B (P0/P1 blocker remediation) are complete
2. All items in Track C (seal enforcement verification) are complete
3. All items in Track D (compliance validation) are complete — specifically all four universal Lula assertions pass, SBOM is generated, Trivy scan passes, and full test suite shows 0 failures
4. The Token Quota Proxy PR (Track A) has been merged to `main` and its CI gates are green
5. `git log --all -S "<any-credential>"` returns zero matches across all history

*This gap analysis was generated on 2026-06-08 against `plans/token-quota-proxy-impl-plan.md` v1.1.0 and `docs/V2_RELEASE_PLAN.md` v1.0. It should be re-evaluated if either document is materially revised.*

## Non-Critical Gaps (Post-Release or Region-Specific)

The following gaps are acceptable to defer past the v2.0.0 stable tag. They are either region-specific (not universal blockers) or explicitly deferred by the implementation plan.

1. **[U-09 / STPA] UCA-4 not added to `stpa_control_structure.yaml`**
   - The plan §13.4 explicitly recommends NOT adding UCA-4 to the STPA model in this PR. The `stpa-freshness-check` CI job will pass as long as `config/stpa_control_structure.yaml` is not modified.
   - Deferral condition: If `stpa_control_structure.yaml` is NOT touched by the PR, the CI job passes. A follow-on PR can add UCA-4 to the STPA model if the compliance team requires it.
   - Risk: LOW — the Token Quota Proxy handles UCA-4 directly; the STPA model is supplementary evidence

2. **[F-01 / F-02] NIST SP 800-53 Lula assertions and ≥45% coverage (US_FED only)**
   - Currently 24% coverage at `v2.0.0-dev.1`. Gate requires ≥45% for US_FED stable release.
   - Deferral: Acceptable for global stable release; blocks US_FED-specific deployment only
   - Action: Document additional implemented controls in OSCAL SSP; activate stub Lula manifests per `compliance/lula/README.md`

3. **[F-03] ATO process initiation (US_FED only)**
   - AO role is currently TBD per `docs/V2_RELEASE_PLAN.md` §8.7
   - Deferral: Acceptable for global stable release; blocks US_FED-specific deployment only

4. **[E-01 / E-03 / E-04] EU AI Act posture, DORA logging, SR 26-2 sentinel (EU_ECB only)**
   - These are EU_ECB-specific gates; not universal blockers
   - Deferral: Acceptable for global stable release; verify before EU_ECB deployment

5. **[A-01 / A-03 / A-04] MAS FEAT posture, MAS Notice 655 logging, SR 26-2 sentinel (APAC_MAS only)**
   - These are APAC_MAS-specific gates; not universal blockers
   - Deferral: Acceptable for global stable release; verify before APAC_MAS deployment

6. **OSCAL component update for CTRL_TQP_007**
   - Per `docs/CHANGE_MANAGEMENT_PROCESS.md` §9.3, OSCAL updates for control implementation changes must be committed within 2 business days of PR merge (not required in the same PR)
   - The plan adds `CTRL_TQP_007` to all three regional baseline JSON files but does not update `compliance/oscal/` component definitions
   - Deferral: Acceptable as a follow-on PR within 2 business days of merge

7. **OPA runtime integration for quota Rego rules**
   - The plan §3.6 notes that the new Rego rules (`quota_within_limits`, `token_quota_within_limits`, `tool_approved`) are dead code unless `governance_middleware.py` injects Redis session state into the OPA input document
   - The plan explicitly allows deferring this to a follow-on PR with the posture: "Python DGE enforcer — OPA rules are secondary evidence layer"
   - Deferral: Acceptable; Python `TokenQuotaProxy` is the primary enforcer; OPA rules provide secondary declarative evidence

---
