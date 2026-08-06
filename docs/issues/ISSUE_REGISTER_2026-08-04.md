# CAGE Issue Register — 2026-08-04

**System:** Cybernetic AI Governance Engine (CAGE)
**Commit SHA:** `6edb597`
**Register Date:** 2026-08-04
**Compiled From:** Phase 1 (Local Test Suite), Phase 2 (GKE Deployment), Phase 3 (GKE Live Tests)
**Reference Architecture Note:** Per [`AGENTS.md`](../../AGENTS.md), CAGE is a reference architecture demonstrating governance patterns for AI systems. It is not deployed to production. Severity ratings below reflect impact *as if* this were a production system, consistent with the illustrative compliance patterns documented in [`plans/SECURITY_REMEDIATION_PLAN.md`](../../plans/SECURITY_REMEDIATION_PLAN.md) and [`docs/POAM.md`](../POAM.md).

---

## Overall Test Run Verdict

| Phase | Environment | Verdict | Headline Result |
|---|---|---|---|
| 1 | Local (`.venv`) | ❌ FAIL (exit 1) | 85 failed, 1352 passed, 157 skipped, 28 collection errors in 41.6s |
| 2 | GKE Deployment | ✅ PASS (exit 0) | All 6 Cloud Build jobs SUCCESS |
| 3 | GKE Live Tests | ⚠️ MIXED | Integration suite self-skipped (127 collected/0 run); load test shows 100% failure on `/governance/validate-action` |

**Overall system verdict:** ❌ **NOT RELEASE-READY** — local test suite cannot fully execute due to missing optional dependencies in `.venv`, and the deployed GKE image (`6edb597`) has a fully broken `/governance/validate-action` endpoint (100% failure rate under load) plus a degraded-mode KMS signer in `compliance-bridge`.

---

## Severity Definitions

| Severity | Definition |
|---|---|
| **CRITICAL** | Security regression or service outage; violates a NIST SP 800-53 / AGENTS.md compliance obligation; blocks production traffic or falsifies governance guarantees |
| **HIGH** | Test suite cannot run (collection error / setup error blocking many tests) or a GKE endpoint is broken/non-functional |
| **MEDIUM** | Degraded capability, missing configuration, or a functional regression with a workaround |
| **LOW / WARNING** | Cosmetic, advisory, or purely informational; no functional or security impact |

---

## Issue Table — Local Test Findings (Phase 1)

| ID | Severity | Category | Affected Artefact(s) | Observed Symptom | Root Cause | Environment |
|---|---|---|---|---|---|---|
| L-1 | HIGH | Test Infra / Dependency | [`tests/test_cage_graph.py`](../../tests/test_cage_graph.py), [`tests/test_optimistic_graph.py`](../../tests/test_optimistic_graph.py), [`tests/test_cybernetic_loop.py`](../../tests/test_cybernetic_loop.py) (18 setup errors), `make test-cybernetic-loop` | 18+ setup errors; entire test files fail to collect/run | `langgraph` not installed in `.venv` — declared only under the `advisor` optional-dependency group in [`pyproject.toml`](../../pyproject.toml:91) but the base/dev environment install does not include `--extra advisor` | local |
| L-2 | HIGH | Test Infra / Dependency | [`tests/test_governance_pipeline_latency.py`](../../tests/test_governance_pipeline_latency.py), [`tests/test_harness_nemo_factory.py`](../../tests/test_harness_nemo_factory.py), [`tests/test_harness_opa_factory.py`](../../tests/test_harness_opa_factory.py), [`tests/test_safety_node.py`](../../tests/test_safety_node.py), [`tests/test_ftra_package.py`](../../tests/test_ftra_package.py) (13), [`tests/test_guardrail_node.py`](../../tests/test_guardrail_node.py) (7), [`tests/test_hitl_rationale.py`](../../tests/test_hitl_rationale.py) (11), [`tests/test_hitl_toctou_revalidation.py`](../../tests/test_hitl_toctou_revalidation.py) (20), [`tests/test_security_medium_severity.py`](../../tests/test_security_medium_severity.py) (13), [`tests/test_output_rail_node.py`](../../tests/test_output_rail_node.py) (9), [`tests/test_agent_state_schema.py`](../../tests/test_agent_state_schema.py) (2) | 85+ test failures/errors across 11 files | `langchain_core` not installed in `.venv` — declared under the `advisor` extra ([`pyproject.toml`](../../pyproject.toml:96)) but not installed in the default dev environment | local |
| L-3 | HIGH | Test Infra / Dependency | [`tests/test_evaluator_mcp.py`](../../tests/test_evaluator_mcp.py), [`tests/test_gateway_connectivity.py`](../../tests/test_gateway_connectivity.py) | Collection errors | `mcp` not installed in `.venv` — declared under the `gateway` extra ([`pyproject.toml`](../../pyproject.toml:65)) but not installed in the default dev environment | local |
| L-4 | HIGH | Test Infra / Dependency | [`tests/test_langfuse_evaluation.py`](../../tests/test_langfuse_evaluation.py) | Collection error | `langchain_openai` not installed in `.venv` — declared under the `advisor` extra ([`pyproject.toml`](../../pyproject.toml:97)) but not installed in the default dev environment | local |
| L-5 | CRITICAL | Governance API / Export Regression | [`tests/test_symbolic_governor.py`](../../tests/test_symbolic_governor.py) (collection error — all tests in file blocked) | `from src.gateway.governance import GovernanceError, SymbolicGovernor` raises ImportError, blocking the entire test file that validates the core governance error contract | [`src/gateway/governance/__init__.py`](../../src/gateway/governance/__init__.py:15-19) wraps the `symbolic_governor` import together with the `langgraph_harness` import inside a single `try/except ImportError: pass` block. Because `langgraph_harness` transitively imports `langgraph` (L-1), the `ImportError` from the missing `langgraph` package aborts the *entire* try block before `GovernanceError`/`SymbolicGovernor` are bound — silently dropping the core governance API export even though `symbolic_governor.py` itself has no `langgraph` dependency | local |
| L-6 | MEDIUM | Test Infra / Mock Patch Target | [`tests/test_symbolic_governor_security.py::test_fiscal_limit_guard_reserve_called_with_correct_args`](../../tests/test_symbolic_governor_security.py:438) | `patch("src.gateway.governance.causal_gatekeeper.causal_safety_check", ...)` fails because `causal_gatekeeper` is not a resolvable attribute on the `src.gateway.governance` package at patch time | [`src/gateway/governance/__init__.py`](../../src/gateway/governance/__init__.py:21-24) only imports `causal_safety_check` and `generate_mock_telemetry` *names* from `causal_gatekeeper` into the package namespace — it never imports the `causal_gatekeeper` submodule itself as an attribute, so `unittest.mock.patch` cannot resolve the dotted path `src.gateway.governance.causal_gatekeeper.causal_safety_check` unless the submodule has already been imported elsewhere in the same process (order-dependent test flakiness) | local |
| L-7 | CRITICAL | Security Regression (Authentication) | [`tests/test_oidc_middleware.py`](../../tests/test_oidc_middleware.py) — `test_malformed_jwt_raises_401`, `test_jwks_fetch_failure_raises_401`, `test_no_matching_key_raises_401` | 3 tests fail — OIDC middleware does not raise `HTTPException(401)` on malformed JWT / JWKS fetch failure / no matching key | Investigation of [`src/gateway/server/governance_middleware.py`](../../src/gateway/server/governance_middleware.py:843-973) shows `validate_oidc_token()` **does** contain `raise HTTPException(status_code=401, ...)` on all three failure paths (lines 891-895, 905-909, 913-918) — the test failures indicate either (a) a signature/behavior drift between the test's expectations and the current exception-raising code path (e.g. an intervening `try/except` swallowing the `HTTPException` before it propagates), or (b) the tests are exercising a stale code path. This must be re-verified against the exact failure traceback before remediation — flagged as a **priority investigation item**, not a confirmed regression location | local |
| L-8 | HIGH | Verification Script / Dataclass Contract Drift | `scripts/verify_all.py` red-team step → [`tests/red_team/adversarial_red_team.py:129`](../../tests/red_team/adversarial_red_team.py:129) | Red-team dry-run step in `verify_all.py` crashes with `TypeError` | `AttackPayload` dataclass in [`tests/red_team/adversarial_red_team.py`](../../tests/red_team/adversarial_red_team.py:84-94) does not declare an `expected_verdict` field, but [`tests/red_team/adversarial_dataset.json`](../../tests/red_team/adversarial_dataset.json:298) payload entries include an `"expected_verdict": "BLOCKED"` key; `AttackPayload(**p)` at line 129 raises `TypeError: __init__() got an unexpected keyword argument 'expected_verdict'` — dataset schema has drifted ahead of the dataclass definition | local |
| L-9 | HIGH | Broken Import / Module Rename | `scripts/verify_colang_locally.py` (exits 1) | Script fails immediately on import | [`scripts/verify_colang_locally.py:21`](../../scripts/verify_colang_locally.py:21) imports `from src.utils.nemo_manager import load_rails`, but the `src/utils/` package/module no longer exists in the repository (confirmed via directory listing — `src/utils` does not exist) — the module was deleted or renamed without updating this script | local |
| L-10 | HIGH | Verification Script / Missing Tooling & Fixtures | `scripts/verify_all.py` (exits 1) | Script fails at the OPA and red-team steps | Two independent causes: (1) `opa test tests/opa/ -v` fails because the `tests/opa/` directory does not exist in the repository (confirmed absent); (2) the `nemoguardrails` CLI is absent from `PATH` in the local dev environment (declared under the `gateway` extra in [`pyproject.toml`](../../pyproject.toml:66) but not installed) — both are treated as fatal by `verify_all.py`'s `success = False` accumulation logic in [`scripts/verify_all.py`](../../scripts/verify_all.py:37-125) | local |
| L-11 | LOW | Performance Degradation (Non-fatal) | `src/gateway/governance/text_filter.py` (Tier-1 keyword scanner) | Startup warning logged; Tier-1 keyword scan falls back to O(n×m) brute-force scanning instead of O(n) Aho-Corasick automaton matching | `pyahocorasick` is declared as an optional performance dependency under the `gateway` extra ([`pyproject.toml`](../../pyproject.toml:67-72)) but absent from `.venv`; the code has a documented, functionally-correct fallback path, so this is non-fatal but degrades throughput under high-volume inference traffic | local |

### Verification Script Summary (Phase 1)

| Script | Exit | Linked Issue(s) |
|---|---|---|
| `scripts/verify_all.py` | 1 | L-8, L-10, L-3 (collection error surfaces via `pytest --maxfail=1` inside verify_all's unit-test step) |
| `scripts/check_stpa_freshness.py` | 0 | None |
| `scripts/verify_langfuse_posture.py` | 1 | K-2 (see below) |
| `scripts/check_policy_drift.py` | 0 | None |
| `scripts/check_lula_stub_count.py` | 0 | None |
| `scripts/verify_colang_locally.py` | 1 | L-9 |

---

## Issue Table — GKE Deployment Findings (Phase 2)

**Verdict: ✅ DEPLOYMENT SUCCEEDED** — all 6 Cloud Build jobs SUCCESS, exit code 0. The following are non-blocking observations recorded for review.

| ID | Severity | Category | Affected Artefact(s) | Observed Symptom | Root Cause | Environment |
|---|---|---|---|---|---|---|
| G-1 | LOW / WARNING | Terraform Configuration Drift | [`infra/targets/gcp-gke/dev.tfvars:56`](../../infra/targets/gcp-gke/dev.tfvars:56), [`infra/targets/gcp-gke/variables.tf`](../../infra/targets/gcp-gke/variables.tf) | Terraform apply logs a warning; the value of `gpu_node_pool_name` has no effect | `gpu_node_pool_name` is declared as a key in all five `*.tfvars` files (`dev.tfvars`, `eu-dev.tfvars`, `eu-prod.tfvars`, `apac-dev.tfvars`, `apac-prod.tfvars`) and is documented as "used as `cloud.google.com/gke-nodepool` nodeSelector", but `infra/targets/gcp-gke/variables.tf` does not declare a matching `variable "gpu_node_pool_name" {}` block at the target/root module level — the value passed via `.tfvars` is silently ignored by Terraform since it is only consumed as an *output* of `infra/modules/gcp_gke_cluster/outputs.tf:47`, not wired through as an input variable to any consumer | GKE |
| G-2 | MEDIUM | Architecture / Reliability Regression | [`infra/modules/governed_advisor/main.tf`](../../infra/modules/governed_advisor/main.tf) | Applied cleanly, but represents an unreviewed reliability regression | The `governed-financial-advisor` Terraform module was refactored: (1) the container name changed from `governed-financial-advisor` to `ingress-agent` (line 58); (2) the CPU limit was reduced from `2` to `500m` (line 334, `resources.limits.cpu`); (3) `liveness_probe`/`readiness_probe` blocks were removed entirely from the container spec (confirmed absent in the full 367-line file) — Kubernetes can no longer detect and restart a hung/unhealthy advisor pod, and the CPU ceiling was cut by 75% with no corresponding load-test validation | GKE |
| G-3 | LOW / WARNING | Cost Impact | GKE node pool `gpu-node-pool-nvidia-l4` | 3 new GPU nodes provisioned during deployment | Expected behavior per `dev.tfvars` GPU node pool configuration (`gpu_node_pool_initial_count`), flagged here purely for cost-tracking visibility, not a defect | GKE |

---

## Issue Table — GKE Live Test Findings (Phase 3)

### Integration Test Run

`pytest` integration run: **127 collected, 0 passed, 131 skipped** — all integration tests self-skip because they require `CAGE_GATEWAY_URL` env var or `--run-integration` flag to be set; this is by design (see `pytest.ini` / `pyproject.toml` `integration` marker), but it means **zero live-endpoint coverage was actually exercised** during this test phase via pytest — all live-endpoint findings below come from the Locust load test and direct pod log inspection instead.

### Load Test Results (5 users, 20s, via port-forward)

| Endpoint | Requests | Failures | Failure Rate | p95 | Linked Issue |
|---|---|---|---|---|---|
| `GET /health` | 6 | 0 | 0% ✅ | 220ms | — |
| `POST /governance/check` | 17 | 1 | 5.9% ⚠️ | 1000ms | K-6 (partial correlation) |
| `POST /governance/validate-action` | 7 | 7 | **100%** ❌ | 240ms | K-6 |

### Make Target Results

| Target | Exit | Result | Linked Issue |
|---|---|---|---|
| `make test-r22` | 0 | 39/39 PASSED | — |
| `make test-cybernetic-loop` | 2 | 18 setup errors | L-1 |
| `make test-integration` | 2 | 10 collection errors | L-1, L-2, L-3, L-4 |

### Remote/Posture Script Results

| Script | Exit | Issue |
|---|---|---|
| `verify_remote.py` | 1 | K-1, K-2 |
| `verify_langfuse_posture.py` | 1 | K-2 |
| `check_apac_mas_posture.py` | 0 | W-1 |
| `check_eu_ecb_posture.py` | 0 | W-2 |

### Issue Table — Pod / Endpoint Findings

| ID | Severity | Category | Affected Artefact(s) | Observed Symptom | Root Cause | Environment |
|---|---|---|---|---|---|---|
| K-1 | HIGH | Missing Deployment Secret | `scripts/verify_remote.py` (U-15/U-16 seal enforcement checks) | Seal enforcement checks (U-15/U-16) are skipped with a warning instead of running | `CAGE_ROUTING_SEAL_SECRET` is absent from the environment used to run `verify_remote.py` against the live GKE deployment — [`scripts/verify_remote.py:242-246`](../../scripts/verify_remote.py:242) explicitly warns and skips rather than failing hard, meaning the routing-seal enforcement contract (GHSA-v3h4-8458-5ww3 mitigation) is **unverified** against the live `6edb597` deployment | GKE |
| K-2 | MEDIUM | Missing Observability Configuration | `scripts/verify_remote.py`, `scripts/verify_langfuse_posture.py` | Both scripts exit 1; 8 required Langfuse env vars reported missing | Langfuse credential/env vars (per [`scripts/verify_langfuse_posture.py:46-50`](../../scripts/verify_langfuse_posture.py:46) `BASE_REQUIRED_VARS` — `GOOGLE_CLOUD_PROJECT`, `GOOGLE_CLOUD_LOCATION`, `LANGFUSE_HOST`, `LANGFUSE_PUBLIC_KEY`, and others) are absent from the local shell environment used to run the posture check against the remote deployment — this is a local verification-environment gap, not necessarily a defect in the deployed pods themselves, but it means Langfuse posture was **not verified** in this test phase | GKE (verification environment) |
| K-3 | CRITICAL | Security Control Degradation (CTRL_KMS_001) | `compliance-bridge` pod — [`src/compliance_bridge/kms_batch_signer.py`](../../src/compliance_bridge/kms_batch_signer.py:360) | Pod log ERROR: `[KMSBatchSigner] Failed to load signer at startup: KMS_GOVERNANCE_KEY is not set` — pod starts in degraded mode without KMS signing | `KMS_GOVERNANCE_KEY` environment variable is not set/wired for the `compliance-bridge` deployment in the live GKE environment; per [`docs/POAM.md`](../POAM.md) and CTRL_KMS_001 (evidentiary-independence control), the HMAC fallback path was intentionally removed, so compliance evidence records signed by this pod are **not KMS-signed** and lack non-repudiation — this directly touches the OSCAL/NIST compliance obligations documented in [`AGENTS.md`](../../AGENTS.md) (shared-module compliance artefact obligations) | GKE |
| K-4 | MEDIUM | Observability Gap | `gateway`, `governed-financial-advisor` pods | Pod log WARNING: OTLP trace export fails with 401 Unauthorized | Langfuse OTLP ingestion credentials (`OTEL_EXPORTER_OTLP_HEADERS`, see [`infra/modules/governed_advisor/main.tf:201`](../../infra/modules/governed_advisor/main.tf:201)) are absent or incorrect in the pod environment — traces are not delivered to Langfuse, degrading AU-12 (Audit Record Generation) observability coverage for the live deployment, though local audit logging is unaffected | GKE |
| K-5 | LOW / WARNING | Missing Route (Non-blocking) | `gateway` pod | Pod log INFO: `GET /v1/models → 404` | Route not registered on the gateway; no test currently depends on this route (confirmed via search — no `/v1/models` route exists anywhere in `src/gateway/server/`), so this is purely informational and non-blocking for the current test suite | GKE |
| K-6 | CRITICAL | Service Outage / Broken Endpoint | `gateway` pod — `POST /governance/validate-action` ([`src/gateway/server/governance_middleware.py:611`](../../src/gateway/server/governance_middleware.py:611)) | Pod log ERROR; load test shows **100% failure (7/7 requests)** on `POST /governance/validate-action` in the deployed image `6edb597` | The endpoint code exists and is mounted (`governance_app.post("/validate-action")`, mounted at `/governance` in [`src/gateway/server/hybrid_server.py:345`](../../src/gateway/server/hybrid_server.py:345)), so the 100% failure is most likely caused by one of: (a) `enforce_routing_seal()` rejecting every request because `CAGE_ROUTING_SEAL_SECRET` is misconfigured/mismatched between caller and gateway pod (correlates with K-1); (b) the newly-added rate limiter or trusted-proxy IP check ([`governance_middleware.py:657-677`](../../src/gateway/server/governance_middleware.py:657)) rejecting all load-test traffic because the load-test client IP is not in `_TRUSTED_PROXY_CIDRS`, causing spoofed/incorrect `client_ip` resolution and false-positive rate-limit trips; or (c) an internal `GovernanceError`/exception in the 7-tier pipeline. **Requires targeted reproduction against the live pod with request/response logging before a definitive root cause can be assigned** — flagged as the single highest-priority live-endpoint defect in this register | GKE |

### Regional Posture Warnings

| ID | Severity | Category | Affected Artefact(s) | Observed Symptom | Root Cause | Environment |
|---|---|---|---|---|---|---|
| W-1 | LOW / WARNING | Compliance Documentation Sentinel | `scripts/check_apac_mas_posture.py`, APAC threshold files under `config/thresholds/` | Script exits 0 but prints `WARNING: SR 26-2 sentinel not found` | [`scripts/check_apac_mas_posture.py:105-123`](../../scripts/check_apac_mas_posture.py:105) checks that APAC threshold YAML/JSON files contain either the phrase `"no legal force"` or the literal string `"SR 26-2"` to document that the US-specific SR 26-2 citation has no legal force in the APAC_MAS jurisdiction; the sentinel text is present in `config/thresholds/US_FED_BASELINE.json` (the source citation) but not confirmed present in the corresponding APAC threshold file(s) — advisory only, does not block deployment | GKE (posture check) |
| W-2 | LOW / WARNING | Compliance Documentation Sentinel | `scripts/check_eu_ecb_posture.py`, EU threshold files under `config/thresholds/` | Script exits 0 but prints `WARNING: SR 26-2 sentinel not found` | Same root cause pattern as W-1, applied to `scripts/check_eu_ecb_posture.py:103-118` and EU_ECB threshold files — advisory only | GKE (posture check) |

---

## Cross-Phase Correlation Notes

- **L-1 → L-5 chain:** The missing `langgraph` dependency (L-1) is not merely a test-infrastructure gap — it silently disables the export of `GovernanceError`/`SymbolicGovernor` from the `src.gateway.governance` package (L-5) due to the shared `try/except ImportError` block in [`src/gateway/governance/__init__.py`](../../src/gateway/governance/__init__.py:15-19). This means **any consumer of the package-level import in an environment missing `langgraph`** (not just `test_symbolic_governor.py`) silently loses access to the core governance exception type. This is a CRITICAL-severity code-structure defect, independent of whether `langgraph` is installed in production.
- **K-1 → K-6 correlation:** The unverified routing-seal secret (K-1) and the 100% failure rate on `/governance/validate-action` (K-6) are very likely the same underlying misconfiguration — `enforce_routing_seal()` runs as the very first line of the endpoint handler ([`governance_middleware.py:654`](../../src/gateway/server/governance_middleware.py:654)) and will reject any request lacking a valid seal signed with the secret the gateway pod expects.
- **G-2 → K-6 correlation:** The removal of liveness/readiness probes on the `governed-financial-advisor` container (G-2) means Kubernetes has no way to detect if the advisor's calls to `/governance/validate-action` are failing due to an unhealthy advisor pod state; combined with K-6, this reduces overall system observability into the failure.

---

## Issue Count Summary

| Severity | Count | IDs |
|---|---|---|
| CRITICAL | 4 | L-5, L-7, K-3, K-6 |
| HIGH | 8 | L-1, L-2, L-3, L-4, L-8, L-9, L-10, K-1 |
| MEDIUM | 5 | L-6, G-2, K-2, K-4 |
| LOW / WARNING | 6 | L-11, G-1, G-3, K-5, W-1, W-2 |
| **TOTAL** | **23** | |

*Note: L-7's severity may be downgraded pending the priority investigation noted in its row — it is provisionally rated CRITICAL because a confirmed regression in OIDC 401-raising behavior would constitute an authentication bypass.*
