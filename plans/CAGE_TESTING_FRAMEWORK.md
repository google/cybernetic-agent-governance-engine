# CAGE Testing and Validation Framework

| Field | Value |
|---|---|
| Status | DRAFT — planning document, no code changes |
| Scope | Testing/validation requirements for the remediation backlog in [`plans/CAGE_IMPLEMENTATION_SPECS.md`](CAGE_IMPLEMENTATION_SPECS.md) and the risks in [`plans/CAGE_RISK_MATRIX.md`](CAGE_RISK_MATRIX.md) |
| Audience | Engineers implementing and validating the remediation backlog; QA/test owners; compliance reviewers |
| Identifier note | The task framing referenced "POAM-023" for reconciliation-worker activation. `POAM-023` in [`docs/POAM_US_FED.md`](../docs/POAM_US_FED.md) / [`docs/compliance/cross-region/POAM.md`](../docs/compliance/cross-region/POAM.md) is actually the closed CBF-external-reconciliation item (`AnchorageGrpcLedgerProvider`/`ExternalLedgerReconciler`, closed 2026-07-27) and a *separate, still-open* `libpython3.11` CVE finding (SI-2). The item this framework tests — the **reconciliation-worker secret population gap** (`gcs-reconciliation-bucket` never set, `CreateContainerConfigError`) — is tracked in [`docs/POAM.md:76`](../docs/POAM.md:76) as **POAM-2026-038** (reopened 2026-08-09). This document uses **POAM-2026-038** throughout §8 and §5.3 and flags the correction here so the two identifiers are not conflated. |

## Table of Contents

1. [Testing Strategy Overview](#1-testing-strategy-overview)
2. [Test Categories and Requirements](#2-test-categories-and-requirements)
3. [Performance and SLA Testing](#3-performance-and-sla-testing)
4. [Security Testing](#4-security-testing)
5. [Compliance Validation Framework](#5-compliance-validation-framework)
6. [Test Data Management](#6-test-data-management)
7. [Continuous Integration Integration](#7-continuous-integration-integration)
8. [Acceptance Criteria Matrix](#8-acceptance-criteria-matrix)
9. [Test Environment Specifications](#9-test-environment-specifications)

---

## 1. Testing Strategy Overview

### 1.1 Testing Pyramid

CAGE's remediation backlog spans pure-function governance logic, Redis/OPA
integration, LangGraph harness orchestration, Kubernetes infrastructure
activation, and formal verification. The pyramid below maps each layer to
the existing `pytest` marker taxonomy in [`pytest.ini`](../pytest.ini) and
the CI jobs in [`.github/workflows/ci.yml`](../.github/workflows/ci.yml).

```
                      ┌─────────────────────────────┐
                      │      Acceptance / Smoke       │  integration-smoke (CI, live GKE gated)
                      │  live GKE, region-parametrized │  scripts/port_forward_dev.sh + full suite
                      └───────────────┬─────────────────┘
                      ┌───────────────▼─────────────────┐
                      │           System Tests            │  pytest -m integration
                      │  cross-component, mocked-external  │  (Redis/OPA containers, no GKE)
                      └───────────────┬─────────────────┘
                      ┌───────────────▼─────────────────┐
                      │        Integration Tests           │  pytest -m "local or unit"
                      │  module boundaries, in-process     │  (pytest-logic CI job, 3 regions)
                      └───────────────┬─────────────────┘
                      ┌───────────────▼─────────────────┐
                      │            Unit Tests               │  pytest -m unit / -m local
                      │  pure functions, single module      │  fast, no I/O, xdist-parallel
                      └─────────────────────────────────┘

           Formal Verification (parallel track, not part of the pyramid):
           proof/model.py BFS enumeration + tests/test_no_direct_bind_proof.py
           pinned-state-count regression (no-direct-bind-proof CI job)
```

**Layer definitions used throughout this document:**

| Layer | Marker(s) | Dependencies | Example |
|---|---|---|---|
| Unit | `unit`, `local` | None (in-process, mocked) | `_classify_violation()` branch coverage |
| Integration | `local` (module-boundary) or `integration` (live services) | Redis/OPA test containers or mocks | `ingest_sync()` against a `fakeredis`/mocked stream |
| System | `integration` | Live Redis + OPA + gateway process, no GKE | HTTP 202 DEFER routing through `governance_middleware.py` |
| Acceptance | `integration` (CI `integration-smoke`) or manual (`port_forward_dev.sh`) | Live GKE dev cluster | End-to-end 200ms SLA benchmark, chaos failover drill |

### 1.2 Test Environment Requirements

| Environment | Purpose | Dependencies | Invocation |
|---|---|---|---|
| Local development | Fast iteration, TDD | `uv sync --all-groups --all-extras`; no external services required for `-m unit`/`-m local` | `uv run pytest tests/ -m "local or unit"` |
| CI (mocked dependencies) | PR/push gate, 3-region matrix | Dummy env vars only (no live Redis/OPA/vLLM) — see [`ci.yml:118-131`](../.github/workflows/ci.yml:118) | `uv run pytest tests/ -m "local or unit" -n auto --dist=loadfile --cov=src --cov-fail-under=75` |
| Dev GKE cluster (live integration) | Cross-component + latency + chaos validation | `governance-cluster-2` (us-central1-a), `scripts/port_forward_dev.sh`, `.env` | `uv run pytest tests/ --run-integration -v --tb=short` (per `AGENTS.md` Test Execution) |
| Prod GKE cluster (smoke only) | Post-deploy verification | Production credentials, restricted network access | `uv run pytest tests/ -m integration --timeout=30 -x -q --ignore=tests/load --ignore=tests/red_team` (same shape as CI `integration-smoke`, pointed at prod) |

### 1.3 Coverage Targets by Component

Repository-wide coverage floor is `--cov-fail-under=80` per
[`.coveragerc:21`](../.coveragerc:21) (75% in the faster PR-gate CI leg,
[`ci.yml:132`](../.github/workflows/ci.yml:132)). This framework adds
component-specific targets for the remediation backlog, tracked as new
`--cov` scoped runs during implementation review (not a change to the
global floor):

| Component | File(s) | Target | Rationale |
|---|---|---|---|
| DEFER/NARROW/PAUSE classification | `symbolic_governor.py::_classify_violation()`, `decisions.py` | 100% branch coverage on the classification table (§2.1 of Implementation Specs) | Safety-critical decision routing; every row of the classification table needs an explicit test |
| Evidence chain blocking gate | `evidence_stream.py::ingest_sync()` | 100% branch coverage on timeout/error/success paths | Fail-closed correctness is the entire point of this gate |
| FTRA extractor abstraction | `langgraph_harness/types.py::FtraNodeConfig`, `ftra/node_factory.py::_parse_plan()` | ≥ 90% including all three `ParseResult.failure_class` branches | Directly addresses BUG-FTRA-SCHEMA-001/BUG-FTRA-JSON-001 regression risk |
| Redis fencing | `cbf.py` fencing branch, `redis_client.py` WAIT/Sentinel path | ≥ 85%, with mandatory chaos-test coverage (unit coverage alone is insufficient for failover claims) | Failure modes are the entire risk surface (R-05) |
| Reconciliation replay defense | `reconciliation_worker.py::ReconciliationResult.sequence`, `cbf.py` sequence-validation branch (§2.10 of Implementation Specs) | 100% branch coverage on advancing/non-advancing/zero-default sequence paths, with mandatory chaos-test coverage | Active-exploit security gap (R-04); unit coverage alone cannot substantiate the replay-rejection claim |
| Reconciliation worker | `reconciliation_worker.py` (existing, already tested) | Maintain existing coverage; add operational verification (not unit-test coverage) checklist | Code-complete; gap is operational (§2.7 of Implementation Specs) |
| Formal model | `proof/model.py`, `proof/distributed_cbf_model.py` (new) | 100% of `assert` statements exercised (BFS is exhaustive by construction) | Proof correctness is binary — either the invariant holds over all reachable states or it doesn't |

---

## 2. Test Categories and Requirements

Each subsection maps to a component in
[`plans/CAGE_IMPLEMENTATION_SPECS.md`](CAGE_IMPLEMENTATION_SPECS.md) §2 and
specifies concrete test cases, not just categories. File paths for new test
modules follow the existing `tests/test_<module>.py` convention.

### 2.A DEFER/NARROW/PAUSE Primitives Testing

**Target code:** `symbolic_governor.py::_classify_violation()` (new),
`validate_action()` DEFER-wiring (§2.1 of Implementation Specs),
`decisions.py` (`NARROW`/`PAUSE` enum members), `pause_primitive.py` (new).

**Existing baseline to extend:** [`tests/test_symbolic_governor.py`](../tests/test_symbolic_governor.py),
[`tests/test_symbolic_governor_confidence_bypass.py`](../tests/test_symbolic_governor_confidence_bypass.py),
[`tests/test_defer_node.py`](../tests/test_defer_node.py),
[`tests/test_defer_queue.py`](../tests/test_defer_queue.py),
[`tests/test_provenance_chain.py`](../tests/test_provenance_chain.py).

**Unit tests — `_classify_violation()` (new file: `tests/test_classify_violation.py`):**

| Test case | Input | Expected `(decision, meta)` |
|---|---|---|
| `test_manual_review_string_routes_require_approval` | `violations[0] == "Manual Review Required..."` | `(REQUIRE_APPROVAL, {})` — unchanged existing behavior |
| `test_confidence_below_fria_zone_defer_routes_defer` | `confidence=0.5`, `FRIA_ZONE_DEFER=0.70` | `(DEFER, {"defer_reason": DeferReason.CONFIDENCE_BELOW_THRESHOLD})` |
| `test_confidence_none_does_not_trigger_confidence_defer` | `confidence=None`, other violation present | Falls through to next rule, not spuriously `DEFER` |
| `test_missing_stpa_context_fields_routes_defer` | STPA/OPA snapshot missing required field | `(DEFER, {"defer_reason": DeferReason.INSUFFICIENT_CONTEXT})` |
| `test_unclassified_violation_routes_deny_unchanged` | Arbitrary violation string, no confidence/context signal | `(DENY, {})` — current behavior preserved byte-for-byte |
| `test_classification_table_exhaustive_branch_coverage` | Parametrized over every row of the §2.1 classification table | 100% branch coverage assertion (coverage gate, not a behavioral assertion) |

**Unit tests — DEFER wiring in `validate_action()` (extend `test_symbolic_governor.py`):**

| Test case | Scenario | Assertion |
|---|---|---|
| `test_validate_action_returns_defer_verdict_not_governance_error` | Confidence below `FRIA_ZONE_DEFER`, previously would raise `GovernanceError` | Returns `{"verdict": DEFER, "defer_id": ..., "missing_input_reason": ...}` — **no exception raised** |
| `test_defer_park_writes_deferqueue_token` | Same as above | `DeferQueue.park()` called once with a well-formed `DeferToken` (mock/spy) |
| `test_defer_verdict_sets_otel_span_attribute` | Same as above | `span.set_attribute("cage.verdict", "DEFER")` observed via span-recording fixture |
| `test_require_approval_path_unaffected_by_defer_wiring` | `"Manual Review Required"` violation | Existing `REQUIRE_APPROVAL` behavior identical pre/post change (regression guard) |
| `test_deny_path_unaffected_for_non_defer_violations` | Generic policy violation | `GovernanceError` still raised, HTTP 403-shaped, unchanged |

**Integration tests — HTTP 202 routing (extend [`tests/test_agent_gateway_adapter.py`](../tests/test_agent_gateway_adapter.py) and [`tests/test_governance_middleware.py`](../tests/test_governance_middleware.py)):**

| Test case | Scenario | Assertion |
|---|---|---|
| `test_ext_authz_check_returns_202_on_defer` | ext_authz `CheckRequest` triggers a DEFER-eligible condition | `CheckResponse` status maps to HTTP 202, `defer_id` present |
| `test_validate_action_endpoint_returns_202_on_defer` | REST `/v1/governance/validate-action` | HTTP 202, JSON body matches §3.2 contract (`verdict`, `defer_id`, `missing_input_reason`, `latency_ms`) |
| `test_narrow_verdict_returns_200_with_narrowed_params` | CBF amount violation, `CAGE_NARROW_ENABLED=true` | HTTP 200, `verdict: NARROW`, `narrowed_params`, `narrow_reason`, seal issued for narrowed amount only |
| `test_narrow_disabled_falls_back_to_deny` | Same CBF amount violation, `CAGE_NARROW_ENABLED=false` (default) | HTTP 403 DENY — confirms default-off backward compatibility |
| `test_pause_verdict_returns_202_with_resume_token` | Node factory raises `PAUSE` via `pause_primitive.py` | HTTP 202, `resume_token`, `resume_after` (or null) |
| `test_pause_resume_endpoint_resumes_thread` | `POST /v1/pause/{resume_token}/resume` | 200 on valid unexpired token; 404 unknown token; 410 expired token |

**System tests — end-to-end deferral flow (new file: `tests/test_defer_e2e_flow.py`, marker `integration`):**

| Test case | Scenario | Assertion |
|---|---|---|
| `test_defer_full_roundtrip_via_gateway` | Submit action via real HTTP client → gateway → DeferQueue (Redis db=1) → poll `/v1/defer/{defer_id}` | Full roundtrip resolves; token expires per TTL if never hydrated |
| `test_defer_then_hydrate_then_resume_allows` | DEFER → external hydration supplies missing context → resubmit | Second submission produces `ALLOW` with seal |
| `test_narrow_then_resubmit_clamped_amount_succeeds` | `NARROW` response → caller resubmits `narrowed_params` verbatim | `ALLOW` with seal on resubmission |
| `test_concurrent_defer_and_pause_do_not_collide_in_redis` | Simultaneous DEFER and PAUSE tokens for different threads | `DEFER:{id}` and `PAUSE:{token}` keys remain independent (db=1 namespace check) |

**Regression guard (backward compatibility, per §6.1 of Implementation Specs):**
`test_deny_rate_unchanged_for_non_defer_eligible_traffic` — replay a fixed
corpus of previously-DENY-classified payloads through the new
`_classify_violation()` path and assert the DENY rate is unchanged for any
payload that does not match a DEFER rule, guarding against the documented
"behavior change for a subset of previously-mislabeled DENY responses."

**Commands:**
```bash
uv run pytest tests/test_classify_violation.py tests/test_symbolic_governor.py \
  tests/test_defer_node.py tests/test_defer_queue.py -v
uv run pytest tests/test_agent_gateway_adapter.py tests/test_governance_middleware.py -v
uv run pytest tests/test_defer_e2e_flow.py -m integration -v
```

### 2.B Evidence Chain Blocking Gate Testing

**Target code:** `evidence_stream.py::ingest_sync()` (new),
`EVIDENCE_CHAIN_BLOCKING` call-site integration in `validate_action()`
(§2.3 of Implementation Specs).

**Existing baseline to extend:** [`tests/test_evidence_stream.py`](../tests/test_evidence_stream.py)
(`TestIngestWithNoRedis`, `TestIngestHashChain`, `TestGcsFlushLoop` classes
already present), [`tests/test_kms_evidence_signing.py`](../tests/test_kms_evidence_signing.py).

**Unit tests — `ingest_sync()` (extend `test_evidence_stream.py` with a new `TestIngestSync` class):**

| Test case | Scenario | Assertion |
|---|---|---|
| `test_ingest_sync_returns_message_id_on_success` | Redis XADD succeeds within timeout | Returns non-`None` Redis Stream message ID |
| `test_ingest_sync_raises_on_redis_unreachable` | Redis connection refused | Raises `EvidenceChainUnavailableError`, never returns `None` |
| `test_ingest_sync_raises_on_xadd_failure` | XADD call raises (e.g. `ResponseError`) | Raises `EvidenceChainUnavailableError` wrapping the original exception |
| `test_ingest_sync_raises_on_timeout` | XADD call exceeds `timeout_s=2.0` | Raises `EvidenceChainUnavailableError` with timeout context; verify actual wall-clock bound via `asyncio.wait_for` mock |
| `test_ingest_sync_respects_custom_timeout_param` | `timeout_s=0.1` with an artificially slowed mock | Raises within ~0.1s, not the default 2.0s |
| `test_ingest_sync_uses_canonical_payload_serialization` | Any successful call | `payload_json` uses `separators=(",", ":")` (schema 1.1, §4.1) |

**Integration tests — `EVIDENCE_CHAIN_BLOCKING=true` behavior (new file: `tests/test_evidence_chain_blocking_gate.py`):**

| Test case | Scenario | Assertion |
|---|---|---|
| `test_blocking_true_gates_seal_issuance_on_commit` | `EVIDENCE_CHAIN_BLOCKING=true`, evidence sink healthy | Seal issued only *after* `ingest_sync()` resolves; assert ordering via call-order spy |
| `test_blocking_true_denies_on_sink_unavailable` | `EVIDENCE_CHAIN_BLOCKING=true`, Redis down | `validate_action()` raises `GovernanceError` (fail-closed DENY), no seal issued |
| `test_blocking_false_preserves_fire_and_forget` | `EVIDENCE_CHAIN_BLOCKING=false` (default) | Seal issued immediately; `ingest()` (not `ingest_sync()`) called fire-and-forget; byte-for-byte identical to pre-change behavior |
| `test_blocking_true_requires_stream_enabled_precondition` | `EVIDENCE_CHAIN_BLOCKING=true`, `EVIDENCE_STREAM_ENABLED=false` | Fails fast at startup with a clear configuration error (validated precondition per §3.1 of Implementation Specs) |
| `test_blocking_true_latency_overhead_bounded` | `EVIDENCE_CHAIN_BLOCKING=true`, healthy sink | Added latency ≤ `timeout_s` bound; feeds into §3 SLA testing |

**Failure mode testing (timeout, connection errors) — parametrized chaos-style suite:**

| Test case | Fault injected | Expected outcome |
|---|---|---|
| `test_evidence_sink_connection_reset_mid_write` | `ConnectionResetError` during XADD | `EvidenceChainUnavailableError`, DENY when blocking=true |
| `test_evidence_sink_partial_write_then_timeout` | XADD hangs past `timeout_s` | Timeout raised, no partial/duplicate record committed |
| `test_evidence_sink_recovers_after_transient_failure` | First call fails, second succeeds (no retry logic assumed unless implemented) | Confirms no silent retry masking a fail-closed requirement, or documents retry semantics if added |
| `test_dual_schema_verify_record_handles_1_0_and_1_1` | Mixed schema records across cutover boundary (§6.2 of Implementation Specs) | `verify_record()` dispatches correctly by `entry["schema"]`, no false mismatch |

**Commands:**
```bash
uv run pytest tests/test_evidence_stream.py -v
uv run pytest tests/test_evidence_chain_blocking_gate.py -v
uv run pytest tests/test_evidence_stream.py tests/test_kms_evidence_signing.py -m local -v
```

### 2.C FTRA Harness Testing

**Target code:** `FtraNodeConfig` (new, §2.4 of Implementation Specs),
`_parse_plan()` hardening (§2.5), `_ftra_boundary_check()` (new, §2.2
Controller-boundary enforcement).

**Existing baseline to extend:** [`tests/test_ftra_package.py`](../tests/test_ftra_package.py)
(`TestIrreversibilityClassifier`, `TestPlanGraphAnalyzer`,
`TestRouteAfterFtra`, `TestCreateFtraNode` classes already present).

**Unit tests — pluggable extractor abstraction (extend `TestCreateFtraNode` in `test_ftra_package.py`):**

| Test case | Scenario | Assertion |
|---|---|---|
| `test_create_ftra_node_default_config_matches_legacy_behavior` | `create_ftra_node()` called with no args (as `graph.py:127` does today) | Identical output to pre-`FtraNodeConfig` behavior — reads `execution_plan_output`/`evaluation_result` |
| `test_create_ftra_node_custom_plan_extractor` | `FtraNodeConfig(plan_extractor=custom_fn)` | Node uses `custom_fn(state)` instead of the hard-coded key lookup |
| `test_create_ftra_node_custom_confidence_extractor` | `FtraNodeConfig(confidence_extractor=custom_fn)` | Confidence sourced from `custom_fn(state)` |
| `test_create_ftra_node_custom_state_keys` | `FtraNodeConfig(status_state_key="my_status", ...)` | Node writes verdict/result/defer_id under the custom keys |
| `test_create_ftra_node_registry_path_override` | `FtraNodeConfig(registry_path=<tmp_path>)` | Loads terminal registry from the override path, not the default |
| `test_ftra_node_config_is_frozen_dataclass` | Attempt mutation post-construction | Raises `FrozenInstanceError` (matches `OpaNodeConfig`/`NemoNodeConfig` convention) |

**Schema drift regression tests (BUG-FTRA-SCHEMA-001, BUG-FTRA-JSON-001) — extend `_parse_plan()` tests in `test_ftra_package.py`:**

| Test case | Regression target | Assertion |
|---|---|---|
| `test_parse_plan_schema_valid_incomplete_llm_output_not_blocked` | BUG-FTRA-SCHEMA-001 — plan missing optional fields with defaults | Returns valid `ExecutionPlan`, `failure_class=None` — no longer misrepresented as BLOCKED |
| `test_parse_plan_missing_required_field_returns_schema_validation_error` | Genuine schema violation | `ParseResult(plan=None, failure_class="SCHEMA_VALIDATION_ERROR")` |
| `test_parse_plan_tokenizer_artifacts_sanitized` | BUG-FTRA-JSON-001 — `Ġ`/`Ċ` BPE markers in raw LLM output | Sanitization strips markers before `json.loads`; parse succeeds |
| `test_parse_plan_tokenizer_sanitize_disabled_via_flag` | `FTRA_SANITIZE_TOKENIZER_ARTIFACTS=false` | Reverts to pre-sanitization behavior (regression guard for the flag itself) |
| `test_parse_plan_malformed_json_returns_json_decode_error` | Non-tokenizer JSON malformation | `ParseResult(plan=None, failure_class="JSON_DECODE_ERROR")` |
| `test_parse_plan_empty_steps_returns_empty_steps_class` | Schema-valid, `steps=[]` | `ParseResult(plan=<plan>, failure_class="EMPTY_STEPS")` — still governance-fatal but distinguishable |
| `test_ftra_span_carries_parse_failure_class_attribute` | Any parse failure path | OTel span `cage.ftra_analysis` carries `cage.ftra.parse_failure_class` attribute (§2.5) |
| `test_parse_plan_markdown_fence_and_tokenizer_combined` | Both markdown fences and BPE markers present | Both stripped in the correct order; parse succeeds |

**Controller-boundary enforcement tests (new file: `tests/test_ftra_boundary_check.py`):**

| Test case | Scenario | Assertion |
|---|---|---|
| `test_boundary_check_noop_for_non_plan_shaped_payload` | `params` lacks `execution_plan`/`execution_plan_output` | Returns `[]` (not applicable), zero overhead |
| `test_boundary_check_classifies_direct_http_bypass` | Plan-shaped payload sent directly to `validate_action()`, bypassing `ftra_node` entirely | Boundary check still runs `IrreversibilityClassifier`, produces violations if plan is irreversible-terminal — **this is the core R-02/R-03 regression test** |
| `test_boundary_check_shares_classification_with_in_graph_node` | Same plan submitted via (a) in-graph `ftra_node` and (b) direct boundary check | Identical classification result — enforces the "never drifts between the two enforcement points" invariant |
| `test_boundary_check_disabled_by_default` | `CAGE_FTRA_BOUNDARY_ENABLED=false` (default) | No boundary check runs; direct HTTP bypass succeeds unclassified (documents the pre-fix gap explicitly as a regression baseline) |
| `test_boundary_check_hitl_required_routes_through_classify_violation` | Boundary check yields `HITL_REQUIRED` | Routes through `_classify_violation()` → `DEFER`/`REQUIRE_APPROVAL`, not a third parking mechanism |
| `test_boundary_check_denyrate_delta_within_threshold` | Enable flag against a fixed traffic sample | DENY/DEFER rate delta ≤ threshold from KRI table in Risk Matrix §7.1 (warning: >1.5x, critical: >2x baseline) |

**Plan-and-execute precondition validation tests:**

| Test case | Scenario | Assertion |
|---|---|---|
| `test_reactive_agent_without_plan_fails_closed_with_clear_diagnostic` | ReAct-style agent state with no `execution_plan_output` ever set | Node fails closed (BLOCKED or not-applicable per config); if a self-check telemetry counter exists (R-01 mitigation), verify it increments distinguishably from a genuine BLOCKED verdict |
| `test_n_consecutive_empty_steps_triggers_compatibility_warning` | N consecutive `EMPTY_STEPS`/absent-plan results for one integrator/thread | Structured warning distinguishing "host agent architecture incompatible with FTRA" from "genuine BLOCKED verdict" (R-01 mitigation, once implemented) |

**Commands:**
```bash
uv run pytest tests/test_ftra_package.py -v
uv run pytest tests/test_ftra_boundary_check.py -v
uv run pytest tests/test_ftra_package.py tests/test_ftra_boundary_check.py -m local --cov=src/gateway/governance/ftra --cov-report=term-missing
```

### 2.D Redis Failover Hardening Testing

**Target code:** `CAGE_REDIS_SYNCHRONOUS_REPLICATION` fencing (§2.6 of
Implementation Specs) — `safety:fence_epoch` Lua-script increment,
`WAIT`/Sentinel-aware read-path rejection in `cbf.py`/`redis_client.py`.

**Existing baseline to extend:** [`tests/test_cbf_chaos.py`](../tests/test_cbf_chaos.py)
(already covers `ConnectionError`, `TimeoutError`, WATCH-conflict exhaustion,
NOSCRIPT reload, and concurrent-write atomicity — see the six `test_cbf_*`
functions), [`tests/test_gateway_redis_client.py`](../tests/test_gateway_redis_client.py),
[`tests/test_redis_config.py`](../tests/test_redis_config.py),
[`tests/test_symbolic_governor_cbf_atomicity.py`](../tests/test_symbolic_governor_cbf_atomicity.py).

**Unit tests — `fence_epoch` logic (new file: `tests/test_redis_fencing.py`):**

| Test case | Scenario | Assertion |
|---|---|---|
| `test_fence_epoch_increments_on_every_cbf_mutating_write` | `CAGE_REDIS_SYNCHRONOUS_REPLICATION=true`, successful `atomic_verify_and_commit()` | `safety:fence_epoch` incremented by exactly 1, via the Lua script (not a separate non-atomic INCR) |
| `test_fence_epoch_noop_when_flag_disabled` | `CAGE_REDIS_SYNCHRONOUS_REPLICATION=false` (default) | `safety:fence_epoch` untouched — confirms no-op on single-node reference deployment |
| `test_fence_epoch_monotonic_across_concurrent_writers` | N concurrent `atomic_verify_and_commit()` calls | Epoch strictly increases by N total, no lost updates (atomicity via Lua) |
| `test_read_path_rejects_regressed_epoch` | A read observes `safety:fence_epoch` lower than the highest epoch this process previously saw | Read rejected/raises, does not silently trust the stale snapshot |
| `test_read_path_accepts_advancing_epoch` | Epoch strictly greater than last observed | Read accepted normally |
| `test_fence_epoch_survives_process_restart_via_redis_persistence` | Process restarts, re-reads `safety:fence_epoch` from Redis | Highest-observed-epoch tracking re-seeds from Redis, not reset to 0 (would defeat the fencing guarantee) |

**Integration tests — `WAIT` acknowledgment (extend `test_cbf_chaos.py` or new `tests/test_redis_wait_acknowledgment.py`):**

| Test case | Scenario | Assertion |
|---|---|---|
| `test_wait_called_after_cbf_mutating_write_when_flag_enabled` | `CAGE_REDIS_SYNCHRONOUS_REPLICATION=true`, replica count > 0 | `WAIT <replica_count> <timeout_ms>` issued after every CBF-mutating write (spy on Redis client calls) |
| `test_wait_timeout_treated_as_write_uncertain` | `WAIT` call times out (insufficient replicas ack within `timeout_ms`) | Write treated as unverified — either retried or surfaced as a fail-closed error per design; explicit assertion on which behavior is chosen at implementation time |
| `test_sentinel_detected_skips_wait_uses_epoch_verification` | Redis Sentinel topology detected (reusing the probe pattern in [`checkpointer.py:110-151`](../src/governed_financial_advisor/graph/checkpointer.py:110)) | Falls back to epoch-based verification against the newly-promoted master instead of `WAIT` |
| `test_wait_not_called_when_flag_disabled` | `CAGE_REDIS_SYNCHRONOUS_REPLICATION=false` | No `WAIT` call issued — zero behavior change from current single-node deployment |

**Chaos testing for replica failover scenarios (new file: `tests/test_redis_failover_chaos.py`, marker `local` for mocked variant + `integration` for live-topology variant):**

| Test case | Scenario | Assertion |
|---|---|---|
| `test_failover_stale_replica_read_rejected` | Simulated primary-to-replica failover where the promoted replica has a stale (lower) `safety:fence_epoch` | Read from the promoted replica is rejected until its epoch catches up — this is the concrete double-spend-prevention mechanism (R-05) |
| `test_failover_no_double_spend_under_concurrent_trades` | Two concurrent trade requests interleaved with a simulated failover event | At most one trade succeeds; the other is rejected/retried — balance never goes negative |
| `test_failover_without_fencing_reproduces_known_vulnerability` | `CAGE_REDIS_SYNCHRONOUS_REPLICATION=false`, same failover scenario | **Negative control**: demonstrates the vulnerability is real and reproducible absent the fix — mirrors `proof/model.py`'s `ungated_transitions()` negative-control philosophy |
| `test_live_sentinel_failover_drill` (marker `integration`, live GKE only) | Actual Redis Sentinel failover triggered against a live replicated Redis deployment | No double-spend observed across the failover window; requires a non-default Redis replication topology, so this test is skipped unless the target environment sets `architecture=replication` |

**Formal-model cross-validation (link to §2.F):** `test_failover_no_double_spend_under_concurrent_trades` should be
cross-checked against `proof/distributed_cbf_model.py`'s "Fencing
interaction" property (§2.9.1 of Implementation Specs) — the runtime test
and the exhaustive BFS model must agree that a stale-epoch commit is
rejected in all reachable states.

**Commands:**
```bash
uv run pytest tests/test_redis_fencing.py tests/test_cbf_chaos.py -v
uv run pytest tests/test_redis_wait_acknowledgment.py -m local -v
uv run pytest tests/test_redis_failover_chaos.py -m local -v          # mocked variant, CI-safe
uv run pytest tests/test_redis_failover_chaos.py -m integration -v    # live replicated-Redis topology only
```

### 2.E Reconciliation Worker Testing

**Target code:** Reconciliation worker activation is an **operational**
gap, not a code gap (§2.7 of Implementation Specs) — the code
(`reconciliation_worker.py`) and manifest
(`deployment/k8s/reconciliation-worker.yaml`) are both already
code-complete. Testing here validates the activation checklist, not new
application logic. Tracked as **POAM-2026-038** (see identifier note in
front matter).

**Existing baseline to extend:** [`tests/test_reconciliation_worker.py`](../tests/test_reconciliation_worker.py)
(`TestReconciliationResult`, `TestStubLedgerProvider`,
`TestExternalLedgerReconcilerHappyPath`,
`TestExternalLedgerReconcilerFailurePaths`, `TestReadVerifiedBalance`
classes already present — these already validate `GcsLedgerProvider`
registration under `"gcs"`, closing the POAM-2026-042 provider-mismatch
regression).

**Secret population verification tests (operational checklist validation, new file: `tests/test_reconciliation_activation_checklist.py`, marker `integration`, dev/prod GKE only):**

| Test case | Scenario | Assertion |
|---|---|---|
| `test_reconciliation_worker_secret_has_gcs_bucket_key` | `kubectl get secret reconciliation-worker-secrets -o jsonpath='{.data.gcs-reconciliation-bucket}'` | Non-empty value present (base64-decodes to a valid GCS bucket name) |
| `test_reconciliation_worker_secret_has_kms_key` | Same secret, `kms-governance-key` field | Non-empty, matches expected KMS resource path format |
| `test_reconciliation_provider_env_matches_gcs` | CronJob pod spec / running pod env | `RECONCILIATION_PROVIDER=gcs` (guards against the historical `"s3"` misconfiguration named in the POAM) |

**CronJob execution validation (new file, marker `integration`):**

| Test case | Scenario | Assertion |
|---|---|---|
| `test_cronjob_last_run_succeeded` | `kubectl get cronjob reconciliation-worker -o jsonpath='{.status.lastSuccessfulTime}'` | Timestamp present and within the last `2 * schedule_interval` (10 minutes for `*/5 * * * *`) |
| `test_cronjob_no_create_container_config_error` | Pod events for the most recent job run | No `CreateContainerConfigError` reason present |
| `test_cronjob_pod_logs_confirm_kms_signature_verification` | Pod logs from the last successful run | Log line confirms KMS-signature verification succeeded (evidence for POAM-2026-038 closure) |

**GCS ledger provider integration tests (extend `TestExternalLedgerReconcilerHappyPath`/`TestGcsFlushLoop`-adjacent coverage, marker `integration`):**

| Test case | Scenario | Assertion |
|---|---|---|
| `test_gcs_ledger_provider_fetch_balance_against_real_bucket` | `GcsLedgerProvider.fetch_balance()` against the actual configured GCS bucket (dev environment) | Returns a well-formed balance record, no `NotImplementedError`/exception |
| `test_reconciliation_verified_balance_populated_in_redis` | `redis-cli GET reconciliation:verified_balance` after a successful CronJob run | Non-empty, KMS-signed payload present |
| `test_fiscal_limit_guard_prefers_reconciled_balance_over_redis_only` | `FiscalLimitGuard` read path when both reconciled and Redis-only balances exist | Reconciled (externally-verified) balance takes precedence, per `cbf.py`'s `read_verified_balance()` |
| `test_reconciliation_staleness_falls_back_gracefully_past_ttl` | `reconciliation:verified_balance` older than 300s TTL | `FiscalLimitGuard` falls back to un-reconciled Redis counters (documented degraded-but-safe behavior) |

**POAM-2026-038 closure evidence checklist (procedural, not a pytest case — record in `docs/POAM.md`):**

1. Run `test_reconciliation_worker_secret_has_gcs_bucket_key` and
   `test_reconciliation_provider_env_matches_gcs` — both green.
2. Run `test_cronjob_last_run_succeeded` and
   `test_cronjob_no_create_container_config_error` — both green for at
   least 3 consecutive scheduled runs (15 minutes of observation).
3. Run `test_reconciliation_verified_balance_populated_in_redis` — green.
4. Attach the KMS-signature verification timestamp from step 2's pod logs
   to the POAM-2026-038 closure entry in `docs/POAM.md`, per the
   Compliance Artifact Obligations in `AGENTS.md`.

**Commands:**
```bash
uv run pytest tests/test_reconciliation_worker.py -v
uv run pytest tests/test_reconciliation_activation_checklist.py -m integration -v   # dev/prod GKE only
bash deployment/scripts/setup_reconciliation_secret.sh   # operational activation step, not a test
```

### 2.F Formal Model Conformance Testing

**Target code:** `proof/model.py` (existing, 21/24/19/20 pinned reachable
states), `proof/distributed_cbf_model.py` (new, §2.9.1 of Implementation
Specs), TLA+ phased extension (§2.9.2).

**Existing baseline to extend:** [`tests/test_no_direct_bind_proof.py`](../tests/test_no_direct_bind_proof.py)
(pins the 21/24/19/20 reachable-state counts; already marked
`pytest.mark.local` per the fix documented in
[`docs/paper/REVISION_TRACKER.md:154`](../docs/paper/REVISION_TRACKER.md:154)).

**Runtime-conformance tests intercepting live `_run_checks()` traces (new file: `tests/test_formal_model_conformance.py`):**

| Test case | Scenario | Assertion |
|---|---|---|
| `test_live_run_checks_trace_matches_a_reachable_model_state` | Instrument `SymbolicGovernor._run_checks()` with a trace collector; run a representative set of live requests through it | Every observed `(tier_outcomes...)` tuple corresponds to a state in `proof/model.py`'s BFS-enumerated reachable-state set — no live trace should visit an "impossible" state |
| `test_no_direct_bind_holds_for_every_observed_trace` | Same instrumented run | For every trace, `phase == EXECUTED` implies `resolvedAllow == True` — the runtime analogue of the static invariant |
| `test_defer_narrow_pause_traces_flagged_as_model_scope_gap` | Traces that produce `DEFER`/`NARROW`/`PAUSE` verdicts (once §2.1 ships) | Explicitly asserted as **out of the current 21/24/19/20 model's scope** until §6.4's blast-radius update lands — this test documents the gap rather than silently passing or failing |
| `test_ftra_boundary_check_traces_flagged_as_model_scope_gap` | Traces where `_ftra_boundary_check()` (§2.2) fires | Same treatment — explicitly out of scope until the model is extended, per §6.4 of Implementation Specs |

**State count validation against `tests/test_no_direct_bind_proof.py` (regression discipline, not new tests — a process requirement):**

Any implementation change that alters `_run_checks()`'s tier list or
outcome domain (notably the Controller-boundary FTRA check from §2.2, or
NARROW/PAUSE becoming reachable terminal-ish outcomes from §2.1) **must**:

1. Update `proof/model.py`'s `TIERS`/transition functions to reflect the
   new tier.
2. Update `tests/test_no_direct_bind_proof.py`'s `EXPECTED_*` constants
   (currently 21/24/19/20) to match the new BFS enumeration output.
3. Update every location in
   [`docs/paper/REVISION_TRACKER.md`](../docs/paper/REVISION_TRACKER.md)'s
   "Consistency blast radius" section.
4. Re-run both `python proof/model.py` (assertion-based) and
   `uv run pytest tests/test_no_direct_bind_proof.py -m local -v`
   (pinned-count regression) before merging.

This is the exact trigger condition documented in §6.4 of the
Implementation Specs and R-15 of the Risk Matrix — CI's
`no-direct-bind-proof` job (`.github/workflows/ci.yml:272-302`) is the
automated backstop, but the manual update steps above cannot be skipped
since the job only detects drift, it does not resolve it.

**Distributed model validation (when implemented, new file: `tests/test_distributed_cbf_proof.py`, `pytestmark = pytest.mark.local` per the precedent fix in `REVISION_TRACKER.md:154`):**

| Test case | Scenario | Assertion |
|---|---|---|
| `test_safety_holds_for_2_3_4_concurrent_agents` | BFS enumeration for N ∈ {2, 3, 4} under atomic (Lua-serialized) commit | `balance >= min_cash_balance` holds in every reachable state |
| `test_ungated_variant_produces_reachable_violation` | Negative control: naive read-then-write race (TOCTOU) variant | Enumerator finds at least one reachable state violating `balance >= min_cash_balance` — confirms the model is load-bearing |
| `test_stale_epoch_commit_rejected_in_all_reachable_states` | Fencing-aware variant with `fence_epoch` in the state tuple | No reachable state permits a commit using a stale epoch — analytically validates §2.6's runtime fencing design |
| `test_distributed_model_state_count_pinned` | Same purpose as `test_no_direct_bind_proof.py` for the single-agent model | Pins the distributed model's reachable-state count so silent drift is caught in CI |

**CI integration for this new proof:** add a `distributed-cbf-proof` job to
[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) mirroring the
existing `no-direct-bind-proof` job structure (raw script assertion run +
pinned pytest regression), per §2.9.1 of the Implementation Specs.

**Commands:**
```bash
python proof/model.py                                          # exhaustive BFS assertion, stdlib-only
uv run pytest tests/test_no_direct_bind_proof.py -m local -v   # pinned 21/24/19/20 state-count regression
python proof/distributed_cbf_model.py --agents 3                # once implemented
uv run pytest tests/test_distributed_cbf_proof.py -m local -v  # once implemented
uv run pytest tests/test_formal_model_conformance.py -m integration -v   # live-trace conformance, dev GKE
```

---

## 3. Performance and SLA Testing

### 3.1 200ms SLA Validation Test Suite

The 200ms budget originates from the FedNow/SEPA Instant 10-second clearing
window disclosure in the paper measurements (e.g.
[`docs/paper/measurements/2026-08-06-fafef04/PROVENANCE.md:48`](../docs/paper/measurements/2026-08-06-fafef04/PROVENANCE.md:48)).
**Current Table 2 measurements use mocked Redis/OPA/consensus RPC**
(per `scripts/measure_paper_metrics.py`'s default mode and
[`docs/paper/MEASUREMENT_RUNBOOK.md:110`](../docs/paper/MEASUREMENT_RUNBOOK.md:110)'s
"B1 — Mocked-I/O latency" step) — this is explicitly disclosed as isolating
"pure governance-logic CPU cost," not a production SLA measurement. Closing
this gap requires the live-GKE benchmark in §3.2.

**Existing baseline to extend:** [`tests/test_governance_pipeline_latency.py`](../tests/test_governance_pipeline_latency.py)
(`TestTier1NemoInputGuardrailLatency`, `TestTier2OpaPolicyCheckLatency`,
`TestTier3SafetyNodeLatency`, `TestTier5NemoOutputRailLatency`,
`TestPipelineCumulativeLatency`, `TestTier1LatencyP95` classes already
present).

| Test case | Scenario | Assertion |
|---|---|---|
| `test_mocked_io_cumulative_latency_under_budget` | Existing `TestPipelineCumulativeLatency` extended with an explicit 200ms comparison | Sum of 4 non-LLM tier latencies (mocked I/O) < 200ms — sanity floor, not the SLA proof itself |
| `test_tier_latency_p95_regression_gate` | `TestTier1LatencyP95`-style P95 check applied to every tier | P95 does not regress > 10% from the last recorded baseline in `docs/paper/measurements/` |
| `test_evidence_chain_blocking_latency_within_budget` | `EVIDENCE_CHAIN_BLOCKING=true` (§2.B) added to the pipeline | Cumulative latency with blocking enabled still < 200ms budget in mocked-I/O mode |
| `test_ftra_boundary_check_latency_overhead` | `CAGE_FTRA_BOUNDARY_ENABLED=true` (§2.C) added to the pipeline | New tier's added latency is quantified and does not push cumulative mocked-I/O latency over budget |

### 3.2 Live GKE Latency Benchmark Procedures

Addresses the **End-to-End Live Latency Benchmarking** gap named in the
task context (R-16 of the Risk Matrix) — this requires access to a live
GKE cluster and cannot be satisfied by mocked-I/O measurements alone.

**Procedure (per `AGENTS.md` Test Execution + `docs/paper/MEASUREMENT_RUNBOOK.md`):**

```bash
# 1. Establish port-forwards to the live GKE dev cluster
bash scripts/port_forward_dev.sh

# 2. In a separate terminal, load env and run the unmocked measurement mode
source .env
export CAGE_ENV=dev
export BACKEND_URL="http://localhost:18080"
export LATENCY_RUNS=200   # paper-grade sample size per MEASUREMENT_RUNBOOK.md
uv run python scripts/measure_paper_metrics.py --unmocked
```

| Test case | Scenario | Assertion |
|---|---|---|
| `test_live_gke_end_to_end_latency_p50_within_budget` | `--unmocked` run against live Redis/OPA/consensus RPC over the real network path | P50 end-to-end latency < 200ms |
| `test_live_gke_end_to_end_latency_p95_p99_recorded` | Same run | P95/P99 recorded and captioned per the E5 gate in `MEASUREMENT_RUNBOOK.md` (`LATENCY_RUNS` in JSON output matches the paper caption) |
| `test_live_gke_latency_matches_mocked_baseline_within_tolerance` | Compare live vs. mocked-I/O measurements from §3.1 | Delta is attributable to network RTT, not a governance-logic regression — document any outlier per the existing `PERFORMANCE_REVIEW.md`-style provenance discipline |
| `test_live_gke_benchmark_rerun_on_tier_count_change` | Any change to `_run_checks()`'s tier count/ordering (DEFER wiring, Controller-boundary FTRA check, etc.) | Re-benchmark triggered per the same condition as §6.4 formal-model consistency (R-16 mitigation) — process requirement, not an automated test |

**Provenance requirement:** every live-GKE benchmark run must produce a
`docs/paper/measurements/<date>-<sha>/PROVENANCE.md` entry following the
existing template (`PROVENANCE_TEMPLATE.md`), recording the git SHA,
`LATENCY_RUNS` value, and pass/fail status of gates E1–E6 defined in
`MEASUREMENT_RUNBOOK.md`.

### 3.3 Load Testing

**Existing infrastructure:** [`scripts/run_gke_load_test.sh`](../scripts/run_gke_load_test.sh)
(Locust-based, safety-limited to `MAX_USERS=50`/`SPAWN_RATE=5`/`RUN_TIME=5m`
by default), [`tests/load/locustfile.py`](../tests/load/locustfile.py),
[`scripts/check_locust_baseline.py`](../scripts/check_locust_baseline.py)
(p95 regression gate, currently wired into the disabled-by-default
`locust-load-test` CI job at
[`ci.yml:464-523`](../.github/workflows/ci.yml:464)).

| Test case | Scenario | Assertion |
|---|---|---|
| `test_load_test_p95_within_baseline` | `run_gke_load_test.sh` against dev GKE gateway | `check_locust_baseline.py --p95-baseline-ms 2000` passes (existing CI threshold) |
| `test_load_test_no_5xx_under_sustained_load` | 50 concurrent users, 5-minute sustained run | Zero HTTP 5xx responses; any DENY/DEFER responses are expected governance behavior, not errors |
| `test_load_test_hpa_scales_under_load` | `deployment/k8s/gateway-hpa.yaml` applied per the script | Pod count increases per HPA policy as load increases, confirming autoscaling is functional under the new DEFER/NARROW/PAUSE code paths |
| `test_load_test_redis_fencing_overhead_under_load` | Load test with `CAGE_REDIS_SYNCHRONOUS_REPLICATION=true` (once implemented) | P95 latency overhead from `WAIT`/fencing quantified and stays within an agreed tolerance band |

**Commands:**
```bash
NAMESPACE=governance-stack ./scripts/run_gke_load_test.sh
uv run python scripts/check_locust_baseline.py --stats-csv /tmp/locust_report_stats.csv --p95-baseline-ms 2000
```

### 3.4 Latency Regression Detection Thresholds

| Signal | Warning threshold | Critical threshold | Source |
|---|---|---|---|
| Tier-level P95 (mocked I/O) | > 10% regression vs. last recorded baseline | > 25% regression | `tests/test_governance_pipeline_latency.py` |
| Cumulative mocked-I/O latency vs. 200ms budget | > 50% of budget consumed (100ms) | > 90% of budget consumed (180ms) | §3.1 |
| Live GKE end-to-end P50 vs. 200ms budget | > 150ms | > 200ms (SLA breach) | §3.2 |
| Locust load-test P95 | > 2000ms (existing CI gate) | > 2x baseline | `scripts/check_locust_baseline.py` |
| New-tier latency overhead (FTRA boundary check, evidence blocking, Redis fencing) | Any measurable overhead not yet captioned in `docs/paper/measurements/` | Overhead pushes cumulative latency past either budget row above | §3.1/§3.2 |

---

## 4. Security Testing

### 4.1 Trust-Boundary Bypass Attempt Tests

Directly targets R-02/R-03 of the Risk Matrix (Trust-Boundary Bypass, False
Sense of Security). Extends the Controller-boundary tests in §2.C with an
explicit adversarial framing.

**File:** `tests/test_ftra_boundary_check.py` (shared with §2.C) plus a
dedicated adversarial suite `tests/test_trust_boundary_bypass.py`.

| Test case | Attack scenario | Expected outcome |
|---|---|---|
| `test_direct_http_bypass_of_ftra_node_blocked_when_boundary_enabled` | Adversary crafts a plan-shaped payload and POSTs directly to `/v1/governance/validate-action`, never invoking `ftra_node` | With `CAGE_FTRA_BOUNDARY_ENABLED=true`: classified and BLOCKED/DEFERRED as if it had gone through the in-graph node |
| `test_ext_authz_direct_check_bypass_blocked_when_boundary_enabled` | Same attack via the ext_authz `/check` endpoint | Same outcome — both ingress paths share `SymbolicGovernor` (§5.2 of Implementation Specs) |
| `test_bypass_reproduces_pre_fix_gap_as_documented_baseline` | Same attack, `CAGE_FTRA_BOUNDARY_ENABLED=false` (default, pre-fix state) | Documents the known-open gap explicitly (negative control) — this test must fail loudly if it starts passing unexpectedly (would indicate an untracked change to default behavior) |
| `test_compromised_host_agent_cannot_disable_controller_boundary_check` | Simulated compromised/malicious host agent process that never wires `ftra_node` at all | Controller-boundary check still fires, independent of host agent cooperation |
| `test_network_policy_compensating_control_restricts_direct_access` | NetworkPolicy-level interim control (R-03 contingency plan) applied | Direct network access to `/validate-action`/ext_authz from outside the trusted host agent's pod/namespace is denied at the network layer — validated via `kubectl` NetworkPolicy simulation or a live-cluster connectivity test |

### 4.2 Redis Replay Attack Simulation Tests

Directly targets R-04 (Redis Replay Vulnerability), specced in **§2.10
(Reconciliation Payload Replay Defense) of the Implementation Specs**. New
file: `tests/test_redis_replay_defense.py`.

**Unit tests — sequence-number validation (`ReconciliationResult.sequence`, `cbf.py` read-path check):**

| Test case | Attack scenario | Expected outcome |
|---|---|---|
| `test_stale_signed_balance_rewrite_resets_ttl_pre_fix` | Compromised agent with Redis write access re-writes a stale-but-validly-signed balance payload to `reconciliation:verified_balance` | **Pre-fix negative control**: demonstrates the TTL clock resets indefinitely absent a sequence number — documents the known vulnerability |
| `test_monotonic_sequence_number_rejects_non_advancing_replay` | Same attack, with `CAGE_RECONCILIATION_REPLAY_DEFENSE=true` (§2.10 mitigation) | Replayed payload with a non-advancing (or equal) `sequence` is rejected by `_read_cbf_state_atomic()`; falls back to self-reported balance with a `CBF_RECONCILED_BALANCE_SEQUENCE_REPLAY_DETECTED` CRITICAL log, exactly mirroring the existing invalid-signature fallback path |
| `test_sequence_zero_default_treated_as_never_advancing` | Pre-migration payload deserialized via `from_redis_payload()`'s `.get("sequence", 0)` default, `CAGE_RECONCILIATION_REPLAY_DEFENSE=true`, `last_accepted > 0` | Defaulted `sequence=0` is correctly rejected as non-advancing — confirms the two-phase rollout ordering (§2.10.5) is enforced, not merely documented |
| `test_sequence_accepted_updates_last_accepted_high_water_mark` | Valid payload with `sequence > last_accepted` | `reconciliation:sequence:last_accepted` is updated to the new value; a subsequent replay of the same (now-stale) sequence is rejected |
| `test_duplicate_kms_signature_detected` | Replay of an identical previously-accepted payload (same `kms_signature`) | Detection indicator fires — repeated identical signature across TTL windows is flagged (per the KRI in Risk Matrix §7.1) |
| `test_replay_defense_independent_of_redis_replication_topology` | Same attack on single-node Redis (no `CAGE_REDIS_SYNCHRONOUS_REPLICATION`) | Sequence-number check is effective even without replication fencing — confirms R-04's fix is additive/independent of §2.6 (R-05) |
| `test_replay_detected_triggers_fail_closed_fiscal_deny` | Replay detected in a live request path | All fiscal-limit-gated actions DENY immediately per the R-04 contingency plan; no partial/degraded-trust mode |
| `test_replay_defense_disabled_preserves_pre_fix_behavior` | `CAGE_RECONCILIATION_REPLAY_DEFENSE=false` (default) | Byte-for-byte identical to today: TTL+signature-only trust, no sequence read/rejection — confirms default-off backward compatibility |

**Chaos test scenario (new, `tests/test_redis_replay_defense.py::TestReplayChaosScenario`, marker `local` for the mocked variant):**

| Test case | Fault injected | Expected outcome |
|---|---|---|
| `test_chaos_reconciliation_worker_restart_preserves_sequence_counter` | Reconciliation worker pod killed/rescheduled mid-cycle, `reconciliation:sequence:latest` already at N | New worker instance's next `INCR` yields N+1, not a reset to 1 — confirms the counter is plain Redis state, not worker-local memory |
| `test_chaos_concurrent_replay_and_legitimate_write_race` | A replayed stale payload and a legitimate new reconciliation cycle write concurrently | The legitimate write's higher `sequence` always wins acceptance regardless of write-order interleaving; the stale replay is rejected whenever it is read after the legitimate write's sequence has been accepted |
| `test_chaos_redis_flush_resets_sequence_without_crashing_cbf` | `reconciliation:sequence:last_accepted` and `reconciliation:sequence:latest` both flushed (e.g. accidental `FLUSHDB`) | CBF fails closed (falls back to self-reported balance) rather than silently accepting a sequence starting again from a low value as advancing past a now-absent high-water mark — the fail-closed default must not be inverted by key absence |
| `test_chaos_replay_defense_toggle_mid_flight_no_partial_state` | `CAGE_RECONCILIATION_REPLAY_DEFENSE` flipped `false`→`true` while requests are in-flight | No request observes a torn/partial check (either fully enforced or fully bypassed per-request, never a half-applied check) |

### 4.3 Schema Migration Security Validation

Directly targets R-10 (Backward-Incompatibility Risk, evidence chain
schema 1.0→1.1). Extends [`tests/test_evidence_stream.py`](../tests/test_evidence_stream.py)
and the `verify_record()` utility tests from §2.B.

| Test case | Scenario | Assertion |
|---|---|---|
| `test_schema_1_0_records_remain_verifiable_post_migration` | Historical schema-1.0 records exist; migration to 1.1 code has shipped | `verify_record()` correctly re-verifies 1.0 records using the 1.0 routine — no false tamper-detection |
| `test_schema_1_1_records_use_canonical_separators` | New records post-cutover | `payload_json` uses `separators=(",", ":")`; `record_hash` is reproducible across independent encoders |
| `test_cutover_boundary_prev_hash_seeded_from_last_record_not_genesis` | `EvidenceStreamSink.__init__()` at cutover time | `_prev_hash` seed reads from `XREVRANGE ... COUNT 1` (last persisted record), never resets to `EVIDENCE_STREAM_GENESIS` sentinel — this is the specific failure mode that would silently break chain continuity |
| `test_heterogeneous_schema_chain_verifies_end_to_end` | A chain spanning both 1.0 and 1.1 records | Full chain (`prev_hash` → `record_hash` linkage) verifies without gaps across the schema boundary |
| `test_no_retroactive_rehash_of_schema_1_0_records` | Migration tooling/utility invoked | Schema-1.0 records' stored `record_hash` is never recomputed/overwritten under the 1.1 rule |
| `test_rollback_to_schema_1_0_preserves_dual_schema_verification` | Post-rollback (§6.2 rollback procedure) | New post-rollback records resume schema-1.0 serialization; `verify_record()` continues to correctly verify all three eras (pre-cutover 1.0, 1.1, post-rollback 1.0) |

### 4.4 Credential Hygiene Validation

Per `AGENTS.md`'s Secret Hygiene standard — validates that no remediation
work introduces credential leakage, consistent with the repository-wide
`security-scan` CI gate.

| Test case | Scenario | Assertion |
|---|---|---|
| `test_no_hardcoded_fallback_secrets_in_new_env_vars` | Static scan of new code touching `EVIDENCE_CHAIN_BLOCKING`, `CAGE_REDIS_SYNCHRONOUS_REPLICATION`, `CAGE_NARROW_ENABLED`, `CAGE_FTRA_BOUNDARY_ENABLED`, `CAGE_RECONCILIATION_REPLAY_DEFENSE` | No `os.environ.get("KEY", "hardcoded-fallback")` pattern for sensitive values (Bandit + manual review) |
| `test_reconciliation_secret_never_logged` | Reconciliation worker activation (§2.E) logging paths | `gcs-reconciliation-bucket`/`kms-governance-key` values never appear in plaintext in pod logs |
| `test_pause_resume_token_not_logged_in_plaintext` | New `PAUSE:{resume_token}` primitive | `resume_token` is masked (`value[:4] + "****"`) in any diagnostic logging, per `AGENTS.md` Debugging Standards |
| `test_kubernetes_manifests_use_secretkeyref_not_value` | Any new/modified K8s manifest referencing the reconciliation secret or new Redis fencing config | `secretKeyRef`/`secretRef` used exclusively — no `value: <secret>` in committed YAML |
| `test_bandit_sast_passes_on_new_governance_modules` | `_classify_violation()`, `pause_primitive.py`, `_ftra_boundary_check()`, `ingest_sync()` | `uv run bandit -r src/ -c pyproject.toml -ll` reports no medium+ severity findings (existing CI gate, [`ci.yml:133-134`](../.github/workflows/ci.yml:133)) |

**Commands:**
```bash
uv run pytest tests/test_trust_boundary_bypass.py tests/test_ftra_boundary_check.py -v
uv run pytest tests/test_redis_replay_defense.py -v
uv run pytest tests/test_evidence_stream.py -k "schema or migration or verify_record" -v
uv run bandit -r src/ -c pyproject.toml -ll
```

---

## 5. Compliance Validation Framework

### 5.1 Lula Validation Integration

[`compliance/lula/`](../compliance/lula/) contains 26 `lula-validation-*.yaml`
manifests (per-control assertions) plus 3 regional postures (US_FED,
EU_ECB, APAC_MAS). The remediation backlog's shared modules
(`src/gateway/governance/`, `src/compliance_bridge/`) require Lula
validation updates per the Compliance Bridge Interfaces obligations in
§5.3 of the Implementation Specs.

| Test case | Scenario | Assertion |
|---|---|---|
| `test_lula_manifest_count_matches_readme` | Existing CI check (`ci.yml:354-365`, `lula-ai600-validation` job) | Disk count of `lula-validation-*.yaml` matches unique references in `compliance/lula/README.md` |
| `test_lula_au12_reflects_evidence_chain_blocking_state` | `lula-validation-au12.yaml` (AU-12, audit logging) | Assertion checks `EVIDENCE_STREAM_ENABLED`/`EVIDENCE_CHAIN_BLOCKING` state, not just NoDirectBind — closes the R-06 overclaim gap named in the Risk Matrix |
| `test_lula_manifest_enumerates_new_redis_key_namespaces` | Any Lula assertion enumerating governance Redis key namespaces | `PAUSE:{resume_token}`, `PAUSE:expiry_index`, `safety:fence_epoch` are reflected (§5.3 of Implementation Specs) |
| `test_lula_sc4_sc8_cover_ftra_boundary_check` | `lula-validation-sc4.yaml`/`lula-validation-sc8.yaml` (boundary protection controls) | Assertion validates `CAGE_FTRA_BOUNDARY_ENABLED` state is disclosed for the deployed posture |
| `test_lula_drafts_promoted_before_release` | [`compliance/lula/drafts/`](../compliance/lula/drafts/) | Any new manifest touching remediation-backlog controls is promoted out of `drafts/` before the corresponding release tag |
| `test_check_ai600_lula_manifests_stub_syntax_valid` | Existing script [`scripts/check_ai600_lula_manifests.py`](../scripts/check_ai600_lula_manifests.py) | Stub manifests validate as OSCAL component-definition structure (existing CI gate, `ci.yml:349-353`) |

**Commands:**
```bash
python3 scripts/check_ai600_lula_manifests.py
ls compliance/lula/lula-validation-*.yaml | wc -l   # cross-check against README unique-reference count
```

### 5.2 OSCAL Control Coverage Verification

Per §5.3 of the Implementation Specs, any control implementation touched by
DEFER/NARROW/PAUSE wiring, the evidence-chain blocking gate, or the
Controller-boundary FTRA check requires an OSCAL component update in
[`compliance/oscal/`](../compliance/oscal/) within 2 business days of merge.

| Test case | Scenario | Assertion |
|---|---|---|
| `test_oscal_ssp_exporter_regenerates_without_error` | [`src/gateway/governance/oscal_ssp_exporter.py`](../src/gateway/governance/oscal_ssp_exporter.py) run post-remediation-merge | SSP regenerates cleanly, no missing-control errors |
| `test_oscal_component_definition_includes_ctrl_tqp_007_and_new_controls` | Existing gap named in `POAM_ISO42001.md:57` (ISO-004) plus any new DEFER/NARROW/PAUSE-related control | Component definition entry exists and links to the correct Lula validation manifest |
| `test_oscal_coverage_above_threshold` | Existing coverage-threshold check (referenced in `AGENTS.md` Debugging Standards: "run `oscal_ssp_exporter.py` to regenerate the SSP" when below threshold) | Coverage percentage does not regress below the repository's configured threshold |
| `test_oscal_cer_links_valid_for_evidence_chain_controls` | [`tests/test_oscal_cer_links.py`](../tests/test_oscal_cer_links.py) (existing) extended for AU-12/evidence-chain-blocking | CER (Control Evidence Record) links resolve correctly for the new `EVIDENCE_CHAIN_BLOCKING`-gated control state |
| `test_oscal_au12_distinguishes_decision_time_from_evidence_of_execution` | R-06 mitigation — OSCAL component citing NoDirectBind for AU-12 | Component definition text explicitly distinguishes the decision-time safety invariant from the opt-in, fail-open-unless-blocking evidence chain guarantee |

**Commands:**
```bash
uv run pytest tests/test_oscal_ssp_exporter.py tests/test_oscal_adapter.py tests/test_oscal_cer_links.py -v
uv run python src/gateway/governance/oscal_ssp_exporter.py --check-coverage
```

### 5.3 POAM Closure Validation Procedures

**POAM-2026-038 (Reconciliation Worker Secret Population)** — see §2.E for
the full activation checklist and closure evidence procedure. Summary
validation gate:

```bash
uv run pytest tests/test_reconciliation_activation_checklist.py -m integration -v
uv run python scripts/check_poam_lula_divergence.py   # confirms POAM.md and Lula assertions agree on closure status
```

**General POAM closure validation pattern** (applies to any POAM item
closed as part of this remediation program, e.g. a future POAM opened for
R-04's replay defense or R-10's schema migration):

| Step | Action | Verification |
|---|---|---|
| 1 | Identify the corresponding test case(s) in this framework that validate the fix | Cross-reference §8 Acceptance Criteria Matrix |
| 2 | Run the test suite and confirm green | `uv run pytest <test_file> -v` |
| 3 | For infrastructure/operational POAMs, gather live evidence (pod logs, `kubectl` output, signature timestamps) | Per the specific POAM's evidence requirement |
| 4 | Update `docs/POAM.md` with commit SHA, Lula validation result, and closure date | Per `AGENTS.md` Compliance Artifact Obligations |
| 5 | Run `scripts/check_poam_lula_divergence.py` to confirm no drift between POAM status and Lula assertions | Existing script, no new tooling needed |

### 5.4 Regional Posture (US_FED, EU_ECB, APAC_MAS) Testing

Per `AGENTS.md`'s Architecture & Design Standards, any change to
`src/gateway/governance/` or `src/compliance_bridge/` (both shared across
all three regional postures) requires region-impact disclosure. CI already
parametrizes `pytest-logic` across all three regions
([`ci.yml:93-103`](../.github/workflows/ci.yml:93)).

| Test case | Scenario | Assertion |
|---|---|---|
| `test_defer_narrow_pause_pass_all_three_region_matrices` | New DEFER/NARROW/PAUSE code paths | `uv run pytest tests/ -m "local or unit" -n auto` passes with `CAGE_DEPLOYMENT_REGION` set to each of `US_FED`/`EU_ECB`/`APAC_MAS` |
| `test_evidence_chain_blocking_staged_rollout_per_region` | `EVIDENCE_CHAIN_BLOCKING=true` staged dev → staging → US_FED prod → EU_ECB/APAC_MAS prod (§6.1 of Implementation Specs) | Each region's posture-specific test subset passes before promoting the flag in that region |
| `test_eu_ecb_dora_art10_reflects_evidence_chain_state` | `lula-validation-dora-art10.yaml` (EU_ECB, DORA Art. 10 logging) | Assertion checks `EVIDENCE_CHAIN_BLOCKING` state — EU_ECB is expected to adopt blocking mode ahead of US_FED per §6.1 |
| `test_apac_mas_notice655_reflects_evidence_chain_state` | `lula-validation-mas-notice655.yaml` | Same pattern for APAC_MAS |
| `test_ftra_boundary_check_denyrate_delta_measured_per_region` | `CAGE_FTRA_BOUNDARY_ENABLED=true` staged per-region (§6.3, Stage 1) | DENY/DEFER rate delta measured independently per region before promoting to the next region — regional gates block regional deployment only, never the global stable tag |
| `test_us_fed_ai600_gates_unaffected_by_narrow_pause` | `ai600-unit-tests` CI job (`ci.yml:428-462`) | Existing AI 600-1 red-team/CBRN gates continue passing with `CAGE_NARROW_ENABLED`/PAUSE primitives present but disabled by default |

**Commands:**
```bash
CAGE_DEPLOYMENT_REGION=US_FED uv run pytest tests/ -m "local or unit" -n auto --dist=loadfile -v
CAGE_DEPLOYMENT_REGION=EU_ECB uv run pytest tests/ -m "local or unit" -n auto --dist=loadfile -v
CAGE_DEPLOYMENT_REGION=APAC_MAS uv run pytest tests/ -m "local or unit" -n auto --dist=loadfile -v
uv run pytest tests/ -m apac_mas -v
uv run pytest compliance/postures/eu_ecb/llm_eval/ -v --timeout=300
```

---

## 6. Test Data Management

### 6.1 Adversarial Corpus Expansion Strategy (Beyond 26 Payloads)

Directly addresses R-08 (Statistical/Generalizability Risk) — the
**Statistical/Generalizability Risk gap** named in the task context.
[`tests/red_team/adversarial_dataset.json`](../tests/red_team/adversarial_dataset.json)
currently contains 26 hand-authored payloads across 6 categories
(`pii_injection`, `prompt_injection`, `rbac_escalation`,
`harmful_financial`, `compound_attack`, `confidence_spoofing`) that serve
as **both** the development corpus (used to tune detectors like
`prompt_injection_detector.py`) and the evaluation corpus (used to report
robustness metrics) — a train/test leakage pattern.

**Expansion procedure:**

1. **Automated red-teaming/fuzzing.** Use `garak`/`PyRIT`-style automated
   adversarial generation to expand beyond the 26 hand-authored payloads,
   per the Risk Matrix's R-08 mitigation strategy. Target: at minimum 3x
   the current corpus size (≥ 78 payloads) as an initial milestone, with
   ongoing quarterly growth tracked as a KRI (Risk Matrix §7.1: "Corpus
   size unchanged for > 1 quarter" is a warning-threshold trigger).
2. **Category coverage audit.** Ensure new payloads are distributed across
   all 6 existing categories plus any newly identified attack categories
   discovered via red-teaming (e.g. FTRA-specific bypass payloads from
   §4.1, Redis-replay-specific payloads from §4.2).
3. **Provenance tagging.** Each new payload records its generation method
   (`hand_authored` | `garak` | `pyrit` | `incident_derived`) in the
   dataset metadata, enabling future analysis of detector performance by
   payload origin.

### 6.2 Test/Eval Set Separation Requirements

**Mandatory split before any robustness metric is published:**

| Requirement | Specification |
|---|---|
| Disjoint partitioning | No payload used to tune/develop a detector (`prompt_injection_detector.py`, `confidence_claim_detector.py`, `authorization_claim_detector.py`) may also appear in the set used to report its detection-rate metric |
| Partition metadata | `adversarial_dataset.json` metadata block records which payloads belong to `dev` vs. `eval` partitions |
| Minimum eval set size | Track as an explicit target once the corpus expansion (§6.1) completes — the current 26-payload corpus has insufficient statistical power for either partition alone |
| Existing benign corpus | [`tests/red_team/benign_dataset.json`](../tests/red_team/benign_dataset.json) (20 prompts, added per `docs/paper/REVISION_TRACKER.md:66` S2 fix) requires the same dev/eval separation treatment |
| Re-run cadence | Detection-rate/FPR metrics must be regenerated against the eval partition only whenever a detector is retrained/retuned against the dev partition |

**Test cases (new file: `tests/red_team/test_corpus_partition_integrity.py`):**

| Test case | Scenario | Assertion |
|---|---|---|
| `test_dev_eval_partitions_are_disjoint` | Load `adversarial_dataset.json` partition metadata | No payload ID appears in both `dev` and `eval` lists |
| `test_every_payload_assigned_a_partition` | Same | Every payload has an explicit partition assignment (no unassigned/ambiguous payloads) |
| `test_eval_partition_used_for_published_metrics` | Cross-check `scripts/measure_paper_metrics.py`'s dataset loading | Confirms the eval-only partition (not the full corpus) is the one referenced when generating paper-facing metrics |
| `test_corpus_size_growth_tracked` | Compare current corpus size against the last quarterly checkpoint | Fails/warns if unchanged for > 1 quarter (KRI from Risk Matrix §7.1) |

### 6.3 Synthetic Data Generation Procedures

For scenarios where real adversarial examples are impractical to
hand-author (e.g. large-scale FTRA schema-drift fuzzing, Redis replay
payload variations):

| Procedure | Target | Tooling |
|---|---|---|
| LLM-plan schema fuzzing | Generate malformed/edge-case `ExecutionPlan` JSON payloads to stress-test `_parse_plan()` hardening (§2.C) | Property-based generation (e.g. `hypothesis`) targeting `ExecutionPlan`/`PlanStep` Pydantic schemas, including tokenizer-artifact injection |
| Redis replay payload variants | Generate KMS-signed-but-stale balance payloads with varying sequence-number/timestamp combinations for §4.2 replay defense testing | Deterministic fixture generator, not live KMS signing (use test KMS key) |
| Concurrent-agent trade sequences | Generate interleaving schedules for `proof/distributed_cbf_model.py`'s BFS enumeration (§2.F) | Exhaustive enumeration is already the model's design — no external fuzzing tool needed here, this is intentional |
| Adversarial prompt corpus expansion | See §6.1 | `garak`, `PyRIT` |

### 6.4 Baseline Measurement Collection Process

Addresses the **Ungoverned Baseline Measurement** gap named in the task
context: the harness mode already exists in
[`scripts/measure_paper_metrics.py`](../scripts/measure_paper_metrics.py)
(`measure_ungoverned_baseline()`, gated behind
`MEASURE_UNGOVERNED_BASELINE=true`), but **results have not yet been
collected**.

**Collection procedure:**

```bash
# Requires UNGOVERNED_ENDPOINT pointing at a raw (non-CAGE-governed) LLM
# endpoint for the A3/§6.6 disclosure comparison.
export MEASURE_UNGOVERNED_BASELINE=true
export UNGOVERNED_ENDPOINT="http://localhost:8081/v1/chat/completions"
export UNGOVERNED_MODEL="default"
uv run python scripts/measure_paper_metrics.py
```

| Test case | Scenario | Assertion |
|---|---|---|
| `test_measure_ungoverned_baseline_runs_without_error` | `MEASURE_UNGOVERNED_BASELINE=true` against a live/mock ungoverned endpoint | Function completes, returns the `ungoverned_deflection_rate_pct`/`ungoverned_fpr_pct` dict shape |
| `test_ungoverned_baseline_judge_llm_retry_on_empty_response` | Judge LLM returns empty body (transient timeout) | Retries once per the existing `[ungoverned] judge LLM returned empty body` retry logic; excludes from denominator if still empty (`JUDGE_UNAVAILABLE`) |
| `test_ungoverned_baseline_confidence_intervals_computed` | Successful run | CI bounds (`ungoverned_deflection_ci_low_pct`/`_ci_high_pct`) present and well-formed for both overall and per-category results |
| `test_governed_vs_ungoverned_comparison_table_generated` | Both governed and baseline results available | Comparison table (or its replacement, since `_REMOVED_fmt_baseline_comparison_table` is marked removed — confirm current replacement mechanism) renders correctly for §6.6 paper disclosure |
| `test_baseline_results_persisted_with_provenance` | Successful collection run | Results written to `docs/paper/measurements/<date>-<sha>/` following the existing `PROVENANCE.md` template, closing the "not yet collected" gap |

**Existing test coverage to extend:** [`tests/test_measure_paper_metrics_ci.py`](../tests/test_measure_paper_metrics_ci.py).

**Commands:**
```bash
uv run pytest tests/test_measure_paper_metrics_ci.py -v
uv run pytest tests/red_team/test_corpus_partition_integrity.py -v
MEASURE_UNGOVERNED_BASELINE=true UNGOVERNED_ENDPOINT="http://localhost:8081/v1/chat/completions" \
  uv run python scripts/measure_paper_metrics.py
```

---

## 7. Continuous Integration Integration

### 7.1 CI Pipeline Test Stage Configuration

New test files/suites introduced by this framework slot into the existing
[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) job structure
without requiring a new top-level workflow. Mapping:

| New test suite | Target CI job | Marker(s) required |
|---|---|---|
| `test_classify_violation.py`, extended `test_symbolic_governor.py` | `pytest-logic` (3-region matrix) | `local` or `unit` |
| `test_evidence_chain_blocking_gate.py` | `pytest-logic` | `local` |
| `test_ftra_boundary_check.py`, extended `test_ftra_package.py` | `pytest-logic` | `local` |
| `test_redis_fencing.py`, `test_redis_failover_chaos.py` (mocked variant) | `pytest-logic` | `local` |
| `test_redis_failover_chaos.py` (live-topology variant), `test_reconciliation_activation_checklist.py` | new `integration`-gated job, mirroring `integration-smoke` | `integration` |
| `test_distributed_cbf_proof.py` | **new** `distributed-cbf-proof` job (mirrors `no-direct-bind-proof`) | `local` |
| `test_formal_model_conformance.py` | `integration-smoke` (live-trace variant) or manual dev-GKE run | `integration` |
| `test_trust_boundary_bypass.py`, `test_redis_replay_defense.py` | `pytest-logic` + `ai600-unit-tests` (security-relevant) | `local` / `red_team` where applicable |
| `tests/red_team/test_corpus_partition_integrity.py` | `ai600-unit-tests` | `red_team` |
| Live GKE SLA benchmark (§3.2) | Manual/scheduled run via `port_forward_dev.sh`, not a blocking PR gate | `integration` |
| Load test (§3.3) | `locust-load-test` (currently `if: false`, nightly-schedule-gated) | `load` |

**New CI job: `distributed-cbf-proof`** (add to `ci.yml` alongside the
existing `no-direct-bind-proof` job, per §2.9.1 of the Implementation
Specs):

```yaml
distributed-cbf-proof:
  name: "Distributed CBF Model Proof"
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@<pinned-sha>
      with:
        persist-credentials: false
    - uses: actions/setup-python@<pinned-sha>
      with:
        python-version: "3.11"
    - name: Run exhaustive distributed CBF enumeration
      run: python proof/distributed_cbf_model.py --agents 3
    - name: Install pytest
      run: pip install pytest pytest-timeout pytest-asyncio
    - name: Run pinned distributed-model state-count regression
      run: python -m pytest tests/test_distributed_cbf_proof.py -m local -v
```

### 7.2 Test Parallelization Strategy

The existing `pytest-logic` job already uses `-n auto --dist=loadfile` on a
4-core runner (per [`ci.yml:87-90`](../.github/workflows/ci.yml:87)). New
test files should:

- Follow the existing `--dist=loadfile` convention (all tests in one file
  run on the same worker) to avoid cross-file fixture contention, matching
  the pattern already required for `tests/test_no_direct_bind_proof.py`'s
  autouse Redis-cleanup fixture interaction.
- Chaos/failover tests (`test_redis_failover_chaos.py`,
  `test_cbf_chaos.py`) should remain in `-m local` (mocked) for the
  parallel PR-gate run, with the live-topology variant isolated to a
  separate, non-parallel `integration` job to avoid flaky cross-worker
  interference with a shared live Redis instance.
- Live-GKE latency benchmarking (§3.2) and load testing (§3.3) are
  explicitly **not** parallelized — both require exclusive access to the
  target environment to produce valid measurements.

### 7.3 Failure Notification and Escalation

Reuses the existing escalation framework from
[`plans/CAGE_RISK_MATRIX.md`](CAGE_RISK_MATRIX.md) §6.4 (Communication
Plan for Failures) and §7.3 (Escalation Thresholds). New test-specific
triggers:

| Test failure | Notification | Escalation |
|---|---|---|
| `no-direct-bind-proof` or `distributed-cbf-proof` job fails on `main` | Formal verification owner (`proof/` module) paged same-day | Escalate to Gateway governance engineering if the failure traces to an un-updated `EXPECTED_*` constant after a tier-count change (§6.4 blast-radius trigger) |
| `test_trust_boundary_bypass.py` regression (bypass becomes possible when it shouldn't) | Security on-call, treat as critical (matches R-02/R-03 severity in Risk Matrix) | Immediate — this is a safety-invariant regression, not a flaky test |
| `test_redis_replay_defense.py` regression | Security on-call, treat as critical (matches R-04 severity) | Immediate |
| `lula-ai600-validation` or new Lula assertion failure | Compliance/OSCAL documentation owner | Same business day; block release if a universal (ISO 42001) gate fails, regional-only if a US_FED/EU_ECB/APAC_MAS-specific assertion fails |
| `integration-smoke` failure (live GKE) | Platform/SRE on-call | Same business day; does not block merge if the failure is infrastructure-availability-related (fork PRs already skip this job per `ci.yml:401-407`) |
| Coverage regression below component-specific target (§1.3) | PR author + reviewer | Blocks merge — coverage gate is enforced via `--cov-fail-under` |

### 7.4 Test Result Artifact Storage

| Artifact | Storage | Retention |
|---|---|---|
| SBOM (`sbom.json`) | GitHub Actions artifact (existing, `ci.yml:391-396`) | 90 days |
| Locust load-test report | GitHub Actions artifact (existing, `ci.yml:517-523`) | 30 days |
| Live-GKE latency benchmark provenance | `docs/paper/measurements/<date>-<sha>/PROVENANCE.md` (committed to repo, per §3.2) | Permanent (version-controlled) |
| Formal-model proof output | CI job logs (`no-direct-bind-proof`, `distributed-cbf-proof`) | GitHub Actions default retention; state-count regressions are additionally pinned in `tests/test_no_direct_bind_proof.py`/`tests/test_distributed_cbf_proof.py` source |
| Coverage reports | `--cov-report=term-missing` (stdout, existing) | Consider adding `--cov-report=xml` + artifact upload for trend tracking across the remediation program (new recommendation) |
| Adversarial corpus partition metadata | Committed to `tests/red_team/adversarial_dataset.json` | Permanent (version-controlled), tracked for quarterly growth review (§6.1) |

**Commands:**
```bash
# Full local reproduction of the PR-gate CI matrix (single region example)
CAGE_DEPLOYMENT_REGION=US_FED CAGE_ENV=test uv run pytest tests/ -m "local or unit" \
  -n auto --dist=loadfile -v --cov-branch --cov=src --cov-fail-under=75
uv run bandit -r src/ -c pyproject.toml -ll
uv run ruff check . && uv run ruff format --check . && uv run mypy src/
```

---

## 8. Acceptance Criteria Matrix

Maps each success criterion from the task context to concrete test cases
defined in §2–§6 above, with an explicit pass condition.

| Success Criterion | Test Cases | Pass Condition |
|---|---|---|
| **POAM-2026-038 Closure** (task framing: "POAM-023" — see identifier note in front matter) — reconciliation K8s manifest authored, daemon wired into serving path, provider-name mismatch fixed | §2.E: `test_reconciliation_worker_secret_has_gcs_bucket_key`, `test_reconciliation_provider_env_matches_gcs`, `test_cronjob_last_run_succeeded`, `test_cronjob_no_create_container_config_error`, `test_reconciliation_verified_balance_populated_in_redis`; existing `tests/test_reconciliation_worker.py` suite | All listed tests green; CronJob completes ≥ 3 consecutive scheduled runs without `CreateContainerConfigError`; `docs/POAM.md` POAM-2026-038 entry updated with commit SHA + KMS-signature verification timestamp per §5.3 closure procedure |
| **FTRA "True Minimum-Impact" Status** — (1) pluggable extractor abstraction | §2.C: `test_create_ftra_node_default_config_matches_legacy_behavior`, `test_create_ftra_node_custom_plan_extractor`, `test_create_ftra_node_custom_confidence_extractor` | `FtraNodeConfig` unit tests green; `graph.py`'s existing no-arg call produces identical output pre/post change |
| ...(2) documented/enforced plan-and-execute precondition | §2.C: `test_reactive_agent_without_plan_fails_closed_with_clear_diagnostic`, `test_n_consecutive_empty_steps_triggers_compatibility_warning`; §4.1 mitigation for R-01 | Precondition documented in FTRA docstrings/architecture docs; self-check telemetry test green once implemented |
| ...(3) Controller-boundary bypass closure | §2.C + §4.1: `test_boundary_check_classifies_direct_http_bypass`, `test_boundary_check_shares_classification_with_in_graph_node`, `test_direct_http_bypass_of_ftra_node_blocked_when_boundary_enabled` | Direct HTTP/ext_authz submission of a plan-shaped payload is classified identically to the in-graph path when `CAGE_FTRA_BOUNDARY_ENABLED=true` |
| ...(4) formal verification of reachability analysis | §2.F: `test_live_run_checks_trace_matches_a_reachable_model_state`, distributed model tests (`test_safety_holds_for_2_3_4_concurrent_agents`, `test_ungated_variant_produces_reachable_violation`) | `proof/distributed_cbf_model.py` BFS enumeration passes; negative control produces a reachable violation, confirming the model is load-bearing |
| ...(5) hardened `_parse_plan()` against schema drift | §2.C: `test_parse_plan_schema_valid_incomplete_llm_output_not_blocked`, `test_parse_plan_tokenizer_artifacts_sanitized`, `test_parse_plan_malformed_json_returns_json_decode_error`, `test_parse_plan_empty_steps_returns_empty_steps_class` | BUG-FTRA-SCHEMA-001 and BUG-FTRA-JSON-001 regression tests green; `ParseResult.failure_class` correctly distinguishes all three failure modes |
| **200ms SLA Validation** — end-to-end live latency benchmark against a real (non-mocked) GKE cluster | §3.2: `test_live_gke_end_to_end_latency_p50_within_budget`, `test_live_gke_end_to_end_latency_p95_p99_recorded` | `scripts/measure_paper_metrics.py --unmocked` P50 < 200ms against live Redis/OPA/consensus RPC; provenance entry recorded in `docs/paper/measurements/` with gates E1–E6 passing |
| **CBF Invariance Theorem Applicability** — scoped to single-trade-per-window execution model | §2.F: `test_safety_holds_for_2_3_4_concurrent_agents`, `test_stale_epoch_commit_rejected_in_all_reachable_states`; documentation scope note in `proof/model.py`/paper | Distributed model explicitly validates (or explicitly scopes out) multi-agent concurrency; any claim beyond single-trade-per-window is either proven by the distributed model or explicitly caveated |
| **Reviewer Invariant Closure — Composed Authority** | §2.A: `test_defer_park_writes_deferqueue_token`, `test_boundary_check_shares_classification_with_in_graph_node`; §4.1 trust-boundary tests | No single component can independently grant authority without the composed DEFER/FTRA-boundary/CBF/OPA chain being satisfied — validated via the boundary-check + classification-sharing tests |
| **Reviewer Invariant Closure — Mediation Coverage** | §2.C + §4.1: `test_boundary_check_classifies_direct_http_bypass`, `test_bypass_reproduces_pre_fix_gap_as_documented_baseline` | Every ingress path to `validate_action()` (ext_authz, REST, future direct import) is mediated by the same classification logic once `CAGE_FTRA_BOUNDARY_ENABLED=true` |
| **Reviewer Invariant Closure — Bounded Composite Authority** | §2.A: `test_narrow_verdict_returns_200_with_narrowed_params`, `test_narrow_disabled_falls_back_to_deny`; §2.D fencing tests | `NARROW` never grants more authority than the CBF barrier certificate computes as admissible; fencing prevents composite authority from exceeding the bounded shared balance under concurrency |
| **Reviewer Invariant Closure — Evidence Sufficiency** | §2.B: `test_blocking_true_gates_seal_issuance_on_commit`, `test_blocking_true_denies_on_sink_unavailable`; §5.2 OSCAL tests | When `EVIDENCE_CHAIN_BLOCKING=true`, no seal is issued without durable evidence commit; OSCAL AU-12 component correctly distinguishes decision-time vs. evidence-of-execution guarantees (closes R-06) |
| **R-04 Redis Replay Vulnerability closure** — monotonic sequence-number replay defense (§2.10 of Implementation Specs) | §4.2: `test_monotonic_sequence_number_rejects_non_advancing_replay`, `test_sequence_zero_default_treated_as_never_advancing`, `test_replay_defense_independent_of_redis_replication_topology`, `test_replay_detected_triggers_fail_closed_fiscal_deny`, chaos scenarios in `TestReplayChaosScenario` | With `CAGE_RECONCILIATION_REPLAY_DEFENSE=true`, a non-advancing/replayed `sequence` is rejected and the CBF fails closed to the self-reported balance; replay defense is effective on single-node Redis independent of §2.6 fencing; default-off behavior is byte-for-byte unchanged |
| **Statistical/Generalizability Risk mitigation** — corpus beyond 26 payloads, dev/eval separation | §6.1, §6.2: `test_dev_eval_partitions_are_disjoint`, `test_corpus_size_growth_tracked` | Corpus expanded (target ≥ 78 payloads initial milestone) with disjoint dev/eval metadata; no payload used for both tuning and reported metrics |
| **Ungoverned Baseline Measurement collection** | §6.4: `test_measure_ungoverned_baseline_runs_without_error`, `test_baseline_results_persisted_with_provenance` | `MEASURE_UNGOVERNED_BASELINE=true` run completes and produces a provenance-recorded result set for the §6.6 paper disclosure |
| **Causal Model Calibration** — baseline intercept fitted from historical data (not fixed 0.5) | Not yet covered by an existing test file — new `tests/test_causal_baseline_calibration.py` required once the offline calibration job (R-09 mitigation) is implemented | Offline calibration job produces a fitted baseline; drift-detection test compares fitted vs. fixed 0.5 and alerts when drift exceeds 0.05 (warning)/0.10 (critical) per Risk Matrix §7.1 KRI |

## 9. Test Environment Specifications

### 9.1 Local Development Environment

| Aspect | Specification |
|---|---|
| Package management | `uv sync --all-groups --all-extras` (per `AGENTS.md` — never bare `pip`) |
| Test invocation | `uv run pytest tests/ -m "local or unit"` — no external services required |
| Python version | Per `pyproject.toml`'s `python-version-file` pin |
| Coverage | `--cov=src --cov-config=.coveragerc --cov-report=term-missing --cov-fail-under=80` (full local run); CI PR-gate uses 75% |
| Redis/OPA/vLLM | Not required for `-m "local or unit"` — all governance-logic tests mock these dependencies |
| Use case | TDD, fast iteration on §2.A–§2.C, §4 unit-level tests |

### 9.2 CI Environment (Mocked Dependencies)

| Aspect | Specification |
|---|---|
| Runner | `ubuntu-latest-4-cores` (pytest-logic, ai600-unit-tests) / `ubuntu-latest` (other jobs) |
| Region matrix | `US_FED`, `EU_ECB`, `APAC_MAS` via `CAGE_DEPLOYMENT_REGION` env var (fail-fast: false) |
| Dependency versions | Dummy/placeholder env vars only — `OPENAI_API_KEY=sk-dummy`, `VLLM_API_KEY=dummy`, `LANGFUSE_PUBLIC_KEY=pk-dummy`, etc. (per [`ci.yml:118-131`](../.github/workflows/ci.yml:118)) |
| Parallelization | `-n auto --dist=loadfile` |
| Gates enforced | `--cov-fail-under=75`, Bandit SAST (medium+ severity), Ruff lint/format, mypy, license headers, STPA/NeMo freshness, NoDirectBind proof, Langfuse posture dry-run, Lula manifest structure |
| Use case | Every push/PR — the authoritative daily regression gate per `AGENTS.md`'s Test Execution guidance |

### 9.3 Dev GKE Cluster (Live Integration)

| Aspect | Specification |
|---|---|
| Cluster | `governance-cluster-2` (us-central1-a) |
| Access | `kubectl` context configured; `scripts/port_forward_dev.sh` establishes auto-reconnecting tunnels (OPA 8181, Langfuse 3001/3000, vLLM fast 8001/18081, vLLM reasoning 8000/18082, Gateway 8080, backend 18080, Redis 6379, Compliance Bridge 3002) |
| Env loading | `.env` at repo root, auto-loaded by `port_forward_dev.sh` and `tests/conftest.py` |
| Test invocation | `uv run pytest tests/ --run-integration -v --tb=short` (full suite) or `-m integration` (targeted subset) |
| Known baseline | 2553 passed, 51 skipped, 1 known test-isolation flake (per `AGENTS.md`, last recorded 2026-08-10) |
| Use case | §2.D live-topology chaos tests, §2.E reconciliation activation checklist, §2.F live-trace conformance, §3.2 SLA benchmark, §3.3 load testing, §5.4 regional posture live checks |

### 9.4 Prod GKE Cluster (Smoke Tests Only)

| Aspect | Specification |
|---|---|
| Access | Production credentials, restricted network access — no broad `--run-integration` sweep |
| Test invocation | `uv run pytest tests/ -m integration --timeout=30 -x -q --ignore=tests/load --ignore=tests/red_team` (mirrors CI's `integration-smoke` job shape) |
| Scope | Smoke-level only: health checks, POAM-2026-038 closure evidence gathering (§2.E), periodic live-GKE SLA re-benchmarking (§3.2) triggered by tier-count changes |
| Restrictions | No load testing (§3.3), no chaos/failover drills (§2.D) against production — those are dev-GKE-only per the safety limits already encoded in `scripts/run_gke_load_test.sh` (`MAX_USERS`, `SPAWN_RATE`, `RUN_TIME` caps) |
| Change trigger | Re-run smoke suite post-deploy for any change to `src/gateway/governance/` or `src/compliance_bridge/` (shared cross-region modules) |
