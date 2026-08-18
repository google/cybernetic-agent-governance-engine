# Audit Remediation — Implementation Plan

**Scope:** Close the implementation gaps identified in the technical audit (Category B — code) and assess Category C (formal verification) for near-term feasibility. Category A (paper/doc) is already drafted per [`docs/paper/REVISION_TRACKER.md`](../docs/paper/REVISION_TRACKER.md) and is cross-referenced here only where it constrains code scope.

**Legend:** Priority `P0` = security/correctness critical · `P1` = important · `P2` = enhancement. Effort: `XS` (<1 file, isolated) · `S` (1 file, contained) · `M` (multi-file, needs tests) · `L` (cross-cutting, needs design review) · `XL` (research-grade / multi-sprint).

---

## Chunk 0 — Cross-cutting notes before starting

- All five Category B items touch [`src/gateway/governance/`](../src/gateway/governance/) or [`src/compliance_bridge/`](../src/compliance_bridge/), which are **shared modules** per [`AGENTS.md`](../AGENTS.md#architecture--design-standards). Every PR below must state US_FED / EU_ECB / APAC_MAS impact and `CAGE_DEPLOYMENT_REGION` guard placement in its description.
- None of the five Category B items requires a new Terraform resource or GKE manifest change — all are pure application-code + config changes deployable via the existing Cloud Build pipelines.
- Recommended branch prefix: `fix/audit-<short-name>` (e.g. `fix/audit-pause-handler`).

---

## Chunk 1 — Item B1: PAUSE Handler Gap in `validate_action()`

**File:** [`symbolic_governor.py:2226-2364`](../src/gateway/governance/symbolic_governor.py:2226)

### 1.1 Problem statement
`_classify_violation()` ([`symbolic_governor.py:496-547`](../src/gateway/governance/symbolic_governor.py:496)) can return `GovernanceDecision.PAUSE`, and the `govern()` method (a sibling entry point, [`symbolic_governor.py:1680-1793`](../src/gateway/governance/symbolic_governor.py:1680)) is not implicated — but `validate_action()` only has explicit branches for `REQUIRE_APPROVAL` ([:2227](../src/gateway/governance/symbolic_governor.py:2227)), `DEFER` ([:2251](../src/gateway/governance/symbolic_governor.py:2251)), and `NARROW` ([:2299](../src/gateway/governance/symbolic_governor.py:2299)). A `PAUSE` decision falls through to the generic DENY block at [:2364](../src/gateway/governance/symbolic_governor.py:2364), raising `GovernanceError` with a synthetic `RefusalReceipt` instead of returning the structured PAUSE response (`pause_token`, `estimated_wait_seconds`, etc.) that [`agent_gateway_adapter.py:836-980`](../src/gateway/server/agent_gateway_adapter.py:836) and [`pause_primitive.py`](../src/gateway/governance/pause_primitive.py) already implement.

### 1.2 Why it matters
Any caller that reaches governance via `validate_action()` (the HTTP `/v1/governance/validate-action` path used by the GFA and any downstream actuator) can never receive a real PAUSE verdict — even with `CAGE_PAUSE_ENABLED=true`, PAUSE candidates are misrepresented as hard DENY with a fabricated `violated_tier="SYMBOLIC_GOVERNOR"` refusal proof. This is a **correctness bug**, not just a missing feature: it silently defeats the CAGE_PAUSE_ENABLED contract for one of the two governance entry points.

### 1.3 Fix design
Add an explicit `if decision == GovernanceDecision.PAUSE:` branch between the NARROW block ([:2362](../src/gateway/governance/symbolic_governor.py:2362)) and the DENY fallback ([:2364](../src/gateway/governance/symbolic_governor.py:2364)), mirroring the DEFER branch's shape:
- Reuse `classification_meta["pause_reason"]` and `classification_meta["estimated_wait_seconds"]` (already populated by `_classify_violation()` at [:533-547](../src/gateway/governance/symbolic_governor.py:533)).
- Call into `PauseManager.pause_request()` (same call as `agent_gateway_adapter.py:886`) to persist state and obtain a `pause_token`, OR — preferred — **return the pause metadata without persisting**, and let the HTTP-layer adapter own persistence (avoids double-writing pause state if both `validate_action()` and `agent_gateway_adapter.py` independently call `PauseManager`). This requires checking whether `validate_action()` callers other than `agent_gateway_adapter.py` exist.
- Set OTel span attributes (`cage.verdict`, `cage.governance.paused`) consistent with the other branches.
- Respect `CAGE_PAUSE_ENABLED` fallback-to-DENY exactly as `_classify_violation()` already does at [:504-517](../src/gateway/governance/symbolic_governor.py:504) — this means in practice `validate_action()` should rarely see a raw `PAUSE` decision when the flag is off, but the branch must exist defensively since flags can change between classification and dispatch in future refactors.

### 1.4 Open design question (resolve before coding)
Does any caller invoke `validate_action()` directly (not via `agent_gateway_adapter.govern_tool_call()`)? If yes, the new branch must persist pause state itself (duplicate the `PauseManager` call from the adapter). If `validate_action()` is only ever reached through the adapter's HTTP path, prefer returning the pause metadata dict only and let the adapter persist — avoiding a state-persistence responsibility split. **Action:** grep all callers of `symbolic_governor.validate_action(` before implementation and document the answer in the PR description.

### 1.5 Priority / Effort
**P0** (correctness bug — governance decision silently misrepresented) / **S** (single method, well-scoped, existing pattern to mirror).

### 1.6 Dependencies
None — self-contained. Should land **before** B2 (HMAC binding) since both touch `symbolic_governor.py`'s seal-issuance code paths and rebasing is cheaper in this order.

### 1.7 Breaking change analysis
**None for external API.** Response shape for PAUSE via `validate_action()` will change from `{verdict: DENY, violations: [...]}` (current buggy behavior) to `{verdict: PAUSE, pause_token, pause_reason, estimated_wait_seconds, ...}` — this is a bug fix, not a contract break, since no documented/tested caller currently depends on the buggy DENY-fallback shape. Confirm via test suite (1.8) that no existing test asserts the old (wrong) behavior; if one does, it is asserting the bug and must be updated, not preserved.

### 1.8 Test requirements
- New unit test in `tests/test_symbolic_governor.py` (extend `TestSymbolicGovernorPause`, [`tests/test_symbolic_governor.py:480`](../tests/test_symbolic_governor.py:480)): call `validate_action()` directly (not the adapter) with a rate-limit violation and `CAGE_PAUSE_ENABLED=true`; assert `result["verdict"] == GovernanceDecision.PAUSE` and the response contains `pause_token`/`pause_reason`.
- Regression test: same scenario with `CAGE_PAUSE_ENABLED=false`; assert fallback to DENY (existing `_classify_violation` behavior, verify `validate_action()` propagates it as an actual DENY response, not a mislabeled one).
- Integration test (if time permits): full HTTP round-trip through `governance_middleware.py`'s `/validate-action` endpoint asserting HTTP 503 + pause_token, extending the pattern in `tests/test_defer_e2e_flow.py::TestPauseE2EFlow` ([:582](../tests/test_defer_e2e_flow.py:582)).

---

## Chunk 2 — Item B2: HMAC Seal Not Bound to Record Hash

**File:** [`routing_seal.py`](../src/gateway/governance/routing_seal.py)

### 2.1 Problem statement
`generate_seal()` ([:181-203](../src/gateway/governance/routing_seal.py:181)) computes `HMAC(expire_hex || action_slug || canonical_payload)`. It does **not** incorporate the `record_hash` produced by the evidence chain (`_link_hash()` in [`evidence_stream.py:392-419`](../src/compliance_bridge/evidence_stream.py:392), or `context_accumulator.py`'s `_link_hash()`). `generate_seal_with_evidence()` ([:206-327](../src/gateway/governance/routing_seal.py:206)) commits evidence and *then* calls the unmodified `generate_seal()` — the seal and the evidence record are correlated only by being issued in temporal proximity within the same function call, not cryptographically bound.

### 2.2 Why it matters
An attacker (or a buggy code path) that can produce a *valid* seal for action `A` with params `P` cannot be proven, from the seal alone, to correspond to the *specific* evidence record that was committed for that decision. This weakens the non-repudiation chain described in the paper's §5.5 (already scoped down to "integrity vs. mediation" per Category A) — the seal proves the gateway approved `(action, params)` at some point, but does not cryptographically prove which durable evidence entry authorized it. This is primarily an **evidentiary integrity gap**, not an active exploit (the seal is still tamper-evident against forgery), but it closes a real gap between the "evidence-of-execution" claim and the seal's actual cryptographic contract.

### 2.3 Fix design
1. Extend `generate_seal()`'s signature to accept an optional `record_hash: str | None = None` parameter.
2. When present, fold `record_hash` into the HMAC message: `message = f"{expire_hex}.{action_slug}.{record_hash_hex}.".encode() + payload`. Use a placeholder (`"-"` or empty string) when `record_hash` is absent, to keep the message format stable and parseable.
3. Extend the seal's on-wire format from `<expire_hex>.<action_slug>.<hmac_hex>` (3 parts) to `<expire_hex>.<action_slug>.<record_hash_prefix>.<hmac_hex>` (4 parts) — **or**, to avoid a wire-format break, keep the 3-part format and fold `record_hash` into the HMAC input only (verifier must be told the `record_hash` out-of-band, e.g. via the evidence lookup at verification time). **Recommendation: fold into HMAC input only, do not change wire format** — this is lower blast radius (see 2.5) and the verifier side (`verify_seal()`) already receives `action`/`params`; it can be extended to accept an optional `record_hash` argument that must match what was used at issuance.
4. Update `generate_seal_with_evidence()` to pass the `commit_result.hash` (already computed at [:290](../src/gateway/governance/routing_seal.py:290)) into `generate_seal()` when evidence commit succeeds (blocking mode) or is best-effort available (fire-and-forget mode, if `sink.ingest()` returns a hash synchronously — check current return type).
5. Update `verify_seal()` and `verify_and_consume_seal()` to accept an optional `expected_record_hash` parameter; when the caller supplies it, recompute the HMAC with it and reject on mismatch.

### 2.4 Backward compatibility strategy
Since `record_hash` is optional (defaults to a stable placeholder), **seals issued without evidence binding remain verifiable** as before — this preserves compatibility with `EVIDENCE_STREAM_ENABLED=false` deployments and with the mirrored verifier copy in [`src/governed_financial_advisor/utils/routing_seal.py`](../src/governed_financial_advisor/utils/routing_seal.py), which **must be updated in lockstep** (see the file's own "SYNC NOTE", [:45-47](../src/governed_financial_advisor/utils/routing_seal.py:45)).

### 2.5 Priority / Effort
**P1** (strengthens evidentiary integrity but does not fix an active vulnerability; current seal is still cryptographically sound against forgery/replay). / **M** (touches 2 files that must stay in sync — `routing_seal.py` and its GFA-side mirror — plus all call sites that pass a seal through `verify_and_consume_seal()`).

### 2.6 Dependencies
- Should land **after** B1 (avoid rebase conflicts in `symbolic_governor.py`'s seal-issuance call sites at [:2324](../src/gateway/governance/symbolic_governor.py:2324), [:2408](../src/gateway/governance/symbolic_governor.py:2408)).
- Must be coordinated with any change to `evidence_stream.py`'s public `CommitResult` shape (none currently planned).

### 2.7 Breaking change analysis
**Wire-format change: NONE** (recommended design keeps the 3-part seal format). **Behavioral change:** callers that want the stronger binding must be updated to pass `record_hash` through explicitly — this is additive, not breaking, for existing callers that don't pass it. **Cross-service risk:** the GFA-side mirror (`governed_financial_advisor/utils/routing_seal.py`) must be updated in the *same PR* — a partial rollout (gateway updated, GFA not) would cause `verify_seal()` to disagree on the message construction whenever a caller starts populating `record_hash`, since the message-construction logic is duplicated, not shared. **Recommendation:** ship both files' changes as one PR; add a CI check (or extend the existing "SYNC NOTE" convention) asserting the two files' HMAC message-construction logic is textually identical modulo import paths.

### 2.8 Test requirements
- Unit tests in `tests/test_routing_seal.py` and `tests/test_routing_seal_security.py`: seal generated with `record_hash="abc123"` fails verification when `verify_seal()` is called with a different/absent `record_hash`.
- Backward-compat test: seal generated without `record_hash` (legacy call signature) still verifies successfully with no `record_hash` argument at verification time.
- Cross-file parity test: assert `src/gateway/governance/routing_seal.py` and `src/governed_financial_advisor/utils/routing_seal.py` produce byte-identical HMAC messages for the same inputs (can be a new `tests/test_routing_seal_mirror_parity.py`).
- Integration: extend `generate_seal_with_evidence()` tests in `tests/test_evidence_chain_blocking.py` to assert the issued seal's HMAC covers the evidence commit's hash when `EVIDENCE_CHAIN_BLOCKING=true`.

---

## Chunk 3 — Item B3: Fence Epoch Cold Start

**File:** [`cbf.py:211`](../src/gateway/governance/cbf.py:211)

### 3.1 Problem statement
`ControlBarrierFunction.__init__()` sets `self._last_seen_epoch: int = 0` ([:211](../src/gateway/governance/cbf.py:211)). `_check_fence_epoch()` ([:275-324](../src/gateway/governance/cbf.py:275)) rejects reads when `current_epoch < self._last_seen_epoch` — but on a freshly spawned instance (new pod, new Cloud Run revision, restart), `_last_seen_epoch=0` means the *first* read after startup can never trigger a regression rejection, no matter how stale the Redis replica actually is, because any `current_epoch >= 0` passes.

### 3.2 Why it matters
This is exactly the gap the R-05 fence-epoch mechanism was built to close: a newly started instance that happens to connect to a stale replica during/after a failover will accept the stale epoch as valid on its first read (silently adopting it as the new `_last_seen_epoch` baseline), reopening the double-spend window the mechanism is meant to close, for at least one request per fresh instance. In an environment with frequent instance churn (Cloud Run scale-to-zero, GKE pod restarts, rolling deploys), this significantly weakens the practical protection.

### 3.3 Fix design
1. In `setup()` ([:213-225](../src/gateway/governance/cbf.py:213)) — already called at instance bootstrap — read the *current* fence epoch from Redis via `_get_fence_epoch()` ([:261-273](../src/gateway/governance/cbf.py:261)) and set `self._last_seen_epoch` to that value (not 0), **provided** the read Redis node can be independently confirmed to be the primary (or a synchronously-replicated replica). This is the minimum viable fix and closes the "epoch=0 always passes" hole, but does not fully solve "which replica did I read from" — see 3.4.
2. Add an explicit external anchor check: before trusting the epoch read during `setup()`, optionally issue a `Redis INFO replication` (or `ROLE`) command to confirm connection to a primary, and log/alert (not necessarily fail-closed, to avoid over-blocking legitimate primary connections) if connected to a replica.
3. Update `_check_fence_epoch()`'s docstring and the R-05 module comment block ([:73-86](../src/gateway/governance/cbf.py:73)) to state the corrected cold-start contract: "epoch is anchored at `setup()` time from the currently connected Redis node; if `setup()` is called against a stale replica, the anchor itself is stale — operators must ensure `setup()` runs against the primary (or a synchronously-WAIT-confirmed replica)."
4. Confirm `setup()` is actually invoked on every instance start before the CBF is used for a real check — trace the call site. If `setup()` is optional/best-effort in some deployment path, that is itself a second gap to flag in the same PR.

### 3.4 Residual risk (document, do not silently claim solved)
Anchoring at `setup()` time only shifts the vulnerability window from "every read forever" to "the single `setup()` read" — if that read itself hits a stale replica, the instance's entire epoch tracking is built on a bad baseline for its whole lifetime. A fully robust fix requires either (a) `setup()` always reading from a `WAIT`-confirmed primary connection, or (b) an external epoch anchor service (e.g. reading the epoch from the reconciliation worker's KMS-signed ledger, which already exists per POAM-2026-038/POAM-2026-031). Recommend implementing (a) now (cheap, closes the "always-zero" bug) and filing a follow-up POAM for (b) rather than blocking this fix on a bigger redesign.

### 3.5 Priority / Effort
**P0** (weakens a documented double-spend defense; directly relevant to a financial safety invariant). / **S** (bounded to `setup()` + `_check_fence_epoch()` docstring; the "confirm primary" check is optional stretch scope — see 3.6).

### 3.6 Scope split (recommended)
- **PR 3a (P0, S):** Fix `setup()` to seed `_last_seen_epoch` from Redis instead of leaving it at 0. This alone closes the "always passes on first read" bug.
- **PR 3b (P1, S):** Add the primary-vs-replica connection check (`ROLE`/`INFO replication`) with logging/telemetry (Prometheus counter for "setup connected to replica"). Non-blocking to ship separately since it's a detection/observability improvement, not a correctness fix.

### 3.7 Dependencies
None. Independent of B1/B2/B4/B5.

### 3.8 Breaking change analysis
**None.** Purely internal state-initialization change; `_last_seen_epoch` is a private attribute with no external contract. `setup()`'s signature and calling convention are unchanged.

### 3.9 Test requirements
- Extend `tests/test_fence_epoch.py`: new test asserting `setup()` sets `_last_seen_epoch` to the value currently in Redis (mock Redis returning e.g. `"7"`, assert `cbf._last_seen_epoch == 7` after `await cbf.setup()`).
- Regression test: a freshly constructed `ControlBarrierFunction()` (no `setup()` called yet) still defaults to 0 — confirm this is documented as "unsafe to use before `setup()`" and add an assertion/log warning if `_check_fence_epoch()` is invoked pre-`setup()`.
- Chaos test (extend `tests/test_cbf_chaos.py` or `tests/test_redis_failover_chaos.py`): simulate instance restart against a Redis replica reporting a regressed epoch; assert the new instance's `setup()`-seeded baseline causes the *next* read (not just eventually) to reject the regression.

---

## Chunk 4 — Item B4: Configuration Validation Enhancement

**File:** [`evidence_stream.py`](../src/compliance_bridge/evidence_stream.py)

### 4.1 Problem statement
`validate_evidence_stream_preconditions()` ([:334-369](../src/compliance_bridge/evidence_stream.py:334)) currently checks exactly one invalid combination: `EVIDENCE_CHAIN_BLOCKING=true` + `EVIDENCE_STREAM_ENABLED=false`. It does not check other plausible production misconfigurations, e.g.:
- `EVIDENCE_STREAM_ENABLED=true` but `EVIDENCE_STREAM_REDIS_URL`/`REDIS_URL` both empty (silent no-op ingestion).
- `EVIDENCE_STREAM_KMS_SIGN=true` but no KMS credentials/`GOVERNANCE_KMS_KEY` configured (would fail at first sign attempt, not at startup).
- Production environment (`CAGE_ENV` not in dev/test/ci) running with `EVIDENCE_STREAM_ENABLED=false` at all — currently silent, arguably should warn loudly given the compliance posture claims made in the paper/docs about evidentiary durability.

### 4.2 Why it matters
The existing check is a good pattern (fail-fast at startup) but only covers one of several known-bad configurations. A production deployment could pass the existing check while still having a broken or degraded evidence chain (e.g., blocking disabled, stream enabled, but pointed at an unreachable Redis URL) that would only surface as an operational incident later, not at boot.

### 4.3 Fix design
Extend `validate_evidence_stream_preconditions()` with additional checks, each raising `ConfigurationError` (hard-fail) or logging `logger.warning`/`logger.critical` (soft-fail) depending on severity, gated by the existing `_IS_PRODUCTION`-style pattern already used in `cbf.py` ([:57-60](../src/gateway/governance/cbf.py:57)) and `routing_seal.py` ([:139-162](../src/gateway/governance/routing_seal.py:139)):
1. **Hard-fail (raise `ConfigurationError`):** `EVIDENCE_STREAM_ENABLED=true` and both `EVIDENCE_STREAM_REDIS_URL` and `REDIS_URL` are empty.
2. **Hard-fail in production only:** `EVIDENCE_STREAM_KMS_SIGN=true` and no resolvable KMS key configuration (mirror the pattern in `kms_signer.py`'s `assert_kms_active_in_production()`, reuse or call it here rather than duplicating logic).
3. **Soft-fail (warn) in production:** `EVIDENCE_STREAM_ENABLED=false` while `CAGE_DEPLOYMENT_REGION` is a regulated region (`US_FED`/`EU_ECB`/`APAC_MAS`) — log a `logger.warning` (not `critical`, to avoid turning an operational choice into a hard startup failure) noting that evidentiary durability claims in the compliance posture may not hold.
4. Keep the function's existing behavior/signature (`-> None`, raises `ConfigurationError`) so call sites in [`hybrid_server.py:77-89`](../src/gateway/server/hybrid_server.py:77) and [`compliance_bridge/main.py:165-173`](../src/compliance_bridge/main.py:165) need no changes.

### 4.4 Priority / Effort
**P1** (defense-in-depth / operational hardening, not a currently-exploitable gap). / **S** (single function, additive checks, existing call sites unaffected).

### 4.5 Dependencies
None. Can land independently and in parallel with B1–B3.

### 4.6 Breaking change analysis
**None for the public function signature.** Risk: a production deployment that was previously passing the (weak) check might now hard-fail startup if it has `EVIDENCE_STREAM_ENABLED=true` with no Redis URL configured — this is **intentional** (fail-fast is the point) but must be called out prominently in the PR description and release notes, since it could break an existing misconfigured-but-"working" deployment on next rollout. Recommend a one-release "warn only" period for the new hard-fail checks (log `logger.critical` but don't raise) before flipping to `raise` in a follow-up PR, to give operators a chance to fix their config without an unplanned outage.

### 4.7 Test requirements
- Extend `tests/test_evidence_stream_preconditions.py`: one test per new check (empty Redis URL with stream enabled → raises; KMS sign enabled with no key in production → raises; stream disabled in a regulated region → warning logged, no raise).
- Confirm existing tests (`test_validation_passes_when_both_disabled`, etc.) still pass unmodified — the new checks must not regress the already-covered combinations.

---

## Chunk 5 — Item B5: Actuator Verification Coverage Audit

**Files:** multiple — see 5.2 for the confirmed call-site inventory.

### 5.1 Problem statement
The audit's premise ("assumption that all actuators call `verify_seal()` is unverified") needs to be checked against the actual call-site inventory, not just asserted. This chunk documents what was found and what remains to formalize.

### 5.2 Confirmed actuator call sites (as of this audit)
| Actuator | Seal check | Mechanism |
|---|---|---|
| [`mcp_tool_server.py::execute_trade_action()`](../src/gateway/server/mcp_tool_server.py:320) | ✅ Yes | `verify_and_consume_seal()` at [:383](../src/gateway/server/mcp_tool_server.py:383) |
| [`governed_financial_advisor/tools/api.py::execute_tool_endpoint()`](../src/governed_financial_advisor/tools/api.py:150) (`execute_trade` branch) | ✅ Yes | `verify_and_consume_seal()` at [:214](../src/governed_financial_advisor/tools/api.py:214) |
| [`mcp_tool_server.py::/tools/execute`](../src/gateway/server/mcp_tool_server.py:463) HTTP endpoint | ✅ Yes (different mechanism) | `enforce_routing_seal()` (HMAC-over-request-body, a *distinct* seal from the per-action routing seal — see 5.3) at [:479](../src/gateway/server/mcp_tool_server.py:479) |
| [`governed_financial_advisor/tools/trades.py::execute_trade()`](../src/governed_financial_advisor/tools/trades.py:46) | ⚠️ Indirect | Delegates via MCP `call_tool("execute_trade_action", ...)` — relies transitively on the `mcp_tool_server.py` check; **does not itself verify**, which is fine as long as the MCP transport cannot be bypassed, but this transitive trust needs to be explicitly documented/tested. |
| [`mcp_tool_server.py::trigger_safety_intervention()`](../src/gateway/server/mcp_tool_server.py:411) | ❌ No seal check | Not a financial actuator (sets a Redis kill-switch flag) — likely acceptable, but should be explicitly reviewed and either seal-gated or documented as an intentionally ungated emergency-stop primitive (fail-safe should probably be *easier* to trigger, not harder, so this may be correct as-is). |
| Other `@mcp.tool()` functions (`check_market_status`, `get_market_sentiment`, `verify_content_safety`) | ❌ No seal check | Read-only / non-mutating — likely fine, but not yet formally classified as "does not require a seal because it has no side effect." |

### 5.3 Distinct-mechanism confusion risk
There are **two different HMAC mechanisms** both called "routing seal" in this codebase:
1. Per-action seal from `generate_seal()`/`verify_seal()` in `routing_seal.py` — scoped to `(action, params)`, issued after `validate_action()`/`govern()` approval.
2. Request-body HMAC (`X-CAGE-Routing-Seal` header) enforced by `enforce_routing_seal()` in `governance_middleware.py` — scoped to the raw HTTP request body, a transport-level integrity check between trusted upstream orchestrators and the gateway.
These serve different trust boundaries (governance-decision binding vs. transport authenticity) but share a name and header/variable naming (`_SEAL_HEADER`, `x-cage-routing-seal`), which is a documentation/clarity risk more than a security one. **Recommend renaming or clearly cross-referencing in docstrings** which mechanism is which, as part of this audit closure (low-cost, high clarity value).

### 5.4 Fix design
1. **Inventory task (do first, no code change):** Produce an explicit table (as started in 5.2) of every function that performs a side-effecting external action (trade execution, safety intervention, any future actuator), and classify it as `SEAL_ENFORCED` / `TRANSITIVELY_ENFORCED` / `INTENTIONALLY_UNGATED` / `GAP`. Commit this table to `docs/architecture/` (e.g. `ACTUATOR_SEAL_COVERAGE.md`) so it becomes a living artifact reviewed on every new actuator addition.
2. **Test coverage:** For every `SEAL_ENFORCED` and `TRANSITIVELY_ENFORCED` actuator, add/confirm a test that calls the actuator **without** a valid seal and asserts it is blocked. Audit `tests/test_trades_mcp.py`, `tests/test_gateway_server_mcp_tool_server.py` for existing coverage; fill gaps.
3. **Middleware enforcement (stretch, P2):** Consider a decorator (`@require_cleared_seal` already exists in `routing_seal.py:485-547` but appears unused in production call sites — grep confirmed no production usage) applied uniformly to actuator functions, rather than each actuator manually calling `verify_and_consume_seal()` inline. This centralizes the enforcement point and makes "did I forget to add the check to my new actuator" structurally harder to get wrong. This is a larger refactor — recommend as a **follow-up**, not part of this closure, since it touches every actuator's call convention.
4. Document the `trigger_safety_intervention()` and read-only tool exemptions explicitly (either add a no-op seal check with a comment explaining why it's intentionally absent, or add a lint/registry-based check that requires every new `@mcp.tool()` to be explicitly classified).

### 5.5 Priority / Effort
**P1** (no confirmed gap found in the audit — the trade actuator IS covered — but the *unverified coverage claim* itself is the real finding: lack of systematic enforcement/inventory is a process gap that could silently regress on a future PR). / **M** (inventory + test-gap-filling is contained; the middleware-enforcement stretch goal is **L** and should be split out).

### 5.6 Dependencies
None blocking. Should reference the B1/B2 changes if `require_cleared_seal`'s decorator signature changes (it will, if B2 adds `record_hash` support) — sequence this **after** B2.

### 5.7 Breaking change analysis
**None** for the inventory/test-gap-filling portion (5.4.1–5.4.2). The middleware-enforcement stretch goal (5.4.3), if pursued, would change every actuator function's call signature/decoration and needs its own dedicated breaking-change analysis in a future PR — explicitly out of scope for this closure pass.

### 5.8 Test requirements
- New/extended tests per actuator per the table in 5.2, asserting blocked execution on missing/invalid/expired/replayed seal.
- A meta-test (`tests/test_actuator_seal_coverage.py`) that walks the `ACTUATOR_SEAL_COVERAGE.md` registry (or a machine-readable sibling, e.g. a small YAML/JSON list) and asserts every listed `SEAL_ENFORCED` function is covered by at least one negative test — a lightweight regression guard against future actuators being added without seal enforcement.

---

## Chunk 6 — Category C: Formal Verification Gaps (Feasibility Assessment)

### 6.1 Item C1 — Code-to-Model Refinement Test (`proof/model.py`)

**Current state:** `proof/model.py` is a hand-abstracted 8-tuple state machine ([:1-80](../proof/model.py:1)) explicitly adapted from an open-source reference, with documented scope boundaries (FTRA excluded, FRIA caveated, actuator seal check modeled as "a verified precondition" rather than integrated). It does **not** import from `src/` — it is a standalone re-implementation of the governance pipeline's control-flow shape, verified via exhaustive BFS over its own abstract states.

**Feasibility of a runtime-trace-conformance test:** Medium-High. The pattern would be:
1. Instrument `SymbolicGovernor._run_checks()` / `validate_action()` to emit a trace of `(tier_name, verdict)` tuples per real invocation (this data largely already exists as OTel span attributes, e.g. `cage.verdict`, `cage.governance.*` — see the span-attribute pattern throughout `symbolic_governor.py`).
2. Write a translator that maps a captured OTel trace (or a structured log) into the model's tuple representation (`(phase, cbf, opa, ...)` per `proof/model.py`'s state shape).
3. Replay each translated trace through the model's transition function and assert the model accepts the same sequence (i.e., the trace corresponds to a reachable path in the BFS-enumerated state graph).
4. Run this as an integration test against a batch of real (or replayed red-team) requests, asserting 100% of traces are model-conformant; any non-conformant trace indicates either a code change that outpaced the model or a genuine `NoDirectBind`-relevant divergence.

**Effort:** **L** — requires building the trace-capture instrumentation (some exists via OTel, some needs adding), the translator (non-trivial: the model's abstract tuple must be kept in lockstep with any future tier additions — PAUSE/NARROW already exist in code per B1 above but are not yet reflected as distinct states in `proof/model.py`, a fact the audit's own Category A section on Table 1 already flags), and a stable test harness that doesn't flake on OTel export timing.

**Recommendation: Pursue partially, now; defer full automation.**
- **Now (P1, M):** Add NARROW and PAUSE as explicit states to `proof/model.py`'s tuple (currently only ALLOW/DENY/DEFER/REQUIRE_APPROVAL-shaped transitions are modeled per the Category A Table 1 finding) — this is a proof-model correctness fix independent of runtime-trace conformance, and is a prerequisite for any conformance test to be meaningful.
- **Defer (XL) to a dedicated research spike:** the full runtime-trace-conformance harness. It has real research/engineering value (closes the "hand-abstracted model" credibility gap) but is a multi-sprint effort with meaningful design risk (trace granularity, timing non-determinism in concurrent CBF∥OPA evaluation, and the model's abstraction level may need rework to be trace-comparable at all). Recommend scoping this as a follow-up spike (`spike/runtime-trace-conformance`) with a narrow first milestone: conformance-check only the linear (non-concurrent) tiers first, expand to the CBF∥OPA interleaving second.

### 6.2 Item C2 — Distributed CBF Conformance (`proof/distributed_cbf_model.py`)

**Current state:** A hand-abstracted N-agent BFS model over a discretized balance pool ([:1-80](../proof/distributed_cbf_model.py:1)), verifying SP-1–SP-4 safety properties (no double-spend, non-negative balances, reserve bounds, fence-epoch stale-read prevention) over small, tractable state spaces (357/2246/12184 states for N=2/3/4).

**Feasibility of trace-based validation against live Redis:** Medium. Unlike C1, this model is already narrowly scoped to the CBF's Lua-atomic operations (`LUA_ATOMIC_CBF` in `cbf.py:162-199`) and the fence-epoch mechanism — both are small, well-defined, high-value targets for trace capture:
1. Instrument `atomic_verify_and_commit()` and `_check_fence_epoch()` to log every `(agent_id, cost, balance_before, balance_after, epoch_before, epoch_after)` tuple.
2. Under a load-test harness (extend `tests/load/` or the existing `test_cbf_chaos.py`/`test_redis_failover_chaos.py` patterns) driving N concurrent simulated agents against a real Redis instance, capture the full operation trace.
3. Replay the trace through `distributed_cbf_model.py`'s transition function and assert every observed `(balance, epoch)` pair corresponds to a reachable model state, and that SP-1–SP-4 hold over the *observed* trace, not just the *modeled* state space.

**Effort:** **M-L** — smaller than C1 because the CBF's actual operations are already a tight, Lua-scripted atomic unit (less surface area than the full 8-tier pipeline), and B3's fence-epoch fix (Chunk 3) is a natural forcing function to also add this instrumentation while touching the same code.

**Recommendation: Pursue now, scoped narrowly, as a natural extension of B3.**
- Bundle the trace-capture instrumentation (6.2.1 above) into the same PR series as B3 (fence epoch cold-start fix) since both require touching `_check_fence_epoch()` and `atomic_verify_and_commit()`.
- Scope the *validation* (6.2.2–6.2.3) as a **separate P2/M follow-up PR** — the instrumentation is cheap and valuable on its own (better observability into fence-epoch behavior in production), while the full trace-replay-against-model harness is a testing investment that can be built once the instrumentation exists and has been observed in a staging/load-test environment for at least one cycle.

### 6.3 Category C summary table

| Item | Feasibility | Recommendation | Effort if pursued |
|---|---|---|---|
| C1 — full runtime-trace conformance (8-tier model) | Medium-High, but high design risk | Defer full harness to a dedicated spike; do the NARROW/PAUSE state-model fix now (prerequisite, and independently valuable) | Model fix: **M** now. Full harness: **XL**, deferred |
| C2 — distributed CBF trace validation | Medium, narrower scope | Pursue instrumentation now (bundled with B3); defer full trace-replay harness to a P2 follow-up | Instrumentation: **S**, bundled with B3. Harness: **M-L**, deferred |

---

## Chunk 7 — Priority / Effort / Dependency Summary Table

| ID | Item | Priority | Effort | Depends on | Blocks |
|---|---|---|---|---|---|
| B1 | PAUSE handler gap in `validate_action()` | **P0** | S | — | B2 (rebase order) |
| B3a | Fence epoch cold-start fix (`setup()` seeds from Redis) | **P0** | S | — | C2 instrumentation |
| B2 | HMAC seal bound to `record_hash` | **P1** | M | B1 | B5 (decorator signature) |
| B3b | Fence epoch primary/replica detection | **P1** | S | B3a | — |
| B4 | Evidence-stream config validation hardening | **P1** | S | — | — |
| B5 | Actuator seal coverage inventory + test gaps | **P1** | M | B2 | — |
| C1-model | Add NARROW/PAUSE states to `proof/model.py` | **P1** | M | B1 (decision shape) | C1-harness |
| C2-instr | Distributed CBF trace instrumentation | **P1** | S | B3a | C2-harness |
| B5-mw | Middleware-based seal enforcement decorator | **P2** | L | B5 | — |
| C1-harness | Runtime-trace-conformance test (full 8-tier) | **P2 (research spike)** | XL | C1-model | — |
| C2-harness | Distributed CBF trace-replay validation harness | **P2** | M-L | C2-instr | — |

---

## Chunk 8 — Recommended PR Sequencing

1. **PR 1 (P0, S):** B1 — PAUSE handler in `validate_action()`. Independent, highest priority, smallest blast radius.
2. **PR 2 (P0, S):** B3a — Fence epoch cold-start fix (`setup()` seeding). Independent of PR 1; can be developed in parallel by a different engineer.
3. **PR 3 (P1, S):** B4 — Evidence-stream config validation hardening. Independent; can also run in parallel with PR 1/2.
4. **PR 4 (P1, S):** B3b — Fence epoch primary/replica detection telemetry. Depends on PR 2 landing first (same file, sequential to avoid conflicts).
5. **PR 5 (P1, M):** B2 — HMAC seal `record_hash` binding (gateway + GFA mirror in one PR). Depends on PR 1 (rebase cleanliness in `symbolic_governor.py`).
6. **PR 6 (P1, M):** B5 — Actuator seal coverage inventory doc + test-gap-filling. Depends on PR 5 (decorator/signature stability).
7. **PR 7 (P1, S):** C2-instr — Distributed CBF trace instrumentation, bundled conceptually with PR 2/4 but can ship as its own PR once B3a/B3b are stable.
8. **PR 8 (P1, M):** C1-model — Add NARROW/PAUSE states to `proof/model.py`'s BFS tuple, update `tests/test_no_direct_bind_proof.py` expected state counts, update the consistency-blast-radius doc list per `REVISION_TRACKER.md`.
9. **Follow-up spikes (not sequenced, scheduled independently):** B5-mw (middleware enforcement refactor), C1-harness (runtime-trace-conformance spike), C2-harness (distributed CBF trace-replay harness).

Each PR should independently pass the full `pytest-logic` CI job in all three region postures per [`AGENTS.md`](../AGENTS.md#test-execution), and any PR touching `src/gateway/governance/`, `src/compliance_bridge/`, `config/compliance/`, `config/thresholds/`, or `config/oscal/` must include the four-point cross-region impact statement required by [`AGENTS.md`](../AGENTS.md#shared-module-cross-region-impact) in its description.

---

## Chunk 9 — Compliance Artifact Follow-Through

Per [`AGENTS.md`](../AGENTS.md#compliance-artifact-obligations):
- B2 (HMAC/`record_hash` binding) and B3 (fence epoch) touch NIST SP 800-53 control implementations (SC-4/SI-2 style controls per existing POAM entries, e.g. POAM-2026-039/POAM-2026-041 precedent) — an OSCAL component update in `compliance/oscal/` is required within 2 business days of each merge.
- B5's actuator inventory may surface new or removed Kubernetes-adjacent enforcement points — if so, a corresponding Lula validation update in `compliance/lula/` should accompany PR 6, or be flagged for a fast-follow PR.
- Any of B1–B5 that closes a gap analogous to an existing open POAM item should update [`docs/POAM.md`](../docs/POAM.md) with commit SHA, Lula result, and closure date per the standard POAM-closure convention already used for POAM-2026-039 through POAM-2026-050.
