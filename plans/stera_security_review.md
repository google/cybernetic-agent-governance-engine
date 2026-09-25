# STERA Pipeline — Bug & Security Review

**Scope:** [symbolic_governor.py](../src/gateway/governance/symbolic_governor.py) (read in full by me), finance domain tiers, CBF/fiscal/TQP, FTRA, causal, consensus, defer/pause, routing seal, ConsequenceGateway (these were covered by 3 parallel read-only reviewers; I spot-checked the critical items).
**Mode:** Static review only. No files changed, no tests run. Unless marked *speculative*, each finding comes from reading the code at HEAD.

---

## 🔴 Critical

### C1. Post-HITL revalidation fails open when CBF refuses without saying "UNSAFE"
[symbolic_governor.py:1994,2065](../src/gateway/governance/symbolic_governor.py#L1986-L2068)
`revalidate_post_hitl` only records a violation when the reason starts with `"UNSAFE"`. `atomic_verify_and_commit` also returns `(False, …)` with other reasons:
- `"RECONCILIATION_UNAVAILABLE: …"`
- `"Fence epoch regression: …"`
- `"Ground truth balance unavailable"`

In all three cases the CBF refused, yet a routing seal is issued.
**Fix:** return the `committed` bool and treat `not committed` as a violation.

### C2. Post-HITL revalidation runs CBF commit and OPA concurrently, with no rollback
[symbolic_governor.py:2031-2035](../src/gateway/governance/symbolic_governor.py#L2029-L2037)
`asyncio.gather(_cbf_revalidate(), _opa_revalidate())` debits the CBF balance even when OPA denies. The main pipeline was reordered specifically to prevent this budget leakage; this path reintroduces it.
**Fix:** run OPA first, then CBF commit. Roll back CBF on any later failure, including a seal-generation failure.

### C3. NARROW issues a seal without CBF/fiscal checks, and caller-supplied params set the clamp
Only reachable when `CAGE_NARROW_ENABLED=true`.
- **Phase 2 is skipped.** Phase 2 only runs when `not violations` ([L1754](../src/gateway/governance/symbolic_governor.py#L1754)), so a NARROW verdict never reaches the CBF commit or fiscal reservation. It still gets a seal ([L2479](../src/gateway/governance/symbolic_governor.py#L2479)).
- **The caller sets the ceiling.** The clamp threshold comes from the request: `params.get("_threshold_config")` ([L2357](../src/gateway/governance/symbolic_governor.py#L2357)). A caller can pass `max_amount: 1e12`.
- **A NARROW with no constraints still gets a seal.** Non-numeric amounts are not clamped, and the violation may be unrelated to amount ([L783](../src/gateway/governance/symbolic_governor.py#L783)). In both cases the original params are sealed.
- **Hard blocks become NARROW.** Bounding `HARD_BLOCK` messages such as *"Trade notional exceeds maximum single-order limit"* ([bounding_tier.py:158-177](../src/cage_finance/tiers/bounding_tier.py#L155-L180)) match the `"exceeds max"` substring, so they are classified as narrowable instead of hard.

**Fix:**
- Re-run the full pipeline on the narrowed params.
- Take thresholds from server config only.
- Refuse NARROW when `constraints_applied` is empty.
- Classify on `Violation.code` / `recoverable`, not on message text (see H1).

### C4. The CBF Lua script is not atomic against concurrent commits (lost updates / double-spend)
[cbf_engine.py:342-370](../src/gateway/governance/safety/cbf_engine.py#L342-L370)
The script checks the barrier against `ARGV[5]`, a balance Python read earlier, and then runs `SET KEYS[1] = ARGV[5]-cost`. It never reads `KEYS[1]` itself. Two concurrent commits that start from the same balance both pass, and only one debit is recorded. The local-debit list is also read and appended outside the script.
**Fix:** pass the expected fence epoch in ARGV and abort inside Lua if `GET KEYS[3]` differs (compare-and-set).

### C5. ConsequenceGateway is never called on the live execution path
[tool_provider.py:118-121](../src/cage_finance/tools/tool_provider.py#L118-L121) is a placeholder, and actuators run without any token check. As a result, the ADR-008 guarantees are not enforced at runtime:
- JWS signature verification
- `act` binding
- single-use consumption

**Fix:** require `ConsequenceGateway.evaluate(...) == EXECUTE` inside `ActuatorRegistry` dispatch, and fail closed when the token is missing.

---

## 🟠 High

| # | Finding | Location | Fix |
|---|---|---|---|
| H1 | **Violations are classified by substring matching on free text.** Messages that include attacker-influenced text (e.g. `symbol=` in bounding messages) can move a hard violation into the soft, pause or narrow bucket. Also, `"Unsafe Control Action" in v.lower()` can never be true (mixed case compared against a lowercased string). | [L385-490](../src/gateway/governance/symbolic_governor.py#L385-L490) | Classify on structured `Violation.code` / `recoverable` / `needs_human_review` |
| H2 | **OPA verdicts are read with a denylist.** Any decision other than `DENY`/`GOVERNANCE_VIOLATION`/`MANUAL_REVIEW` is treated as ALLOW. That includes `"REJECT"`, `"ERROR"`, `"NONE"` (from `allow: null`), and cached garbage. The same pattern appears in 3 places. | [L1575](../src/gateway/governance/symbolic_governor.py#L1575), [L1621](../src/gateway/governance/symbolic_governor.py#L1621), [L2085](../src/gateway/governance/symbolic_governor.py#L2085) | Allowlist: only `== "ALLOW"` passes |
| H3 | **A NaN confidence skips the confidence tier.** `float("nan") < threshold` is False, and the FRIA/DEFER zone checks behave the same way. | [L1460](../src/gateway/governance/symbolic_governor.py#L1460), [L504](../src/gateway/governance/symbolic_governor.py#L504) | Reject values that are not finite or fall outside [0,1] |
| H4 | **`execute_trade_bounded` is governed only by the bounding tier.** CBF, fiscal, consensus and causal all claim only `execute_trade`, yet the cost resolver says bounded trades carry a cash cost. So no cash-barrier debit and no fiscal reservation happen. | [cbf_tier.py:39](../src/cage_finance/tiers/cbf_tier.py#L39-L40), [invariants.py:72](../src/cage_finance/invariants.py#L72) | Claim both actions (or an explicit set) |
| H5 | **CBF rollback is not validated.** It uses `float(params["amount"])`, while commit uses `amount_minor`, so the two can disagree. NaN or oversized values can inflate or poison the balance. A missing key defaults to a $100k balance. | [cbf_engine.py:1546-1578](../src/gateway/governance/safety/cbf_engine.py#L1546-L1578), [cbf_tier.py:59](../src/cage_finance/tiers/cbf_tier.py#L58-L60) | Store the committed cost per transaction and roll back exactly that amount; never default the balance |
| H6 | **FTRA DFS only starts from `steps[0]`.** A second root, a step depending on an unknown id, or a duplicate `step.id` hides irreversible steps. | [graph_analyzer.py:160-196](../src/gateway/governance/ftra/graph_analyzer.py#L160-L196) | Classify every node; reject duplicate or unknown deps |
| H7 | **Defer `_resolve()` has no status guard,** and `replay_evaluate` returns ADMITTED even when `_resolve` returns None. An EXPIRED/RESOLVED token can therefore be re-admitted. | [defer_queue.py:749-766](../src/gateway/governance/defer_queue.py#L749-L766), [L1370-1378](../src/gateway/governance/defer_queue.py#L1370-L1378) | Check `status == PARKED` inside the CAS/Lua; fail on None |
| H8 | **`resume_request` does a non-atomic get-then-set** and does not reject EXPIRED tokens, so the same request can be resumed twice. | [pause_primitive.py:325-406](../src/gateway/governance/pause_primitive.py#L325-L406) | Lua CAS `PAUSED→RESUMED` |
| H9 | **A mismatched local KMS public key is logged and then trusted.** Anyone who can write that PEM can forge tokens. | [kms_signer.py:651-660](../src/gateway/governance/kms_signer.py#L651-L660) | Raise on mismatch |
| H10 | **Causal cache key covers only `(action_type, regime)`.** One small SAFE result caches True for any amount. NaN or negative amounts also pass. | [causal/gatekeeper.py:597-664](../src/gateway/governance/causal/gatekeeper.py#L597-L664) | Include the amount bucket in the key or never cache True; add `isfinite` checks |
| H11 | **`FiscalLimitGuard.release` is not idempotent.** A double release frees other agents' capacity. | [resource_guard.py:653-666](../src/gateway/governance/safety/resource_guard.py#L653-L666) | Only `DECRBY` if `DEL reservation` returned 1 |

---

## 🟡 Medium

- **Consensus vote parsing is order-dependent.** It checks `"APPROVE" in content` first, so *"REJECT — cannot APPROVE"* and *"DISAPPROVE"* both count as APPROVE ([engine.py:365](../src/gateway/governance/consensus/engine.py#L365-L371)). This can be driven by prompt injection via `symbol`.
- **Consensus is skipped when `amount` is below the threshold, but CBF charges `amount_minor`.** Sending `{amount_minor: huge, amount: 0.01}` skips consensus.
- **Seal generation after a Phase 2 commit has no rollback.** In `govern()` and `validate_action()`, if `generate_seal_with_evidence` raises, the CBF debit and fiscal reservation leak ([L1894](../src/gateway/governance/symbolic_governor.py#L1894), [L2748](../src/gateway/governance/symbolic_governor.py#L2748)).
- **The routing seal and envelope fall back to the current key on an unknown `kid`.** Also: the JWT decode does not require `exp`/`iss`, and envelopes are issued unsigned when KMS fails ([routing_seal.py:642-673](../src/gateway/governance/routing_seal.py#L642-L673), [governance_envelope.py:470-533](../src/gateway/governance/governance_envelope.py#L470-L533)).
- **Replay-marker TTL is not tied to token `exp`.** It is a fixed 90s, so tokens with a longer TTL can be replayed ([consequence_authority_store.py:93](../src/gateway/governance/consequence_authority_store.py#L93)).
- **Unguarded counters and missing NaN checks:**
  - TQP rollback has no floor, so counters can go negative.
  - The FTRA semantic validator and STPA UCA-2/UCA-5 accept NaN.
- **`pre_check` treats an STPA exception as "no violations"** ([L2179-2183](../src/gateway/governance/symbolic_governor.py#L2177-L2183)). It feeds NeMo context.
- **The CBF threshold override ignores the domain `threshold_key`.** Healthcare gets the finance floor ([cbf_engine.py:1751](../src/gateway/governance/safety/cbf_engine.py#L1751-L1755)).
- **Defer key TTL equals the zset score**, so the key expires before the sweep and EXPIRED/refusal evidence is lost. Also, `approve()` ignores wall-clock expiry.

## 🔵 Low / correctness

- **`_stpa_violation_count` also counts FTRA violations** ([L1400](../src/gateway/governance/symbolic_governor.py#L1400)). As a result, every FTRA HITL case becomes a hard **DENY** and never REQUIRE_APPROVAL. This fails closed, but it breaks Phase 3.3.
- **Consensus `ESCALATE` messages fall into `UNKNOWN_HARD` and become DENY.** The `needs_human_review` flag is ignored.
- **The span sets `tier2.confidence.independently_verified=True` for a self-reported value** ([L1465](../src/gateway/governance/symbolic_governor.py#L1465)). This misleads the audit trail.
- **Environment guards disagree.** The stub-reconciliation guard ([L150-153](../src/gateway/governance/symbolic_governor.py#L150-L153)) defaults `CAGE_ENV` to `"dev"` and matches only `== "production"`. `_IS_PRODUCTION` defaults to production. Values such as `prod`/`staging` skip the stub guard.
- **Full request params go into OTel `OBSERVATION_INPUT`.** This is a possible PII leak ([L1836](../src/gateway/governance/symbolic_governor.py#L1836), [L2294](../src/gateway/governance/symbolic_governor.py#L2294)).
- **`agent_id` in responses comes from `params["_caller_principal"]`.** Only `agent_gateway_adapter` overwrites it; other entry paths can spoof it.
- **Dead code:** `_fiscal_token` is always None ([L1776-1791](../src/gateway/governance/symbolic_governor.py#L1776-L1791)).
- **Layer 1 contains finance vocabulary** (`_legacy_finance_cost_resolver`). This violates the kernel-agnostic rule.
- **Actuator registry:** the first wildcard (`"*"`) actuator catches every action, and prefix claims are loose.
- **`claims_action` uses exact string match** (e.g. `"Execute_Trade"` would bypass the tiers if downstream normalises names). *Speculative.*

---

## Suggested remediation order
1. C1, C2 (fail-open in the HITL path), then H2, H3 (small allowlist/finiteness fixes).
2. C4 (CBF CAS), H5, H11 (money-state integrity).
3. C5 (wire up ConsequenceGateway), H7, H8 (state-machine CAS).
4. C3 / H1: replace string classification with structured `Violation` codes, and keep NARROW disabled until then.
5. H4, H6, H10, then the Medium items.

Each fail-closed fix needs a test that observes it fail (per AGENTS.md).
