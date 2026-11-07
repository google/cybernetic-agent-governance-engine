# Human Oversight Scope — CAGE v3.0.1

**Document:** AI600-005 / NIST AI 600-1 §2.5 / ISO 42001 §A.8.4
**Date:** 2026-08-16
**Status:** Active
**POAM:** AI600-005

---

## Purpose

This document defines the human oversight scope for the Cybernetic AI Governance Engine (CAGE). It satisfies:

- **NIST AI 600-1 §2.5** — Human-AI Configuration controls
- **ISO 42001 §A.8.4** — Human oversight of AI system decisions
- **SR 26-2 §3.2** — US Federal Reserve HITL SLA requirements (US_FED only)
- **DORA Art. 10** — ICT incident management oversight (EU_ECB only)
- **MAS FEAT §3.2** — Human oversight of AI decisions (APAC_MAS only)

---

## Escalation Triggers

CAGE automatically escalates governance decisions to human review when any of the following conditions are met:

| Trigger | Code Location | Threshold / Condition |
|---|---|---|
| **Consensus notional / critic split** | [`src/cage_finance/tiers/consensus_tier.py`](../../src/cage_finance/tiers/consensus_tier.py) (`ConsensusTierPlugin`) + [`src/gateway/governance/consensus/engine.py`](../../src/gateway/governance/consensus/engine.py) | Trade amount > $10,000 USD (`domains.finance.consensus.threshold_usd` in `config/governance_thresholds.json`) with critic split (`ViolationKind.HITL` → `REQUIRE_APPROVAL`) |
| **Model confidence in approval band** | [`src/gateway/governance/governor/stages/confidence.py`](../../src/gateway/governance/governor/stages/confidence.py) (`ConfidenceStage`) | `0.70 <= confidence < 0.95` (`CTRL_AGT_001` → `ViolationKind.HITL` / `REQUIRE_APPROVAL`; `< 0.70` emits `ViolationKind.DEFERRABLE` → turn-terminal `DEFER` hold) |
| **CausalGatekeeper block** | `src/gateway/governance/causal/gatekeeper.py` `causal_safety_check()` | World-model p-value < `get_causal_lock_p_value_threshold()` (0.05) or marginal risk boundary exceeded |
| **OPA MANUAL_REVIEW decision** | `src/cage_finance/opa/trade_governance.rego` | OPA policy (package `trade.governance`) returns `"MANUAL_REVIEW"` |
| **Governance confidence low** | `src/gateway/governance/consensus/engine.py` `ConsensusEngine` | ConsensusEngine self-reported confidence < threshold |
| **NeMo Policy Refinement Proposal (CR-2)** | `src/governed_financial_advisor/server.py` | `POST /v1/nemo/approve-refinement/{proposal_id}` requires human risk officer sign-off with rationale |

---

## DeferQueue Schema

Parked governance records use the [`DeferToken`](../../src/gateway/governance/defer_queue.py)
Pydantic model and [`DeferReason`](../../src/gateway/governance/defer_queue.py) enum in
[`src/gateway/governance/defer_queue.py`](../../src/gateway/governance/defer_queue.py):

| `DeferReason` | Governance Disposition | Resolution Semantics |
|---|---|---|
| `HITL_REQUIRED` | `REQUIRE_APPROVAL` | Human dual-control approval via `DeferQueue.approve()` (`ApprovalRecord` quorum) and single-use consumption via `DeferQueue.consume_approval()` |
| `CONFIDENCE_BELOW_THRESHOLD` | `DEFER` | Turn-terminal hold when `confidence < 0.70` (`ViolationKind.DEFERRABLE`); not overridable by human dual-control approval |
| `WARRANT_INELIGIBLE` | `DEFER` | Turn-terminal hold when a governing warrant is missing, expired, or revoked; requires warrant re-issuance and a fresh request |
| `EXTERNAL_HOLD` | `DEFER` | External normative provider escalation (quorum = 3; routes to DLQ on TTL expiry via `DeferQueue.expire_stale()`) |
| `FTRA_IRREVERSIBLE_TERMINAL` | `REQUIRE_APPROVAL` / graph park | Pre-execution FTRA terminal reachability hold (`CTRL_FTRA_001`) |

Controller-boundary `REQUIRE_APPROVAL` verdicts (including notional/quorum consensus escalations from [`src/cage_finance/tiers/consensus_tier.py`](../../src/cage_finance/tiers/consensus_tier.py), `[0.70, 0.95)` confidence escalations from [`src/gateway/governance/governor/stages/confidence.py`](../../src/gateway/governance/governor/stages/confidence.py), and out-of-envelope or irreversible FTRA findings such as `FTRA_REGISTERED_IRREVERSIBLE`, `FTRA_REGISTERED_EXTERNALLY_REVERSIBLE`, `FTRA_UNREGISTERED_ACTION`, `FTRA_MAGNITUDE_EXCEEDS_ENVELOPE`, and `FTRA_CONFIDENCE_BELOW_ENVELOPE`) are parked by `SymbolicGovernor.validate_action()` as `DeferToken` records with `DeferReason.HITL_REQUIRED` in [`defer_queue.py`](../../src/gateway/governance/defer_queue.py), returning `deferred_id` for human approval via `DeferQueue.approve()` and single-use redemption via `DeferQueue.consume_approval()`.

---

## Human Approval & Audit Trail (AI600-005)

Each operator approval appended via `DeferQueue.approve()` in
[`defer_queue.py`](../../src/gateway/governance/defer_queue.py) records a durable
[`ApprovalRecord`](../../src/gateway/governance/defer_queue.py) bound to the parked
decision (`approver_urn`, `approved_at_utc`, `auth_method`, `auth_principal_hash`,
server-stamped `approved_barrier_preview`, and WebAuthn `client_data_json` /
`challenge_binding`). Regional regulatory citations and SLA windows are defined in
[`constants.py`](../../src/gateway/governance/constants.py) (`HITL_CITATIONS` /
`HITL_CITATION_DEFAULT` and `HITL_SLA_HOURS` / `HITL_SLA_HOURS_DEFAULT`), while
every post-approval execution decision enters the signed governance evidence chain.

---

## SLA Requirements by Region

CAGE defines region-specific HITL resolution SLAs based on the active deployment
region (`CAGE_DEPLOYMENT_REGION`) in [`constants.py`](../../src/gateway/governance/constants.py)
(`HITL_SLA_HOURS` and `HITL_CITATIONS`, with `HITL_SLA_HOURS_DEFAULT` and
`HITL_CITATION_DEFAULT` fallbacks):

| Region | SLA | Regulatory Authority |
|---|---|---|
| `US_FED` | **4 hours** | SR 26-2 §3.2 — Federal Reserve supervisory guidance on model risk management |
| `EU_ECB` | **2 hours** | DORA Art. 10 — ICT incident management for major incidents |
| `APAC_MAS` | **1 hour** | MAS FEAT §3.2 — Human oversight of AI decisions |
| *(default)* | **4 hours** | ISO 42001 §A.8.4 fallback |

> [!IMPORTANT]
> SR 26-2 §3.2 (4-hour SLA) is a US Federal Reserve requirement that has no legal force outside `US_FED` deployments. EU_ECB and APAC_MAS deployments must use their respective regional SLAs.

---

## Automated Governance Thresholds

**Source:** [`src/gateway/governance/governor/stages/confidence.py`](../../src/gateway/governance/governor/stages/confidence.py)

The universal confidence band decides whether a governance decision is handled
automatically or escalated. `ConfidenceStage` (Tier 2) applies it in every
region, reading `get_agent_confidence_threshold()` (`confidence.agent_threshold`,
default 0.95, env `AGENT_CONFIDENCE_THRESHOLD`) and `get_confidence_defer_floor()`
(`confidence.defer_floor`, default 0.70, env `CONFIDENCE_DEFER_FLOOR`) from
[`schemas/thresholds.py`](../../src/gateway/governance/schemas/thresholds.py).
FTRA uses the same floor to choose between `DEFER` and `REQUIRE_APPROVAL` on plan graphs.

### Confidence Band

| Score | Violation | Disposition | Human Required? |
|---|---|---|---|
| score ≥ `confidence.agent_threshold` (0.95) | none | Confidence check clears | No |
| `confidence.defer_floor` (0.70) ≤ score < 0.95 | `ViolationKind.HITL` (`CONFIDENCE_BELOW_THRESHOLD`) | `REQUIRE_APPROVAL` — parked in `DeferQueue` (`DeferReason.HITL_REQUIRED`) for human dual-control approval and consumed via `DeferQueue.consume_approval()` | **Yes** |
| score < `confidence.defer_floor` (0.70) | `ViolationKind.DEFERRABLE` (`CONFIDENCE_BELOW_THRESHOLD`) | `DEFER` — turn-terminal hold parked in `DeferQueue` (`DeferReason.CONFIDENCE_BELOW_THRESHOLD`) | No (turn-terminal hold; not overridable by human approval) |

On replay, `replay_evaluate()` in `defer_queue.py` re-checks the hydrated
confidence against `get_confidence_defer_floor()`: at or above it the token is
admitted, otherwise it remains parked.

### FRIA Tier (EU_ECB only)

The EU AI Act Art. 27 Fundamental Rights Impact Assessment is **not** part of the
confidence band. It is the phase-1 `fria` tier
([`FriaTier`](../../src/gateway/governance/jurisdiction/eu_ai_act/fria_tier.py)),
contributed only when `CAGE_DEPLOYMENT_REGION=EU_ECB` and run right after
`causal`. A stale or missing FRIA artefact, or an unreachable / erroring
`NormativeProvider`, is a HARD refusal. If the provider refuses with a
`needs_human_review` finding, the tier raises HITL `FRIA_EXTERNAL_HOLD` and the
governor parks a REQUIRE_APPROVAL `DeferToken` for a human reviewer to resolve
within the applicable SLA (see
[SLA Requirements by Region](#sla-requirements-by-region)).

### Consensus Requirement

Trades with `amount ≥ $10,000 USD` require multi-critic consensus (Tier 5).
The consensus engine
([`src/gateway/governance/consensus/engine.py`](../../src/gateway/governance/consensus/engine.py)) invokes multiple
LLM critics with a **10-second hard timeout** (`CONSENSUS_CRITIC_TIMEOUT_S`, default `10.0`s) per critic call. Unanimity is
required; a single dissenting critic escalates the decision to human review via
the DeferQueue. Background audit logging for consensus decisions is handled by
`_AUDIT_QUEUE` (`asyncio.Queue(maxsize=1000)`) and a background audit worker
task.

### Causal Lock Escalation

**Source:** [`src/gateway/governance/causal/gatekeeper.py`](../../src/gateway/governance/causal/gatekeeper.py)

When the causal gatekeeper's marginal risk boundary condition is triggered:

```
(0.5 + β × amount / normalization_scale) > CAUSAL_LOCK_RISK_BOUNDARY  (0.95)
```

the request is **denied, not escalated**. β is fitted per normalised unit of
trade amount ($10,000 for finance), so the left-hand side is 0.5 plus the
predicted change in risk score for this trade; on the finance synthetic
telemetry the boundary trips at about $9,144. Every causal failure is a HARD
violation (decision D3), and HARD outranks HITL in the classifier, so no human
approval can override a causal lock, including for trades that other tiers
would route to review.

The other causal lock conditions are refusals of the world model itself, with
the same HARD outcome:
- `PlaceboTreatmentRefuter` result missing, non-finite, or with zero spread across its simulations — the refutation carries no evidence
- `PlaceboTreatmentRefuter` p-value < `CAUSAL_LOCK_P_VALUE_THRESHOLD` (0.05) — causal estimate is not robust
- Placebo effect magnitude > `CAUSAL_LOCK_PLACEBO_EFFECT_MAGNITUDE` (0.2 per normalised unit) — spurious causal signal detected

**Telemetry freshness:** In production, `causal_safety_check()` **fails closed**
when no live telemetry is provided — there is no mock fallback for missing
telemetry in a production deployment (`CAGE_ENV=production`). The causal cache
stores only the params-independent world-model verdict (β and the placebo
refutation outcome), never the allow/deny decision: the marginal risk boundary
is recomputed from the request's trade amount on every call. It uses
synchronous Redis helpers (`_causal_cache_get_sync` / `_causal_cache_set_sync`)
that are safe to call from `asyncio.to_thread` worker pools. Cache TTL is
`CAUSAL_CACHE_TTL_SECONDS` (60 s);
telemetry staleness limit is `TELEMETRY_MAX_STALENESS_SECONDS` (300 s).

---

## Reviewer Workflow (`validate-action → deferred_id → DeferQueue.approve → execute_trade_action(deferred_id)`)

1. **Pre-flight & Parking (`POST /validate-action` → `deferred_id`):** `SymbolicGovernor.validate_action()` evaluates the proposed action under `Profile.DRY_RUN` without minting a seal or mutating barrier state. When `ClassificationEngine` returns `REQUIRE_APPROVAL`, `_park_for_hitl()` writes a `DeferToken` (`DeferReason.HITL_REQUIRED`) to `DeferQueue` and returns `deferred_id` on `GovernanceVerdict`.
2. **Alert received & SLA window starts:** DeferQueue Pub/Sub message triggers reviewer notification (email/Slack/PagerDuty); SLA timer starts from `escalated_at` timestamp.
3. **Reviewer accesses:** DeferQueue UI or API endpoint `GET /v1/hitl/queue/{trace_id}`.
4. **Reviewer evaluates:** Langfuse trace, governance decision rationale, amount/confidence,
   and the **barrier preview**. Before the trade is parked, `run_pipeline()` previews every
   phase-2 barrier side-effect-free (`phase2_mode()` → `PREVIEW` in
   [`src/gateway/governance/governor/pipeline.py`](../../src/gateway/governance/governor/pipeline.py)).
   The DeferToken `original_verdict_snapshot` records `barrier_preview` (`PASS` / `FAIL`) and
   `barrier_preview_violations`, so the reviewer sees, for example, a fiscal-cap breach the
   approved trade would hit. A barrier that would refuse outright (`HARD`, e.g. CBF or a dose
   barrier) denies the request before it ever reaches a reviewer (`hard_preview_denies_before_hitl`).
   Each breach carries `bound`, how much the tier would still admit (e.g. the fiscal tier's
   remaining daily headroom, `Violation.bound` in
   [`src/gateway/governance/contracts.py`](../../src/gateway/governance/contracts.py)). When
   narrowing is enabled and every finding other than the approval itself is NARROWABLE, the
   `REQUIRE_APPROVAL` response carries `narrowed_params` and the snapshot a `narrow_hint`: the
   clamped trade, kept only if a `DRY_RUN` over it leaves nothing but HITL findings
   (`SymbolicGovernor._reverified_narrow_hint` in
   [`src/gateway/governance/governor/governor.py`](../../src/gateway/governance/governor/governor.py)).
   The hint authorises nothing; an approval covers it because an approved trade may shrink,
   and the committing run re-verifies whatever executes.
5. **Reviewer decides (`DeferQueue.approve` / `POST /defer/{deferred_id}/approve`):**
   - `OVERRIDE` (`DeferQueue.approve`) — records an `ApprovalRecord`, stamps `approved_barrier_preview` from the server-stored `barrier_preview` (never from caller input), and transitions the `DeferToken` to `RESOLVED` (`resolution="ESCALATED"`) once quorum is met
   - `UPHOLD` (`DeferQueue.reject`) — confirms the block; decision is logged
   - `DEFER` — escalates to senior reviewer; re-queued with extended SLA
6. **Single-commit execution (`execute_trade_action(..., deferred_id=...)` → `enforce_approved_governance` → `revalidate_post_hitl`):**
   On human approval, `gateway_tool_guard` adds the `deferred_id` to the tool call's arguments
   ([`src/governed_financial_advisor/graph/governance/tool_guard.py`](../../src/governed_financial_advisor/graph/governance/tool_guard.py))
   and the advisor invokes the gateway's `execute_trade_action(..., deferred_id=deferred_id)` MCP tool.
   Inside [`src/gateway/server/governance_middleware.py`](../../src/gateway/server/governance_middleware.py),
   `enforce_approved_governance()` checks the quorum-approved `HITL_REQUIRED` token without
   spending it (`DeferQueue.redeemable_approval`, verifying action and canonical parameter SHA-256
   binding) and calls `SymbolicGovernor.revalidate_post_hitl(..., approval=PostHitlApproval(...))` in
   [`src/gateway/governance/governor/governor.py`](../../src/gateway/governance/governor/governor.py).
   The governor spends the approval exactly once (`DeferQueue.consume_approval`, an atomic CAS)
   only when the run is about to mint a seal. A DENY spends it; a `WARRANT_INELIGIBLE` DEFER
   leaves it redeemable (POAM-2026-104), and the tool reports `DEFERRED:`.
   Under `Profile.POST_HITL` (`stage_runs_under` in `pipeline.py`), the governor re-runs the
   read-only stages whose verdict can change while a human decides: `opa`, the warrant gate
   (when a region marks a norm `requires_warrant`), and every tier that declares
   `revalidated_after_approval` (under `EU_ECB`, `fria`). A human-review hold any of them reports,
   OPA's `MANUAL_REVIEW` included, is answered only if the approval was given against it
   (`PostHitlApproval.approved_holds`, read from the parked token's holds); a hold the reviewer
   never saw is refused with `DENY` (`reason="approval_context_drift"`, GHSA-f6xq-23f7-9grm).
   It then commits every claiming Phase 2 barrier (`cbf`, `fiscal`, or `dose_barrier`) inside
   `ReservationScope`. If `approved_barrier_preview == PASS` at approval time but a live Phase 2
   barrier now fails (`FAIL`), `revalidate_post_hitl()` refuses with `DENY`
   (`reason="APPROVAL_CONTEXT_DRIFT"`).
   The `GovernanceSeal` is minted, verified, and settled (`governor.settle(seal, executed=...)`)
   strictly inside `governance_middleware.py`; the advisor never receives a seal (POAM-2026-079).
7. **Audit record persisted:** Override decision stored in Langfuse compliance project.

---

## Scope Boundaries

Human oversight is **in scope** for:
- Financial trade decisions > $10,000 USD (`ConsensusTierPlugin` in [`src/cage_finance/tiers/consensus_tier.py`](../../src/cage_finance/tiers/consensus_tier.py) / FTRA out-of-envelope `REQUIRE_APPROVAL` escalations)
- Controller-boundary FTRA `REQUIRE_APPROVAL` escalations (`FTRA_REGISTERED_IRREVERSIBLE`, `FTRA_REGISTERED_EXTERNALLY_REVERSIBLE`, `FTRA_UNREGISTERED_ACTION`, `FTRA_MAGNITUDE_EXCEEDS_ENVELOPE`, `FTRA_CONFIDENCE_BELOW_ENVELOPE`) parked as `DeferReason.HITL_REQUIRED` and consumed via `DeferQueue.consume_approval()`
- Governance decisions with confidence in `[0.70, 0.95)` (`ViolationKind.HITL`, `CONFIDENCE_BELOW_THRESHOLD`, parked as `DeferReason.HITL_REQUIRED`)
- OPA policy `MANUAL_REVIEW` / `requires_hitl` decisions and EU AI Act Art. 27 `FRIA_EXTERNAL_HOLD` holds

Human oversight is **out of scope** for:
- Turn-terminal `DEFER` holds on confidence `< 0.70` (`DeferReason.CONFIDENCE_BELOW_THRESHOLD`) or missing/stale/revoked warrants (`DeferReason.WARRANT_INELIGIBLE`) — turn-terminal holds cannot be overridden by human dual-control approval
- Tier 1 keyword blocks (Aho-Corasick) — these are bright-line safety controls that are not overridable
- CBRN content blocks — these are immutable Cat-M controls (no override permitted without AO pre-approval)
- SC-8 TLS validation failures — infrastructure-level controls not subject to HITL
- Phase 1 or Phase 2 `ViolationKind.HARD` refusals (STPA unsafe control actions, CBF liquidity barrier breaches `CBF_BARRIER_VIOLATED`, causal gatekeeper `CAUSAL_CHECK_FAILED` rejections) — denied before reaching HITL (`hard_preview_denies_before_hitl`)
- `DeferReason.FTRA_IRREVERSIBLE_TERMINAL` tokens in `replay_evaluate()` — terminal-state tokens cannot be released via automated hydration replay

---

## Related Documents

- [`src/cage_finance/tiers/consensus_tier.py`](../../src/cage_finance/tiers/consensus_tier.py) — Finance consensus tier (`ConsensusTierPlugin`, `$10,000` notional threshold)
- [`src/gateway/governance/governor/stages/confidence.py`](../../src/gateway/governance/governor/stages/confidence.py) — Tier 2 `ConfidenceStage` (`>= 0.95` pass, `[0.70, 0.95)` `REQUIRE_APPROVAL`, `< 0.70` turn-terminal `DEFER`)
- [`src/gateway/governance/defer_queue.py`](../../src/gateway/governance/defer_queue.py) — DeferQueue implementation (Redis db=1, noeviction, `_DEFAULT_TTL = 3600 * 4`)
- [`src/gateway/governance/constants.py`](../../src/gateway/governance/constants.py) — `HITL_SLA_HOURS` and `HITL_CITATIONS` dicts
- [`compliance/lula/lula-validation-ai600-human-ai-config.yaml`](../../compliance/lula/lula-validation-ai600-human-ai-config.yaml) — Lula validation manifest
- [`docs/POAM.md`](../POAM.md) — AI600-005 POAM item
