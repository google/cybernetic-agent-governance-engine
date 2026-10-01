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
| **Consensus threshold exceeded** | `hitl_escalator.py` `should_escalate_for_consensus()` | Trade amount > $10,000 USD (`consensus.threshold_usd` in `governance_thresholds.json`) |
| **Model confidence low** | `hitl_escalator.py` `should_escalate_for_confidence()` | Confidence < 0.95 (CTRL_AGT_001) |
| **CausalGatekeeper block** | `src/gateway/governance/causal/gatekeeper.py` `causal_safety_check()` | World-model p-value < `get_causal_lock_p_value_threshold()` (0.05) or marginal risk boundary exceeded |
| **OPA MANUAL_REVIEW decision** | `src/cage_finance/opa/trade_governance.rego` | OPA policy (package `trade.governance`) returns `"MANUAL_REVIEW"` |
| **Governance confidence low** | `src/gateway/governance/consensus/engine.py` `ConsensusEngine` | ConsensusEngine self-reported confidence < threshold |
| **NeMo Policy Refinement Proposal (CR-2)** | `src/governed_financial_advisor/server.py` | `POST /v1/nemo/approve-refinement/{proposal_id}` requires human risk officer sign-off with rationale |

---

## DeferQueue Schema

Escalation records written to the DeferQueue have the following schema (matches
[`DeferToken`](../../src/gateway/governance/defer_queue.py) Pydantic model and
[`EscalationRecord`](../../src/gateway/governance/hitl_escalator.py) dataclass):

```json
{
  "event": "hitl_escalation",
  "trace_id": "<langfuse-trace-id>",
  "reason": "<EscalationReason.value>",
  "amount_usd": 12500.00,
  "confidence": 0.87,
  "reviewer_queue": "compliance-review",
  "status": "pending_review",
  "timestamp": "2026-06-23T14:00:00.000000Z",
  "escalated_at": "2026-06-23T14:00:00.000000Z"
}
```

`EscalationReason` enum values (from [`hitl_escalator.py`](../../src/gateway/governance/hitl_escalator.py)):

| Value | Trigger |
|---|---|
| `CONSENSUS_THRESHOLD` | Trade amount exceeds consensus threshold |
| `CONFIDENCE_LOW` | Model confidence below 0.95 |
| `CAUSAL_BLOCK` | CausalGatekeeper marginal risk boundary or placebo refutation failure |
| `MANUAL_REVIEW` | OPA policy returned `"MANUAL_REVIEW"` |
| `GOVERNANCE_CONFIDENCE_LOW` | ConsensusEngine self-reported confidence below threshold |

Controller-boundary `REQUIRE_APPROVAL` verdicts (including out-of-envelope or irreversible FTRA findings such as `FTRA_REGISTERED_IRREVERSIBLE`, `FTRA_REGISTERED_EXTERNALLY_REVERSIBLE`, `FTRA_UNREGISTERED_ACTION`, `FTRA_MAGNITUDE_EXCEEDS_ENVELOPE`, and `FTRA_CONFIDENCE_BELOW_ENVELOPE`) are parked by `SymbolicGovernor.validate_action()` as `DeferToken` records with `DeferReason.HITL_REQUIRED` in [`defer_queue.py`](../../src/gateway/governance/defer_queue.py), returning `deferred_id` for human approval via `DeferQueue.approve()`. Multi-step plan trajectories deferred by `PlanGraphAnalyzer` use `DeferReason.FTRA_COMPOUND_IRREVERSIBLE`, while legacy terminal-state tokens (`DeferReason.FTRA_IRREVERSIBLE_TERMINAL`) cannot be released via automated replay (`replay_evaluate()`).

---

## Human Override Audit Trail (AI600-005)

When a human reviewer resolves an escalation, the `hitl_override_audit_span()`
function in [`hitl_escalator.py`](../../src/gateway/governance/hitl_escalator.py)
emits a structured OTel span with the following attributes. The function accepts
an optional `region` parameter; when provided it resolves the regulatory citation
via `get_hitl_regulatory_citation(region)` (from
[`constants.py`](../../src/gateway/governance/constants.py) `HITL_CITATIONS`)
and stamps the span accordingly:

| OTel Attribute | Description |
|---|---|
| `hitl.reviewer_id` | Pseudonymised reviewer identifier (e.g. `reviewer-123`) |
| `hitl.decision` | `OVERRIDE` \| `UPHOLD` \| `DEFER` |
| `hitl.reason` | Free-text justification (≤500 chars) |
| `hitl.original_escalation_reason` | `EscalationReason.value` that triggered escalation |
| `hitl.override_ts` | ISO 8601 UTC timestamp of the override decision |
| `hitl.trace_id` | Langfuse trace ID of the governed request |
| `hitl.regulatory_citation` | Resolved from `HITL_CITATIONS[region]` (e.g. `"SR 26-2 §3.2"` for US_FED) |
| `langfuse.trace.metadata.iso.control_id` | `A.8.4` |
| `langfuse.trace.metadata.iso.requirement` | `Human Oversight and Control` |
| `langfuse.trace.metadata.poam_ref` | `AI600-005` |

Override decisions are persisted to the Langfuse compliance project as scored
events, creating an immutable evidence trail for ISO 42001 §A.8.4 and AI 600-1
§2.5 compliance.

---

## SLA Requirements by Region

CAGE enforces different HITL resolution SLAs based on the active deployment
region (`CAGE_DEPLOYMENT_REGION`). The SLA hours are defined in
[`constants.py`](../../src/gateway/governance/constants.py)
(`HITL_SLA_HOURS` dict) and resolved at call time by
`get_hitl_sla_hours(region)` in
[`hitl_escalator.py`](../../src/gateway/governance/hitl_escalator.py):

| Region | SLA | Regulatory Authority |
|---|---|---|
| `US_FED` | **4 hours** | SR 26-2 §3.2 — Federal Reserve supervisory guidance on model risk management |
| `EU_ECB` | **2 hours** | DORA Art. 10 — ICT incident management for major incidents |
| `APAC_MAS` | **1 hour** | MAS FEAT §3.2 — Human oversight of AI decisions |
| *(default)* | **4 hours** | ISO 42001 §A.8.4 fallback |

The regulatory citation string for each region is returned by
`get_hitl_regulatory_citation(region)` (`HITL_CITATIONS` dict) and is stamped
on the OTel span at override time.

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
| `confidence.defer_floor` (0.70) ≤ score < 0.95 | `DEFER` (`CONFIDENCE_GREY_ZONE`) | DEFER — parked in the `DeferQueue` (`DeferReason.CONFIDENCE_GREY_ZONE`) for data hydration | No (automated hydration; token stays parked until it clears the floor or expires) |
| score < `confidence.defer_floor` (0.70) | `HITL` (`LOW_CONFIDENCE`) | REQUIRE_APPROVAL — parked in `DeferQueue` (`DeferReason.HITL_REQUIRED`) for human approval | **Yes** |

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
(0.5 + estimate.value × amount) > CAUSAL_LOCK_RISK_BOUNDARY  (0.95)
```

the request is escalated to human review. This condition indicates that the
causal effect of the proposed trade, combined with the trade amount, pushes
the system into a high-risk region of the causal model's state space.

Additional causal lock conditions that trigger human escalation:
- `PlaceboTreatmentRefuter` p-value < `CAUSAL_LOCK_P_VALUE_THRESHOLD` (0.05) — causal estimate is not robust
- Placebo effect magnitude > `CAUSAL_LOCK_PLACEBO_EFFECT_MAGNITUDE` (0.2) — spurious causal signal detected

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
   - `OVERRIDE` (`DeferQueue.approve`) — transitions the `DeferToken` to `DeferStatus.APPROVED`, stamps `approved_barrier_preview` from the server-stored `original_verdict_snapshot["barrier_preview"]` (never from caller input), and emits `hitl_override_audit_span()`
   - `UPHOLD` (`DeferQueue.reject`) — confirms the block; decision is logged
   - `DEFER` — escalates to senior reviewer; re-queued with extended SLA
6. **Single-commit execution (`execute_trade_action(..., deferred_id=...)` → `enforce_approved_governance` → `revalidate_post_hitl`):**
   On human approval, the advisor invokes `execute_trade_action(..., deferred_id=deferred_id)`
   ([`src/governed_financial_advisor/tools/trades.py`](../../src/governed_financial_advisor/tools/trades.py)).
   Inside [`src/gateway/server/governance_middleware.py`](../../src/gateway/server/governance_middleware.py),
   `enforce_approved_governance()` atomically consumes the quorum-approved `HITL_REQUIRED` token
   exactly once (`DeferQueue.consume_approval`, verifying action and canonical parameter SHA-256
   binding) and calls `SymbolicGovernor.revalidate_post_hitl(..., approved_barrier_preview=...)` in
   [`src/gateway/governance/governor/governor.py`](../../src/gateway/governance/governor/governor.py).
   Under `Profile.POST_HITL` (`stage_runs_under` in `pipeline.py`), the governor skips `ftra` and
   `confidence` (which the human reviewer resolved), re-evaluates Phase 1 (`stpa`, `bounding`,
   `opa`, `consensus`, `causal`, and under `EU_ECB` `fria`), and commits every claiming Phase 2
   barrier (`cbf`, `fiscal`, or `dose_barrier`) inside `ReservationScope`. If
   `approved_barrier_preview == PASS` at approval time but a live Phase 2 barrier now fails
   (`FAIL`), `revalidate_post_hitl()` refuses with `DENY` (`reason="APPROVAL_CONTEXT_DRIFT"`).
   The `GovernanceSeal` is minted, verified, and settled (`governor.settle(seal, executed=...)`)
   strictly inside `governance_middleware.py`; the advisor never receives a seal (POAM-2026-079).
7. **Audit record persisted:** Override decision stored in Langfuse compliance project.

---

## Scope Boundaries

Human oversight is **in scope** for:
- Financial trade decisions > $10,000 USD (FTRA out-of-envelope / consensus escalation)
- Controller-boundary FTRA escalations (`FTRA_REGISTERED_IRREVERSIBLE`, `FTRA_REGISTERED_EXTERNALLY_REVERSIBLE`, `FTRA_UNREGISTERED_ACTION`, `FTRA_MAGNITUDE_EXCEEDS_ENVELOPE`, `FTRA_CONFIDENCE_BELOW_ENVELOPE`) parked as `DeferReason.HITL_REQUIRED`
- Governance decisions with confidence < 0.70 (`LOW_CONFIDENCE`, `DeferReason.HITL_REQUIRED`)
- OPA policy `MANUAL_REVIEW` / `requires_hitl` decisions and EU AI Act Art. 27 `FRIA_EXTERNAL_HOLD` holds

Human oversight is **out of scope** for:
- Tier 1 keyword blocks (Aho-Corasick) — these are bright-line safety controls that are not overridable
- CBRN content blocks — these are immutable Cat-M controls (no override permitted without AO pre-approval)
- SC-8 TLS validation failures — infrastructure-level controls not subject to HITL
- Phase 1 or Phase 2 `ViolationKind.HARD` refusals (STPA unsafe control actions, CBF liquidity barrier breaches `CBF_BARRIER_VIOLATED`, causal gatekeeper `CAUSAL_CHECK_FAILED` rejections) — denied before reaching HITL (`hard_preview_denies_before_hitl`)
- `DeferReason.FTRA_IRREVERSIBLE_TERMINAL` tokens in `replay_evaluate()` — terminal-state tokens cannot be released via automated hydration replay

---

## Related Documents

- [`src/gateway/governance/hitl_escalator.py`](../../src/gateway/governance/hitl_escalator.py) — HITL escalation functions including `hitl_override_audit_span()`, `get_hitl_sla_hours()`, `get_hitl_regulatory_citation()`
- [`src/gateway/governance/defer_queue.py`](../../src/gateway/governance/defer_queue.py) — DeferQueue implementation (Redis db=1, noeviction, `_DEFAULT_TTL = 3600 * 4`)
- [`src/gateway/governance/constants.py`](../../src/gateway/governance/constants.py) — `HITL_SLA_HOURS` and `HITL_CITATIONS` dicts
- [`compliance/lula/lula-validation-ai600-human-ai-config.yaml`](../../compliance/lula/lula-validation-ai600-human-ai-config.yaml) — Lula validation manifest
- [`docs/POAM.md`](../POAM.md) — AI600-005 POAM item
