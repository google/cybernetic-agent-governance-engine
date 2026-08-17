# Human Oversight Scope — CAGE v3.0.0

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
| **CausalGatekeeper block** | `causal_gatekeeper.py` `causal_safety_check()` | World-model p-value < `get_causal_lock_p_value_threshold()` (0.05) or marginal risk boundary exceeded |
| **OPA MANUAL_REVIEW decision** | `src/governed_financial_advisor/governance/policy/trade_governance.rego` | OPA policy (package `trade.governance`) returns `"MANUAL_REVIEW"` |
| **Governance confidence low** | `consensus.py` `ConsensusEngine` | ConsensusEngine self-reported confidence < threshold |
| **POAM-TIER2-001 structural flag** | `symbolic_governor.py` `_run_checks()` Tier 2 | Structural corroboration heuristic: STPA violation count ≥ 1 AND OPA margin < threshold; overrides the model-supplied confidence signal |
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

FTRA-parked tokens use `DeferReason.FTRA_IRREVERSIBLE_TERMINAL` from
[`defer_queue.py`](../../src/gateway/governance/defer_queue.py) — these are a
distinct category from HITL escalation records and are not overridable by
reviewers.

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

**Source:** [`src/gateway/governance/symbolic_governor.py`](../../src/gateway/governance/symbolic_governor.py)

The `SymbolicGovernor` Tier 6b FRIA zone classification determines whether a
governance decision is handled automatically or escalated to human review. The
thresholds are env-overridable constants (`FRIA_ZONE_ALLOW`, `FRIA_ZONE_DEFER`)
enforced at runtime:

### FRIA Zone Classification

| Score | Zone | Disposition | Human Required? |
|---|---|---|---|
| score ≥ `FRIA_ZONE_ALLOW` (0.95) | ALLOW | Async attestation — automated pass | No |
| `FRIA_ZONE_DEFER` (0.70) ≤ score < 0.95 | DEFER | Synchronous blocking gate — human review | **Yes** |
| score < `FRIA_ZONE_DEFER` (0.70) | BLOCK | Hard block | **Yes** |

The DEFER zone maps directly to the DeferQueue escalation path. A DEFER decision
writes an escalation record to the queue and blocks the request until a human
reviewer resolves it within the applicable SLA (see
[SLA Requirements by Region](#sla-requirements-by-region)).

### Consensus Requirement

Trades with `amount ≥ $10,000 USD` require multi-critic consensus (Tier 5)
before reaching the FRIA zone classifier. The consensus engine
([`consensus.py`](../../src/gateway/governance/consensus.py)) invokes multiple
LLM critics with a **30-second hard timeout** per critic call. Unanimity is
required; a single dissenting critic escalates the decision to human review via
the DeferQueue. Background audit logging for consensus decisions is handled by
`_AUDIT_QUEUE` (`asyncio.Queue(maxsize=1000)`) and a background audit worker
task.

### Causal Lock Escalation

**Source:** [`src/gateway/governance/causal_gatekeeper.py`](../../src/gateway/governance/causal_gatekeeper.py)

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
uses synchronous Redis helpers (`_causal_cache_get_sync` /
`_causal_cache_set_sync`) that are safe to call from `asyncio.to_thread`
worker pools. Cache TTL is `CAUSAL_CACHE_TTL_SECONDS` (60 s);
telemetry staleness limit is `TELEMETRY_MAX_STALENESS_SECONDS` (300 s).

---

## Reviewer Workflow

1. **Alert received:** DeferQueue Pub/Sub message triggers reviewer notification (email/Slack/PagerDuty)
2. **Review window starts:** SLA timer starts from `escalated_at` timestamp
3. **Reviewer accesses:** DeferQueue UI or API endpoint `GET /v1/hitl/queue/{trace_id}`
4. **Reviewer evaluates:** Langfuse trace, governance decision rationale, amount/confidence
5. **Reviewer decides:**
   - `OVERRIDE` — approve the previously blocked action; override is logged via `hitl_override_audit_span()`
   - `UPHOLD` — confirm the block; decision is logged
   - `DEFER` — escalate to senior reviewer; re-queued with extended SLA
6. **Post-HITL re-validation:** On human approval, `revalidate_post_hitl()` in
   [`symbolic_governor.py`](../../src/gateway/governance/symbolic_governor.py)
   re-runs **only Tiers 2 and 4** (CBF + OPA) — the tiers most likely to drift
   during a HITL review window (cash balance and policy state may have changed).
   STPA, consensus, causal, and FRIA tiers are **not** re-run.
7. **Audit record persisted:** Override decision stored in Langfuse compliance project

---

## Scope Boundaries

Human oversight is **in scope** for:
- Financial trade decisions > $10,000 USD
- Governance decisions with confidence < 0.95
- CausalGatekeeper world-model rejections
- OPA policy MANUAL_REVIEW decisions
- POAM-TIER2-001 structural corroboration flags (STPA violation + OPA margin below threshold)

Human oversight is **out of scope** for:
- Tier 1 keyword blocks (Aho-Corasick) — these are bright-line safety controls that are not overridable
- CBRN content blocks — these are immutable Cat-M controls (no override permitted without AO pre-approval)
- SC-8 TLS validation failures — infrastructure-level controls not subject to HITL
- `DeferReason.FTRA_IRREVERSIBLE_TERMINAL` parked tokens — FTRA terminal-state tokens cannot be released by a HITL reviewer

---

## Related Documents

- [`src/gateway/governance/hitl_escalator.py`](../../src/gateway/governance/hitl_escalator.py) — HITL escalation functions including `hitl_override_audit_span()`, `get_hitl_sla_hours()`, `get_hitl_regulatory_citation()`
- [`src/gateway/governance/defer_queue.py`](../../src/gateway/governance/defer_queue.py) — DeferQueue implementation (Redis db=1, noeviction, `_DEFAULT_TTL = 3600 * 4`)
- [`src/gateway/governance/constants.py`](../../src/gateway/governance/constants.py) — `HITL_SLA_HOURS` and `HITL_CITATIONS` dicts
- [`compliance/lula/lula-validation-ai600-human-ai-config.yaml`](../../compliance/lula/lula-validation-ai600-human-ai-config.yaml) — Lula validation manifest
- [`docs/POAM.md`](../POAM.md) — AI600-005 POAM item
