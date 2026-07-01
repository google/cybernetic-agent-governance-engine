# Human Oversight Scope — CAGE v0.1.0

**Document:** AI600-005 / NIST AI 600-1 §2.5 / ISO 42001 §A.8.4
**Date:** 2026-06-23
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

| Trigger | Code Location | Threshold |
|---|---|---|
| **Consensus threshold exceeded** | `hitl_escalator.py` `should_escalate_for_consensus()` | Trade amount > $10,000 USD |
| **Model confidence low** | `hitl_escalator.py` `should_escalate_for_confidence()` | Confidence < 0.95 (CTRL_AGT_001) |
| **CausalGatekeeper block** | `governance_middleware.py` | World-model p-value < 0.05 |
| **OPA MANUAL_REVIEW decision** | `trade_governance.rego` | OPA policy returns MANUAL_REVIEW |
| **Governance confidence low** | `consensus.py` | ConsensusEngine self-reported confidence < threshold |

---

## DeferQueue Schema

Escalation records written to the DeferQueue have the following schema:

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

---

## Human Override Audit Trail (AI600-005)

When a human reviewer resolves an escalation, the `hitl_override_audit_span()` function in `hitl_escalator.py` emits a structured OTel span with the following attributes:

| OTel Attribute | Description |
|---|---|
| `hitl.reviewer_id` | Pseudonymised reviewer identifier (e.g. `reviewer-123`) |
| `hitl.decision` | `OVERRIDE` \| `UPHOLD` \| `DEFER` |
| `hitl.reason` | Free-text justification (≤500 chars) |
| `hitl.original_escalation_reason` | `EscalationReason.value` that triggered escalation |
| `hitl.override_ts` | ISO 8601 UTC timestamp of the override decision |
| `hitl.trace_id` | Langfuse trace ID of the governed request |
| `langfuse.trace.metadata.iso.control_id` | `A.8.4` |
| `langfuse.trace.metadata.iso.requirement` | `Human Oversight and Control` |
| `langfuse.trace.metadata.poam_ref` | `AI600-005` |

Override decisions are persisted to the Langfuse compliance project as scored events, creating an immutable evidence trail for ISO 42001 §A.8.4 and AI 600-1 §2.5 compliance.

---

## SLA Requirements by Region

CAGE enforces different HITL resolution SLAs based on the active deployment region (`CAGE_DEPLOYMENT_REGION`):

| Region | SLA | Regulatory Authority |
|---|---|---|
| `US_FED` | **4 hours** | SR 26-2 §3.2 — Federal Reserve supervisory guidance on model risk management |
| `EU_ECB` | **2 hours** | DORA Art. 10 — ICT incident management for major incidents |
| `APAC_MAS` | **1 hour** | MAS FEAT §3.2 — Human oversight of AI decisions |
| *(default)* | **4 hours** | ISO 42001 §A.8.4 fallback |

The SLA is returned by `get_hitl_sla_hours(region)` in `hitl_escalator.py`.

> [!IMPORTANT]
> SR 26-2 §3.2 (4-hour SLA) is a US Federal Reserve requirement that has no legal force outside `US_FED` deployments. EU_ECB and APAC_MAS deployments must use their respective regional SLAs.

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
6. **Audit record persisted:** Override decision stored in Langfuse compliance project

---

## Scope Boundaries

Human oversight is **in scope** for:
- Financial trade decisions > $10,000 USD
- Governance decisions with confidence < 0.95
- CausalGatekeeper world-model rejections
- OPA policy MANUAL_REVIEW decisions

Human oversight is **out of scope** for:
- Tier 1 keyword blocks (Aho-Corasick) — these are bright-line safety controls that are not overridable
- CBRN content blocks — these are immutable Cat-M controls (no override permitted without AO pre-approval)
- SC-8 TLS validation failures — infrastructure-level controls not subject to HITL

---

## Related Documents

- `src/gateway/governance/hitl_escalator.py` — HITL escalation functions including `hitl_override_audit_span()`
- `src/gateway/governance/defer_queue.py` — DeferQueue implementation
- `compliance/lula/lula-validation-ai600-human-ai-config.yaml` — Lula validation manifest
- `docs/POAM_US_FED.md` — AI600-005 POAM item
