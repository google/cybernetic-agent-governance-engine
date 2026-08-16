# ISO/IEC 42001: Artificial Intelligence Management System (AIMS) Compliance

> **Last updated:** 2026-06-15 — Added jurisdiction separation principle; ISO 42001 is the universal baseline for all regions.

## Overview

This document maps the **Neuro-Cybernetic Governance** implementation to the clauses of **ISO/IEC 42001**. The architecture implements a **Continuous Compliance** model: NeMo and OPA handle live enforcement, Langfuse captures evidence, and **Lula** periodically audits both to generate OSCAL Assessment Results that serve as machine-readable proof for auditors.

> **Jurisdiction separation principle:** **ISO/IEC 42001:2023 is the sole universal governance baseline** for CAGE. Every clause mapping, Annex A control, and Lula validation in this document applies to **all deployment regions** (`US_FED`, `EU_ECB`, `APAC_MAS`). Jurisdiction-specific frameworks (SR 26-2, NIST AI 600-1, EU AI Act, GDPR, DORA, MAS FEAT, MAS Notice 655) are **additive layers** that extend — but never replace — the ISO 42001 baseline. They are activated exclusively by `CAGE_DEPLOYMENT_REGION` and impose no obligations on other regions. See [`docs/GOVERNANCE_CROSSWALK.md`](../cross-region/GOVERNANCE_CROSSWALK.md) for the full regional applicability matrix.

---

## Compliance Model: Continuous Audit ("Evidence-Loop")

Runtime Enforcement (NeMo + OPA)
↓ OTel spans tagged iso42001.control_id
Evidence Store (Langfuse)
↓ time-windowed aggregation (langfuse-bridge)
Lula Validation (Real-time CronJob every 6h)
↓ Deterministic OSCAL Assessment Result (signed via HMAC)
Feedback Loop (complianceAuditWorkflow → Langfuse compliance project)

---

## Clause Mapping

### Clause 6: Planning

- **6.1 Actions to address risks and opportunities:**
  - **Implementation:** The **Planner Agent (System 4)** generates execution plans that are explicitly analyzed for risk before execution.
  - **Code:** `src/governed_financial_advisor/agents/execution_analyst/`

### Clause 8: Operation

- **8.1 Operational planning and control:**
  - **Implementation:** The **Governance Gateway** acts as the operational control point, enforcing policies on all AI actions via the **8-tier governance pipeline** (FTRA pre-pipeline boundary gate plus 7 in-pipeline tiers via [`src/gateway/governance/symbolic_governor.py`](../../../src/gateway/governance/symbolic_governor.py)): NoDirectBind invariant → PII sanitization → CBF + OPA concurrent → Causal gatekeeper → Confabulation scoring → Consensus → FRIA zones.
  - **Code:** [`src/gateway/server/governance_middleware.py`](../../../src/gateway/server/governance_middleware.py)
- **8.2 AI Risk Assessment:**
  - **Implementation:** The **8-tier governance pipeline** (FTRA + 7 in-pipeline tiers) performs real-time risk assessment (STPA, CBF, causal SCM) on every tool call. OPA Rego policies enforce fiscal limits and RBAC. The Control Barrier Function provides a formal mathematical safety guarantee via `h(S(t+1)) ≥ (1−γ)·h(S(t))`.
  - **Code:** [`src/governed_financial_advisor/governance/policy/trade_governance.rego`](../../../src/governed_financial_advisor/governance/policy/trade_governance.rego), [`src/gateway/governance/cbf.py`](../../../src/gateway/governance/cbf.py)

### Clause 9: Performance Evaluation

- **9.1 Monitoring, measurement, analysis and evaluation:**
  - **Implementation (Runtime):** The **Evaluator Agent (System 3)** acts as the real-time monitor, racing against execution to detect anomalies.
  - **Code:** [`src/governed_financial_advisor/agents/evaluator/agent.py`](../../../src/governed_financial_advisor/agents/evaluator/agent.py)
  - **Implementation (Continuous Audit):** **Lula** validates each ISO 42001 control every 6 hours via the `compliance_bridge` API. Findings are expressed as **OSCAL Assessment Results** using a deterministic Python parser ([`oscal_parser.py`](../../../src/compliance_bridge/oscal_parser.py)) to ensure high-integrity evidence mapping.
  - **Lula Manifests:** `compliance/lula/`
  - **Bridge Service:** `src/compliance_bridge/`
  - **Telemetry:** OpenTelemetry spans tagged with `iso42001.control_id` flow to Langfuse. The bridge aggregates them into a `safety_rate` per control over a 24-hour window with a 48-hour staleness guard and a configurable startup grace period.
  - **Assessment State Integrity (CAGE v2.2.0):** Each OSCAL finding carries one of four states: `PASS`, `FAIL`, `NOT_APPLICABLE`, or `ERROR`. A scanner/collector failure ("fetch failed", timeout) maps to `ERROR` — **never** to `NOT_APPLICABLE`. This distinction is required by NIST SP 800-53A §3.2: evaluation errors must be flagged as Incomplete/Unknown so auditors can investigate the evidence gap. `ERROR` findings on critical controls (SC-4, A.9.2, A.8.4) trigger the same Slack/PagerDuty alert as explicit `FAIL` findings and score `0.0` in Langfuse. See [`docs/technical-report/06-COMPLIANCE-STANDARDS.md §5.5`](../../technical-report/06-COMPLIANCE-STANDARDS.md) for the full state table.

### Clause 10: Improvement

- **10.1 Nonconformity and corrective action:**
  - **Implementation (Immediate):** The **Interrupt Mechanism** (Redis-based) is an automated corrective action that stops nonconforming behavior immediately via the `trigger_safety_intervention` tool.
  - **Implementation (Audit-Driven):** The **complianceAuditWorkflow** (Mastra) ingests OSCAL findings back into Langfuse and fires Slack/PagerDuty alerts for critical control failures (A.9.2 Data Privacy, SC-4 Fiscal Limits).
  - **Code:** [`src/compliance_bridge/audit_workflow.py`](../../../src/compliance_bridge/audit_workflow.py)

---

## Annex A Control Mapping

| Control   | Description                | Enforcement Component                  | Lula Validation                                                           | Threshold                           | Critical Alert on ERROR? |
| --------- | -------------------------- | -------------------------------------- | ------------------------------------------------------------------------- | ----------------------------------- | ------------------------ |
| **A.4**   | Resource Management        | Token Quota Proxy (`CTRL_TQP_007`) — per-session step-count (≤12) and token (≤100,000) quota enforcement via Redis atomic Lua counters; fail-closed HTTP 429 | N/A (no manifest)                                                         | step_count ≤ `STEP_QUOTA_MAX`; token_count ≤ `TOKEN_QUOTA_MAX` | No |
| **A.5.2** | Social Impact Assessment   | NeMo output rail + Aho-Corasick Tier-1 | [`lula-validation-a52.yaml`](../../../compliance/lula/lula-validation-a52.yaml) | safety_rate ≥ 99%                   | No                       |
| **A.5.3** | Logging and Monitoring     | OTel spans → Langfuse (all tiers)      | [`lula-validation-a53.yaml`](../../../compliance/lula/lula-validation-a53.yaml) | safety_rate ≥ 98%                   | No                       |
| **A.9.2** | Data Transfer to Suppliers | Presidio PII masking (NeMo input rail) | [`lula-validation-a92.yaml`](../../../compliance/lula/lula-validation-a92.yaml) | safety_rate = 100% (zero tolerance) | **Yes** — CRITICAL_CONTROL |
| **SC-4**  | Fiscal Limits and RBAC     | `trade_governance.rego` (OPA)          | [`lula-validation-sc4.yaml`](../../../compliance/lula/lula-validation-sc4.yaml) | k8s label present                   | **Yes** — CRITICAL_CONTROL |
| **A.8.4** | AI System Operation Controls | HITL + Saga WAL; DEFER state machine | N/A (no manifest)                                                         | STPA UCA checks pass                | **Yes** — CRITICAL_CONTROL |

> **Note on `ERROR` state (CAGE v2.2.0):** A scanner/collector failure on any control produces an `ERROR` finding — not `NOT_APPLICABLE`. For the three `CRITICAL_CONTROL` entries above (A.9.2, SC-4, A.8.4), an `ERROR` finding triggers the same Slack/PagerDuty alert as an explicit `FAIL`. This ensures evidence gaps on the most sensitive controls are never silently hidden. See [`docs/technical-report/06-COMPLIANCE-STANDARDS.md §5.5`](../../technical-report/06-COMPLIANCE-STANDARDS.md) for the full four-state semantics table.

---

## OSCAL Component Definition

The machine-readable OSCAL Component Definition linking each control to its technical implementation and Lula validation is at:
[`compliance/oscal/component-definition.yaml`](../../../compliance/oscal/component-definition.yaml)

---

## Mathematical Safety Controls

This section documents the formal mathematical foundations of the CAGE governance kernel as they relate to ISO 42001 Annex A controls.

### CBF Condition and Barrier Function (A.6.1 — Risk Assessment)

The Control Barrier Function ([`src/gateway/governance/cbf.py`](../../../src/gateway/governance/cbf.py)) provides a formal proof of safety for the financial state machine:

- **Safe set:** `S = {x ∈ ℝⁿ : h(x) ≥ 0}`
- **Barrier function:** `h(x) = cash_balance − min_cash_balance`
- **Discrete-time CBF condition:** `h(S(t+1)) ≥ (1−γ)·h(S(t))` where `γ ∈ (0,1)`

If the CBF condition is satisfied at every time step, the system is mathematically guaranteed to remain in the safe set `S`. Any proposed trade that would violate the condition is denied before execution.

### 8-Tier Governance Pipeline (A.8.4 — AI System Operation Controls)

The 8-tier pipeline (FTRA + 7 in-pipeline tiers via [`src/gateway/governance/symbolic_governor.py`](../../../src/gateway/governance/symbolic_governor.py)) is the primary runtime enforcement mechanism for ISO 42001 A.8.4:

| Tier | Control | ISO 42001 Mapping |
|------|---------|-------------------|
| 1 — NoDirectBind | Structural tool-binding invariant | A.8.4 (operation controls) |
| 2 — PII sanitization | Presidio + regex scrubbing | A.9.2 (data transfer to suppliers) |
| 3 — CBF + OPA concurrent | Barrier function + policy engine | A.6.1 (risk assessment) |
| 4 — Causal gatekeeper | SCM + PlaceboTreatmentRefuter | A.6.1 (risk assessment) |
| 5 — Confabulation scoring | `risk_score = 1.0 − confidence` | A.5.2 (social impact assessment) |
| 6 — Consensus | ≥$10k trades, 30s timeout, multi-model quorum | A.8.4 (operation controls) |
| 7 — FRIA zones | `FRIA_ZONE_ALLOW=0.95`, `FRIA_ZONE_DEFER=0.70` | A.6.1 (risk assessment) |

### FRIA Zone Thresholds (A.6.1)

The FRIA zone thresholds define three access-control tiers for AI-generated recommendations:

| Score Range | Zone | Action |
|-------------|------|--------|
| ≥ 0.95 | `FRIA_ZONE_ALLOW` | Async attestation — no blocking |
| 0.70 – 0.95 | `FRIA_ZONE_DEFER` | Synchronous blocking gate — HITL required |
| < 0.70 | BLOCK | Hard deny — no override path |

### Confabulation Risk Formula (A.5.2)

The confabulation scorer ([`src/gateway/governance/confabulation_scorer.py`](../../../src/gateway/governance/confabulation_scorer.py)) computes:

```
risk_score = 1.0 − confidence
```

A `risk_score` above the configured threshold triggers a `DEFER` (HITL escalation) or `DENY` decision. This maps to ISO 42001 A.5.2 (social impact assessment) by ensuring that low-confidence AI outputs are never autonomously executed.

### Causal Marginal Risk Boundary (A.6.1)

The causal gatekeeper ([`src/gateway/governance/causal_gatekeeper.py`](../../../src/gateway/governance/causal_gatekeeper.py)) applies a marginal risk boundary:

```
(0.5 + estimate.value × amount) > 0.95  →  DENY
```

The `PlaceboTreatmentRefuter` runs 50 simulations with significance threshold p < 0.05 and minimum effect size |eff| > 0.2 to validate causal estimates before they are used in the boundary check.

### Fiscal Limit Parameters (A.4 — Resource Management)

| Parameter | Value | Enforcement |
|-----------|-------|-------------|
| Daily cap | $500,000 USD (integer cents) | [`fiscal_limit_guard.py`](../../../src/gateway/governance/fiscal_limit_guard.py) |
| Window | 86,400 seconds | Redis key TTL |
| Retry policy | Exponential backoff: `_RETRY_BASE_MS × 2^attempt` | Atomic WATCH/MULTI/EXEC |
| Fail mode | Fail-closed | Redis error → rejected token |

---

## System Description (Annex A)

- **A.1 AI System Lifecycle:** Managed via the LangGraph workflow ([`src/governed_financial_advisor/graph/graph.py`](../../../src/governed_financial_advisor/graph/graph.py)).
- **A.2 Data Quality:** Enforced via `GeneratedSTPAValidator` checks on data inputs (e.g., latency thresholds, order volume fractions). The 8-tier governance pipeline (FTRA + 7 in-pipeline tiers via [`src/gateway/governance/symbolic_governor.py`](../../../src/gateway/governance/symbolic_governor.py)) provides the primary runtime enforcement layer.
- **A.5.2/A.5.3/A.9.2/SC-4:** Automatically validated every 6 hours by the Lula CronJob ([`deployment/k8s/lula-cron.yaml`](../../../deployment/k8s/lula-cron.yaml)).
