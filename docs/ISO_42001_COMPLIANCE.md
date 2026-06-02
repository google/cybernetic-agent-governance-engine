# ISO/IEC 42001: Artificial Intelligence Management System (AIMS) Compliance

## Overview

This document maps the **Neuro-Cybernetic Governance** implementation to the clauses of **ISO/IEC 42001**. The architecture implements a **Continuous Compliance** model: NeMo and OPA handle live enforcement, Langfuse captures evidence, and **Lula** periodically audits both to generate OSCAL Assessment Results that serve as machine-readable proof for auditors.

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
  - **Code:** [`src/governed_financial_advisor/agents/execution_analyst/`](../src/governed_financial_advisor/agents/execution_analyst/)

### Clause 8: Operation

- **8.1 Operational planning and control:**
  - **Implementation:** The **TypeScript Governance Gateway** acts as the operational control point, enforcing policies on all AI actions via three-tier semantic shielding.
  - **Code:** [`src/gateway/src/governance/middleware/stpaGovernanceMiddleware.ts`](../src/gateway/src/governance/middleware/stpaGovernanceMiddleware.ts)
- **8.2 AI Risk Assessment:**
  - **Implementation:** The **Symbolic Governor** performs real-time risk assessment (STPA, CBF) on every tool call. OPA Rego policies enforce fiscal limits and RBAC.
  - **Code:** [`src/governed_financial_advisor/governance/policy/trade_governance.rego`](../src/governed_financial_advisor/governance/policy/trade_governance.rego)

### Clause 9: Performance Evaluation

- **9.1 Monitoring, measurement, analysis and evaluation:**
  - **Implementation (Runtime):** The **Evaluator Agent (System 3)** acts as the real-time monitor, racing against execution to detect anomalies.
  - **Code:** [`src/governed_financial_advisor/agents/evaluator/agent.py`](../src/governed_financial_advisor/agents/evaluator/agent.py)
  - **Implementation (Continuous Audit):** **Lula** validates each ISO 42001 control every 6 hours via the `langfuse-bridge` compliance API. Findings are expressed as **Signed OSCAL Assessment Results** using a deterministic TypeScript parser to ensure high-integrity evidence mapping.
  - **Lula Manifests:** [`compliance/lula/`](../compliance/lula/)
  - **Bridge Service:** [`src/langfuse-bridge/`](../src/langfuse-bridge/)
  - **Telemetry:** OpenTelemetry spans tagged with `iso42001.control_id` flow to Langfuse. The bridge aggregates them into a `safety_rate` per control over a 24-hour window with a 48-hour staleness guard and a configurable startup grace period.

### Clause 10: Improvement

- **10.1 Nonconformity and corrective action:**
  - **Implementation (Immediate):** The **Interrupt Mechanism** (Redis-based) is an automated corrective action that stops nonconforming behavior immediately via the `trigger_safety_intervention` tool.
  - **Implementation (Audit-Driven):** The **complianceAuditWorkflow** (Mastra) ingests OSCAL findings back into Langfuse and fires Slack/PagerDuty alerts for critical control failures (A.9.2 Data Privacy, SC-4 Fiscal Limits).
  - **Code:** [`src/langfuse-bridge/src/workflows/complianceAuditWorkflow.ts`](../src/langfuse-bridge/src/workflows/complianceAuditWorkflow.ts)

---

## Annex A Control Mapping

| Control   | Description                | Enforcement Component                  | Lula Validation                                                           | Threshold                           |
| --------- | -------------------------- | -------------------------------------- | ------------------------------------------------------------------------- | ----------------------------------- |
| **A.5.2** | Social Impact Assessment   | NeMo output rail + Aho-Corasick Tier-1 | [`lula-validation-a52.yaml`](../compliance/lula/lula-validation-a52.yaml) | safety_rate ≥ 99%                   |
| **A.5.3** | Logging and Monitoring     | OTel spans → Langfuse (all tiers)      | [`lula-validation-a53.yaml`](../compliance/lula/lula-validation-a53.yaml) | safety_rate ≥ 98%                   |
| **A.9.2** | Data Transfer to Suppliers | Presidio PII masking (NeMo input rail) | [`lula-validation-a92.yaml`](../compliance/lula/lula-validation-a92.yaml) | safety_rate = 100% (zero tolerance) |
| **SC-4**  | Fiscal Limits and RBAC     | `trade_governance.rego` (OPA)          | [`lula-validation-sc4.yaml`](../compliance/lula/lula-validation-sc4.yaml) | k8s label present                   |

---

## OSCAL Component Definition

The machine-readable OSCAL Component Definition linking each control to its technical implementation and Lula validation is at:
[`compliance/oscal/component-definition.yaml`](../compliance/oscal/component-definition.yaml)

---

## System Description (Annex A)

- **A.1 AI System Lifecycle:** Managed via the LangGraph workflow ([`src/governed_financial_advisor/graph/graph.py`](../src/governed_financial_advisor/graph/graph.py)).
- **A.2 Data Quality:** Enforced via `STPAValidator` checks on data inputs (e.g., Latency thresholds).
- **A.5.2/A.5.3/A.9.2/SC-4:** Automatically validated every 6 hours by the Lula CronJob ([`deployment/k8s/lula-cron.yaml`](../deployment/k8s/lula-cron.yaml)).
