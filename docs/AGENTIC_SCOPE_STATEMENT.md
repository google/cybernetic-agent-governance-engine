# Agentic Scope Statement

**System:** Cybernetic AI Governance Engine (CAGE) — Governed Financial Advisor (GFA)
**Version:** v0.1.0
**Date:** 2026-07-01
**Authority:** AI 600-1 §2.5.1, SR 26-2 §3.1
**POAM Reference:** AI600-004

---

## 1. System Identification

| Field | Value |
|---|---|
| System Name | Governed Financial Advisor (GFA) |
| System Owner | CAGE Platform Team |
| GCP Project | YOUR_GCP_PROJECT_ID |
| Cluster | cage-dev (GKE, us-central1-a) |
| Namespace | governance-stack |
| Deployment Region | US_FED (primary), EU_ECB, APAC_MAS |

---

## 2. Authorized Action Space (AI 600-1 §2.5.1)

The GFA agent is authorized to perform the following actions within its defined scope:

### 2.1 Permitted Tool Calls

| Tool | Description | Constraint |
|---|---|---|
| `get_portfolio` | Retrieve portfolio holdings | Read-only; no state mutation |
| `get_market_data` | Fetch real-time market prices | Read-only; external API |
| `analyze_risk` | Compute portfolio risk metrics | Computation only |
| `execute_trade` | Submit a trade order | Requires HITL approval when amount_usd > $10,000 |
| `explain_decision` | Generate explainability report | Read-only; audit artifact |
| `evaluate_compliance` | Run OPA policy evaluation | Read-only; governance check |

### 2.2 Prohibited Actions

- Direct database writes outside approved tool interfaces
- Exfiltration of PII or portfolio data to unapproved endpoints
- Bypassing the CAGE Gateway HMAC routing seal
- Executing trades without ConsensusEngine approval above threshold
- Accessing resources outside the `governance-stack` namespace without cross-namespace proxy

---

## 3. Agentic Boundaries (SR 26-2 §3.1)

### 3.1 Human-in-the-Loop (HITL) Escalation Triggers

Per `config/thresholds/governance_thresholds.json`:

- **Trade amount > $10,000 USD**: Mandatory HITL approval via `hitl_escalator`
- **Risk score > 0.8**: Escalation to human reviewer
- **Consensus disagreement**: When fast model and reasoning model diverge beyond threshold
- **OPA policy DENY**: Automatic block; human review required before retry

### 3.2 Causal Gatekeeper Constraints

The `CausalGatekeeper` enforces the authorized action space at runtime:
- Blocks tool calls with `amount == 0` (no-op guard)
- Validates action type against the permitted tool list
- Logs all blocked actions to the audit trail (Langfuse + Redis)

### 3.3 Routing Seal Enforcement

All inter-service requests are signed with an HMAC routing seal (`CAGE_ROUTING_SEAL_SECRET`).
Unsigned requests return HTTP 403. The seal includes:
- Action type
- Payload hash
- Timestamp (replay protection)

---

## 4. Recursive Governance Risk (AI 600-1 §2.1, §2.5.3)

The GFA architecture introduces a **recursive governance risk**: the AI governance layer itself
(gateway, ConsensusEngine, OPA policy engine) relies on LLM inference to make governance
decisions. If the LLM confabulates or produces incorrect governance outputs, the governance
layer may fail to block unsafe actions — or may incorrectly block safe ones.

### 4.1 Mitigations

| Risk | Mitigation |
|---|---|
| Recursive confabulation in governance | ConsensusEngine cross-validates fast model (Qwen2.5-7B) against reasoning model (DeepSeek-R1) |
| Governance layer LLM failure | OPA policy engine provides deterministic fallback (no LLM dependency) |
| Routing seal bypass | HMAC seal enforced at gateway; unsigned requests return HTTP 403 |
| HITL escalation failure | Threshold-based escalation is deterministic (amount_usd > $10,000) |
| Audit trail manipulation | Immutable audit log in Redis + Langfuse; KMS-signed evidence |

### 4.2 ConsensusEngine Design

The `ConsensusEngine` (`src/gateway/governance/consensus.py`) mitigates recursive governance
risk by requiring agreement between two independent model paths before high-value actions
proceed. Disagreement triggers HITL escalation per AI 600-1 §2.5.3.

---

## 5. Compliance Posture

| Framework | Status | Reference |
|---|---|---|
| ISO/IEC 42001 | Implemented | `compliance/lula/lula-validation-a52.yaml` |
| NIST SP 800-53 | Implemented (≥45% coverage) | `compliance/lula/lula-validation-nist-*.yaml` |
| CSA AARM | Implemented | `compliance/lula/lula-validation-aarm-vectors.yaml` |
| EU AI Act | Implemented | `compliance/lula/lula-validation-eu-fria.yaml` |
| MAS FEAT | Implemented | `compliance/postures/apac_mas/` |
| SR 26-2 | Implemented | Telemetry suppression sentinel active |

---

## 5. Data Residency

| Region | Data Path | Constraint |
|---|---|---|
| US_FED | us-central1 | NIST SP 800-53 data boundary |
| EU_ECB | europe-west1 | GDPR Art. 44 / EU AI Act |
| APAC_MAS | asia-southeast1 | MAS TRM §4.2 / MAS Notice 655 |

All storage paths are gated on `CAGE_DEPLOYMENT_REGION` environment variable.

---

## 6. ATO Package References (AI 600-1 §2.5.4)

- **OSCAL SSP:** `compliance/oscal/`
- **POAM:** `docs/POAM.md`
- **STPA Analysis:** `compliance/stpa/`
- **Lula Validations:** `compliance/lula/`
- **OPA Policies:** `compliance/postures/us_fed/opa/`
- **GDPR DPIA:** `docs/GDPR_DPIA.md`
- **FRIA Attestation:** `docs/FRIA_ATTESTATION.md`

---

*This document satisfies AI 600-1 §2.5.1 (Agentic Scope Statement) and SR 26-2 §3.1 (Model Risk Management — Authorized Action Space) requirements for the CAGE ATO package.*
