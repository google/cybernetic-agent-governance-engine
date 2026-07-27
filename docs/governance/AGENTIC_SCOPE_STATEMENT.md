# CAGE Agentic Scope Statement

**Authority**: NIST AI 600-1 §2.5.1, §2.5.4 | SR 26-2 §3.1 | EO 14110 §4.2
**Version**: 2.1.0
**Date**: 2026-07-27

---

## 1. Authorized Action Space

The Cybernetic Governance Engine (CAGE) `governed-financial-advisor` is authorized to
perform the following actions on behalf of authenticated users:

| Action | Authorization | Constraint |
|---|---|---|
| Read market data | ✅ Authorized | Read-only; no write to external systems |
| Generate advisory text | ✅ Authorized | Subject to NeMo guardrails and OPA policy |
| Query portfolio state | ✅ Authorized | Read-only via `get_portfolio` tool |
| Retrieve earnings reports | ✅ Authorized | Read-only via `get_market_data` tool |
| Execute trades | ⛔ **NOT authorized** | No direct trade execution; advisory only |
| Transfer funds | ⛔ **NOT authorized** | Outside authorized action space |
| Modify account settings | ⛔ **NOT authorized** | Outside authorized action space |
| Access external APIs | ⛔ **NOT authorized** | Except pre-approved market data endpoints |

### 1.1 Scope Limitation Enforcement

The authorized action space is enforced at three independent layers:

1. **OPA Policy Engine** (`src/gateway/governance/langgraph_harness/opa_node_factory.py`):
   Evaluates every tool call against `config/opa/system_authz.rego`. Any tool not
   explicitly listed in the `allowed_tools` set is denied with a `GovernanceError`.

2. **Routing Seal** (`src/gateway/governance/routing_seal.py`):
   Every approved governance decision is sealed with an HMAC-SHA256 token
   (`GOVERNANCE_SALT` key, ≥64 chars). Downstream actuators MUST verify the seal
   before executing any action. Seal TTL: 30 seconds (`GOVERNANCE_SEAL_TTL_S`).

3. **CausalGatekeeper** (`src/gateway/governance/causal_gatekeeper.py`):
   Performs DoWhy causal inference + placebo refutation before any high-stakes action.
   Fails closed when the world-model is untrustworthy (p-value < 0.05 or placebo
   effect > 0.2).

---

## 2. Human Oversight Boundaries

### 2.1 Consensus Threshold

Per `config/thresholds/US_FED_BASELINE.json` → `consensus.threshold_usd`:

- **Threshold**: USD 10,000
- **Enforcement**: `ConsensusEngine` (`src/gateway/governance/consensus.py`)
- **Behavior**: Any advisory action involving amounts > USD 10,000 triggers a
  two-critic consensus check (Risk Manager + Compliance Officer personas on
  distinct model backends). A split vote or unanimous ERROR escalates to HITL.

### 2.2 Confidence Threshold

Per `config/thresholds/US_FED_BASELINE.json` → `confidence.min_trade_confidence`:

- **Threshold**: 0.95 (95%)
- **Enforcement**: `CTRL_AGT_001` via OPA `system_authz.rego`
- **Behavior**: Any LLM response with `confidence < 0.95` is blocked and logged
  as a confabulation event via `confabulation_scorer.py`.

### 2.3 HITL Escalation Path

When the consensus threshold is exceeded or confidence is below threshold, the
`hitl_escalator.py` module routes the request to the human review queue:

1. `EscalationRequest` is created with `reason`, `amount_usd`, and `confidence`
2. Escalation record is written to `defer_queue` (Redis db=1, `noeviction` policy)
3. Compliance review team receives the escalation via the configured queue
4. SLA: escalations must be resolved within 4 hours (SR 26-2 §3.2)

### 2.4 Override Audit Trail

All governance overrides and escalations are logged to the WORM ledger via
`src/gateway/governance/uca_logger.py`:

- **Storage**: GCS WORM bucket (`OSCAL_S3_BUCKET_US_FED`, `us-central1`)
- **Signing**: KMS-signed (`KMSGovernanceSigner`, US_FED key ring)
- **Retention**: 90 days minimum (FISMA AU-11)
- **Format**: ISO 42001 Clause 6.1 UCA records (YAML, cryptographically signed)

---

## 3. Inter-Agent Trust Model

### 3.1 Trusted Orchestrator

The CAGE gateway (`src/gateway/server/hybrid_server.py`) is the **sole trusted
orchestrator**. No peer-to-peer agent calls are permitted without routing seal
verification.

### 3.2 CAGE-003 Agent Registry (v2.1.0)

The CAGE-003 Agent Registry (`src/gateway/governance/ingress/agent_registry_adapter.py`)
maintains a SPIFFE trust-domain catalog of all authorized agents. Each registered
agent entry includes:

- **SPIFFE SVID**: `spiffe://cage.local/<service-name>` — cryptographic identity
- **Allowed tools**: enumerated set of tool names the agent may invoke
- **Trust level**: `INTERNAL` | `DOWNSTREAM` | `EXTERNAL`
- **Region scope**: `US_FED` | `EU_ECB` | `APAC_MAS` | `ALL`

The registry is loaded at gateway startup and consulted by the OPA agent catalog
policy (`config/opa/agent_catalog.json`). Any agent not present in the registry
is denied at the Envoy ext_authz boundary (`src/gateway/server/agent_gateway_adapter.py`)
before reaching the governance kernel.

### 3.3 Trust Hierarchy

```
CAGE Gateway (trusted orchestrator)
  ├── ConsensusEngine (internal — same trust boundary)
  ├── CausalGatekeeper (internal — same trust boundary)
  ├── NeMo Guardrails (internal — same trust boundary)
  ├── Agent Registry (CAGE-003 — SPIFFE trust-domain catalog)
  └── governed-financial-advisor (downstream — requires routing seal + SPIFFE SVID)
        └── Market Data API (external — read-only, pre-approved)
```

### 3.3 Inter-Agent Call Requirements

Any call from the `governed-financial-advisor` to an external service MUST:

1. Present a valid routing seal (HMAC-SHA256, `GOVERNANCE_SALT` key)
2. Have passed OPA policy evaluation (`ALLOW` decision)
3. Have passed the CausalGatekeeper check
4. Be within the authorized action space (§1 above)

Calls that fail any of these checks raise `SymbolicGovernorViolation` and are
logged to the UCA WORM ledger.

### 3.4 No Peer-to-Peer Agent Calls

CAGE does not implement peer-to-peer agent communication. All inter-component
calls are mediated by the gateway. This eliminates the NIST AI 600-1 §2.5.3 risk
of unverified inter-agent trust propagation.

---

## 4. Scope Limitation Enforcement Mechanisms

| Mechanism | File | NIST AI 600-1 Control |
|---|---|---|
| OPA policy evaluation | `src/gateway/governance/langgraph_harness/opa_node_factory.py` | §2.5.1 |
| Routing seal verification | `src/gateway/governance/routing_seal.py` | §2.5.4 |
| CausalGatekeeper | `src/gateway/governance/causal_gatekeeper.py` | §2.3 |
| ConsensusEngine threshold | `src/gateway/governance/consensus.py` | §2.5.2 |
| HITL escalator | `src/gateway/governance/hitl_escalator.py` | §2.5.2 |
| Confabulation scorer | `src/gateway/governance/confabulation_scorer.py` | §2.1 |
| Prompt injection detector | `src/gateway/governance/prompt_injection_detector.py` | §2.3 |
| NeMo CBRN rails | `src/gateway/governance/nemo/colang/cbrn_rails.co` | §2.6 |

---

## 5. Override Audit Trail

All governance decisions (ALLOW, BLOCK, ESCALATE) are recorded in the UCA WORM
ledger via `src/gateway/governance/uca_logger.py`. The audit trail includes:

- `compliance_event_id`: UUID v4 prefixed with `UCA-`
- `timestamp`: ISO 8601 UTC
- `uca_type`: `quota_exceeded` | `prompt_injection` | `pii_sanitization` | `hitl_escalation`
- `agent_id`: authenticated agent identifier
- `block_reason`: human-readable reason for the governance decision
- `cryptographic_signature`: KMS-signed (production) or HMAC-SHA256 stub (test)
- `deployment_region`: `US_FED` | `EU_ECB` | `APAC_MAS` (enforces data residency)
- `worm_path`: GCS path for the signed record

---

## 6. Recursive Governance Risk

The `ConsensusEngine` uses LLM inference to govern LLM outputs — creating a
recursive governance risk where NIST AI 600-1 confabulation risks in the governance
layer propagate to the governed system.

### 6.1 Mitigation

The `governance_layer_confidence_check` in `consensus.py` applies the same
`CONFIDENCE_MIN_SCORE` threshold (0.95) to the ConsensusEngine's own LLM calls.
If the governance LLM call has `confidence < 0.95`, the request is escalated to
HITL rather than silently allowed.

### 6.2 Residual Risk

The ConsensusEngine uses two distinct model backends (DeepSeek-R1 for Risk Manager,
Llama 3.1 for Compliance Officer) to reduce correlated failure risk. However, both
models share the same training data distribution, which means correlated confabulation
on novel financial scenarios remains a residual risk.

**Compensating control**: The CausalGatekeeper provides a non-LLM causal inference
check that is independent of the LLM confidence scores.

---

## 6b. FTRA Commencement Reachability Gate (v2.1.0)

The FTRA Commencement Reachability Gate (`src/gateway/governance/ftra/`) enforces
that no financial transaction advisory workflow can commence unless the agent's
LangGraph state graph contains a reachable path from the start node to a
`HUMAN_APPROVED` terminal node. This is a **pre-execution structural check** —
it runs before any LLM inference.

| Module | Role |
|---|---|
| [`ftra/classifier.py`](../../src/gateway/governance/ftra/classifier.py) | Classifies graph nodes by type (start, terminal, HITL, advisory) |
| [`ftra/graph_analyzer.py`](../../src/gateway/governance/ftra/graph_analyzer.py) | Performs reachability analysis; raises `FTRAViolation` if no HITL path exists |
| [`ftra/models.py`](../../src/gateway/governance/ftra/models.py) | `FTRAResult` Pydantic model with `reachable`, `path`, and `violation_reason` fields |
| [`ftra/node_factory.py`](../../src/gateway/governance/ftra/node_factory.py) | LangGraph node factory — same pattern as `langgraph_harness/` |
| [`ftra_reachability.py`](../../src/gateway/governance/ftra_reachability.py) | Top-level entry point; called by `SymbolicGovernor` at Tier 0 |

**Scope enforcement**: The FTRA gate is a mandatory pre-condition for the
`governed-financial-advisor` scope. Any graph that lacks a reachable HITL path
is rejected before the authorized action space (§1) is evaluated.

---

## 7. SR 26-2 Compliance Evidence

| SR 26-2 Requirement | CAGE Implementation | Evidence |
|---|---|---|
| §2.5.1 Authorized action space | OPA policy + routing seal | `opa_node_factory.py`, `routing_seal.py` |
| §2.5.2 Human oversight | ConsensusEngine + HITL escalator | `consensus.py`, `hitl_escalator.py` |
| §2.5.3 Inter-agent trust | Gateway-only orchestration + CAGE-003 registry | `hybrid_server.py`, `agent_registry_adapter.py` |
| §2.5.4 Scope limitation | CausalGatekeeper + OPA + FTRA gate | `causal_gatekeeper.py`, `ftra_reachability.py` |
| §3.1 Scope statement | This document | `docs/governance/AGENTIC_SCOPE_STATEMENT.md` |
| §3.2 HITL SLA (4 hours) | DeferQueue TTL + escalation | `defer_queue.py`, `hitl_escalator.py` |
| §4.1 Agent identity | SPIFFE SVID + Envoy ext_authz | `agent_registry_adapter.py`, `agent_gateway_adapter.py` |

---

*Document end — CAGE Agentic Scope Statement v2.1.0*
*Authority: NIST AI 600-1 §2.5, SR 26-2 §3.1, EO 14110 §4.2*
*Next review: 2026-10-27 (quarterly) or upon any SR 26-2 amendment*
