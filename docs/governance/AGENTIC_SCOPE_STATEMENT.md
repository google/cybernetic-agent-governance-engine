# CAGE Agentic Scope Statement

**Authority**: NIST AI 600-1 §2.5.1, §2.5.4 | SR 26-2 §3.1 | EO 14110 §4.2
**Version**: 2.1.1
**Date**: 2026-08-05

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
| Execute trades | ⛔ **NOT authorized** | ⛔ NOT authorized for autonomous agent execution. Note: `execute_trade` IS a supported governed action when invoked with human-in-the-loop approval via the governance pipeline. |
| Transfer funds | ⛔ **NOT authorized** | Outside authorized action space |
| Modify account settings | ⛔ **NOT authorized** | Outside authorized action space |
| Access external APIs | ⛔ **NOT authorized** | Except pre-approved market data endpoints |

### 1.1 Scope Limitation Enforcement

The authorized action space is enforced at three independent layers:

1. **OPA Policy Engine** (`src/gateway/governance/langgraph_harness/opa_node_factory.py`):
   Evaluates every tool call against `src/cage_finance/opa/trade_governance.rego`
   (package `trade.governance`). Any tool not explicitly listed in the `allowed_roles` set is
   denied with a `GovernanceError`. System-level authorization is enforced by `deployment/system_authz.rego`.

2. **Routing Seal** (`src/gateway/governance/routing_seal.py`):
   Every approved governance decision is sealed with a KMS-signed JWT bound to the
   evidence record (HMAC-SHA256 keyed by `GOVERNANCE_SALT` only in dev/test). The
   gateway's actuator path MUST verify and consume the seal before executing any
   action. Seal TTL: 30 seconds (`GOVERNANCE_SEAL_TTL_S`). Callers of the gateway are
   authenticated separately, by Linkerd mTLS workload identity
   (`src/gateway/server/workload_identity.py`).

3. **CausalGatekeeper** (`src/gateway/governance/causal/gatekeeper.py`):
   Performs DoWhy causal inference + placebo refutation before any high-stakes action.
   Fails closed when the world-model is untrustworthy (p-value < 0.05 or placebo
   effect > 0.2).

---

## 2. Human Oversight Boundaries

### 2.1 Consensus Threshold

Per `config/governance_thresholds.json` → `consensus.threshold_usd`:

- **Threshold**: USD 10,000
- **Enforcement**: `ConsensusEngine` (`src/gateway/governance/consensus/engine.py`)
- **Behavior**: Any advisory action involving amounts > USD 10,000 triggers a
  two-critic consensus check (Risk Manager + Compliance Officer personas on
  distinct model backends). A split vote or unanimous ERROR escalates to HITL.

### 2.2 Confidence Threshold

Two thresholds apply (`CTRL_AGT_001`):

- **Universal band** (`config/governance_thresholds.json` → `confidence.agent_threshold` 0.95 /
  `confidence.defer_floor` 0.70), identical in every region:
  `src/gateway/governance/governor/stages/confidence.py` (Tier 2) passes ≥ 0.95, asks for approval
  (REQUIRE_APPROVAL) in 0.70–0.95 and defers below 0.70, for every action. OPA `system_authz.rego`
  (`confidence_sufficient`, ≥ 0.95 for `execute_trade`) repeats the 0.95 floor.
- **Regional trade floor** (`domains.finance.confidence.min_trade_confidence.value`): 0.95 globally, raised by
  the region's `config/thresholds/{REGION}_BASELINE.json` overlay to 0.96 (`APAC_MAS`) and 0.97
  (`EU_ECB`). `src/cage_finance/tiers/trade_confidence_tier.py` enforces it for trade execution with the
  same band semantics: below the floor, REQUIRE_APPROVAL at or above 0.70, DEFER below.
- **Behavior**: Any LLM response with `confidence < 0.95` is blocked and the
  confabulation risk score (`1.0 - confidence`) is recorded via `confabulation_scorer.py`.

### 2.3 HITL Escalation Path

When the consensus threshold is exceeded or confidence is below threshold, the
`hitl_escalator.py` module routes the request to the human review queue:

1. `EscalationRequest` is created with `reason` (`EscalationReason` enum), `amount_usd`, and `confidence`
2. `escalate_to_human()` returns an `EscalationRecord` written to the DeferQueue
   (Redis `db=1`, `noeviction` policy, key prefix `DEFER:`, default TTL 4 hours)
3. Compliance review team receives the escalation via the configured queue
4. SLA: escalations must be resolved within the region-specific window (see §7 below)

### 2.4 Override Audit Trail

All governance overrides and escalations are logged to the WORM ledger via
`src/gateway/governance/uca_logger.py`:

- **Storage**: GCS WORM bucket (`OSCAL_S3_BUCKET_US_FED`, `us-central1`)
- **Signing**: KMS-signed (`KMSGovernanceSigner`, US_FED key ring)
- **Retention**: 90 days minimum (FISMA AU-11; GDPR Art. 5(1)(e) for EU_ECB;
  MAS Notice 655 §4.3 for APAC_MAS — resolved from `CAGE_DEPLOYMENT_REGION`)
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
policy (`config/opa/agent_catalog.rego`). Any agent not present in the registry
is denied at the Envoy ext_authz boundary before reaching the governance kernel.

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

### 3.4 Inter-Agent Call Requirements

Any call from the `governed-financial-advisor` to an external service MUST:

1. Present a valid routing seal (HMAC-SHA256, `GOVERNANCE_SALT` key, TTL 30s)
2. Have passed OPA policy evaluation (`ALLOW` decision)
3. Have passed the CausalGatekeeper check
4. Be within the authorized action space (§1 above)

Calls that fail any of these checks raise `GovernanceError` (from `src/gateway/governance/governor/verdicts.py`)
and are logged to the UCA WORM ledger.

### 3.5 No Peer-to-Peer Agent Calls

CAGE does not implement peer-to-peer agent communication. All inter-component
calls are mediated by the gateway. This eliminates the NIST AI 600-1 §2.5.3 risk
of unverified inter-agent trust propagation.

---

## 4. Scope Limitation Enforcement Mechanisms

| Mechanism | File | NIST AI 600-1 Control |
|---|---|---|
| OPA policy evaluation | `src/gateway/governance/langgraph_harness/opa_node_factory.py` | §2.5.1 |
| Trade governance policy | `src/cage_finance/opa/trade_governance.rego` | §2.5.1 |
| Routing seal verification | `src/gateway/governance/routing_seal.py` | §2.5.4 |
| CausalGatekeeper | `src/gateway/governance/causal/gatekeeper.py` | §2.3 |
| ConsensusEngine threshold | `src/gateway/governance/consensus/engine.py` | §2.5.2 |
| HITL escalator | `src/gateway/governance/hitl_escalator.py` | §2.5.2 |
| Control Barrier Function | `src/gateway/governance/safety/cbf_engine.py` | §2.5.4 |
| Confabulation scorer | `src/gateway/governance/confabulation_scorer.py` | §2.1 |
| Prompt injection detector | `src/gateway/governance/prompt_injection_detector.py` | §2.3 |
| NeMo CBRN rails | `src/integrations/nemo/colang/cbrn_rails.co` | §2.6 |
| FTRA Reachability Gate | `src/gateway/governance/ftra/node_factory.py` | §2.5.4 |

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

The local confidence pre-check in `src/gateway/governance/governor/stages/confidence.py` Tier 2 applies
`AGENT_CONFIDENCE_THRESHOLD` (default 0.95, env-overridable) to the ConsensusEngine's
own LLM calls. If the governance LLM call has `confidence < 0.95`, the request is
escalated to HITL rather than silently allowed. High self-reported confidence cannot
override a structural refusal: every STPA finding and every undecided OPA verdict is
`HARD`, and the pipeline stops before the confidence stage runs.

### 6.2 Residual Risk

The ConsensusEngine uses two distinct model backends (DeepSeek-R1 for Risk Manager,
Llama 3.1 for Compliance Officer — configured via `CONSENSUS_RISK_MANAGER_URL` /
`CONSENSUS_COMPLIANCE_OFFICER_URL`) to reduce correlated failure risk. However, both
models share the same training data distribution, which means correlated confabulation
on novel financial scenarios remains a residual risk.

**Compensating control**: The CausalGatekeeper provides a non-LLM causal inference
check that is independent of the LLM confidence scores.

---

## 6b. FTRA Commencement Reachability Gate (v2.1.0)

The Forward-Looking Trajectory Reachability Analyzer (FTRA, `CTRL_FTRA_001`,
`src/gateway/governance/ftra/`) enforces that no step of a proposed
`ExecutionPlan` can commence if it would reach an irreversible terminal action
(e.g. `execute_trade`, `write_db`) without either sufficient Evaluator
confidence or human clearance. The gate runs as a LangGraph node inserted
between `evaluator` and `safety_check` — a **pre-execution, per-plan
structural check**, not a one-time graph-compilation check.

| Module | Role |
|---|---|
| [`src/gateway/governance/ftra/classifier.py`](../../src/gateway/governance/ftra/classifier.py) | `IrreversibilityClassifier` — classifies each plan-step action name via the compiled `config/ftra/terminal_registry.json`; fail-closed to `IRREVERSIBLE_TERMINAL` for unregistered actions |
| [`src/gateway/governance/ftra/graph_analyzer.py`](../../src/gateway/governance/ftra/graph_analyzer.py) | `PlanGraphAnalyzer` — builds a NetworkX `DiGraph` over plan steps, runs DFS from step 0, returns a `ReachabilityResult` |
| [`src/gateway/governance/ftra/models.py`](../../src/gateway/governance/ftra/models.py) | `TerminalClassification`, `FTRAVerdict` (`CLEAR` \| `HITL_REQUIRED` \| `BLOCKED`), `ReachabilityResult` |
| [`src/gateway/governance/ftra/node_factory.py`](../../src/gateway/governance/ftra/node_factory.py) | `create_ftra_node()` / `route_after_ftra()` — LangGraph node factory and conditional-edge routing |

**Scope enforcement**: FTRA is a mandatory pre-condition for the
`governed-financial-advisor` scope. Any plan where an irreversible terminal is
reachable is either routed to human review (`HITL_REQUIRED`) or blocked
outright (`BLOCKED`, confidence < 0.70) before the authorized action space
(§1) is evaluated further. Parked tokens use `DeferReason.FTRA_IRREVERSIBLE_TERMINAL`
in the DeferQueue.

> **Removed scaffold:** `graph_analyzer.py` was refactored into the FTRA subpackage at `src/gateway/governance/ftra/graph_analyzer.py` (not deleted).

---

## 7. Regional HITL SLA Requirements

CAGE enforces different HITL resolution SLAs based on the active deployment region
(`CAGE_DEPLOYMENT_REGION`). These are resolved at runtime by `get_hitl_sla_hours()`
and `get_hitl_regulatory_citation()` in `hitl_escalator.py`:

| Region | SLA | Regulatory Authority |
|---|---|---|
| `US_FED` | **4 hours** | SR 26-2 §3.2 |
| `EU_ECB` | **2 hours** | DORA Art. 10 |
| `APAC_MAS` | **1 hour** | MAS FEAT §3.2 |
| *(default/unset)* | **4 hours** | ISO 42001 §A.8.4 fallback |

SLA constants are stored in `constants.py` (`HITL_SLA_HOURS`, `HITL_CITATIONS`).
SR 26-2 §3.2 (4-hour SLA) has no legal force outside `US_FED` deployments.

---

## 8. SR 26-2 Compliance Evidence

| SR 26-2 Requirement | CAGE Implementation | Evidence |
|---|---|---|
| §2.5.1 Authorized action space | OPA policy + routing seal | `opa_node_factory.py`, `routing_seal.py` |
| §2.5.2 Human oversight | ConsensusEngine + HITL escalator | `src/gateway/governance/consensus/engine.py`, `hitl_escalator.py` |
| §2.5.3 Inter-agent trust | Gateway-only orchestration + CAGE-003 registry | `hybrid_server.py`, `agent_registry_adapter.py` |
| §2.5.4 Scope limitation | CausalGatekeeper + OPA + FTRA gate | `src/gateway/governance/causal/gatekeeper.py`, `src/gateway/governance/ftra/node_factory.py` |
| §3.1 Scope statement | This document | `docs/governance/AGENTIC_SCOPE_STATEMENT.md` |
| §3.2 HITL SLA (4 hours) | DeferQueue TTL + escalation | `defer_queue.py`, `hitl_escalator.py` |
| §4.1 Agent identity | SPIFFE SVID + Envoy ext_authz | `agent_registry_adapter.py` |

---

*Document end — CAGE Agentic Scope Statement v2.1.0*
*Authority: NIST AI 600-1 §2.5, SR 26-2 §3.1, EO 14110 §4.2*
*Next review: 2026-11-05 (quarterly) or upon any SR 26-2 amendment*
