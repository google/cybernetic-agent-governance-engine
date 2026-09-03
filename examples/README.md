# CAGE Examples

> **Framing note:** CAGE is a **domain-agnostic** governance substrate. Every enforcement layer exercised by the demos below is domain-neutral — it operates on abstract action primitives. The scenarios use concrete nouns from the **finance example domain** ([`src/cage_finance/`](../src/cage_finance/)) purely because a concrete trace is easier to read than an abstract one. The **healthcare example domain** ([`src/cage_healthcare/`](../src/cage_healthcare/)) is of equal standing and drives the identical tiers with `dose_order`, `SerumConcentrationBarrier`, and clinical critics substituted in. Neither domain is required: `CAGE_ACTIVE_PLUGINS=""` runs the bare substrate. See [`docs/architecture/DOMAIN_PLUGIN_ARCHITECTURE.md`](../docs/architecture/DOMAIN_PLUGIN_ARCHITECTURE.md).
>
> Reading the tables below: the **Layer / Mechanism** columns are kernel-owned and domain-independent; the scenario narratives are domain-flavoured illustrations.

---

# CAGE · Chaos Agent Playground

> **"Show, don't tell."** — An interactive local demo of the CAGE governance stack intercepting adversarial agent payloads across every enforcement layer.
>
> **Domain Plugin Example: Finance.** Scenarios A–E below are written against finance-domain nouns (`execute_trade`, drawdown, slippage). The tiers they trip are domain-neutral: an equivalent healthcare run would trip the same tiers on a `dose_order` exceeding a concentration barrier, and an adopter's manufacturing run on a setpoint exceeding a tolerance band.

## What It Does

Runs three adversarial attack scenarios through the **real** CAGE governance pipeline — no Kubernetes, no external services, no LLM calls required. Every governance layer executes its actual logic:

| Tier | Layer | Implementation |
|------|-------|---------------|
| 0 | STPA Python Validator | `GeneratedSTPAValidator` — compiled from `config/stpa_control_structure.yaml` |
| 1 | Agentic Confidence Threshold | SR 26-2 §IV.B check against `governance_thresholds.json` |
| 2 | OPA Rego Emulator | Mirrors `config/opa/generated_stpa_policy.rego` logic inline |
| 3 | Prompt Injection Scanner | Tier-1 keywords from `governance_thresholds.json` |
| 4 | Cilium L7 Egress | Emulates `deployment/k8s/cilium-egress-lockdown.yaml` FQDN rules |

## Quick Start

```bash
# All 3 scenarios, interactive (pause between each)
uv run python examples/chaos_agent_playground.py

# Batch / non-interactive (CI / README demos)
uv run python examples/chaos_agent_playground.py --no-pause

# Single scenario
uv run python examples/chaos_agent_playground.py --scenario A
uv run python examples/chaos_agent_playground.py --scenario B
uv run python examples/chaos_agent_playground.py --scenario C
```

## Attack Scenarios

> All five scenarios are **Domain Plugin Example: Finance**. Each maps to a domain-neutral failure class, shown in the table below. The healthcare column illustrates the same class in the other shipped example domain.

| Scenario | Domain-neutral failure class | Finance framing (shown below) | Healthcare equivalent |
|---|---|---|---|
| A | Stale/latent input beyond freshness bound + confidence starvation | Gas front-running on stale market data | Dose computed from a stale lab result |
| B | Unauthenticated consequential write + unauthorised egress | PII exfiltration via `write_db` | Patient record write without clinician token |
| C | Prompt injection + control bypass | Guardrail override before risk assessment | Guardrail override before contraindication check |
| D | Compensating rollback after partial commit | Credit-leg failure LIFO rollback | Reversal of a partially administered order |
| E | Ghost state after crash between phases | OOM crash between PENDING and COMPLETED | Interrupted order left in an indeterminate state |

### Scenario A — Gas Front-Running / Stale Data Injection *(Domain Plugin Example: Finance)*

An LLM agent receives a market manipulation prompt instructing it to execute a large `NVDA` BUY order during a gas spike. The payload carries:

- **340 ms latency** (UCA-2 threshold: 200 ms) → STPA Tier-0 block
- **6.2% daily drawdown** (UCA-5 threshold: 4.5%) → STPA + OPA block
- **0.87 confidence** (SR 26-2 §IV.B threshold: 0.95) → Tier-1 block

```
🔴 Tier 0 · GeneratedSTPAValidator        BLOCKED
   ✗ STPA UCA-2: latency 340ms > 200ms
   ✗ STPA UCA-5: drawdown 6.2% > 4.5%
🔴 Tier 1 · Agentic Confidence Threshold   BLOCKED
   ✗ SR 26-2 §IV.B: agentic model confidence 0.87 < 0.95
```

### Scenario B — PII Exfiltration via Unauthenticated write_db *(Domain Plugin Example: Finance)*

A compromised pod attempts to write raw client PII (SSN, account number) to the database without a signed approval token, then tries to open an egress connection to `malicious-exfil.attacker.io`:

```
🔴 Tier 0 · GeneratedSTPAValidator        BLOCKED
   ✗ STPA UCA-1: write_db requires approval_token
🔴 Tier 2 · OPA Rego Policy               DENY
   ✗ OPA UCA-1: write_db requires signed approval_token
🔴 Tier 4 · Cilium L7 Egress              DENY — PACKET DROPPED
   ✗ CiliumPolicy: 'malicious-exfil.attacker.io' not in allowlist
```

### Scenario C — Prompt Injection + Compliance Bypass *(Domain Plugin Example: Finance)*

Multi-vector attack: Tier-1 keyword injection (`SYSTEM OVERRIDE`, `DISABLE GUARDRAILS`) combined with `compliance_checked=False` and `risk_assessed=False`:

```
🔴 Tier 0 · GeneratedSTPAValidator        BLOCKED
   ✗ UCA-8: trade before risk assessment
   ✗ UCA-9: compliance check bypassed
🔴 Tier 2 · OPA Rego Policy               DENY (2 rules)
🔴 Tier 3 · Tier-1 Keyword Scanner        BLOCKED
   ✗ Matched: ['SYSTEM OVERRIDE', 'DISABLE GUARDRAILS']
```

## Architecture Notes

The playground is intentionally **zero-infrastructure**: it bootstraps from repo root, loads `governance_thresholds.json` directly, imports the real `GeneratedSTPAValidator`, and runs all checks synchronously. The latency figures shown are real Python execution times — typically sub-millisecond for the deterministic layers.

To test the **live** stack (with OPA server, Redis, NeMo Guardrails integrated into the gateway):

```bash
# Compile fresh artifacts (includes langgraph Saga nodes)
uv run python -m src.gateway.governance.stpa_compiler compile

# Deploy to governance-stack
kubectl apply -f deployment/k8s/linkerd-mtls-policy.yaml
kubectl apply -f deployment/k8s/cilium-egress-lockdown.yaml

# Verify governance edges
linkerd viz authz deployment/opa-service -n governance-stack
cilium monitor --type l7
```

## Saga Scenarios (D & E)

Two additional scenarios exercise the **UCA-4 Saga WAL** compensating sub-graph generated by `stpa_compiler` (`config/stpa_control_structure.yaml` → `generated_saga_nodes.py`):

### Scenario D — UCA-4 LIFO Rollback (Credit-Leg Failure)

Simulates a COMPLETED ledger entry whose credit-leg API call returned 500. `saga_router_node` delegates to `compensate_reverse_trade_node_uca_4` in LIFO order:

```
✅ Saga UCA-4: safety_status=BLOCKED  ledger entry=ROLLED_BACK
```

### Scenario E — Ghost State (OOM Crash Between PENDING and COMPLETED)

Simulates an OOM crash that left a dangling PENDING WAL entry. `saga_router_node` detects ghost state and escalates:

```
❗ Saga UCA-4: safety_status=ESCALATED  next_step=human_review
```

Both scenarios exercise the SR 26-2 Non-Determinism Containment dimension. The forward WAL node (`forward_execute_trade_node_uca_4`) now calls `GatewayMCPClient.call_tool("execute_trade_action", ...)` — a real production-grade MCP invocation generated deterministically by the `stpa_compiler` from `execution_type: mcp_tool` in `stpa_control_structure.yaml`.

## Compliance Traceability

Every blocked scenario emits OTel span attributes matching the live system:

```
cage.governance.decision=BLOCKED
cage.governance.blocking_tier=<0-4>
nist.control_id=SC-4,A.8.4
iso42001.control_id=A.8.4
cage.governance.violation_count=<n>
```

These attributes are the same tags that flow into Langfuse, the Compliance Bridge, and the OSCAL SSP exporter — closing the audit loop from demo to production evidence.

---

# CAGE · Governance-as-Code Demo (`governance_demo.py`)

> **"Three acts, zero infrastructure."** — A self-contained walkthrough of the three headline governance capabilities of CAGE: atomic fiscal pre-reservation, HITL mandatory rationale, and tamper-evident hash chain verification.

No Kubernetes, no external services, no LLM calls required. Uses `fakeredis` for Act 1 and the real `PlaygroundTelemetry` evidence chain for Acts 2 & 3.

## Quick Start

```bash
# Full interactive walkthrough (default)
uv run python examples/governance_demo.py

# Skip inter-act pauses (CI / README demos)
uv run python examples/governance_demo.py --no-pause

# Run a single act
uv run python examples/governance_demo.py --act 1
uv run python examples/governance_demo.py --act 2
uv run python examples/governance_demo.py --act 3
```

## Acts

### Act 1 — Multi-Agent Concurrency Race (FiscalLimitGuard)

Three agents (trading, hedging, liquidity) simultaneously attempt a **$180,000** trade against a **$200,000** daily cap. Without `FiscalLimitGuard` all three would read `remaining=$200k` and pass OPA — a classic TOCTOU race. With the guard, exactly one reservation succeeds atomically at the Redis layer via `WATCH/MULTI/EXEC`; the other two are rejected before reaching OPA.

```
✓ trading-agent        $180,000   RESERVED  running=$180,000/$200,000
✗ hedging-agent        $180,000   REJECTED  (cap=$200,000  running=$180,000)
✗ liquidity-agent      $180,000   REJECTED  (cap=$200,000  running=$180,000)

PASS — exactly one reservation atomically succeeded
```

Also demonstrates the Saga rollback path: `release()` restores the reserved amount when the winning trade fails.

### Act 2 — HITL Approval with Mandatory Rationale

A **$95,000** TSLA trade arrives with `risk_score=0.82` (threshold: 0.70). The LangGraph graph interrupts at `approval_node`. The demo:

1. Proves the API rejects an empty rationale with `422 Unprocessable Entity`
2. Prompts the operator for a mandatory free-text rationale (or uses a default in `--no-pause` mode)
3. Hashes the rationale into the `cage-intent/1.0` evidence chain **before** the graph resumes — ensuring the human decision is persisted even if the agentic graph crashes mid-execution

```
✓ 422 Unprocessable Entity — empty rationale rejected
✓ Evidence record written  →  APPROVED
  hash   : <sha256[:32]>…
  ISO    : A.8.4 · A.7.2 · §6.1    NIST: GOVERN-5 · SC-4
```

### Act 3 — Tamper-Evident Hash Chain Verification

Reads every evidence record written in Acts 1 & 2, recomputes each SHA-256 link, then mutates one field to prove tamper detection:

```
✓ Chain VALID  —  N record(s) verified  (<elapsed> ms)
✓ Tamper detected at record [00]  →  chain integrity FAILED  ✓
```

The evidence chain is written to `examples/evidence/evidence_chain_<date>.ndjson` and can be re-verified at any time with `--act 3`.

## Compliance Coverage

| Act | Mechanism | Controls |
|-----|-----------|----------|
| 1 | `FiscalLimitGuard` Redis atomic pre-reservation | SR 26-2 §IV.B, NIST SC-4 |
| 2 | HITL mandatory rationale → evidence chain | ISO 42001 A.8.4, A.7.2, §6.1; NIST GOVERN-5; MiFID II Art. 25 |
| 3 | SHA-256 hash chain verification + tamper proof | `cage-intent/1.0`; GDPR Art. 30 |

---

# Shared Audit Infrastructure (`telemetry.py`)

`telemetry.py` is the shared audit library used by both `chaos_agent_playground.py` and `governance_demo.py`. It is not a runnable script — import it as a module.

## Two Complementary Audit Mechanisms

### 1. OTel Span Emitter

Emits real OpenTelemetry spans with the same Langfuse attribute schema used by the live gateway (`symbolic_governor.py`, `generated_stpa_validator.py`). When `LANGFUSE_HOST` / `LANGFUSE_PUBLIC_KEY` / `LANGFUSE_SECRET_KEY` are set, spans flow directly into Langfuse Cloud. Without credentials the `LoggingSpanExporter` fallback captures them locally.

Span attributes mirror the live system exactly:

```
langfuse.observation.type       = "span"
langfuse.observation.name       = "governance_evaluation"
langfuse.observation.output     = "BLOCKED" | "APPROVED"
cage.governance.decision        = "BLOCKED" | "APPROVED"
cage.governance.blocking_tier   = 0–4 | -1
cage.governance.violation_count = int
cage.evidence.chain_hash        = sha256 hex
```

### 2. NDJSON Evidence Chain

Writes a tamper-evident, cryptographically linked audit log to `examples/evidence/evidence_chain_<date>.ndjson`. Each record SHA-256 hashes its own payload and chains the previous record's hash — forming an append-only, verifiable evidence trail.

A separate `view_access_log_<date>.ndjson` registers every read-access event with the accessor identity, timestamp, and record hash — satisfying **MiFID II Article 25** and **GDPR Article 30** view-tracking requirements.

## Integrity vs. Provenance

The hash chain guarantees **data integrity** (non-tampering) but does **not** guarantee **data provenance** (truthfulness at creation). Every `cage-intent/1.0` record includes a `provenance_disclaimer` field to make this residual limitation machine-readable and auditor-visible. Cloud KMS asymmetric signing (`kms_signer.py`) covers governance plan signatures; per-record KMS attestation is a roadmap item.

## Usage

```python
from examples.telemetry import PlaygroundTelemetry

tel = PlaygroundTelemetry()

# Wrap a scenario execution in an OTel span + evidence record
with tel.scenario_span("A", "execute_trade", params) as span:
    # ... run governance tiers ...
    tel.record_result(
        span,
        violations,
        blocking_tier,
        elapsed_ms,
        action="execute_trade",
        params=params,
        scenario_id="A",
    )
tel.flush()

# HITL approval record (written before graph resume)
record_hash = tel.record_approval(
    thread_id="thread-abc123",
    approved=True,
    reviewer="analyst@example.com",
    rationale="Trade within IPS mandate; drawdown < CBF limit.",
)

# View-access audit log (read-tracking)
records = tel.read_evidence_log(
    accessor_id="analyst@example.com",
    reason="compliance review",
)

# Verify chain integrity
valid, count = tel.verify_chain()
```
