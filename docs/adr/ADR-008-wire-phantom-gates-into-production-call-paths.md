# ADR-008: Wire Phantom Gates Into Production Call Paths (Two-Stage Execution Boundaries)

**Status:** Implemented  
**Date:** 2026-09-14  
**Decision Makers:** CAGE Core Architecture Team  
**Supersedes:** N/A  
**Compliance Mapping:** NIST SP 800-53 CA-7, AC-3 | ISO 42001 §A.8.4 | CSA AARM Deferral Service  

---

## Context

Prior to this ADR, CAGE's governance engine evaluated Financial Risk Impact Assessments (FRIA) and immediately authorized action execution in a single atomic phase. This created three critical security vulnerabilities:

1. **Time-of-Check-Time-of-Use (TOCTOU) Gap**: The action payload could be modified between governance evaluation and execution, bypassing policy checks entirely.
2. **Replay Attack Surface**: A valid governance decision could be captured and replayed for a different action without re-validation.
3. **Missing Fail-Closed Path**: When confidence scores fell below the Confidence-Starvation Boundary (0.70), the system lacked a formal deferral mechanism, forcing brittle binary ALLOW/DENY choices on fundamentally ambiguous context.

The CSA AI Agent Risk Matrix (AARM) v1.0 specifies a "Deferral Service" primitive for situational ambiguity. NIST SP 800-53 AC-3 requires cryptographically binding access decisions to the exact resource being accessed. ISO 42001 §A.8.4 mandates formal pause mechanisms when operating conditions change.

---

## Decision

We implement a **two-stage execution boundary** with cryptographic binding and a fail-closed deferral path:

### Phase 1: Governance Decision (FRIA Evaluation)
The [`SymbolicGovernor`](../../src/gateway/governance/symbolic_governor.py) evaluates the action through domain-specific governance tiers and consensus scoring:

1. **Input**: Action name, parameters, optional result preview
2. **Evaluation**: Execute domain tiers (STPA, CBF, OPA, FRIA, Bounding Contracts)
3. **Confidence Routing**:
   - `confidence >= 0.95` → **ALLOW** (autonomous clearance)
   - `0.70 <= confidence < 0.95` → **MANUAL_REVIEW** (human sign-off via `/v1/approvals/pending`)
   - `confidence < 0.70` → **DEFER** (data-hydration loop via DeferQueue)
   - Hard failures → **DENY** (immediate block)

4. **Output**: If ALLOW, generates a signed **ConsequenceToken** (compact JWS with `act` = SHA-256 digest of JCS-canonicalized action payload, `rec` = evidence record hash, `iat`/`exp` timestamps). If DEFER, parks the decision in DeferQueue and returns `defer_id`.

### Phase 2: Consequence Authorization (ConsequenceGateway)
The [`ConsequenceGateway`](../../src/gateway/governance/consequence_gateway.py) verifies the consequence authority before execution:

1. **Input**: ConsequenceToken (compact JWS), current action payload
2. **6-Step Verification Sequence**:
   - **Step 1-2**: JWS signature + TTL verification (via [`ConsequenceToken.verify()`](../../src/gateway/governance/consequence_token.py))
   - **Step 3-4**: Recompute SHA-256 digest of JCS-canonicalized action payload; compare to `act` claim (TOCTOU protection)
   - **Step 5**: Atomic single-use consumption via [`ConsequenceAuthorityStore`](../../src/gateway/governance/consequence_authority_store.py) (replay protection)
   - **Step 6**: Emit `EXECUTE` / `HOLD` / `BLOCK` decision

3. **Output**: `ConsequenceEvaluation` with decision and reason code

### Supporting Infrastructure

#### GovernanceEnvelopeBuilder
[`GovernanceEnvelopeBuilder`](../../src/gateway/governance/governance_envelope.py) constructs RFC 8785 JCS-canonicalized, cryptographically signed envelopes for:
- **Compliance Evidence**: Long-term archival with provenance chain
- **Cross-Service Attestation**: Gateway → Actuator trust boundary
- **Audit Trail**: Deterministic hashing for tamper-evident logging

Envelope structure (v2.1):
```json
{
  "envelope_version": "2.1",
  "envelope_type": "cage_governance_decision",
  "issued_at": "2026-09-14T00:00:00.000Z",
  "expires_at": "2026-09-14T00:00:30.000Z",
  "issuer": {
    "service": "cage-gateway",
    "instance_id": "gke-cluster-abc123",
    "region": "us-central1"
  },
  "subject": {
    "action": "execute_trade",
    "action_hash": "sha256:...",
    "record_hash": "sha256:...",
    "agent_id": "advisor-prod-v3"
  },
  "governance_context": {
    "policy_version": "sha256:...",
    "tiers_passed": ["stpa", "cbf", "opa", "consensus"],
    "deployment_region": "US_FED",
    "controls_satisfied": ["CTRL_OPA_001", "CTRL_CBF_002"]
  },
  "payload": { ... },
  "signature": {
    "algorithm": "ES256",
    "kid": "...",
    "value": "base64url(...)"
  }
}
```

#### DeferQueue Fail-Closed Path
[`DeferQueue`](../../src/gateway/governance/defer_queue.py) provides a Redis-backed (db=1, `noeviction` maxmemory policy) state machine for parking ambiguous decisions:

**Data Structures**:
- `DEFER:{defer_id}` — Redis Hash containing full `DeferToken` JSON
- `DEFER:expiry_index` — Redis ZSet with `member=defer_id, score=expiry_unix_ts`

**Resolution Paths**:
1. **Human-in-the-loop escalation**: `POST /v1/defer/{defer_id}/escalate` — dual-approval step-up with operator URN tracking
2. **Automated data injection**: `POST /v1/defer/{defer_id}/inject` — confidence re-evaluation after context enrichment
3. **Status polling**: `GET /v1/defer/{defer_id}` — client-side status check (PARKED, PARTIALLY_APPROVED, RESOLVED)
4. **Batch listing**: `GET /v1/defer/pending` — list all pending tokens with pagination

**Confidence-Starvation Boundary** (UCA-7 in [`ontology.py`](../../src/gateway/governance/ontology.py)):
```
confidence >= 0.95        → ALLOW (autonomous clearance)
0.70 <= confidence < 0.95 → MANUAL_REVIEW (human sign-off)
confidence < 0.70         → DEFER (data-hydration, NOT human triage)
```

**TTL Defaults**:
- Standard deferral: 4 hours (`_DEFAULT_TTL = 3600 * 4`)
- External validation hold: 5 minutes (`_DEFAULT_HOLD_TTL = 300`)

---

## Consequences

### Positive

1. **TOCTOU Gap Eliminated**: The `act` claim in the ConsequenceToken binds the authorization to the exact byte-for-byte payload via SHA-256(JCS-canonicalized-action). Any modification between Phase 1 and Phase 2 causes digest mismatch → `BLOCK` with `ACTION_BINDING_MISMATCH` reason code.

2. **Replay Attack Prevention**: Atomic single-use consumption in `ConsequenceAuthorityStore` (Redis `WATCH`/`MULTI`/`EXEC` transaction) ensures each ConsequenceToken can only authorize execution once. Second attempt returns `HOLD` with `ALREADY_CONSUMED` reason code.

3. **Formal Deferral Primitive**: DEFER state satisfies CSA AARM specification and prevents operational fatigue from forcing human operators to triage fundamentally corrupted context (confidence < 0.70). Data-hydration loop at `POST /v1/defer/{defer_id}/inject` enables automated resolution.

4. **Compliance Evidence Chain**: `GovernanceEnvelopeBuilder` produces RFC 8785 canonical JSON with deterministic SHA-256 hashes, enabling:
   - NIST SP 800-53 AU-10 (Non-repudiation)
   - ISO 42001 §9.3 (Management Review)
   - OSCAL SSP evidence bundle generation

5. **Cross-Service Trust Boundary**: Signed governance envelopes enable zero-trust actuator validation — actuators independently verify the JWS signature and TTL without trusting the gateway transport layer (defense-in-depth).

### Negative

1. **Latency Overhead**: Two-stage evaluation adds ~15-25ms median latency:
   - Phase 1: FRIA evaluation + ConsequenceToken signing (~10-15ms)
   - Phase 2: JCS canonicalization + SHA-256 digest + Redis consumption (~5-10ms)
   - Mitigation: Latency is acceptable for financial advisory workflows (multi-second user think time). Not suitable for sub-10ms HFT scenarios.

2. **Redis Dependency**: DeferQueue requires Redis availability for DEFER path. Failure modes:
   - Redis unreachable → fallback to local `defer_id` UUID (DEFER verdict still enforced, but token NOT persisted — HITL API cannot resolve it)
   - Redis eviction → tokens lost (mitigated by `noeviction` maxmemory policy on db=1)

3. **Operational Complexity**: DEFER state machine introduces three new HTTP endpoints (`/v1/defer/pending`, `/v1/defer/{defer_id}`, `/v1/defer/{defer_id}/inject`, `/v1/defer/{defer_id}/escalate`) requiring documentation, monitoring, and SLO tracking.

4. **Breaking Change for Legacy Clients**: Pre-ADR-008 clients expect synchronous ALLOW/DENY decisions. DEFER returns HTTP 202 with `defer_id` — clients must implement polling loop or fail-closed timeout.

### Neutral

1. **ConsequenceToken TTL**: Default 30-second TTL may be too aggressive for high-latency external FRIA providers (e.g., cross-region normative APIs). Configurable via `GovernanceEnvelopeBuilder(ttl_s=...)`.

2. **JCS Canonicalization Dependency**: RFC 8785 JCS guarantees deterministic serialization but requires strict adherence to Unicode normalization and lexicographic key ordering. Any deviation breaks digest binding.

---

## Implementation Status

**Fully Implemented** (as of 2026-09-14):

- ✅ [`ConsequenceGateway`](../../src/gateway/governance/consequence_gateway.py:82) — 6-step verification sequence
- ✅ [`GovernanceEnvelopeBuilder`](../../src/gateway/governance/governance_envelope.py:253) — RFC 8785 JCS envelope builder
- ✅ [`DeferQueue`](../../src/gateway/governance/defer_queue.py:298) — Redis-backed defer state machine
- ✅ [`ConsequenceToken`](../../src/gateway/governance/consequence_token.py) — JWS compact serialization with KMS signing
- ✅ [`ConsequenceAuthorityStore`](../../src/gateway/governance/consequence_authority_store.py) — Redis single-use consumption
- ✅ [`POST /v1/defer/{defer_id}/inject`](../../src/compliance_bridge/main.py:1449) — automated data injection endpoint
- ✅ [`POST /v1/defer/{defer_id}/escalate`](../../src/compliance_bridge/main.py:1651) — dual-approval escalation endpoint
- ✅ [`GET /v1/defer/{defer_id}`](../../src/compliance_bridge/main.py:1308) — status polling endpoint (ADR-008 Phase 4)
- ✅ [`GET /v1/defer/pending`](../../src/compliance_bridge/main.py:1262) — batch listing endpoint
- ✅ FTRA integration: [`_park_in_defer_queue()`](../../src/gateway/governance/ftra/node_factory.py:814) — parks HITL_REQUIRED verdicts
- ✅ LangGraph defer node: [`defer_node()`](../../src/governed_financial_advisor/graph/nodes/defer_node.py:39) — parks ambiguous transactions in DeferQueue
- ✅ Tool execution integration: [`BoundedToolExecutor`](../../src/cage_finance/tools/tool_provider.py:114) — ConsequenceGateway evaluation (ADR-008 Phase 2)

**Test Coverage**:
- Unit tests: `tests/test_consequence_gateway.py`, `tests/test_defer_queue.py`, `tests/test_governance_envelope.py`
- Integration tests: `tests/integration/test_defer_workflow.py`
- Marker: `pytestmark = [pytest.mark.unit, pytest.mark.local]`

---

## Alternatives Considered

### Alternative 1: Single-Stage Authorization with Action Hash Validation
**Rejected Reason**: Combining governance evaluation and execution authorization in a single phase preserves the TOCTOU gap. Even with action hash validation, there's no enforcement boundary between decision and execution.

### Alternative 2: Inline DEFER Logic in SymbolicGovernor
**Rejected Reason**: Embedding deferral state management in the governor violates Layer 1 (Kernel) domain-agnostic invariant. DeferQueue belongs in Layer 3 (Integrations & Rails) per v3.0.1 architecture.

### Alternative 3: Synchronous Human Review for All confidence < 0.70
**Rejected Reason**: Creates operational fatigue. When context is fundamentally corrupted (missing required fields, NaN confidence scores), human operators cannot make informed decisions. DEFER → automated data-hydration is the correct fail-closed path per AARM specification.

### Alternative 4: PostgreSQL-Backed Defer Queue
**Rejected Reason**: Redis sorted sets (`ZADD`/`ZRANGEBYSCORE`) provide O(log N) TTL-based expiry lookups with atomic `WATCH`/`MULTI`/`EXEC` transactions. PostgreSQL would require advisory locks and polling-based expiry cleanup, increasing operational complexity.

---

## References

- **NIST SP 800-53 Rev. 5**:
  - AC-3 (Access Enforcement) — cryptographic binding of decisions to resources
  - CA-7 (Continuous Monitoring) — defer queue audit trail
  - AU-10 (Non-repudiation) — signed governance envelopes

- **ISO/IEC 42001:2023**:
  - §A.8.4 (AI System Operation Controls) — formal pause mechanisms

- **CSA AI Agent Risk Matrix (AARM) v1.0**:
  - Deferral Service Primitive — situational ambiguity handling

- **CAGE Internal References**:
  - [`src/gateway/governance/decisions.py`](../../src/gateway/governance/decisions.py) — GovernanceDecision enumeration (ALLOW, DENY, DEFER, MANUAL_REVIEW)
  - [`src/gateway/governance/ontology.py`](../../src/gateway/governance/ontology.py) — UCA-7 (Confidence-Starvation Boundary)
  - [`src/gateway/governance/symbolic_governor.py`](../../src/gateway/governance/symbolic_governor.py:2412) — DeferQueue integration for DEFER path
  - [`src/compliance_bridge/aarm_mapper.py`](../../src/compliance_bridge/aarm_mapper.py:251) — AARM compliance mapping

- **Related ADRs**:
  - ADR-001: MinIO Tensorizer for vLLM Weight Streaming
  - ADR-002: Portability Improvements (Gateway & Node Selectors)
  - ADR-003: Region-Gated Compliance Hardening
  - ADR-004: Decouple Security Posture from High Availability

---

## Revision History

| Version | Date       | Author                     | Changes                                           |
|---------|------------|----------------------------|---------------------------------------------------|
| 1.0     | 2026-09-14 | CAGE Core Architecture Team | Initial formalization of implemented design      |

---

**End of ADR-008**
