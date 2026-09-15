# FlowSignal Phase 3 v0.2 Canonical Schema Mapping

**Document Version:** 0.2
**Integration Phase:** 3 — Schema Reconciliation & Endpoint Cutover
**Status:** Candidate v0.2 Extracted
**Last Updated:** 2026-09-15

---

## Overview

This document defines the canonical JSON payload structure and decision mapping rules for CAGE's integration with FlowSignal Phase 3 v0.2. FlowSignal acts as an external normative authority provider, receiving escalation requests from CAGE and returning authoritative determinations.

---

## §1 — Legacy Draft Schema (7 Fields) — **SUPERSEDED**

The following 7-field minimal schema was used in the initial draft contract and is preserved for historical reference only. **This schema is superseded by §2 below.**

```json
{
  "magnitude": <numeric/decimal>,
  "currency": <string>,
  "context": <string>,
  "platform": <string>,
  "execution_id": <string>,
  "evidence_references": [<string>, ...],
  "approval_id": <string | null>
}
```

---

## §2 — Candidate v0.2 Schema (37 Fields)

Extracted from [`FlowSignal-CAGE-Phase3-v0.2-Candidate.zip`](FlowSignal-CAGE-Phase3-v0.2-Candidate.zip):
**Source:** `harness/app/api.py::CageAuthorityDetermineRequest`
**Baseline Commit:** `87fc133828ca9e8c16a9bda425aa508aa661469e`

### Complete Field Specification

```python
class CageAuthorityDetermineRequest(BaseModel):
    """CAGE v3-facing request model (37 fields total, 35 required + 2 optional)."""

    # Core Request Identifiers (3 fields)
    approval_id: str
    platform: str
    execution_id: str
    
    # Scenario & Action Context (4 fields)
    scenario_id: str
    action: str
    target: str
    context: str  # CAGE vocabulary: symbol/purpose → FlowSignal context
    
    # Actor Identity & Authorization (5 fields)
    actor_id: str
    actor_type: str
    actor_role: str
    actor_authenticated: bool
    kya_status: str
    
    # Principal (Institutional Context) (2 fields)
    principal_id: str
    principal_name: str
    
    # Mandate Boundary & Limits (7 fields)
    mandate_id: str
    mandate_status: str
    mandate_max_amount: float
    mandate_currency: str
    permitted_source_accounts: list[str]
    permitted_counterparty_class: str
    mandate_valid_until: datetime  # ISO 8601
    
    # Proposed Transaction Details (5 fields)
    magnitude: float  # CAGE vocabulary: amount → FlowSignal magnitude
    currency: str  # ISO 4217
    source_account: str
    beneficiary: str
    purpose: str
    
    # Runtime State & Risk Context (4 fields)
    counterparty_status: str
    account_status: str
    risk_state: str
    approval_required: bool
    
    # Mutable Evidence Freshness (4 fields)
    screening_status: str
    screening_captured_at: datetime  # ISO 8601
    screening_max_age_seconds: int
    screening_source: str
    
    # Execution Timing (1 field)
    requested_execution_time: datetime  # ISO 8601
    
    # Optional Fields (2 fields)
    authority_resolution_path: str | None = None
    evidence_references: list[dict[str, Any]] = Field(default_factory=list)
```

### CAGE → FlowSignal Field Mapping

| FlowSignal Field | Type | Required | CAGE Source (GovernanceEnvelope) | Default Value |
|------------------|------|----------|----------------------------------|---------------|
| `approval_id` | `str` | ✓ | `envelope.approval_id or envelope.correlation_id` | correlation_id fallback |
| `platform` | `str` | ✓ | `"GOOGLE-CAGE-REFERENCE"` | Hard-coded constant |
| `execution_id` | `str` | ✓ | `envelope.correlation_id` | — |
| `scenario_id` | `str` | ✓ | `envelope.thread_id` | — |
| `action` | `str` | ✓ | `envelope.action` | — |
| `target` | `str` | ✓ | `envelope.target` | — |
| `context` | `str` | ✓ | `envelope.params.get("symbol", envelope.params.get("purpose", ""))` | Empty string |
| `actor_id` | `str` | ✓ | `envelope.operator_urn` | — |
| `actor_type` | `str` | ✓ | `"autonomous_agent"` | Hard-coded default |
| `actor_role` | `str` | ✓ | `envelope.params.get("actor_role", "agent")` | `"agent"` |
| `actor_authenticated` | `bool` | ✓ | `True` | Hard-coded (CAGE kernel pre-authenticates) |
| `kya_status` | `str` | ✓ | `"VERIFIED"` | Hard-coded default |
| `principal_id` | `str` | ✓ | `envelope.params.get("principal_id", "cage-default")` | `"cage-default"` |
| `principal_name` | `str` | ✓ | `envelope.params.get("principal_name", "CAGE Platform")` | `"CAGE Platform"` |
| `mandate_id` | `str` | ✓ | `envelope.params.get("mandate_id", "DEFAULT-MANDATE")` | `"DEFAULT-MANDATE"` |
| `mandate_status` | `str` | ✓ | `"ACTIVE"` | Hard-coded default |
| `mandate_max_amount` | `float` | ✓ | `float(envelope.params.get("mandate_max_amount", 1000000.0))` | `1000000.0` |
| `mandate_currency` | `str` | ✓ | `envelope.params.get("currency", "USD")` | `"USD"` |
| `permitted_source_accounts` | `list[str]` | ✓ | `envelope.params.get("permitted_source_accounts", ["DEFAULT"])` | `["DEFAULT"]` |
| `permitted_counterparty_class` | `str` | ✓ | `envelope.params.get("permitted_counterparty_class", "UNRESTRICTED")` | `"UNRESTRICTED"` |
| `mandate_valid_until` | `datetime` | ✓ | `envelope.params.get("mandate_valid_until", "2099-12-31T23:59:59Z")` | `"2099-12-31T23:59:59Z"` |
| `magnitude` | `float` | ✓ | `float(envelope.params.get("amount", 0.0))` | `0.0` |
| `currency` | `str` | ✓ | `envelope.params.get("currency", "USD")` | `"USD"` |
| `source_account` | `str` | ✓ | `envelope.params.get("source_account", "DEFAULT")` | `"DEFAULT"` |
| `beneficiary` | `str` | ✓ | `envelope.params.get("beneficiary", "UNKNOWN")` | `"UNKNOWN"` |
| `purpose` | `str` | ✓ | `envelope.params.get("purpose", "CAGE transaction")` | `"CAGE transaction"` |
| `counterparty_status` | `str` | ✓ | `envelope.params.get("counterparty_status", "UNKNOWN")` | `"UNKNOWN"` |
| `account_status` | `str` | ✓ | `envelope.params.get("account_status", "ACTIVE")` | `"ACTIVE"` |
| `risk_state` | `str` | ✓ | `envelope.params.get("risk_state", "NORMAL")` | `"NORMAL"` |
| `approval_required` | `bool` | ✓ | `bool(envelope.params.get("approval_required", False))` | `False` |
| `screening_status` | `str` | ✓ | `envelope.params.get("screening_status", "CLEAR")` | `"CLEAR"` |
| `screening_captured_at` | `datetime` | ✓ | `envelope.params.get("screening_captured_at", datetime.utcnow().isoformat())` | Current UTC timestamp |
| `screening_max_age_seconds` | `int` | ✓ | `int(envelope.params.get("screening_max_age_seconds", 3600))` | `3600` |
| `screening_source` | `str` | ✓ | `envelope.params.get("screening_source", "CAGE-INTERNAL")` | `"CAGE-INTERNAL"` |
| `requested_execution_time` | `datetime` | ✓ | `envelope.params.get("requested_execution_time", datetime.utcnow().isoformat())` | Current UTC timestamp |
| `authority_resolution_path` | `str \| None` | ✗ | `None` | `None` |
| `evidence_references` | `list[dict]` | ✗ | `[{"type": "governance_decision", "uri": f"cer://{envelope.correlation_id}"}]` | Single CER reference |

### Example Candidate v0.2 Request Payload

```json
{
  "approval_id": "approval-abc-123",
  "platform": "GOOGLE-CAGE-REFERENCE",
  "execution_id": "550e8400-e29b-41d4-a716-446655440000",
  "scenario_id": "thread-xyz-789",
  "action": "payment.release",
  "target": "TREASURY_PAYMENT_GATEWAY",
  "context": "Invoice 78431",
  "actor_id": "agent-treasury-01",
  "actor_type": "autonomous_agent",
  "actor_role": "treasury_agent",
  "actor_authenticated": true,
  "kya_status": "VERIFIED",
  "principal_id": "institution-001",
  "principal_name": "Example Financial Institution",
  "mandate_id": "MANDATE-TREASURY-001",
  "mandate_status": "ACTIVE",
  "mandate_max_amount": 1000000.0,
  "mandate_currency": "GBP",
  "permitted_source_accounts": ["TREASURY-001"],
  "permitted_counterparty_class": "APPROVED_SUPPLIERS",
  "mandate_valid_until": "2026-12-31T23:59:59Z",
  "magnitude": 750000.0,
  "currency": "GBP",
  "source_account": "TREASURY-001",
  "beneficiary": "SUPPLIER-X",
  "purpose": "Invoice 78431",
  "counterparty_status": "APPROVED",
  "account_status": "ACTIVE",
  "risk_state": "NORMAL",
  "approval_required": false,
  "screening_status": "CLEAR",
  "screening_captured_at": "2026-08-10T09:00:00Z",
  "screening_max_age_seconds": 3600,
  "screening_source": "SCREENING-SERVICE-01",
  "requested_execution_time": "2026-08-10T09:15:00Z",
  "authority_resolution_path": null,
  "evidence_references": [
    {"type": "governance_decision", "uri": "cer://550e8400-e29b-41d4-a716-446655440000"}
  ]
}
```

---

## §3 — FlowSignal Endpoint Contract

### Endpoint Cutover (Phase 3 v0.2)

- **Legacy Endpoint (Phase 1):** `POST /validate/fria` (7-field minimal schema)
- **Candidate Endpoint (Phase 3 v0.2):** `POST /cage/validate` (37-field full schema)

CAGE's [`provider_01`](../../src/integrations/provider_01/provider.py) adapter now targets `/cage/validate` by default, overrideable via:
```bash
export CAGE_NORMATIVE_VALIDATE_PATH="/cage/validate"
```

---

## §4 — Decision Mapping Rules

FlowSignal returns one of three canonical decision values. CAGE maps these to internal governance actions as follows:

| FlowSignal Decision | CAGE Internal Action | Consequence | Audit Trail Requirement |
|---------------------|----------------------|-------------|------------------------|
| **`ALLOW`** | Issue `ConsequenceToken` | Action proceeds to execution via [`ActuatorRegistry`](../../src/gateway/governance/execution_actuator.py) | Token minted and logged to evidence stream |
| **`ESCALATE`** | Park thread with `DeferReason.FLOWSIGNAL_HOLD` or `DeferReason.EXTERNAL_HOLD` | Action suspended pending manual review or additional approval; thread enters [`DeferQueue`](../../src/gateway/governance/defer_queue.py) | Deferral reason and FlowSignal response logged |
| **`REFUSE`** | Abort execution with `decision_code = ENFORCED_REFUSE` | Action permanently denied; no ConsequenceToken issued | Refusal recorded in tamper-evident chain with full FlowSignal response |

### Decision Flow Diagram

```
┌─────────────────────────────────────────┐
│  CAGE Governance Envelope               │
│  (CageAuthorityDetermineRequest)        │
└──────────────┬──────────────────────────┘
               │
               ▼
     ┌─────────────────────┐
     │   FlowSignal v0.2   │
     │  (External Authority)│
     └─────────┬───────────┘
               │
      ┌────────┴─────────┐
      │                  │
      ▼                  ▼                  ▼
   [ALLOW]          [ESCALATE]          [REFUSE]
      │                  │                  │
      ▼                  ▼                  ▼
ConsequenceToken    DeferQueue        ENFORCED_REFUSE
      │                  │                  │
      ▼                  ▼                  ▼
Execute Action    Human Review      Permanent Denial
```

---

## Invariants & Validation Rules

### Request Invariants (CAGE Sender)
1. **Magnitude Precision**: `magnitude` must be a valid decimal number with at most 2 decimal places for fiat currencies.
2. **Currency Validity**: `currency` must be a valid ISO 4217 code.
3. **Execution ID Uniqueness**: `execution_id` must be globally unique within the CAGE instance.
4. **Evidence Non-Empty**: `evidence_references` array must contain at least one valid CER URI.
5. **Platform Immutability**: `platform` must always be `"GOOGLE-CAGE-REFERENCE"` (hard-coded constant).

### Response Invariants (FlowSignal Provider)
1. **Decision Enumeration**: Response `decision` field must be exactly one of: `"ALLOW"`, `"ESCALATE"`, `"REFUSE"`.
2. **Case Sensitivity**: Decision values are case-sensitive and must be uppercase.
3. **Tamper Evidence**: FlowSignal responses should include cryptographic signatures or receipt identifiers for audit trail integrity.

---

## Integration Phases

- **Phase 1 (This Document)**: Payload contracts and decision mapping specification
- **Phase 2 (Future)**: `NormativeProvider` adapter implementation in [`src/integrations/flowsignal/`](../../src/integrations/)
- **Phase 3 (Future)**: Live integration testing with FlowSignal sandbox environment
- **Phase 4 (Future)**: Production readiness review and OSCAL control mapping

---

## Related Documentation

- [Adapter Architecture Specification](../technical-report/11-ADAPTER-ARCHITECTURE.md) — Generic normative provider integration patterns
- [Consequence Gateway](../../src/gateway/governance/consequence_gateway.py) — Fail-closed execution boundary
- [Defer Queue](../../src/gateway/governance/defer_queue.py) — Escalation and deferral mechanism
- [Evidence Stream](../../src/gateway/governance/evidence/stream.py) — Tamper-evident audit chain

---

## Audit & Compliance Notes

1. **Field Name Precision**: The exact field names documented above (`magnitude`, `currency`, `context`, `platform`, `execution_id`, `evidence_references`, `approval_id`) constitute the canonical contract for FlowSignal Phase 3 v0.2 integration.
2. **Decision Code Mapping**: The three-way decision mapping (`ALLOW` → ConsequenceToken, `ESCALATE` → DeferQueue, `REFUSE` → ENFORCED_REFUSE) is normative and must not be bypassed.
3. **Refusals as Primary Evidence**: `REFUSE` decisions must be recorded in the tamper-evident chain with the same completeness and durability as `ALLOW` approvals (per Adapter Architecture Standards).
4. **No Direct Bypass**: All FlowSignal interactions must route through the [`ConsequenceGateway`](../../src/gateway/governance/consequence_gateway.py) to maintain fail-closed execution boundaries (ADR-008).

---

**End of Document**
