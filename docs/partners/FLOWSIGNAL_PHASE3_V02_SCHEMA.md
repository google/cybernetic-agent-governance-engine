# FlowSignal Phase 3 v0.2 Canonical Schema Mapping

**Document Version:** 0.2  
**Integration Phase:** 1 — Payload Contracts  
**Status:** Draft  
**Last Updated:** 2026-09-14

---

## Overview

This document defines the canonical JSON payload structure and decision mapping rules for CAGE's integration with FlowSignal Phase 3 v0.2. FlowSignal acts as an external normative authority provider, receiving escalation requests from CAGE and returning authoritative determinations.

---

## `CageAuthorityDetermineRequest` Payload Structure

CAGE sends the following JSON payload when requesting a determination from FlowSignal:

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

### Field Specifications

| Field Name | Type | Required | Description | CAGE Internal Mapping |
|------------|------|----------|-------------|----------------------|
| `magnitude` | `number` (decimal) | **Yes** | Numeric value of the transaction or action magnitude | Mapped from CAGE internal `amount` |
| `currency` | `string` | **Yes** | ISO 4217 currency code (e.g., `"USD"`, `"EUR"`, `"GBP"`) | Extracted from transaction context |
| `context` | `string` | **Yes** | Human-readable description of the action intent or purpose | Mapped from CAGE internal `symbol` or `purpose` field |
| `platform` | `string` | **Yes** | Static platform identifier | Always set to `"GOOGLE-CAGE-REFERENCE"` |
| `execution_id` | `string` | **Yes** | Unique identifier for this execution request (UUID v4 or deterministic hash of action parameters) | Generated or derived from action envelope |
| `evidence_references` | `array<string>` | **Yes** | Array of URIs referencing supporting evidence in CAGE's tamper-evident chain | Format: `["cer://...", "cer://..."]` (CAGE Evidence References) |
| `approval_id` | `string \| null` | No | Optional pre-authorization identifier from prior human-in-the-loop approval | May be `null` for initial escalations |

### Example Request Payload

```json
{
  "magnitude": 75000.00,
  "currency": "USD",
  "context": "Large equity purchase: AAPL 500 shares",
  "platform": "GOOGLE-CAGE-REFERENCE",
  "execution_id": "550e8400-e29b-41d4-a716-446655440000",
  "evidence_references": [
    "cer://evidence/2026-09-14/tx-abc123",
    "cer://compliance/fria/550e8400"
  ],
  "approval_id": null
}
```

---

## Decision Mapping Rules

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
