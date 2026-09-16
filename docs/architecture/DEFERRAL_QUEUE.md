# Deferral Queue State Machine

## 1. Architectural Role & Domain Boundary

The Deferral Queue (`DeferQueue`) implements the "Deferral Service" mandate from the CSA AARM specification. It provides a formal parking state for executions suffering from situational ambiguity or data starvation, preventing the brittle constraint of forcing a binary ALLOW/DENY decision under uncertainty.

**Trust Boundaries**:
- **Upstream (Symbolic Governor)**: Determines when a context is confidence-starved (e.g., confidence `< 0.70`).
- **Downstream (Operators/Systems)**: External systems or human operators resolve the deferral via data injection or dual-control escalation.

## 2. Data & Execution Flow

When an execution enters the DEFER state, the context is parked as an immutable `DeferToken` in Redis.

```mermaid
flowchart TD
    Governor[Symbolic Governor] -->|Confidence < FRIA_ZONE_DEFER| Queue[DeferQueue]
    
    subgraph Redis db=1 (noeviction)
        Queue --> Hash[Redis Hash\nDEFER:defer_id]
        Queue --> ZSet[Redis ZSet\nDEFER:expiry_index]
    end
    
    Hash --> Resolution
    
    subgraph Resolution Paths
        Resolution --> Inject[Automated Data Injection\nPOST /v1/defer/id/inject]
        Resolution --> Escalate[HITL Dual-Control\nPOST /v1/defer/id/escalate]
        ZSet -->|TTL Expiry| Expire[Auto-Escalate to MANUAL_REVIEW]
    end
    
    Inject --> Resume[Resume LangGraph Thread]
    Escalate --> Resume
```

## 3. State Machine & Lifecycle

A `DeferToken` represents the parked execution context and progresses through a strict lifecycle:

- **Parking**: Token is minted with an initial TTL (default: 4 hours) and a `DeferReason` (e.g., `CONFIDENCE_BELOW_THRESHOLD`, `DATA_STARVATION`, `EXTERNAL_HOLD`).
- **Dual-Control Approval (Schema v2/v3)**: Human-in-the-loop escalation supports quorum-based approvals. The token tracks `approvals` containing durable operator URNs, timestamps, and WebAuthn cryptographic challenge bindings.
- **Resolution**:
  - `INJECTED`: An automated system supplies missing context, resuming execution.
  - `ESCALATED`: A human operator cryptographically signs the clearance.
  - `EXPIRED`: The TTL lapses, auto-escalating the decision to an explicit `MANUAL_REVIEW`.
  - Zero-Authority Parking: If `upstream_permit_id` is set, the token is bound to an external authority and cannot be resumed locally.

## 4. Operational Guarantees & Edge Cases

- **Eviction Immunity**: The tokens are stored in Redis `db=1` configured with a `noeviction` maxmemory policy. This guarantees that a sudden burst of unrelated cache traffic will never prematurely evict a pending deferral context.
- **Atomicity via Watch/Multi/Exec**: `DeferQueue.resolve()` uses Redis optimistic locking (`WATCH DEFER:{id}`) to ensure that a token cannot be simultaneously resolved by both an automated injection and a human operator.
- **WebAuthn Cryptographic Binding**: Phase 5 fixes require operators to bind approvals using WebAuthn. The queue validates the raw `client_data_json` against the signed `challenge_binding` to mathematically prove human intent at resolution time.

## 5. Configuration Contracts & Runtime Matrix

- **Confidence Boundaries**: Limits are configured via `config/governance_thresholds.json`. By default, executions below `FRIA_ZONE_DEFER` (0.70) are deferred.
- **Redis Isolation**: Deferral operations depend strictly on `db=1`, isolating them from the LangGraph checkpointer at `db=0`.
- **Feature Flagging**: Controlled by `CAGE_DEFER_ENABLED` (default: `true`). If disabled, all deferrable events fallback directly to a terminal `DENY` to ensure fail-closed safety.

