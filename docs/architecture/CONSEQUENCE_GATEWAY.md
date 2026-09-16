# Consequence Gateway & Token Authority

## 1. Architectural Role & Domain Boundary

The `ConsequenceGateway` acts as the vendor-agnostic post-FRIA (Fundamental Rights Impact Assessment) execution boundary. It bridges the gap between the `SymbolicGovernor`'s abstract policy decisions and the downstream `ExecutionActuator`'s concrete side-effects.

Its primary role is to ensure that no action is executed unless it possesses a valid, unexpired, mathematically bound, and cryptographically signed `ConsequenceToken` (JWS). It enforces exactly-once execution semantics by atomizing authority consumption against a central `ConsequenceAuthorityStore`.

**Trust Boundaries**:
- **Upstream (Governance Layer)**: Trusted to mint `ConsequenceToken`s exclusively upon successful `ALLOW` classifications.
- **Downstream (Actuators)**: Cannot execute side-effects autonomously; they rely entirely on the Gateway's final `EXECUTE` emission.

## 2. Data & Execution Flow

The gateway evaluates requests using a strict 6-step sequence to verify cryptographically-bound execution rights.

```mermaid
sequenceDiagram
    participant Adapter as Execution Adapter
    participant Gateway as ConsequenceGateway
    participant KMS as KMS Signer
    participant Store as Authority Store (Redis)
    
    Adapter->>Gateway: evaluate(token, action_payload)
    Gateway->>KMS: Verify JWS Signature & Claims
    KMS-->>Gateway: Valid Claims (sub, tid, rec, act)
    Gateway->>Gateway: JCS-canonicalize action_payload
    Gateway->>Gateway: Hash SHA256(canonical_payload)
    Gateway->>Gateway: Assert Hash == claims.act (TOCTOU Defense)
    Gateway->>Store: consume_once(rec, binding_hash)
    Store-->>Gateway: Result: Consumed Successfully
    Gateway-->>Adapter: ConsequenceDecision.EXECUTE
```

## 3. State Machine & Lifecycle

The lifecycle revolves around the `ConsequenceToken` and its corresponding authority record:

- **Minting**: Upon governance clearance, a short-TTL JWS is minted. It encapsulates the actor (`sub`), thread (`tid`), authority record ID (`rec`), and action digest (`act`).
- **Transit**: The token travels transparently through execution queues alongside the raw action payload.
- **Consumption (Atomic)**: The `ConsequenceAuthorityStore` consumes the record (`rec`) binding it to the unique execution tuple.
- **Rejection States**:
  - `TOKEN_INVALID`: Cryptographic signature failure or TTL expiration.
  - `ACTION_BINDING_MISMATCH`: The hash of the presented payload does not match the signed `act` claim.
  - `ALREADY_CONSUMED`: The token was previously consumed (Replay attempt).
  - `AUTHORITY_RECORD_BINDING_MISMATCH`: The record was consumed by a different payload/thread (Substitution attempt).

## 4. Operational Guarantees & Edge Cases

- **Fail-Closed Evaluation**: Any cryptographic failure, payload mismatch, or Redis connectivity error immediately collapses the decision to `BLOCK`. It never silently defaults to `EXECUTE`.
- **TOCTOU Elimination**: By JCS-canonicalizing the raw runtime payload and re-deriving the SHA-256 hash immediately before consumption, the gateway completely eliminates Time-of-Check to Time-of-Use tampering vectors.
- **Clock Skew Tolerance**: The token verifier permits an `iat` claim up to 5 seconds in the future to mitigate minor NTP drift across distributed Kubernetes nodes.
- **Algorithm Confusion Prevention**: The token verification strictly asserts that the token's header `alg` matches the `KMSGovernanceSigner`'s hardcoded expected algorithm, entirely rejecting `alg: none` attacks.

## 5. Configuration Contracts & Runtime Matrix

- **Storage Backend (Redis)**: The `ConsequenceAuthorityStore` relies on a highly available Redis instance for atomic `SETNX` or LUA-based single-use consumptions.
- **KMS Signer**: Requires an active, reachable Cloud KMS hardware security module (HSM) connection at initialization. If the signer is unreachable or the key is disabled, the service refuses to start.
- **Canonicalization Contract**: Downstream execution payloads must be strictly JSON-serializable to support stable JCS (JSON Canonicalization Scheme, RFC 8785) hashing.

