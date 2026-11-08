# Deferral Queue State Machine

**Last Updated:** 2026-11-08

## 1. Architectural Role & Domain Boundary

The Deferral Queue ([`DeferQueue`](../../src/gateway/governance/defer_queue.py)) implements the "Deferral Service" mandate from the CSA AARM specification. It provides a formal parking state for executions suffering from situational ambiguity or data starvation, preventing the brittle constraint of forcing a binary ALLOW/DENY decision under uncertainty.

**Trust Boundaries**:
- **Upstream (Gateway `SymbolicGovernor`)**: `ConfidenceStage` emits a `DEFERRABLE` violation when the self-reported confidence is below `FRIA_ZONE_DEFER` (default 0.70), and `WarrantStage` emits `RELIANCE_INELIGIBLE` when a governing warrant is missing, stale, or revoked. `ClassificationEngine` then returns `DEFER`, and `handle_defer()` ([`governor/verdicts.py`](../../src/gateway/governance/governor/verdicts.py)) parks a `DeferToken` via `DeferQueue.park()` on Redis `db=1` (from `REDIS_URL`), reusing the process-scoped shared queue (`get_shared_defer_queue()` / `open_defer_queue()`, pre-warmed at gateway boot with pre-loaded CAS Lua script SHAs via `ensure_scripts_loaded()`). The gateway is the only component that parks tokens.
- **Downstream (Operators/Systems)**: External systems or human operators resolve the deferral via data injection or dual-control escalation. The resolution API is served by the compliance bridge ([`src/compliance_bridge/main.py`](../../src/compliance_bridge/main.py)), which opens its own `DeferQueue` on the same Redis database.
- **Governed advisor (client)**: The advisor owns no `DeferQueue`. Its [`defer_node`](../../src/governed_financial_advisor/graph/nodes/defer_node.py) only checkpoints the gateway-issued `deferral_ticket_id`, and fails closed (raises) when that ticket is missing.

## 2. Data & Execution Flow

When an execution enters the DEFER state, the context is parked as an immutable `DeferToken` in Redis.

```mermaid
flowchart TD
    Governor[Gateway SymbolicGovernor] -->|Confidence < confidence.defer_floor| Queue[DeferQueue]
    
    subgraph Redis db=1 (noeviction)
        Queue --> Hash[Redis Hash\nDEFER:defer_id]
        Queue --> ZSet[Redis ZSet\nDEFER:expiry_index]
    end
    
    Hash --> Resolution
    
    subgraph Resolution Paths
        Resolution --> Inject[Automated Data Injection\ncompliance bridge POST /v1/defer/id/inject]
        Resolution --> Escalate[HITL Dual-Control\ncompliance bridge POST /v1/defer/id/escalate]
        ZSet -->|TTL Expiry via expire_stale| Expire[Auto-Escalate to MANUAL_REVIEW]
    end
    
    Inject --> Resume[Resume LangGraph Thread]
    Escalate --> Resume
```

## 3. State Machine & Lifecycle

A `DeferToken` represents the parked execution context and progresses through a strict lifecycle:

- **Parking**: Token is minted with an initial TTL (default: 4 hours) and a `DeferReason` (e.g., `CONFIDENCE_BELOW_THRESHOLD`, `WARRANT_INELIGIBLE`, `DATA_STARVATION`, `EXTERNAL_HOLD`). The reason is mapped from the classifier's `classification_reason` by exact match; an unmapped reason is an error, never a default. `WARRANT_INELIGIBLE` tokens need a quorum of 3 and cannot be resolved by data injection: only a re-issued warrant and a fresh request clear them. If the Redis park fails, `handle_defer()` logs a warning and still returns `DEFER` with a local `defer_id`. The action is not executed, but the token is not persisted, so the resolution API cannot find it.
- **Dual-Control Approval (Schema v2/v3, `POAM-2026-196`)**: Human-in-the-loop escalation goes through `POST /v1/defer/{defer_id}/escalate` on [`src/compliance_bridge/main.py`](../../src/compliance_bridge/main.py) and `DeferQueue.approve()`, which enforces a per-reason quorum (`get_required_quorum()`: 2 for baseline dual control, 3 for irreversible terminals and external escalations), authenticates human operators via [`require_human_operator_identity()`](../../src/compliance_bridge/auth.py) without requiring workload `CAGE_INTERNAL_TOKEN`, refuses workload SVID principals (`403 Forbidden` via [`ensure_human_operator_principal()`](../../src/compliance_bridge/auth.py)), and enforces separation of duties against the request's `initiator_urn` bound at park time in [`_park_defer_context()`](../../src/gateway/governance/governor/verdicts.py) (resolving verified mTLS `current_client_identity()` first before falling back to request parameters). The token tracks `approvals` containing verified human OIDC `sub` principals (e.g., `risk-officer-primary@example.com`, matched directly against `CAGE_TRUSTED_OPERATOR_IDENTITIES`), UTC timestamps, and WebAuthn challenge bindings.
- **Resolution**:
  - `INJECTED`: An automated system supplies missing context; `replay_evaluate()` admits the token only if the enriched confidence reaches `DEFER_CONFIDENCE_THRESHOLD`, otherwise it stays `PARKED`.
  - `ESCALATED`: The approval quorum is met by distinct operators.
  - `EXPIRED`: The TTL lapses and `DeferQueue.expire_stale()` marks the token expired, escalating it to an explicit `MANUAL_REVIEW` (`EXTERNAL_HOLD` tokens can also be routed to a DLQ publisher). At HEAD no background task in `src/` calls `expire_stale()`, so an operator job must schedule the sweep.
  - Zero-Authority Parking: If `upstream_permit_id` is set, the token is bound to an external authority and cannot be resumed locally.

## 4. Operational Guarantees & Edge Cases

- **Eviction Immunity**: The tokens are stored in Redis `db=1` configured with a `noeviction` maxmemory policy. This guarantees that a sudden burst of unrelated cache traffic will never prematurely evict a pending deferral context.
- **Atomicity via Revision CAS**: Token mutations use a revision-based compare-and-swap Lua script (`DeferQueue._cas_update()`), with bounded retry in `_resolve()`. A token therefore cannot be resolved concurrently by both an automated injection and a human operator. Per ADR-008 the resolution path is **strictly private**: there is no public `resolve()` or `atomic_resolve()`. Callers reach resolution only through `replay_evaluate()` (inject), `approve()` (escalate), or `expire_stale()` (TTL), while `_atomic_resolve()` is the private status-CAS helper invoked internally by `consume_approval()` (`RESOLVED -> CONSUMED`).
- **Retry-safe writes**: Pooled Redis clients re-send a command whose reply was lost, after the server already ran it. Parking is therefore one Lua script that writes token, status, revision and TTL together, and parking, the revision CAS (`DeferQueue._cas_update()`) and `DeferQueue._atomic_resolve()` store a random per-attempt `op_id` in the token hash. A re-sent script finds its own `op_id` and returns its original success instead of a conflict; any other writer still conflicts.
- **WebAuthn CollectedClientData Challenge & Human OIDC Binding (`POAM-2026-196`)**: Whenever `DeploymentPosture.from_env().is_enforcing()` holds, [`ApprovalRecord`](../../src/gateway/governance/defer_queue.py), `DeferQueue.approve()`, and `POST /v1/defer/{defer_id}/escalate` require non-empty `client_data_json` and `challenge_binding` and verify via `ApprovalRecord.verify_webauthn_challenge()` that `client_data_json` decodes to a W3C CollectedClientData JSON payload with `"type": "webauthn.get"` whose base64url `challenge` decodes to the exact 32-byte SHA-256 `challenge_binding` digest. (`verify_webauthn_challenge()` validates CollectedClientData challenge binding and caches `client_data_hash`; full FIDO2 `authenticatorData` + COSE assertion signature verification and RP `origin` pinning are tracked separately.) Human operator identity is verified at the compliance bridge boundary via [`validate_operator_oidc_token()`](../../src/compliance_bridge/auth.py) and [`OidcVerifier`](../../src/compliance_bridge/oidc_verifier.py), which validate the operator's Bearer JWT against out-of-band `kid`-resolved public keys (`CAGE_OPERATOR_JWKS_JSON`, `CAGE_OPERATOR_JWKS_FILE`, or `https://` `CAGE_OPERATOR_JWKS_URI`), pinned `iss` (`CAGE_OPERATOR_OIDC_ISSUER`) and `aud` (`CAGE_OPERATOR_OIDC_AUDIENCE`), and the fail-closed `CAGE_TRUSTED_OPERATOR_IDENTITIES` human allowlist.

## 5. Configuration Contracts & Runtime Matrix

- **Confidence Boundaries**: Limits are configured via `config/governance_thresholds.json`. By default, executions below `confidence.defer_floor` (0.70, `get_confidence_defer_floor()`) are deferred; `replay_evaluate()` admits a hydrated token only once its confidence clears the same floor.
- **Redis Isolation**: Deferral operations depend strictly on `db=1`, isolating them from the LangGraph checkpointer at `db=0`. In the `gcp-gke` target this is the governance Memorystore instance, and Redis runs with `noeviction` in every environment.
- **Feature Flagging**: Controlled by `CAGE_DEFER_ENABLED` (default: `true`), read once at assembly into the governor's `ClassificationEngine`. If disabled, all deferrable events fall back directly to a terminal `DENY` to ensure fail-closed safety.

## 6. Operator HITL Review Runbook (`POAM-2026-196`)

Human risk officers inspect and approve parked `DeferToken` records using [`scripts/cage_hitl_review.py`](../../scripts/cage_hitl_review.py) over a local tunnel to port `3001`, authenticated with a human OIDC JWT (`CAGE_OPERATOR_OIDC_TOKEN`; workload `CAGE_INTERNAL_TOKEN` is never required on `approve`):

1. **Open a local port-forward to `compliance-bridge` (`3001`) and export your human OIDC JWT** (whose `kid` resolves in `CAGE_OPERATOR_JWKS_URI` / `CAGE_OPERATOR_JWKS_JSON` / `CAGE_OPERATOR_JWKS_FILE` and whose `sub` claim matches an entry in `CAGE_TRUSTED_OPERATOR_IDENTITIES`, e.g. `risk-officer-primary@example.com`):
   ```bash
   kubectl port-forward -n governance-stack svc/compliance-bridge 3001:3001
   export COMPLIANCE_BRIDGE_URL="http://127.0.0.1:3001"
   export CAGE_OPERATOR_OIDC_TOKEN="<human-oidc-jwt>"
   ```
2. **List parked deferrals**:
   ```bash
   python scripts/cage_hitl_review.py list --limit 50
   ```
3. **Inspect a specific `defer_id`** (verify `initiator_urn`, `defer_reason`, `required_quorum`, `barrier_preview`, and `narrow_hint`):
   ```bash
   python scripts/cage_hitl_review.py inspect <defer_id>
   ```
4. **Submit a human approval** (each distinct reviewer runs `approve` with their own OIDC JWT and WebAuthn `client_data_json` + `challenge_binding` until `required_quorum` is reached; self-approval by `initiator_urn` and workload SVID tokens are rejected with `403 Forbidden`):
   ```bash
   python scripts/cage_hitl_review.py approve <defer_id> \
     --client-data-json "$CAGE_WEBAUTHN_CLIENT_DATA_JSON" \
     --challenge-binding "$CAGE_WEBAUTHN_CHALLENGE_BINDING"
   ```
