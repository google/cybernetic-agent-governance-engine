# CAGE Client SDK (`cage-client`)

Lightweight Python Policy Enforcement Point (PEP) client for the **Cybernetic AI Governance Engine (CAGE)**.

## Features

- **Decoupled PEP/PDP Verification & Committing Tool Execution**: Communicates out-of-process with CAGE Gateways over TLS/mTLS (`POST /governance/validate-action` via `validate_action()` / `preview()`, and `POST /tools/execute` via `execute_tool()`).
- **Fail-Closed Envelope & CommitOutcome Signature Verification**: Verifies every HTTP `200` and HTTP `403` `GovernanceEnvelope` and every `CommitOutcome` (`200`, `202`, `403`) by default against out-of-band `kid` trust anchors (`GET /governance/.well-known/jwks.json` or pinned `public_keys`), enforces `expires_at` temporal freshness, binds `subject.action` + `subject.action_hash` + `payload.correlation_id` (on preview envelopes) or `tool_name` + `idempotency_key` + `request_hash` (on `CommitOutcome` payloads), separates HITL deferral ticket lifetime (`defer_expires_at`) from 5-minute envelope expiry (`envelope_expires_at`), and routes all verification opt-out posture checks through `enforce_verification_posture()` (rejecting opt-outs unless `CAGE_ENV` / `ENVIRONMENT` is explicitly `dev`/`development`/`test`/`testing`, and logging a warning whenever opt-out is active).
- **Fail-Closed HTTP & Transport Mediation**: Network failures, `5xx` errors, unsigned or non-envelope `403` responses, and malformed or tampered payloads fail closed (`CageGatewayError`, `GatewayUnavailableError`, `RoutingSealVerificationError`, `CommitOutcomeDecodeError`, or `CLIENT_INFERRED` `CommitStatus.INDETERMINATE` for ambiguous post-dispatch `execute_tool()` failures) and are never treated as verified `DENY`, `DEFER`, or `EXECUTED` outcomes.
- **Deterministic Idempotency & LangGraph (`langgraph>=1.0.0`) Nodes**: Includes `derive_plan_step_key()` / `derive_idempotency_key()` and `cage_client.langgraph` (`governed_node`, `approval_park_node`, `governed_tool_node`) with explicit `Command` routing, durable `deferred_id` checkpointing before `interrupt()`, and guaranteed `ToolMessage(tool_call_id=...)` pairing across `1..N` tool-call batches.
- **Immutable Schema Validation**: Parses verified gateway `GovernanceEnvelope` and `CommitOutcome` responses into frozen Pydantic models (`extra="forbid"`, strict mode).
- **W3C Distributed Tracing**: Propagates `traceparent` context across agent-to-gateway hops.

> **Preview vs. Committing Execution (`POAM-2026-251`):** `CageClient.validate_action()` and `CageClient.preview()` call `POST /governance/validate-action`, which is **advisory/preview-only** — it reserves no budget, mints no single-use routing seal, and performs no actuation. Committing side effects must call `CageClient.execute_tool()` (`POST /tools/execute`) or use `cage_client.langgraph` (`governed_node`, `approval_park_node`, `governed_tool_node`), which verify the gateway's signed `CommitOutcome`. The legacy `@cage_guard` decorator was removed in `0.5.0`; migration of [`src/governed_financial_advisor/`](../../src/governed_financial_advisor/) onto these SDK nodes remains tracked in [`POAM-2026-251`](../../docs/POAM.md).

## Security Model & Verification Scope

1. **Out-of-Band `kid` Signature, Freshness & Request Binding (`AU-10`, `SC-23`):** By default (`verify_signature=True`, `verify_expiration=True`, `verify_subject=True`), `CageClient` resolves signing keys strictly out-of-band by `kid` from `{gateway_url}/governance/.well-known/jwks.json` (`JwksKeyResolver`, bounded `jwks_ttl_s=300.0` refresh, immediate eviction on authoritative HTTP `200` empty/malformed key sets, and hard `max_jwks_staleness_s=3600.0` fail-closed eviction) or caller-pinned `public_keys` — never from embedded keys. It accepts `ES256` (EC P-256) and `EdDSA` (Ed25519) only, and rejects any JWKS containing another key type/algorithm. It verifies RFC 8785 JCS canonical bytes, checks `expires_at` freshness within `clock_skew_seconds`, validates `subject.action` + `subject.action_hash` + `payload.correlation_id` (constant-time `hmac.compare_digest()` on preview envelopes), separates HITL deferral ticket lifetime (`defer_expires_at`, parsed strictly or derived from `issued_at + ttl_seconds` with a `WARNING` log when defaulting to `14400s` — never `envelope.expires_at`) onto `DeferralPending` and `PreviewResult`, and verifies signed `CommitOutcome` binding (`tool_name`, `idempotency_key`, `request_hash`, out-of-band `kid`) on `execute_tool()` responses (`200`, `202`, `403`). Every response is parsed as strict JSON (repeated keys or `NaN` fail closed). All verification posture decisions pass through `enforce_verification_posture()`: disabling verification raises `ValueError` at startup unless `CAGE_ENV` (or `ENVIRONMENT`) is explicitly `"dev"`, `"development"`, `"test"`, or `"testing"`, and emits a `WARNING` log when permitted.
2. **Channel TLS/mTLS Does Not Substitute for Envelope Signature Verification (`SC-8`):** TLS/mTLS configured via `transport.py` (`create_mtls_transport`) protects only the point-to-point transport channel and **does NOT substitute for end-to-end `GovernanceEnvelope.signature` or `CommitOutcome.signature` verification**. Signed payloads ensure trust does not rest solely on transport or proxy configuration.

## Installation

```bash
pip install "git+https://github.com/google/cybernetic-agent-governance-engine.git#subdirectory=packages/cage-client"
# With LangGraph (>=1.0.0) node factories:
pip install "cage-client[langgraph] @ git+https://github.com/google/cybernetic-agent-governance-engine.git#subdirectory=packages/cage-client"
```

Or with `uv`:

```bash
uv add "git+https://github.com/google/cybernetic-agent-governance-engine.git#subdirectory=packages/cage-client"
```

## Programmatic Preview & Committing Execution Example

```python
import asyncio
from cage_client import (
    CageClient,
    CommitStatus,
    GovernanceDecision,
    RoutingSealVerificationError,
    derive_plan_step_key,
)


async def run_governed_flow() -> None:
    # Resolves gateway signing keys out-of-band from /governance/.well-known/jwks.json
    # (or supply pinned trust anchors via public_keys={"kid": pem_bytes}).
    async with CageClient(
        gateway_url="https://cage-gateway.example.com",
    ) as client:
        try:
            # 1. Non-raising advisory preview (5 explicit GovernanceDecision outcomes)
            decision = await client.preview(
                action="query_portfolio",
                parameters={"account_scope": "summary"},
                agent_id="research-analyst-01",
            )
            if decision.decision is not GovernanceDecision.ALLOWED:
                print(
                    "Preview blocked/deferred:", decision.decision, decision.reason_code
                )
                return

            # 2. Committing tool execution with deterministic plan-step idempotency key
            idempotency_key = derive_plan_step_key(
                session_id="sess-01",
                step_id="step-1",
                tool_name="query_portfolio",
                arguments={"account_scope": "summary"},
            )
            outcome = await client.execute_tool(
                tool_name="query_portfolio",
                arguments={"account_scope": "summary"},
                principal="research-analyst-01",
                idempotency_key=idempotency_key,
            )
            if outcome.status is CommitStatus.EXECUTED:
                print("Committed result:", outcome.result)
            else:
                print(
                    "Non-executed commit outcome:",
                    outcome.status,
                    outcome.refusal_reason,
                )
        except RoutingSealVerificationError as exc:
            print("Envelope or CommitOutcome signature verification failed:", exc)


asyncio.run(run_governed_flow())
```

## Learn More

- **LangGraph Integration Guide & Node Factories:** [`docs/guides/LANGGRAPH_QUICKSTART.md`](../../docs/guides/LANGGRAPH_QUICKSTART.md)
- **Worked LangGraph Reference Application:** [`src/governed_financial_advisor/`](../../src/governed_financial_advisor/)
- **In-Monorepo Kernel Node Factories (Domain Plugins):** [`docs/architecture/EXTENSIBILITY_ARCHITECTURE.md`](../../docs/architecture/EXTENSIBILITY_ARCHITECTURE.md#41-langgraph-harness--governance-node-composition)
- **Breaking Changes (`0.5.0` `@cage_guard` removal):** [`docs/BREAKING_CHANGES.md`](../../docs/BREAKING_CHANGES.md)

## License

Apache License 2.0.
