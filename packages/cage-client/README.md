# CAGE Client SDK (`cage-client`)

Lightweight Python Policy Enforcement Point (PEP) client for the **Cybernetic AI Governance Engine (CAGE)**.

## Features

- **Decoupled PEP/PDP Verification**: Communicates out-of-process with CAGE Gateways over TLS/mTLS (`POST /governance/validate-action`).
- **Fail-Closed Envelope Signature & Freshness Verification on Every Verdict**: Verifies every HTTP `200` and HTTP `403` `GovernanceEnvelope` by default against out-of-band `kid` trust anchors (`/governance/.well-known/jwks.json` or pinned `public_keys`), enforces `expires_at` temporal freshness, and binds `subject.action` + `subject.action_hash` to the submitted request before returning `ALLOW` or dispatching `NARROW`, `DENY`, `DEFER`, or `REQUIRE_APPROVAL`.
- **Fail-Closed HTTP & Posture Mediation**: Network failures, `5xx` errors, unsigned or non-envelope `403` responses, legacy `202`/`409`/`422` responses, and malformed or tampered `GovernanceEnvelope` payloads fail closed with `CageGatewayError` / `RoutingSealVerificationError` and are never treated as verified `DENY` or `DEFER` verdicts. Disabling verification is rejected whenever `CAGE_ENV` is unset, `"local"`, or any enforcing posture.
- **Immutable Schema Validation**: Parses verified gateway `GovernanceEnvelope` responses into frozen Pydantic models (`extra="forbid"`, strict mode).
- **W3C Distributed Tracing**: Propagates `traceparent` context across agent-to-gateway hops.

> **Preview vs. Committing Execution (`POAM-2026-251`):** `CageClient.validate_action()` calls `POST /governance/validate-action`, which is **advisory/preview-only** — it reserves no budget, mints no single-use routing seal, and performs no actuation. Committing runs execute on the gateway (`POST /tools/execute` or MCP `/mcp/`). The legacy `@cage_guard` decorator was removed in `0.5.0`; a replacement LangGraph node factory (`governed_node` / `approval_park_node`) over both preview and committing execution is tracked in [`POAM-2026-251`](../../docs/POAM.md). For a complete LangGraph reference today, see [`src/governed_financial_advisor/`](../../src/governed_financial_advisor/).

## Security Model & Verification Scope

1. **Out-of-Band `kid` Signature, Freshness & Request Binding (`AU-10`, `SC-23`):** By default (`verify_signature=True`, `verify_expiration=True`, `verify_subject=True`), `CageClient` resolves signing keys strictly out-of-band by `kid` from `{gateway_url}/governance/.well-known/jwks.json` (`JwksKeyResolver`, bounded `jwks_ttl_s=300.0` refresh, immediate eviction on authoritative HTTP `200` empty/malformed key sets, and hard `max_jwks_staleness_s=3600.0` fail-closed eviction) or caller-pinned `public_keys` — never from embedded envelope keys. It accepts exactly two signature algorithms, the two the gateway signs with (`ES256` on EC P-256 and `EdDSA` on Ed25519), and rejects every other algorithm and key type; a JWKS containing any other key is refused as a whole. It verifies signatures over RFC 8785 JCS canonical bytes, checks `expires_at` freshness within `clock_skew_seconds`, and validates `subject.action` + `subject.action_hash` on **every** HTTP `200` and HTTP `403` `GovernanceEnvelope` before returning `ALLOW` or dispatching `NARROW` / `DENY` / `DEFER` / `REQUIRE_APPROVAL` verdicts. Every verdict response is parsed as strict JSON (a repeated key or `NaN` is refused), and the envelope is validated without stripping, case-folding, or coercing anything. Disabling verification raises `ValueError` at startup unless `CAGE_ENV` (or `ENVIRONMENT`) is explicitly `"dev"`, `"development"`, `"test"`, or `"testing"`.
2. **Channel TLS/mTLS Does Not Substitute for Envelope Signature Verification (`SC-8`):** TLS/mTLS configured via `transport.py` (`create_mtls_transport`) protects only the point-to-point transport channel and **does NOT substitute for end-to-end `GovernanceEnvelope.signature` verification**. The envelope carries an asymmetric signature specifically so trust does not rest solely on transport or proxy configuration.

## Installation

```bash
pip install "git+https://github.com/google/cybernetic-agent-governance-engine.git#subdirectory=packages/cage-client"
```

Or with `uv`:

```bash
uv add "git+https://github.com/google/cybernetic-agent-governance-engine.git#subdirectory=packages/cage-client"
```

## Programmatic Preview Example (Read-Only / Non-Actuating)

```python
import asyncio
from cage_client import (
    CageClient,
    DeferralPending,
    PolicyViolationException,
    RoutingSealVerificationError,
)


async def preview_classification() -> None:
    # Resolves gateway signing keys out-of-band from /governance/.well-known/jwks.json
    # (or supply pinned trust anchors via public_keys={"kid": pem_bytes}).
    async with CageClient(
        gateway_url="https://cage-gateway.example.com",
    ) as client:
        try:
            envelope = await client.validate_action(
                action="query_portfolio",
                parameters={"account_scope": "summary"},
                agent_id="research-analyst-01",
            )
            print("Preview verdict:", envelope.payload.get("verdict"))
        except RoutingSealVerificationError as exc:
            print("Envelope signature/freshness/binding failed:", exc)
        except PolicyViolationException as exc:
            print("Preview denied or narrowed:", exc.reason_code, exc.violation_details)
        except DeferralPending as exc:
            print("Preview deferred, ticket:", exc.ticket_id)


asyncio.run(preview_classification())
```

## Learn More

- **LangGraph Integration Status & Reference Pointer:** [`docs/guides/LANGGRAPH_QUICKSTART.md`](../../docs/guides/LANGGRAPH_QUICKSTART.md)
- **Worked LangGraph Reference Application:** [`src/governed_financial_advisor/`](../../src/governed_financial_advisor/)
- **In-Monorepo Kernel Node Factories (Domain Plugins):** [`docs/architecture/EXTENSIBILITY_ARCHITECTURE.md`](../../docs/architecture/EXTENSIBILITY_ARCHITECTURE.md#41-langgraph-harness--governance-node-composition)
- **Breaking Changes (`0.5.0` `@cage_guard` removal):** [`docs/BREAKING_CHANGES.md`](../../docs/BREAKING_CHANGES.md)

## License

Apache License 2.0.
