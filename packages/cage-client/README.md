# CAGE Client SDK (`cage-client`)

Lightweight Python Policy Enforcement Point (PEP) client for the **Cybernetic AI Governance Engine (CAGE)**. Designed for zero-overhead integration into LangGraph and LangChain agent graphs.

## Features

- **Decoupled PEP/PDP Architecture**: Communicates out-of-process with CAGE Gateways via REST over TLS/mTLS.
- **Fail-Closed Envelope Signature & Freshness Verification**: Verifies every HTTP `200` `GovernanceEnvelope` by default against out-of-band `kid` trust anchors (`/governance/.well-known/jwks.json` or pinned `public_keys`), enforces `expires_at` temporal freshness, and binds `subject.action` + `subject.action_hash` to the submitted request.
- **Fail-Closed HTTP & Verdict Mediation**: Network failures, `5xx` errors, refusals (`403`/`422` or HTTP `200` `DENY`/`NARROW`), deferrals (`202`/`409` or HTTP `200` `DEFER`/`REQUIRE_APPROVAL`), and malformed or tampered `GovernanceEnvelope` payloads automatically block execution.
- **Immutable Schema Validation**: Parses verified gateway `GovernanceEnvelope` responses into frozen Pydantic models (`extra="forbid"`).
- **LangGraph Native Adapter**: Pre-execution node decoration via `@cage_guard`.
- **W3C Distributed Tracing**: Propagates `traceparent` context across agent-to-gateway hops.

## Security Model & Verification Scope

1. **Out-of-Band `kid` Signature, Freshness & Request Binding (`AU-10`, `SC-23`):** By default (`verify_signature=True`, `verify_expiration=True`, `verify_subject=True`), `CageClient` resolves signing keys strictly out-of-band by `kid` from `{gateway_url}/governance/.well-known/jwks.json` (`JwksKeyResolver`, bounded `jwks_ttl_s=300.0` refresh and hard `max_jwks_staleness_s=3600.0` fail-closed eviction) or caller-pinned `public_keys` — never from embedded envelope keys. It accepts exactly two signature algorithms, the two the gateway signs with (`ES256` on EC P-256 and `EdDSA` on Ed25519), and rejects every other algorithm and key type; a JWKS containing any other key is refused as a whole. It verifies signatures over RFC 8785 JCS canonical bytes, checks `expires_at` freshness within `clock_skew_seconds`, and validates `subject.action` + `subject.action_hash` before returning `ALLOW` or dispatching `NARROW` / `DENY` / `DEFER` verdicts. It acts only on the values it verified: the response is parsed as strict JSON (a repeated key or `NaN` is refused), and the envelope is validated without stripping, case-folding or coercing anything, so the verdict, `kid`, algorithm, subject and timestamps are read exactly as signed. Disabling verification is rejected at startup in any non-dev/test `CAGE_ENV` posture.
2. **Channel TLS/mTLS Does Not Substitute for Envelope Signature Verification (`SC-8`):** TLS/mTLS configured via `transport.py` (`create_mtls_transport`) protects only the point-to-point transport channel and **does NOT substitute for end-to-end `GovernanceEnvelope.signature` verification**. The envelope carries an asymmetric signature specifically so trust does not rest solely on transport or proxy configuration.

## Installation

### From GitHub Repository
```bash
# Direct git installation
pip install "git+https://github.com/google/cybernetic-agent-governance-engine.git#subdirectory=packages/cage-client"

# With LangGraph support
pip install "cage-client[langgraph] @ git+https://github.com/google/cybernetic-agent-governance-engine.git#subdirectory=packages/cage-client"
```

### With `uv`
```bash
uv add "git+https://github.com/google/cybernetic-agent-governance-engine.git#subdirectory=packages/cage-client"
```

## Quick Start

### 1. Programmatic Policy Validation

```python
import asyncio
from cage_client import (
    CageClient,
    DeferralPending,
    PolicyViolationException,
    RoutingSealVerificationError,
)


async def main():
    # Resolves gateway signing keys out-of-band from /governance/.well-known/jwks.json
    # (or supply pinned trust anchors via public_keys={"kid": pem_bytes}).
    async with CageClient(
        gateway_url="https://cage-gateway.example.com",
    ) as client:
        try:
            envelope = await client.validate_action(
                action="execute_trade",
                parameters={"symbol": "AAPL", "amount": 1000.0},
                agent_id="portfolio-manager",
            )
            print("Action approved:", envelope.payload.get("verdict"))
        except RoutingSealVerificationError as exc:
            print("Envelope signature/freshness/binding failed:", exc)
        except PolicyViolationException as exc:
            print("Action denied:", exc.reason_code, exc.violation_details)
        except DeferralPending as exc:
            print("Action deferred for HITL review, ticket:", exc.ticket_id)


asyncio.run(main())
```

### 2. LangGraph Node Pre-Execution Guard

```python
from cage_client import CageClient
from cage_client.adapters.langgraph import cage_guard

cage = CageClient(gateway_url="https://cage-gateway.example.com")


@cage_guard(
    client=cage,
    action="execute_trade",
)
async def trade_execution_node(state: dict) -> dict:
    # This node only executes if CAGE Gateway issues a cryptographically verified ALLOW envelope
    return {"trade_status": "EXECUTED"}
```

## Client SDK vs. Node Factories: Which to Use?

CAGE provides two integration patterns for LangGraph applications. Choose based on your deployment model:

| Use Case | Recommended Approach | Dependencies |
|----------|---------------------|--------------|
| **Standalone LangGraph app** consuming CAGE as a governance service | ✅ `cage-client` SDK | Lightweight package (`httpx`, `pydantic`, `cryptography`) |
| **Building inside the CAGE monorepo** (e.g., new domain plugin) | Node factories ([`langgraph_harness/`](../../src/gateway/governance/langgraph_harness/)) | Full CAGE repository |
| **Rapid prototyping** with minimal dependencies | ✅ `cage-client` SDK | Lightweight |
| **Contributing to CAGE core** or extending the kernel | Node factories | Full monorepo |
| **Enterprise deployment** with separate governance infrastructure | ✅ `cage-client` SDK | Decoupled PEP/PDP |

### Client SDK (This Package)

**Pros:**
- Lightweight: 3 runtime dependencies (`httpx`, `pydantic`, `cryptography`)
- End-to-end verified: Out-of-band `kid` JWKS/PEM signature, freshness, and action-hash verification on by default
- Decoupled: LangGraph app and CAGE services deploy independently
- Simple: `pip install cage-client[langgraph]` and you're ready
- Fail-closed: Network errors and envelope verification failures automatically block execution

**Architecture:**
```
Your LangGraph App (pip install cage-client)
    │
    └──► @cage_guard decorator ──HTTP/2──► CAGE Gateway :8080
                                            (separate deployment)
```

**Example:**
```python
from cage_client import CageClient
from cage_client.adapters.langgraph import cage_guard

cage = CageClient(gateway_url="https://cage-gateway.example.com")


@cage_guard(client=cage, action="execute_trade")
async def trade_node(state: dict) -> dict:
    return {"result": "executed"}
```

### Node Factories (Advanced)

**Pros:**
- Direct access to CAGE kernel internals
- No network hop for in-process governance nodes
- Full control over tier composition

**Architecture:**
```
CAGE Monorepo
    │
    └──► src/gateway/governance/langgraph_harness/
         (embedded in same Python process)
```

**Example:**
```python
from src.gateway.governance.langgraph_harness import create_opa_safety_node

graph.add_node("safety_check", create_opa_safety_node(policy_path="trade_governance"))
```

**When to use:** You're building a new domain plugin inside `src/cage_yourdomain/` or extending CAGE's kernel.

### Migration Path

If you start with the client SDK and later need direct kernel access, the migration is straightforward:

```python
# Before (client SDK)
@cage_guard(client=cage, action="execute_trade")
async def trade_node(state): ...


# After (node factory)
from src.gateway.governance.langgraph_harness import create_opa_safety_node

graph.add_node("opa_check", create_opa_safety_node(policy_path="trade_governance"))
```

The decision semantics remain identical (`ALLOW`/`DENY`/`DEFER`).

## Learn More

- **Quick Start Guide:** [`docs/guides/LANGGRAPH_QUICKSTART.md`](../../docs/guides/LANGGRAPH_QUICKSTART.md)
- **Tutorial Notebook:** [`docs/guides/langgraph_governance_tutorial.ipynb`](../../docs/guides/langgraph_governance_tutorial.ipynb)
- **LangGraph Harness (Advanced):** [`docs/architecture/EXTENSIBILITY_ARCHITECTURE.md`](../../docs/architecture/EXTENSIBILITY_ARCHITECTURE.md#41-langgraph-harness--governance-node-composition)
- **Release Notes:** [client-v0.2.0](https://github.com/google/cybernetic-agent-governance-engine/releases/tag/client-v0.2.0)

## License

Apache License 2.0.
