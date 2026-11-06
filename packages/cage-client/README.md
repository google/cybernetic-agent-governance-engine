# CAGE Client SDK (`cage-client`)

Lightweight Python Policy Enforcement Point (PEP) client for the **Cybernetic AI Governance Engine (CAGE)**. Designed for zero-overhead integration into LangGraph and LangChain agent graphs.

## Features

- **Decoupled PEP/PDP Architecture**: Communicates out-of-process with CAGE Gateways via REST over TLS/mTLS.
- **Fail-Closed HTTP Mediation**: Network failures, `5xx` errors, refusals (`403`/`422`), deferrals (`202`/`409`), and malformed `GovernanceEnvelope` JSON automatically block execution.
- **Immutable Schema Validation**: Parses gateway `GovernanceEnvelope` responses into frozen Pydantic models (`signature` and `expires_at` are parsed as untrusted schema fields and are **not** verified client-side; see [Security Model & Verification Scope](#security-model--verification-scope)).
- **LangGraph Native Adapter**: Pre-execution node decoration via `@cage_guard`.
- **W3C Distributed Tracing**: Propagates `traceparent` context across agent-to-gateway hops.

## Security Model & Verification Scope

1. **HTTP Status & Schema Mediation Only (No Client-Side Signature or Freshness Check):** `CageClient` currently performs Pydantic schema validation and fail-closed HTTP status mediation (`200`/`403`/`422`/`202`/`409`/`5xx`) only — **it does NOT verify `GovernanceEnvelope.signature` against a gateway trust anchor and does NOT check `GovernanceEnvelope.expires_at` freshness client-side**. Both `signature` and `expires_at` are parsed as untrusted fields unless verified separately against an independently resolved out-of-band `kid` trust anchor.
2. **Channel TLS/mTLS Does Not Substitute for Envelope Signature Verification:** TLS/mTLS configured via `transport.py` (`create_mtls_transport`) protects only the point-to-point transport channel and **does NOT substitute for end-to-end `GovernanceEnvelope.signature` verification**. The envelope carries a cryptographic signature specifically so trust does not rest solely on transport or proxy configuration.

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
from cage_client import CageClient, PolicyViolationException, DeferralPending


async def main():
    async with CageClient(
        gateway_url="http://localhost:8080",
    ) as client:
        try:
            envelope = await client.validate_action(
                action="execute_trade",
                parameters={"symbol": "AAPL", "amount": 1000.0},
                agent_id="portfolio-manager",
            )
            print("Action approved:", envelope.payload.get("decision"))
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

cage = CageClient(gateway_url="http://localhost:8080")


@cage_guard(
    client=cage,
    action="execute_trade",
)
async def trade_execution_node(state: dict) -> dict:
    # This node only executes if CAGE Gateway issues an ALLOW decision
    return {"trade_status": "EXECUTED"}
```

## Client SDK vs. Node Factories: Which to Use?

CAGE provides two integration patterns for LangGraph applications. Choose based on your deployment model:

| Use Case | Recommended Approach | Dependencies |
|----------|---------------------|--------------|
| **Standalone LangGraph app** consuming CAGE as a governance service | ✅ `cage-client` SDK | Lightweight package (httpx, pydantic) |
| **Building inside the CAGE monorepo** (e.g., new domain plugin) | Node factories ([`langgraph_harness/`](../../src/gateway/governance/langgraph_harness/)) | Full CAGE repository |
| **Rapid prototyping** with minimal dependencies | ✅ `cage-client` SDK | Lightweight |
| **Contributing to CAGE core** or extending the kernel | Node factories | Full monorepo |
| **Enterprise deployment** with separate governance infrastructure | ✅ `cage-client` SDK | Decoupled PEP/PDP |

### Client SDK (This Package)

**Pros:**
- Lightweight: 2 runtime dependencies (`httpx`, `pydantic`)
- Decoupled: LangGraph app and CAGE services deploy independently
- Simple: `pip install cage-client[langgraph]` and you're ready
- Fail-closed: Network errors automatically block execution

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

cage = CageClient(gateway_url="http://localhost:8080")


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
