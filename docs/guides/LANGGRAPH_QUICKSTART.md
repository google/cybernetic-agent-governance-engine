# LangGraph Integration Quickstart

5-minute guide to integrating CAGE governance into your LangGraph application using the `cage-client` SDK.

## Prerequisites

- Python 3.10+
- Docker & Docker Compose (for CAGE services)

## Step 1: Install Client SDK

```bash
pip install "cage-client[langgraph] @ git+https://github.com/google/cybernetic-agent-governance-engine.git#subdirectory=packages/cage-client"
```

Or with `uv`:

```bash
uv add "cage-client[langgraph] @ git+https://github.com/google/cybernetic-agent-governance-engine.git#subdirectory=packages/cage-client"
```

## Step 2: Start CAGE Services

```bash
# Clone the repository (one-time setup)
git clone https://github.com/google/cybernetic-agent-governance-engine.git
cd cybernetic-agent-governance-engine

# Start governance infrastructure
docker compose up -d

# Verify gateway is ready
curl http://localhost:8080/health
# Expected: {"status":"healthy"}
```

This starts:
- **Gateway** (`:8080`) — Policy enforcement endpoint
- **OPA** (`:8181`) — Policy engine
- **Redis** (`:6379`) — State & CBF storage
- **NeMo Guardrails** — Input/output rails (embedded in gateway)

## Step 3: Minimal Working Example

```python
from typing import TypedDict
from langgraph.graph import StateGraph, START, END
from cage_client import CageClient
from cage_client.adapters.langgraph import cage_guard

# Initialize governance client (once at app startup)
cage = CageClient(
    gateway_url="http://localhost:8080",
    routing_seal_secret="dev-secret-key"  # From your .env
)

# Define your state
class AgentState(TypedDict):
    query: str
    proposed_action: dict
    agent_id: str
    result: str

# Decorate high-stakes nodes with governance
@cage_guard(client=cage, action="execute_trade")
async def execute_trade_node(state: AgentState) -> AgentState:
    """This node ONLY executes if CAGE returns ALLOW."""
    trade = state["proposed_action"]
    # Your business logic here
    return {"result": f"Executed: {trade}"}

# Build your graph
def planner(state: AgentState) -> AgentState:
    return {"proposed_action": {"symbol": "AAPL", "amount": 1000}}

graph = StateGraph(AgentState)
graph.add_node("planner", planner)
graph.add_node("execute_trade", execute_trade_node)  # ← Governed node
graph.add_edge(START, "planner")
graph.add_edge("planner", "execute_trade")
graph.add_edge("execute_trade", END)

app = graph.compile()

# Run it
result = await app.ainvoke({
    "query": "Buy AAPL",
    "agent_id": "advisor-v1"
})
print(result["result"])
```

## What Happens at Runtime

1. LangGraph reaches `execute_trade_node`
2. `@cage_guard` intercepts and calls `http://localhost:8080/v1/governance/validate`
3. CAGE Gateway evaluates the action through its STERA 8-tier admissibility pipeline:
   - **Tier 0:** STPA/UCA validation
   - **Tier 1:** Agent confidence threshold (4-State AARM):
     - $\text{Conf} \ge 0.95$: **ALLOW / DENY** (autonomous clearance via `system_authz.rego`)
     - $0.70 \le \text{Conf} < 0.95$: **MANUAL_REVIEW** (requires human sign-off $\to$ parked in `DeferQueue` $\to$ Two-Node HITL via `approval_node`)
     - $\text{Conf} < 0.70$: **DEFER** (data starvation / missing context $\to$ automated hydration loop in Redis `db=1` to prevent operator fatigue)
   - **Tier 2:** OPA policy evaluation (explicit UCA/CBF/policy violations $\to$ **DENY**)
   - **Tier 3:** Control Barrier Function (CBF)
   - **Tier 4:** Fiscal limit pre-reservation
   - **Tier 5:** Multi-model consensus
   - **Tier 6:** Causal gatekeeper
   - **Tier 6b:** Adaptive FRIA gate
4. Decision returned:
   - **ALLOW** → Node executes (autonomous execution permitted)
   - **DENY** → Raises `PolicyViolationException` (explicit UCA/CBF/policy violations)
   - **MANUAL_REVIEW** → Raises `DeferralPending` (parked in `DeferQueue` for human sign-off via Two-Node HITL `approval_node`)
   - **DEFER** → Routed to automated data-hydration loop in Redis `db=1` (context starvation)

## Handling MANUAL_REVIEW Decisions (Two-Node HITL Pattern)

In CAGE v3.0.1 (Decoupled PEP Architecture), checkpointing and execution suspension must happen at the state-machine boundary, not within the enforcement wrapper. The architectural decoupling ensures that `@cage_guard` validates out-of-process and raises `DeferralPending`. Therefore, the LangGraph dynamic `interrupt()` primitive belongs strictly in `approval_node`, not within the decorator.

The canonical way to handle `MANUAL_REVIEW` is the **Two-Node HITL Pattern**, consisting of a 4-phase lifecycle:

1. `@cage_guard` validates out-of-process and raises `DeferralPending` when the gateway returns a `MANUAL_REVIEW` decision.
2. A graph conditional edge catches the exception (or checks state) and routes to an `approval_node`.
3. The `approval_node` calls `interrupt(...)` to suspend the thread to the checkpointer.
4. An external caller (e.g., UI or admin script) invokes `app.ainvoke(Command(resume=...), config=config)` to resume execution once approved.

> **Example:** See [`examples/langgraph_cage_guard_demo.py`](../../examples/langgraph_cage_guard_demo.py) as the canonical reference implementation currently running in HEAD.

## Error Handling

```python
from cage_client.exceptions import PolicyViolationException, DeferralPending

try:
    result = await app.ainvoke({"query": "..."})
except PolicyViolationException as e:
    print(f"Action denied: {e.reason_code}")
    print(f"Details: {e.violation_details}")
except DeferralPending as e:
    print(f"HITL required, ticket: {e.ticket_id}")
    print(f"Expires at: {e.expires_at}")
```

## Next Steps

- **Define Your Policy:** Edit `config/opa/trade_governance.rego` or use STPA compiler
- **HITL Workflow:** See [`docs/security/HITL_TOCTOU_REMEDIATION.md`](../security/HITL_TOCTOU_REMEDIATION.md)
- **Production Deployment:** See [`infra/DEPLOYMENT_GUIDE.md`](../../infra/DEPLOYMENT_GUIDE.md)
- **Full Example:** Governed Financial Advisor at [`src/governed_financial_advisor/`](../../src/governed_financial_advisor/)
- **Client SDK Reference:** [`packages/cage-client/README.md`](../../packages/cage-client/README.md)

## Troubleshooting

**Gateway not responding:**
```bash
docker compose ps  # Check all services are running
docker compose logs gateway  # Check gateway logs
```

**Policy violations:**
```bash
# Check OPA policy evaluation
curl -X POST http://localhost:8181/v1/data/trade/governance \
  -H "Content-Type: application/json" \
  -d '{"input": {"action": "execute_trade", "amount": 1000}}'
```

**Import errors:**
```bash
# Verify installation
pip show cage-client
# Reinstall with LangGraph support
pip install --force-reinstall "cage-client[langgraph] @ git+https://..."
```
