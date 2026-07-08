# How to Demo: Agentic Observability

This guide explains how to run the CAGE observability demo and visualize the governance pipeline in Langfuse.

## Prerequisites

### 1. Python Environment

Python 3.10+ with project dependencies installed:

```bash
uv sync
```

### 2. Redis

Redis must be running (used for safety state and the defer queue):

```bash
# Local via Docker
docker run -d -p 6379:6379 redis:latest

# Or via Docker Compose (recommended)
docker compose up redis -d
```

### 3. Observability Configuration

The application sends traces directly to Langfuse's integrated OTLP ingestion endpoint.

Ensure your `.env` file contains:

```bash
ENABLE_LOGGING=true
LANGFUSE_PUBLIC_KEY=<YOUR_LANGFUSE_PUBLIC_KEY>
LANGFUSE_SECRET_KEY=<YOUR_LANGFUSE_SECRET_KEY>
LANGFUSE_HOST=<YOUR_LANGFUSE_HOST>   # e.g. https://cloud.langfuse.com
```

For Kubernetes deployments, also set:

```bash
BACKEND_URL=<YOUR_GATEWAY_URL>
```

> **Note:** The standalone OpenTelemetry Collector sidecar was deprecated on 2026-05-31. Traces now go directly to Langfuse's integrated OTLP endpoint.

---

## Running the Demo Script

The script [`src/governed_financial_advisor/demo/demo_observability.py`](../../src/governed_financial_advisor/demo/demo_observability.py) orchestrates three scenarios designed to exercise the governance pipeline and populate the Langfuse dashboard.

Run it from the project root:

```bash
python3 src/governed_financial_advisor/demo/demo_observability.py
```

### Demo Scenarios

The script simulates three users executing trades, each triggering a different governance outcome:

#### Scenario 1: The Happy Path

- **Action:** Buys $1,000 of a stock within policy limits
- **Outcome:** ✅ Allowed — passes all governance checks
- **What it demonstrates:** Normal inference flow with minimal governance overhead. Generates "Reasoning Spend" telemetry and a thin "Governance Tax" layer.

#### Scenario 2: The Policy Violation

- **Action:** Attempts to buy $20,000 of a stock (exceeds the junior user limit of $5,000)
- **Outcome:** 🛑 Blocked by OPA policy engine
- **What it demonstrates:** The OPA access enforcement layer (`AC-3`). Increments the rejected-request counter tagged with the policy ID that triggered the block.

#### Scenario 3: The Bankruptcy Protocol

- **Action:** Repeatedly buys large batches, draining the cash reserve
- **Outcome:** 💸 Cash reserve depleted → Control Barrier Function (CBF) triggers bankruptcy protocol
- **What it demonstrates:** The CBF safety layer (`src/gateway/governance/safety.py`). Emits `event.bankruptcy=True` and `safety.bankruptcy_deficit` telemetry.

---

## Verifying in Langfuse

Navigate to your Langfuse dashboard and open the **Agentic DevOps** board.

### Widget 1: The Currency Ledger (Governance Tax vs. Reasoning Spend)

- **Chart type:** Stacked area chart showing request duration breakdown
- **Green area (Reasoning):** Time spent in `reasoning.execution` — the agent thinking
- **Red area (Tax):** Time spent in `governance.opa_check` — policy verification overhead
- **Goal:** The "Tax" layer should be thin relative to "Reasoning", demonstrating low governance latency

### Widget 2: The Wall Impact (Policy Friction)

- **Chart type:** Bar chart grouped by Policy ID
- **Filter:** `governance.verdict = REJECTED`
- **Expected:** A bar for the finance limit policy from Scenario 2, showing which OPA rule blocked the request

### Widget 3: The Bankruptcy Monitor

- **Chart type:** Stat (big number)
- **Filter:** `event.bankruptcy = True`
- **Expected value:** > 0 (red alert state)
- **Insight:** Confirms the Control Barrier Function successfully intervened before total cash depletion

---

## Verifying MCP Distributed Tracing

After a tool call via MCP (e.g., `get_market_data`, `check_market_status`), verify W3C trace context propagation across the SSE boundary:

1. Open **Langfuse → Traces** and find a trace containing `mcp_tool:*` (client-side span)
2. Expand the span — you should see a child span `mcp.tool:*` (server-side), confirming the `traceparent` header crossed the SSE boundary
3. Check the span attributes:
   - `mcp.tool.name` — the tool that was called
   - `mcp.tool.result_length` — confirms the result was captured
   - `langfuse.observation.input` / `langfuse.observation.output` — full I/O recorded

To generate a test trace:

```bash
python tests/test_gateway_connectivity.py
```

---

## Governance Telemetry Reference

All CAGE governance metrics follow the naming convention `cage.<subsystem>.<metric_name>`.

Key attributes emitted on governance spans:

| Attribute | Description |
|-----------|-------------|
| `governance.verdict` | `ALLOWED` \| `REJECTED` \| `ESCALATED` |
| `governance.policy_id` | OPA rule ID that produced the verdict |
| `governance.opa_check` | Duration of OPA policy evaluation (ms) |
| `safety.bankruptcy_deficit` | Cash deficit amount when CBF triggers |
| `event.bankruptcy` | `True` when bankruptcy protocol activates |
| `model.confidence_score` | LLM confidence score for the inference |
| `iso.control_id` | ISO 42001 control ID associated with the span |

---

## Troubleshooting

| Symptom | Resolution |
|---------|------------|
| No traces appear in Langfuse | Verify `ENABLE_LOGGING=true` and that `LANGFUSE_PUBLIC_KEY` / `LANGFUSE_SECRET_KEY` are set correctly |
| Redis connection error | Ensure Redis is running on port 6379: `docker run -d -p 6379:6379 redis:latest` |
| Wrong span attributes | Verify spans have attributes starting with `langfuse.trace.metadata.governance.` and `langfuse.trace.metadata.safety.` |
| MCP tool spans missing | Ensure `patch_mcp_tools(mcp)` is called before `app.mount("/mcp", ...)` in `hybrid_server.py` |
| Scanner noise in traces | The `server_request_hook` in `hybrid_server.py` filters out vulnerability scanner probes — only legitimate `GET`/`POST` requests appear in Langfuse |
