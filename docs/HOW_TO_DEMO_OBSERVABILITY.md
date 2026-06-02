# 🎬 How to Demo: Agentic Observability

This guide explains how to run the observability demo script and visualize the "Governor's Ledger" in Langfuse.

## 📋 Prerequisites

1.  **Environment**: Python 3.10+ with project dependencies installed.
2.  **Infrastructure**: Redis must be running (used for safety state).
    ```bash
    # Local via Docker
    docker run -d -p 6379:6379 redis:latest
    ```
3.  **Observability**: Application must be configured to send traces directly to Langfuse's integrated OTLP ingestion endpoint (standalone OTel Collector deprecated 2026-05-31).
    - Ensure `.env` has `ENABLE_LOGGING=true`.
    - **OSS Deployment**: If running in a project deployed with `--is-oss`, ensure `GOOGLE_CLOUD_PROJECT`, `GOOGLE_CLOUD_LOCATION` (GCP deployments only — required for Workload Identity authentication), and `BACKEND_URL` are set to enable OIDC authentication.

## 🚀 Running the Demo Script

The script `src/governed_financial_advisor/demo/demo_observability.py` orchestrates three specific scenarios designed to light up your analytics widgets.

Run it from the project root:

```bash
python3 src/governed_financial_advisor/demo/demo_observability.py
```

### What Happens?

The script simulates 3 different users executing trades:

1.  **Scenario 1: The Happy Path ("Currency Ledger")**
    - **User:** `demo_user_happy`
    - **Action:** Buys $1,000 AAPL.
    - **Outcome:** ✅ Allowed.
    - **Metric:** Generates valid "Reasoning Spend" and minimal "Governance Tax".

2.  **Scenario 2: The Policy Violation ("Wall Impact")**
    - **User:** `demo_user_risky`
    - **Action:** Tries to buy $20,000 TSLA (Junior limit is $5,000).
    - **Outcome:** 🛑 Blocked by OPA.
    - **Metric:** Increments "Rejected" count for `langfuse.trace.metadata.governance.policy_id` (or `langfuse.trace.metadata.iso.control_id`).

3.  **Scenario 3: The Bankruptcy ("Safety Valve")**
    - **User:** `demo_user_spender`
    - **Action:** Repeatedly buys $4,500 batches of GOOGL.
    - **Outcome:** 💸 Drains cash reserve -> Triggers Bankruptcy Protocol.
    - **Metric:** Emits `langfuse.trace.metadata.event.bankruptcy=True` and `langfuse.trace.metadata.safety.bankruptcy_deficit`.

---

## 📊 Verifying in Langfuse

Navigate to your Langfuse Dashboard and check the **Agentic DevOps** board.

### Widget 1: The Currency Ledger (Tax vs. Spend)

- **Look for:** A stacked area chart showing request duration.
- **What you see:**
  - **Green Area (Reasoning):** Time spent in `reasoning.execution` (Agent thinking).
  - **Red Area (Tax):** Time spent in `governance.opa_check` (Policy verification).
- **Goal:** Ensure the "Tax" layer is thin compared to "Reasoning".

### Widget 2: The Wall Impact (Friction)

- **Look for:** A bar chart grouped by Policy ID.
- **Data:** Filtered for `governance.verdict = REJECTED`.
- **Insight:** You should see a bar for **"Finance-Limit-Junior"** (or similar OPA rule ID) from Scenario 2.

### Widget 3: The Bankruptcy Monitor

- **Look for:** A big number widget (Stat).
- **Filter:** `langfuse.trace.metadata.event.bankruptcy = True`.
- **Value:** Should be **> 0** (Red Alert).
- **Insight:** Indicates the Control Barrier Function (CBF) successfully intervened to prevent total ruin.

---

## 🔗 Verifying MCP Distributed Tracing

After a tool call via MCP (e.g., `get_market_data`, `check_market_status`), verify the W3C trace context propagation:

1.  **Open Langfuse Traces** and find a trace containing `mcp_tool:*` (client-side span).
2.  **Expand the span** — you should see a child span `mcp.tool:*` (server-side), proving the `traceparent` crossed the SSE boundary.
3.  **Check attributes:**
    - `mcp.tool.name` — the tool that was called.
    - `mcp.tool.result_length` — confirming the result was captured.
    - `langfuse.observation.input` / `langfuse.observation.output` — full I/O.

> **Tip:** Run `python tests/test_gateway_connectivity.py` to generate a test trace.

---

## Troubleshooting

- **No Traces?** Check that the gateway and langfuse-worker pods are running on your Kubernetes cluster, and `ENABLE_LOGGING=true`. (The standalone otel-collector has been deprecated — traces now go directly to Langfuse's integrated OTLP endpoint.)
- **Scanner Noise?** The `server_request_hook` in `hybrid_server.py` filters out vulnerability scanner probes (non-GET/POST methods, `/.git`, `/.env`, etc.). Only legitimate `GET`/`POST` requests appear in Langfuse.
- **Redis Error?** Ensure Redis is running on port 6379.
- **Wrong Attributes?** Verify the spans in Langfuse "Traces" view have attributes starting with `langfuse.trace.metadata.governance.` and `langfuse.trace.metadata.safety.`.
- **MCP Tool Spans Missing?** Ensure `patch_mcp_tools(mcp)` is called before `app.mount("/mcp", ...)` in `hybrid_server.py`.
