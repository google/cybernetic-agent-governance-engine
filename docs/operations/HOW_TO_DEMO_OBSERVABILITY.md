# How to Demo: Agentic Observability

This guide explains how to run the CAGE observability demo and visualise the
governance pipeline in Langfuse.

---

## Prerequisites

### 1. Python Environment

Python 3.10+ with project dependencies installed:

```bash
uv sync --all-groups --all-extras
```

### 2. Redis

Redis must be running (used for safety state and the defer queue):

```bash
# Local via Docker
docker run -d -p 6379:6379 redis:latest

# Or via Docker Compose (recommended for the full local stack)
docker compose up redis -d
```

### 3. Observability Configuration

The application sends traces directly to Langfuse's integrated OTLP ingestion
endpoint. No standalone OpenTelemetry Collector is needed — the Jaeger/OTel
Collector sidecar was **deprecated 2026-05-31**.

Ensure your `.env` file contains:

```bash
ENABLE_LOGGING=true
LANGFUSE_PUBLIC_KEY=<YOUR_LANGFUSE_PUBLIC_KEY>
LANGFUSE_SECRET_KEY=<YOUR_LANGFUSE_SECRET_KEY>
LANGFUSE_HOST=<YOUR_LANGFUSE_HOST>   # e.g. https://cloud.langfuse.com or http://localhost:3000
```

For Kubernetes deployments (governed-advisor container), the OTLP endpoint is
set via environment variable:

```
OTEL_EXPORTER_OTLP_ENDPOINT=http://langfuse-web:3000/api/public/otel/v1/traces
OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf
OTEL_EXPORTER_OTLP_HEADERS=Authorization=Basic ${LANGFUSE_BASIC_AUTH_B64}
```

For a running Kubernetes cluster, forward the Langfuse service locally:

```bash
# Port-forward all services at once (auto-reconnecting)
bash scripts/port_forward_dev.sh

# Or forward Langfuse UI only
kubectl port-forward svc/langfuse-web 3000:3000 -n governance-stack
```

---

## Running the Demo Script

[`src/governed_financial_advisor/demo/demo_observability.py`](../../src/governed_financial_advisor/demo/demo_observability.py)
orchestrates three scenarios designed to exercise the governance pipeline and
populate the Langfuse dashboard.

Run it from the project root:

```bash
python3 src/governed_financial_advisor/demo/demo_observability.py
```

### Demo Scenarios

#### Scenario 1: The Happy Path

- **Action:** Buys $1,000 of a stock within policy limits
- **Outcome:** ✅ Allowed — passes all governance checks
- **What it demonstrates:** Normal inference flow with minimal governance
  overhead. Generates `reasoning.execution` telemetry and a thin
  `governance.opa_check` layer (the "Governance Tax").

#### Scenario 2: The Policy Violation

- **Action:** Attempts to buy $20,000 of a stock (exceeds the junior user limit
  of $5,000)
- **Outcome:** 🛑 Blocked by OPA policy engine
- **What it demonstrates:** The OPA access enforcement layer (`AC-3`).
  Increments the rejected-request counter tagged with the OPA rule ID that
  triggered the block. Emits `governance.verdict = REJECTED` and
  `governance.policy_id`.

#### Scenario 3: The Bankruptcy Protocol

- **Action:** Repeatedly buys large batches, draining the cash reserve
- **Outcome:** 💸 Cash reserve depleted → Control Barrier Function (CBF)
  triggers bankruptcy protocol
- **What it demonstrates:** The CBF safety layer
  ([`src/gateway/governance/cbf.py`](../../src/gateway/governance/cbf.py)). Emits `event.bankruptcy=True` and
  `safety.bankruptcy_deficit` telemetry.

---

## Verifying in Langfuse

Navigate to your Langfuse dashboard (port-forwarded to `http://localhost:3000`
in dev, or `LANGFUSE_HOST` in prod) and open the **Agentic DevOps** board.

### Widget 1: The Currency Ledger (Governance Tax vs. Reasoning Spend)

- **Chart type:** Stacked area chart showing request duration breakdown
- **Green area (Reasoning):** Time spent in `reasoning.execution` — the agent
  thinking
- **Red area (Tax):** Time spent in `governance.opa_check` — policy
  verification overhead
- **Goal:** The "Tax" layer should be thin relative to "Reasoning",
  demonstrating low governance latency

### Widget 2: The Wall Impact (Policy Friction)

- **Chart type:** Bar chart grouped by Policy ID
- **Filter:** `governance.verdict = REJECTED`
- **Expected:** A bar for the finance limit policy from Scenario 2, showing
  which OPA rule blocked the request

### Widget 3: The Bankruptcy Monitor

- **Chart type:** Stat (big number)
- **Filter:** `event.bankruptcy = True`
- **Expected value:** > 0 (red alert state)
- **Insight:** Confirms the Control Barrier Function successfully intervened
  before total cash depletion

---

## Verifying MCP Distributed Tracing

After a tool call via MCP (e.g., `get_market_data`, `check_market_status`),
verify W3C trace context propagation across the SSE boundary:

1. Open **Langfuse → Traces** and find a trace containing `mcp_tool:*`
   (client-side span)
2. Expand the span — you should see a child span `mcp.tool:*` (server-side),
   confirming the `traceparent` header crossed the SSE boundary
3. Check the span attributes:
   - `mcp.tool.name` — the tool that was called
   - `mcp.tool.result_length` — confirms the result was captured
   - `langfuse.observation.input` / `langfuse.observation.output` — full I/O
     recorded

To generate a test trace:

```bash
python tests/test_gateway_connectivity.py
```

---

## AgentSight eBPF Observability (Kubernetes)

AgentSight provides kernel-level observability via eBPF probes attached to the
governed-advisor process. It captures SSL/TLS traffic (intent layer) alongside
system call activity (action layer) and correlates them.

### Docker Compose (local demo)

```bash
# Launch AgentSight daemon + dashboard + governed-advisor
docker compose -f deployment/agentsight/docker-compose.agentsight.yaml up
```

This starts:
1. **`agentsight-daemon`** — privileged container with eBPF probes targeting
   `python3` processes; exports telemetry to `http://agentsight-dashboard:8080`
2. **`agentsight-dashboard`** — visualisation UI at `http://localhost:3000`
3. **`governed-advisor`** — your application, observed from the outside

> **Required:** The daemon container must run with `privileged: true`,
> `pid: host`, and `network_mode: host` to attach eBPF probes. These settings
> are set in
> [`deployment/agentsight/docker-compose.agentsight.yaml`](../../deployment/agentsight/docker-compose.agentsight.yaml).

### Kubernetes (deployed)

AgentSight is deployed as a DaemonSet on the cluster:

```bash
# Check DaemonSet status
kubectl get pods -n governance-stack -l app=agentsight

# Access AgentSight UI (ClusterIP service — port-forward required)
kubectl port-forward svc/agentsight-ui 3000:80 -n governance-stack
# Open: http://localhost:3000
```

The AgentSight configuration file is
[`deployment/agentsight/agentsight-config.yaml`](../../deployment/agentsight/agentsight-config.yaml).

Probes enabled:
- **SSL/TLS interception** (`probes.ssl`) — OpenSSL intercept for intent
  capture
- **Syscall monitoring** (`probes.syscalls`) — `execve`, `openat`, `connect`,
  `socket`, `bind`

---

## Governance Telemetry Reference

All CAGE governance metrics follow the naming convention
`cage.<subsystem>.<metric_name>`.

Key attributes emitted on governance spans:

| Attribute | Description |
|-----------|-------------|
| `governance.verdict` | `ALLOWED` \| `REJECTED` \| `ESCALATED` |
| `governance.policy_id` | OPA rule ID that produced the verdict |
| `governance.opa_check` | Duration of OPA policy evaluation (ms) |
| `safety.bankruptcy_deficit` | Cash deficit when CBF triggers |
| `event.bankruptcy` | `True` when bankruptcy protocol activates |
| `model.confidence_score` | LLM confidence score for the inference |
| `iso.control_id` | ISO 42001 control ID associated with the span |

---

## Evaluating Langfuse Traces

To run a batch evaluation against recorded Langfuse traces:

```bash
# Fetch and print recent traces/scores
python scripts/fetch_langfuse_metrics.py

# Run LLM-judge evaluation
bash scripts/run_langfuse_eval_test.sh

# Replay failed scores from a previous evaluation run
python scripts/replay_failed_scores.py
```

---

## Troubleshooting

| Symptom | Resolution |
|---------|------------|
| No traces appear in Langfuse | Verify `ENABLE_LOGGING=true` and that `LANGFUSE_PUBLIC_KEY` / `LANGFUSE_SECRET_KEY` are set correctly in `.env` |
| Redis connection error | Ensure Redis is running on port 6379: `docker run -d -p 6379:6379 redis:latest` |
| Wrong span attributes | Verify spans carry attributes starting with `langfuse.trace.metadata.governance.` and `langfuse.trace.metadata.safety.` |
| MCP tool spans missing | Ensure `patch_mcp_tools(mcp)` is called before `app.mount("/mcp", ...)` in `hybrid_server.py` |
| Scanner noise in traces | The `server_request_hook` in `hybrid_server.py` filters vulnerability scanner probes — only legitimate `GET`/`POST` requests appear in Langfuse |
| AgentSight daemon won't start | Requires `privileged: true` and `pid: host`; check kernel version supports eBPF (≥ 5.8) |
| Port 3000 conflict (AgentSight vs Langfuse) | In dev, Langfuse is forwarded to 3000 and 3001; AgentSight UI is forwarded separately — ensure only one is active on port 3000 at a time |
| Langfuse port-forward drops | Use `scripts/port_forward_dev.sh` — it runs auto-reconnecting loops for all services |
