# CAGE External API Reference

> **Generated:** 2026-08-05 · **Scope:** Consumer-facing HTTP REST, gRPC, and
> SSE endpoints intended for external clients and integrations.

This document covers APIs intended for external consumers and client
integrations — including the primary LLM inference endpoint, the Governed
Financial Advisor application API, compliance artifact exports, and the gRPC
Gateway service. Internal inter-service and governance APIs are documented
separately.

> For internal inter-service and governance APIs, see API_MAP_INTERNAL.md.

---

## 1. Gateway Server — port 8080

The gateway is a FastAPI composition root defined in
[`hybrid_server.py`](../src/gateway/server/hybrid_server.py) that mounts three
sub-applications:

| Mount path | Sub-app | Source file |
|---|---|---|
| `/inference` | `inference_app` | [`inference_proxy.py`](../src/gateway/server/inference_proxy.py) |
| `/governance` | `governance_app` | [`governance_middleware.py`](../src/gateway/server/governance_middleware.py) |
| `/` (catch-all) | `mcp_app` | [`mcp_tool_server.py`](../src/gateway/server/mcp_tool_server.py) |

**Global middleware:**
`_DebugEndpointGuard` — returns
HTTP 404 for any `/debug/*` path unless `CAGE_ENV` is `dev` or `test`.

---

### 1.1 Root App — [`hybrid_server.py`](../src/gateway/server/hybrid_server.py)

#### `GET /healthz`

KMS connectivity health check.

**Response 200 OK:**
```json
{
  "status": "healthy",
  "kms_active": true,
  "env": "prod"
}
```

**Response 503 Service Unavailable:** when KMS is unreachable.

---

### 1.2 Inference Sub-App — [`inference_proxy.py`](../src/gateway/server/inference_proxy.py)

Mounted at `/inference`. Implements an OpenAI-compatible governed inference
endpoint.

#### `POST /inference/v1/chat/completions`

OpenAI-compatible governed inference. Governance pipeline runs in order:

1. **Tier-1 Aho-Corasick keyword scan** — blocks CBRN/prohibited terms (HTTP 403)
2. **Token Quota check** (`TokenQuotaProxy`) — ISO 42001 Annex A.4; atomic Redis Lua counter (HTTP 429 on breach)
3. **NeMo input rail** — in-process manager verifies input
4. **vLLM proxy** — forwards to backend resolved by `_resolve_backend_url()`
5. **NeMo output masking** — strips PII / policy violations from response

**Request body:** Standard OpenAI Chat Completion format.

```json
{
  "model": "string",
  "messages": [{"role": "user|assistant|system", "content": "string"}],
  "temperature": 0.7,
  "stream": false,
  "max_tokens": 1024
}
```

**Response 200 OK:** Standard OpenAI Chat Completion response (or
`StreamingResponse` when `stream: true`).

**Response 403 Forbidden** (Tier-1 keyword block):
```json
{
  "id": "chatcmpl-blocked-...",
  "object": "chat.completion",
  "choices": [
    {
      "message": {"role": "assistant", "content": "<governance refusal>"},
      "finish_reason": "stop"
    }
  ]
}
```

**Response 429 Too Many Requests** (quota exceeded):
```json
{
  "error": "quota_exceeded",
  "reason": "string",
  "step_count": 12,
  "accumulated_tokens": 4096,
  "session_id": "string"
}
```

---

### 1.3 MCP Tool Server — [`mcp_tool_server.py`](../src/gateway/server/mcp_tool_server.py)

Mounted at `/` (catch-all).

#### `GET /health`

**Response 200 OK:**
```json
{
  "status": "ok",
  "mode": "mcp-tool-server",
  "nemo": "active"
}
```

---

## 2. Compliance Bridge — port 3001

Defined in [`main.py`](../src/compliance_bridge/main.py). CORS origins:
`localhost:5173`, `localhost:3000`, and `UI_ORIGIN` env var.

#### `GET /health`

**Response 200 OK:**
```json
{
  "status": "ok",
  "service": "compliance-bridge",
  "version": "0.1.0",
  "langfuse_compliance_configured": true,
  "langfuse_app_configured": true,
  "oscal_storage_configured": true,
  "environment": "prod"
}
```

---

#### `GET /v1/events/stream`

SSE governance event stream. Clients receive real-time governance events.
Heartbeat `ping` sent every 30 seconds. Max 100 concurrent subscribers
(enforced by `GovernanceEventBus`).

**Event type:** `governance-event`

**Event data** (wire shape from `GovernanceEventBus.publish()`):
```json
{
  "type": "AUDIT_FINDING | GOVERNANCE_VIOLATION | REMEDIATION_GENERATED | CONTEXT_CHAIN_SEALED | DEFER_PARKING | DEFER_RESOLVED",
  "traceId": "string",
  "controlId": "A.9.2",
  "result": "PASS | FAIL",
  "safetyRate": 0.94,
  "auditId": "uuid",
  "timestamp": "2026-07-05T01:00:00Z"
}
```

---

#### `GET /v1/controls`

List supported compliance controls filtered by `CAGE_DEPLOYMENT_REGION`.

**Query params:**

| Param | Type | Description |
|---|---|---|
| `framework` | `string` (optional) | Filter by framework name |

**Response 200 OK:**
```json
{
  "controls": [
    {
      "control_id": "A.9.2",
      "name": "string",
      "iso_clause": "string",
      "score_name": "safety_rate",
      "critical": true,
      "frameworks": ["ISO_42001", "US_FED"]
    }
  ],
  "total": 7,
  "framework_filter": null,
  "deployment_region": "US_FED"
}
```

**Response header:** `X-CAGE-Deployment-Region: US_FED`

---

#### `GET /v1/metrics/summary`

Aggregate compliance posture snapshot across all supported controls.

**Query params:**

| Param | Type | Default | Description |
|---|---|---|---|
| `window_hours` | `int` | `24` | Lookback window |

**Response 200 OK:**
```json
{
  "overall_pass_rate": 0.94,
  "total_controls": 7,
  "passing_controls": 6,
  "failing_controls": ["SC-4"],
  "critical_fails": [],
  "window_hours": 24,
  "controls": {
    "A.9.2": {}
  }
}
```

---

#### `GET /v1/metrics/{control_id}`

Per-control compliance metrics. 5-minute TTL cache. Queries Langfuse
application project for traces tagged `control:<controlId>`. Semaphore(6)
concurrency limit (see `get_compliance_metrics()`).

**Path params:** `control_id` — must be in `SUPPORTED_CONTROLS`

**Query params:**

| Param | Type | Default |
|---|---|---|
| `window_hours` | `int` | `24` |

**Response 200 OK** (`ComplianceMetrics`):
```json
{
  "control_id": "A.9.2",
  "safety_rate": 0.97,
  "total_traces": 1420,
  "blocked_traces": 43,
  "passed_traces": 1377,
  "window_hours": 24.0,
  "last_event_utc": "2026-07-05T01:00:00Z",
  "evidence_age_seconds": 120.4,
  "startup_grace_active": false,
  "startup_grace_remaining_hours": 0.0,
  "confabulation_rate": 0.02,
  "confabulation_blocked_traces": 28
}
```

**Response 404 Not Found:** Unknown `control_id`.

---

#### `GET /v1/oscal/assessment-results`

Generate an OSCAL 1.1.2 Assessment Results document from live metrics.

**Query params:**

| Param | Type | Default | Description |
|---|---|---|---|
| `window_hours` | `int` | `24` | Lookback window |
| `format` | `json\|yaml` | `json` | Output format |
| `audit_id` | `string` (optional) | — | Attach to existing audit |

**Response 200 OK:** OSCAL Assessment Results document.
`Content-Type: application/json` or `application/yaml`.

---

#### `GET /v1/aarm/conformance-report`

Generate an on-demand CSA AARM Conformance Report Card (11 threat vectors).

**Query params:**

| Param | Type | Default | Description |
|---|---|---|---|
| `window_hours` | `int` | `24` | Lookback window |
| `format` | `json\|yaml` | `json` | Output format |
| `include_narrative` | `bool` | `false` | Include LLM narrative |
| `audit_id` | `string` (optional) | — | Attach to existing audit |

**Response 200 OK:** AARM Conformance Report Card document.

---

## 3. Governed Financial Advisor

Defined in [`server.py`](../src/governed_financial_advisor/server.py). Port from
`Config.PORT`. Lifespan initializes the LangGraph agent graph and Redis
checkpointer.

### 3.1 Core Endpoints — [`server.py`](../src/governed_financial_advisor/server.py)

#### `GET /`

**Response 200 OK:**
```json
{
  "status": "ok",
  "message": "Governed Financial Advisor API"
}
```

---

#### `GET /health`

**Response 200 OK:**
```json
{
  "status": "ok",
  "service": "financial-advisor-graph-agent",
  "project_id": "my-gcp-project"
}
```

---

#### `POST /agent/query`

Main LangGraph agent query. Requires `X-API-Key` header. 240-second timeout.

**Request body** (`QueryRequest`):
```json
{
  "prompt": "Should I buy 100 shares of AAPL?",
  "user_id": "u-001",
  "thread_id": "thread-uuid"
}
```

**Response 200 OK:**
```json
{
  "response": "Based on current market conditions...",
  "trace_id": "langfuse-trace-uuid"
}
```

**Response 202 Accepted:** When LangGraph hits a HITL interrupt — returns
`approval_required: true` with interrupt payload.

**Response 408 Request Timeout:** Agent exceeded 240 seconds.
**Response 401 Unauthorized:** Missing or invalid API key.

---

#### `POST /v1/approvals/{thread_id}/resume`

Resume a LangGraph thread paused at a HITL interrupt. Requires `X-API-Key`
header. Uses LangGraph `Command` pattern to inject the approval decision.

**Path params:** `thread_id` — LangGraph thread UUID

**Request body** (`ApprovalResumeRequest`):
```json
{
  "approved": true,
  "reviewer": "compliance-officer@example.com",
  "rationale": "Trade within risk parameters",
  "comment": "Approved after manual review",
  "max_slippage_pct": 0.5
}
```

**Response 200 OK:**
```json
{
  "status": "resumed",
  "thread_id": "thread-uuid",
  "approved": true,
  "evidence_recorded": true
}
```

**Response 410 Gone:** HITL TTL expired — thread can no longer be resumed.

---

#### `GET /v1/approvals/pending`

List all LangGraph threads currently paused at HITL interrupts.

**Response 200 OK:**
```json
{
  "pending": [
    {
      "thread_id": "thread-uuid",
      "interrupt_payload": {},
      "interrupted_at": "2026-07-05T01:00:00Z"
    }
  ]
}
```

---

#### `POST /v1/refinement/trigger`

Submit a Kubeflow Pipelines run for the governance refinement pipeline via
`_submit_kfp_run()`.

**Request body** (`RefinementTriggerRequest`):
```json
{
  "pipeline_id": "governance-refinement-v2",
  "trigger_reason": "SC-4 safety rate below threshold",
  "trace_ids": ["trace-uuid-1", "trace-uuid-2"]
}
```

**Response 200 OK:**
```json
{
  "status": "accepted",
  "pipeline_id": "governance-refinement-v2",
  "message": "KFP run submitted",
  "kfp": {
    "run_id": "kfp-run-uuid",
    "status": "PENDING"
  }
}
```

---

#### `POST /v1/nemo/propose-refinement`

Stage a NeMo Guardrails refinement proposal for human review.

**Request body** (`NeMoApplyRefinementRequest`):
```json
{
  "control_id": "A.9.2",
  "verdict": "TIGHTEN",
  "source": "langfuse-webhook"
}
```

**Response 200 OK:**
```json
{
  "status": "staged",
  "proposal_id": "proposal-uuid",
  "control_id": "A.9.2",
  "message": "Proposal staged for human review"
}
```

---

#### `POST /v1/nemo/approve-refinement/{proposal_id}`

Approve or reject a staged NeMo refinement proposal. Requires `X-API-Key`.

**Path params:** `proposal_id` — UUID

**Request body** (`NeMoApproveRequest`):
```json
{
  "approved": true,
  "reviewer": "ml-ops@example.com",
  "rationale": "Refinement validated against test suite"
}
```

**Response 200 OK:**
```json
{
  "status": "applied",
  "proposal_id": "proposal-uuid",
  "control_id": "A.9.2",
  "applied_at": "2026-07-05T01:00:00Z"
}
```

---

#### `GET /v1/nemo/proposals/pending`

List all staged NeMo refinement proposals awaiting human review.

**Response 200 OK:**
```json
{
  "pending": [
    {
      "proposal_id": "uuid",
      "control_id": "A.9.2",
      "verdict": "TIGHTEN",
      "staged_at": "2026-07-05T01:00:00Z"
    }
  ],
  "count": 2
}
```

---

#### `POST /v1/nemo/apply-refinement`

Legacy gated endpoint. In production routes to the proposal/approval flow.
In dev may apply directly.

**Request body:** Same as `NeMoApplyRefinementRequest`.

---

## 4. gRPC Gateway Service — [`gateway.proto`](../src/agentsight-ui/gateway_protos/gateway.proto)

**Package:** `gateway` · **Service:** `Gateway`

Exposed to external gRPC clients. Implements server-streaming governed LLM
responses and unary tool execution.

### `rpc Chat(ChatRequest) returns (stream ChatResponse)`

Server-streaming RPC. Streams governed LLM responses token-by-token.

**`ChatRequest` message:**

| Field | Type | Description |
|---|---|---|
| `model` | `string` | Model identifier |
| `messages` | `repeated Message` | Conversation history |
| `temperature` | `float` | Sampling temperature |
| `system_instruction` | `string` | System prompt override |
| `mode` | `string` | Inference mode |
| `guided_json` | `string` | JSON schema for structured output |
| `guided_regex` | `string` | Regex for constrained output |
| `guided_choice` | `repeated string` | Allowed output choices |

**`Message` message:**

| Field | Type |
|---|---|
| `role` | `string` |
| `content` | `string` |

**`ChatResponse` message (streamed):**

| Field | Type | Description |
|---|---|---|
| `content` | `string` | Token chunk |
| `is_final` | `bool` | True on last chunk |
| `input_tokens` | `int32` | Input token count (final chunk only) |
| `output_tokens` | `int32` | Output token count (final chunk only) |

---

### `rpc ExecuteTool(ToolRequest) returns (ToolResponse)`

Unary RPC. Execute a named tool via gRPC.

**`ToolRequest` message:**

| Field | Type | Description |
|---|---|---|
| `tool_name` | `string` | Tool identifier |
| `params_json` | `string` | JSON-encoded parameters |

**`ToolResponse` message:**

| Field | Type | Description |
|---|---|---|
| `output` | `string` | Tool output |
| `error` | `string` | Error message if failed |
| `status` | `string` | `SUCCESS` or `ERROR` |

---

## 5. Key Schemas and Types

### 5.1 `TradeOrder`

Pydantic model for validated trade orders.

| Field | Type | Constraints |
|---|---|---|
| `symbol` | `str` | 1–5 uppercase letters |
| `amount` | `float` | > 0 |
| `currency` | `str` | — |
| `confidence` | `float` | 0.0–1.0 |
| `side` | `str` (optional) | — |
| `type` | `str` (optional) | — |
| `transaction_id` | `str` | UUID v4 |
| `trader_id` | `str` (optional) | — |
| `trader_role` | `str` (optional) | `"junior"` or `"senior"` |

---

### 5.2 `ComplianceMetrics`

Pydantic model returned by `GET /v1/metrics/{control_id}`.

| Field | Type | Description |
|---|---|---|
| `control_id` | `str` | Control identifier |
| `safety_rate` | `float` (optional) | Pass rate 0.0–1.0 |
| `total_traces` | `int` | Total traces in window |
| `blocked_traces` | `int` | Blocked/failed traces |
| `passed_traces` | `int` | Passed traces |
| `window_hours` | `float` | Lookback window |
| `last_event_utc` | `str` | ISO 8601 timestamp |
| `evidence_age_seconds` | `float` | Age of most recent evidence |
| `startup_grace_active` | `bool` | Within startup grace period |
| `startup_grace_remaining_hours` | `float` | Grace period remaining |
| `confabulation_rate` | `float` (optional) | Confabulation detection rate |
| `confabulation_blocked_traces` | `int` | Confabulation-blocked traces |

---

### 5.3 `OscalFinding`

Frozen Pydantic model representing a single OSCAL finding.

| Field | Type | Description |
|---|---|---|
| `control_id` | `str` | Control identifier |
| `result` | `str` | `PASS`, `FAIL`, `NOT_APPLICABLE`, or `ERROR` |
| `safety_rate` | `float` (optional) | Pass rate |
| `evidence_age_s` | `float` (optional) | Evidence age in seconds |
| `finding_id` | `str` | UUID |
| `remarks` | `str` (optional) | Human-readable remarks |
| `chain_index` | `int` (optional) | Position in hash chain |

---

### 5.4 `AgentState`

LangGraph `TypedDict` representing the full agent execution state.

| Field | Type | Description |
|---|---|---|
| `messages` | `Annotated[list[BaseMessage], add_messages]` | Conversation history |
| `next_step` | `Literal[...]` | Router target node |
| `risk_status` | `str` | Risk assessment result |
| `risk_feedback` | `str` | Risk analyst feedback |
| `loop_count` | `int` | Iteration counter |
| `safety_status` | `str` | Safety check result |
| `governance_signature` | `str` | KMS-backed governance seal |
| `risk_attitude` | `str` | User risk preference |
| `investment_period` | `str` | Investment horizon |
| `reasoning_output` | `str` | Advisor reasoning |
| `execution_plan_output` | `str` | Trader execution plan |
| `data_analyst_ticker` | `str` | Ticker under analysis |
| `evaluation_result` | `str` | Evaluator verdict |
| `opa_results` | `dict` | OPA policy evaluation results |
| `execution_result` | `str` | Trade execution result |
| `governance_summary` | `str` | Governance pipeline summary |
| `user_id` | `str` | User identifier |
| `latency_stats` | `dict` | Per-node latency measurements |
| `completed_transactions` | `Annotated[list[LedgerEntry], add]` | Immutable ledger |
| `approval_required` | `bool` | HITL interrupt flag |
| `approval_decision` | `bool\|None` | Human approval decision |
| `hitl_expires_at` | `str\|None` | HITL TTL timestamp |
| `guardrail_blocked` | `bool` | NeMo input rail blocked |
| `guardrail_reason` | `str\|None` | Block reason |
| `output_rail_applied` | `bool` | NeMo output rail applied |

---

### 5.5 `LedgerEntry`

Immutable transaction ledger entry appended to `AgentState.completed_transactions`.

| Field | Type | Description |
|---|---|---|
| `sequence_id` | `str` | Monotonic sequence |
| `timestamp` | `str` | ISO 8601 |
| `uca_ref` | `str` | STPA UCA reference |
| `action` | `str` | Action taken |
| `idempotency_key` | `str` | Deduplication key |
| `status` | `str` | `PENDING`, `COMPLETED`, `ROLLED_BACK`, or `PARTIAL_FAILURE` |
| `context_data` | `dict` | Arbitrary context |

---

### 5.6 `QueryRequest`

| Field | Type |
|---|---|
| `prompt` | `str` |
| `user_id` | `str` |
| `thread_id` | `str` |

---

### 5.7 `ApprovalResumeRequest`

| Field | Type | Constraints |
|---|---|---|
| `approved` | `bool` | — |
| `reviewer` | `str` | Non-empty |
| `rationale` | `str` | Min 10 chars |
| `comment` | `str` | — |
| `max_slippage_pct` | `float` | 0.0–100.0 |

---

## 6. Authentication and Security Model

### `X-CAGE-Routing-Seal` (Gateway)

HMAC-SHA256 computed over the raw request body bytes. Verified by
`_verify_routing_seal()`
and enforced by
`enforce_routing_seal()`.

Required on:
- `POST /governance/check`
- `POST /tools/execute` (MCP tool server)

The seal is also returned in `POST /governance/validate-action` responses and
must be verified by callers before actuating any trade.

---

### `Authorization: Bearer <token>` (Compliance Bridge)

Validated by `require_internal_token` using
`hmac.compare_digest` (constant-time). Token sourced from
`COMPLIANCE_BRIDGE_INTERNAL_TOKEN` env var.

**Dev bypass:** When `CAGE_ENV=dev` and no token is configured, the check is
skipped.

Required on:
- `POST /v1/audit/ingest`

---

### `X-API-Key` (Governed Financial Advisor)

Validated by [`infrastructure/auth.py`](../src/governed_financial_advisor/infrastructure/auth.py).

Required on:
- `POST /agent/query`
- `POST /v1/approvals/{thread_id}/resume`
- `POST /v1/nemo/approve-refinement/{proposal_id}`
- `POST /tools/execute`

---

### Secret Hygiene Rules

Per `.roo/rules-code/01-code-standards.md`:

- Never embed secrets in source files
- Kubernetes manifests must use `secretKeyRef` or `secretRef`
- Credential patterns that must never appear in committed files:
  - `pk-lf-*` or `sk-lf-*` (Langfuse keys)
  - `hf_*` (HuggingFace tokens)
  - `GOOG*` (Google credentials)
  - `redis://*:*@*` (Redis connection strings with credentials)

---

### Region Guard (Shared Modules)

`src/gateway/governance/` and `src/compliance_bridge/` deploy simultaneously
to `US_FED`, `EU_ECB`, and `APAC_MAS` via `CAGE_DEPLOYMENT_REGION`.

| Region | Data residency |
|---|---|
| `US_FED` | `us-central1` or approved US regions |
| `EU_ECB` | `europe-west1` only |
| `APAC_MAS` | `asia-southeast1` only |

The "no legal force" SR 26-2 sentinel must never be removed from EU and APAC
baselines — it suppresses telemetry lacking legal basis under GDPR / MAS
Notice 655.

#### `POST /v1/webhooks/langfuse`

Langfuse webhook receiver — triggers refinement pipeline when safety metrics
breach thresholds.

**Request body** (`LangfuseWebhookEvent`):
```json
{
  "type": "score",
  "name": "safety_rate",
  "value": 0.72,
  "traceId": "trace-uuid",
  "data": {}
}
```

**Response 200 OK:**
```json
{
  "status": "triggered | cooldown | deferred | ignored | threshold_ok"
}
```

---

### 3.2 Tools Router — [`tools/api.py`](../src/governed_financial_advisor/tools/api.py)

Mounted at `/tools`. All endpoints require `X-API-Key` header.

#### `POST /tools/execute`

Execute a named tool with governance enforcement. For `execute_trade`, calls
`GatewayClient.validate_action()`
and verifies the routing seal before actuation.

**Request body** (`ToolExecutionRequest`):
```json
{
  "tool_name": "execute_trade",
  "params": {
    "symbol": "AAPL",
    "amount": 5000.0,
    "currency": "USD",
    "confidence": 0.91,
    "trader_id": "u-001",
    "trader_role": "senior"
  }
}
```

**Supported `tool_name` values:**

| Tool name | Description | Governance |
|---|---|---|
| `check_market_status` | Market data lookup | None |
| `get_market_sentiment` | Sentiment analysis | None |
| `simulate_governance_check` | Dry-run governance sim | None |
| `trigger_safety_intervention` | Lock system | None |
| `verify_content_safety` | NeMo content check | None |
| `evaluate_policy` | OPA Rego evaluation | None |
| `execute_trade` | Governed trade execution | Full 8-tier pipeline (FTRA + 7 in-pipeline tiers) via Gateway |

**Response 200 OK:**
```json
{
  "status": "SUCCESS",
  "output": "string",
  "trace_id": "otel-trace-id"
}
```

---

### 3.3 Demo Router — [`demo/router.py`](../src/governed_financial_advisor/demo/router.py)

Mounted at `/demo`. **Dev environment only** — returns 404 in production.

#### `GET /demo/status`

**Response 200 OK:**
```json
{
  "status": "ready",
  "context": {}
}
```

---

#### `POST /demo/context`

Set demo context state.

**Request body** (`ContextRequest`):
```json
{
  "context": {}
}
```

**Response 200 OK:** `{"status": "ok"}`

---

#### `POST /demo/reset`

Reset demo state to defaults.

**Response 200 OK:** `{"status": "reset"}`

---

#### `GET /v1/telemetry/history`

Paginated historical compliance telemetry from Langfuse.

**Query params:**

| Param | Type | Default | Description |
|---|---|---|---|
| `page` | `int` | `1` | Page number |
| `limit` | `int` | `20` | Items per page |
| `before_timestamp` | `string` (optional) | — | ISO 8601 cursor |

**Response 200 OK:**
```json
{
  "telemetry": [
    {
      "traceId": "string",
      "controlId": "A.9.2",
      "result": "PASS",
      "safetyRate": 0.97,
      "timestamp": "2026-07-05T01:00:00Z"
    }
  ],
  "hasMore": true,
  "page": 1,
  "limit": 20
}
```

---

## 7. Outbound Vendor APIs — Normative Provider Contract

The sections above document endpoints CAGE **serves**. This section documents
the outbound calls CAGE **makes** to external compliance vendors, because those
calls have a wire contract that vendor implementers must satisfy.

Vendor adapters are isolated under `src/integrations/{provider}/` and are
lazy-loaded. Providers are numbered/anonymized and have **no configured live
endpoints** in this repository — all URLs are placeholders. Per-provider detail,
including each provider's verdict vocabulary, is in the `README.md` inside each
adapter directory.

| Provider | Protocol | Style |
|---|---|---|
| `provider_01` | `NormativeProvider` | Synchronous FRIA gate (HTTP) |
| `provider_03` | `NormativeProvider` | Synchronous FRIA gate (HTTP) |
| `provider_06` | `NormativeProvider` | Synchronous integrity verifier (HTTP) |
| `provider_02` | Attestation surface | Out-of-band receipt certification |
| `provider_04` | `AttestationProvider` + envelope mapper | Out-of-band (stub) |
| `provider_05` | `AttestationProvider` ×3 | Out-of-band, seeded/synthetic |

---

### 7.1 `POST {base}/validate/fria` — Provider 01 Synchronous Gate

**Base URL:** `https://api.example.com/normative` (placeholder,
`CAGE_NORMATIVE_ENDPOINT`)
**Auth:** `Authorization: Bearer <key>`
**Timeout:** 5s default (`CAGE_NORMATIVE_GATE_TIMEOUT_SECONDS`)
**Adapter:** [`provider_01/provider.py`](../src/integrations/provider_01/provider.py:323)

Every 200 response **must** include a top-level `decision`. The vocabulary is
`ALLOW` / `REFUSE` / `ESCALATE`, matched case-insensitively.

| `decision` | `admitted` | Finding code | Effect |
|---|---|---|---|
| `ALLOW` | `true` | `CONSEQUENCE_TOKEN` (`info`) | ConsequenceToken JWS minted |
| `REFUSE` | `false` | `FLOWSIGNAL_REFUSE` (`blocked`) | Hard deny |
| `ESCALATE` | `false` | `FLOWSIGNAL_HOLD` (`review`) | `needs_human_review: true` → `DeferQueue` |
| Unrecognized | `false` | `PARSE_ERROR` (`blocked`) | Fail-closed |
| *(absent)* | `false` | `cage.endpoint_error` (`blocked`) | Fail-closed |

**`REVIEW` is not valid on this endpoint.** `PASS`/`REVIEW`/`BLOCKED` is
`provider_06`'s vocabulary
([`provider_06/adapter.py`](../src/integrations/provider_06/adapter.py:87)).
Map an upstream `REVIEW` to `ESCALATE` — both reach the `DeferQueue`.

**Request example (`ALLOW`):**
```json
{
  "decision": "ALLOW",
  "authority_record_id": "ar-7f3c9b21",
  "authority_state_version": 14
}
```

`authority_record_id` is **required on `ALLOW`**. CAGE mints a ConsequenceToken
bound to it; without the field the mint raises, a
`CONSEQUENCE_TOKEN_MINT_FAILED` finding (`blocked`) is emitted, and `admitted`
is forced to `false`
([`provider.py`](../src/integrations/provider_01/provider.py:357)). This is a
**separate** failure from a missing `decision` — the response is well-formed and
says `ALLOW`, yet still fails closed. `authority_state_version` is nullable.

> **Wire-contract change:** the legacy binary `admitted`/`findings` shape is no
> longer accepted; `decision` is mandatory and its absence fails closed rather
> than admitting. The `authority_record_id`-on-`ALLOW` requirement is documented
> alongside it. See **BC-03** in
> [`docs/BREAKING_CHANGES_v3.md`](BREAKING_CHANGES_v3.md).

---

### 7.2 Other Provider 01 endpoints

| Method | Path | Purpose | Failure mode |
|---|---|---|---|
| `GET` | `/legal-baseline/{region}` | Fetch regional normative baseline | Returns `NormativeBaseline` with populated `error`; empty profile |
| `GET` | `/evidence-chain/{thread_id}` | Seal governance evidence hash (`?evidence_hash=`) | Returns `EvidenceSeal` with populated `error` |

---

## External Endpoint Summary

| Service | Method | Path | Description |
|---|---|---|---|
| Gateway Server | `GET` | `/healthz` | KMS connectivity health check |
| Gateway Server | `POST` | `/inference/v1/chat/completions` | OpenAI-compatible governed LLM inference |
| MCP Tool Server | `GET` | `/health` | MCP tool server health probe |
| Compliance Bridge | `GET` | `/health` | Compliance Bridge health probe |
| Compliance Bridge | `GET` | `/v1/events/stream` | SSE governance event stream |
| Compliance Bridge | `GET` | `/v1/controls` | List compliance controls registry |
| Compliance Bridge | `GET` | `/v1/metrics/summary` | Aggregate compliance posture snapshot |
| Compliance Bridge | `GET` | `/v1/metrics/{control_id}` | Per-control compliance metrics |
| Compliance Bridge | `GET` | `/v1/oscal/assessment-results` | OSCAL 1.1.2 Assessment Results export |
| Compliance Bridge | `GET` | `/v1/aarm/conformance-report` | CSA AARM Conformance Report Card |
| Compliance Bridge | `GET` | `/v1/telemetry/history` | Paginated compliance telemetry history |
| Governed Financial Advisor | `GET` | `/` | Service root |
| Governed Financial Advisor | `GET` | `/health` | Service health probe |
| Governed Financial Advisor | `POST` | `/agent/query` | Main LangGraph agent query |
| Governed Financial Advisor | `POST` | `/v1/approvals/{thread_id}/resume` | Resume HITL-interrupted thread |
| Governed Financial Advisor | `GET` | `/v1/approvals/pending` | List pending HITL approvals |
| Governed Financial Advisor | `POST` | `/v1/refinement/trigger` | Submit KFP governance refinement run |
| Governed Financial Advisor | `POST` | `/v1/nemo/propose-refinement` | Stage NeMo refinement proposal |
| Governed Financial Advisor | `POST` | `/v1/nemo/approve-refinement/{proposal_id}` | Approve/reject NeMo proposal |
| Governed Financial Advisor | `GET` | `/v1/nemo/proposals/pending` | List pending NeMo proposals |
| Governed Financial Advisor | `POST` | `/v1/nemo/apply-refinement` | Legacy NeMo refinement endpoint |
| Governed Financial Advisor | `POST` | `/v1/webhooks/langfuse` | Langfuse webhook receiver |
| Governed Financial Advisor | `POST` | `/tools/execute` | Execute named tool with governance |
| Governed Financial Advisor | `GET` | `/demo/status` | Demo status (dev only) |
| Governed Financial Advisor | `POST` | `/demo/context` | Set demo context (dev only) |
| Governed Financial Advisor | `POST` | `/demo/reset` | Reset demo state (dev only) |
| gRPC Gateway | `rpc` | `Chat` | Server-streaming governed LLM responses |
| gRPC Gateway | `rpc` | `ExecuteTool` | Unary tool execution via gRPC |

---
