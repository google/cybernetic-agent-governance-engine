# CAGE Open Interoperability Specification — Developer Preview Spec

> **Version:** 1.0-preview
> **Audience:** External software publishers and integration partners
> **Status:** Developer Preview — subject to change before general availability
> **Distribution:** Cleared for external distribution — sanitized per security review 2026-07-05

---

## Table of Contents

1. [Platform Overview](#1-platform-overview)
2. [Authentication and Security Model](#2-authentication-and-security-model)
3. [Gateway Service — Governed Inference API](#3-gateway-service--governed-inference-api)
4. [Compliance Artifact Service](#4-compliance-artifact-service)
5. [Governed Agentic Workflow Service (Financial Advisory Reference Implementation)](#5-financial-advisory-service)
6. [Real-Time Event Streams](#6-real-time-event-streams)
7. [gRPC Services](#7-grpc-services)
8. [Schema Reference](#8-schema-reference)
9. [Error Reference](#9-error-reference)
10. [Rate Limits and Quotas](#10-rate-limits-and-quotas)

---

## 1. Platform Overview

CAGE (Cybernetic Agent Governance Engine) is a domain-agnostic governed AI platform
that provides policy-enforced, auditable, and compliance-ready AI inference and
high-reliability agentic workflow capabilities for any regulated or
safety-critical industry. The first production vertical is a governed financial
advisory workflow; the governance kernel applies equally to pharmaceutical,
critical infrastructure, and other high-reliability agentic deployments.

### Functional Topology

The platform is composed of three externally addressable services and one gRPC
endpoint, each with a distinct governance responsibility:

| Service | Role |
|---|---|
| **Gateway Service** | Core composition and platform ingestion root layer. Hosts the governed inference pipeline and the MCP tool server. |
| **Compliance Artifact Service** | Compliance posture monitoring, OSCAL artifact export, CSA AARM conformance reporting, and real-time governance event streaming. |
| **Governed Agentic Workflow Service** | Multi-agent orchestration layer for governed agentic workflows, consequential action execution, and human-in-the-loop (HITL) approval workflows. The reference implementation provides governed financial analysis and trade execution; the same orchestration pattern applies to any high-reliability agentic domain. |
| **gRPC Gateway** | Server-streaming and unary gRPC interface for governed LLM responses and tool execution. |

### Governance Pipeline

Every inference request passes through a multi-tier governance pipeline before
reaching the high-throughput inference backend:

1. **Tier-1 keyword scan** — blocks prohibited terms (CBRN and related categories); returns HTTP 403 on breach
2. **Token quota enforcement** — ISO 42001 Annex A.4 compliant atomic counter via distributed cache layer; returns HTTP 429 on breach
3. **AI safety guardrails layer (input)** — verifies input against active safety rails
4. **Governed inference** — forwards to the high-throughput inference backend
5. **AI safety guardrails layer (output)** — strips PII and policy violations from the response before delivery

### Deployment Regions

The platform deploys simultaneously across three regulatory regions, each with
strict data residency requirements:

| Region token | Data residency |
|---|---|
| `US_FED` | United States federal-approved regions |
| `EU_ECB` | `europe-west1` only |
| `APAC_MAS` | `asia-southeast1` only |

The active region is reflected in the `X-CAGE-Deployment-Region` response
header on applicable endpoints.

---

## 2. Authentication and Security Model

CAGE uses three distinct authentication mechanisms, each scoped to a specific
service. All transport must use TLS.

---

### 2.1 `X-CAGE-Routing-Seal` — Gateway Service

An HMAC-SHA256 seal computed over the raw request body bytes. The Gateway
Service verifies this seal on governed write operations to ensure request
integrity end-to-end.

**Required on:**
- `POST /governance/check`
- `POST /tools/execute`

The seal is also returned in `POST /governance/validate-action` responses and
**must be verified by callers before actuating any trade**.

**Header format:**
```
X-CAGE-Routing-Seal: <hex-encoded HMAC-SHA256>
```

---

### 2.2 `Authorization: Bearer <token>` — Compliance Artifact Service

Bearer token validated using constant-time comparison against the configured
service credential.

**Required on:**
- `POST /v1/audit/ingest`

**Header format:**
```
Authorization: Bearer <token>
```

---

### 2.3 `X-API-Key` — Financial Advisory Service

API key validated by the Financial Advisory Service authentication layer.

**Required on:**
- `POST /agent/query`
- `POST /v1/approvals/{thread_id}/resume`
- `POST /v1/nemo/approve-refinement/{proposal_id}`
- `POST /tools/execute`

**Header format:**
```
X-API-Key: <api-key>
```

---

## 3. Gateway Service — Governed Inference API

The Gateway Service acts as the core composition and platform ingestion root
layer. It is an HTTP/1.1 and HTTP/2 compliant REST service that mounts three
functional sub-applications:

| Mount path | Sub-application |
|---|---|
| `/inference` | Governed Inference Pipeline |
| `/governance` | Governance Middleware |
| `/` (catch-all) | MCP Tool Server |

> **Security note:** Any request to a `/debug/*` path returns HTTP 404 in
> production environments.

---

### 3.1 Health Check

#### `GET /healthz`

Key management service connectivity health check.

**Response 200 OK:**
```json
{
  "status": "healthy",
  "kms_active": true,
  "env": "prod"
}
```

**Response 503 Service Unavailable:** Returned when the key management service
is unreachable.

---

### 3.2 MCP Tool Server Health

#### `GET /health`

MCP Tool Server health probe.

**Response 200 OK:**
```json
{
  "status": "ok",
  "mode": "mcp-tool-server",
  "nemo": "active"
}
```

---

### 3.3 Governed Inference Endpoint

#### `POST /inference/v1/chat/completions`

OpenAI-compatible governed inference endpoint. Every request passes through
the full five-tier governance pipeline described in Section 1 before a
response is returned.

**Required headers:**

| Header | Description |
|---|---|
| `Content-Type` | `application/json` |
| `traceparent` | W3C trace context (recommended) |

**Request body** — Standard OpenAI Chat Completion format:

```json
{
  "model": "string",
  "messages": [{"role": "user|assistant|system", "content": "string"}],
  "temperature": 0.7,
  "stream": false,
  "max_tokens": 1024
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `model` | `string` | Yes | Model identifier |
| `messages` | `array` | Yes | Conversation history |
| `temperature` | `float` | No | Sampling temperature |
| `stream` | `bool` | No | Enable streaming response |
| `max_tokens` | `int` | No | Maximum output tokens |

**Response 200 OK:** Standard OpenAI Chat Completion response object. When
`stream: true`, returns a streaming response using server-sent events in
OpenAI streaming format.

**Response 403 Forbidden** — Tier-1 keyword governance block:
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

**Response 429 Too Many Requests** — Token quota exceeded:
```json
{
  "error": "quota_exceeded",
  "reason": "string",
  "step_count": 12,
  "accumulated_tokens": 4096,
  "session_id": "string"
}
```

See [Section 10](#10-rate-limits-and-quotas) for quota semantics.

---

## 4. Compliance Artifact Service

The Compliance Artifact Service provides compliance posture monitoring, OSCAL
artifact export, CSA AARM conformance reporting, and real-time governance event
streaming. It is an HTTP/1.1 and HTTP/2 compliant REST service.

---

### 4.1 Health Check

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

### 4.2 Compliance Controls Registry

#### `GET /v1/controls`

List all compliance controls supported by the platform, filtered by the active
deployment region (`CAGE_DEPLOYMENT_REGION`).

**Query parameters:**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `framework` | `string` | No | Filter by framework name (e.g., `ISO_42001`, `US_FED`) |

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

### 4.3 Aggregate Compliance Posture

#### `GET /v1/metrics/summary`

Aggregate compliance posture snapshot across all supported controls.

**Query parameters:**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `window_hours` | `int` | `24` | Lookback window in hours |

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

## 5. Financial Advisory Service

The Financial Advisory Service provides a multi-agent orchestration layer for
governed financial analysis, trade execution, and human-in-the-loop (HITL)
approval workflows. It is an HTTP/1.1 and HTTP/2 compliant REST service.

---

### 5.1 Service Root

#### `GET /`

**Response 200 OK:**
```json
{
  "status": "ok",
  "message": "Governed Financial Advisor API"
}
```

---

### 5.2 Health Check

#### `GET /health`

**Response 200 OK:**
```json
{
  "status": "ok",
  "service": "financial-advisor-graph-agent"
}
```

---

### 5.3 Agent Query

#### `POST /agent/query`

Main multi-agent orchestration query. Submits a natural-language prompt to the
governed financial advisor agent graph. Requires `X-API-Key` header.
Request timeout: 240 seconds.

**Required headers:**

| Header | Description |
|---|---|
| `X-API-Key` | Service API key |
| `Content-Type` | `application/json` |

**Request body** — see [`QueryRequest`](#86-queryrequest) schema:
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
  "trace_id": "trace-uuid"
}
```

**Response 202 Accepted:** Returned when the agent graph reaches a
human-in-the-loop (HITL) interrupt. The response body includes
`approval_required: true` along with the interrupt payload. Use
`POST /v1/approvals/{thread_id}/resume` to continue.

**Response 401 Unauthorized:** Missing or invalid API key.

**Response 408 Request Timeout:** Agent exceeded the 240-second timeout.

---

### 5.4 HITL Approval — Resume Thread

#### `POST /v1/approvals/{thread_id}/resume`

Resume a thread paused at a HITL interrupt. Injects the human approval
decision into the agent graph to continue execution. Requires `X-API-Key`.

**Path parameters:**

| Parameter | Description |
|---|---|
| `thread_id` | Agent thread UUID |

**Required headers:** `X-API-Key`

**Request body** — see [`ApprovalResumeRequest`](#87-approvalresumerequest) schema:
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

**Response 410 Gone:** HITL TTL expired — the thread can no longer be resumed.

---

### 5.5 HITL Approval — List Pending

#### `GET /v1/approvals/pending`

List all agent threads currently paused at HITL interrupts awaiting human
review.

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

### 5.6 Governance Refinement Pipeline

#### `POST /v1/refinement/trigger`

Submit a governance refinement pipeline run. Triggers the refinement workflow
when compliance metrics breach configured thresholds.

**Request body:**
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

### 5.7 AI Safety Guardrails Refinement — Propose

#### `POST /v1/nemo/propose-refinement`

Stage an AI safety guardrails layer refinement proposal for human review.

**Request body:**
```json
{
  "control_id": "A.9.2",
  "verdict": "TIGHTEN",
  "source": "observability-webhook"
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

### 5.8 AI Safety Guardrails Refinement — Approve

#### `POST /v1/nemo/approve-refinement/{proposal_id}`

Approve or reject a staged AI safety guardrails refinement proposal. Requires
`X-API-Key`.

**Path parameters:**

| Parameter | Description |
|---|---|
| `proposal_id` | Proposal UUID |

**Required headers:** `X-API-Key`

**Request body:**
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

### 5.9 AI Safety Guardrails Refinement — List Pending

#### `GET /v1/nemo/proposals/pending`

List all staged AI safety guardrails refinement proposals awaiting human
review.

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

### 5.10 AI Safety Guardrails Refinement — Legacy Apply

#### `POST /v1/nemo/apply-refinement`

Legacy gated endpoint. In production, routes to the proposal/approval flow
described in Sections 5.7–5.8.

**Request body:** Same as `POST /v1/nemo/propose-refinement`.

---

### 5.11 Observability Webhook Receiver

#### `POST /v1/webhooks/langfuse`

Webhook receiver that triggers the governance refinement pipeline when safety
metrics breach configured thresholds.

**Request body:**
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

### 5.12 Tool Execution

#### `POST /tools/execute`

Execute a named tool with full governance enforcement. For `execute_trade`,
the Gateway Service validates the action and verifies the routing seal before
actuation. Requires `X-API-Key` and `X-CAGE-Routing-Seal` headers.

**Required headers:** `X-API-Key`, `X-CAGE-Routing-Seal`

**Request body:**
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
| `simulate_governance_check` | Dry-run governance simulation | None |
| `trigger_safety_intervention` | Lock system | None |
| `verify_content_safety` | AI safety guardrails content check | None |
| `evaluate_policy` | Policy evaluation engine assessment | None |
| `execute_trade` | Governed trade execution | Full 7-tier pipeline via Gateway Service |

**Response 200 OK:**
```json
{
  "status": "SUCCESS",
  "output": "string",
  "trace_id": "otel-trace-id"
}
```

---

## 6. Real-Time Event Streams

### 6.1 Governance Event Stream

#### `GET /v1/events/stream`

Server-Sent Events (SSE) stream of real-time governance events from the
Compliance Artifact Service. A heartbeat `ping` event is emitted every 30
seconds to keep the connection alive. The platform supports a maximum of 100
concurrent subscribers.

**SSE event type:** `governance-event`

**Event `data` field** (JSON-encoded):
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

| Field | Type | Description |
|---|---|---|
| `type` | `string` | Event classification |
| `traceId` | `string` | Observability trace identifier |
| `controlId` | `string` | Compliance control identifier |
| `result` | `string` | `PASS` or `FAIL` |
| `safetyRate` | `float` | Safety pass rate at time of event |
| `auditId` | `string` | UUID of the associated audit record |
| `timestamp` | `string` | ISO 8601 UTC timestamp |

**Connection management:**
- Reconnect using the standard SSE `Last-Event-ID` header to resume from the
  last received event.
- The server closes the connection after 100 concurrent subscribers are
  reached; clients should implement exponential back-off on reconnect.

---

## 7. gRPC Services

**Package:** `gateway`
**Service:** `Gateway`

The gRPC Gateway service exposes server-streaming governed LLM responses and
unary tool execution to external gRPC clients.

---

### 7.1 `rpc Chat(ChatRequest) returns (stream ChatResponse)`

Server-streaming RPC. Streams governed LLM response tokens as they are
generated. The full governance pipeline (Section 1) applies before the first
token is streamed.

**`ChatRequest` message fields:**

| Field | Type | Description |
|---|---|---|
| `model` | `string` | Model identifier |
| `messages` | `repeated Message` | Conversation history |
| `temperature` | `float` | Sampling temperature |
| `system_instruction` | `string` | System prompt override |
| `mode` | `string` | Inference mode |
| `guided_json` | `string` | JSON schema for structured output |
| `guided_regex` | `string` | Regex pattern for constrained output |
| `guided_choice` | `repeated string` | Allowed output choices |

**`Message` message fields:**

| Field | Type |
|---|---|
| `role` | `string` |
| `content` | `string` |

**`ChatResponse` message fields (streamed):**

| Field | Type | Description |
|---|---|---|
| `content` | `string` | Token chunk |
| `is_final` | `bool` | `true` on the last chunk |
| `input_tokens` | `int32` | Input token count (final chunk only) |
| `output_tokens` | `int32` | Output token count (final chunk only) |

---

### 7.2 `rpc ExecuteTool(ToolRequest) returns (ToolResponse)`

Unary RPC. Execute a named tool via gRPC with governance enforcement.

**`ToolRequest` message fields:**

| Field | Type | Description |
|---|---|---|
| `tool_name` | `string` | Tool identifier |
| `params_json` | `string` | JSON-encoded parameters |

**`ToolResponse` message fields:**

| Field | Type | Description |
|---|---|---|
| `output` | `string` | Tool output |
| `error` | `string` | Error message if failed |
| `status` | `string` | `SUCCESS` or `ERROR` |

---

## 8. Schema Reference

All schemas below are JSON Schema Invariant Payload Definitions — the
canonical wire shapes for request and response bodies across all CAGE services.

---

### 8.1 `ComplianceMetrics`

Returned by `GET /v1/metrics/{control_id}`.

| Field | Type | Required | Description |
|---|---|---|---|
| `control_id` | `string` | Yes | Control identifier |
| `safety_rate` | `float` | No | Pass rate 0.0–1.0 |
| `total_traces` | `integer` | Yes | Total traces in window |
| `blocked_traces` | `integer` | Yes | Blocked/failed traces |
| `passed_traces` | `integer` | Yes | Passed traces |
| `window_hours` | `float` | Yes | Lookback window in hours |
| `last_event_utc` | `string` | Yes | ISO 8601 timestamp of most recent event |
| `evidence_age_seconds` | `float` | Yes | Age of most recent evidence in seconds |
| `startup_grace_active` | `boolean` | Yes | Whether within startup grace period |
| `startup_grace_remaining_hours` | `float` | Yes | Grace period remaining in hours |
| `confabulation_rate` | `float` | No | Confabulation detection rate |
| `confabulation_blocked_traces` | `integer` | Yes | Confabulation-blocked traces |

---

### 8.2 `OscalFinding`

Represents a single OSCAL finding within an Assessment Results document.

| Field | Type | Required | Description |
|---|---|---|---|
| `control_id` | `string` | Yes | Control identifier |
| `result` | `string` | Yes | `PASS`, `FAIL`, `NOT_APPLICABLE`, or `ERROR` |
| `safety_rate` | `float` | No | Pass rate 0.0–1.0 |
| `evidence_age_s` | `float` | No | Evidence age in seconds |
| `finding_id` | `string` | Yes | UUID |
| `remarks` | `string` | No | Human-readable remarks |
| `chain_index` | `integer` | No | Position in the cryptographic hash chain |

---

### 8.3 `TradeOrder`

JSON Schema Invariant Payload Definition for validated trade orders submitted
through the governed trade execution pipeline.

| Field | Type | Required | Constraints |
|---|---|---|---|
| `symbol` | `string` | Yes | 1–5 uppercase letters |
| `amount` | `float` | Yes | Must be > 0 |
| `currency` | `string` | Yes | — |
| `confidence` | `float` | Yes | 0.0–1.0 |
| `side` | `string` | No | — |
| `type` | `string` | No | — |
| `transaction_id` | `string` | Yes | UUID v4 |
| `trader_id` | `string` | No | — |
| `trader_role` | `string` | No | `"junior"` or `"senior"` |

---

### 8.4 `AgentState`

System Protocol Data Contract representing the full agent execution state
within the multi-agent orchestration layer. This is the internal state
propagated across agent nodes; fields are surfaced in API responses where
noted.

| Field | Type | Description |
|---|---|---|
| `messages` | `array` | Conversation history (append-only) |
| `next_step` | `string` | Router target node |
| `risk_status` | `string` | Risk assessment result |
| `risk_feedback` | `string` | Risk analyst feedback |
| `loop_count` | `integer` | Iteration counter |
| `safety_status` | `string` | Safety check result |
| `governance_signature` | `string` | Key management service-backed governance seal |
| `risk_attitude` | `string` | User risk preference |
| `investment_period` | `string` | Investment horizon |
| `reasoning_output` | `string` | Advisor reasoning |
| `execution_plan_output` | `string` | Trader execution plan |
| `data_analyst_ticker` | `string` | Ticker under analysis |
| `evaluation_result` | `string` | Evaluator verdict |
| `opa_results` | `object` | Policy evaluation engine results |
| `execution_result` | `string` | Trade execution result |
| `governance_summary` | `string` | Governance pipeline summary |
| `user_id` | `string` | User identifier |
| `latency_stats` | `object` | Per-node latency measurements |
| `completed_transactions` | `array` of `LedgerEntry` | Immutable append-only ledger |
| `approval_required` | `boolean` | HITL interrupt flag |
| `approval_decision` | `boolean\|null` | Human approval decision |
| `hitl_expires_at` | `string\|null` | HITL TTL timestamp (ISO 8601) |
| `guardrail_blocked` | `boolean` | AI safety guardrails input rail blocked |
| `guardrail_reason` | `string\|null` | Block reason |
| `output_rail_applied` | `boolean` | AI safety guardrails output rail applied |

---

### 8.5 `LedgerEntry`

Immutable transaction ledger entry appended to `AgentState.completed_transactions`.
Entries are never modified after creation.

| Field | Type | Required | Description |
|---|---|---|---|
| `sequence_id` | `string` | Yes | Monotonic sequence identifier |
| `timestamp` | `string` | Yes | ISO 8601 timestamp |
| `uca_ref` | `string` | Yes | STPA Unsafe Control Action reference |
| `action` | `string` | Yes | Action taken |
| `idempotency_key` | `string` | Yes | Deduplication key |
| `status` | `string` | Yes | `PENDING`, `COMPLETED`, `ROLLED_BACK`, or `PARTIAL_FAILURE` |
| `context_data` | `object` | Yes | Arbitrary context payload |

---

### 8.6 `QueryRequest`

Request body for `POST /agent/query`.

| Field | Type | Required |
|---|---|---|
| `prompt` | `string` | Yes |
| `user_id` | `string` | Yes |
| `thread_id` | `string` | Yes |

---

### 8.7 `ApprovalResumeRequest`

Request body for `POST /v1/approvals/{thread_id}/resume`.

| Field | Type | Required | Constraints |
|---|---|---|---|
| `approved` | `boolean` | Yes | — |
| `reviewer` | `string` | Yes | Non-empty |
| `rationale` | `string` | Yes | Minimum 10 characters |
| `comment` | `string` | Yes | — |
| `max_slippage_pct` | `float` | Yes | 0.0–100.0 |

---

## 9. Error Reference

All CAGE services return errors as JSON objects. The following error shapes
and status codes apply across the platform.

---

### 9.1 HTTP 400 Bad Request

Returned when the request body fails schema validation.

```json
{
  "detail": [
    {
      "loc": ["body", "field_name"],
      "msg": "field required",
      "type": "value_error.missing"
    }
  ]
}
```

---

### 9.2 HTTP 401 Unauthorized

Returned when the `X-API-Key` header is missing or invalid.

```json
{
  "detail": "Unauthorized"
}
```

---

### 9.3 HTTP 403 Forbidden — Governance Block

Returned by the Governed Inference endpoint when a Tier-1 keyword governance
rule is triggered.

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

---

### 9.4 HTTP 404 Not Found

Returned when a path parameter references an unknown resource (e.g., unknown
`control_id`).

```json
{
  "detail": "Not found"
}
```

---

### 9.5 HTTP 408 Request Timeout

Returned by `POST /agent/query` when the agent graph exceeds the 240-second
timeout.

```json
{
  "detail": "Agent timeout"
}
```

---

### 9.6 HTTP 410 Gone

Returned by `POST /v1/approvals/{thread_id}/resume` when the HITL TTL has
expired and the thread can no longer be resumed.

```json
{
  "detail": "HITL TTL expired"
}
```

---

### 9.7 HTTP 429 Too Many Requests — Quota Exceeded

Returned by the Governed Inference endpoint when the token quota is breached.

```json
{
  "error": "quota_exceeded",
  "reason": "string",
  "step_count": 12,
  "accumulated_tokens": 4096,
  "session_id": "string"
}
```

See [Section 10](#10-rate-limits-and-quotas) for retry guidance.

---

### 9.8 HTTP 500 Internal Server Error

Returned when an unhandled error occurs within the platform.

```json
{
  "detail": "Internal server error"
}
```

Clients should implement exponential back-off with jitter when retrying after
a 500 response.

---

### 9.9 HTTP 503 Service Unavailable

Returned by `GET /healthz` when the key management service is unreachable.

```json
{
  "detail": "KMS unreachable"
}
```

---

## 10. Rate Limits and Quotas

### 10.1 Token Quota — Governed Inference

The Governed Inference endpoint enforces ISO 42001 Annex A.4 compliant token
quotas via an atomic counter in the distributed cache layer.

| Quota dimension | Behaviour on breach |
|---|---|
| Per-session token accumulation | HTTP 429 with `quota_exceeded` body |
| Per-session step count | HTTP 429 with `quota_exceeded` body |

**Retry guidance:** When a 429 is received, inspect the `reason` field in the
response body. Do not retry immediately. Implement exponential back-off
starting at 1 second, doubling up to a maximum of 60 seconds.

**Response fields on 429:**

| Field | Type | Description |
|---|---|---|
| `error` | `string` | Always `"quota_exceeded"` |
| `reason` | `string` | Human-readable reason |
| `step_count` | `integer` | Current step count for the session |
| `accumulated_tokens` | `integer` | Tokens accumulated in the session |
| `session_id` | `string` | Session identifier |

---

### 10.2 SSE Subscriber Limit

The governance event stream (`GET /v1/events/stream`) supports a maximum of
**100 concurrent subscribers**. Connections beyond this limit are rejected.
Clients should implement reconnect logic with exponential back-off.

---

### 10.3 Compliance Metrics Cache

`GET /v1/metrics/{control_id}` results are cached with a **5-minute TTL**.
Clients polling for real-time posture should use the SSE stream
(`GET /v1/events/stream`) instead of polling this endpoint at intervals shorter
than 5 minutes.

---

### 10.4 Agent Query Concurrency

`POST /agent/query` enforces a per-request timeout of **240 seconds**. Clients
should not submit a new query for the same `thread_id` while a prior query is
in flight.

---

## Endpoint Summary

| Service | Method | Path | Auth | Description |
|---|---|---|---|---|
| Gateway Service | `GET` | `/healthz` | None | Key management service connectivity health check |
| Gateway Service | `POST` | `/inference/v1/chat/completions` | None | OpenAI-compatible governed LLM inference |
| Gateway Service | `GET` | `/health` | None | MCP tool server health probe |
| Compliance Artifact Service | `GET` | `/health` | None | Service health probe |
| Compliance Artifact Service | `GET` | `/v1/events/stream` | None | SSE governance event stream |
| Compliance Artifact Service | `GET` | `/v1/controls` | None | List compliance controls registry |
| Compliance Artifact Service | `GET` | `/v1/metrics/summary` | None | Aggregate compliance posture snapshot |
| Compliance Artifact Service | `GET` | `/v1/metrics/{control_id}` | None | Per-control compliance metrics |
| Compliance Artifact Service | `GET` | `/v1/oscal/assessment-results` | `Bearer` | OSCAL 1.1.2 Assessment Results export |
| Compliance Artifact Service | `GET` | `/v1/aarm/conformance-report` | `Bearer` | CSA AARM Conformance Report Card |
| Compliance Artifact Service | `GET` | `/v1/telemetry/history` | None | Paginated compliance telemetry history |
| Financial Advisory Service | `GET` | `/` | None | Service root |
| Financial Advisory Service | `GET` | `/health` | None | Service health probe |
| Financial Advisory Service | `POST` | `/agent/query` | `X-API-Key` | Main multi-agent orchestration query |
| Financial Advisory Service | `POST` | `/v1/approvals/{thread_id}/resume` | `X-API-Key` | Resume HITL-interrupted thread |
| Financial Advisory Service | `GET` | `/v1/approvals/pending` | None | List pending HITL approvals |
| Financial Advisory Service | `POST` | `/v1/refinement/trigger` | None | Submit governance refinement pipeline run |
| Financial Advisory Service | `POST` | `/v1/nemo/propose-refinement` | None | Stage AI safety guardrails refinement proposal |
| Financial Advisory Service | `POST` | `/v1/nemo/approve-refinement/{proposal_id}` | `X-API-Key` | Approve/reject AI safety guardrails proposal |
| Financial Advisory Service | `GET` | `/v1/nemo/proposals/pending` | None | List pending AI safety guardrails proposals |
| Financial Advisory Service | `POST` | `/v1/nemo/apply-refinement` | None | Legacy AI safety guardrails refinement endpoint |
| Financial Advisory Service | `POST` | `/v1/webhooks/langfuse` | None | Observability webhook receiver |
| Financial Advisory Service | `POST` | `/tools/execute` | `X-API-Key` + `X-CAGE-Routing-Seal` | Execute named tool with governance |
| gRPC Gateway | `rpc` | `Chat` | — | Server-streaming governed LLM responses |
| gRPC Gateway | `rpc` | `ExecuteTool` | — | Unary tool execution via gRPC |

---

*End of CAGE Open Interoperability Specification — Developer Preview Spec v1.0-preview*

