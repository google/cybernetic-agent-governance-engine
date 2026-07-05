# CAGE API Map — Cybernetic AI Governance Engine

> **Generated:** 2026-07-05 · **Scope:** All HTTP REST, gRPC, SSE, and MCP
> endpoints across all four services plus cross-service call patterns.

---

## Table of Contents

1. [Service Overview](#1-service-overview)
2. [Gateway Server — port 8080](#2-gateway-server--port-8080)
   - 2.1 [Root App — hybrid_server.py](#21-root-app--hybrid_serverpy)
   - 2.2 [Inference Sub-App — inference_proxy.py](#22-inference-sub-app--inference_proxypy)
   - 2.3 [Governance Sub-App — governance_middleware.py](#23-governance-sub-app--governance_middlewarepy)
   - 2.4 [MCP Tool Server Sub-App — mcp_tool_server.py](#24-mcp-tool-server-sub-app--mcp_tool_serverpy)
3. [Compliance Bridge — port 3001](#3-compliance-bridge--port-3001)
4. [Governed Financial Advisor](#4-governed-financial-advisor)
   - 4.1 [Core Endpoints — server.py](#41-core-endpoints--serverpy)
   - 4.2 [Tools Router — tools/api.py](#42-tools-router--toolsapipy)
   - 4.3 [Demo Router — demo/router.py](#43-demo-router--demoRouterpy)
5. [gRPC Services](#5-grpc-services)
   - 5.1 [Gateway gRPC — gateway.proto](#51-gateway-grpc--gatewayproto)
   - 5.2 [NeMo Guardrails gRPC — nemo.proto](#52-nemo-guardrails-grpc--nemoproto)
6. [MCP Tools — FastMCP over SSE](#6-mcp-tools--fastmcp-over-sse)
7. [Key Schemas and Types](#7-key-schemas-and-types)
   - 7.1 [Gateway Schemas](#71-gateway-schemas)
   - 7.2 [Compliance Bridge Schemas](#72-compliance-bridge-schemas)
   - 7.3 [Governed Financial Advisor Schemas](#73-governed-financial-advisor-schemas)
   - 7.4 [Protocol Interfaces — Contracts](#74-protocol-interfaces--contracts)
8. [Cross-Service Call Patterns](#8-cross-service-call-patterns)
9. [Authentication and Security Model](#9-authentication-and-security-model)
10. [Compliance Control Registry](#10-compliance-control-registry)

---

## 1. Service Overview

| Service | Default Port | Framework | Auth Model |
|---|---|---|---|
| Gateway Server | `8080` | FastAPI (3 sub-apps) | `X-CAGE-Routing-Seal` HMAC-SHA256 |
| Compliance Bridge | `3001` | FastAPI | Bearer token (`COMPLIANCE_BRIDGE_INTERNAL_TOKEN`) |
| Governed Financial Advisor | `Config.PORT` | FastAPI + LangGraph | `X-API-Key` header |
| NeMo gRPC Sidecar | `PORT` env (default `8000`) | gRPC asyncio | mTLS (cluster-internal) |

### Service Topology

```
AgentSight UI (:5173)
  │  SSE  GET /v1/events/stream
  │  REST  GET /v1/metrics/{id}
  └──► Compliance Bridge (:3001)
         │  Langfuse SDK
         │  Redis Streams
         └──► GCS / Langfuse / Redis

Governed Financial Advisor (:Config.PORT)
  │  POST /governance/validate-action
  │  GET  /governance/policy-version
  │  POST /inference/v1/chat/completions
  └──► Gateway Server (:8080)
         │  gRPC Verify
         ├──► NeMo gRPC Sidecar (:8000)
         │  POST /v1/chat/completions
         ├──► vLLM Backend
         │  Rego eval
         ├──► OPA Policy Engine
         │  HMAC seal / KMS sign
         └──► Cloud KMS
```

### Lifespan Warm-Up (Gateway)

On startup, [`_gateway_lifespan()`](src/gateway/server/hybrid_server.py:58) pre-warms:
- NeMo Rails singleton (in-process)
- OPA client
- Token Quota Proxy (Redis connection)
- KMS signer
- Routing seal verifier
- KFP polling task (background)

---

## 2. Gateway Server — port 8080

The gateway is a FastAPI composition root defined in
[`hybrid_server.py`](src/gateway/server/hybrid_server.py) that mounts three
sub-applications:

| Mount path | Sub-app | Source file |
|---|---|---|
| `/inference` | `inference_app` | [`inference_proxy.py`](src/gateway/server/inference_proxy.py) |
| `/governance` | `governance_app` | [`governance_middleware.py`](src/gateway/server/governance_middleware.py) |
| `/` (catch-all) | `mcp_app` | [`mcp_tool_server.py`](src/gateway/server/mcp_tool_server.py) |

**Global middleware:**
[`_DebugEndpointGuard`](src/gateway/server/hybrid_server.py:231) — returns
HTTP 404 for any `/debug/*` path unless `CAGE_ENV` is `dev` or `test`.

---

### 2.1 Root App — [`hybrid_server.py`](src/gateway/server/hybrid_server.py)

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

### 2.2 Inference Sub-App — [`inference_proxy.py`](src/gateway/server/inference_proxy.py)

Mounted at `/inference`. Implements an OpenAI-compatible governed inference
endpoint.

#### `POST /inference/v1/chat/completions`

OpenAI-compatible governed inference. Governance pipeline runs in order:

1. **Tier-1 Aho-Corasick keyword scan** — blocks CBRN/prohibited terms (HTTP 403)
2. **Token Quota check** ([`TokenQuotaProxy`](src/gateway/governance/token_quota_proxy.py:194)) — ISO 42001 Annex A.4; atomic Redis Lua counter (HTTP 429 on breach)
3. **NeMo input rail** — in-process manager verifies input
4. **vLLM proxy** — forwards to backend resolved by [`_resolve_backend_url()`](src/gateway/server/inference_proxy.py:174)
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

### 2.3 Governance Sub-App — [`governance_middleware.py`](src/gateway/server/governance_middleware.py)

Mounted at `/governance`.

#### `POST /governance/check`

Internal dry-run governance check. Requires `X-CAGE-Routing-Seal` header
(HMAC-SHA256 over request body, verified by
[`enforce_routing_seal()`](src/gateway/server/governance_middleware.py:178)).

**Request body:**
```json
{
  "tool_name": "execute_trade_action",
  "params": {"symbol": "AAPL", "amount": 1000.0}
}
```

**Response 200 OK:**
```json
{
  "status": "APPROVED",
  "violations": [],
  "opa_results": {}
}
```

**Response 403 Forbidden:** Missing or invalid routing seal.

---

#### `GET /governance/policy-version`

Returns the currently active OPA policy hash.

**Response 200 OK:**
```json
{
  "active_hash": "sha256:abc123..."
}
```

---

#### `POST /governance/validate-action`

Unified 7-tier governance validation pipeline. Primary governance entry point
for the Governed Financial Advisor.

**7-tier pipeline (in order):**

| Tier | Name | Implementation |
|---|---|---|
| 1 | Keyword scan | Aho-Corasick via [`tier1_keyword_check()`](src/gateway/server/governance_middleware.py:244) |
| 2 | Confidence check | [`ConfidenceThresholds`](src/gateway/governance/schemas/thresholds.py:94) |
| 3 | CBF barrier | [`CbfThresholds`](src/gateway/governance/schemas/thresholds.py:56) |
| 4 | OPA Rego eval | [`PolicyClient.evaluate()`](src/gateway/governance/contracts.py:74) |
| 5 | Fiscal limit | [`FiscalGuard.reserve()`](src/gateway/governance/contracts.py:159) |
| 6 | Consensus check | [`ConsensusProvider.check_consensus()`](src/gateway/governance/contracts.py:52) |
| 7 | Causal gatekeeper | [`CausalGatekeeper.causal_safety_check()`](src/gateway/governance/contracts.py:120) |

**Request body** ([`ValidateActionRequest`](src/gateway/server/governance_middleware.py:343)):
```json
{
  "action": "execute_trade",
  "params": {
    "symbol": "AAPL",
    "amount": 5000.0,
    "currency": "USD",
    "confidence": 0.87,
    "trader_id": "u-001",
    "trader_role": "senior"
  },
  "policy_version_id": "sha256:abc123..."
}
```

**Response 200 OK:**
```json
{
  "verdict": "APPROVED",
  "violations": [],
  "seal": "hmac-sha256:...",
  "latency_ms": 42.3
}
```

**Response 403 Forbidden:** Hard governance refusal. Also emits a signed OSCAL
compliance receipt via
[`_emit_refusal_receipt()`](src/gateway/server/governance_middleware.py:417).

---

### 2.4 MCP Tool Server Sub-App — [`mcp_tool_server.py`](src/gateway/server/mcp_tool_server.py)

Mounted at `/` (catch-all). Exposes both an HTTP tool dispatch endpoint and a
FastMCP SSE transport.

**Rate limit:** 60 requests / 60 seconds per client IP, enforced by
[`_check_rate_limit()`](src/gateway/server/mcp_tool_server.py:82).

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

#### `POST /tools/execute`

HTTP tool dispatch. Requires `X-CAGE-Routing-Seal` header.

**Request body** (`ToolExecutionRequest`):
```json
{
  "tool_name": "execute_trade_action",
  "params": {"symbol": "TSLA", "amount": 2500.0}
}
```

**Response 200 OK:**
```json
{
  "status": "SUCCESS",
  "output": "string"
}
```

**Response 429 Too Many Requests:** Rate limit exceeded.
**Response 403 Forbidden:** Missing or invalid routing seal.

---

#### `GET /mcp` — FastMCP SSE Transport

FastMCP SSE transport endpoint. Implements the Model Context Protocol over
Server-Sent Events. MCP clients connect here to discover and invoke the six
registered tools (see [Section 6](#6-mcp-tools--fastmcp-over-sse)).

---

## 3. Compliance Bridge — port 3001

Defined in [`main.py`](src/compliance_bridge/main.py). CORS origins:
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
(enforced by [`GovernanceEventBus`](src/compliance_bridge/sse_events.py:93)).

**Event type:** `governance-event`

**Event data** (wire shape from [`GovernanceEventBus.publish()`](src/compliance_bridge/sse_events.py:197)):
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
concurrency limit (see [`get_compliance_metrics()`](src/compliance_bridge/metrics.py:234)).

**Path params:** `control_id` — must be in `SUPPORTED_CONTROLS`

**Query params:**

| Param | Type | Default |
|---|---|---|
| `window_hours` | `int` | `24` |

**Response 200 OK** ([`ComplianceMetrics`](src/compliance_bridge/types.py:63)):
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

#### `GET /v1/audit/status/{audit_id}`

Poll the status of an async audit workflow.

**Path params:** `audit_id` — UUID

**Response 200 OK:**
```json
{
  "audit_id": "uuid",
  "status": "pending | running | done | error",
  "result": {}
}
```

**Response 404 Not Found:** Unknown `audit_id`.

---

#### `POST /v1/audit/ingest`

Ingest an OSCAL audit result and run the 6-step audit workflow. Requires
`Authorization: Bearer <COMPLIANCE_BRIDGE_INTERNAL_TOKEN>` (validated by
[`require_internal_token`](src/compliance_bridge/auth.py:40)). Dev bypass when
`CAGE_ENV=dev` and no token configured.

**Query params:**

| Param | Type | Default | Description |
|---|---|---|---|
| `background` | `bool` | `false` | Run workflow asynchronously |

**Request body** (`AuditIngestRequest`):
```json
{
  "oscal_yaml": "---\noscal-version: 1.1.2\n...",
  "audit_id": "uuid (optional, auto-generated if omitted)"
}
```

**Audit workflow steps** ([`run_audit_workflow()`](src/compliance_bridge/audit_workflow.py:697)):

| Step | Description |
|---|---|
| 1 | Persist OSCAL artifact to GCS/S3 |
| 2 | Parse OSCAL YAML to `OscalFinding` list |
| 2b | SHA-256 hash-chain Context Accumulator (AARM mandate) |
| 3 | Ingest findings to Langfuse compliance project |
| 4 | Alert on critical control failures |
| 5 | LLM remediation advisory via vLLM |
| 6 | Generate AARM Conformance Report |

**Response 200 OK** (synchronous):
```json
{
  "audit_id": "uuid",
  "status": "done",
  "findings": [],
  "chain_root": "sha256:...",
  "chain_length": 7,
  "chain_integrity_valid": true,
  "aarm_report_artifact": "gs://bucket/aarm/..."
}
```

**Response 202 Accepted** (when `background=true`):
```json
{
  "audit_id": "uuid",
  "status": "running"
}
```

**Response 401 Unauthorized:** Missing or invalid Bearer token.

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

#### `GET /v1/defer/pending`

List execution contexts currently parked in the DEFER queue (Redis db=1).

**Query params:**

| Param | Type | Default |
|---|---|---|
| `limit` | `int` | `50` |

**Response 200 OK:**
```json
{
  "pending": [
    {
      "defer_id": "uuid",
      "parked_at": "2026-07-05T01:00:00Z",
      "reason": "string",
      "context": {}
    }
  ],
  "count": 3
}
```

---

#### `POST /v1/defer/{defer_id}/inject`

Resolve a parked DEFER token via automated data injection.

**Path params:** `defer_id` — UUID

**Request body** (`DeferResolveRequest`):
```json
{
  "injection_data": {},
  "note": "Resolved by reconciliation worker"
}
```

**Response 200 OK:**
```json
{
  "status": "resolved",
  "defer_id": "uuid",
  "resolution": "INJECTED"
}
```

**Response 404 Not Found:** Unknown `defer_id`.

---

#### `POST /v1/defer/{defer_id}/escalate`

Escalate a DEFER-parked token to full HITL `MANUAL_REVIEW`.

**Path params:** `defer_id` — UUID

**Response 200 OK:**
```json
{
  "status": "escalated",
  "defer_id": "uuid",
  "resolution": "ESCALATED"
}
```

---

#### `GET /v1/prompts/{name}`

Langfuse prompt proxy — fetches a compiled prompt by name.

**Path params:** `name` — prompt name in Langfuse

**Query params:**

| Param | Type | Default | Description |
|---|---|---|---|
| `label` | `string` | `production` | Langfuse label |
| `cache_ttl_seconds` | `int` | `300` | Client-side cache hint |

**Response 200 OK:**
```json
{
  "name": "governance-refusal-advisory",
  "text": "You are a compliance advisor...",
  "version": "3"
}
```

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

## 4. Governed Financial Advisor

Defined in [`server.py`](src/governed_financial_advisor/server.py). Port from
`Config.PORT`. Lifespan initializes the LangGraph agent graph and Redis
checkpointer.

### 4.1 Core Endpoints — [`server.py`](src/governed_financial_advisor/server.py)

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

**Request body** ([`QueryRequest`](src/governed_financial_advisor/server.py:134)):
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

**Request body** ([`ApprovalResumeRequest`](src/governed_financial_advisor/server.py:140)):
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
[`_submit_kfp_run()`](src/governed_financial_advisor/server.py:649).

**Request body** ([`RefinementTriggerRequest`](src/governed_financial_advisor/server.py:180)):
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

**Request body** ([`NeMoApplyRefinementRequest`](src/governed_financial_advisor/server.py:194)):
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

**Request body** ([`NeMoApproveRequest`](src/governed_financial_advisor/server.py:829)):
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

#### `POST /v1/webhooks/langfuse`

Langfuse webhook receiver — triggers refinement pipeline when safety metrics
breach thresholds.

**Request body** ([`LangfuseWebhookEvent`](src/governed_financial_advisor/server.py:213)):
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

### 4.2 Tools Router — [`tools/api.py`](src/governed_financial_advisor/tools/api.py)

Mounted at `/tools`. All endpoints require `X-API-Key` header.

#### `POST /tools/execute`

Execute a named tool with governance enforcement. For `execute_trade`, calls
[`GatewayClient.validate_action()`](src/governed_financial_advisor/infrastructure/gateway_client.py:102)
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
| `execute_trade` | Governed trade execution | Full 7-tier pipeline via Gateway |

**Response 200 OK:**
```json
{
  "status": "SUCCESS",
  "output": "string",
  "trace_id": "otel-trace-id"
}
```

---

### 4.3 Demo Router — [`demo/router.py`](src/governed_financial_advisor/demo/router.py)

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

## 5. gRPC Services

### 5.1 Gateway gRPC — [`gateway.proto`](src/gateway/protos/gateway.proto)

**Package:** `gateway` · **Service:** `Gateway`

#### `rpc Chat(ChatRequest) returns (stream ChatResponse)`

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

#### `rpc ExecuteTool(ToolRequest) returns (ToolResponse)`

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

### 5.2 NeMo Guardrails gRPC — [`nemo.proto`](src/gateway/protos/nemo.proto)

**Package:** `governance` · **Service:** `NeMoGuardrails`

Implemented by [`NeMoService`](src/gateway/governance/nemo/server.py:131).
Runs on port from `PORT` env var (default `8000`). Note: LangGraph nodes use
the in-process manager, not this sidecar.

#### `rpc Verify(VerifyRequest) returns (VerifyResponse)`

Unary RPC. Verify input/output text against NeMo Guardrails rails.

**`VerifyRequest` message:**

| Field | Type | Description |
|---|---|---|
| `input` | `string` | Text to verify |
| `context_json` | `string` | JSON-encoded context |

**`VerifyResponse` message:**

| Field | Type | Description |
|---|---|---|
| `response` | `string` | Guardrails response (may be modified) |
| `status` | `string` | `PASS`, `BLOCKED`, or `ERROR` |

---

## 6. MCP Tools — FastMCP over SSE

Registered via `@mcp.tool()` in
[`mcp_tool_server.py`](src/gateway/server/mcp_tool_server.py). Accessible via
the FastMCP SSE transport at `GET /mcp` or via HTTP at `POST /tools/execute`.

| Tool name | Signature | Description |
|---|---|---|
| `simulate_governance_check` | `(target_tool: str, target_params: dict, risk_profile: str)` | Dry-run governance simulation — no side effects |
| `execute_trade_action` | `(symbol: str, amount: float, currency: str, confidence: float, transaction_id: str\|None, trader_id: str, trader_role: str, dry_run: bool)` | Governed trade execution — full 7-tier pipeline |
| `trigger_safety_intervention` | `(reason: str = "Unknown")` | Lock system immediately |
| `check_market_status` | `(symbol: str)` | Market data lookup |
| `get_market_sentiment` | `(symbol: str)` | Market sentiment analysis |
| `verify_content_safety` | `(text: str)` | NeMo content safety check |

**`execute_trade_action` governance flow:**
1. Calls `POST /governance/validate-action` internally
2. Verifies returned routing seal via
   [`routing_seal`](src/gateway/governance/routing_seal.py)
3. Only actuates trade if seal is valid and verdict is `APPROVED`

---

## 7. Key Schemas and Types

### 7.1 Gateway Schemas

#### [`TradeOrder`](src/gateway/core/structs.py:24)

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

#### [`GovernanceThresholds`](src/gateway/governance/schemas/thresholds.py:116)

Root schema for `config/governance_thresholds.json`. Loaded and cached by
[`load_and_validate_thresholds()`](src/gateway/governance/schemas/thresholds.py:153).

| Field | Type | Description |
|---|---|---|
| `cbf` | `CbfThresholds` | `{min_cash_balance, gamma}` |
| `drawdown` | `DrawdownThresholds` | `{limit}` |
| `stpa` | `StpaThresholds` | `{uca5_drawdown_threshold_pct, uca6_max_order_volume_fraction, max_sell_portfolio_fraction, max_latency_ms}` |
| `confidence` | `ConfidenceThresholds` | `{min_trade_confidence}` |
| `consensus` | `ConsensusThresholds` | `{threshold_usd}` |
| `tier1_keywords` | `list[str]` | Prohibited keyword list (non-empty) |
| `tier1_keywords_cbrn` | `list[str]` | CBRN keyword list |
| `tier1_keywords_cbrn_enabled` | `bool` | Enable CBRN scan |
| `pii_audit_log_enabled` | `bool` | Enable PII audit logging |
| `pii_audit_retention_days` | `int` | PII log retention |

---

#### [`ValidateActionRequest`](src/gateway/server/governance_middleware.py:343)

| Field | Type | Description |
|---|---|---|
| `action` | `str` | Action/tool name |
| `params` | `dict` | Action parameters |
| `policy_version_id` | `str` (optional) | Expected policy hash |

---

### 7.2 Compliance Bridge Schemas

#### [`ComplianceMetrics`](src/compliance_bridge/types.py:63)

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

#### [`OscalFinding`](src/compliance_bridge/types.py:101)

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

#### [`EvidenceStreamSink`](src/compliance_bridge/evidence_stream.py:140)

SHA-256 hash-chained Redis Streams sink. Wire format per entry:

| Field | Description |
|---|---|
| `schema` | Schema version identifier |
| `sequence` | Monotonic sequence number |
| `event_type` | Governance event type |
| `control_id` | Control identifier |
| `prev_hash` | SHA-256 of previous entry |
| `record_hash` | SHA-256 of this entry |
| `payload_json` | JSON-encoded event payload |
| `timestamp_utc` | ISO 8601 timestamp |
| `kms_signature` | Async KMS signature |

GCS flush daemon runs every 60 seconds, writing NDJSON to CMEK-encrypted bucket.

---

### 7.3 Governed Financial Advisor Schemas

#### [`AgentState`](src/governed_financial_advisor/graph/state.py:56)

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

#### [`LedgerEntry`](src/governed_financial_advisor/graph/state.py:34)

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

#### [`QueryRequest`](src/governed_financial_advisor/server.py:134)

| Field | Type |
|---|---|
| `prompt` | `str` |
| `user_id` | `str` |
| `thread_id` | `str` |

---

#### [`ApprovalResumeRequest`](src/governed_financial_advisor/server.py:140)

| Field | Type | Constraints |
|---|---|---|
| `approved` | `bool` | — |
| `reviewer` | `str` | Non-empty |
| `rationale` | `str` | Min 10 chars |
| `comment` | `str` | — |
| `max_slippage_pct` | `float` | 0.0–100.0 |

---

### 7.4 Protocol Interfaces — Contracts

Defined in [`contracts.py`](src/gateway/governance/contracts.py). These are
`Protocol` interfaces implemented by the governance pipeline components.

| Protocol | Key method | Description |
|---|---|---|
| [`SafetyFilter`](src/gateway/governance/contracts.py:23) | `verify_action(action_name, payload) -> str` | NeMo/keyword safety check |
| [`ConsensusProvider`](src/gateway/governance/contracts.py:47) | `check_consensus(action, amount, symbol) -> dict` | Multi-agent consensus |
| [`PolicyClient`](src/gateway/governance/contracts.py:60) | `evaluate(policy_path, input_data) -> dict` | OPA Rego evaluation |
| [`CausalGatekeeper`](src/gateway/governance/contracts.py:107) | `causal_safety_check(params, telemetry) -> bool` | Causal inference gate |
| [`FiscalGuard`](src/gateway/governance/contracts.py:145) | `reserve(token) -> ReservationToken` | Fiscal limit reservation |

---

## 8. Cross-Service Call Patterns

### GFA → Gateway

Implemented by [`GatewayClient`](src/governed_financial_advisor/infrastructure/gateway_client.py:38)
(singleton). Base URL from `GATEWAY_URL` env (default `http://localhost:8080`).
All calls inject W3C `traceparent` header for distributed tracing.

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/governance/validate-action` | 7-tier governance check before any trade |
| `GET` | `/governance/policy-version` | Verify policy hash matches expected |
| `POST` | `/inference/v1/chat/completions` | Governed LLM inference for agent nodes |

**`validate_action` call detail** ([`GatewayClient.validate_action()`](src/governed_financial_advisor/infrastructure/gateway_client.py:102)):
- Decorated with `@side_effect_node(kind="api_call", external_system="gateway_api")`
- Injects `traceparent` header from active OpenTelemetry span
- Returns `(verdict, seal, violations, latency_ms)`
- Raises on non-200 or DENIED verdict

---

### AgentSight UI → Compliance Bridge

Calls made from [`KernelDashboard.tsx`](src/agentsight-ui/src/KernelDashboard.tsx:155).
Backend URL from `VITE_BACKEND_URL` env (proxied via Vite dev server as `/api`).

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/api/health` | Service health check on mount |
| `GET` | `/api/v1/metrics/{controlId}` | Per-control metrics polling |
| `GET (SSE)` | `/v1/events/stream` | Real-time governance event stream |
| `GET` | `/api/v1/telemetry/history` | Paginated telemetry history |

**Monitored controls** (hardcoded in dashboard):
`A.5.2`, `A.5.3`, `A.9.2`, `SC-4`

**Critical controls** (alert threshold 0.8):
`A.9.2`, `SC-4`

---

### Compliance Bridge → External

| Destination | Protocol | Purpose |
|---|---|---|
| Langfuse (compliance project) | Langfuse SDK | Ingest OSCAL findings, query traces |
| Langfuse (app project) | Langfuse SDK | Query application traces for metrics |
| Redis (db=0) | Redis Streams | Evidence stream sink |
| Redis (db=1) | Redis key-value | DEFER queue storage |
| GCS / S3 | HTTP | OSCAL artifact persistence, NDJSON flush |
| Cloud KMS | gRPC | Async evidence entry signing |
| vLLM | HTTP | LLM remediation advisory generation |

---

### Gateway → External

| Destination | Protocol | Purpose |
|---|---|---|
| vLLM Backend | HTTP | LLM inference forwarding |
| OPA | HTTP | Rego policy evaluation |
| Redis | Redis | Token quota atomic counters (Lua scripts) |
| Cloud KMS | gRPC | Routing seal signing and verification |
| NeMo gRPC Sidecar | gRPC | Input/output rail verification |

---

## 9. Authentication and Security Model

### `X-CAGE-Routing-Seal` (Gateway)

HMAC-SHA256 computed over the raw request body bytes. Verified by
[`_verify_routing_seal()`](src/gateway/server/governance_middleware.py:139)
and enforced by
[`enforce_routing_seal()`](src/gateway/server/governance_middleware.py:178).

Required on:
- `POST /governance/check`
- `POST /tools/execute` (MCP tool server)

The seal is also returned in `POST /governance/validate-action` responses and
must be verified by callers before actuating any trade.

---

### `Authorization: Bearer <token>` (Compliance Bridge)

Validated by [`require_internal_token`](src/compliance_bridge/auth.py:40) using
`hmac.compare_digest` (constant-time). Token sourced from
`COMPLIANCE_BRIDGE_INTERNAL_TOKEN` env var.

**Dev bypass:** When `CAGE_ENV=dev` and no token is configured, the check is
skipped.

Required on:
- `POST /v1/audit/ingest`

---

### `X-API-Key` (Governed Financial Advisor)

Validated by [`infrastructure/auth.py`](src/governed_financial_advisor/infrastructure/auth.py).

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

---

## 10. Compliance Control Registry

Defined in [`types.py`](src/compliance_bridge/types.py:154).

### Universal Controls (all regions)

| Control ID | Name | Score field | Critical |
|---|---|---|---|
| `A.5.2` | AI Risk Assessment | `safety_rate` | No |
| `A.5.3` | AI Transparency | `safety_rate` | No |
| `A.6.2` | AI Roles and Responsibilities | `safety_rate` | No |
| `A.8.4` | AI System Logging | `safety_rate` | Yes |
| `A.9.2` | AI Incident Response | `safety_rate` | Yes |
| `SC-4` | Information in Shared Resources | `safety_rate` | Yes |

**Critical controls:** `A.9.2`, `SC-4`, `A.8.4`

---

### Jurisdictional Controls

**US_FED only:**

| Control ID | Name |
|---|---|
| `SA-11` | Developer Testing and Evaluation |
| `SC-7` | Boundary Protection |
| `SC-8` | Transmission Confidentiality and Integrity |
| `AC-2` | Account Management |
| `IR-1` | Incident Response Policy |

**EU_ECB only:**

| Control ID | Name |
|---|---|
| `Article 12` | ECB AI Transparency Article 12 |
| `Article 13` | ECB AI Accountability Article 13 |

**APAC_MAS only:**

| Control ID | Name |
|---|---|
| `MAS-FEAT-1` | MAS FEAT Fairness Principle 1 |

---

### Governance Event → Control Mapping

[`get_iso_control_map()`](src/compliance_bridge/types.py:483) maps governance
event names to control IDs:

| Event name | Control ID |
|---|---|
| `governance_violation` | `A.9.2` |
| `safety_check` | `A.9.2` |
| `confabulation_detected` | `SC-4` |
| `audit_finding` | `A.8.4` |
| `transparency_event` | `A.5.3` |
| `risk_assessment` | `A.5.2` |

---

### SLA Thresholds

[`get_sla_seconds()`](src/compliance_bridge/types.py:412) returns per-control
evidence freshness SLAs. Universal defaults:

| Control ID | Max evidence age |
|---|---|
| `A.9.2` | 300 seconds |
| `SC-4` | 300 seconds |
| `A.8.4` | 600 seconds |
| `A.5.2` | 3600 seconds |
| `A.5.3` | 3600 seconds |
| `A.6.2` | 3600 seconds |

Jurisdictional overrides apply per region.

---

### `TokenQuotaProxy` — ISO 42001 Annex A.4

[`TokenQuotaProxy`](src/gateway/governance/token_quota_proxy.py:194) enforces
per-session token and step-count quotas using atomic Redis Lua scripts.

**Key methods:**

| Method | Description |
|---|---|
| [`check_and_increment()`](src/gateway/governance/token_quota_proxy.py:296) | Atomically check quota and increment counters |
| [`reconcile_actual_tokens()`](src/gateway/governance/token_quota_proxy.py:392) | Correct over-allocation after vLLM responds |
| [`rollback_step()`](src/gateway/governance/token_quota_proxy.py:433) | Decrement counters after downstream failure |
| [`reset_session()`](src/gateway/governance/token_quota_proxy.py:470) | Delete all Redis keys for a session (admin/test) |
| [`get_session_state()`](src/gateway/governance/token_quota_proxy.py:490) | Return current session counters |

**`QuotaExceededError`** ([`token_quota_proxy.py:133`](src/gateway/governance/token_quota_proxy.py:133)):
Raised when a session exceeds its token or step-count quota. Carries
`step_count`, `accumulated_tokens`, and `reason` fields surfaced in the HTTP
429 response.
