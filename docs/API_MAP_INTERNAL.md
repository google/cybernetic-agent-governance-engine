# CAGE Internal API Reference

> **Generated:** 2026-07-05 · **Scope:** Inter-service, governance middleware,
> and infrastructure APIs not exposed to external consumers.

This document covers inter-service, governance middleware, and infrastructure
APIs not exposed to external consumers — including the governance validation
pipeline, MCP tool dispatch, NeMo gRPC sidecar, DEFER queue management,
cross-service call patterns, and the compliance control registry.

> For external consumer-facing APIs, see [API_MAP_EXTERNAL.md](API_MAP_EXTERNAL.md).

---

## Internal Endpoint Summary

| Service | Method | Path | Description |
|---|---|---|---|
| Gateway Governance | `POST` | `/governance/check` | Internal dry-run governance check |
| Gateway Governance | `GET` | `/governance/policy-version` | Active OPA policy hash |
| Gateway Governance | `POST` | `/governance/validate-action` | Unified 7-tier governance validation |
| Gateway MCP | `POST` | `/tools/execute` | HTTP MCP tool dispatch (internal agents) |
| Gateway MCP | `GET` | `/mcp` | FastMCP SSE transport |
| Compliance Bridge | `GET` | `/v1/audit/status/{audit_id}` | Poll async audit workflow status |
| Compliance Bridge | `POST` | `/v1/audit/ingest` | Ingest OSCAL audit result (Bearer token) |
| Compliance Bridge | `GET` | `/v1/defer/pending` | List DEFER queue entries |
| Compliance Bridge | `POST` | `/v1/defer/{defer_id}/inject` | Resolve DEFER token via data injection |
| Compliance Bridge | `POST` | `/v1/defer/{defer_id}/escalate` | Escalate DEFER token to HITL |
| Compliance Bridge | `GET` | `/v1/prompts/{name}` | Langfuse prompt proxy |
| gRPC NeMo | `rpc` | `Verify` | NeMo Guardrails input/output verification |

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

## 2. Gateway Server — Governance Sub-App

### [`governance_middleware.py`](src/gateway/server/governance_middleware.py)

Mounted at `/governance`. All endpoints are internal — called by the Governed
Financial Advisor and other internal services only.

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

## 4. Compliance Bridge — Internal Endpoints

Defined in [`main.py`](src/compliance_bridge/main.py).

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

## 5. MCP Tools — FastMCP over SSE

Registered via `@mcp.tool()` in
[`mcp_tool_server.py`](src/gateway/server/mcp_tool_server.py). Accessible via
the FastMCP SSE transport at `GET /mcp` or via HTTP at `POST /tools/execute`.
Called by internal agents only.

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

## 6. gRPC NeMo Guardrails — [`nemo.proto`](src/gateway/protos/nemo.proto)

**Package:** `governance` · **Service:** `NeMoGuardrails`

Implemented by [`NeMoService`](src/gateway/governance/nemo/server.py:131).
Runs on port from `PORT` env var (default `8000`). Note: LangGraph nodes use
the in-process manager, not this sidecar.

### `rpc Verify(VerifyRequest) returns (VerifyResponse)`

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

## 7. Key Internal Schemas and Types

### 7.1 [`GovernanceThresholds`](src/gateway/governance/schemas/thresholds.py:116)

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

### 7.2 [`ValidateActionRequest`](src/gateway/server/governance_middleware.py:343)

| Field | Type | Description |
|---|---|---|
| `action` | `str` | Action/tool name |
| `params` | `dict` | Action parameters |
| `policy_version_id` | `str` (optional) | Expected policy hash |

---

### 7.3 [`EvidenceStreamSink`](src/compliance_bridge/evidence_stream.py:140)

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

## 9. Compliance Control Registry

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

## 3. Gateway MCP Tool Server — Internal Endpoints

### [`mcp_tool_server.py`](src/gateway/server/mcp_tool_server.py)

Mounted at `/` (catch-all). The following endpoints are called by internal
agents only.

**Rate limit:** 60 requests / 60 seconds per client IP, enforced by
[`_check_rate_limit()`](src/gateway/server/mcp_tool_server.py:82).

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
registered tools (see [Section 5](#5-mcp-tools--fastmcp-over-sse)).

---
