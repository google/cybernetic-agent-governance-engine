# CAGE × Google Agent Gateway — Service Extension Integration Research

**Status:** Research / Pre-implementation
**Author:** CAGE Engineering Team
**Date:** 2026-07-15
**Change category:** Cat-M (Major) — new external API integration; AO pre-approval required before
implementation per `docs/governance/CHANGE_MANAGEMENT_PROCESS.md`

---

## 1. What This Document Covers

Gap 6 in [`docs/architecture/SUBSTRATE_MOAT_STRATEGY.md`](SUBSTRATE_MOAT_STRATEGY.md) identifies
that CAGE has no integration with Google Agent Gateway's (AGW) **Service Extensions** mechanism.
This document:

1. Explains what Service Extensions are and how they work at the protocol level
2. Maps the AGW protocol to CAGE's existing governance surface
3. Identifies exactly what needs to be built (`src/gateway/server/agw_service_extension.py`)
4. Identifies what infrastructure changes are needed (`infra/agw/`)
5. Flags compliance obligations that apply to this work

---

## 2. Google Agent Gateway — Service Extensions Protocol

### 2.1 What Service Extensions Are

Google Agent Gateway is a fully managed GCP service that sits in front of MCP servers and
enforces network-layer controls (mTLS, IAP, SPIFFE identity, Model Armor prompt injection
filtering). It is **not** a semantic governance layer — it has no knowledge of CAGE's 7-tier
pipeline, CBF invariants, OPA policies, or causal gatekeeper.

**Service Extensions** is AGW's mechanism for delegating authorization decisions to a custom
external endpoint. Before AGW allows an MCP tool call to egress to the backend MCP server, it
calls the operator-registered Service Extension endpoint and waits for an allow/deny decision.
This is the integration point where CAGE becomes the semantic governance layer that AGW calls.

### 2.2 Protocol: Envoy `ext_authz` gRPC

AGW Service Extensions implement the **Envoy external authorization protocol**:

```
package envoy.service.auth.v3;

service Authorization {
  rpc Check(CheckRequest) returns (CheckResponse) {}
}
```

This is the same protocol used by Envoy's `ext_authz` HTTP filter and is documented at:
- https://www.envoyproxy.io/docs/envoy/latest/api-v3/service/auth/v3/attribute_context.proto
- https://cloud.google.com/service-extensions/docs/overview

**`CheckRequest` structure (relevant fields):**

```protobuf
message CheckRequest {
  AttributeContext attributes = 1;
}

message AttributeContext {
  message HttpRequest {
    string id      = 1;
    string method  = 2;
    map<string, string> headers = 3;
    string path    = 4;
    string host    = 5;
    string body    = 10;  // ← MCP tool call JSON body is here
  }
  HttpRequest request = 6;
}
```

**`CheckResponse` structure:**

```protobuf
message CheckResponse {
  google.rpc.Status status = 1;
  oneof http_response {
    OkHttpResponse     ok_response      = 2;  // allow — can inject headers
    DeniedHttpResponse denied_response  = 3;  // deny — returns HTTP 403
  }
}

message OkHttpResponse {
  repeated HeaderValueOption headers = 2;  // headers to inject into the forwarded request
}

message DeniedHttpResponse {
  google.rpc.HttpStatus status  = 1;
  repeated HeaderValueOption headers = 2;
  string body = 3;
}
```

### 2.3 What AGW Sends in the Request Body

When an MCP client calls a tool through AGW, the tool call is encoded as a JSON-RPC 2.0
request in the HTTP body:

```json
{
  "jsonrpc": "2.0",
  "id": "call-abc123",
  "method": "tools/call",
  "params": {
    "name": "execute_trade_action",
    "arguments": {
      "symbol": "AAPL",
      "amount": 15000.0,
      "currency": "USD",
      "confidence": 0.97,
      "trader_role": "senior"
    }
  }
}
```

The Service Extension adapter must parse this body to extract `params.name` (tool name) and
`params.arguments` (tool params) before calling CAGE's governance pipeline.

---

## 3. CAGE's Existing Governance Surface

### 3.1 What Already Exists

CAGE already has the complete governance pipeline exposed via two surfaces:

| Surface | Location | Protocol | What it does |
|---|---|---|---|
| `POST /governance/validate-action` | [`src/gateway/server/governance_middleware.py:516`](../../src/gateway/server/governance_middleware.py) | HTTP/JSON | Full 7-tier pipeline → `{verdict, violations, seal, latency_ms}` |
| `rpc ExecuteTool` | [`src/gateway/protos/gateway.proto:31`](../../src/gateway/protos/gateway.proto) | gRPC (port 50051) | CAGE's own tool execution protocol — NOT ext_authz |
| `POST /governance/check` | [`src/gateway/server/governance_middleware.py:308`](../../src/gateway/server/governance_middleware.py) | HTTP/JSON | Dry-run governance check |

The key method is [`SymbolicGovernor.validate_action()`](../../src/gateway/governance/symbolic_governor.py:837):

```python
async def validate_action(
    self,
    action: str,
    params: dict[str, Any],
    policy_version_id: str | None = None,
) -> dict[str, Any]:
    # Returns: {"verdict": "APPROVED"|"DENIED", "violations": [...], "seal": "...", "latency_ms": ...}
```

This is the **single choke point** for all tool execution governance. The Service Extension
adapter needs to call this method (or the HTTP endpoint that wraps it) and translate the
result into an `ext_authz` `CheckResponse`.

### 3.2 What Is Missing

CAGE does **not** have:

1. A gRPC service implementing `envoy.service.auth.v3.Authorization.Check`
2. A proto definition for the Envoy auth v3 types (or a dependency on `envoy-api`)
3. A JSON-RPC 2.0 body parser that extracts MCP tool name and arguments from the AGW request
4. Infrastructure (Terraform) to register the Service Extension with AGW and configure the
   callout to CAGE's endpoint

---

## 4. What Needs to Be Built

### 4.1 New File: `src/gateway/server/agw_service_extension.py`

A new gRPC servicer implementing `envoy.service.auth.v3.Authorization`:

```
AGW (ext_authz callout)
    │
    │  gRPC CheckRequest
    ▼
agw_service_extension.py
    │  parse JSON-RPC body → (tool_name, params)
    │
    │  call validate_action(tool_name, params)
    ▼
symbolic_governor.validate_action()   ← existing, unchanged
    │
    │  {"verdict": "APPROVED", "seal": "hmac-sha256-..."}
    ▼
agw_service_extension.py
    │  build CheckResponse
    │  on APPROVED: OkHttpResponse + inject X-CAGE-Routing-Seal header
    │  on DENIED:   DeniedHttpResponse(403) + violation detail
    ▼
AGW (forwards or blocks the MCP tool call)
```

**Key design decisions:**

- **Async gRPC server:** Use `grpcio-aio` (`grpc.aio`) — consistent with the existing async
  FastAPI/asyncio architecture. The servicer's `Check` method is `async def`.
- **Shared event loop:** The gRPC server and the FastAPI server share the same asyncio event
  loop so `validate_action()` can be awaited directly without thread-pool overhead.
- **Proto dependency:** Two options:
  - Option A: Vendor the relevant Envoy auth v3 proto files into `src/gateway/protos/` and
    compile them with `grpc_tools.protoc`. This avoids a runtime dependency on `envoy-api`.
  - Option B: Use the `envoy-api` PyPI package if it provides pre-compiled Python stubs.
    As of 2026-07, `envoy-api` does not publish stable Python stubs; Option A is preferred.
- **Body size limit:** AGW may truncate large request bodies in the `CheckRequest`. The adapter
  must handle truncated bodies gracefully (fail-closed: deny if body cannot be parsed).
- **Timeout:** AGW Service Extensions have a configurable callout timeout (default 10s). CAGE's
  7-tier pipeline median latency is well under 200ms on the hot path; the timeout is not a
  concern for the async path. The DEFER path (HITL escalation) must return a provisional
  `DeniedHttpResponse` immediately and handle the DEFER state machine separately.

**Routing seal injection:**

On approval, the adapter injects the HMAC-SHA256 routing seal as a request header that AGW
forwards to the backend MCP server:

```
X-CAGE-Routing-Seal: <hmac-sha256-hex>
```

The backend MCP server (CAGE's [`mcp_tool_server.py`](../../src/gateway/server/mcp_tool_server.py))
already calls [`enforce_routing_seal()`](../../src/gateway/server/governance_middleware.py:181)
on every tool call — so the seal verification is already implemented. The Service Extension
adapter simply needs to inject the seal header so the MCP server receives it.

**Skeleton (illustrative — not production code):**

```python
# src/gateway/server/agw_service_extension.py
# (requires: grpcio-aio, compiled envoy.service.auth.v3 proto stubs)

import json
import grpc
from envoy.service.auth.v3 import attribute_context_pb2  # vendored
from envoy.service.auth.v3 import authorization_pb2       # vendored
from envoy.service.auth.v3 import authorization_pb2_grpc  # vendored
from google.rpc import status_pb2, code_pb2

from src.gateway.governance.singletons import symbolic_governor
from src.gateway.governance.symbolic_governor import GovernanceError


class CAGEAuthorizationServicer(authorization_pb2_grpc.AuthorizationServicer):

    async def Check(
        self,
        request: authorization_pb2.CheckRequest,
        context: grpc.aio.ServicerContext,
    ) -> authorization_pb2.CheckResponse:
        body = request.attributes.request.http.body
        try:
            rpc = json.loads(body)
            tool_name = rpc["params"]["name"]
            params = rpc["params"].get("arguments", {})
        except (json.JSONDecodeError, KeyError):
            # Fail-closed: cannot parse body → deny
            return _denied(403, "CAGE: unparseable MCP tool call body")

        try:
            result = await symbolic_governor.validate_action(
                action=tool_name, params=params
            )
        except GovernanceError as exc:
            return _denied(403, f"CAGE governance block: {exc}")

        if result["verdict"] != "APPROVED":
            violations = "; ".join(result.get("violations", []))
            return _denied(403, f"CAGE governance denied: {violations}")

        # Inject routing seal so the backend MCP server can verify it
        seal = result.get("seal", "")
        return _ok(headers={"x-cage-routing-seal": seal})


def _ok(headers: dict[str, str]) -> authorization_pb2.CheckResponse:
    from envoy.service.auth.v3.authorization_pb2 import OkHttpResponse
    from envoy.config.core.v3.base_pb2 import HeaderValueOption, HeaderValue
    ok = OkHttpResponse(headers=[
        HeaderValueOption(header=HeaderValue(key=k, value=v))
        for k, v in headers.items()
    ])
    return authorization_pb2.CheckResponse(
        status=status_pb2.Status(code=code_pb2.OK),
        ok_response=ok,
    )


def _denied(http_status: int, body: str) -> authorization_pb2.CheckResponse:
    from envoy.service.auth.v3.authorization_pb2 import DeniedHttpResponse
    from envoy.type.v3.http_status_pb2 import HttpStatus, StatusCode
    denied = DeniedHttpResponse(
        status=HttpStatus(code=StatusCode.Value("FORBIDDEN")),
        body=body,
    )
    return authorization_pb2.CheckResponse(
        status=status_pb2.Status(code=code_pb2.PERMISSION_DENIED),
        denied_response=denied,
    )
```

### 4.2 Proto Changes: `src/gateway/protos/`

Add vendored Envoy auth v3 proto files (or a `buf` dependency):

```
src/gateway/protos/
├── gateway.proto          ← existing
├── nemo.proto             ← existing
└── envoy/                 ← new (vendored from envoy-api)
    ├── service/auth/v3/
    │   ├── attribute_context.proto
    │   └── authorization.proto
    ├── config/core/v3/
    │   └── base.proto
    └── type/v3/
        └── http_status.proto
```

Alternatively, use `buf` with a `buf.yaml` dependency on `buf.build/envoyproxy/envoy`.

### 4.3 New Infrastructure: `infra/agw/`

A new Terraform module (GCP-specific, optional for non-GCP operators) that:

1. Creates a **Service Extension** resource pointing to CAGE's gRPC endpoint
2. Configures AGW to call the extension on every MCP tool call egress
3. Sets the callout timeout (recommended: 5s — well above CAGE's p99 latency)
4. Configures mTLS between AGW and CAGE's Service Extension endpoint

```hcl
# infra/agw/main.tf (illustrative)
resource "google_network_services_lb_traffic_extension" "cage_authz" {
  name     = "cage-semantic-authz"
  project  = var.project_id
  location = var.region

  load_balancing_scheme = "INTERNAL_MANAGED"

  extension_chains {
    name = "cage-governance-chain"
    match_condition {
      cel_expression = "request.path.startsWith('/mcp')"
    }
    extensions {
      name      = "cage-authz-ext"
      authority = var.cage_gateway_endpoint
      service   = var.cage_gateway_grpc_service_url
      timeout   = "5s"
      fail_open = false  # fail-closed: deny if CAGE is unreachable
    }
  }
}
```

> **Note:** `google_network_services_lb_traffic_extension` is the Terraform resource for
> GCP Service Extensions (Traffic Extensions). The exact resource type for AGW-specific
> callouts may differ — verify against the GCP provider documentation at implementation time.
> AGW may use `google_network_services_authz_extension` for authorization callouts specifically.

### 4.4 New Document: `docs/architecture/CAGE_AGW_REFERENCE_ARCH.md`

A joint reference architecture document describing the CAGE + AGW defense-in-depth stack:

```
Internet
    │
    ▼
Google Cloud Armor (DDoS, WAF)
    │
    ▼
Google Agent Gateway (AGW)
    ├── mTLS + SPIFFE identity verification
    ├── IAP authentication
    ├── Model Armor (network-tier prompt injection)
    └── Service Extension callout → CAGE (semantic governance)
              │
              │  ext_authz gRPC CheckRequest
              ▼
         CAGE Gateway (agw_service_extension.py)
              │
              │  validate_action() → 7-tier pipeline
              ▼
         SymbolicGovernor
              ├── STPA hazard validation
              ├── Confidence threshold
              ├── CBF (Redis atomic) + OPA (concurrent)
              ├── Fiscal Limit Pre-Reservation
              ├── Multi-agent Consensus
              ├── DoWhy Causal Gatekeeper
              └── Adaptive FRIA Gate
              │
              │  APPROVED + X-CAGE-Routing-Seal header
              ▼
         AGW forwards to backend MCP server
              │
              ▼
         CAGE MCP Tool Server (enforce_routing_seal → execute)
```

This stack provides **two independent governance layers**:
- AGW: network-tier identity, transport security, coarse prompt injection
- CAGE: semantic governance, mathematical safety invariants, multi-jurisdiction compliance

---

## 5. Integration Points with Existing Code

### 5.1 No Changes Required to Core Governance

[`SymbolicGovernor.validate_action()`](../../src/gateway/governance/symbolic_governor.py:837)
is called unchanged. The Service Extension adapter is a **thin translation layer** — it
converts the AGW `ext_authz` wire format into the `(action, params)` tuple that
`validate_action()` already accepts.

### 5.2 Routing Seal — Already Implemented

[`enforce_routing_seal()`](../../src/gateway/server/governance_middleware.py:181) in
`governance_middleware.py` already verifies the `X-CAGE-Routing-Seal` header on every
`/tools/execute` call. The Service Extension adapter injects this header on approval;
the MCP tool server verifies it. No changes needed to either file.

### 5.3 `hybrid_server.py` — Minimal Change

[`hybrid_server.py`](../../src/gateway/server/hybrid_server.py) needs to start the
`agw_service_extension.py` gRPC server alongside the existing FastAPI server. The gRPC
server reuses **port 50051**, which is already exposed in the Kubernetes Service and
whitelisted in all NetworkPolicies (see [`infra/modules/gateway/main.tf`](../../infra/modules/gateway/main.tf)).
CAGE currently runs strictly on HTTP/SSE (port 8080) with no active gRPC listener on
port 50051, so no NetworkPolicy or Kubernetes Service changes are required.

`serve_agw_extension()` must return the running `grpc.aio.Server` instance so that
`_gateway_lifespan()` can shut it down gracefully during FastAPI shutdown, preventing
socket leaks and ensuring connection draining:

```python
# Addition to hybrid_server.py _gateway_lifespan():
from src.gateway.server.agw_service_extension import serve_agw_extension
# Startup:
grpc_server = await serve_agw_extension(port=int(os.getenv("AGW_EXT_GRPC_PORT", "50051")))
yield
# Shutdown:
await grpc_server.stop(grace=5.0)
```

No new port block is needed in the Terraform module — port 50051 is already declared:

```hcl
# Already present in infra/modules/gateway/main.tf — no change required
port {
  container_port = 50051
  name           = "grpc"
}
```

### 5.4 DEFER State Machine — Special Handling

When `validate_action()` returns `verdict: "MANUAL_REVIEW"` (HITL escalation), the Service
Extension adapter cannot hold the AGW callout open indefinitely (AGW timeout is 5s). The
correct behaviour is:

1. Return `DeniedHttpResponse(403)` with body `{"verdict": "DEFERRED", "thread_id": "..."}` immediately
2. The MCP client receives a 403 and must poll `GET /v1/approvals/pending` for the HITL decision
3. On human approval, the client retries the tool call — the second call will pass governance
   (the DEFER state machine in Redis `db=1` tracks the approved thread)

This is consistent with the existing HITL flow in
[`src/governed_financial_advisor/server.py`](../../src/governed_financial_advisor/server.py).

---

## 6. Compliance Obligations

### 6.1 Change Management

This integration constitutes a **Cat-M (Major)** change under
`docs/governance/CHANGE_MANAGEMENT_PROCESS.md`:

- **New external API integration** (AGW Service Extensions callout protocol)
- **New GCP service** (google_network_services_lb_traffic_extension or equivalent)
- **New network exposure** (port 50051 reused for AGW callout infrastructure — already whitelisted in all NetworkPolicies)

**AO pre-approval is required before any implementation work begins.**

### 6.2 NIST SP 800-53 Controls Affected

| Control | Impact |
|---|---|
| **SC-8** (Transmission Confidentiality) | mTLS required between AGW and CAGE's ext_authz endpoint |
| **SC-12** (Cryptographic Key Establishment) | New mTLS certificate lifecycle; must use Cloud KMS or GKE Workload Identity |
| **AC-3** (Access Enforcement) | The ext_authz endpoint must itself be protected — only AGW's service account should be able to call it |
| **AU-2** (Audit Events) | Every `CheckRequest` / `CheckResponse` must be logged with the existing OTel/Langfuse pipeline |
| **SI-10** (Information Input Validation) | The JSON-RPC body parser must validate structure before passing to `validate_action()` |

### 6.3 OSCAL Update Required

An OSCAL component update in `compliance/oscal/` is required within 2 business days of PR
merge, per the compliance artifact obligations in `.roo/rules-code/01-code-standards.md`.

### 6.4 Lula Validation

Port 50051 is already exposed in the Kubernetes Service and Terraform module. No new port
is introduced. However, if any Lula validation file references port 50051 in a way that
must be updated to reflect the new ext_authz service running on it, a Lula validation
update in `compliance/lula/` must be included in the same PR or flagged for a follow-on PR.

### 6.5 Multi-Region Guard

The `agw_service_extension.py` module will be deployed to all three regions
(`US_FED`, `EU_ECB`, `APAC_MAS`). Any new storage path, GCS write, or telemetry export
in this module **must** be gated on `CAGE_DEPLOYMENT_REGION` per the shared-module region
guard obligations in `.roo/rules/00-global-standards.md`.

---

## 7. Implementation Checklist

> This checklist is for the implementation PR. It does not constitute AO approval.

- [ ] AO pre-approval obtained (Cat-M change)
- [ ] Envoy auth v3 proto files vendored into `src/gateway/protos/envoy/` (or `buf.yaml` dependency added)
- [ ] `src/gateway/server/agw_service_extension.py` implemented with:
  - [ ] `CAGEAuthorizationServicer.Check()` async gRPC handler
  - [ ] JSON-RPC 2.0 body parser (fail-closed on parse error)
  - [ ] `validate_action()` delegation
  - [ ] `OkHttpResponse` with `X-CAGE-Routing-Seal` header injection on approval
  - [ ] `DeniedHttpResponse(403)` with violation detail on denial
  - [ ] `DeniedHttpResponse(403)` with `verdict: DEFERRED` on MANUAL_REVIEW
  - [ ] Apache 2.0 license header
  - [ ] `CAGE_DEPLOYMENT_REGION` guard on any telemetry exports
- [ ] `hybrid_server.py` updated: `grpc_server = await serve_agw_extension(port=50051)`; `await grpc_server.stop(grace=5.0)` in shutdown block
- [ ] `infra/modules/gateway/main.tf` — **no change required** (port 50051 already declared)
- [ ] `infra/agw/` Terraform module created (GCP-specific, optional)
- [ ] `docs/architecture/CAGE_AGW_REFERENCE_ARCH.md` written
- [ ] Unit tests in `tests/` covering: parse error → deny, governance deny → DeniedHttpResponse, governance approve → OkHttpResponse + seal header
- [ ] OSCAL component update in `compliance/oscal/` (within 2 business days of merge)
- [ ] Lula validation update in `compliance/lula/` if any existing validation referencing port 50051 requires amendment

---

## 8. Open Questions

| # | Question | Owner | Priority |
|---|---|---|---|
| 1 | Does AGW use `google_network_services_authz_extension` or `google_network_services_lb_traffic_extension` for MCP-specific callouts? Verify against GCP provider docs at implementation time. | Infra | HIGH |
| 2 | Does AGW truncate the JSON-RPC body in `CheckRequest.attributes.request.http.body`? If so, what is the size limit? | Platform | HIGH |
| 3 | What mTLS certificate authority does AGW use for callout authentication? GKE Workload Identity Federation or a separate CA? | Security | HIGH |
| 4 | ~~Should the ext_authz gRPC server share port 50051 with the existing `gateway.Gateway` service or use a dedicated port 50052?~~ **RESOLVED:** Reuse port 50051. `hybrid_server.py` starts no gRPC listener on 50051 today (HTTP/SSE only on 8080); port 50051 is already whitelisted in all NetworkPolicies and the Kubernetes Service. No new port or NetworkPolicy change required. | Architecture | **RESOLVED** |
| 5 | Does the DEFER state machine need to be extended to track AGW-originated HITL escalations separately from GFA-originated ones? | Governance | MEDIUM |

---

## 9. References

- [Google Cloud Service Extensions overview](https://cloud.google.com/service-extensions/docs/overview)
- [Envoy `ext_authz` filter documentation](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_authz_filter)
- [Envoy auth v3 proto — `authorization.proto`](https://github.com/envoyproxy/envoy/blob/main/api/envoy/service/auth/v3/authorization.proto)
- [Envoy auth v3 proto — `attribute_context.proto`](https://github.com/envoyproxy/envoy/blob/main/api/envoy/service/auth/v3/attribute_context.proto)
- [`docs/architecture/SUBSTRATE_MOAT_STRATEGY.md` — Gap 6](SUBSTRATE_MOAT_STRATEGY.md) (§9.6)
- [`src/gateway/server/governance_middleware.py`](../../src/gateway/server/governance_middleware.py) — existing `validate_action` HTTP endpoint
- [`src/gateway/governance/symbolic_governor.py`](../../src/gateway/governance/symbolic_governor.py) — `validate_action()` method (line 837)
- [`src/gateway/server/hybrid_server.py`](../../src/gateway/server/hybrid_server.py) — composition root
- [`infra/modules/gateway/main.tf`](../../infra/modules/gateway/main.tf) — existing gateway Terraform module
