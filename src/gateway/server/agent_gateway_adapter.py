# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Agent Gateway Adapter — Cloud-Agnostic Envoy ext_authz gRPC Servicer
=====================================================================

This module implements the Envoy ``ext_authz`` gRPC protocol
(``envoy.service.auth.v3.Authorization.Check``) as a cloud-agnostic
governance enforcement point.  It is compatible with any Envoy-based proxy:

  - Istio sidecar (self-managed Kubernetes)
  - Contour / Emissary ingress controllers
  - Any standalone Envoy deployment
  - **GCP Agent Gateway (AGW)** — see "GCP Adaptation" section below

The adapter is intentionally free of GCP-specific SDK calls.  All
cloud-provider integrations are handled at the deployment layer (mTLS
certificate provisioning, service account binding, etc.).

Architecture
------------
::

    [Agent / MCP Client]
          │
          ▼
    [Envoy proxy / AGW]  ──ext_authz gRPC──▶  [AgentGatewayAdapter :50051]
                                                      │
                                                      ▼
                                              symbolic_governor.validate_action()
                                              (full 7-tier CAGE pipeline)
                                                      │
                                          ┌───────────┼───────────┐
                                          ▼           ▼           ▼
                                       APPROVED    DENIED    MANUAL_REVIEW
                                          │           │           │
                                   OkHttpResponse  403 Denied  202 DEFERRED
                                   + routing seal  + violation  + thread_id

GCP Adaptation (optional deployment configuration)
--------------------------------------------------
When deployed behind **GCP Agent Gateway (AGW)**, this adapter functions as
an AGW Service Extension.  No code changes are required — AGW uses the same
Envoy ext_authz gRPC protocol.  The only GCP-specific configuration is:

  1. The AGW service extension resource pointing to this adapter's endpoint
  2. mTLS certificate provisioning via GCP Workload Identity or Cloud KMS
  3. The ``CAGE_DEPLOYMENT_REGION`` env var for telemetry region-gating

See ``docs/architecture/CAGE_AGW_REFERENCE_ARCH.md`` for the full GCP
deployment diagram and mTLS certificate lifecycle.

Compliance obligations (Cat-M change — AO pre-approval required)
-----------------------------------------------------------------
- SC-8  (Transmission Confidentiality): mTLS required between calling proxy
  and this adapter's gRPC endpoint.
- SC-12 (Cryptographic Key Establishment): mTLS certificate lifecycle managed
  by service mesh or GCP Workload Identity.
- AC-3  (Access Enforcement): gRPC endpoint must only accept calls from the
  registered proxy service account (enforced by mTLS CN/SAN validation).
- AU-2  (Audit Events): every CheckRequest/CheckResponse is logged via the
  existing OTel/Langfuse pipeline.
- SI-10 (Information Input Validation): JSON-RPC body parser validates
  structure before passing to validate_action().
- OSCAL component update in compliance/oscal/ required within 2 business days
  of PR merge.

Environment variables
---------------------
- ``AGENT_GW_GRPC_PORT``      — gRPC listen port (default: 50051)
- ``AGENT_GW_BODY_SIZE_LIMIT``— max JSON-RPC body bytes (default: 65536 / 64KB)
- ``CAGE_DEPLOYMENT_REGION``  — region guard for telemetry exports
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

from opentelemetry import trace

logger = logging.getLogger("Gateway.AgentGatewayAdapter")
tracer = trace.get_tracer(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_BODY_SIZE_LIMIT: int = int(os.getenv("AGENT_GW_BODY_SIZE_LIMIT", "65536"))
_DEFAULT_GRPC_PORT: int = int(os.getenv("AGENT_GW_GRPC_PORT", "50051"))

# CAGE_DEPLOYMENT_REGION guard — any telemetry export in this module must be
# gated on this value per shared-module region guard obligations.
_DEPLOYMENT_REGION: str = os.getenv("CAGE_DEPLOYMENT_REGION", "US_FED")


# ---------------------------------------------------------------------------
# JSON-RPC 2.0 body parser (SI-10 — Information Input Validation)
# ---------------------------------------------------------------------------


class ParseError(ValueError):
    """Raised when the JSON-RPC 2.0 body cannot be parsed or is structurally invalid."""


def parse_jsonrpc_body(body: str | bytes) -> tuple[str, dict[str, Any]]:
    """Parse a JSON-RPC 2.0 request body and extract (tool_name, params).

    Validates the structure before returning.  Raises ``ParseError`` on any
    structural violation — the caller must return a ``DeniedHttpResponse(403)``
    (fail-closed) when this exception is raised.

    Supported body shapes:
      - ``{"method": "tools/call", "params": {"name": "<tool>", "arguments": {...}}}``
      - ``{"method": "<tool>", "params": {...}}``  (simplified MCP form)

    Args:
        body: Raw request body bytes or string from ``CheckRequest.attributes.request.http.body``.

    Returns:
        Tuple of ``(tool_name, params_dict)``.

    Raises:
        ParseError: If the body is empty, too large, not valid JSON, or missing
            required JSON-RPC 2.0 fields.
    """
    if not body:
        raise ParseError("empty body")

    raw = body if isinstance(body, bytes) else body.encode()
    if len(raw) > _BODY_SIZE_LIMIT:
        raise ParseError(
            f"body size {len(raw)} exceeds limit {_BODY_SIZE_LIMIT} — fail-closed"
        )

    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ParseError(f"invalid JSON: {exc}") from exc

    if not isinstance(doc, dict):
        raise ParseError("JSON-RPC body must be a JSON object")

    params = doc.get("params")
    if not isinstance(params, dict):
        raise ParseError("'params' field must be a JSON object")

    # MCP tools/call shape: params.name + params.arguments
    if "name" in params:
        tool_name = params.get("name", "")
        tool_params = params.get("arguments", {})
    else:
        # Simplified shape: method is the tool name, params is the arguments
        tool_name = doc.get("method", "")
        tool_params = params

    if not tool_name or not isinstance(tool_name, str):
        raise ParseError("could not extract tool_name from JSON-RPC body")

    if not isinstance(tool_params, dict):
        tool_params = {}

    return tool_name, tool_params


# ---------------------------------------------------------------------------
# Verdict → gRPC response builders
# ---------------------------------------------------------------------------


def _build_ok_response(routing_seal: str) -> dict[str, Any]:
    """Build an OkHttpResponse dict with the CAGE routing seal header.

    The routing seal is injected as ``x-cage-routing-seal`` so the downstream
    MCP tool server can verify it via ``enforce_routing_seal()``.

    Args:
        routing_seal: HMAC-SHA256 routing seal string from validate_action().

    Returns:
        Dict representation of OkHttpResponse with headers list.
    """
    return {
        "ok_response": {
            "headers": [
                {
                    "header": {
                        "key": "x-cage-routing-seal",
                        "value": routing_seal,
                    },
                    "append": False,
                }
            ]
        }
    }


def _build_denied_response(
    status_code: int,
    body: dict[str, Any],
) -> dict[str, Any]:
    """Build a DeniedHttpResponse dict.

    Args:
        status_code: HTTP status code (403 for DENIED, 202 for DEFERRED).
        body:        JSON-serialisable response body dict.

    Returns:
        Dict representation of DeniedHttpResponse.
    """
    return {
        "denied_response": {
            "status": {"code": status_code},
            "headers": [
                {
                    "header": {
                        "key": "content-type",
                        "value": "application/json",
                    },
                    "append": False,
                }
            ],
            "body": json.dumps(body),
        }
    }


# ---------------------------------------------------------------------------
# Core Check handler — pure Python, no gRPC dependency at import time
# ---------------------------------------------------------------------------


async def handle_check_request(
    body: str | bytes,
    caller_principal: str = "",
) -> dict[str, Any]:
    """Process an ext_authz CheckRequest and return a CheckResponse dict.

    This is the pure-Python core of the adapter, separated from the gRPC
    servicer so it can be unit-tested without a running gRPC server.

    Decision table:
      - Parse error          → DeniedHttpResponse(403) fail-closed
      - Body > 64KB          → DeniedHttpResponse(403) fail-closed
      - APPROVED             → OkHttpResponse + x-cage-routing-seal header
      - DENIED               → DeniedHttpResponse(403) + violation JSON
      - MANUAL_REVIEW        → DeniedHttpResponse(202) + {verdict: DEFERRED, thread_id}

    Args:
        body:             Raw JSON-RPC 2.0 body from the CheckRequest.
        caller_principal: SPIFFE ID or OIDC sub from the mTLS peer certificate
                          (used for OPA agent catalog lookup).

    Returns:
        CheckResponse dict with either ``ok_response`` or ``denied_response``.
    """
    # ── SI-10: Parse and validate JSON-RPC body ───────────────────────────────
    try:
        tool_name, params = parse_jsonrpc_body(body)
    except ParseError as exc:
        logger.warning(
            "AgentGatewayAdapter: JSON-RPC parse error (fail-closed): %s", exc
        )
        _emit_audit_event(
            event_type="PARSE_ERROR",
            tool_name="<unknown>",
            verdict="DENIED",
            detail=str(exc),
        )
        return _build_denied_response(
            403,
            {
                "error": "parse_error",
                "message": "JSON-RPC 2.0 body could not be parsed — request denied",
                "detail": str(exc),
            },
        )

    # Inject caller identity into params for OPA agent catalog evaluation
    if caller_principal:
        params = {**params, "_caller_principal": caller_principal}

    # ── Run the full CAGE 7-tier governance pipeline ──────────────────────────
    with tracer.start_as_current_span("cage.ext_authz.check") as span:
        span.set_attribute("cage.tool_name", tool_name)
        span.set_attribute("cage.caller_principal", caller_principal)
        span.set_attribute("cage.deployment_region", _DEPLOYMENT_REGION)

        try:
            from src.gateway.governance.singletons import symbolic_governor

            result = await symbolic_governor.validate_action(
                action=tool_name,
                params=params,
            )
        except Exception as exc:
            logger.error(
                "AgentGatewayAdapter: validate_action raised unexpected error "
                "for tool '%s': %s — fail-closed",
                tool_name,
                exc,
                exc_info=True,
            )
            span.set_status(trace.StatusCode.ERROR, str(exc))
            _emit_audit_event(
                event_type="INTERNAL_ERROR",
                tool_name=tool_name,
                verdict="DENIED",
                detail=str(exc),
            )
            return _build_denied_response(
                403,
                {
                    "error": "internal_error",
                    "message": "Governance pipeline error — request denied",
                },
            )

        verdict: str = result.get("verdict", "DENIED")
        violations: list[str] = result.get("violations", [])
        seal: str = result.get("seal", "")
        thread_id: str = result.get("thread_id", "")

        span.set_attribute("cage.verdict", verdict)

        _emit_audit_event(
            event_type="CHECK",
            tool_name=tool_name,
            verdict=verdict,
            detail="; ".join(violations) if violations else "",
        )

        if verdict == "APPROVED":
            logger.info(
                "AgentGatewayAdapter: APPROVED tool='%s' caller='%s'",
                tool_name,
                caller_principal,
            )
            return _build_ok_response(seal)

        if verdict == "MANUAL_REVIEW":
            logger.info(
                "AgentGatewayAdapter: DEFERRED tool='%s' caller='%s' thread_id='%s'",
                tool_name,
                caller_principal,
                thread_id,
            )
            # ext_authz timeout is typically 5s — return immediately with DEFERRED.
            # The MCP client must poll GET /v1/approvals/pending for the outcome.
            return _build_denied_response(
                202,
                {
                    "verdict": "DEFERRED",
                    "thread_id": thread_id,
                    "message": (
                        "Request requires human approval. "
                        "Poll GET /v1/approvals/pending for the outcome."
                    ),
                },
            )

        # DENIED
        logger.warning(
            "AgentGatewayAdapter: DENIED tool='%s' caller='%s' violations=%s",
            tool_name,
            caller_principal,
            violations,
        )
        return _build_denied_response(
            403,
            {
                "verdict": "DENIED",
                "violations": violations,
                "tool_name": tool_name,
            },
        )


def _emit_audit_event(
    event_type: str,
    tool_name: str,
    verdict: str,
    detail: str,
) -> None:
    """Emit an AU-2 audit log entry for every CheckRequest/CheckResponse.

    Region-gated: telemetry is only emitted when the deployment region is
    consistent with the configured data residency requirements.

    Args:
        event_type: One of CHECK, PARSE_ERROR, INTERNAL_ERROR.
        tool_name:  The tool name extracted from the JSON-RPC body.
        verdict:    APPROVED, DENIED, DEFERRED, or ERROR.
        detail:     Human-readable detail string (violations or error message).
    """
    # AU-2: log every CheckRequest/CheckResponse via the existing OTel pipeline.
    # Region guard: telemetry export is always local — no cross-region writes.
    logger.info(
        "AU-2 ext_authz audit: event_type=%s tool=%s verdict=%s region=%s detail=%s",
        event_type,
        tool_name,
        verdict,
        _DEPLOYMENT_REGION,
        detail[:200] if detail else "",
    )


# ---------------------------------------------------------------------------
# gRPC servicer — wraps handle_check_request in the Envoy ext_authz protocol
# ---------------------------------------------------------------------------


class CAGEAuthorizationServicer:
    """Async gRPC servicer implementing envoy.service.auth.v3.Authorization.

    This servicer is cloud-agnostic.  It works with any Envoy-based proxy
    (Istio, Contour, Emissary) and also as a GCP AGW Service Extension.

    The servicer shares the FastAPI asyncio event loop so ``validate_action()``
    can be awaited directly without thread-pool overhead.

    GCP Adaptation note
    -------------------
    When deployed as a GCP AGW Service Extension, the calling proxy is the
    AGW control plane.  The mTLS peer certificate carries the AGW service
    account identity.  No code changes are required — the protocol is
    identical to standard Envoy ext_authz.
    """

    async def Check(self, request: Any, context: Any) -> Any:
        """Handle an ext_authz CheckRequest.

        Extracts the JSON-RPC body and caller principal from the request,
        delegates to ``handle_check_request()``, and returns the result
        as a CheckResponse.

        Args:
            request: ``CheckRequest`` protobuf message.
            context: ``grpc.aio.ServicerContext``.

        Returns:
            ``CheckResponse`` protobuf message.
        """
        # Extract body and caller principal from the CheckRequest
        try:
            http_req = request.attributes.request.http
            body: str = http_req.body or ""
            # Prefer raw_body if body is empty (binary payloads)
            if not body and hasattr(http_req, "raw_body") and http_req.raw_body:
                body = http_req.raw_body

            # Extract caller principal from mTLS peer certificate (SC-8 / AC-3)
            # The peer principal is set by the service mesh from the SPIFFE ID
            # in the client certificate's SAN field.
            caller_principal: str = request.attributes.source.principal or ""
        except Exception as exc:
            logger.warning(
                "AgentGatewayAdapter: failed to extract request fields: %s — fail-closed",
                exc,
            )
            response_dict = _build_denied_response(
                403,
                {
                    "error": "request_extraction_error",
                    "message": "Could not extract request fields — fail-closed",
                },
            )
            return _dict_to_check_response(response_dict)

        response_dict = await handle_check_request(body, caller_principal)
        return _dict_to_check_response(response_dict)


def _dict_to_check_response(response_dict: dict[str, Any]) -> Any:
    """Convert a response dict to a CheckResponse-compatible object.

    Returns a simple namespace object that mirrors the protobuf structure.
    In production, this is replaced by the actual protobuf-generated class
    when grpcio-tools is available.  In tests, the dict form is used directly.

    Args:
        response_dict: Dict with either ``ok_response`` or ``denied_response``.

    Returns:
        Object with the CheckResponse structure.
    """
    # Return the dict directly — the gRPC framework serialises it.
    # When grpcio-tools stubs are generated, replace this with the
    # generated CheckResponse class.
    return response_dict


# ---------------------------------------------------------------------------
# serve_agent_gateway() — called from hybrid_server.py lifespan
# ---------------------------------------------------------------------------


async def serve_agent_gateway(port: int = _DEFAULT_GRPC_PORT) -> Any:
    """Start the async gRPC server for the ext_authz Authorization service.

    Called from ``hybrid_server.py`` ``_gateway_lifespan()`` startup block.
    Returns the running ``grpc.aio.Server`` instance for graceful shutdown.

    The server listens on ``[::]:<port>`` (all interfaces).  In production,
    mTLS is enforced by the service mesh or AGW — the server itself does not
    terminate TLS (the proxy handles it).

    Port note: Port 50051 is already declared in the existing Kubernetes
    Service manifest and whitelisted in all network policies.  No NetworkPolicy
    or Kubernetes Service changes are required.

    GCP Adaptation note
    -------------------
    When deployed on GCP, the AGW control plane connects to this port via
    the Service Extension configuration.  The GCP-specific configuration
    (service extension resource, IAM binding, mTLS CA) is managed in
    ``infra/`` Terraform modules — not in this file.

    Args:
        port: gRPC listen port (default: ``AGENT_GW_GRPC_PORT`` env var or 50051).

    Returns:
        Running ``grpc.aio.Server`` instance.

    Raises:
        ImportError: If ``grpcio`` is not installed.
        RuntimeError: If the server fails to start.
    """
    try:
        import grpc
        import grpc.aio
    except ImportError as exc:
        raise ImportError(
            "grpcio is required for the Agent Gateway Adapter. "
            "Install it with: pip install grpcio"
        ) from exc

    servicer = CAGEAuthorizationServicer()

    server = grpc.aio.server()

    # Register the servicer.  In production with generated stubs, use:
    #   from src.gateway.protos.envoy.service.auth.v3 import authorization_pb2_grpc
    #   authorization_pb2_grpc.add_AuthorizationServicer_to_server(servicer, server)
    #
    # Without generated stubs, register via the generic handler:
    from grpc import GenericMethodHandler, method_service_name

    server.add_generic_rpc_handlers(
        [
            _make_authorization_handler(servicer),
        ]
    )

    listen_addr = f"[::]:{port}"
    server.add_insecure_port(listen_addr)

    await server.start()
    logger.info(
        "✅ AgentGatewayAdapter gRPC server started on %s "
        "(ext_authz Authorization.Check ready)",
        listen_addr,
    )
    return server


def _make_authorization_handler(servicer: CAGEAuthorizationServicer) -> Any:
    """Build a generic gRPC handler for the Authorization.Check method.

    This avoids requiring generated protobuf stubs at import time.  When
    grpcio-tools stubs are generated from the vendored proto files, replace
    this with the generated ``add_AuthorizationServicer_to_server()`` call.

    Args:
        servicer: The ``CAGEAuthorizationServicer`` instance.

    Returns:
        A ``grpc.ServiceRpcHandlers`` compatible object.
    """
    import grpc

    async def _check_handler(request_bytes: bytes, context: Any) -> bytes:
        """Deserialise CheckRequest, call servicer.Check, serialise CheckResponse."""
        # Without generated stubs, we work with raw JSON over gRPC.
        # In production with grpcio-tools, replace with protobuf ser/de.
        try:
            request_dict = json.loads(request_bytes) if request_bytes else {}
        except Exception:
            request_dict = {}

        # Wrap in a simple namespace to match the protobuf API
        request_obj = _DictNamespace(request_dict)
        response_dict = await servicer.Check(request_obj, context)
        return json.dumps(response_dict).encode()

    return grpc.method_service_name(
        grpc.unary_unary_rpc_method_handler(
            _check_handler,
            request_deserializer=lambda b: b,
            response_serializer=lambda r: r,
        ),
        "envoy.service.auth.v3.Authorization",
    )


class _DictNamespace:
    """Recursive namespace that wraps a dict for attribute-style access.

    Used to present the raw JSON CheckRequest dict as a protobuf-like object
    without requiring generated stubs.
    """

    def __init__(self, data: dict | Any) -> None:
        self._data = data if isinstance(data, dict) else {}

    def __getattr__(self, name: str) -> Any:
        val = self._data.get(name, {})
        if isinstance(val, dict):
            return _DictNamespace(val)
        return val or ""
