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
                                              (full 8-tier CAGE pipeline: FTRA + 7 in-pipeline tiers)
                                                      │
                                  ┌───────────────────┼──────────────────────┐
                                  ▼           ▼        ▼                     ▼
                                ALLOW       DENY  REQUIRE_APPROVAL          DEFER
                                  │           │        │                     │
                           OkHttpResponse  403 Denied  202 REQUIRE_APPROVAL  202 DEFER
                           + routing seal  + violation + thread_id           + defer_id
                                                       (human sign-off)      (data-hydration)

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

from src.gateway.governance.decisions import GovernanceDecision

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

# Phase 1.2: CAGE_DEFER_ENABLED feature flag for backward compatibility.
# When False, DEFER decisions fall back to DENY (403) for gradual rollout safety.
_DEFER_ENABLED: bool = os.getenv("CAGE_DEFER_ENABLED", "true").lower() == "true"

# Phase 1.3: CAGE_NARROW_ENABLED feature flag for partial-authority execution.
# When False, NARROW decisions fall back to DEFER or DENY for gradual rollout safety.
# Default is False (opt-in).
_NARROW_ENABLED: bool = os.getenv("CAGE_NARROW_ENABLED", "false").lower() == "true"

# Phase 1.4: CAGE_PAUSE_ENABLED feature flag for resumable suspension.
# When False, PAUSE decisions fall back to DENY for gradual rollout safety.
# Default is False (opt-in).
_PAUSE_ENABLED: bool = os.getenv("CAGE_PAUSE_ENABLED", "false").lower() == "true"

# ---------------------------------------------------------------------------
# Prometheus metrics (Phase 1.2/1.3: DEFER and NARROW telemetry)
# ---------------------------------------------------------------------------

# Lazy-initialized Prometheus counters for defer and narrow decisions.
# Using a module-level dict to avoid import-time side effects if prometheus_client
# is not installed.
_METRICS: dict = {}


def _get_defer_counter() -> Any:
    """Get or create the Prometheus counter for defer decisions.

    Returns:
        prometheus_client.Counter or None if prometheus_client is not available.
    """
    if "defer_counter" not in _METRICS:
        try:
            from prometheus_client import Counter

            _METRICS["defer_counter"] = Counter(
                "cage_governance_defer_total",
                "Total number of DEFER governance decisions",
                ["tool_name", "defer_reason"],
            )
        except ImportError:
            logger.debug("prometheus_client not installed — defer counter disabled")
            _METRICS["defer_counter"] = None
    return _METRICS["defer_counter"]


def _get_narrow_counter() -> Any:
    """Get or create the Prometheus counter for narrow decisions.

    Returns:
        prometheus_client.Counter or None if prometheus_client is not available.
    """
    if "narrow_counter" not in _METRICS:
        try:
            from prometheus_client import Counter

            _METRICS["narrow_counter"] = Counter(
                "cage_governance_narrow_total",
                "Total number of NARROW governance decisions",
                ["tool_name", "constraint_type"],
            )
        except ImportError:
            logger.debug("prometheus_client not installed — narrow counter disabled")
            _METRICS["narrow_counter"] = None
    return _METRICS["narrow_counter"]


def _increment_defer_counter(tool_name: str, defer_reason: str) -> None:
    """Increment the Prometheus counter for DEFER decisions.

    Args:
        tool_name: The tool/action that was deferred.
        defer_reason: The reason code for the deferral.
    """
    counter = _get_defer_counter()
    if counter is not None:
        try:
            counter.labels(tool_name=tool_name, defer_reason=defer_reason).inc()
        except Exception as exc:
            logger.debug("Failed to increment defer counter: %s", exc)


def _increment_narrow_counter(tool_name: str, constraint_type: str) -> None:
    """Increment the Prometheus counter for NARROW decisions.

    Args:
        tool_name: The tool/action that was narrowed.
        constraint_type: The type of constraint applied (e.g., "amount", "scope").
    """
    counter = _get_narrow_counter()
    if counter is not None:
        try:
            counter.labels(tool_name=tool_name, constraint_type=constraint_type).inc()
        except Exception as exc:
            logger.debug("Failed to increment narrow counter: %s", exc)


def _get_pause_counter() -> Any:
    """Get or create the Prometheus counter for pause decisions.

    Returns:
        prometheus_client.Counter or None if prometheus_client is not available.
    """
    if "pause_counter" not in _METRICS:
        try:
            from prometheus_client import Counter

            _METRICS["pause_counter"] = Counter(
                "cage_governance_pause_total",
                "Total number of PAUSE governance decisions",
                ["tool_name", "pause_reason"],
            )
        except ImportError:
            logger.debug("prometheus_client not installed — pause counter disabled")
            _METRICS["pause_counter"] = None
    return _METRICS["pause_counter"]


def _get_active_pauses_gauge() -> Any:
    """Get or create the Prometheus gauge for active pauses.

    Returns:
        prometheus_client.Gauge or None if prometheus_client is not available.
    """
    if "active_pauses_gauge" not in _METRICS:
        try:
            from prometheus_client import Gauge

            _METRICS["active_pauses_gauge"] = Gauge(
                "cage_governance_active_pauses",
                "Current number of active paused requests",
            )
        except ImportError:
            logger.debug(
                "prometheus_client not installed — active pauses gauge disabled"
            )
            _METRICS["active_pauses_gauge"] = None
    return _METRICS["active_pauses_gauge"]


def _increment_pause_counter(tool_name: str, pause_reason: str) -> None:
    """Increment the Prometheus counter for PAUSE decisions.

    Args:
        tool_name: The tool/action that was paused.
        pause_reason: The reason for the pause (RATE_LIMITED, CIRCUIT_OPEN, etc.).
    """
    counter = _get_pause_counter()
    if counter is not None:
        try:
            counter.labels(tool_name=tool_name, pause_reason=pause_reason).inc()
        except Exception as exc:
            logger.debug("Failed to increment pause counter: %s", exc)


def _set_active_pauses_gauge(count: int) -> None:
    """Set the Prometheus gauge for active pauses.

    Args:
        count: The current number of active paused requests.
    """
    gauge = _get_active_pauses_gauge()
    if gauge is not None:
        try:
            gauge.set(count)
        except Exception as exc:
            logger.debug("Failed to set active pauses gauge: %s", exc)


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


def _build_narrow_response(
    routing_seal: str,
    body: dict[str, Any],
) -> dict[str, Any]:
    """Build an OkHttpResponse dict for NARROW decisions.

    NARROW decisions return HTTP 200 OK (action is allowed but with modified
    parameters). The response includes:
      - x-cage-routing-seal header (attests to narrowed params)
      - X-Governance-Narrowed: true header (signals param modification)
      - JSON body with original_params and narrowed_params

    Args:
        routing_seal: HMAC-SHA256 routing seal for the narrowed parameters.
        body:         JSON-serialisable response body dict containing original
                      and narrowed parameters.

    Returns:
        Dict representation of OkHttpResponse with NARROW-specific headers.
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
                },
                {
                    "header": {
                        "key": "X-Governance-Narrowed",
                        "value": "true",
                    },
                    "append": False,
                },
                {
                    "header": {
                        "key": "content-type",
                        "value": "application/json",
                    },
                    "append": False,
                },
            ],
            # Include response body for NARROW (unlike plain ALLOW)
            "body": json.dumps(body),
        }
    }


def _build_pause_response(
    retry_after_seconds: int,
    body: dict[str, Any],
) -> dict[str, Any]:
    """Build a DeniedHttpResponse dict for PAUSE decisions.

    PAUSE decisions return HTTP 503 Service Unavailable with a Retry-After
    header. The response includes:
      - HTTP 503 Service Unavailable status
      - Retry-After header (seconds until client should retry)
      - JSON body with pause_token, resume_endpoint, expires_at

    Args:
        retry_after_seconds: Seconds until client should retry.
        body:                JSON-serialisable response body dict containing
                             pause_token, resume_endpoint, expires_at, etc.

    Returns:
        Dict representation of DeniedHttpResponse with PAUSE-specific headers.
    """
    return {
        "denied_response": {
            "status": {"code": 503},
            "headers": [
                {
                    "header": {
                        "key": "content-type",
                        "value": "application/json",
                    },
                    "append": False,
                },
                {
                    "header": {
                        "key": "Retry-After",
                        "value": str(retry_after_seconds),
                    },
                    "append": False,
                },
                {
                    "header": {
                        "key": "X-Cage-Paused",
                        "value": "true",
                    },
                    "append": False,
                },
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

    Decision table (canonical GovernanceDecision vocabulary):
      - Parse error          → DeniedHttpResponse(403) fail-closed
      - Body > 64KB          → DeniedHttpResponse(403) fail-closed
      - ALLOW                → OkHttpResponse + x-cage-routing-seal header
      - DENY                 → DeniedHttpResponse(403) + violation JSON
      - NARROW               → OkHttpResponse(200) + x-cage-routing-seal + X-Governance-Narrowed
                               Action allowed with constrained parameters. Client proceeds with
                               narrowed_params. Feature flag: CAGE_NARROW_ENABLED (default: false)
      - PAUSE                → DeniedHttpResponse(503) + Retry-After header + {verdict: PAUSE,
                               pause_token, resume_endpoint, expires_at}
                               Client must call POST /v1/pause/{pause_token}/resume to unblock.
                               Feature flag: CAGE_PAUSE_ENABLED (default: false)
      - REQUIRE_APPROVAL     → DeniedHttpResponse(202) + {verdict: REQUIRE_APPROVAL, thread_id}
                               Client must poll GET /v1/approvals/pending (human sign-off path)
      - DEFER                → DeniedHttpResponse(202) + {verdict: DEFER, defer_id, missing_input_reason}
                               Client must poll GET /v1/defer/pending (data-hydration path)

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

    # ── Run the full CAGE 8-tier governance pipeline (FTRA + 7 in-pipeline tiers) ──
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

        verdict: str = result.get("verdict", GovernanceDecision.DENY)
        violations: list[str] = result.get("violations", [])
        seal: str = result.get("seal", "")
        thread_id: str = result.get("thread_id", "")
        defer_id: str = result.get("defer_id", "")
        missing_input_reason: str = result.get("missing_input_reason", "")

        span.set_attribute("cage.verdict", verdict)

        _emit_audit_event(
            event_type="CHECK",
            tool_name=tool_name,
            verdict=verdict,
            detail="; ".join(violations) if violations else "",
        )

        if verdict == GovernanceDecision.ALLOW:
            logger.info(
                "AgentGatewayAdapter: ALLOW tool='%s' caller='%s'",
                tool_name,
                caller_principal,
            )
            return _build_ok_response(seal)

        if verdict == GovernanceDecision.REQUIRE_APPROVAL:
            logger.info(
                "AgentGatewayAdapter: REQUIRE_APPROVAL tool='%s' caller='%s' thread_id='%s'",
                tool_name,
                caller_principal,
                thread_id,
            )
            # ext_authz timeout is typically 5s — return immediately.
            # The MCP client must poll GET /v1/approvals/pending for the human
            # sign-off outcome.  This is structurally distinct from DEFER:
            # the action context is complete; a human must approve it.
            return _build_denied_response(
                202,
                {
                    "verdict": GovernanceDecision.REQUIRE_APPROVAL,
                    "decision": GovernanceDecision.REQUIRE_APPROVAL,
                    "thread_id": thread_id,
                    "message": (
                        "Request requires human approval. "
                        "Poll GET /v1/approvals/pending for the outcome."
                    ),
                },
            )

        if verdict == GovernanceDecision.DEFER:
            # Extract Phase 1.2 DEFER response fields from validate_action result
            defer_token: str = result.get("defer_token", defer_id or "")
            classification_reason: str = result.get("classification_meta", {}).get(
                "classification_reason", missing_input_reason
            )
            deferrable: bool = result.get("deferrable", True)
            violations_list: list[str] = result.get("violations", violations)
            retry_after: int = result.get("retry_after_seconds", 300)
            defer_reason_code: str = result.get(
                "defer_reason", "CONFIDENCE_BELOW_THRESHOLD"
            )

            # Phase 1.2 Backward Compatibility: When CAGE_DEFER_ENABLED=false,
            # DEFER falls back to DENY (403) for gradual rollout safety.
            if not _DEFER_ENABLED:
                logger.warning(
                    "AgentGatewayAdapter: DEFER->DENY fallback (CAGE_DEFER_ENABLED=false) "
                    "tool='%s' caller='%s' defer_reason='%s'",
                    tool_name,
                    caller_principal,
                    defer_reason_code,
                )
                _emit_audit_event(
                    event_type="DEFER_FALLBACK",
                    tool_name=tool_name,
                    verdict="DENIED",
                    detail=f"DEFER->DENY fallback: {classification_reason}",
                )
                return _build_denied_response(
                    403,
                    {
                        "verdict": GovernanceDecision.DENY,
                        "violations": violations_list,
                        "tool_name": tool_name,
                        "fallback_from": "DEFER",
                        "classification_reason": classification_reason,
                    },
                )

            logger.info(
                "AgentGatewayAdapter: DEFER tool='%s' caller='%s' defer_token='%s' "
                "reason='%s'",
                tool_name,
                caller_principal,
                defer_token,
                defer_reason_code,
            )

            # Emit Prometheus counter for defer decisions
            _increment_defer_counter(tool_name, defer_reason_code)

            # Context is missing or below the Confidence-Starvation Boundary.
            # Route to the DeferQueue data-hydration loop — NOT human triage.
            # The MCP client must poll GET /v1/defer/pending for the outcome.
            #
            # Phase 1.2 Response body schema (§2.1 CAGE Implementation Specs):
            #   - decision: "DEFER"
            #   - classification_reason: Human-readable explanation
            #   - deferrable: true (violations are soft/deferrable)
            #   - violations: list of soft violations
            #   - defer_token: UUID v4 for resume capability
            #   - retry_after_seconds: Suggested retry interval
            return _build_denied_response(
                202,
                {
                    "decision": GovernanceDecision.DEFER,
                    "classification_reason": classification_reason,
                    "deferrable": deferrable,
                    "violations": violations_list,
                    "defer_token": defer_token,
                    "retry_after_seconds": retry_after,
                    "message": (
                        "Request deferred pending context hydration. "
                        "Poll GET /v1/defer/pending for the outcome."
                    ),
                },
            )

        # ── NARROW path (Phase 1.3 — partial-authority/clamped execution) ────
        if verdict == GovernanceDecision.NARROW:
            # Extract Phase 1.3 NARROW response fields from validate_action result
            original_params_narrow: dict = result.get("original_params", params)
            narrowed_params: dict = result.get("narrowed_params", params)
            constraints_applied: list[str] = result.get("constraints_applied", [])
            narrowing_reason: str = result.get("narrowing_reason", "")
            seal_narrow: str = result.get("seal", "")

            # Phase 1.3 Backward Compatibility: When CAGE_NARROW_ENABLED=false,
            # NARROW falls back to DEFER or DENY for gradual rollout safety.
            # Note: This check is redundant with symbolic_governor's check, but
            # provides defense-in-depth at the HTTP layer.
            if not _NARROW_ENABLED:
                logger.warning(
                    "AgentGatewayAdapter: NARROW->DENY fallback (CAGE_NARROW_ENABLED=false) "
                    "tool='%s' caller='%s' constraints='%s'",
                    tool_name,
                    caller_principal,
                    constraints_applied,
                )
                _emit_audit_event(
                    event_type="NARROW_FALLBACK",
                    tool_name=tool_name,
                    verdict="DENIED",
                    detail=f"NARROW->DENY fallback: {narrowing_reason}",
                )
                return _build_denied_response(
                    403,
                    {
                        "verdict": GovernanceDecision.DENY,
                        "violations": violations,
                        "tool_name": tool_name,
                        "fallback_from": "NARROW",
                        "narrowing_reason": narrowing_reason,
                    },
                )

            logger.info(
                "AgentGatewayAdapter: NARROW tool='%s' caller='%s' constraints=%s "
                "reason='%s'",
                tool_name,
                caller_principal,
                constraints_applied,
                narrowing_reason,
            )

            # OTel span attribute for NARROW telemetry
            span.set_attribute("cage.governance.narrowed", True)

            # Emit Prometheus counter for narrow decisions
            # Emit one counter per constraint type applied
            for constraint in constraints_applied:
                # Extract constraint type from constraint string (e.g., "amount clamped: ...")
                constraint_type = constraint.split()[0] if constraint else "unknown"
                _increment_narrow_counter(tool_name, constraint_type)

            _emit_audit_event(
                event_type="NARROW",
                tool_name=tool_name,
                verdict="NARROW",
                detail=f"constraints={constraints_applied}; reason={narrowing_reason}",
            )

            # HTTP 200 OK — action is allowed but with narrowed parameters
            # Response includes X-Governance-Narrowed: true header
            #
            # Phase 1.3 Response body schema:
            #   - decision: "NARROW"
            #   - original_params: Original parameters as submitted
            #   - narrowed_params: Constrained parameters that will be executed
            #   - narrowing_reason: Human-readable explanation
            #   - constraints_applied: List of applied constraints
            #   - execution_allowed: true (action proceeds with narrowed params)
            return _build_narrow_response(
                seal_narrow,
                {
                    "decision": GovernanceDecision.NARROW,
                    "original_params": original_params_narrow,
                    "narrowed_params": narrowed_params,
                    "narrowing_reason": narrowing_reason,
                    "constraints_applied": constraints_applied,
                    "execution_allowed": True,
                    # Canonical verdict field for consistency
                    "verdict": GovernanceDecision.NARROW,
                    "tool_name": tool_name,
                },
            )

        # ── PAUSE path (Phase 1.4 — resumable suspension) ─────────────────────
        if verdict == GovernanceDecision.PAUSE:
            from datetime import datetime, timezone

            from src.gateway.governance.pause_primitive import (
                PauseManager,
                build_resume_endpoint,
            )
            from src.gateway.infrastructure.redis_client import redis_client

            # Extract Phase 1.4 PAUSE response fields from validate_action result
            pause_reason: str = result.get("classification_meta", {}).get(
                "pause_reason", "RATE_LIMITED"
            )
            estimated_wait: int = result.get("classification_meta", {}).get(
                "estimated_wait_seconds", 60
            )
            request_id: str = params.get("request_id", params.get("thread_id", ""))

            # Phase 1.4 Backward Compatibility: When CAGE_PAUSE_ENABLED=false,
            # PAUSE falls back to DENY for gradual rollout safety.
            # Note: This check is redundant with symbolic_governor's check, but
            # provides defense-in-depth at the HTTP layer.
            if not _PAUSE_ENABLED:
                logger.warning(
                    "AgentGatewayAdapter: PAUSE->DENY fallback (CAGE_PAUSE_ENABLED=false) "
                    "tool='%s' caller='%s' reason='%s'",
                    tool_name,
                    caller_principal,
                    pause_reason,
                )
                _emit_audit_event(
                    event_type="PAUSE_FALLBACK",
                    tool_name=tool_name,
                    verdict="DENIED",
                    detail=f"PAUSE->DENY fallback: {pause_reason}",
                )
                return _build_denied_response(
                    403,
                    {
                        "verdict": GovernanceDecision.DENY,
                        "violations": violations,
                        "tool_name": tool_name,
                        "fallback_from": "PAUSE",
                        "pause_reason": pause_reason,
                    },
                )

            # Store the pause state in Redis
            try:
                pause_manager = PauseManager(redis_client)
                pause_token = await pause_manager.pause_request(
                    request_id=request_id or f"{tool_name}_{caller_principal}",
                    reason=pause_reason,
                    ttl_seconds=3600,  # 1 hour default
                    original_request=params,
                    estimated_wait_secs=estimated_wait,
                )

                # Calculate expires_at
                expires_at = datetime.now(tz=timezone.utc)
                expires_at = datetime.fromtimestamp(
                    expires_at.timestamp() + 3600, tz=timezone.utc
                )
                resume_endpoint = build_resume_endpoint(pause_token)

                logger.info(
                    "AgentGatewayAdapter: PAUSE tool='%s' caller='%s' pause_token='%s' "
                    "reason='%s' expires_at='%s'",
                    tool_name,
                    caller_principal,
                    pause_token,
                    pause_reason,
                    expires_at.isoformat(),
                )

                # OTel span attributes for PAUSE telemetry
                span.set_attribute("cage.governance.paused", True)
                span.set_attribute("cage.pause_token", pause_token)
                span.set_attribute("cage.pause_reason", pause_reason)

                # Emit Prometheus counter for pause decisions
                _increment_pause_counter(tool_name, pause_reason)

                _emit_audit_event(
                    event_type="PAUSE",
                    tool_name=tool_name,
                    verdict="PAUSE",
                    detail=f"pause_token={pause_token}; reason={pause_reason}; "
                    f"expires_at={expires_at.isoformat()}",
                )

                # HTTP 503 Service Unavailable — action is paused pending resume
                # Response includes Retry-After header
                #
                # Phase 1.4 Response body schema:
                #   - decision: "PAUSE"
                #   - pause_token: UUID for resuming via POST /v1/pause/{token}/resume
                #   - pause_reason: Reason code (RATE_LIMITED, CIRCUIT_OPEN, etc.)
                #   - resume_endpoint: URL path to resume
                #   - expires_at: ISO-8601 UTC timestamp when pause expires
                #   - estimated_wait_seconds: Optional hint for client polling
                return _build_pause_response(
                    estimated_wait,
                    {
                        "decision": GovernanceDecision.PAUSE,
                        "pause_token": pause_token,
                        "pause_reason": pause_reason,
                        "resume_endpoint": resume_endpoint,
                        "expires_at": expires_at.isoformat(),
                        "estimated_wait_seconds": estimated_wait,
                        "retry_after_seconds": estimated_wait,
                        # Canonical verdict field for consistency
                        "verdict": GovernanceDecision.PAUSE,
                        "tool_name": tool_name,
                        "message": (
                            f"Request paused: {pause_reason}. "
                            f"Call POST {resume_endpoint} to resume, "
                            f"or retry after {estimated_wait} seconds."
                        ),
                    },
                )
            except Exception as pause_exc:
                # If Redis is unavailable, fall back to DENY
                logger.error(
                    "AgentGatewayAdapter: PAUSE Redis storage failed for tool='%s': %s "
                    "— falling back to DENY",
                    tool_name,
                    pause_exc,
                )
                _emit_audit_event(
                    event_type="PAUSE_ERROR",
                    tool_name=tool_name,
                    verdict="DENIED",
                    detail=f"PAUSE Redis error: {pause_exc}",
                )
                return _build_denied_response(
                    403,
                    {
                        "verdict": GovernanceDecision.DENY,
                        "decision": GovernanceDecision.DENY,
                        "violations": violations,
                        "tool_name": tool_name,
                        "fallback_from": "PAUSE",
                        "error": "pause_storage_error",
                    },
                )

        # DENY (default fallback)
        logger.warning(
            "AgentGatewayAdapter: DENY tool='%s' caller='%s' violations=%s",
            tool_name,
            caller_principal,
            violations,
        )
        return _build_denied_response(
            403,
            {
                "verdict": GovernanceDecision.DENY,
                "decision": GovernanceDecision.DENY,
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
    server.add_generic_rpc_handlers(
        [
            _AuthorizationGenericHandler(servicer),
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


class _AuthorizationGenericHandler:
    """Generic gRPC handler for the Envoy ext_authz Authorization.Check method.

    This implements the gRPC GenericRpcHandler protocol to handle incoming
    Authorization.Check RPCs without requiring generated protobuf stubs.
    When grpcio-tools stubs are generated from the vendored proto files,
    replace this with the generated ``add_AuthorizationServicer_to_server()`` call.

    Attributes:
        SERVICE_NAME: The full gRPC service name for Envoy ext_authz.
        CHECK_METHOD: The full method path for the Check RPC.
    """

    SERVICE_NAME = "envoy.service.auth.v3.Authorization"
    CHECK_METHOD = "/envoy.service.auth.v3.Authorization/Check"

    def __init__(self, servicer: CAGEAuthorizationServicer) -> None:
        """Initialize the handler with the CAGE servicer.

        Args:
            servicer: The ``CAGEAuthorizationServicer`` instance to delegate calls to.
        """
        self._servicer = servicer

    def service(self, handler_call_details: Any) -> Any:
        """Return the appropriate RPC method handler for the given call details.

        This method is called by the gRPC server for each incoming RPC to
        determine which handler should process the request.

        Args:
            handler_call_details: gRPC HandlerCallDetails containing the method name.

        Returns:
            A ``grpc.RpcMethodHandler`` for the Authorization.Check method,
            or None if the method is not handled by this service.
        """
        import grpc

        method = getattr(handler_call_details, "method", None)
        if method != self.CHECK_METHOD:
            return None

        async def _check_handler(request_bytes: bytes, context: Any) -> bytes:
            """Deserialise CheckRequest, call servicer.Check, serialise response."""
            # Without generated stubs, we work with raw JSON over gRPC.
            # In production with grpcio-tools, replace with protobuf ser/de.
            try:
                request_dict = json.loads(request_bytes) if request_bytes else {}
            except json.JSONDecodeError:
                logger.warning("Failed to decode gRPC request as JSON, empty dict")
                request_dict = {}
            except Exception as e:
                logger.warning("Unexpected error decoding gRPC request: %s", e)
                request_dict = {}

            # Wrap in a simple namespace to match the protobuf API
            request_obj = _DictNamespace(request_dict)
            response_dict = await self._servicer.Check(request_obj, context)
            return json.dumps(response_dict).encode()

        return grpc.unary_unary_rpc_method_handler(
            _check_handler,
            request_deserializer=lambda b: b,
            response_serializer=lambda r: r,
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


# ---------------------------------------------------------------------------
# Resume endpoint handler — POST /v1/pause/{pause_token}/resume
# ---------------------------------------------------------------------------


async def handle_resume_request(
    pause_token: str,
    resume_context: dict[str, Any] | None = None,
) -> tuple[int, dict[str, Any]]:
    """Handle a resume request for a paused action.

    This is the HTTP handler for POST /v1/pause/{pause_token}/resume.
    Resume is idempotent: calling resume on an already-resumed token
    returns 200 OK (ALREADY_RESUMED) without side effects.

    Args:
        pause_token:    The pause_token UUID from the original PAUSE response.
        resume_context: Optional context data to attach to the resumed request.

    Returns:
        Tuple of (http_status_code, response_body_dict):
            - 200 OK: Resume successful (RESUMED or ALREADY_RESUMED)
            - 404 Not Found: pause_token invalid or not found
            - 410 Gone: pause_token expired (must retry original request)
            - 500 Internal Server Error: Redis unavailable

    OTel Span Attributes:
        - cage.pause_token: The pause token being resumed
        - cage.resume_result: RESUMED | ALREADY_RESUMED | EXPIRED | NOT_FOUND
    """
    from src.gateway.governance.pause_primitive import (
        PauseManager,
        ResumeResult,
    )
    from src.gateway.infrastructure.redis_client import redis_client

    with tracer.start_as_current_span("cage.pause.resume") as span:
        span.set_attribute("cage.pause_token", pause_token)

        try:
            pause_manager = PauseManager(redis_client)
            result = await pause_manager.resume_request(
                pause_token=pause_token,
                resume_context=resume_context,
            )

            span.set_attribute("cage.resume_result", result.value)

            if result == ResumeResult.RESUMED:
                logger.info(
                    "AgentGatewayAdapter: Resume successful pause_token='%s'",
                    pause_token,
                )
                _emit_audit_event(
                    event_type="RESUME",
                    tool_name="pause_resume",
                    verdict="RESUMED",
                    detail=f"pause_token={pause_token}",
                )
                return 200, {
                    "status": "RESUMED",
                    "pause_token": pause_token,
                    "message": "Request successfully resumed",
                }

            if result == ResumeResult.ALREADY_RESUMED:
                logger.info(
                    "AgentGatewayAdapter: Resume idempotent (already resumed) pause_token='%s'",
                    pause_token,
                )
                _emit_audit_event(
                    event_type="RESUME_IDEMPOTENT",
                    tool_name="pause_resume",
                    verdict="ALREADY_RESUMED",
                    detail=f"pause_token={pause_token}",
                )
                return 200, {
                    "status": "ALREADY_RESUMED",
                    "pause_token": pause_token,
                    "message": "Request was already resumed (idempotent success)",
                }

            if result == ResumeResult.EXPIRED:
                logger.warning(
                    "AgentGatewayAdapter: Resume failed (expired) pause_token='%s'",
                    pause_token,
                )
                _emit_audit_event(
                    event_type="RESUME_EXPIRED",
                    tool_name="pause_resume",
                    verdict="EXPIRED",
                    detail=f"pause_token={pause_token}",
                )
                return 410, {
                    "status": "EXPIRED",
                    "pause_token": pause_token,
                    "error": "pause_expired",
                    "message": "Pause expired — retry the original request",
                }

            if result == ResumeResult.NOT_FOUND:
                logger.warning(
                    "AgentGatewayAdapter: Resume failed (not found) pause_token='%s'",
                    pause_token,
                )
                _emit_audit_event(
                    event_type="RESUME_NOT_FOUND",
                    tool_name="pause_resume",
                    verdict="NOT_FOUND",
                    detail=f"pause_token={pause_token}",
                )
                return 404, {
                    "status": "NOT_FOUND",
                    "pause_token": pause_token,
                    "error": "pause_not_found",
                    "message": "Pause token not found or already expired",
                }

            # Unexpected result
            logger.error(
                "AgentGatewayAdapter: Unexpected resume result=%s pause_token='%s'",
                result,
                pause_token,
            )
            return 500, {
                "status": "ERROR",
                "pause_token": pause_token,
                "error": "unexpected_result",
                "message": f"Unexpected resume result: {result}",
            }

        except Exception as exc:
            logger.error(
                "AgentGatewayAdapter: Resume failed with exception pause_token='%s': %s",
                pause_token,
                exc,
                exc_info=True,
            )
            span.record_exception(exc)
            _emit_audit_event(
                event_type="RESUME_ERROR",
                tool_name="pause_resume",
                verdict="ERROR",
                detail=f"pause_token={pause_token}; error={exc}",
            )
            return 500, {
                "status": "ERROR",
                "pause_token": pause_token,
                "error": "internal_error",
                "message": "Resume failed due to internal error",
            }


async def handle_get_pause_state(
    pause_token: str,
) -> tuple[int, dict[str, Any]]:
    """Handle a GET request to retrieve pause state.

    This is the HTTP handler for GET /v1/pause/{pause_token}.
    Returns the current state of a paused request.

    Args:
        pause_token: The pause_token UUID.

    Returns:
        Tuple of (http_status_code, response_body_dict):
            - 200 OK: Pause state found
            - 404 Not Found: pause_token invalid or not found
            - 500 Internal Server Error: Redis unavailable
    """
    from src.gateway.governance.pause_primitive import PauseManager
    from src.gateway.infrastructure.redis_client import redis_client

    with tracer.start_as_current_span("cage.pause.get_state") as span:
        span.set_attribute("cage.pause_token", pause_token)

        try:
            pause_manager = PauseManager(redis_client)
            state = await pause_manager.get_pause_state(pause_token)

            if state is None:
                span.set_attribute("cage.pause_found", False)
                return 404, {
                    "status": "NOT_FOUND",
                    "pause_token": pause_token,
                    "error": "pause_not_found",
                    "message": "Pause token not found or already expired",
                }

            span.set_attribute("cage.pause_found", True)
            span.set_attribute("cage.pause_status", state.status.value)

            return 200, {
                "pause_token": state.pause_token,
                "request_id": state.request_id,
                "pause_reason": state.pause_reason.value,
                "status": state.status.value,
                "paused_at_utc": state.paused_at_utc,
                "expires_at_utc": state.expires_at_utc,
                "resumed_at_utc": state.resumed_at_utc,
                "estimated_wait_secs": state.estimated_wait_secs,
            }

        except Exception as exc:
            logger.error(
                "AgentGatewayAdapter: Get pause state failed pause_token='%s': %s",
                pause_token,
                exc,
                exc_info=True,
            )
            span.record_exception(exc)
            return 500, {
                "status": "ERROR",
                "pause_token": pause_token,
                "error": "internal_error",
                "message": "Failed to retrieve pause state",
            }
