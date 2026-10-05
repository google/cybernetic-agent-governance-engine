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
Governance Middleware (Phase 3.1)
==================================
Isolated execution environment orchestrating STPA, the Symbolic Governor,
and OPA.  Callers are authenticated before they reach this surface by mesh
workload identity (``workload_identity.WorkloadIdentityMiddleware`` on the
gateway root app, POAM-2026-080); this module holds no ingress secret.

This module is intentionally free of MCP tool definitions and HTTP proxy
logic — those live in ``mcp_tool_server.py`` and ``inference_proxy.py``
respectively.
"""

from __future__ import annotations

import json
import logging
import math
import os
import time
import uuid
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from cachetools import TTLCache
from fastapi import FastAPI, HTTPException, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from opentelemetry import context as otel_context
from opentelemetry.propagate import extract as otel_extract
from pydantic import BaseModel, field_validator

from src.gateway.governance.decisions import GovernanceDecision
from src.gateway.governance.evidence.stream import get_evidence_sink
from src.gateway.governance.governance_envelope import GovernanceEnvelopeBuilder
from src.gateway.governance.governor.governor import GovernanceError, SymbolicGovernor
from src.gateway.governance.iso_control import stamp_iso_control
from src.gateway.governance.kms_signer import get_governance_signer
from src.gateway.governance.prompt_injection_detector import detect_indirect_injection
from src.gateway.governance.text_filter import ac_keyword_scan
from src.gateway.server.app_state import governor_of
from src.gateway.server.state_commitment_api import (
    router as state_commitment_router,
)

logger = logging.getLogger("Gateway.GovernanceMiddleware")


# CAGE_ENV takes precedence over ENVIRONMENT for forward compatibility.
_ENVIRONMENT: str = (
    os.environ.get("CAGE_ENV") or os.environ.get("ENVIRONMENT", "production")
).lower()


def _is_dev_environment() -> bool:
    """M-15: Secondary check using K8s namespace to prevent CAGE_ENV spoofing.

    In production GKE deployments the pod's namespace is mounted at
    /var/run/secrets/kubernetes.io/serviceaccount/namespace.
    If that file exists and does NOT contain 'dev', we treat the environment
    as production regardless of the CAGE_ENV env var.
    """
    if _ENVIRONMENT not in ("dev", "development", "test"):
        return False
    # Secondary check: K8s namespace file (present in GKE pods)
    ns_file = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
    try:
        with open(ns_file, encoding="utf-8") as f:
            namespace = f.read().strip().lower()
        # If namespace doesn't contain 'dev' or 'test', treat as production
        if namespace and not any(kw in namespace for kw in ("dev", "test", "local")):
            logger.warning(
                "⚠️  M-15: CAGE_ENV=%s but K8s namespace=%r — treating as production.",
                _ENVIRONMENT,
                namespace,
            )
            return False
    except FileNotFoundError:
        pass  # Not running in K8s — trust CAGE_ENV
    except Exception as exc:
        logger.warning("M-15: Could not read K8s namespace file: %s", exc)
    return True


# ---------------------------------------------------------------------------
# Governance enforcement helpers
# ---------------------------------------------------------------------------


async def enforce_governance(
    governor: SymbolicGovernor, tool_name: str, params: dict[str, Any]
) -> str:
    """Run the full Symbolic Governor pipeline for the given tool call.

    Gap 2 fix (No-Direct-Bind): ``govern()`` now returns a routing seal on
    approval.  This function propagates that seal to callers so they can
    verify it before executing the governed action, satisfying the invariant:
        NoDirectBind == (phase = "EXECUTED") => (resolvedAllow = TRUE)

    Returns:
        HMAC-SHA256 routing seal string (non-empty on approval).

    Raises:
        PermissionError: If the governor blocks the action.
    """
    if tool_name in {"check_market_status", "verify_content_safety"}:
        return ""  # Exempt read-only tools from governance overhead

    try:
        seal = await governor.govern(tool_name, params)
        return seal
    except GovernanceError as exc:
        logger.warning("🛡️ Symbolic Governor BLOCKED %s: %s", tool_name, exc)
        await _emit_refusal_receipt(
            action_id=tool_name,
            refusal_reason=str(exc),
            oscal_control_ref="SC-4",
            params=params,
            receipt=exc.receipt,
        )
        raise PermissionError(f"Governance Blocked: {exc}")


async def enforce_approved_governance(
    governor: SymbolicGovernor,
    tool_name: str,
    params: dict[str, Any],
    *,
    deferred_id: str,
    approval_covers: Callable[[dict[str, Any], dict[str, Any]], bool],
) -> str:
    """Commit and seal a human-approved action: the post-approval committing run.

    1. Consume the ``HITL_REQUIRED`` token ``deferred_id`` from the gateway's
       DeferQueue exactly once. It must be quorum-approved, parked for
       ``tool_name``, and ``approval_covers(approved_params, params)`` must
       hold, so an approval for one action cannot authorise a different or
       larger one. Consumption is a compare-and-swap: a replayed or concurrent
       ``deferred_id`` is refused.
    2. Run ``SymbolicGovernor.revalidate_post_hitl()`` (POST_HITL profile:
       commit + seal) on the fresh ``params``, bound to the token's
       ``barrier_preview``: an approval given against PASS whose barriers now
       refuse is ``APPROVAL_CONTEXT_DRIFT``.

    The approval is spent before re-validation, so a re-validation refusal
    also burns it: the operator must approve a fresh request.

    Returns:
        The routing seal for ``params``.

    Raises:
        PermissionError: The approval is missing, unapproved, mismatched or
            already consumed, or post-approval re-validation refused.
    """
    from src.gateway.governance.defer_queue import open_defer_queue

    def _covers(approved: dict[str, Any]) -> bool:
        try:
            return bool(approval_covers(approved, params))
        except Exception as exc:  # a raising matcher never authorises
            logger.warning("approval_covers raised for %s: %s", tool_name, exc)
            return False

    try:
        async with open_defer_queue() as queue:
            token = await queue.consume_approval(
                deferred_id, action=tool_name, covers=_covers
            )
    except Exception as exc:  # queue unreachable: no approval can be proven
        logger.error("DeferQueue unavailable consuming %s: %s", deferred_id, exc)
        token = None
    if token is None:
        reason = f"no unconsumed approval {deferred_id!r} covers this {tool_name}"
        await _emit_refusal_receipt(
            action_id=tool_name,
            refusal_reason=reason,
            oscal_control_ref="AC-3",
            params=params,
        )
        raise PermissionError(f"Governance Blocked: {reason}")

    try:
        return await governor.revalidate_post_hitl(
            tool_name,
            params,
            approved_barrier_preview=token.barrier_preview,
            trace_id=token.thread_id,
        )
    except GovernanceError as exc:
        logger.warning("🛡️ Post-approval re-validation BLOCKED %s: %s", tool_name, exc)
        await _emit_refusal_receipt(
            action_id=tool_name,
            refusal_reason=str(exc),
            oscal_control_ref="SC-4",
            params=params,
            receipt=exc.receipt,
        )
        raise PermissionError(f"Governance Blocked: {exc}")


async def tier1_keyword_check(text: str, span: Any = None) -> str | None:
    """Run Tier-1 Aho-Corasick keyword scan.

    Returns a violation message if blocked, else None.
    Stamps the ISO 42001 evidence attribute on *span* when provided.
    """
    if ac_keyword_scan(text):
        stamp_iso_control(span, ingress_stage=1, control="A.5.2", outcome="BLOCK")
        return "keyword_match"
    stamp_iso_control(span, ingress_stage=1, control="A.5.2", outcome="PASS")
    return None


async def sanitize_mcp_tool_response(
    tool_name: str,
    response_text: str,
    span: Any = None,
) -> str | None:
    """Sanitize an MCP tool response for indirect injection (AI 600-1 §2.3, AI600-003).

    Checks the tool response against the indirect injection pattern set in
    ``prompt_injection_detector.detect_indirect_injection()``.  Called in the
    governance middleware after every MCP tool invocation, before the response
    is returned to the agent pipeline.

    Args:
        tool_name:     Name of the MCP tool that produced the response.
        response_text: The raw string content returned by the tool call.
        span:          Active OTel span for evidence stamping (optional).

    Returns:
        A violation description string if indirect injection was detected,
        ``None`` if the response is clean.
    """
    result = detect_indirect_injection(tool_name, response_text)
    if result.detected:
        stamp_iso_control(span, ingress_stage=2, control="A.9.2", outcome="BLOCK")
        logger.warning(
            '🔴 [AI600-003] MCP tool response rejected: tool=%s pattern=%s "\n'
            "(ISO 42001 A.9.2 — indirect injection blocked)",
            tool_name,
            result.pattern_matched,
        )
        return f"indirect_injection:{result.pattern_matched}"
    stamp_iso_control(span, ingress_stage=2, control="A.9.2", outcome="PASS")
    return None


# ---------------------------------------------------------------------------
# Minimal FastAPI sub-application for the middleware surface
# (mounted by mcp_tool_server under /governance)
# ---------------------------------------------------------------------------

governance_app = FastAPI(title="CAGE Governance Middleware")

# ---------------------------------------------------------------------------
# In-memory rate limiter for /validate-action (GHSA-v3h4-8458-5ww3)
#
# Prevents unauthenticated DoS and governance configuration oracle attacks
# by capping requests per client IP within a sliding window.
#
# Limits: 60 requests per 60-second window per client IP.
# Configurable via VALIDATE_ACTION_RATE_LIMIT and VALIDATE_ACTION_RATE_WINDOW.
#
# MED-3 LIMITATION: This is an in-process, in-memory rate limiter.  In a
# multi-pod Kubernetes deployment each pod maintains its own independent bucket,
# so the effective rate limit is _RATE_LIMIT_MAX x pod_count.  For true
# cross-pod enforcement, replace this with a Redis-backed sliding window
# (e.g. ZREMRANGEBYSCORE + ZADD + ZCARD in a Lua script, similar to the
# TokenQuotaProxy pattern in token_quota_proxy.py).
# ---------------------------------------------------------------------------

_RATE_LIMIT_MAX: int = int(os.environ.get("VALIDATE_ACTION_RATE_LIMIT", "60"))
_RATE_LIMIT_WINDOW: int = int(os.environ.get("VALIDATE_ACTION_RATE_WINDOW", "60"))

# {client_ip: [timestamp, ...]} — timestamps of requests within the window
# Uses TTLCache to prevent unbounded memory growth: entries expire after 1 hour,
# and max 10,000 unique IPs are tracked simultaneously.
_validate_action_rate_buckets: TTLCache[str, list[float]] = TTLCache(
    maxsize=10000, ttl=3600
)

# ---------------------------------------------------------------------------
# HIGH-5: Trusted proxy CIDR list for X-Forwarded-For validation.
#
# X-Forwarded-For is a client-controlled header.  Only trust it when the
# direct TCP connection comes from a known trusted proxy (load balancer, ingress
# controller, or API gateway).  Requests from untrusted sources use the direct
# connection IP so attackers cannot spoof their IP to bypass rate limiting.
#
# Configure via CAGE_TRUSTED_PROXY_CIDRS (comma-separated CIDR list).
# Default: RFC-1918 private ranges (suitable for GKE / Cloud Load Balancing).
# ---------------------------------------------------------------------------
import ipaddress as _ipaddress

_TRUSTED_PROXY_CIDRS: list[str] = [
    cidr.strip()
    for cidr in os.environ.get(
        "CAGE_TRUSTED_PROXY_CIDRS",
        "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.1/32,::1/128",
    ).split(",")
    if cidr.strip()
]


def _is_trusted_proxy(ip: str) -> bool:
    """Return True if *ip* is within the configured trusted proxy CIDR list."""
    try:
        addr = _ipaddress.ip_address(ip)
        return any(
            addr in _ipaddress.ip_network(cidr, strict=False)
            for cidr in _TRUSTED_PROXY_CIDRS
        )
    except ValueError:
        return False


def _client_ip(request: Request) -> str:
    """Rate-limit key: X-Forwarded-For only when the TCP peer is a trusted proxy.

    HIGH-5 fix: untrusted sources use the direct connection IP so attackers
    cannot spoof their IP to bypass the per-IP rate limit.
    """
    direct_ip = request.client.host if request.client else "unknown"
    if _is_trusted_proxy(direct_ip):
        xff = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        return xff if xff else direct_ip
    return direct_ip


def _check_validate_action_rate_limit(client_ip: str) -> bool:
    """Return True if the request is within the rate limit, False if exceeded.

    Uses a sliding window algorithm: timestamps older than the window are
    evicted on each check.  Thread-safe under Python's GIL for single-process
    deployments.

    MED-3: In multi-pod Kubernetes deployments this limiter is per-pod.
    See the module-level comment above for the Redis-backed alternative.

    Memory safety: Uses TTLCache with maxsize=10000 and ttl=3600 to prevent
    unbounded memory growth from unique IPs.
    """
    now = time.monotonic()
    window_start = now - _RATE_LIMIT_WINDOW

    # TTLCache doesn't auto-create entries like defaultdict; handle missing keys
    if client_ip not in _validate_action_rate_buckets:
        _validate_action_rate_buckets[client_ip] = []
    bucket = _validate_action_rate_buckets[client_ip]

    # Evict expired timestamps (sliding window)
    _validate_action_rate_buckets[client_ip] = [
        ts for ts in bucket if ts > window_start
    ]
    bucket = _validate_action_rate_buckets[client_ip]

    if len(bucket) >= _RATE_LIMIT_MAX:
        logger.warning(
            "🚦 validate-action rate limit exceeded for client=%s "
            "(%d requests in %ds window)",
            client_ip,
            len(bucket),
            _RATE_LIMIT_WINDOW,
        )
        return False

    bucket.append(now)
    return True


# ---------------------------------------------------------------------------
# /validate-action — Unified Governance Routing (Option 2)
# ---------------------------------------------------------------------------


class ValidateActionRequest(BaseModel):
    """Payload for POST /governance/validate-action."""

    action: str
    params: dict[str, Any]
    policy_version_id: str | None = None

    @field_validator("params")
    @classmethod
    def _reject_non_finite_floats(cls, v: dict[str, Any]) -> dict[str, Any]:
        for key, val in v.items():
            if isinstance(val, float) and not math.isfinite(val):
                raise ValueError(
                    f"params[{key!r}] contains non-finite float {val!r} "
                    "— NaN and Infinity are not permitted"
                )
        return v


# ---------------------------------------------------------------------------
# P6 — Signed OSCAL compliance receipt on GovernanceError (hard refusal)
# ---------------------------------------------------------------------------


def _serialize_receipt(
    receipt_obj: Any,
) -> dict[str, Any]:
    """Serialize a RefusalReceipt to a dict for evidence ingestion.

    Preserves the receipt's computed proof_hash exactly without recomputation.
    Handles nested frozen dataclasses (GovernanceTierFailure).

    Args:
        receipt_obj: RefusalReceipt instance.

    Returns:
        Serialized dict suitable for JSON encoding and evidence stream ingestion.
    """
    from dataclasses import asdict, is_dataclass

    def _convert_value(obj: Any) -> Any:
        """Recursively convert dataclass instances and tuples."""
        if is_dataclass(obj) and not isinstance(obj, type):
            return asdict(obj)
        elif isinstance(obj, tuple):
            return [_convert_value(item) for item in obj]
        elif isinstance(obj, list):
            return [_convert_value(item) for item in obj]
        elif isinstance(obj, dict):
            return {k: _convert_value(v) for k, v in obj.items()}
        else:
            return obj

    return _convert_value(receipt_obj)


async def _emit_refusal_receipt(
    action_id: str,
    refusal_reason: str,
    oscal_control_ref: str,
    params: dict[str, Any],
    receipt: Any = None,
) -> None:
    """Emit a signed OSCAL compliance receipt for a hard governance refusal.

    Called from every ``GovernanceError`` handler in this module.  The receipt
    is signed via ``KMSGovernanceSigner.sign()`` and published to the evidence
    stream via ``EvidenceStreamSink.ingest()``.

    If OSCAL emission itself fails, the error is logged at ERROR level but the
    original ``GovernanceError`` is NOT suppressed — the refusal must still
    propagate to the caller.

    A2 fix: Now accepts the full RefusalReceipt v3 object and serializes it
    with tier_failures and the 5-part proof chain intact. When receipt is None,
    degrades to a summary form (legacy path) but logs a warning to make the
    degraded case visible.

    Args:
        action_id:         The tool / action name that triggered the refusal.
        refusal_reason:    The ``str(exc)`` of the ``GovernanceError``.
        oscal_control_ref: OSCAL control reference (e.g. ``"SC-4"``).
        params:            Original action parameters (used for context only).
        receipt:           Full RefusalReceipt v3 object (if available).
    """
    receipt_id = str(uuid.uuid4())
    timestamp_utc = datetime.now(tz=timezone.utc).isoformat()

    # A2: Serialize the full receipt if provided; degrade to summary if None
    if receipt is not None:
        # Serialize the full v3 RefusalReceipt with tier_failures and proof chain
        receipt_payload: dict[str, Any] = _serialize_receipt(receipt)
        receipt_payload["type"] = "GOVERNANCE_REFUSAL_RECEIPT"
        receipt_payload["receipt_id"] = receipt_id
        receipt_payload["action_id"] = action_id
        receipt_payload["timestamp_utc"] = timestamp_utc
        receipt_payload["oscal_control_ref"] = oscal_control_ref
        receipt_payload["kms_signature"] = ""
        # proof_hash is already in the serialized payload from the receipt
    else:
        # Degraded path: emit summary form when receipt is None
        # Log a warning to make this visible — silently emitting thin receipts
        # is how the defect arose in the first place.
        logger.warning(
            "⚠️ [A2] Emitting degraded refusal receipt (receipt=None): "
            "action='%s' — tier_failures and proof_hash unavailable. "
            "This indicates GovernanceError was raised without a receipt.",
            action_id,
        )
        receipt_payload = {
            "type": "GOVERNANCE_REFUSAL_RECEIPT",
            "receipt_id": receipt_id,
            "action_id": action_id,
            "refusal_reason": refusal_reason,
            "timestamp_utc": timestamp_utc,
            "oscal_control_ref": oscal_control_ref,
            "kms_signature": "",
        }

    # Sign the receipt via KMS
    try:
        signer = get_governance_signer()
        # Sign a stable subset of the receipt (exclude kms_signature itself)
        signable = {k: v for k, v in receipt_payload.items() if k != "kms_signature"}
        receipt_payload["kms_signature"] = signer.sign(signable)
    except Exception as sign_exc:
        logger.error(
            "❌ [P6] Failed to KMS-sign refusal receipt for action '%s' "
            "(receipt_id=%s): %s — receipt will be emitted unsigned.",
            action_id,
            receipt_id,
            sign_exc,
        )

    # Publish to evidence stream
    try:
        sink = get_evidence_sink()
        await sink.ingest(receipt_payload)
        # MED-7 fix: a successfully emitted refusal receipt is not an error —
        # logging it at ERROR level polluted error dashboards with normal events.
        logger.info(
            "🔴 [P6] Signed OSCAL refusal receipt emitted: action='%s' "
            "control='%s' receipt_id=%s kms_signed=%s has_proof_hash=%s",
            action_id,
            oscal_control_ref,
            receipt_id,
            bool(receipt_payload["kms_signature"]),
            "proof_hash" in receipt_payload,
        )
    except Exception as emit_exc:
        logger.error(
            "❌ [P6] Failed to emit OSCAL refusal receipt for action '%s' "
            "(receipt_id=%s): %s — GovernanceError will still propagate.",
            action_id,
            receipt_id,
            emit_exc,
        )


@governance_app.get("/policy-version")
async def get_policy_version_endpoint() -> JSONResponse:
    """Retrieve the active policy hash for session pinning verification."""
    from src.gateway.governance.constants import ControlRegistry

    return JSONResponse(content={"active_hash": ControlRegistry().active_hash})


@governance_app.get("/jwks")
async def get_jwks_endpoint() -> JSONResponse:
    """Return the JSON Web Key Set (JWKS) for routing seal verification.

    External verifiers (GFA actuators, compliance auditors) use this endpoint
    to fetch the public keys needed to verify JWT routing seals issued by the
    gateway.

    Key rotation is handled automatically:
    - New keys are added when KMS keys are rotated
    - Old keys remain available for a grace period (default: 1 hour)
    - Expired keys are automatically removed on access

    Response format (RFC 7517 JWK Set):
        {
            "keys": [
                {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "...",
                    "y": "...",
                    "kid": "...",
                    "use": "sig",
                    "alg": "ES256"
                }
            ]
        }

    Cache-Control:
        The response includes Cache-Control headers matching the JWKS cache TTL
        to allow external verifiers to cache the keyset appropriately.
    """
    from src.gateway.governance.jwks import _JWKS_CACHE_TTL_S, get_jwks

    jwks = get_jwks()
    jwks_dict = jwks.to_dict()

    return JSONResponse(
        content=jwks_dict,
        headers={
            "Cache-Control": f"public, max-age={_JWKS_CACHE_TTL_S}",
            "Content-Type": "application/json",
        },
    )


@governance_app.get("/.well-known/jwks.json")
async def get_jwks_well_known() -> JSONResponse:
    """RFC 8615 well-known alias for the JWKS endpoint.

    Henrik Ibsen contract: clients must be able to fetch public keys at the
    standard well-known location in addition to the /jwks shorthand.
    Delegates to get_jwks_endpoint() so all caching and key-rotation
    behaviour is identical between the two paths.
    """
    return await get_jwks_endpoint()


@governance_app.post("/validate-action")
async def validate_action_endpoint(
    request: Request,
    body: ValidateActionRequest,
) -> JSONResponse:
    """Unified governance validation for structured tool execution payloads.

    Called by the GFA service (and any future tool actuators) instead of
    invoking OPA directly.  This endpoint is the **Single Choke Point** for
    all tool-level governance decisions.

    W3C Trace Context:
        The GFA injects a ``traceparent`` header via
        ``opentelemetry.propagate.inject(headers)``.  This endpoint extracts
        it and attaches the incoming span context so that all
        ``cage.validate_action`` child spans are connected to the GFA's
        ``cage.tool_execute`` root span, producing a unified Telemetry trace
        tree across the service boundary.

    Governance tiers executed (8-tier pipeline via ``run_pipeline()``, matching
    ``TIER_LABELS`` in ``proof/model.py``; plugin tiers such as ``bounding`` run
    alongside):
        - Tier 0.5: FTRA action classification & reachability analysis
        - Tier 1: STPA/STAMP Unsafe Control Action validation
        - Tier 2: Agent confidence threshold pre-check (fast-fail)
        - Tier 3b: OPA Rego policy evaluation — declarative rule enforcement
        - Tier 5: Multi-agent Consensus gate (ISO 42001)
        - Tier 6: DoWhy Causal Gatekeeper — refutation-based safety lock
        - Tier 3a (phase 2): Control Barrier Function (CBF) — barrier headroom
        - Tier 4 (phase 2): Fiscal Limit Pre-Reservation

    This endpoint is a non-committing decision: phase-2 tiers are previewed,
    nothing is reserved, and no routing seal is minted. The caller uses the
    verdict only for routing; the single committing run (commit + seal +
    actuation) happens inside the gateway when the governed tool executes.

    Returns:
        ``ALLOW`` / ``NARROW`` (NARROW carries ``narrowed_params``) as a signed
        governance envelope; ``REQUIRE_APPROVAL`` with the ``deferred_id`` of
        the gateway-held approval token; ``DEFER`` (202 for external holds);
        or 403 ``DENIED`` with a refusal receipt.
    """
    # GHSA-v3h4-8458-5ww3: the caller is authenticated before any processing by
    # WorkloadIdentityMiddleware (mesh identity, POAM-2026-080) on the root app.

    # ── Rate limiting: prevent DoS via rapid unauthenticated requests ─────────
    # HIGH-5 fix: only trust X-Forwarded-For when the direct TCP connection
    # comes from a known trusted proxy (load balancer / ingress controller).
    # Untrusted sources use the direct connection IP so attackers cannot spoof
    # their IP to bypass the per-IP rate limit.
    client_ip = _client_ip(request)
    if not _check_validate_action_rate_limit(client_ip):
        raise HTTPException(
            status_code=429,
            detail={
                "error": "rate_limit_exceeded",
                "message": (
                    f"Too many requests to /validate-action from {client_ip}. "
                    f"Limit: {_RATE_LIMIT_MAX} requests per {_RATE_LIMIT_WINDOW}s."
                ),
            },
        )

    # ── Extract W3C trace context from inbound headers ────────────────────────
    # The GFA injected 'traceparent' via otel_inject(headers).  Extracting it
    # here and attaching it as the current context means all spans opened by
    # SymbolicGovernor.validate_action() (cage.cbf_action_check,
    # cage.opa_action_check, cage.routing_seal) are children of the GFA's
    # cage.tool_execute span in Telemetry — not orphaned fragments.
    governor = governor_of(request.app)  # fail closed before any evaluation
    carrier = dict(request.headers)
    remote_ctx = otel_extract(carrier)
    token = otel_context.attach(remote_ctx)

    try:
        result = await governor.validate_action(
            action=body.action,
            params=body.params,
            policy_version_id=body.policy_version_id,
        )

        # Phase 1, §3.2: HTTP 202 Accepted for FlowSignal ESCALATE decisions
        # When the verdict is DEFER and it's an external provider escalation, return
        # HTTP 202 with an async receipt body so clients know to poll for resolution.
        # Detection: defer_reason == "EXTERNAL_HOLD" OR
        #            is_external_hold == True (explicit marker). The EU fria tier
        #            reports a provider hold as HITL → REQUIRE_APPROVAL instead.
        verdict = result.get("verdict")
        defer_reason = result.get("defer_reason", "")
        is_external_hold = result.get("is_external_hold", False)

        if verdict == "DEFER" and (
            defer_reason == "EXTERNAL_HOLD" or is_external_hold is True
        ):
            defer_id = result.get("defer_id", "")
            receipt_payload = {
                "schema_version": "1.0.0",
                "defer_id": defer_id,
                "status": "pending_review",
                "poll_url": f"/v1/defer/{defer_id}",
                "verdict": "DEFER",
                "defer_reason": "EXTERNAL_HOLD",
                "ttl_seconds": 300,  # External provider escalations use 5-minute TTL (configurable per-provider)
                "latency_ms": result.get("latency_ms", 0),
            }
            logger.info(
                "🔔 FlowSignal ESCALATE → HTTP 202: defer_id=%s action=%s",
                defer_id,
                body.action,
            )
            return JSONResponse(
                status_code=202,
                content=receipt_payload,
            )

        # ADR-008 Phase 3: Build canonical signed envelope for admissible verdicts
        if verdict in (GovernanceDecision.ALLOW, GovernanceDecision.NARROW):
            from src.gateway.governance.seams.attestation import ExternalAttestation

            # Convert dict attestations to ExternalAttestation objects
            attestations_raw = result.get("external_attestations")
            attestations = None
            if attestations_raw:
                attestations = []
                for att in attestations_raw:
                    if isinstance(att, dict):
                        # Extract standard fields; everything else goes into metadata
                        standard_keys = {
                            "type",
                            "status",
                            "receipt_id",
                            "attested_at",
                            "provider_name",
                        }
                        metadata = {
                            k: v for k, v in att.items() if k not in standard_keys
                        }
                        attestations.append(
                            ExternalAttestation(
                                attestation_type=att.get("type", ""),
                                status=att.get("status", ""),
                                receipt_id=att.get("receipt_id", ""),
                                attested_at=att.get("attested_at", ""),
                                provider_name=att.get("provider_name", "unknown"),
                                metadata=metadata,
                            )
                        )
                    else:
                        attestations.append(att)

            builder = GovernanceEnvelopeBuilder()
            envelope = await builder.build(
                action=body.action,
                params=body.params,
                governance_result=jsonable_encoder(result),
                record_hash=result.get("record_hash"),
                agent_id=result.get("agent_id"),
                tiers_passed=result.get("tiers_passed", []),
                controls_satisfied=result.get("controls_satisfied", []),
                external_attestations=attestations,
            )
            return JSONResponse(content=envelope.to_dict(include_signature=True))

        # REQUIRE_APPROVAL (carries ``deferred_id``) and DEFER: flat format
        payload = {"schema_version": "1.0.0", **result}
        return JSONResponse(content=jsonable_encoder(payload))

    except GovernanceError as exc:
        # P6: emit a signed OSCAL compliance receipt for every hard refusal.
        # Errors during emission are logged but do NOT suppress the refusal.
        await _emit_refusal_receipt(
            action_id=body.action,
            refusal_reason=str(exc),
            oscal_control_ref="SC-4",
            params=body.params,
            receipt=exc.receipt,
        )

        # ADR-008 Phase 3: Return complete refusal contract
        refusal_content: dict[str, Any] = {
            "schema_version": "2.0.0",
            "verdict": "DENIED",
            "violations": getattr(exc, "violations", [str(exc)]),
        }

        # Include refusal receipt fields if available
        if hasattr(exc, "receipt") and exc.receipt is not None:
            refusal_content["refusal_receipt"] = _serialize_receipt(exc.receipt)
            if hasattr(exc.receipt, "proof_hash"):
                refusal_content["proof_hash"] = exc.receipt.proof_hash

        return JSONResponse(
            status_code=403,
            content=refusal_content,
        )
    except Exception:
        logger.error("❌ validate_action internal error", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal governance error")
    finally:
        otel_context.detach(token)


# ---------------------------------------------------------------------------
# E1 — OIDC JWT Validation Middleware (Work Stream E, Phase B)
# ---------------------------------------------------------------------------
# Validates Bearer JWTs against a configurable JWKS endpoint and injects
# caller_identity into the request state for OPA agent catalog evaluation.
#
# Design principles:
#   - Backward-compatible: if CAGE_OIDC_JWKS_URI is not set, all requests
#     pass through unchanged (existing deployments unaffected).
#   - Additive: caller_identity is injected as request.state.caller_identity;
#     existing OPA policies do not need to change — the field is optional.
#   - Works with any OIDC provider: Keycloak, Dex, Auth0, Google, Azure AD, Okta.
#
# GCP Adaptation note:
#   When deployed behind GCP IAP, set CAGE_OIDC_JWKS_URI to the IAP JWKS
#   endpoint (https://www.gstatic.com/iap/verify/public_key-jwk) and
#   CAGE_OIDC_ISSUER to https://cloud.google.com/iap. No code changes needed.
#
# Environment variables:
#   CAGE_OIDC_JWKS_URI  — JWKS endpoint URL; if unset, OIDC validation disabled
#   CAGE_OIDC_ISSUER    — expected iss claim; if unset, skip issuer check
#   CAGE_OIDC_AUDIENCE  — expected aud claim; if unset, skip audience check
# ---------------------------------------------------------------------------

_OIDC_JWKS_URI: str | None = os.environ.get("CAGE_OIDC_JWKS_URI")
_OIDC_ISSUER: str | None = os.environ.get("CAGE_OIDC_ISSUER")
_OIDC_AUDIENCE: str | None = os.environ.get("CAGE_OIDC_AUDIENCE")

# JWKS cache: bounded TTLCache to prevent memory exhaustion from malicious
# OIDC providers serving unbounded JWK sets.
try:
    from cachetools import TTLCache

    _jwks_cache: TTLCache = TTLCache(maxsize=100, ttl=3600)
except ImportError:
    # Fallback to dict if cachetools not available — log warning at runtime
    import warnings

    warnings.warn(
        "cachetools not installed — JWKS cache will be unbounded. "
        "Install cachetools for production use: pip install cachetools",
        RuntimeWarning,
        stacklevel=2,
    )
    _jwks_cache: dict[str, Any] = {}  # type: ignore[no-redef]
_JWKS_CACHE_TTL_S: float = 3600.0  # 1 hour


def _get_jwks_cache_key() -> str:
    return _OIDC_JWKS_URI or ""


# HIGH-3 fix: hardcoded allowlist — never trust the 'alg' field from the JWT
# header.  An attacker can set alg=none or alg=HS256 to bypass signature
# verification (JWT algorithm confusion attack, CVE-2015-9235 class).
_OIDC_ALLOWED_ALGORITHMS: list[str] = [
    "RS256",
    "RS384",
    "RS512",
    "ES256",
    "ES384",
    "ES512",
]


async def _fetch_jwks() -> dict[str, Any]:
    """Fetch and cache the JWKS from CAGE_OIDC_JWKS_URI.

    Returns a dict mapping ``kid`` → JWK key data dict.
    Caches for ``_JWKS_CACHE_TTL_S`` seconds to avoid hammering the JWKS endpoint.

    HIGH-4 fix: uses httpx.AsyncClient (already a dependency) with explicit
    TLS verification instead of urllib.request.urlopen which used the default
    SSL context and suppressed the Bandit S310 warning.

    Raises:
        RuntimeError: If the JWKS endpoint is unreachable or returns invalid JSON.
    """
    now = time.monotonic()
    fetched_at = _jwks_cache.get("_fetched_at", 0.0)
    if _jwks_cache and (now - fetched_at) < _JWKS_CACHE_TTL_S:
        return dict(_jwks_cache)  # type: ignore[arg-type,return-value]

    if not _OIDC_JWKS_URI:
        return {}

    try:
        import httpx as _httpx

        async with _httpx.AsyncClient(verify=True, timeout=5.0) as client:
            resp = await client.get(_OIDC_JWKS_URI)
            resp.raise_for_status()
            jwks_doc = resp.json()
    except Exception as exc:
        raise RuntimeError(
            f"Failed to fetch JWKS from {_OIDC_JWKS_URI}: {exc}"
        ) from exc

    keys: dict[str, Any] = {}
    for key_data in jwks_doc.get("keys", []):
        kid = key_data.get("kid", "default")
        keys[kid] = key_data

    keys["_fetched_at"] = now
    _jwks_cache.clear()
    _jwks_cache.update(keys)
    return dict(_jwks_cache)  # type: ignore[arg-type]


def _decode_jwt_header(token: str) -> dict[str, Any]:
    """Decode the JWT header (first segment) without verification.

    Args:
        token: Raw JWT string.

    Returns:
        Decoded header dict.

    Raises:
        ValueError: If the token is malformed.
    """
    import base64

    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("JWT must have exactly 3 segments")

    # Add padding — use modulo to avoid adding 4 chars when length % 4 == 0
    header_b64 = parts[0] + "=" * ((4 - len(parts[0]) % 4) % 4)
    try:
        header_bytes = base64.urlsafe_b64decode(header_b64)
        return json.loads(header_bytes)
    except Exception as exc:
        raise ValueError(f"Could not decode JWT header: {exc}") from exc


async def validate_oidc_token(token: str) -> dict[str, Any]:
    """Validate an OIDC JWT and return the caller_identity dict.

    Validates:
      1. JWT signature against the JWKS endpoint
      2. ``exp`` claim (token not expired)
      3. ``iss`` claim (if CAGE_OIDC_ISSUER is set)
      4. ``aud`` claim (if CAGE_OIDC_AUDIENCE is set)

    Args:
        token: Raw JWT string from ``Authorization: Bearer <token>`` header.

    Returns:
        ``caller_identity`` dict with ``sub``, ``iss``, and ``scope`` fields.

    Raises:
        HTTPException(401): If the token is invalid, expired, or fails
            signature verification.
    """
    # Step 1: Import PyJWT.
    # HIGH-2 fix: when OIDC is configured, a missing PyJWT dependency must be a
    # hard failure — silently returning {} accepted any token without verification,
    # creating a complete authentication bypass.
    # NOTE: the import is attempted first so that if PyJWT is absent AND OIDC is
    # not configured, we return {} immediately (backward compat, no token parsing).
    try:
        import jwt as pyjwt  # PyJWT
    except ImportError as _pyjwt_exc:
        if _OIDC_JWKS_URI:
            logger.error(
                "❌ OIDC is configured (CAGE_OIDC_JWKS_URI=%s) but PyJWT is not "
                "installed. Install with: pip install PyJWT[crypto]",
                _OIDC_JWKS_URI,
            )
            raise HTTPException(
                status_code=503,
                detail={
                    "error": "oidc_unavailable",
                    "message": "OIDC token validation is configured but PyJWT is not "
                    "installed. Contact the system administrator.",
                },
            ) from _pyjwt_exc
        return {}

    # Step 2: Decode JWT header to get kid — do NOT read 'alg' from header.
    # HIGH-3 fix: algorithm is determined by server-side allowlist
    # (_OIDC_ALLOWED_ALGORITHMS), never by the untrusted JWT header field.
    # Structural validation (3-segment check, valid base64 JSON) always runs when
    # PyJWT is available, so malformed tokens always yield 401.
    try:
        header = _decode_jwt_header(token)
    except ValueError as exc:
        logger.warning("OIDC: malformed JWT header: %s", exc)
        raise HTTPException(
            status_code=401,
            headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
            detail={"error": "invalid_token", "message": "Malformed JWT"},
        )

    kid = header.get("kid", "default")

    # Step 3: If OIDC is not configured, skip JWKS-dependent validation.
    # This path is only reachable when PyJWT IS installed but no JWKS URI is set
    # (token structure was valid above). Return empty identity — backward compat.
    if not _OIDC_JWKS_URI:
        return {}

    # Step 4: Fetch JWKS and find the matching key.
    try:
        jwks = await _fetch_jwks()
    except RuntimeError as exc:
        logger.error("OIDC: JWKS fetch failed: %s", exc)
        raise HTTPException(
            status_code=401,
            headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
            detail={"error": "invalid_token", "message": "JWKS endpoint unavailable"},
        )

    key_data = jwks.get(kid) or jwks.get("default")
    if not key_data or not isinstance(key_data, dict):
        logger.warning("OIDC: no matching key for kid=%s", kid)
        raise HTTPException(
            status_code=401,
            headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
            detail={"error": "invalid_token", "message": f"No JWKS key for kid={kid}"},
        )

    # Step 5: Build PyJWT public key from JWK — try RSA first, fall back to EC.
    try:
        key_kty = key_data.get("kty", "RSA")
        if key_kty == "EC":
            public_key = pyjwt.algorithms.ECAlgorithm.from_jwk(json.dumps(key_data))
        else:
            public_key = pyjwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key_data))  # type: ignore[assignment]
    except Exception as exc:
        logger.warning("OIDC: could not construct public key from JWK: %s", exc)
        raise HTTPException(
            status_code=401,
            headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
            detail={"error": "invalid_token", "message": "Invalid JWKS key format"},
        )

    # Verify and decode the JWT using the server-side algorithm allowlist.
    # HIGH-3 fix: algorithms are hardcoded — never sourced from the JWT header.
    decode_kwargs: dict[str, Any] = {
        "algorithms": _OIDC_ALLOWED_ALGORITHMS,
        "options": {"verify_exp": True},
    }
    if _OIDC_AUDIENCE:
        decode_kwargs["audience"] = _OIDC_AUDIENCE
    if _OIDC_ISSUER:
        decode_kwargs["issuer"] = _OIDC_ISSUER

    try:
        claims = pyjwt.decode(token, public_key, **decode_kwargs)  # type: ignore[arg-type]
    except pyjwt.ExpiredSignatureError:
        logger.warning("OIDC: JWT expired")
        raise HTTPException(
            status_code=401,
            headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
            detail={"error": "invalid_token", "message": "JWT has expired"},
        )
    except pyjwt.InvalidTokenError as exc:
        logger.warning("OIDC: JWT validation failed: %s", exc)
        raise HTTPException(
            status_code=401,
            headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
            detail={"error": "invalid_token", "message": str(exc)},
        )

    caller_identity: dict[str, Any] = {
        "sub": claims.get("sub", ""),
        "iss": claims.get("iss", ""),
        "scope": claims.get("scope", claims.get("scp", "")),
    }
    logger.debug(
        "OIDC: validated caller sub=%s iss=%s",
        caller_identity["sub"],
        caller_identity["iss"],
    )
    return caller_identity


class OIDCValidationMiddleware:
    """ASGI middleware that validates OIDC Bearer JWTs and injects caller_identity.

    Behaviour:
      - If ``CAGE_OIDC_JWKS_URI`` is not set: pass through unchanged (backward compat).
      - If ``Authorization: Bearer <jwt>`` header is absent: pass through unchanged.
      - If JWT is present but invalid: return HTTP 401.
      - If JWT is valid: inject ``request.state.caller_identity`` dict.

    The ``caller_identity`` dict (``{sub, iss, scope}``) is available to all
    downstream handlers via ``request.state.caller_identity``.  OPA policies
    can use ``input.caller_identity.sub`` for RBAC decisions — no changes to
    existing OPA policies required (the field is additive).

    GCP Adaptation note:
      When deployed behind GCP IAP, the IAP JWT is passed as
      ``X-Goog-IAP-JWT-Assertion``.  To use IAP, set CAGE_OIDC_JWKS_URI to
      the IAP JWKS endpoint and read the header name from the environment.
      This is a GCP-specific deployment configuration — no code changes needed.
    """

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # If OIDC is not configured, pass through unchanged (backward compat)
        if not _OIDC_JWKS_URI:
            await self.app(scope, receive, send)
            return

        from starlette.requests import Request as StarletteRequest
        from starlette.responses import JSONResponse as StarletteJSONResponse

        request = StarletteRequest(scope, receive)
        auth_header = request.headers.get("Authorization", "")

        # No Authorization header — pass through unchanged (backward compat)
        if not auth_header.startswith("Bearer "):
            await self.app(scope, receive, send)
            return

        token = auth_header[len("Bearer ") :]

        try:
            caller_identity = await validate_oidc_token(token)
            request.state.caller_identity = caller_identity
        except HTTPException as exc:
            response = StarletteJSONResponse(
                status_code=exc.status_code,
                content=exc.detail,
                headers=exc.headers or {},
            )
            await response(scope, receive, send)
            return

        await self.app(scope, receive, send)


# POST /governance/state-commitments — generic state-commitment service.
governance_app.include_router(state_commitment_router)

# Register the OIDC middleware on the governance_app sub-application.
# It runs before all governance endpoints, injecting caller_identity into
# request.state for OPA agent catalog evaluation.
governance_app.add_middleware(OIDCValidationMiddleware)
