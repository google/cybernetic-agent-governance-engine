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
and OPA.  Also enforces the HMAC-SHA256 ``X-CAGE-Routing-Seal`` (Phase 3.3)
to guarantee that only trusted upstream orchestrators can reach the
governance enforcement surface.

This module is intentionally free of MCP tool definitions and HTTP proxy
logic — those live in ``mcp_tool_server.py`` and ``inference_proxy.py``
respectively.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from opentelemetry import context as otel_context
from opentelemetry.propagate import extract as otel_extract
from pydantic import BaseModel

from src.gateway.governance.iso_control import stamp_iso_control
from src.gateway.governance.kms_signer import get_governance_signer
from src.gateway.governance.prompt_injection_detector import detect_indirect_injection
from src.gateway.governance.routing_seal import SymbolicGovernorViolation
from src.gateway.governance.singletons import symbolic_governor
from src.gateway.governance.symbolic_governor import GovernanceError
from src.gateway.governance.text_filter import ac_keyword_scan

logger = logging.getLogger("Gateway.GovernanceMiddleware")


_CAGE_SEAL_SECRET: str | None = os.environ.get("CAGE_ROUTING_SEAL_SECRET")
_SEAL_HEADER = "X-CAGE-Routing-Seal"
_SEAL_ENFORCEMENT = os.environ.get("CAGE_SEAL_ENFORCEMENT", "enforce").lower()
# Set CAGE_SEAL_ENFORCEMENT=log to log-only without blocking (useful in development).

# CAGE_ENV takes precedence over ENVIRONMENT for forward compatibility.
_ENVIRONMENT: str = (
    os.environ.get("CAGE_ENV") or os.environ.get("ENVIRONMENT", "production")
).lower()

_IS_PRODUCTION: bool = _ENVIRONMENT not in ("development", "test", "dev", "ci")

# CAGE-SEC-001: CAGE_SEAL_ENFORCEMENT=log is prohibited in production.
# In log mode, requests with invalid routing seals are allowed through with only
# a warning — this creates a bypass vector equivalent to disabling seal enforcement.
# Mirror of the CBF_FAIL_OPEN guard in symbolic_governor.py (No-Direct-Bind §3).
if _SEAL_ENFORCEMENT == "log" and _IS_PRODUCTION:
    raise RuntimeError(
        f"CAGE STARTUP FAILURE (CAGE-SEC-001): CAGE_SEAL_ENFORCEMENT=log is set in "
        f"environment '{_ENVIRONMENT}'. Log mode allows requests with invalid routing "
        f"seals to pass through — this is a governance bypass vector equivalent to "
        f"disabling seal enforcement. Set CAGE_SEAL_ENFORCEMENT=enforce (the default) "
        f"or set CAGE_ENV=development to bypass (not for production use)."
    )


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
# POAM-012 — Module-level startup validation of CAGE_ROUTING_SEAL_SECRET
# SC-12 / AC-3: HMAC key must be present and sufficiently strong in all
# non-development environments.  This check runs at import time so the
# service fails fast rather than surfacing the gap on the first live request.
# ---------------------------------------------------------------------------
_HMAC_MIN_LENGTH = 32  # HMAC-SHA256 security minimum (256-bit key)

if not _CAGE_SEAL_SECRET:
    if _ENVIRONMENT not in ("development", "test"):
        raise RuntimeError(
            "CAGE_ROUTING_SEAL_SECRET must be set in non-development environments (POAM-012). "
            "Generate a cryptographically random secret of at least 32 characters and export it "
            "as CAGE_ROUTING_SEAL_SECRET.  To bypass in local dev, set CAGE_ENV=development or "
            "ENVIRONMENT=development."
        )
    logger.warning(
        "⚠️  POAM-012: CAGE_ROUTING_SEAL_SECRET is not set. "
        "Routing seal verification is DISABLED. "
        "Acceptable only in development/test environments — never in production."
    )
elif len(_CAGE_SEAL_SECRET) < _HMAC_MIN_LENGTH:
    raise RuntimeError(
        f"CAGE_ROUTING_SEAL_SECRET is set but is only {len(_CAGE_SEAL_SECRET)} characters long. "
        f"A minimum of {_HMAC_MIN_LENGTH} characters is required for HMAC-SHA256 security (POAM-012)."
    )


def _verify_routing_seal(request: Request, body_bytes: bytes) -> bool:
    """Verify the HMAC-SHA256 routing seal on an incoming request.

    The upstream API gateway computes:
        HMAC-SHA256(key=CAGE_ROUTING_SEAL_SECRET, msg=<raw request body bytes>)
    and places the hex digest in the ``X-CAGE-Routing-Seal`` header.

    Returns ``True`` if the seal is valid or if enforcement is disabled.
    """
    # SC-12 / AC-3 Control: CAGE_ROUTING_SEAL_SECRET must be set in production.
    # NIST SP 800-53 SC-12 requires cryptographic key establishment for system integrity.
    # POAM-012: Enforced via RuntimeError in non-development environments (2026-04-01).
    if not _CAGE_SEAL_SECRET:
        if _ENVIRONMENT not in ("development", "test"):
            raise RuntimeError(
                "CAGE_ROUTING_SEAL_SECRET is not set. Routing seal enforcement cannot be "
                "disabled in non-development environments. Set CAGE_ROUTING_SEAL_SECRET or "
                "set ENVIRONMENT=development to bypass (not for production use)."
            )
        logger.warning(
            "⚠️ CAGE_ROUTING_SEAL_SECRET not set — routing seal verification DISABLED. "
            "This is only acceptable in development/test environments."
        )
        return True  # Bypass allowed only in development/test

    provided_seal = request.headers.get(_SEAL_HEADER, "")
    if not provided_seal:
        logger.warning(
            "Missing %s header on request to %s", _SEAL_HEADER, request.url.path
        )
        return False

    expected = hmac.new(
        _CAGE_SEAL_SECRET.encode(),
        body_bytes,
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(expected, provided_seal.lower())


def enforce_routing_seal(request: Request, body_bytes: bytes) -> None:
    """Raise HTTP 403 if the routing seal is invalid and enforcement is active.

    In ``log`` mode the violation is recorded but the request is allowed through.
    In ``enforce`` mode (default) an HTTP 403 is raised.
    """
    if _verify_routing_seal(request, body_bytes):
        return

    if _SEAL_ENFORCEMENT == "log":
        logger.warning(
            "🔓 Routing seal INVALID for %s — enforcement=log, allowing through.",
            request.url.path,
        )
        return

    logger.error(
        "🔒 Routing seal INVALID for %s — rejecting request.", request.url.path
    )
    raise HTTPException(
        status_code=403,
        detail={
            "error": "invalid_routing_seal",
            "message": (
                f"Request missing or has an invalid {_SEAL_HEADER} header. "
                "Only trusted upstream orchestrators may invoke this endpoint."
            ),
        },
    )


# ---------------------------------------------------------------------------
# Governance enforcement helpers
# ---------------------------------------------------------------------------


async def enforce_governance(tool_name: str, params: dict[str, Any]) -> str:
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
        seal = await symbolic_governor.govern(tool_name, params)
        return seal
    except GovernanceError as exc:
        logger.warning("🛡️ Symbolic Governor BLOCKED %s: %s", tool_name, exc)
        await _emit_refusal_receipt(
            action_id=tool_name,
            refusal_reason=str(exc),
            oscal_control_ref="SC-4",
            params=params,
        )
        raise PermissionError(f"Governance Blocked: {exc}")


async def tier1_keyword_check(text: str, span: Any = None) -> str | None:
    """Run Tier-1 Aho-Corasick keyword scan.

    Returns a violation message if blocked, else None.
    Stamps the ISO 42001 evidence attribute on *span* when provided.
    """
    if ac_keyword_scan(text):
        stamp_iso_control(span, tier=1, control="A.5.2", outcome="BLOCK")
        return "keyword_match"
    stamp_iso_control(span, tier=1, control="A.5.2", outcome="PASS")
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
        stamp_iso_control(span, tier=2, control="A.9.2", outcome="BLOCK")
        logger.warning(
            '🔴 [AI600-003] MCP tool response rejected: tool=%s pattern=%s "\n'
            "(ISO 42001 A.9.2 — indirect injection blocked)",
            tool_name,
            result.pattern_matched,
        )
        return f"indirect_injection:{result.pattern_matched}"
    stamp_iso_control(span, tier=2, control="A.9.2", outcome="PASS")
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
_validate_action_rate_buckets: dict[str, list[float]] = defaultdict(list)

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


def _check_validate_action_rate_limit(client_ip: str) -> bool:
    """Return True if the request is within the rate limit, False if exceeded.

    Uses a sliding window algorithm: timestamps older than the window are
    evicted on each check.  Thread-safe under Python's GIL for single-process
    deployments.

    MED-3: In multi-pod Kubernetes deployments this limiter is per-pod.
    See the module-level comment above for the Redis-backed alternative.
    """
    now = time.monotonic()
    window_start = now - _RATE_LIMIT_WINDOW
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


class GovernanceCheckRequest(dict):
    pass  # plain dict accepted via Request


@governance_app.post("/check")
async def governance_check(request: Request) -> JSONResponse:
    """Internal endpoint: run a governance dry-run check against a proposed tool call.

    Requires a valid X-CAGE-Routing-Seal.

    Request body (JSON):
        {"tool_name": str, "params": dict}
    """
    body_bytes = await request.body()
    enforce_routing_seal(request, body_bytes)

    try:
        body = json.loads(body_bytes)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON body.")

    tool_name: str = body.get("tool_name", "")
    params: dict[str, Any] = body.get("params", {})

    if not tool_name:
        raise HTTPException(status_code=400, detail="'tool_name' is required.")

    result = await symbolic_governor.verify(tool_name, params)
    violations = result.get("violations", [])
    return JSONResponse(
        content={
            "status": "APPROVED" if not violations else "REJECTED",
            "violations": violations,
            "opa_results": result.get("opa_results"),
        }
    )


# ---------------------------------------------------------------------------
# /validate-action — Unified Governance Routing (Option 2)
# ---------------------------------------------------------------------------


class ValidateActionRequest(BaseModel):
    """Payload for POST /governance/validate-action."""

    action: str
    params: dict[str, Any]
    policy_version_id: str | None = None


# ---------------------------------------------------------------------------
# P4 — KMS-verified governance signature check
# ---------------------------------------------------------------------------


def _verify_governance_signature(governance_signature: str, payload_plan: dict) -> None:
    """Verify a KMS-backed governance signature against a plan payload.

    Replaces the previous truthy check (``if governance_signature:``) with a
    call to the KMS asymmetric verifier.  A missing or invalid signature raises
    ``SymbolicGovernorViolation`` so the failure cannot be silently ignored.

    Verification algorithm:
        The ``KMSGovernanceSigner.verify()`` method computes a SHA-256 digest
        of the canonical JSON plan (``json.dumps(plan, sort_keys=True,
        separators=(",", ":"))``), then verifies the provided signature against
        the Cloud KMS public key using EC-DSA (SHA-256 prehashed) or RSA-PSS
        as appropriate for the configured key type.

    Key reference:
        ``KMS_GOVERNANCE_KEY`` environment variable — full Cloud KMS key
        version resource name (e.g.
        ``projects/my-proj/locations/us-central1/keyRings/cage-governance/
        cryptoKeys/plan-signer/cryptoKeyVersions/1``).

    Expected digest format:
        The ``governance_signature`` argument must be a lowercase hex-encoded
        byte string produced by ``KMSGovernanceSigner.sign(plan_dict)``.

    Args:
        governance_signature: Hex-encoded KMS signature string.
        payload_plan:         The governance plan dict that was signed.

    Raises:
        SymbolicGovernorViolation: If the signature is absent, empty, or fails
            cryptographic verification.
    """
    if not governance_signature:
        raise SymbolicGovernorViolation(
            "governance_signature is absent or empty — KMS verification cannot proceed",
            action="governance_check",
        )

    try:
        signer = get_governance_signer()
        valid = signer.verify(plan=payload_plan, signature_hex=governance_signature)
    except Exception as exc:
        raise SymbolicGovernorViolation(
            f"KMS verifier raised an unexpected error: {exc}",
            action="governance_check",
        ) from exc

    if not valid:
        raise SymbolicGovernorViolation(
            "KMS signature verification failed — governance plan may be tampered",
            action="governance_check",
        )

    logger.debug(
        "✅ KMS governance signature verified (algorithm=%s)",
        getattr(get_governance_signer(), "signing_algorithm", "UNKNOWN"),
    )


# ---------------------------------------------------------------------------
# P6 — Signed OSCAL compliance receipt on GovernanceError (hard refusal)
# ---------------------------------------------------------------------------


async def _emit_refusal_receipt(
    action_id: str,
    refusal_reason: str,
    oscal_control_ref: str,
    params: dict[str, Any],
) -> None:
    """Emit a signed OSCAL compliance receipt for a hard governance refusal.

    Called from every ``GovernanceError`` handler in this module.  The receipt
    is signed via ``KMSGovernanceSigner.sign()`` and published to the evidence
    stream via ``EvidenceStreamSink.ingest()``.

    If OSCAL emission itself fails, the error is logged at ERROR level but the
    original ``GovernanceError`` is NOT suppressed — the refusal must still
    propagate to the caller.

    Receipt fields:
        - ``action_id``         : tool / action name that was refused
        - ``refusal_reason``    : human-readable violation description
        - ``timestamp_utc``     : ISO 8601 UTC timestamp of the refusal
        - ``oscal_control_ref`` : OSCAL control ID (e.g. ``"SC-4"``)
        - ``kms_signature``     : hex-encoded KMS signature of the receipt
        - ``receipt_id``        : UUID v4 for idempotent deduplication

    Args:
        action_id:         The tool / action name that triggered the refusal.
        refusal_reason:    The ``str(exc)`` of the ``GovernanceError``.
        oscal_control_ref: OSCAL control reference (e.g. ``"SC-4"``).
        params:            Original action parameters (used for context only).
    """
    receipt_id = str(uuid.uuid4())
    timestamp_utc = datetime.now(tz=timezone.utc).isoformat()

    receipt: dict[str, Any] = {
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
        signable = {k: v for k, v in receipt.items() if k != "kms_signature"}
        receipt["kms_signature"] = signer.sign(signable)
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
        from src.compliance_bridge.evidence_stream import (
            get_evidence_sink,
        )

        sink = get_evidence_sink()
        await sink.ingest(receipt)
        # MED-7 fix: a successfully emitted refusal receipt is not an error —
        # logging it at ERROR level polluted error dashboards with normal events.
        logger.info(
            "🔴 [P6] Signed OSCAL refusal receipt emitted: action='%s' "
            "control='%s' receipt_id=%s kms_signed=%s",
            action_id,
            oscal_control_ref,
            receipt_id,
            bool(receipt["kms_signature"]),
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
        ``cage.tool_execute`` root span, producing a unified Langfuse trace
        tree across the service boundary.

    Governance tiers executed (full 7-tier pipeline via _run_checks()):
        - Tier 0: STPA/STAMP Unsafe Control Action validation
        - Tier 1: Agent confidence threshold pre-check (fast-fail)
        - Tier 2: Control Barrier Function (CBF) — mathematical safety bounds
          (runs concurrently with Tier 4 OPA check via asyncio.gather)
        - Tier 3: Fiscal Limit Pre-Reservation — atomic Redis WATCH/MULTI/EXEC
        - Tier 4: OPA Rego policy evaluation — declarative rule enforcement
          (CBF and OPA run concurrently via asyncio.gather for execute_trade)
        - Tier 5: Multi-agent Consensus gate (ISO 42001)
        - Tier 6: DoWhy Causal Gatekeeper — refutation-based safety lock
        - Tier 6b: Adaptive FRIA Enforcement (EU AI Act Art. 29a)

    The routing seal is issued ONLY after all tiers pass — a seal issued
    before full pipeline completion would imply governance approval that
    was never actually granted.

    Returns:
        JSON with ``verdict`` (APPROVED|DENIED), ``violations`` list,
        ``seal`` (HMAC-SHA256 routing seal on approval), and ``latency_ms``.
    """
    # ── GHSA-v3h4-8458-5ww3: Enforce routing seal FIRST, before any processing.
    # Without this check, unauthenticated callers could trigger DoS or use the
    # endpoint as a governance configuration oracle.
    body_bytes = await request.body()
    enforce_routing_seal(request, body_bytes)

    # ── Rate limiting: prevent DoS via rapid unauthenticated requests ─────────
    # HIGH-5 fix: only trust X-Forwarded-For when the direct TCP connection
    # comes from a known trusted proxy (load balancer / ingress controller).
    # Untrusted sources use the direct connection IP so attackers cannot spoof
    # their IP to bypass the per-IP rate limit.
    direct_ip = request.client.host if request.client else "unknown"
    if _is_trusted_proxy(direct_ip):
        xff = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        client_ip = xff if xff else direct_ip
    else:
        client_ip = direct_ip
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
    # symbolic_governor.validate_action() (cage.cbf_action_check,
    # cage.opa_action_check, cage.routing_seal) are children of the GFA's
    # cage.tool_execute span in Langfuse — not orphaned fragments.
    carrier = dict(request.headers)
    remote_ctx = otel_extract(carrier)
    token = otel_context.attach(remote_ctx)

    try:
        result = await symbolic_governor.validate_action(
            action=body.action,
            params=body.params,
            policy_version_id=body.policy_version_id,
        )
        return JSONResponse(content=result)

    except GovernanceError as exc:
        # P6: emit a signed OSCAL compliance receipt for every hard refusal.
        # Errors during emission are logged but do NOT suppress the refusal.
        await _emit_refusal_receipt(
            action_id=body.action,
            refusal_reason=str(exc),
            oscal_control_ref="SC-4",
            params=body.params,
        )
        return JSONResponse(
            status_code=403,
            content={
                "verdict": "DENIED",
                "violations": [str(exc)],
                "seal": "",
                "latency_ms": 0,
            },
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

# JWKS cache: {kid: public_key_pem, "_fetched_at": float}
_jwks_cache: dict[str, Any] = {}
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
        return _jwks_cache

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
    return _jwks_cache


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

    # Add padding
    header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
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
    try:
        import jwt as pyjwt  # PyJWT
    except ImportError as _pyjwt_exc:
        # HIGH-2 fix: when OIDC is configured, a missing PyJWT dependency must
        # be a hard failure — silently returning {} accepted any token without
        # verification, creating a complete authentication bypass.
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

    # Decode header to get kid for JWKS lookup — do NOT read 'alg' from header.
    # HIGH-3 fix: the algorithm is determined by the server-side allowlist
    # (_OIDC_ALLOWED_ALGORITHMS), never by the untrusted JWT header field.
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
    # HIGH-3: 'alg' is intentionally NOT read from the header here.

    # Fetch JWKS and find the matching key
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

    # Build PyJWT public key from JWK — try RSA first, fall back to EC.
    try:
        key_kty = key_data.get("kty", "RSA")
        if key_kty == "EC":
            public_key = pyjwt.algorithms.ECAlgorithm.from_jwk(json.dumps(key_data))
        else:
            public_key = pyjwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key_data))
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
        claims = pyjwt.decode(token, public_key, **decode_kwargs)
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


# Register the OIDC middleware on the governance_app sub-application.
# It runs before all governance endpoints, injecting caller_identity into
# request.state for OPA agent catalog evaluation.
governance_app.add_middleware(OIDCValidationMiddleware)
