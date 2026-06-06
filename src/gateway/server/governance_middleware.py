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
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from opentelemetry import context as otel_context
from opentelemetry.propagate import extract as otel_extract
from pydantic import BaseModel

from src.gateway.governance.singletons import symbolic_governor, opa_client
from src.gateway.governance.symbolic_governor import GovernanceError
from src.gateway.governance.text_filter import ac_keyword_scan
from src.gateway.governance.iso_control import stamp_iso_control
from src.gateway.governance.schemas.thresholds import THRESHOLDS
from src.gateway.governance.routing_seal import SymbolicGovernorViolation
from src.gateway.governance.kms_signer import get_governance_signer

logger = logging.getLogger("Gateway.GovernanceMiddleware")


_CAGE_SEAL_SECRET: Optional[str] = os.environ.get("CAGE_ROUTING_SEAL_SECRET")
_SEAL_HEADER = "X-CAGE-Routing-Seal"
_SEAL_ENFORCEMENT = os.environ.get("CAGE_SEAL_ENFORCEMENT", "enforce").lower()
# Set CAGE_SEAL_ENFORCEMENT=log to log-only without blocking (useful in development).

# CAGE_ENV takes precedence over ENVIRONMENT for forward compatibility.
_ENVIRONMENT: str = (
    os.environ.get("CAGE_ENV") or os.environ.get("ENVIRONMENT", "production")
).lower()

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
        logger.warning("Missing %s header on request to %s", _SEAL_HEADER, request.url.path)
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

async def enforce_governance(tool_name: str, params: Dict[str, Any]) -> str:
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


async def tier1_keyword_check(text: str, span: Any = None) -> Optional[str]:
    """Run Tier-1 Aho-Corasick keyword scan.

    Returns a violation message if blocked, else None.
    Stamps the ISO 42001 evidence attribute on *span* when provided.
    """
    if ac_keyword_scan(text):
        stamp_iso_control(span, tier=1, control="A.5.2", outcome="BLOCK")
        return "keyword_match"
    stamp_iso_control(span, tier=1, control="A.5.2", outcome="PASS")
    return None


# ---------------------------------------------------------------------------
# Minimal FastAPI sub-application for the middleware surface
# (mounted by mcp_tool_server under /governance)
# ---------------------------------------------------------------------------

governance_app = FastAPI(title="CAGE Governance Middleware")


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
    params: Dict[str, Any] = body.get("params", {})

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
    params: Dict[str, Any]


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
    params: Dict[str, Any],
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

    receipt: Dict[str, Any] = {
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
        from src.compliance_bridge.evidence_stream import get_evidence_sink  # noqa: PLC0415
        sink = get_evidence_sink()
        await sink.ingest(receipt)
        logger.error(
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
        - Tier 3: OPA Rego policy evaluation — declarative rule enforcement
          (CBF and OPA run concurrently via asyncio.gather for execute_trade)
        - Tier 4: Fiscal Limit Pre-Reservation — atomic Redis WATCH/MULTI/EXEC
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
    except Exception as exc:
        logger.error("❌ validate_action internal error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))
    finally:
        otel_context.detach(token)
