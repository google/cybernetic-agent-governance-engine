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

import hashlib
import inspect
import json
import logging
import math
import os
import uuid
from collections.abc import Callable
from contextlib import AsyncExitStack
from contextvars import ContextVar, Token
from datetime import datetime, timezone
from typing import Any, NoReturn

from fastapi import FastAPI, HTTPException, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from opentelemetry import context as otel_context
from opentelemetry.propagate import extract as otel_extract
from pydantic import BaseModel, Field, field_validator

from src.gateway.governance.decisions import GovernanceDecision
from src.gateway.governance.evidence.stream import get_evidence_sink
from src.gateway.governance.governance_envelope import GovernanceEnvelopeBuilder
from src.gateway.governance.governor.approval import PostHitlApproval
from src.gateway.governance.governor.errors import GovernanceDeferred
from src.gateway.governance.governor.governor import GovernanceError, SymbolicGovernor
from src.gateway.governance.governor.metrics import governor_metrics
from src.gateway.governance.governor.pipeline import OpaVerdict
from src.gateway.governance.governor.stages.opa import decode_opa_verdict
from src.gateway.governance.iso_control import stamp_iso_control
from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
from src.gateway.governance.kms_signer import get_governance_signer
from src.gateway.governance.prompt_injection_detector import detect_indirect_injection
from src.gateway.governance.text_filter import ac_keyword_scan
from src.gateway.observability.mcp_tracing import sanitize_trace_carrier
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


_last_refusal_proof_hash: ContextVar[str | None] = ContextVar(
    "cage_last_refusal_proof_hash", default=None
)


def set_last_refusal_proof_hash(proof_hash: str | None) -> Token[str | None]:
    """Bind ``proof_hash`` for the current execution task."""
    return _last_refusal_proof_hash.set(proof_hash)


def get_last_refusal_proof_hash() -> str | None:
    """Return the most recent refusal ``proof_hash`` bound in this task."""
    return _last_refusal_proof_hash.get()


def reset_last_refusal_proof_hash(token: Token[str | None]) -> None:
    """Restore ``_last_refusal_proof_hash`` to its prior value."""
    _last_refusal_proof_hash.reset(token)


class GovernanceBlockedError(PermissionError):
    """A :class:`PermissionError` carrying the refusal's ``proof_hash``."""

    def __init__(
        self, message: str, *, proof_hash: str = "", violated_tier: str = ""
    ) -> None:
        super().__init__(message)
        self.proof_hash: str = proof_hash
        self.violated_tier: str = violated_tier


class ActionDeferred(PermissionError):
    """The committing run deferred: nothing was sealed, committed or refused.

    A :class:`PermissionError`, so every caller that only needs to stop
    still fails closed. ``deferred_id`` names the record that stays
    resolvable: a freshly parked token on the plain committing run, or the
    retained approval itself after a post-approval deferral
    (``approval_retained``). ``defer_reason`` and ``reliance`` say why.
    """

    def __init__(self, cause: GovernanceDeferred, *, approval_retained: bool) -> None:
        super().__init__(f"Governance Deferred: {cause}")
        self.deferred_id: str = cause.deferred_id
        self.defer_reason: str = cause.defer_reason
        self.reliance: list[dict[str, Any]] = list(cause.reliance)
        self.approval_retained: bool = approval_retained


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
        ActionDeferred: The committing run deferred (an ineligible warrant).
        PermissionError: If the governor blocks the action.
    """
    if tool_name in {"verify_content_safety"}:
        return ""  # Exempt kernel-internal read-only tools from governance overhead

    try:
        seal = await governor.govern(tool_name, params)
        return seal
    except GovernanceDeferred as exc:
        # A warrant failure removes reliance; it is never a refusal. The
        # deferral (parked token + GOVERNANCE_DEFERRAL) is already evidenced.
        logger.info("🕒 Symbolic Governor DEFERRED %s: %s", tool_name, exc)
        raise ActionDeferred(exc, approval_retained=False) from exc
    except GovernanceError as exc:
        logger.warning("🛡️ Symbolic Governor BLOCKED %s: %s", tool_name, exc)
        emitted = await _emit_refusal_receipt(
            action_id=tool_name,
            refusal_reason=str(exc),
            oscal_control_ref="SC-4",
            params=params,
            receipt=exc.receipt,
        )
        receipt_hash = (
            str(getattr(exc.receipt, "proof_hash", "") or "")
            if exc.receipt is not None
            else ""
        )
        resolved_hash = (
            emitted if isinstance(emitted, str) and emitted else receipt_hash
        )
        if resolved_hash:
            set_last_refusal_proof_hash(resolved_hash)
        raise GovernanceBlockedError(
            f"Governance Blocked: {exc}",
            proof_hash=resolved_hash,
            violated_tier=str(getattr(exc.receipt, "violated_tier", "") or "")
            if exc.receipt is not None
            else "",
        ) from exc


async def enforce_approved_governance(
    governor: SymbolicGovernor,
    tool_name: str,
    params: dict[str, Any],
    *,
    deferred_id: str,
    approval_covers: Callable[[dict[str, Any], dict[str, Any]], bool],
) -> str:
    """Commit and seal a human-approved action: the post-approval committing run.

    1. Check that the ``HITL_REQUIRED`` token ``deferred_id`` in the gateway's
       DeferQueue is redeemable (``DeferQueue.redeemable_approval``): quorum-
       approved, unspent, parked for ``tool_name``, and
       ``approval_covers(approved_params, params)`` holds, so an approval for
       one action cannot authorise a different or larger one. Nothing is
       spent yet.
    2. Run ``SymbolicGovernor.revalidate_post_hitl()`` (POST_HITL profile) on
       the fresh ``params``, handing it the approval bound to its
       ``barrier_preview``, to the human-review holds the reviewer was shown
       (``DeferToken.hitl_holds``; a hold outside them refuses the run) and
       to a ``spend`` that re-checks the token and
       consumes it with the ``RESOLVED -> CONSUMED`` compare-and-swap
       (``DeferQueue.consume_approval``). The governor spends it only when
       it seals (a replayed or concurrent ``deferred_id`` loses the swap and
       seals nothing) or refuses; a warrant-ineligible DEFER leaves it
       unspent, so the same approval redeems once the warrant returns
       (POAM-2026-104).

    Returns:
        The routing seal for ``params``.

    Raises:
        ActionDeferred: Post-approval re-validation deferred; the approval
            is retained (``approval_retained``).
        PermissionError: The approval is missing, unapproved, mismatched,
            expired or already consumed, or post-approval re-validation
            refused.
    """
    from src.gateway.governance.defer_queue import open_defer_queue

    def _covers(approved: dict[str, Any]) -> bool:
        try:
            return bool(approval_covers(approved, params))
        except Exception as exc:  # a raising matcher never authorises
            logger.warning("approval_covers raised for %s: %s", tool_name, exc)
            return False

    async def _refuse_unredeemable() -> NoReturn:
        reason = f"no unconsumed approval {deferred_id!r} covers this {tool_name}"
        emitted = await _emit_refusal_receipt(
            action_id=tool_name,
            refusal_reason=reason,
            oscal_control_ref="AC-3",
            params=params,
            receipt_expected=False,
        )
        resolved_hash = emitted if isinstance(emitted, str) else ""
        if resolved_hash:
            set_last_refusal_proof_hash(resolved_hash)
        raise GovernanceBlockedError(
            f"Governance Blocked: {reason}",
            proof_hash=resolved_hash,
            violated_tier="MIDDLEWARE",
        )

    try:
        async with AsyncExitStack() as stack:
            try:
                queue = await stack.enter_async_context(open_defer_queue())
                token = await queue.redeemable_approval(
                    deferred_id, action=tool_name, covers=_covers
                )
            except Exception as exc:  # queue unreachable: no approval can be proven
                logger.error("DeferQueue unavailable checking %s: %s", deferred_id, exc)
                token = None
            if token is None:
                await _refuse_unredeemable()

            async def _spend() -> bool:
                try:
                    spent = await queue.consume_approval(
                        deferred_id, action=tool_name, covers=_covers
                    )
                except Exception as exc:  # unprovable spend never authorises
                    logger.error(
                        "DeferQueue unavailable spending %s: %s", deferred_id, exc
                    )
                    return False
                return spent is not None

            approval = PostHitlApproval(
                approval_id=deferred_id,
                barrier_preview=token.barrier_preview,
                spend=_spend,
                thread_id=token.thread_id,
                approved_holds=token.hitl_holds,
            )
            return await governor.revalidate_post_hitl(
                tool_name, params, approval=approval
            )
    except GovernanceDeferred as exc:
        # Primary evidence is already hash-chained (GOVERNANCE_DEFERRAL naming
        # the approval); a deferral is not a refusal, so no refusal receipt.
        logger.info("🕒 Post-approval re-validation DEFERRED %s: %s", tool_name, exc)
        raise ActionDeferred(exc, approval_retained=True) from exc
    except GovernanceError as exc:
        logger.warning("🛡️ Post-approval re-validation BLOCKED %s: %s", tool_name, exc)
        emitted = await _emit_refusal_receipt(
            action_id=tool_name,
            refusal_reason=str(exc),
            oscal_control_ref="SC-4",
            params=params,
            receipt=exc.receipt,
        )
        receipt_hash = (
            str(getattr(exc.receipt, "proof_hash", "") or "")
            if exc.receipt is not None
            else ""
        )
        resolved_hash = (
            emitted if isinstance(emitted, str) and emitted else receipt_hash
        )
        if resolved_hash:
            set_last_refusal_proof_hash(resolved_hash)
        raise GovernanceBlockedError(
            f"Governance Blocked: {exc}",
            proof_hash=resolved_hash,
            violated_tier=str(getattr(exc.receipt, "violated_tier", "") or "")
            if exc.receipt is not None
            else "",
        ) from exc


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
# Shared, principal-keyed GCRA rate limiter for /validate-action (GHSA-v3h4-8458-5ww3, A4)
#
# Enforces dual-bucket GCRA limits in Redis across gateway replicas:
#   - rl:validate-action:id:{l5d-client-id} (fleet workload identity budget)
#   - rl:validate-action:p:{principal}      (per end-user or session budget)
# ---------------------------------------------------------------------------

from src.gateway.server.rate_limit import (
    DEFAULT_PRINCIPAL_PER_MIN,
    DEFAULT_WINDOW_SECONDS,
    RateLimitVerdict,
    get_shared_rate_limiter,
)

_RATE_LIMIT_MAX: int = int(
    os.environ.get(
        "CAGE_RATE_LIMIT_PRINCIPAL_PER_MIN",
        os.environ.get("VALIDATE_ACTION_RATE_LIMIT", str(DEFAULT_PRINCIPAL_PER_MIN)),
    )
)
_RATE_LIMIT_WINDOW: int = int(
    os.environ.get(
        "CAGE_RATE_LIMIT_WINDOW_SECONDS",
        os.environ.get("VALIDATE_ACTION_RATE_WINDOW", str(int(DEFAULT_WINDOW_SECONDS))),
    )
)

# Retained alias pointing to the shared fallback bucket cache for test reset helpers.
_validate_action_rate_buckets = get_shared_rate_limiter()._fallback_tat


async def _check_validate_action_rate_limit(request: Request) -> RateLimitVerdict:
    """Evaluate the dual-bucket GCRA rate limit for ``POST /governance/validate-action``."""
    return await get_shared_rate_limiter().check_request(
        request,
        "validate-action",
        principal_per_min=_RATE_LIMIT_MAX,
        window_seconds=float(_RATE_LIMIT_WINDOW),
    )


# ---------------------------------------------------------------------------
# /validate-action — Unified Governance Routing (Option 2)
# ---------------------------------------------------------------------------


def _check_non_finite_recursive(obj: Any, path: str = "params") -> None:
    """Recursively reject NaN and Infinity across dicts, lists, and tuples."""
    if isinstance(obj, float) and not math.isfinite(obj):
        raise ValueError(
            f"{path} contains non-finite float {obj!r} "
            "— NaN and Infinity are not permitted"
        )
    if isinstance(obj, dict):
        for key, val in obj.items():
            _check_non_finite_recursive(val, f"{path}[{key!r}]")
    elif isinstance(obj, (list, tuple)):
        for idx, item in enumerate(obj):
            _check_non_finite_recursive(item, f"{path}[{idx}]")


class ValidateActionRequest(BaseModel):
    """Payload for POST /governance/validate-action."""

    action: str
    params: dict[str, Any]
    policy_version_id: str | None = None

    @field_validator("params")
    @classmethod
    def _reject_non_finite_floats(cls, v: dict[str, Any]) -> dict[str, Any]:
        _check_non_finite_recursive(v, "params")
        return v


class PolicyPrecheckRequest(BaseModel):
    """Payload for POST /governance/policy-precheck (advisory OPA dry-run)."""

    action: str
    params: dict[str, Any] = Field(default_factory=dict)

    @field_validator("action")
    @classmethod
    def _reject_blank_action(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("action must be a non-empty string")
        return cleaned

    @field_validator("params")
    @classmethod
    def _reject_non_finite_floats(cls, v: dict[str, Any]) -> dict[str, Any]:
        _check_non_finite_recursive(v, "params")
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


async def record_refusal(
    action_id: str,
    refusal_reason: str,
    *,
    oscal_control_ref: str,
    params: dict[str, Any],
) -> str:
    """Record a refusal decided outside the governor in the evidence stream.

    Such a refusal has no tier ``RefusalReceipt`` (for example, a resubmitted
    idempotency key the execution ledger turned away), so its summary receipt
    is signed and ingested like every other refusal in this module.
    """
    return await _emit_refusal_receipt(
        action_id=action_id,
        refusal_reason=refusal_reason,
        oscal_control_ref=oscal_control_ref,
        params=params,
        receipt_expected=False,
    )


async def _emit_refusal_receipt(
    action_id: str,
    refusal_reason: str,
    oscal_control_ref: str,
    params: dict[str, Any],
    receipt: Any = None,
    *,
    receipt_expected: bool = True,
) -> str:
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
        receipt_expected:  False for a refusal decided outside the governor,
                           which never has a RefusalReceipt to attach.
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
        proof_hash = str(
            receipt_payload.get("proof_hash")
            or getattr(receipt, "proof_hash", "")
            or ""
        )
    else:
        # Degraded path: emit summary form when receipt is None
        # Log a warning to make this visible — silently emitting thin receipts
        # is how the defect arose in the first place.
        if receipt_expected:
            logger.warning(
                "⚠️ [A2] Emitting degraded refusal receipt (receipt=None): "
                "action='%s' — tier_failures and proof_hash unavailable. "
                "This indicates GovernanceError was raised without a receipt.",
                action_id,
            )
        computed_hash = hashlib.sha256(
            jcs_canonicalize_plan(
                {
                    "action_id": action_id,
                    "oscal_control_ref": oscal_control_ref,
                    "receipt_id": receipt_id,
                    "refusal_reason": refusal_reason,
                    "timestamp_utc": timestamp_utc,
                }
            )
        ).hexdigest()
        receipt_payload = {
            "type": "GOVERNANCE_REFUSAL_RECEIPT",
            "receipt_id": receipt_id,
            "action_id": action_id,
            "refusal_reason": refusal_reason,
            "timestamp_utc": timestamp_utc,
            "oscal_control_ref": oscal_control_ref,
            "kms_signature": "",
        }
        if receipt_expected:
            receipt_payload["receipt_digest"] = computed_hash
        else:
            receipt_payload["proof_hash"] = computed_hash
        proof_hash = computed_hash
        governor_metrics().refusal_decided("MIDDLEWARE")

    if proof_hash:
        set_last_refusal_proof_hash(proof_hash)

    # Sign the receipt via KMS
    try:
        signer = get_governance_signer()
        # Sign a stable subset of the receipt (exclude kms_signature itself)
        signable = {k: v for k, v in receipt_payload.items() if k != "kms_signature"}
        receipt_payload["kms_signature"] = await signer.sign_async(signable)
    except Exception as sign_exc:
        logger.error(
            "❌ [P6] Failed to KMS-sign refusal receipt for action '%s' "
            "(receipt_id=%s): %s — receipt will be emitted unsigned.",
            action_id,
            receipt_id,
            sign_exc,
        )

    # Publish to evidence stream
    from src.gateway.governance.evidence.stream import (
        commit_decision_evidence,
        is_evidence_chain_blocking,
    )

    try:
        sink = get_evidence_sink()
        await commit_decision_evidence(
            receipt_payload,
            label="GOVERNANCE_REFUSAL_RECEIPT",
            sink=sink,
            sentinel_unset=False,
        )
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
        governor_metrics().evidence_publish_failure("refusal_receipt")
        logger.error(
            "❌ [P6] Failed to emit OSCAL refusal receipt for action '%s' "
            "(receipt_id=%s): %s",
            action_id,
            receipt_id,
            emit_exc,
        )
        if is_evidence_chain_blocking():
            raise
    return proof_hash


@governance_app.get("/policy-version")
async def get_policy_version_endpoint() -> JSONResponse:
    """Retrieve the active policy hash and thresholds digest for session pinning."""
    from src.gateway.governance.constants import ControlRegistry
    from src.gateway.governance.schemas.thresholds import thresholds_digest

    return JSONResponse(
        content={
            "active_hash": ControlRegistry().active_hash,
            "thresholds_digest": thresholds_digest(),
        }
    )


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


@governance_app.post("/policy-precheck")
async def policy_precheck_endpoint(
    request: Request,
    body: PolicyPrecheckRequest,
) -> JSONResponse:
    """Side-effect-free OPA policy pre-check over the gateway's UDS sidecar (D-195-3, F-100).

    Binds server-authoritative parameters via ``governor.bind_server_inputs()``
    (resolving ``trader_role``, ``approval_token``, ``semantic_score``, etc. and
    stripping spoofed caller values) before evaluating the active domain's Rego
    package via ``governor.components.opa.evaluate_policy()``. Caller workload
    identity is enforced by ``WorkloadIdentityMiddleware`` and principal rate
    limits match ``/governance/validate-action``.

    Invariants (ADR-008):
        - Never mints a routing seal or signs a governance envelope.
        - Never mutates CBF state, fiscal reservations, or ``DeferQueue``.
        - Overrides spoofed caller server-bound inputs via ``bind_server_inputs()``.
        - Fails closed to ``"DENY"`` on any OPA error or undecodable verdict.
    """
    rl_res = await _check_validate_action_rate_limit(request)
    if inspect.isawaitable(rl_res):
        rl_res = await rl_res
    if isinstance(rl_res, bool):
        rl_verdict = RateLimitVerdict(
            allowed=rl_res, retry_after_seconds=1 if not rl_res else 0
        )
    else:
        rl_verdict = rl_res
    if not rl_verdict.allowed:
        retry_after = max(1, int(rl_verdict.retry_after_seconds or 1))
        return JSONResponse(
            status_code=429,
            headers={"Retry-After": str(retry_after)},
            content={
                "error": "rate_limit_exceeded",
                "scope": rl_verdict.scope or "principal",
                "retry_after_seconds": retry_after,
            },
        )

    from src.gateway.server.quarantine_guard import (
        check_and_refuse_quarantined_workload,
    )

    quarantine_refusal = await check_and_refuse_quarantined_workload(
        request.scope,
        action_id=body.action,
        surface="governance_middleware",
        app_obj=getattr(request, "app", None),
        body_params=body.params,
    )
    if quarantine_refusal is not None:
        q_status, q_payload = quarantine_refusal
        return JSONResponse(status_code=q_status, content=q_payload)

    governor = governor_of(request.app)  # fail closed if governor not assembled
    carrier = sanitize_trace_carrier(request.headers)
    remote_ctx = otel_extract(carrier)
    token = otel_context.attach(remote_ctx)
    try:
        try:
            bound_params = await governor.bind_server_inputs(body.action, body.params)
            # body.action always overrides any caller-supplied "action" inside params.
            opa_payload: dict[str, Any] = {**bound_params, "action": body.action}
            raw_result = await governor.components.opa.evaluate_policy(opa_payload)
            verdict = decode_opa_verdict(raw_result)
        except Exception as exc:
            logger.error(
                "OPA policy-precheck failed for action=%s: %s", body.action, exc
            )
            verdict = OpaVerdict.DENY

        if verdict is OpaVerdict.ALLOW:
            decision = "ALLOW"
        elif verdict is OpaVerdict.MANUAL_REVIEW:
            decision = "MANUAL_REVIEW"
        else:
            decision = "DENY"

        return JSONResponse(
            status_code=200,
            content={
                "schema_version": "1.0.0",
                "action": body.action,
                "decision": decision,
                "dry_run": True,
                "advisory": True,
            },
        )
    finally:
        otel_context.detach(token)


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

    Governance tiers executed (7-tier deterministic pipeline via ``run_pipeline()``,
    matching ``TIER_LABELS`` in ``proof/model.py``; plugin tiers such as
    ``bounding`` or optional ``causal`` run alongside):
        - Tier 0.5: FTRA action classification & reachability analysis
        - Tier 1: STPA/STAMP Unsafe Control Action validation
        - Tier 2: Agent confidence threshold pre-check (fast-fail)
        - Tier 3b: OPA Rego policy evaluation — declarative rule enforcement
        - Tier 5: Notional threshold escalation / Consensus gate (ISO 42001)
        - Tier 3a (phase 2): Control Barrier Function (CBF) — barrier headroom
        - Tier 4 (phase 2): Fiscal Limit Pre-Reservation

    This endpoint is a non-committing decision: phase-2 tiers are previewed,
    nothing is reserved, and no routing seal is minted. The caller uses the
    verdict only for routing; the single committing run (commit + seal +
    actuation) happens inside the gateway when the governed tool executes.

    Returns:
        ``ALLOW`` / ``NARROW`` (NARROW carries ``narrowed_params``) as a signed
        governance envelope; ``REQUIRE_APPROVAL`` with the ``deferred_id`` of
        the gateway-held approval token; ``DEFER`` with the ``defer_id`` of
        the parked hold;
        or 403 ``DENIED`` with a refusal receipt.
    """
    # GHSA-v3h4-8458-5ww3: the caller is authenticated before any processing by
    # WorkloadIdentityMiddleware (mesh identity, POAM-2026-080) on the root app.

    # ── Rate limiting: shared dual-bucket GCRA (identity + principal) ─────────
    rl_res = await _check_validate_action_rate_limit(request)
    if inspect.isawaitable(rl_res):
        rl_res = await rl_res
    if isinstance(rl_res, bool):
        rl_verdict = RateLimitVerdict(
            allowed=rl_res, retry_after_seconds=1 if not rl_res else 0
        )
    else:
        rl_verdict = rl_res
    if not rl_verdict.allowed:
        retry_after = max(1, int(rl_verdict.retry_after_seconds or 1))
        return JSONResponse(
            status_code=429,
            headers={"Retry-After": str(retry_after)},
            content={
                "error": "rate_limit_exceeded",
                "scope": rl_verdict.scope or "principal",
                "retry_after_seconds": retry_after,
            },
        )

    # ── Out-of-Band Quarantine Enforcement (SC-7 / AC-3) ──────────────────────
    from src.gateway.server.quarantine_guard import (
        check_and_refuse_quarantined_workload,
    )

    quarantine_refusal = await check_and_refuse_quarantined_workload(
        request.scope,
        action_id=body.action,
        surface="governance_middleware",
        app_obj=getattr(request, "app", None),
        body_params=body.params,
    )
    if quarantine_refusal is not None:
        q_status, q_payload = quarantine_refusal
        return JSONResponse(status_code=q_status, content=q_payload)

    # ── Extract W3C trace context from inbound headers ────────────────────────
    # The GFA injected 'traceparent' via otel_inject(headers).  Extracting it
    # here and attaching it as the current context means all spans opened by
    # SymbolicGovernor.validate_action() (cage.cbf_action_check,
    # cage.opa_action_check, cage.routing_seal) are children of the GFA's
    # cage.tool_execute span in Telemetry — not orphaned fragments.
    governor = governor_of(request.app)  # fail closed before any evaluation
    carrier = sanitize_trace_carrier(request.headers)
    remote_ctx = otel_extract(carrier)
    token = otel_context.attach(remote_ctx)

    try:
        result = await governor.validate_action(
            action=body.action,
            params=body.params,
            policy_version_id=body.policy_version_id,
        )

        # ADR-008 Phase 3: Build canonical signed envelope for all HTTP 200 verdicts
        from src.gateway.governance.contracts import Violation
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
                    metadata = {k: v for k, v in att.items() if k not in standard_keys}
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

        payload_result = {
            k: v for k, v in result.items() if k != "external_attestations"
        }
        if "violations" in payload_result and isinstance(
            payload_result["violations"], list
        ):
            payload_result["violations"] = [
                v.to_dict() if isinstance(v, Violation) else v
                for v in payload_result["violations"]
            ]

        builder = GovernanceEnvelopeBuilder()
        envelope = await builder.build(
            action=body.action,
            params=body.params,
            governance_result=jsonable_encoder(payload_result),
            agent_id=result.get("agent_id"),
            tiers_passed=result.get("tiers_passed", []),
            external_attestations=attestations,
        )
        return JSONResponse(content=envelope.to_dict(include_signature=True))

    except GovernanceError as exc:
        from src.gateway.governance.evidence.stream import (
            EvidenceChainUnavailableError,
        )

        # P6: emit a signed OSCAL compliance receipt for every hard refusal.
        # Under EVIDENCE_CHAIN_BLOCKING=true, a failed evidence write returns 503
        # rather than an un-evidenced 403 refusal.
        try:
            emitted = await _emit_refusal_receipt(
                action_id=body.action,
                refusal_reason=str(exc),
                oscal_control_ref="SC-4",
                params=body.params,
                receipt=exc.receipt,
            )
        except EvidenceChainUnavailableError as emit_exc:
            return JSONResponse(
                status_code=503,
                content={
                    "error": "evidence_chain_unavailable",
                    "detail": str(emit_exc),
                },
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
        elif isinstance(emitted, str) and emitted:
            refusal_content["proof_hash"] = emitted

        return JSONResponse(
            status_code=403,
            content=refusal_content,
        )
    except Exception as exc:
        from src.gateway.governance.evidence.stream import (
            EvidenceChainUnavailableError,
        )

        if isinstance(exc, EvidenceChainUnavailableError):
            return JSONResponse(
                status_code=503,
                content={
                    "error": "evidence_chain_unavailable",
                    "detail": str(exc),
                },
            )
        logger.error("❌ validate_action internal error", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal governance error")
    finally:
        otel_context.detach(token)


# POST /governance/state-commitments — generic state-commitment service.
governance_app.include_router(state_commitment_router)
