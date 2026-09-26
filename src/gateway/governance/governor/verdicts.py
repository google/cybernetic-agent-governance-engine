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

import logging
import os
import re
import uuid
from typing import Any

from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode

from src.gateway.governance.constants import ControlRegistry, GovernanceControl
from src.gateway.governance.contracts import GovernanceTierFailure, Violation, ViolationKind
from src.gateway.governance.contracts import RefusalReceipt
from src.gateway.governance import routing_seal
from src.gateway.governance.governor.errors import GovernanceError
from src.gateway.governance.decisions import GovernanceDecision
from src.gateway.governance.classification_engine import ClassificationResult

logger = logging.getLogger(__name__)
tracer = trace.get_tracer(__name__)
OBSERVATION_OUTPUT = "observation.output"


def resolve_thread_id(params: dict[str, Any]) -> str:
    """Resolve thread_id from params."""
    if "thread_id" in params:
        return str(params["thread_id"])
    if "transaction_id" in params:
        return str(params["transaction_id"])
    return "unknown"


def build_refusal_receipt(
    action: str,
    params: dict[str, Any],
    violations: list[Violation],
    tier_failures: list[GovernanceTierFailure],
    *,
    violated_tier_default: str = "SYMBOLIC_GOVERNOR"
) -> RefusalReceipt:
    thread_id = resolve_thread_id(params)
    _first_tf = tier_failures[0] if tier_failures else None
    
    violated_rule = "Multiple violations" if len(violations) > 1 else (str(violations[0]) if violations else "Unknown violation")
    
    # Generate standing at refusal
    standing_at_refusal = {
        "is_compliant": False,
        "failures": [
            {
                "tier": tf.tier,
                "control_id": tf.control_id,
                "rule_description": tf.rule_description,
                "governing_state": tf.governing_state,
                "protected_consequence": tf.protected_consequence,
            }
            for tf in tier_failures
        ]
    }
    
    return RefusalReceipt(
        thread_id=thread_id,
        action=action,
        violated_tier=_first_tf.tier if _first_tf else violated_tier_default,
        violated_rule=violated_rule,
        standing_at_refusal=standing_at_refusal,
        schema_version="v2",
        attempted_params={
            k: v for k, v in params.items() if k not in ("thread_id", "transaction_id")
        },
        standing_snapshot=_first_tf.governing_state if _first_tf else {},
        control_id=_first_tf.control_id if _first_tf else "",
        protected_consequence=_first_tf.protected_consequence if _first_tf else "",
        non_formation_proof=[tf.tier for tf in tier_failures],
        tier_failures=tier_failures
    )


async def publish_refusal(receipt: RefusalReceipt) -> None:
    from src.gateway.governance.evidence.stream import get_evidence_sink
    try:
        sink = get_evidence_sink()
        event = {"type": "GOVERNANCE_REFUSAL", "receipt": receipt.to_dict() if hasattr(receipt, "to_dict") else vars(receipt)}
        await sink.ingest(event)
    except Exception as exc:
        logger.error(f"Failed to publish refusal receipt: {exc}")


async def issue_seal(action: str, params: dict[str, Any], *, path: str) -> str:
    with tracer.start_as_current_span("cage.routing_seal") as seal_span:
        seal = await routing_seal.generate_seal_with_evidence(action, params)
        seal_span.set_attribute("cage.seal_issued", True)
        seal_span.set_attribute("cage.seal_path", path)
        return seal


async def _park_defer_context(
    action: str,
    params: dict[str, Any] | None,
    metadata: dict[str, Any] | None,
    thread_id: str | None,
    confidence: float,
    classification_meta: dict[str, Any],
    violations: list[Violation],
) -> str:
    from src.gateway.governance.defer_queue import DeferQueue, DeferReason, DeferToken

    effective_thread_id = thread_id or str(uuid.uuid4())

    opa_input_snapshot = {
        "action": action,
        "params": params or {},
        "metadata": metadata or {},
        "violations": [str(v) for v in violations],
        "classification_reason": classification_meta.get("classification_reason", ""),
    }

    reason_str = classification_meta.get("classification_reason", "")
    if "confidence" in reason_str.lower():
        defer_reason = DeferReason.CONFIDENCE_BELOW_THRESHOLD
    elif "context" in reason_str.lower() or "missing" in reason_str.lower():
        defer_reason = DeferReason.INSUFFICIENT_CONTEXT
    elif "ambiguous" in reason_str.lower():
        defer_reason = DeferReason.AMBIGUOUS_SEMANTIC_DISTANCE
    elif "data" in reason_str.lower() and "starvation" in reason_str.lower():
        defer_reason = DeferReason.DATA_STARVATION
    else:
        defer_reason = DeferReason.CONFIDENCE_BELOW_THRESHOLD

    token = DeferToken(
        thread_id=effective_thread_id,
        defer_reason=defer_reason,
        opa_input_snapshot=opa_input_snapshot,
        confidence_score=confidence,
        aarm_vector="AARM-V7",
    )

    async def _park() -> str:
        import redis.asyncio as aioredis
        redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379")
        client = aioredis.from_url(redis_url, db=1, decode_responses=True)
        try:
            queue = DeferQueue(client)
            return await queue.park(token)
        finally:
            await client.aclose()

    try:
        return await _park()
    except Exception as exc:
        logger.warning(
            "DeferQueue park failed (%s) — using local defer_id only "
            "(token NOT persisted to Redis; HITL API will not find it). "
            "action=%s thread_id=%s",
            exc, action, effective_thread_id,
        )
        return token.defer_id


def handle_require_approval(
    action: str,
    params: dict[str, Any],
    violations: list[Violation],
    tier_failures: list[GovernanceTierFailure],
    classification_meta: dict[str, Any],
    latency_ms: float = 0.0,
) -> dict[str, Any]:
    span = trace.get_current_span()
    span.set_attribute("cage.verdict", GovernanceDecision.REQUIRE_APPROVAL)
    span.set_attribute(OBSERVATION_OUTPUT, GovernanceDecision.REQUIRE_APPROVAL)
    span.set_status(Status(StatusCode.OK))
    logger.info(
        "🔶 handle_require_approval REQUIRE_APPROVAL: action=%s reason=%s (%.1fms)",
        action,
        classification_meta.get("classification_reason", ""),
        latency_ms,
    )
    return {
        "verdict": GovernanceDecision.REQUIRE_APPROVAL,
        "violations": violations,
        "seal": "",
        "latency_ms": latency_ms,
        "classification_meta": classification_meta,
    }


async def handle_defer(
    action: str,
    params: dict[str, Any],
    violations: list[Violation],
    tier_failures: list[GovernanceTierFailure],
    classification_meta: dict[str, Any],
    latency_ms: float = 0.0,
) -> dict[str, Any]:
    span = trace.get_current_span()
    defer_metadata = {
        "cbf_violation": any("CBF" in str(v) for v in violations),
        "opa_decision": classification_meta.get("opa_decision"),
        "policy_ambiguous": classification_meta.get("policy_ambiguous", False),
        "params": params,
        "action": action,
    }
    _confidence = float(params.get("confidence", 0.0))
    defer_token = await _park_defer_context(
        action=action,
        params=params,
        metadata=defer_metadata,
        thread_id=params.get("thread_id"),
        confidence=_confidence,
        classification_meta=classification_meta,
        violations=violations,
    )

    span.set_attribute("cage.verdict", GovernanceDecision.DEFER)
    span.set_attribute("cage.defer_token", defer_token)
    span.set_attribute(OBSERVATION_OUTPUT, GovernanceDecision.DEFER)
    span.set_status(Status(StatusCode.OK))
    logger.info(
        "🕒 handle_defer DEFER: action=%s reason=%s (%.1fms)",
        action,
        classification_meta.get("classification_reason", ""),
        latency_ms,
    )

    agent_id = params.get("_caller_principal", "")
    return {
        "verdict": GovernanceDecision.DEFER,
        "violations": violations,
        "seal": "",
        "latency_ms": latency_ms,
        "classification_meta": classification_meta,
        "defer_reason": "CONFIDENCE_BELOW_THRESHOLD",
        "defer_token": defer_token,
        "deferrable": classification_meta.get("deferrable", True),
        "retry_after_seconds": 300,
        "agent_id": agent_id,
    }


async def handle_pause(
    action: str,
    params: dict[str, Any],
    violations: list[Violation],
    tier_failures: list[GovernanceTierFailure],
    classification_meta: dict[str, Any],
    latency_ms: float = 0.0,
) -> dict[str, Any]:
    span = trace.get_current_span()
    from src.gateway.governance.contracts import PauseReceipt
    from src.gateway.governance.pause_primitive import PauseManager, build_resume_endpoint
    from src.gateway.infrastructure.redis_client import redis_client
    from src.gateway.governance.governor._legacy_startup import is_cage_pause_enabled

    pause_reason: str = classification_meta.get("pause_reason", "RATE_LIMITED")
    estimated_wait: int = classification_meta.get("estimated_wait_seconds", 60)
    _va_pause_thread_id = resolve_thread_id(params)

    if not is_cage_pause_enabled():
        span.set_attribute("cage.verdict", GovernanceDecision.DENY)
        span.set_attribute("cage.pause_fallback", True)
        span.set_status(Status(StatusCode.ERROR))
        logger.warning(
            "🚫 handle_pause PAUSE->DENY fallback: action=%s reason=%s (CAGE_PAUSE_ENABLED=false)",
            action, pause_reason,
        )
        receipt = build_refusal_receipt(
            action, params, violations, tier_failures, violated_tier_default="PAUSE_FALLBACK"
        )
        span.set_attribute("cage.refusal_proof_hash", receipt.proof_hash)
        await publish_refusal(receipt)
        raise GovernanceError(
            f"Transient condition ({pause_reason}) detected; CAGE_PAUSE_ENABLED=false — request denied",
            receipt=receipt,
        )

    pause_token = ""
    expires_at_utc = ""
    try:
        pause_manager = PauseManager(redis_client)
        request_id = params.get("request_id", params.get("thread_id", f"{action}_{_va_pause_thread_id}"))
        pause_token = await pause_manager.pause_request(
            request_id=request_id,
            reason=pause_reason,
            ttl_seconds=3600,
            original_request=params,
            thread_id=_va_pause_thread_id,
            estimated_wait_secs=estimated_wait,
        )
        pause_state = await pause_manager.get_pause_state(pause_token)
        if pause_state:
            expires_at_utc = pause_state.expires_at_utc
    except Exception as pause_exc:
        logger.error("🚫 handle_pause PAUSE->DENY (Redis unavailable): action=%s reason=%s error=%s", action, pause_reason, pause_exc)
        span.set_attribute("cage.verdict", GovernanceDecision.DENY)
        span.set_attribute("cage.pause_redis_error", True)
        span.set_status(Status(StatusCode.ERROR))
        receipt = build_refusal_receipt(
            action, params, violations, tier_failures, violated_tier_default="PAUSE_REDIS_ERROR"
        )
        span.set_attribute("cage.refusal_proof_hash", receipt.proof_hash)
        await publish_refusal(receipt)
        raise GovernanceError(
            f"Transient condition ({pause_reason}) detected; PAUSE storage failed — request denied",
            receipt=receipt,
        )

    pause_receipt = PauseReceipt(
        thread_id=_va_pause_thread_id,
        action=action,
        pause_reason=pause_reason,
        pause_token=pause_token,
        violations=[str(v) for v in violations],
        standing_at_pause={
            "symbol": params.get("symbol"),
            "amount": params.get("amount"),
            "confidence": params.get("confidence"),
        },
        estimated_wait_seconds=estimated_wait,
        expires_at_utc=expires_at_utc,
    )

    span.set_attribute("cage.verdict", GovernanceDecision.PAUSE)
    span.set_attribute("cage.pause_token", pause_token)
    span.set_attribute("cage.pause_reason", pause_reason)
    span.set_attribute("cage.pause_estimated_wait", estimated_wait)
    span.set_attribute("cage.pause_receipt_hash", pause_receipt.proof_hash)
    span.set_attribute(OBSERVATION_OUTPUT, GovernanceDecision.PAUSE)
    span.set_status(Status(StatusCode.OK))
    logger.info(
        "⏸️ handle_pause PAUSE: action=%s reason=%s wait=%ds (%.1fms)",
        action, pause_reason, estimated_wait, latency_ms,
    )
    agent_id = params.get("_caller_principal", "")
    
    return {
        "verdict": GovernanceDecision.PAUSE,
        "violations": violations,
        "seal": "",
        "latency_ms": latency_ms,
        "classification_meta": classification_meta,
        "pause_token": pause_token,
        "pause_reason": pause_reason,
        "resume_endpoint": build_resume_endpoint(pause_token),
        "expires_at_utc": expires_at_utc,
        "estimated_wait_seconds": estimated_wait,
        "retry_after_seconds": estimated_wait,
        "pause_receipt": pause_receipt,
        "agent_id": agent_id,
        "execution_allowed": False,
    }


async def handle_narrow(
    action: str,
    params: dict[str, Any],
    violations: list[Violation],
    tier_failures: list[GovernanceTierFailure],
    classification_meta: dict[str, Any],
    latency_ms: float = 0.0,
) -> dict[str, Any]:
    span = trace.get_current_span()
    original_params = classification_meta.get("original_params", params)
    narrowed_params = classification_meta.get("narrowed_params", params)
    narrowing_reason = classification_meta.get("narrowing_reason", "Constraints applied")
    constraints_applied = classification_meta.get("constraints_applied", {})

    seal = await issue_seal(action, narrowed_params, path="narrow")

    span.set_attribute("cage.verdict", GovernanceDecision.NARROW)
    span.set_attribute("cage.governance.narrowed", True)
    import json
    span.set_attribute("cage.governance.constraints_applied", json.dumps(constraints_applied)[:500])
    span.set_attribute(OBSERVATION_OUTPUT, GovernanceDecision.NARROW)
    span.set_status(Status(StatusCode.OK))
    logger.info(
        "📐 handle_narrow NARROW: action=%s reason=%s constraints=%s (%.1fms)",
        action, narrowing_reason, constraints_applied, latency_ms,
    )
    agent_id = params.get("_caller_principal", "")

    return {
        "verdict": GovernanceDecision.NARROW,
        "violations": violations,
        "seal": seal,
        "latency_ms": latency_ms,
        "agent_id": agent_id,
        "classification_meta": classification_meta,
        "original_params": original_params,
        "narrowed_params": narrowed_params,
        "narrowing_reason": narrowing_reason,
        "constraints_applied": constraints_applied,
        "execution_allowed": True,
    }


async def handle_deny(
    action: str,
    params: dict[str, Any],
    violations: list[Violation],
    tier_failures: list[GovernanceTierFailure],
    classification_meta: dict[str, Any] | None = None,
    latency_ms: float = 0.0,
) -> None:
    span = trace.get_current_span()
    span.set_attribute("cage.verdict", GovernanceDecision.DENY)
    span.set_attribute(OBSERVATION_OUTPUT, GovernanceDecision.DENY)
    span.set_status(Status(StatusCode.ERROR))
    logger.warning("🚫 handle_deny DENY: action=%s violations=%d", action, len(violations))
    
    receipt = build_refusal_receipt(
        action, params, violations, tier_failures
    )
    span.set_attribute("cage.refusal_proof_hash", receipt.proof_hash)
    await publish_refusal(receipt)
    raise GovernanceError(
        _error_message(violations[0]),
        payload={**(classification_meta or {}), **_control_payload(violations[0])},
        receipt=receipt,
    )



_CONTROL_ID_RE = re.compile(r"^\[(CTRL_[A-Z0-9_]+)\]")


def _control_payload(violation: Violation) -> dict[str, Any]:
    """Resolve control metadata (incl. ``legacy_citation``) for SIEM consumers.

    Control IDs are carried as a ``[CTRL_xxx]`` message prefix; unknown or
    absent IDs yield an empty dict rather than a guessed citation.
    """
    m = _CONTROL_ID_RE.match(violation.message)
    if not m:
        return {}
    try:
        control = GovernanceControl(m.group(1))
        meta = ControlRegistry().get_mapping(control)
    except (ValueError, KeyError):
        return {}
    return {
        "control_id": control.value,
        "primary_framework": meta.get("primary_framework", ""),
        "legacy_citation": meta.get("legacy_citation", ""),
    }


def _error_message(violation: Violation) -> str:
    """Human-readable denial text that always carries a machine-greppable tag.

    Messages that already lead with a ``[TAG]`` (control ID or UCA code) are
    kept verbatim; otherwise the violation code is prefixed.
    """
    msg = violation.message
    return msg if msg.startswith("[") else f"[{violation.code}] {msg}"
