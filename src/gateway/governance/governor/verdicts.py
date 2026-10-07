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

import json
import logging
import os
import re
import uuid
from typing import TYPE_CHECKING, Any

from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode

if TYPE_CHECKING:
    from src.gateway.governance.defer_queue import DeferReason

from src.gateway.governance import routing_seal
from src.gateway.governance.agent_confidence import reported_confidence
from src.gateway.governance.classification_engine import ClassificationResult
from src.gateway.governance.constants import ControlRegistry, GovernanceControl
from src.gateway.governance.contracts import (
    GovernanceTierFailure,
    RefusalReceipt,
    Violation,
    ViolationKind,
)
from src.gateway.governance.decisions import GovernanceDecision
from src.gateway.governance.governor.errors import GovernanceError

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
    violated_tier_default: str = "SYMBOLIC_GOVERNOR",
) -> RefusalReceipt:
    thread_id = resolve_thread_id(params)
    _first_tf = tier_failures[0] if tier_failures else None

    violated_rule = (
        "Multiple violations"
        if len(violations) > 1
        else (str(violations[0]) if violations else "Unknown violation")
    )

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
        ],
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
        # Contract: a string naming the tiers that held the action back.
        non_formation_proof=",".join(tf.tier for tf in tier_failures),
        tier_failures=tuple(tier_failures),
    )


async def publish_refusal(receipt: RefusalReceipt) -> None:
    from src.gateway.governance.evidence.stream import get_evidence_sink

    try:
        sink = get_evidence_sink()
        event = {
            "type": "GOVERNANCE_REFUSAL",
            "receipt": receipt.to_dict()
            if hasattr(receipt, "to_dict")
            else vars(receipt),
        }
        await sink.ingest(event)
    except Exception as exc:
        logger.error(f"Failed to publish refusal receipt: {exc}")


async def issue_seal(action: str, params: dict[str, Any], *, path: str) -> str:
    with tracer.start_as_current_span("cage.routing_seal") as seal_span:
        seal = await routing_seal.generate_seal_with_evidence(action, params)
        seal_span.set_attribute("cage.seal_issued", True)
        seal_span.set_attribute("cage.seal_path", path)
        return seal


def _reason_from_classification(classification_meta: dict[str, Any]) -> "DeferReason":
    """The ``DeferReason`` for a classifier DEFER, by exact reason match.

    Raises:
        ValueError: The classification reason is not one the classifier
            emits with DEFER; parking it under a guessed reason would
            misstate why the request was held.
    """
    from src.gateway.governance.classification_engine import (
        REASON_CONFIDENCE_BELOW_THRESHOLD,
        REASON_RELIANCE_INELIGIBLE,
    )
    from src.gateway.governance.defer_queue import DeferReason

    by_reason = {
        REASON_CONFIDENCE_BELOW_THRESHOLD: DeferReason.CONFIDENCE_BELOW_THRESHOLD,
        REASON_RELIANCE_INELIGIBLE: DeferReason.WARRANT_INELIGIBLE,
    }
    reason = classification_meta.get("classification_reason")
    if reason not in by_reason:
        raise ValueError(f"no DeferReason for classification reason {reason!r}")
    return by_reason[reason]


async def _park_defer_context(
    action: str,
    params: dict[str, Any] | None,
    metadata: dict[str, Any] | None,
    thread_id: str | None,
    confidence: float,
    classification_meta: dict[str, Any],
    violations: list[Violation],
    *,
    defer_reason: "DeferReason | None" = None,
) -> tuple[str, bool]:
    """Park a DeferToken and return ``(defer_id, persisted)``.

    ``persisted`` is False when the queue was unreachable: the id then names
    no stored token, so nothing can approve or resume it.
    """
    from src.gateway.governance.defer_queue import DeferToken, open_defer_queue

    effective_thread_id = thread_id or str(uuid.uuid4())

    opa_input_snapshot = {
        "action": action,
        "params": params or {},
        "metadata": metadata or {},
        "violations": [str(v) for v in violations],
        "classification_reason": classification_meta.get("classification_reason", ""),
        # What the reviewer was told the approved request would hit (Phase-2 preview).
        "barrier_preview": classification_meta.get("barrier_preview"),
        "barrier_preview_violations": classification_meta.get(
            "barrier_preview_violations", []
        ),
        # Re-verified clamped params that would leave only the approval to give.
        "narrow_hint": classification_meta.get("narrow_hint"),
    }

    token = DeferToken(
        thread_id=effective_thread_id,
        defer_reason=defer_reason or _reason_from_classification(classification_meta),
        opa_input_snapshot=opa_input_snapshot,
        confidence_score=min(max(confidence, 0.0), 1.0),
        aarm_vector="AARM-V7",
    )

    try:
        async with open_defer_queue() as queue:
            return await queue.park(token), True
    except Exception as exc:
        logger.error(
            "DeferQueue park failed (%s) — token NOT persisted; nothing can "
            "approve or resume it. action=%s thread_id=%s",
            exc,
            action,
            effective_thread_id,
        )
        return token.defer_id, False


async def handle_require_approval(
    action: str,
    params: dict[str, Any],
    violations: list[Violation],
    tier_failures: list[GovernanceTierFailure],
    classification_meta: dict[str, Any],
    latency_ms: float = 0.0,
) -> dict[str, Any]:
    """Park the pending approval in the gateway's DeferQueue; mint no seal.

    The returned ``deferred_id`` names the ``HITL_REQUIRED`` token operators
    approve (``DeferQueue.approve``) and the committing run consumes. It is
    ``None`` when the token could not be persisted: such a request can never
    be approved, so the caller must treat it as refused.

    ``violations`` include what the phase-2 barriers reported when previewed
    (never committed) before approval, and ``classification_meta`` carries
    ``barrier_preview`` (``PASS``/``FAIL``) with ``barrier_preview_violations``
    so the reviewer sees, e.g., that the trade would breach the daily cap. A
    HARD preview never reaches here: it is classified DENY first.

    ``narrowed_params`` is the advisory clamp from ``classification_meta``'s
    ``narrow_hint`` (``None`` without one): params a DRY_RUN found to clear
    every barrier, leaving only the approval to give. An approval may cover
    them because an approved trade may shrink; the committing run
    re-verifies whatever is executed.
    """
    from src.gateway.governance.defer_queue import DeferReason

    span = trace.get_current_span()
    defer_id, persisted = await _park_defer_context(
        action=action,
        params=params,
        metadata={"action": action, "params": params},
        thread_id=params.get("thread_id"),
        confidence=reported_confidence(params),
        classification_meta=classification_meta,
        violations=violations,
        defer_reason=DeferReason.HITL_REQUIRED,
    )
    deferred_id = defer_id if persisted else None
    span.set_attribute("cage.verdict", GovernanceDecision.REQUIRE_APPROVAL)
    span.set_attribute("cage.deferred_id", deferred_id or "")
    span.set_attribute(OBSERVATION_OUTPUT, GovernanceDecision.REQUIRE_APPROVAL)
    span.set_status(Status(StatusCode.OK))
    logger.info(
        "🔶 handle_require_approval REQUIRE_APPROVAL: action=%s reason=%s deferred_id=%s (%.1fms)",
        action,
        classification_meta.get("classification_reason", ""),
        deferred_id,
        latency_ms,
    )
    return {
        "verdict": GovernanceDecision.REQUIRE_APPROVAL,
        "violations": violations,
        "deferred_id": deferred_id,
        "latency_ms": latency_ms,
        "classification_reason": classification_meta.get("classification_reason", ""),
        "classification_meta": classification_meta,
        "narrowed_params": (classification_meta.get("narrow_hint") or {}).get(
            "narrowed_params"
        ),
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
    defer_reason = _reason_from_classification(classification_meta)
    defer_metadata = {
        "cbf_violation": any("CBF" in str(v) for v in violations),
        "opa_decision": classification_meta.get("opa_decision"),
        "policy_ambiguous": classification_meta.get("policy_ambiguous", False),
        "params": params,
        "action": action,
    }
    defer_token, _persisted = await _park_defer_context(
        action=action,
        params=params,
        metadata=defer_metadata,
        thread_id=params.get("thread_id"),
        confidence=reported_confidence(params),
        classification_meta=classification_meta,
        violations=violations,
        defer_reason=defer_reason,
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
        "latency_ms": latency_ms,
        "classification_meta": classification_meta,
        "defer_reason": defer_reason.value,
        "defer_token": defer_token,
        "deferrable": classification_meta.get("deferrable", True),
        "retry_after_seconds": 300,
        "agent_id": agent_id,
    }


def handle_narrow(
    action: str,
    original_params: dict[str, Any],
    narrowed_params: dict[str, Any],
    *,
    violations: list[Violation],
    classification_meta: dict[str, Any],
    latency_ms: float = 0.0,
) -> dict[str, Any]:
    """Build the NARROW-candidate response for params that were re-verified.

    ``SymbolicGovernor.validate_action`` re-runs the DRY_RUN profile (phase-2
    stages through ``preview()``) on the narrower's proposal before calling
    this; nothing is committed and no seal is minted. ``narrowed_params`` is
    echoed back as given (never re-read from ``classification_meta``) so the
    response names exactly the params that were re-verified. Executing them
    is a separate committing run that governs them again.
    """
    span = trace.get_current_span()
    narrowing_reason = classification_meta.get(
        "narrowing_reason", "Constraints applied"
    )
    constraints_applied = classification_meta.get("constraints_applied", {})

    span.set_attribute("cage.verdict", GovernanceDecision.NARROW)
    span.set_attribute("cage.governance.narrowed", True)
    span.set_attribute(
        "cage.governance.constraints_applied", json.dumps(constraints_applied)[:500]
    )
    span.set_attribute(OBSERVATION_OUTPUT, GovernanceDecision.NARROW)
    span.set_status(Status(StatusCode.OK))
    logger.info(
        "📐 handle_narrow NARROW: action=%s reason=%s constraints=%s (%.1fms)",
        action,
        narrowing_reason,
        constraints_applied,
        latency_ms,
    )
    agent_id = original_params.get("_caller_principal", "")

    return {
        "verdict": GovernanceDecision.NARROW,
        "violations": violations,
        "latency_ms": latency_ms,
        "agent_id": agent_id,
        "classification_meta": {
            **classification_meta,
            "narrowed_params": narrowed_params,
        },
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
    logger.warning(
        "🚫 handle_deny DENY: action=%s violations=%d", action, len(violations)
    )

    receipt = build_refusal_receipt(action, params, violations, tier_failures)
    span.set_attribute("cage.refusal_proof_hash", receipt.proof_hash)
    await publish_refusal(receipt)
    # Lead with the violation that decided the refusal (a HARD one when
    # present), so a co-occurring HITL finding never masks the real cause.
    ordered = sorted(violations, key=lambda v: v.kind != ViolationKind.HARD)

    quarantine_meta: dict[str, Any] = {}
    auto_quarantine = os.getenv(
        "CAGE_ENABLE_AUTO_QUARANTINE", "false"
    ).strip().lower() in ("true", "1", "yes") or bool(
        params.get("_quarantine_on_breach")
    )
    if auto_quarantine and ordered and ordered[0].kind == ViolationKind.HARD:
        import time as _time

        from src.gateway.governance.quarantine_actuator import dispatch_quarantine
        from src.gateway.governance.seams.quarantine import (
            QuarantineDirective,
            QuarantineTriggerReason,
        )

        lead_code = ordered[0].code
        if lead_code.startswith("FTRA"):
            trigger_reason = QuarantineTriggerReason.FTRA_UNCONTAINABLE_TERMINAL
        elif lead_code.startswith("RECON"):
            trigger_reason = QuarantineTriggerReason.RECONCILIATION_STATE_DRIFT
        else:
            trigger_reason = QuarantineTriggerReason.CRITICAL_CBF_BREACH

        agent_svid = str(
            params.get("_caller_principal")
            or params.get("agent_svid")
            or params.get("workload_svid")
            or "spiffe://cluster.local/ns/cage/sa/unknown-agent"
        )
        thread_id = str(params.get("thread_id") or "default-thread")
        sandbox_id = str(params.get("sandbox_id") or "default-sandbox")
        directive = QuarantineDirective(
            thread_id=thread_id,
            agent_svid=agent_svid,
            sandbox_id=sandbox_id,
            reason=trigger_reason,
            violation_codes=tuple(v.code for v in ordered),
            issued_at=int(_time.time()),
            correlation_id=str(params.get("correlation_id") or uuid.uuid4()),
            governance_decision_digest=receipt.proof_hash,
            nonce=uuid.uuid4().hex,
        )
        q_receipt = await dispatch_quarantine(directive)
        span.set_attribute("cage.quarantine.rule_id", q_receipt.rule_id or "")
        span.set_attribute("cage.quarantine.quarantined", q_receipt.quarantined)
        quarantine_meta = {
            "quarantine_rule_id": q_receipt.rule_id,
            "quarantined": q_receipt.quarantined,
            "quarantine_enforcement_plane": q_receipt.enforcement_plane,
        }

    raise GovernanceError(
        _error_message(ordered[0]),
        payload={
            **(classification_meta or {}),
            **_control_payload(ordered[0]),
            **quarantine_meta,
        },
        receipt=receipt,
        violations=[_error_message(v) for v in ordered],
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
