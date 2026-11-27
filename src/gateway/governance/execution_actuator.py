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
ExecutionActuator protocol and supporting types for downstream execution boundary.

CAGE is the ISSUER, not the consumer. This is a fundamentally different trust
boundary from the upstream NormativeProvider/AttestationProvider seams.

BREAKING CHANGE (C0): ExecutionActuator, ExecutionClearance, ActuationReceipt,
and ActuatorCapability have been moved to src.gateway.governance.seams.actuation
to eliminate circular dependencies with vendor adapters. This module now
re-exports them for backward compatibility, but the re-export will be removed
in the same PR per the C0 specification.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import math
import os
import time
import uuid
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from src.gateway.governance import execution_idempotency as _idempotency
from src.gateway.governance.execution_idempotency import ExecutionStatus

# Re-export seam contracts for backward compatibility during transition.
# New code should import directly from seams.actuation.
from src.gateway.governance.seams.actuation import (
    ActuationError,
    ActuationIndeterminateError,
    ActuationOutcome,
    ActuationReceipt,
    ActuationRejectedError,
    ActuatorCapability,
    ExecutionActuator,
    ExecutionClearance,
    ReceiptVerification,
)

logger = logging.getLogger("Gateway.Governance.ExecutionActuator")

__all__ = [
    "ActuationError",
    "ActuationIndeterminateError",
    "ActuationOutcome",
    "ActuationReceipt",
    "ActuationRejectedError",
    "ActuatorCapability",
    "ActuatorRegistry",
    "ExecutionActuator",
    "ExecutionClearance",
    "ReceiptVerification",
    "approval_covers_bounded",
    "build_execution_clearance",
    "dispatch_actuation",
    "get_actuator_registry",
    "ingest_actuation_receipt",
    "load_actuators_from_env",
    "require_sealed_action",
    "verify_clearance_contract",
]

_EVENT_TYPE_BY_OUTCOME: dict[ActuationOutcome, str] = {
    ActuationOutcome.ACCEPTED: "ACTUATION_RECEIPT",
    ActuationOutcome.REJECTED: "ACTUATION_REFUSAL_RECEIPT",
    ActuationOutcome.UNKNOWN: "ACTUATION_INDETERMINATE_RECEIPT",
}

#: What a recorded receipt says about the side effect, in ledger terms.
_ATTEMPT_STATUS_BY_OUTCOME: dict[ActuationOutcome, ExecutionStatus] = {
    ActuationOutcome.ACCEPTED: ExecutionStatus.EXECUTED,
    ActuationOutcome.REJECTED: ExecutionStatus.BLOCKED,
    ActuationOutcome.UNKNOWN: ExecutionStatus.UNKNOWN,
}


def approval_covers_bounded(
    approved: Mapping[str, Any],
    requested: Mapping[str, Any],
    bound_fields: tuple[str, ...],
    quantity_field: str,
) -> bool:
    """True iff ``approved`` matches ``requested`` on ``bound_fields`` and bounds ``quantity_field``."""
    if any(approved.get(field) != requested.get(field) for field in bound_fields):
        return False
    try:
        raw_approved = approved[quantity_field]
        raw_requested = requested[quantity_field]
        if isinstance(raw_approved, bool) or isinstance(raw_requested, bool):
            return False
        approved_qty = float(raw_approved)
        requested_qty = float(raw_requested)
    except (KeyError, TypeError, ValueError):
        return False
    if not (math.isfinite(approved_qty) and math.isfinite(requested_qty)):
        return False
    return 0.0 < requested_qty <= approved_qty


def require_sealed_action(governed: Any, action: str) -> tuple[str, dict[str, Any]]:
    """Extract validated ``(seal, evaluated_params)`` from a ``SealedAction``."""
    from src.gateway.governance.routing_seal import SymbolicGovernorViolation

    seal = getattr(governed, "seal", None)
    evaluated = getattr(governed, "params", None)
    if not isinstance(seal, str) or not seal.strip() or not isinstance(evaluated, dict):
        raise SymbolicGovernorViolation("No seal", action=action)
    return seal, evaluated


def verify_clearance_contract(
    clearance: ExecutionClearance, executor_id: str
) -> tuple[str, str] | None:
    """Verify local clearance routing, quorum, seal digest, and routing seal.

    Returns ``None`` when valid, or ``(error_code, detail)`` on failure.
    """
    from src.gateway.governance import routing_seal as _rs

    seal = clearance.routing_seal
    if (
        clearance.executor_id != executor_id
        or clearance.decision != "ALLOW"
        or not isinstance(seal, str)
        or not seal.strip()
    ):
        return ("CLEARANCE_INVALID", "")
    if clearance.target_route.rstrip("/") not in ("local://default", "*"):
        return ("TARGET_ROUTE_MISMATCH", clearance.target_route)
    if len(clearance.approvals) < clearance.required_quorum:
        return ("QUORUM_NOT_MET", "")
    if not hmac.compare_digest(
        _rs.seal_digest(seal), clearance.governance_decision_digest
    ):
        return ("SEAL_DIGEST_MISMATCH", "")
    try:
        if not _rs.verify_seal(seal, clearance.action, dict(clearance.params)):
            return ("INVALID_ROUTING_SEAL", "verify_seal False")
    except _rs.SymbolicGovernorViolation as exc:
        return ("INVALID_ROUTING_SEAL", exc.reason)
    return None


def build_execution_clearance(
    action: str,
    thread_id: str,
    target: str,
    operator_urn: str,
    executor_id: str,
    consequence_ceiling: str,
    params: dict[str, Any],
    routing_seal: str,
    *,
    target_route: str = "local://default",
) -> ExecutionClearance:
    """Build a direct ``ExecutionClearance`` bound to ``routing_seal`` and ``params``."""
    from src.gateway.governance.routing_seal import seal_digest

    return ExecutionClearance(
        thread_id=thread_id,
        decision="ALLOW",
        decision_path="DIRECT",
        action=action,
        target=target,
        operator_urn=operator_urn,
        issued_at=int(time.time()),
        issued_at_provenance="CONSTRUCTION_TIME",
        correlation_id=thread_id,
        correlation_id_source="THREAD_DERIVED",
        governance_decision_digest=seal_digest(routing_seal),
        opa_input_digest=hashlib.sha256(
            json.dumps(params, sort_keys=True).encode()
        ).hexdigest(),
        nonce=uuid.uuid4().hex[:32],
        params=params,
        executor_id=executor_id,
        target_route=target_route,
        consequence_ceiling=consequence_ceiling,
        approvals=[],
        required_quorum=0,
        routing_seal=routing_seal,
    )


async def dispatch_actuation(
    actuator: ExecutionActuator,
    clearance: ExecutionClearance,
) -> ActuationReceipt:
    """Actuate through the kernel boundary and record the receipt exactly once.

    This is the only sanctioned way to invoke ``ExecutionActuator.actuate()``.
    Actuators never write evidence themselves, so every receipt — accepted,
    refused, or indeterminate — enters the hash-chained stream from this one
    place. An exception raised by the actuator is not proof the side effect
    did not happen, so it is converted into an ``UNKNOWN``, non-retryable
    receipt rather than propagated.

    It is also the only writer of the current attempt record
    (:class:`~src.gateway.governance.execution_idempotency.ActuationAttempt`,
    POAM-2026-252 / POAM-2026-254). Synchronously before ``actuate()`` is
    awaited, it verifies that the active attempt holds a live, unspent,
    kernel-attached ``ExecutionLedger`` claim matching
    ``(clearance.action, clearance.thread_id)``, consumes that claim, and marks
    the dispatch so the record says the action may have executed before any
    byte can leave. It settles the record from the receipt only once the
    receipt is in the evidence stream. A dispatch that is cancelled, or raises
    past this point, is never settled and leaves the record ``UNKNOWN``.

    Raises:
        ActuationAttemptScopeError: No ``actuation_attempt_scope()`` is open;
            the actuator is never awaited.
        UnclaimedActuationError: The active attempt holds no live unspent
            kernel ``ExecutionLedger`` claim matching
            ``(clearance.action, clearance.thread_id)``; ``_dispatched`` stays
            ``False`` and the actuator is never awaited.
    """
    # Synchronous: verify the kernel claim, consume it, and mark the record
    # before actuate() is even awaited.
    attempt = _idempotency.mark_dispatch(
        action=clearance.action,
        idempotency_key=clearance.thread_id,
    )
    try:
        receipt = await actuator.actuate(clearance)
    except asyncio.CancelledError:
        logger.error(
            "[ExecutionActuator] %s cancelled mid-actuate (outcome UNKNOWN)",
            actuator.actuator_id,
        )
        cancelled_receipt = ActuationReceipt(
            accepted=False,
            receipt_id=None,
            session_uuid=None,
            raw_receipt=None,
            findings=[
                {
                    "code": "ACTUATOR_CANCELLED",
                    "severity": "TERMINAL",
                    "detail": "asyncio.CancelledError during actuate()",
                }
            ],
            retryable=False,
            timestamp_utc=datetime.now(tz=timezone.utc).isoformat(),
            outcome=ActuationOutcome.UNKNOWN,
        )
        ingest_task = asyncio.create_task(
            ingest_actuation_receipt(
                clearance, cancelled_receipt, actuator_id=actuator.actuator_id
            )
        )
        try:
            await asyncio.shield(ingest_task)
        except BaseException as ingest_exc:  # noqa: BLE001
            logger.error(
                "[ExecutionActuator] Failed to ingest UNKNOWN receipt on cancellation for %s: %s",
                actuator.actuator_id,
                ingest_exc,
            )
        raise
    except Exception as exc:
        logger.error(
            "[ExecutionActuator] %s raised during actuate (outcome UNKNOWN): %s",
            actuator.actuator_id,
            exc,
        )
        receipt = ActuationReceipt(
            accepted=False,
            receipt_id=None,
            session_uuid=None,
            raw_receipt=None,
            findings=[
                {
                    "code": "ACTUATOR_EXCEPTION",
                    "severity": "TERMINAL",
                    "detail": f"{type(exc).__name__}: {exc}",
                }
            ],
            retryable=False,
            timestamp_utc=datetime.now(tz=timezone.utc).isoformat(),
            outcome=ActuationOutcome.UNKNOWN,
        )
    await ingest_actuation_receipt(clearance, receipt, actuator_id=actuator.actuator_id)
    # Only after the receipt is in the evidence stream; REJECTED is the only
    # receipt that can take the record back to "nothing executed". A receipt
    # without a readable outcome settles nothing and leaves the record UNKNOWN.
    outcome = getattr(receipt, "outcome", None)
    _idempotency.settle_dispatch(
        attempt,
        _ATTEMPT_STATUS_BY_OUTCOME.get(outcome)
        if isinstance(outcome, ActuationOutcome)
        else None,
    )
    return receipt


async def ingest_actuation_receipt(
    clearance: ExecutionClearance,
    receipt: ActuationReceipt,
    *,
    actuator_id: str | None = None,
) -> str | None:
    """Emit an ``ActuationReceipt`` to the evidence stream; return its msg id.

    Called by ``dispatch_actuation()``; not by actuators. Refusal receipts
    (including ``CREDENTIAL_BROKER_FAILED``, ``EXECUTOR_ID_MISMATCH``, and
    ``TARGET_ROUTE_MISMATCH``) are recorded as ``ACTUATION_REFUSAL_RECEIPT``;
    accepted receipts as ``ACTUATION_RECEIPT``; indeterminate ones (the side
    effect may have happened) as ``ACTUATION_INDETERMINATE_RECEIPT``. The
    receipt's signature ``verification`` status is recorded alongside.
    """
    from src.gateway.governance.evidence.stream import get_evidence_sink

    # ActuationReceipt.__post_init__ always derives an outcome; UNKNOWN is the
    # fail-closed reading should one ever be missing.
    outcome = receipt.outcome or ActuationOutcome.UNKNOWN
    event_type = _EVENT_TYPE_BY_OUTCOME[outcome]
    finding_codes = [
        str(f.get("code", ""))
        for f in (receipt.findings or [])
        if isinstance(f, dict) and f.get("code")
    ]
    event: dict[str, Any] = {
        "type": event_type,
        "controlId": "AC-3",
        "accepted": bool(receipt.accepted),
        "outcome": outcome.value,
        "verification": receipt.verification.value,
        "actuator_id": actuator_id or clearance.executor_id,
        "thread_id": clearance.thread_id,
        "action": clearance.action,
        "target": clearance.target,
        "operator_urn": clearance.operator_urn,
        "executor_id": clearance.executor_id,
        "target_route": clearance.target_route,
        "correlation_id": clearance.correlation_id,
        "governance_decision_digest": clearance.governance_decision_digest,
        "receipt_id": receipt.receipt_id,
        "session_uuid": receipt.session_uuid,
        "findings": list(receipt.findings or []),
        "finding_codes": finding_codes,
        "retryable": bool(receipt.retryable),
        "envelope_digest": receipt.envelope_digest,
        "timestamp_utc": receipt.timestamp_utc
        or datetime.now(tz=timezone.utc).isoformat(),
    }

    try:
        sink = get_evidence_sink()
        has_redis = getattr(sink, "_redis", None) is not None
        msg_id = await sink.ingest(event)
        if has_redis and msg_id is None:
            from src.gateway.governance.governor.metrics import governor_metrics

            governor_metrics().evidence_publish_failure("actuation")
        return msg_id
    except Exception as exc:
        from src.gateway.governance.governor.metrics import governor_metrics

        governor_metrics().evidence_publish_failure("actuation")
        logger.error(
            "[ExecutionActuator] Failed to ingest %s for action=%s thread_id=%s: %s",
            event_type,
            clearance.action,
            clearance.thread_id,
            exc,
        )
        return None


def _load_actuator(name: str) -> ExecutionActuator:
    """Lazy-load execution actuator by name.

    Args:
        name: Actuator name (actuator_01, actuator_02, actuator_03).

    Returns:
        Instantiated ExecutionActuator.

    Raises:
        ValueError: Unknown actuator name.
        Exception: Actuator.from_env() configuration errors propagate.
    """
    normalized = name.strip().lower()

    if normalized in ("actuator_01", "a01"):
        from src.integrations.actuator_01.adapter import Actuator01Adapter

        return Actuator01Adapter.from_env()

    if normalized in ("actuator_02", "a02", "sandbox"):
        from src.integrations.actuator_02.adapter import Actuator02Adapter

        return Actuator02Adapter.from_env()

    if normalized in ("actuator_03", "a03", "dpu_quarantine"):
        from src.integrations.actuator_03.adapter import Actuator03Adapter

        return Actuator03Adapter.from_env()

    raise ValueError(
        f"Unknown execution actuator: '{name}'. Supported: actuator_01, actuator_02, actuator_03"
    )


class ActuatorRegistry:
    """
    Registry of ExecutionActuator instances.

    Unlike NormativeProvider's singleton, this supports N registered actuators
    dispatched by claim (which actions each actuator handles).

    The registry shape is fixed now so a second actuator does not force a refactor.
    """

    def __init__(self) -> None:
        self._actuators: dict[str, ExecutionActuator] = {}
        self._claims: dict[str, set[str]] = {}  # actuator_id -> set of action patterns

    def register(
        self,
        actuator: ExecutionActuator,
        claims: set[str] | None = None,
    ) -> None:
        """
        Register an actuator.

        Args:
            actuator: The ExecutionActuator instance
            claims: Set of action patterns this actuator handles (e.g., {"trade.*", "transfer.*"})
                   If None, the actuator handles all actions (default for the first actuator)
        """
        actuator_id = actuator.actuator_id
        if actuator_id in self._actuators:
            raise ValueError(f"Actuator {actuator_id} already registered")

        if not isinstance(actuator, ExecutionActuator):
            raise TypeError(
                f"Actuator must implement ExecutionActuator protocol, got {type(actuator)}"
            )

        if claims is None:
            declared = getattr(actuator, "claims", None) or getattr(
                actuator, "supported_actions", None
            )
            effective_claims = (
                {str(c).strip() for c in declared if str(c).strip()}
                if declared
                else {"*"}
            )
        else:
            effective_claims = {str(c).strip() for c in claims if str(c).strip()}
        self._actuators[actuator_id] = actuator
        self._claims[actuator_id] = effective_claims

    def get_actuator(self, action: str) -> ExecutionActuator | None:
        """Retrieve the most specific actuator claiming ``action`` (KG-27).

        Precedence order:
            1. Exact action match (``pattern == action``)
            2. Longest prefix glob match (``pattern.endswith("*")`` with non-empty prefix)
            3. Catch-all wildcard (``"*"``)
        """
        # 1. Exact match
        for actuator_id, patterns in self._claims.items():
            if action in patterns and action != "*":
                return self._actuators[actuator_id]

        # 2. Longest non-wildcard prefix match
        best_prefix_len = -1
        best_actuator_id: str | None = None
        for actuator_id, patterns in self._claims.items():
            for pattern in patterns:
                if pattern != "*" and pattern.endswith("*"):
                    prefix = pattern[:-1]
                    if action.startswith(prefix) and len(prefix) > best_prefix_len:
                        best_prefix_len = len(prefix)
                        best_actuator_id = actuator_id
        if best_actuator_id is not None:
            return self._actuators[best_actuator_id]

        # 3. Catch-all wildcard fallback
        for actuator_id, patterns in self._claims.items():
            if "*" in patterns:
                return self._actuators[actuator_id]
        return None

    def list_actuators(self) -> list[str]:
        """Return list of registered actuator IDs."""
        return list(self._actuators.keys())


# ── Thread-safe singleton accessor ──

import threading

_actuator_registry_singleton: ActuatorRegistry | None = None
_actuator_registry_lock = threading.Lock()


def get_actuator_registry() -> ActuatorRegistry:
    """
    Retrieve the global ActuatorRegistry singleton.

    Thread-safe singleton accessor for the ActuatorRegistry.
    Creates the registry on first access.

    Returns:
        The global ActuatorRegistry instance.
    """
    global _actuator_registry_singleton
    if _actuator_registry_singleton is None:
        with _actuator_registry_lock:
            if _actuator_registry_singleton is None:
                _actuator_registry_singleton = ActuatorRegistry()
    return _actuator_registry_singleton


def load_actuators_from_env(
    registry: ActuatorRegistry | None = None,
) -> ActuatorRegistry:
    """Load actuators from CAGE_ACTIVE_ACTUATORS environment variable.

    Reads:
        CAGE_ACTIVE_ACTUATORS: Comma-separated list of actuator names
            (e.g., "actuator_01"). Empty or unset -> no-op.

    Args:
        registry: Target registry (defaults to global singleton).

    Returns:
        The registry (for chaining).

    Raises:
        ValueError: Unknown actuator name or duplicate registration.
        Exception: Actuator configuration errors propagate (fail-closed).
    """
    if registry is None:
        registry = get_actuator_registry()

    actuator_names_raw = os.getenv("CAGE_ACTIVE_ACTUATORS", "").strip()

    # Hermetic default: return registry unmodified
    if not actuator_names_raw:
        logger.info("CAGE_ACTIVE_ACTUATORS unset or empty; no actuators loaded")
        return registry

    # Split on comma, strip whitespace, ignore empty tokens
    actuator_names = [
        name.strip() for name in actuator_names_raw.split(",") if name.strip()
    ]

    # Lazy-load and register each actuator
    loaded_ids: list[str] = []
    for name in actuator_names:
        actuator = _load_actuator(name)
        registry.register(actuator)
        loaded_ids.append(actuator.actuator_id)

    logger.info(
        "Loaded %d execution actuator(s): %s",
        len(loaded_ids),
        ", ".join(loaded_ids),
    )

    return registry
