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

"""Kernel factory and dispatch module for out-of-band workload quarantine.

Provides:
  - ``InferenceProxySvidQuarantineActuator``: CAGE-native quarantine that
    revokes the offending ``thread_id`` and ``agent_svid`` in CAGE's Governance
    Redis (``db=1``) so ``inference_proxy.py`` immediately blocks all subsequent
    model inference calls ("cutting off the agent's next thought").
  - ``SimulatedQuarantineActuator``: Tier-2 posture-completing simulator with
    deterministic fault injection for hermetic tests (refused in ``prod``).
  - ``UnavailableQuarantineActuator``: Fail-closed default when unconfigured.
  - ``dispatch_quarantine()``: Executes quarantine and commits a
    ``WORKLOAD_QUARANTINE_RECEIPT`` (``controlId: "SC-7"``) to ``EvidenceStreamSink``.
"""

from __future__ import annotations

import hashlib
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any

from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
from src.gateway.governance.seams.actuation import (
    ActuationOutcome,
    ReceiptVerification,
)
from src.gateway.governance.seams.quarantine import (
    QuarantineActuator,
    QuarantineDirective,
    QuarantineReceipt,
    QuarantineTriggerReason,
)

logger = logging.getLogger("Gateway.Governance.QuarantineActuator")

_QUARANTINE_THREAD_PREFIX = "QUARANTINE:THREAD:"
_QUARANTINE_SVID_PREFIX = "QUARANTINE:SVID:"

# In-process quarantine registry backing hermetic tests and local fail-closed checks
_LOCAL_QUARANTINED_THREADS: dict[str, float] = {}
_LOCAL_QUARANTINED_SVIDS: dict[str, float] = {}


def clear_local_quarantine_state() -> None:
    """Clear in-process quarantine state (for hermetic test isolation)."""
    _LOCAL_QUARANTINED_THREADS.clear()
    _LOCAL_QUARANTINED_SVIDS.clear()


async def is_workload_quarantined(
    thread_id: str | None = None,
    agent_svid: str | None = None,
    redis_client: Any | None = None,
) -> bool:
    """Return True if the thread_id or agent_svid has been quarantined by CAGE."""
    now = time.time()
    if thread_id:
        exp = _LOCAL_QUARANTINED_THREADS.get(thread_id)
        if exp is not None and exp > now:
            return True
    if agent_svid:
        exp = _LOCAL_QUARANTINED_SVIDS.get(agent_svid)
        if exp is not None and exp > now:
            return True

    if redis_client is not None:
        try:
            if thread_id and await redis_client.exists(
                f"{_QUARANTINE_THREAD_PREFIX}{thread_id}"
            ):
                return True
            if agent_svid and await redis_client.exists(
                f"{_QUARANTINE_SVID_PREFIX}{agent_svid}"
            ):
                return True
        except Exception as exc:
            logger.error(
                "[QuarantineActuator] Redis check failed (fail-closed quarantine): %s",
                exc,
            )
            return True
    return False


class UnavailableQuarantineActuator:
    """Fail-closed default actuator when no quarantine backend is configured."""

    @property
    def actuator_id(self) -> str:
        return "unavailable_quarantine"

    async def quarantine_workload(
        self, directive: QuarantineDirective
    ) -> QuarantineReceipt:
        return QuarantineReceipt(
            quarantined=False,
            enforcement_plane="SIMULATED",
            rule_id=None,
            latency_us=None,
            outcome=ActuationOutcome.REJECTED,
            verification=ReceiptVerification.UNVERIFIED,
            findings=[
                {
                    "code": "QUARANTINE_ACTUATOR_UNCONFIGURED",
                    "severity": "TERMINAL",
                    "detail": f"No quarantine actuator configured for thread_id={directive.thread_id}",
                }
            ],
            timestamp_utc=datetime.now(tz=timezone.utc).isoformat(),
        )

    async def health_check(self) -> bool:
        return False


class SimulatedQuarantineActuator:
    """Tier-2 posture-completing local simulator with deterministic fault injection.

    Permitted only in non-production postures (``dev``, ``test``, ``ci``, ``development``).
    Raises ``RuntimeError`` if instantiated when ``CAGE_ENV`` is ``prod`` or ``production``.
    """

    def __init__(self, fault_mode: str | None = None) -> None:
        env = os.environ.get("CAGE_ENV", "dev").strip().lower()
        if env in ("prod", "production"):
            raise RuntimeError(
                "SimulatedQuarantineActuator is forbidden in production posture (CAGE_ENV=prod)"
            )
        self._fault_mode = (
            fault_mode
            if fault_mode is not None
            else os.environ.get("SIMULATED_QUARANTINE_FAULT_MODE", "").strip().upper()
        )

    @property
    def actuator_id(self) -> str:
        return "simulated_quarantine"

    async def quarantine_workload(
        self, directive: QuarantineDirective
    ) -> QuarantineReceipt:
        now_utc = datetime.now(tz=timezone.utc).isoformat()
        digest = hashlib.sha256(jcs_canonicalize_plan(directive.to_dict())).hexdigest()

        if self._fault_mode == "REJECT":
            return QuarantineReceipt(
                quarantined=False,
                enforcement_plane="SIMULATED",
                rule_id=None,
                latency_us=12.0,
                outcome=ActuationOutcome.REJECTED,
                verification=ReceiptVerification.UNVERIFIED,
                findings=[
                    {
                        "code": "SIMULATED_FAULT_REJECT",
                        "severity": "TERMINAL",
                        "detail": "Deterministic fault injection: REJECT",
                    }
                ],
                envelope_digest=digest,
                timestamp_utc=now_utc,
            )

        if self._fault_mode == "TIMEOUT":
            return QuarantineReceipt(
                quarantined=False,
                enforcement_plane="SIMULATED",
                rule_id=None,
                latency_us=None,
                outcome=ActuationOutcome.UNKNOWN,
                verification=ReceiptVerification.UNVERIFIED,
                findings=[
                    {
                        "code": "SIMULATED_FAULT_TIMEOUT",
                        "severity": "TERMINAL",
                        "detail": "Deterministic fault injection: TIMEOUT",
                    }
                ],
                envelope_digest=digest,
                timestamp_utc=now_utc,
            )

        rule_id = f"sim-qrule-{digest[:12]}"
        return QuarantineReceipt(
            quarantined=True,
            enforcement_plane="SIMULATED",
            rule_id=rule_id,
            latency_us=45.0,
            outcome=ActuationOutcome.ACCEPTED,
            verification=ReceiptVerification.VERIFIED,
            findings=[],
            envelope_digest=digest,
            timestamp_utc=now_utc,
        )

    async def health_check(self) -> bool:
        return self._fault_mode not in ("REJECT", "TIMEOUT")


class InferenceProxySvidQuarantineActuator:
    """CAGE-native quarantine actuator that blocks agent SVIDs and threads at inference_proxy.py."""

    def __init__(self, redis_client: Any | None = None) -> None:
        self._redis = redis_client

    @property
    def actuator_id(self) -> str:
        return "cage_inference_proxy_svid"

    async def quarantine_workload(
        self, directive: QuarantineDirective
    ) -> QuarantineReceipt:
        t0 = time.perf_counter()
        now_utc = datetime.now(tz=timezone.utc).isoformat()
        canonical_bytes = jcs_canonicalize_plan(directive.to_dict())
        digest = hashlib.sha256(canonical_bytes).hexdigest()
        expiry = time.time() + max(1, directive.ttl_seconds)

        if directive.thread_id:
            _LOCAL_QUARANTINED_THREADS[directive.thread_id] = expiry
        if directive.agent_svid:
            _LOCAL_QUARANTINED_SVIDS[directive.agent_svid] = expiry

        if self._redis is not None:
            try:
                if directive.thread_id:
                    await self._redis.set(
                        f"{_QUARANTINE_THREAD_PREFIX}{directive.thread_id}",
                        digest,
                        ex=max(1, directive.ttl_seconds),
                    )
                if directive.agent_svid:
                    await self._redis.set(
                        f"{_QUARANTINE_SVID_PREFIX}{directive.agent_svid}",
                        digest,
                        ex=max(1, directive.ttl_seconds),
                    )
            except Exception as exc:
                return QuarantineReceipt(
                    quarantined=False,
                    enforcement_plane="CAGE_INFERENCE_PROXY_SVID",
                    rule_id=None,
                    latency_us=(time.perf_counter() - t0) * 1_000_000.0,
                    outcome=ActuationOutcome.UNKNOWN,
                    verification=ReceiptVerification.UNVERIFIED,
                    findings=[
                        {
                            "code": "REDIS_QUARANTINE_WRITE_FAILED",
                            "severity": "TERMINAL",
                            "detail": f"{type(exc).__name__}: {exc}",
                        }
                    ],
                    envelope_digest=digest,
                    timestamp_utc=now_utc,
                )

        latency_us = (time.perf_counter() - t0) * 1_000_000.0
        rule_id = f"cage-svid-qrule-{digest[:12]}"
        return QuarantineReceipt(
            quarantined=True,
            enforcement_plane="CAGE_INFERENCE_PROXY_SVID",
            rule_id=rule_id,
            latency_us=latency_us,
            outcome=ActuationOutcome.ACCEPTED,
            verification=ReceiptVerification.VERIFIED,
            findings=[],
            envelope_digest=digest,
            timestamp_utc=now_utc,
        )

    async def health_check(self) -> bool:
        if self._redis is None:
            return True
        try:
            await self._redis.ping()
            return True
        except Exception:
            return False


def load_quarantine_actuator_from_env(
    redis_client: Any | None = None,
) -> QuarantineActuator:
    """Resolve the active QuarantineActuator from CAGE_QUARANTINE_ACTUATOR."""
    configured = os.environ.get("CAGE_QUARANTINE_ACTUATOR", "").strip().lower()
    if configured in ("actuator_03", "a03", "sentry", "doca_quarantine"):
        from src.integrations.actuator_03.adapter import Actuator03Adapter

        return Actuator03Adapter.from_env()
    if configured in ("simulated", "sim"):
        return SimulatedQuarantineActuator()
    if configured in ("cage_svid", "inference_proxy", "svid", ""):
        return InferenceProxySvidQuarantineActuator(redis_client=redis_client)
    return UnavailableQuarantineActuator()


async def dispatch_quarantine(
    directive: QuarantineDirective,
    actuator: QuarantineActuator | None = None,
) -> QuarantineReceipt:
    """Execute workload quarantine and record WORKLOAD_QUARANTINE_RECEIPT in EvidenceStreamSink."""
    active_actuator = actuator or load_quarantine_actuator_from_env()
    try:
        receipt = await active_actuator.quarantine_workload(directive)
    except Exception as exc:
        logger.error(
            "[QuarantineActuator] %s raised during quarantine_workload: %s",
            active_actuator.actuator_id,
            exc,
        )
        receipt = QuarantineReceipt(
            quarantined=False,
            enforcement_plane="SIMULATED",
            rule_id=None,
            latency_us=None,
            outcome=ActuationOutcome.UNKNOWN,
            verification=ReceiptVerification.UNVERIFIED,
            findings=[
                {
                    "code": "QUARANTINE_ACTUATOR_EXCEPTION",
                    "severity": "TERMINAL",
                    "detail": f"{type(exc).__name__}: {exc}",
                }
            ],
            timestamp_utc=datetime.now(tz=timezone.utc).isoformat(),
        )

    try:
        from src.gateway.governance.evidence.stream import get_evidence_sink

        sink = get_evidence_sink()
        await sink.ingest(
            {
                "type": "WORKLOAD_QUARANTINE_RECEIPT",
                "controlId": "SC-7",
                "quarantined": receipt.quarantined,
                "enforcement_plane": receipt.enforcement_plane,
                "rule_id": receipt.rule_id,
                "latency_us": receipt.latency_us,
                "outcome": receipt.outcome.value,
                "verification": receipt.verification.value,
                "actuator_id": active_actuator.actuator_id,
                "thread_id": directive.thread_id,
                "agent_svid": directive.agent_svid,
                "sandbox_id": directive.sandbox_id,
                "reason": directive.reason.value,
                "violation_codes": list(directive.violation_codes),
                "correlation_id": directive.correlation_id,
                "governance_decision_digest": directive.governance_decision_digest,
                "findings": list(receipt.findings),
                "envelope_digest": receipt.envelope_digest,
                "timestamp_utc": receipt.timestamp_utc
                or datetime.now(tz=timezone.utc).isoformat(),
            }
        )
    except Exception as exc:
        logger.error(
            "[QuarantineActuator] Failed to ingest WORKLOAD_QUARANTINE_RECEIPT: %s",
            exc,
        )

    return receipt


__all__ = [
    "InferenceProxySvidQuarantineActuator",
    "QuarantineActuator",
    "QuarantineDirective",
    "QuarantineReceipt",
    "QuarantineTriggerReason",
    "SimulatedQuarantineActuator",
    "UnavailableQuarantineActuator",
    "clear_local_quarantine_state",
    "dispatch_quarantine",
    "is_workload_quarantined",
    "load_quarantine_actuator_from_env",
]
