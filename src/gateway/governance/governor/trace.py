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

"""Governance trace events: one per governor decision, one per actuation.

Each event projects onto a ``proof.model.State``, so an evidence stream can be
checked against the formal model after the fact
(``scripts/check_trace_conformance.py``, ``proof/trace_conformance.py``).
The kernel never imports ``proof/``; the event schema is the contract.

A decision event carries the run's ``plan`` (stages selected, in execution
order, with their phase) and ``outcomes`` (``PASS``/``FAIL`` per stage that
ran), the verdict, the model phase it maps to, and ``seal_ref`` (SHA-256 of
the seal, never the seal itself).  The actuation event carries only the
``seal_ref`` of the seal consumed, which the checker joins to its issuance.

Events are published best effort, like refusal receipts' companion
telemetry: a failed publish is logged and never changes a decision.  The
authoritative evidence for a refusal remains its ``GOVERNANCE_REFUSAL``
receipt.
"""

from __future__ import annotations

import hashlib
import logging
from enum import StrEnum
from typing import Any

from src.gateway.governance.governor.pipeline import PipelineResult, Profile

logger = logging.getLogger(__name__)

TRACE_EVENT_TYPE = "GOVERNANCE_TRACE"
TRACE_SCHEMA_VERSION = 1


class TracePhase(StrEnum):
    """The proof/model.py phase a trace event maps to."""

    CHECKING = "CHECKING"  # decided without a seal and without a refusal
    SEAL_ISSUED = "SEAL_ISSUED"
    NARROW = "NARROW"  # a seal over a narrower's re-verified params
    DENIED = "DENIED"
    EXECUTED = "EXECUTED"  # the seal was verified and consumed


#: Verdicts that carry a seal when the governor issues one.
SEALING_VERDICTS = frozenset({"ALLOW", "NARROW"})


def seal_ref(seal: str) -> str:
    """A stable, non-secret reference to ``seal`` for joining trace events."""
    return hashlib.sha256(seal.encode()).hexdigest()


def trace_phase(verdict: str, *, sealed: bool) -> TracePhase:
    """Map a governor verdict to its model phase.

    A seal makes ALLOW ``SEAL_ISSUED`` and NARROW ``NARROW``. DENY is
    ``DENIED``. Every unsealed non-refusal (a DRY_RUN ALLOW, a NARROW
    candidate, REQUIRE_APPROVAL, DEFER) is still ``CHECKING``: nothing is
    authorised yet.
    """
    if verdict == "DENY":
        return TracePhase.DENIED
    if sealed and verdict == "ALLOW":
        return TracePhase.SEAL_ISSUED
    if sealed and verdict == "NARROW":
        return TracePhase.NARROW
    return TracePhase.CHECKING


def decision_trace_event(
    result: PipelineResult,
    *,
    action: str,
    profile: Profile,
    path: str,
    verdict: str,
    seal: str | None = None,
    narrower_present: bool = False,
    clamped_params_valid: bool = False,
) -> dict[str, Any]:
    """The trace event for one governor decision over ``result``.

    For NARROW, ``result`` is the refused run whose findings were narrowed
    (the model's NARROW state records where the original run failed), and
    ``seal`` is the seal over the re-verified params.
    """
    if seal is not None and verdict not in SEALING_VERDICTS:
        raise ValueError(f"verdict {verdict} cannot carry a seal")
    return {
        "type": TRACE_EVENT_TYPE,
        "schema_version": TRACE_SCHEMA_VERSION,
        "action": action,
        "path": path,
        "profile": profile.value,
        "verdict": verdict,
        "phase": trace_phase(verdict, sealed=seal is not None).value,
        "seal_present": seal is not None,
        "seal_ref": seal_ref(seal) if seal is not None else None,
        "governed": result.governed,
        "narrower_present": narrower_present,
        "clamped_params_valid": clamped_params_valid,
        "plan": [list(entry) for entry in result.plan],
        "outcomes": [list(entry) for entry in result.stage_outcomes],
    }


def executed_trace_event(seal: str, *, action: str) -> dict[str, Any]:
    """The trace event for a seal verified and consumed at the actuator."""
    return {
        "type": TRACE_EVENT_TYPE,
        "schema_version": TRACE_SCHEMA_VERSION,
        "action": action,
        "path": "actuation",
        "phase": TracePhase.EXECUTED.value,
        "seal_present": True,
        "seal_ref": seal_ref(seal),
    }


async def publish_trace(event: dict[str, Any]) -> None:
    """Append ``event`` to the evidence stream, best effort."""
    from src.gateway.governance.evidence.stream import get_evidence_sink

    try:
        await get_evidence_sink().ingest(event)
    except Exception as exc:  # noqa: BLE001 - telemetry never changes a decision
        logger.warning("Failed to publish %s event: %s", TRACE_EVENT_TYPE, exc)
