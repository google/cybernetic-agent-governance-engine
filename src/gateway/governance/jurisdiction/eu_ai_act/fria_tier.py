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

"""The ``fria`` tier: EU AI Act Art. 27 Fundamental Rights Impact Assessment.

Exists only under the EU jurisdiction contribution (D-L). For every action it
claims, ``evaluate()``:

1. refuses (HARD ``FRIA_ASSESSMENT_STALE``) when the deployer's FRIA artefact
   for the action — or the system-wide ``"*"`` artefact — is missing,
   unparseable, future-dated, or older than the reassessment interval
   (Art. 27(2)); no provider call is made for an unassessed action;
2. consults the normative provider's ``validate_fria()`` under a timeout:

   * unreachable, timed out, raised, or returned ``error`` → HARD
     ``FRIA_PROVIDER_UNAVAILABLE`` (an EU deployment never runs unassessed);
   * admitted → no violation;
   * refused with a ``needs_human_review`` finding → HITL
     ``FRIA_EXTERNAL_HOLD`` (the governor parks an approval token);
   * refused otherwise → HARD ``FRIA_REJECTED``.

Model confidence plays no part: a confident model is not an impact
assessment, so the old confidence fast path that skipped the provider is
deliberately absent. ``ConfidenceStage`` owns the confidence band in every
region.
"""

from __future__ import annotations

import asyncio
import logging
import math
from collections.abc import Callable, Mapping
from datetime import datetime, timedelta, timezone
from typing import Any

from src.gateway.governance.constants import GovernanceControl
from src.gateway.governance.contracts import CommitReceipt, Violation, ViolationKind
from src.gateway.governance.seams.normative import NormativeProvider

logger = logging.getLogger(__name__)

FRIA_TIER_NAME = "fria"
#: Phase-1 slot after ``causal`` (order 6).
FRIA_TIER_ORDER = 7
#: Artefact key covering every action not assessed individually.
SYSTEM_WIDE_ASSESSMENT = "*"

CODE_STALE = "FRIA_ASSESSMENT_STALE"
CODE_UNAVAILABLE = "FRIA_PROVIDER_UNAVAILABLE"
CODE_HOLD = "FRIA_EXTERNAL_HOLD"
CODE_REJECTED = "FRIA_REJECTED"

_CONTROL = GovernanceControl.FRIA_ASSESSMENT.value

#: ``action -> artefact`` where an artefact carries an ISO-8601 ``assessed_at``.
AssessmentLookup = Callable[[str], Mapping[str, Any] | None]
ActionClaim = Callable[[str, Mapping[str, Any]], bool]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class FriaTier:
    """Phase-1, read-only ``GovernanceTierPlugin`` for ``CTRL_FRIA_006``.

    Args:
        provider: The deployment's ``NormativeProvider``.
        region: Region sent to the provider with every validation.
        assessment_lookup: Returns the FRIA artefact recorded for an action
            key (an action name or :data:`SYSTEM_WIDE_ASSESSMENT`), or None.
        reassessment_interval_days: Maximum artefact age (Art. 27(2)).
        gate_timeout_seconds: Upper bound on one ``validate_fria()`` call.
        claims: Which actions are high-risk (e.g. a domain's Annex III
            classifier). ``None`` claims every action — fail closed until the
            domain can say which of its actions are not high-risk.
        clock: Current time (UTC, timezone-aware); injectable for tests.

    Raises:
        ValueError: The interval or timeout is not a positive finite number.
    """

    phase = 1
    order = FRIA_TIER_ORDER
    tier_name = FRIA_TIER_NAME
    runtime_requirements: tuple[str, ...] = ()

    def __init__(
        self,
        provider: NormativeProvider,
        *,
        region: str,
        assessment_lookup: AssessmentLookup,
        reassessment_interval_days: float,
        gate_timeout_seconds: float,
        claims: ActionClaim | None = None,
        clock: Callable[[], datetime] = _utcnow,
    ) -> None:
        for name, value in (
            ("reassessment_interval_days", reassessment_interval_days),
            ("gate_timeout_seconds", gate_timeout_seconds),
        ):
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not (
                math.isfinite(value) and value > 0
            ):
                raise ValueError(f"FriaTier: {name} must be a positive finite number, got {value!r}")
        self._provider = provider
        self._region = region
        self._lookup = assessment_lookup
        self._interval = timedelta(days=float(reassessment_interval_days))
        self._timeout = float(gate_timeout_seconds)
        self._claims = claims
        self._clock = clock

    @property
    def provider(self) -> NormativeProvider:
        return self._provider

    def claims_action(self, action: str, params: dict[str, Any]) -> bool:
        return True if self._claims is None else bool(self._claims(action, params))

    async def evaluate(self, action: str, params: dict[str, Any]) -> list[Violation]:
        stale = self._staleness(action)
        if stale is not None:
            return [self._violation(CODE_STALE, ViolationKind.HARD, stale)]
        try:
            result = await asyncio.wait_for(
                self._provider.validate_fria(self._payload(action, params)),
                timeout=self._timeout,
            )
        except asyncio.TimeoutError:
            return [self._unavailable(f"validate_fria timed out after {self._timeout:.1f}s")]
        except Exception as exc:
            return [self._unavailable(f"validate_fria raised {type(exc).__name__}: {exc}")]
        if result.error:
            return [self._unavailable(f"provider reported an error: {result.error}")]
        if result.admitted:
            return []
        hold = next((f for f in result.findings if f.get("needs_human_review") is True), None)
        if hold is not None:
            detail = hold.get("message") or "provider escalated the assessment to a human reviewer"
            return [self._violation(CODE_HOLD, ViolationKind.HITL, f"FRIA hold: {detail}")]
        return [
            self._violation(
                CODE_REJECTED,
                ViolationKind.HARD,
                f"FRIA refused the action; findings={list(result.findings)!r}",
            )
        ]

    async def commit(
        self, action: str, params: dict[str, Any]
    ) -> tuple[list[Violation], CommitReceipt | None]:
        return [], None  # phase 1: never called with effect

    async def rollback(self, action: str, params: dict[str, Any], receipt: CommitReceipt) -> None:
        return None

    # ------------------------------------------------------------------

    def _staleness(self, action: str) -> str | None:
        """Why the action's FRIA artefact is not current, or None if it is."""
        try:
            artefact = self._lookup(action) or self._lookup(SYSTEM_WIDE_ASSESSMENT)
        except Exception as exc:  # an unreadable record is no record
            return f"FRIA artefact lookup failed ({type(exc).__name__}: {exc})"
        if not artefact:
            return f"no FRIA artefact recorded for {action!r} or system-wide"
        raw = artefact.get("assessed_at")
        try:
            assessed_at = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        except ValueError:
            return f"FRIA artefact assessed_at {raw!r} is not ISO-8601"
        if assessed_at.tzinfo is None:
            return f"FRIA artefact assessed_at {raw!r} has no timezone"
        now = self._clock()
        if assessed_at > now:
            return f"FRIA artefact assessed_at {raw!r} lies in the future"
        if now - assessed_at > self._interval:
            return (
                f"FRIA artefact assessed_at {raw!r} is older than the "
                f"{self._interval.days}-day reassessment interval (Art. 27(2))"
            )
        return None

    def _payload(self, action: str, params: Mapping[str, Any]) -> dict[str, Any]:
        thread_id = params.get("thread_id") or params.get("transaction_id") or ""
        return {
            "action": action,
            "params": dict(params),
            "thread_id": str(thread_id),
            "region": self._region,
            "control_id": _CONTROL,
        }

    def _unavailable(self, detail: str) -> Violation:
        logger.error("[fria] %s — failing closed", detail)
        return self._violation(CODE_UNAVAILABLE, ViolationKind.HARD, detail)

    def _violation(self, code: str, kind: ViolationKind, detail: str) -> Violation:
        # The [CTRL_…] prefix lets refusal payloads resolve the control's citation.
        return Violation(tier=FRIA_TIER_NAME, code=code, message=f"[{_CONTROL}] {detail}", kind=kind)
