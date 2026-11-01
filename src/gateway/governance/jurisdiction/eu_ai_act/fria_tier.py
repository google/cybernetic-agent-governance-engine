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
2. refuses (HARD ``FRIA_MAGNITUDE_INVALID``, carrying the ``MAGNITUDE_*``
   reason) when the payload it would send breaks the domain's declared
   consequence magnitudes (``ConsequenceMagnitudes``): an undeclared action, a
   declared magnitude that is absent, or one that is not a whole, positive
   number of minor units. No provider call is made, and a tier built without
   a policy refuses every action;
3. consults the normative provider's ``validate_fria()`` under a timeout:

   * unreachable, timed out, raised, or returned ``error`` → HARD
     ``FRIA_PROVIDER_UNAVAILABLE`` (an EU deployment never runs unassessed);
   * admitted → no violation;
   * refused with a ``needs_human_review`` finding → HITL
     ``FRIA_EXTERNAL_HOLD`` (the governor parks an approval token);
   * refused otherwise → HARD ``FRIA_REJECTED``.

The provider's determination can change while a human reviews a held request
(a mandate revoked, screening gone stale), and the artefact can expire, so the
tier is ``revalidated_after_approval``: ``revalidate_post_hitl()`` (POST_HITL)
consults the provider again before an approved request is sealed. A refusal,
an unavailable provider or a stale artefact then denies. A
``FRIA_EXTERNAL_HOLD`` is answered only if the approval was given against it
(GHSA-f6xq-23f7-9grm).

The provider payload (:meth:`FriaTier._payload`) names the request: the
verified workload identity of the caller as ``actor_id`` / ``operator_urn``
(empty when there is none), the active trace id as ``correlation_id``
(raising :class:`ValueError` when no recording OpenTelemetry span is active,
so ``evaluate()`` fails closed locally with ``FRIA_PROVIDER_UNAVAILABLE``
without calling the provider), and a ``thread_id`` falling back from the
request's ``thread_id`` to its ``transaction_id`` to that trace id.

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

from opentelemetry import trace

from src.gateway.governance.consequence_magnitude import (
    ConsequenceMagnitudes,
    describe,
    magnitude_violations,
)
from src.gateway.governance.constants import GovernanceControl
from src.gateway.governance.contracts import ReadOnlyTier, Violation, ViolationKind
from src.gateway.governance.seams.normative import NormativeProvider

logger = logging.getLogger(__name__)

FRIA_TIER_NAME = "fria"
#: Phase-1 slot after ``causal`` (order 6).
FRIA_TIER_ORDER = 7
#: Artefact key covering every action not assessed individually.
SYSTEM_WIDE_ASSESSMENT = "*"

CODE_STALE = "FRIA_ASSESSMENT_STALE"
CODE_MAGNITUDE = "FRIA_MAGNITUDE_INVALID"
CODE_UNAVAILABLE = "FRIA_PROVIDER_UNAVAILABLE"
CODE_HOLD = "FRIA_EXTERNAL_HOLD"
CODE_REJECTED = "FRIA_REJECTED"

_CONTROL = GovernanceControl.FRIA_ASSESSMENT.value

#: ``action -> artefact`` where an artefact carries an ISO-8601 ``assessed_at``.
AssessmentLookup = Callable[[str], Mapping[str, Any] | None]
ActionClaim = Callable[[str, Mapping[str, Any]], bool]
#: The verified identity of the caller the request is evaluated for, or None.
CallerIdentity = Callable[[], str | None]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _no_caller() -> str | None:
    return None


def _trace_id() -> str:
    """The active OTel trace id (32 hex characters), or ``""`` outside a trace."""
    span_context = trace.get_current_span().get_span_context()
    return f"{span_context.trace_id:032x}" if span_context.is_valid else ""


class FriaTier(ReadOnlyTier):
    """Read-only (phase-1) tier for ``CTRL_FRIA_006``.

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
        caller_identity: The verified workload identity of the caller, sent
            as ``actor_id`` / ``operator_urn``. The EU contribution wires the
            gateway's workload identity; the default knows no caller, so the
            provider sees an empty actor (provider_01 then cannot mint a
            ConsequenceToken and refuses an admission).
        consequence_magnitudes: The domain's declared consequence-magnitude
            policy, checked against the provider payload before the provider
            is consulted. The EU contribution passes the governor's; without
            one every action is refused (``MAGNITUDE_UNDECLARED``).

    Raises:
        ValueError: The interval or timeout is not a positive finite number.
    """

    order = FRIA_TIER_ORDER
    tier_name = FRIA_TIER_NAME
    runtime_requirements: tuple[str, ...] = ()
    #: The provider's determination can be revoked, and the artefact can
    #: expire, while a human reviews a held request: POST_HITL re-runs the
    #: tier before an approved request is sealed (GHSA-f6xq-23f7-9grm).
    revalidated_after_approval = True

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
        caller_identity: CallerIdentity = _no_caller,
        consequence_magnitudes: ConsequenceMagnitudes | None = None,
    ) -> None:
        for name, value in (
            ("reassessment_interval_days", reassessment_interval_days),
            ("gate_timeout_seconds", gate_timeout_seconds),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not (math.isfinite(value) and value > 0)
            ):
                raise ValueError(
                    f"FriaTier: {name} must be a positive finite number, got {value!r}"
                )
        self._provider = provider
        self._region = region
        self._lookup = assessment_lookup
        self._interval = timedelta(days=float(reassessment_interval_days))
        self._timeout = float(gate_timeout_seconds)
        self._claims = claims
        self._clock = clock
        self._caller_identity = caller_identity
        self._magnitudes = consequence_magnitudes

    @property
    def provider(self) -> NormativeProvider:
        return self._provider

    @property
    def consequence_magnitudes(self) -> ConsequenceMagnitudes | None:
        """The declared policy the pre-flight checks, or ``None`` (refuse all)."""
        return self._magnitudes

    def claims_action(self, action: str, params: dict[str, Any]) -> bool:
        return True if self._claims is None else bool(self._claims(action, params))

    async def evaluate(self, action: str, params: dict[str, Any]) -> list[Violation]:
        stale = self._staleness(action)
        if stale is not None:
            return [self._violation(CODE_STALE, ViolationKind.HARD, stale)]
        # Built once: the payload checked is the payload sent. Building it
        # needs an active trace span for the correlation id; without one
        # the tier refuses here, before the provider is consulted.
        try:
            payload = self._payload(action, params)
        except Exception as exc:
            return [
                self._unavailable(
                    f"FRIA payload not built ({type(exc).__name__}: {exc})"
                )
            ]
        refused = magnitude_violations(self._magnitudes, payload)
        if refused:
            return [
                self._violation(
                    CODE_MAGNITUDE,
                    ViolationKind.HARD,
                    "consequence magnitude refused before the provider was "
                    f"consulted: {describe(refused)}",
                )
            ]
        try:
            result = await asyncio.wait_for(
                self._provider.validate_fria(payload),
                timeout=self._timeout,
            )
        except asyncio.TimeoutError:
            return [
                self._unavailable(f"validate_fria timed out after {self._timeout:.1f}s")
            ]
        except Exception as exc:
            return [
                self._unavailable(f"validate_fria raised {type(exc).__name__}: {exc}")
            ]
        if result.error:
            return [self._unavailable(f"provider reported an error: {result.error}")]
        if result.admitted:
            # An admission contributes no violation, so its findings -- including
            # any ConsequenceToken the provider minted -- are dropped here and do
            # not reach the routing seal. ConsequenceGateway verifies such tokens
            # only for callers that present one; it is not on the governor's
            # ALLOW path (decision D2, POAM-2026-089).
            return []
        hold = next(
            (f for f in result.findings if f.get("needs_human_review") is True), None
        )
        if hold is not None:
            detail = (
                hold.get("message")
                or "provider escalated the assessment to a human reviewer"
            )
            return [
                self._violation(CODE_HOLD, ViolationKind.HITL, f"FRIA hold: {detail}")
            ]
        return [
            self._violation(
                CODE_REJECTED,
                ViolationKind.HARD,
                f"FRIA refused the action; findings={list(result.findings)!r}",
            )
        ]

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
        """What ``validate_fria()`` receives (``NormativeProvider.validate_fria``).

        The caller and the correlation id sit at the top level, where
        adapters read them; they are never taken from ``params``, which the
        caller controls. Requires an active OpenTelemetry trace span; raises
        :class:`ValueError` when ``_trace_id()`` is empty so ``evaluate()``
        fails closed locally without calling the provider.
        """
        correlation_id = _trace_id()
        if not correlation_id:
            raise ValueError(
                "FRIA payload requires a non-empty correlation_id "
                "(no active OpenTelemetry trace span)"
            )
        thread_id = (
            params.get("thread_id") or params.get("transaction_id") or correlation_id
        )
        caller = self._caller()
        return {
            "action": action,
            "params": dict(params),
            "thread_id": str(thread_id),
            "correlation_id": correlation_id,
            "actor_id": caller,
            "operator_urn": caller,
            "region": self._region,
            "control_id": _CONTROL,
        }

    def _caller(self) -> str:
        """The verified caller identity, or ``""``; an unreadable one is none."""
        try:
            caller = self._caller_identity()
        except Exception as exc:  # an identity that cannot be read is no identity
            logger.warning("[fria] caller identity unavailable: %s", exc)
            return ""
        return caller if isinstance(caller, str) else ""

    def _unavailable(self, detail: str) -> Violation:
        logger.error("[fria] %s — failing closed", detail)
        return self._violation(CODE_UNAVAILABLE, ViolationKind.HARD, detail)

    def _violation(self, code: str, kind: ViolationKind, detail: str) -> Violation:
        # The [CTRL_…] prefix lets refusal payloads resolve the control's citation.
        return Violation(
            tier=FRIA_TIER_NAME, code=code, message=f"[{_CONTROL}] {detail}", kind=kind
        )
