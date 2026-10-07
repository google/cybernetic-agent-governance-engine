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

"""Warrant reliance gate: a per-norm, read-only kernel stage.

Governing rule (Warrant Contract v0.1): a warrant failure removes CAGE's
right to rely on that norm. It does not itself become an ALLOW or a DENY.

For every :class:`~src.gateway.governance.contracts.NormBinding` that
requires a warrant and governs the requested action, the stage fetches the
issuer's current warrant from the configured
:class:`~src.gateway.governance.seams.warrant.WarrantSource` and verifies its
standing with the kernel :class:`WarrantStandingVerifier` against the
evaluation context (``action``, the deployment ``jurisdiction`` and the
binding's ``governing_version``). Each norm that is not eligible yields one
``RELIANCE_INELIGIBLE`` violation, which the classifier turns into DEFER.

Any failure is ineligible, never "in scope": no warrant (MISSING), a
revoked, suspended, expired, tampered, out-of-scope or other-version
warrant, a warrant for another norm, and a source that raises or does not
answer within ``fetch_timeout_seconds``.

This is not a pre-OPA short-circuit. The stage emits only non-HARD findings,
so the pipeline still runs every other stage: an independent HARD finding
(OPA, STPA, FTRA, a barrier) still denies, and a warrant failure can never
mask it. The binding's ``value`` is bound to the warrant through
``governing_version``: the v0.1 warrant carries no value field, so a value
change needs a new version and a re-issued warrant.

The stage is assembled only when some binding requires a warrant
(``assembly.assemble_governor``); it adds no proof states of its own. Its
findings are covered by the verdict lattice in ``proof/model.py``
(``RELIANCE_INELIGIBLE``).

Besides its findings, the stage reports one
:class:`~src.gateway.governance.warrant.reliance.RelianceRecord` per
governing warranted norm, eligible or not, in ``StageOutput.reliance``. The
pipeline carries them in ``PipelineResult.reliance`` into the seal's evidence
record (ALLOW / NARROW), the parked ``DeferToken`` and its deferral evidence
(DEFER / REQUIRE_APPROVAL) and the ``RefusalReceipt`` (DENY), and the
envelope's ``WARRANT`` attestations.
"""

from __future__ import annotations

import asyncio
import math
from collections.abc import Callable, Sequence
from datetime import datetime, timezone

from opentelemetry import trace

from src.gateway.governance.contracts import NormBinding, Violation, ViolationKind
from src.gateway.governance.governor.pipeline import Stage, StageContext, StageOutput
from src.gateway.governance.seams.warrant import WarrantSource
from src.gateway.governance.warrant.model import (
    RelianceStatus,
    StandingVerificationResult,
)
from src.gateway.governance.warrant.reliance import RelianceRecord
from src.gateway.governance.warrant.verifier import WarrantStandingVerifier

tracer = trace.get_tracer(__name__)

#: Upper bound on one warrant fetch; an unanswered fetch is ineligible.
DEFAULT_FETCH_TIMEOUT_SECONDS = 2.0

#: ``Violation.code`` prefix; the suffix is the ``RelianceStatus`` value.
RELIANCE_CODE_PREFIX = "RELIANCE_"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class WarrantStage(Stage):
    """Gate each warranted norm an action relies on (phase 1, read-only)."""

    name: str = "warrant"
    mutating: bool = False

    def __init__(
        self,
        bindings: Sequence[NormBinding],
        source: WarrantSource,
        *,
        jurisdiction: str,
        clock: Callable[[], datetime] = _utc_now,
        fetch_timeout_seconds: float = DEFAULT_FETCH_TIMEOUT_SECONDS,
    ) -> None:
        warranted = tuple(b for b in bindings if b.requires_warrant)
        if not warranted:
            raise ValueError("WarrantStage needs at least one warranted NormBinding")
        if not isinstance(source, WarrantSource):
            raise TypeError(
                f"{type(source).__name__} does not implement the WarrantSource seam"
            )
        if not isinstance(jurisdiction, str) or not jurisdiction:
            raise ValueError("WarrantStage needs the deployment jurisdiction")
        if (
            isinstance(fetch_timeout_seconds, bool)
            or not isinstance(fetch_timeout_seconds, (int, float))
            or not math.isfinite(fetch_timeout_seconds)
            or fetch_timeout_seconds <= 0
        ):
            raise ValueError(
                "fetch_timeout_seconds must be a finite positive number, "
                f"got {fetch_timeout_seconds!r}"
            )
        self._bindings = warranted
        self._source = source
        self._jurisdiction = jurisdiction
        self._clock = clock
        self._timeout = float(fetch_timeout_seconds)

    @property
    def bindings(self) -> tuple[NormBinding, ...]:
        """The warranted norms this stage gates."""
        return self._bindings

    @property
    def source_name(self) -> str:
        return str(self._source.provider_name)

    async def run(self, ctx: StageContext) -> StageOutput:
        governing = [b for b in self._bindings if b.governs(ctx.action)]
        if not governing:
            return StageOutput()
        with tracer.start_as_current_span("cage.warrant_check") as span:
            span.set_attribute("governance.stage", self.name)
            span.set_attribute("cage.warrant.source", self.source_name)
            span.set_attribute("cage.warrant.norms", [b.norm_id for b in governing])
            now = self._clock()
            standings = await asyncio.gather(
                *(self._standing(b, ctx.action, now) for b in governing)
            )
            records = tuple(
                RelianceRecord(
                    norm_id=binding.norm_id,
                    governing_version=str(binding.governing_version),
                    provider_name=self.source_name,
                    standing=standing,
                )
                for binding, standing in zip(governing, standings, strict=True)
            )
            violations = tuple(
                self._violation(record) for record in records if not record.eligible
            )
            span.set_attribute("cage.warrant.ineligible_count", len(violations))
            return StageOutput(violations=violations, reliance=records)

    async def _standing(
        self, binding: NormBinding, action: str, now: datetime
    ) -> StandingVerificationResult:
        evaluated_at = now.isoformat()
        try:
            warrant = await asyncio.wait_for(
                self._source.fetch(binding.norm_id), timeout=self._timeout
            )
        except Exception as exc:  # timeout or source fault: ineligible, never ALLOW
            return StandingVerificationResult(
                eligible=False,
                reliance_status=RelianceStatus.INELIGIBLE_UNRESOLVED,
                reason=(
                    f"warrant source {self.source_name!r} failed: "
                    f"{type(exc).__name__}: {exc}"
                ),
                evaluated_at=evaluated_at,
            )
        if warrant is not None and warrant.norm_id != binding.norm_id:
            return StandingVerificationResult(
                eligible=False,
                reliance_status=RelianceStatus.INELIGIBLE_UNRESOLVED,
                reason=(
                    f"warrant source returned a warrant for norm {warrant.norm_id!r} "
                    f"when {binding.norm_id!r} was requested"
                ),
                evaluated_at=evaluated_at,
                warrant=warrant,
                warrant_id=warrant.warrant_id,
                warrant_digest=warrant.digest,
            )
        return WarrantStandingVerifier.verify_standing(
            warrant,
            context={
                "action": action,
                "jurisdiction": self._jurisdiction,
                "governing_version": binding.governing_version,
            },
            now=now,
        )

    def _violation(self, record: RelianceRecord) -> Violation:
        status = record.reliance_status.value
        return Violation(
            tier=self.name,
            code=f"{RELIANCE_CODE_PREFIX}{status}",
            message=(
                f"norm {record.norm_id!r} is ineligible for reliance "
                f"({status}): {record.standing.reason}"
            ),
            kind=ViolationKind.RELIANCE_INELIGIBLE,
        )


__all__ = ["DEFAULT_FETCH_TIMEOUT_SECONDS", "RELIANCE_CODE_PREFIX", "WarrantStage"]
