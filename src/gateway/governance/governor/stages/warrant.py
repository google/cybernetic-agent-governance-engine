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
requires a warrant and governs the requested action, the stage reads the
issuer's warrant through the kernel
:class:`~src.gateway.governance.warrant.cache.WarrantCache` (which wraps the
configured :class:`~src.gateway.governance.seams.warrant.WarrantSource` and
enforces the contract's 60 s freshness window) and verifies its standing with
the kernel :class:`WarrantStandingVerifier` against the evaluation context
(``action``, the deployment ``jurisdiction`` and the binding's
``governing_version``). Each norm that is not eligible yields one
``RELIANCE_INELIGIBLE`` violation, which the classifier turns into DEFER.

Any failure is ineligible, never "in scope": no warrant (MISSING), a
revoked, suspended, expired, tampered, out-of-scope or other-version
warrant, a warrant for another norm, a source that raises or does not answer
within the cache's ``fetch_timeout_seconds`` (UNRESOLVED), and a cached
warrant older than ``max_age_seconds`` whose re-fetch failed (STALE).

This is not a pre-OPA short-circuit. The stage emits only non-HARD findings,
so the pipeline still runs every other stage: an independent HARD finding
(OPA, STPA, FTRA, a barrier) still denies, and a warrant failure can never
mask it. The binding's ``value`` is bound to the warrant through
``governing_version``: the v0.1 warrant carries no value field, so a value
change needs a new version and a re-issued warrant.

The stage is assembled only when some binding requires a warrant
(``assembly.assemble_governor``); it adds no proof states of its own. Its
findings are covered by the verdict lattice in ``proof/model.py``
(``RELIANCE_INELIGIBLE``). It also runs under ``POST_HITL``, through the same
cache: a warrant still inside the window is served, an older one is
re-fetched before the approved action may seal.

Besides its findings, the stage reports one
:class:`~src.gateway.governance.warrant.reliance.RelianceRecord` per
governing warranted norm, eligible or not, in ``StageOutput.reliance``,
including when CAGE received the warrant state (``observed_at``) and how old
it was (``age_seconds``). The pipeline carries them in
``PipelineResult.reliance`` into the seal's evidence record (ALLOW / NARROW),
the parked ``DeferToken`` and its deferral evidence (DEFER /
REQUIRE_APPROVAL) and the ``RefusalReceipt`` (DENY), and the envelope's
``WARRANT`` attestations.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Sequence
from datetime import datetime, timezone

from opentelemetry import trace

from src.gateway.governance.contracts import NormBinding, Violation, ViolationKind
from src.gateway.governance.governor.pipeline import Stage, StageContext, StageOutput
from src.gateway.governance.warrant.cache import (
    WarrantCache,
    WarrantFreshness,
    WarrantObservation,
)
from src.gateway.governance.warrant.model import (
    RelianceStatus,
    StandingVerificationResult,
)
from src.gateway.governance.warrant.reliance import RelianceRecord
from src.gateway.governance.warrant.verifier import WarrantStandingVerifier

tracer = trace.get_tracer(__name__)

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
        cache: WarrantCache,
        *,
        jurisdiction: str,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        warranted = tuple(b for b in bindings if b.requires_warrant)
        if not warranted:
            raise ValueError("WarrantStage needs at least one warranted NormBinding")
        if not isinstance(cache, WarrantCache):
            raise TypeError(
                f"WarrantStage reads warrants through a WarrantCache, got "
                f"{type(cache).__name__}"
            )
        if not isinstance(jurisdiction, str) or not jurisdiction:
            raise ValueError("WarrantStage needs the deployment jurisdiction")
        self._bindings = warranted
        self._cache = cache
        self._jurisdiction = jurisdiction
        self._clock = clock

    @property
    def bindings(self) -> tuple[NormBinding, ...]:
        """The warranted norms this stage gates."""
        return self._bindings

    @property
    def cache(self) -> WarrantCache:
        """The freshness cache every warrant read goes through."""
        return self._cache

    @property
    def source_name(self) -> str:
        return self._cache.provider_name

    async def run(self, ctx: StageContext) -> StageOutput:
        governing = [b for b in self._bindings if b.governs(ctx.action)]
        if not governing:
            return StageOutput()
        with tracer.start_as_current_span("cage.warrant_check") as span:
            span.set_attribute("governance.stage", self.name)
            span.set_attribute("cage.warrant.source", self.source_name)
            span.set_attribute("cage.warrant.norms", [b.norm_id for b in governing])
            span.set_attribute(
                "cage.warrant.max_age_seconds", self._cache.max_age_seconds
            )
            now = self._clock()
            observations = await asyncio.gather(
                *(self._cache.observe(b.norm_id) for b in governing)
            )
            records = tuple(
                self._record(binding, observation, ctx.action, now)
                for binding, observation in zip(governing, observations, strict=True)
            )
            violations = tuple(
                self._violation(record) for record in records if not record.eligible
            )
            span.set_attribute("cage.warrant.ineligible_count", len(violations))
            span.set_attribute(
                "cage.warrant.stale_count",
                sum(
                    r.reliance_status is RelianceStatus.INELIGIBLE_STALE
                    for r in records
                ),
            )
            return StageOutput(violations=violations, reliance=records)

    def _record(
        self,
        binding: NormBinding,
        observation: WarrantObservation,
        action: str,
        now: datetime,
    ) -> RelianceRecord:
        return RelianceRecord(
            norm_id=binding.norm_id,
            required_governing_version=str(binding.governing_version),
            provider_name=self.source_name,
            standing=self._standing(binding, observation, action, now),
            observed_at=(
                observation.observed_at.isoformat()
                if observation.observed_at is not None
                else ""
            ),
            age_seconds=observation.age_seconds,
            max_age_seconds=observation.max_age_seconds,
        )

    def _standing(
        self,
        binding: NormBinding,
        observation: WarrantObservation,
        action: str,
        now: datetime,
    ) -> StandingVerificationResult:
        attested_at = now.isoformat()
        warrant = observation.warrant
        if observation.freshness is WarrantFreshness.UNRESOLVED:
            return StandingVerificationResult(
                eligible=False,
                reliance_status=RelianceStatus.INELIGIBLE_UNRESOLVED,
                reason=observation.error,
                attested_at=attested_at,
            )
        if observation.freshness is WarrantFreshness.STALE:
            # The last state is evidence of what went stale, never relied on.
            return StandingVerificationResult(
                eligible=False,
                reliance_status=RelianceStatus.INELIGIBLE_STALE,
                reason=(
                    f"warrant state stale: observed {observation.age_seconds:.3f}s "
                    f"ago > {observation.max_age_seconds:g}s and re-fetch failed "
                    f"({observation.error})"
                ),
                attested_at=attested_at,
                warrant=warrant,
                warrant_id=warrant.warrant_id if warrant is not None else "",
                warrant_digest=warrant.digest if warrant is not None else "",
            )
        if warrant is not None and warrant.norm_id != binding.norm_id:
            return StandingVerificationResult(
                eligible=False,
                reliance_status=RelianceStatus.INELIGIBLE_UNRESOLVED,
                reason=(
                    f"warrant source returned a warrant for norm {warrant.norm_id!r} "
                    f"when {binding.norm_id!r} was requested"
                ),
                attested_at=attested_at,
                warrant=warrant,
                warrant_id=warrant.warrant_id,
                warrant_digest=warrant.digest,
            )
        if observation.manifest_error and observation.key_manifest is None:
            return StandingVerificationResult(
                eligible=False,
                reliance_status=RelianceStatus.INELIGIBLE_UNRESOLVED,
                reason=f"key manifest verification failed: {observation.manifest_error}",
                attested_at=attested_at,
                warrant=warrant,
                warrant_id=warrant.warrant_id if warrant is not None else "",
                warrant_digest=warrant.digest if warrant is not None else "",
            )
        return WarrantStandingVerifier.verify_standing(
            warrant,
            context={
                "action": action,
                "jurisdiction": self._jurisdiction,
                "governing_version": binding.governing_version,
                "norm_value": binding.value,
            },
            now=now,
            key_manifest=observation.key_manifest,
            max_age_seconds=observation.max_age_seconds,
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


__all__ = ["RELIANCE_CODE_PREFIX", "WarrantStage"]
