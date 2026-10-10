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

"""Warrant freshness cache: the Warrant Contract v0.1 reliance window.

The frozen contract (Q2) lets CAGE rely on a warrant state for at most 60 s.
:class:`WarrantCache` wraps a
:class:`~src.gateway.governance.seams.warrant.WarrantSource` and enforces that
window for the kernel ``WarrantStage``:

* Every warrant the source returns is stamped with **CAGE's receipt time**
  (``observed_at``): a monotonic reading for the age arithmetic and a UTC wall
  clock reading for evidence. The v0.1 schema carries no issuer
  ``state_as_of``, so freshness is measured from receipt, never from a time the
  issuer declares.
* A cached warrant is served only while ``age <= max_age_seconds``. Past that
  the cache re-fetches; a re-fetched state (e.g. ``REVOKED``) replaces the
  cached one at once.
* A re-fetch that raises or does not answer within ``fetch_timeout_seconds``
  never extends the old state: the observation is ``STALE`` and the stage maps
  it to ``INELIGIBLE_STALE`` (a ``RELIANCE_INELIGIBLE`` finding, so DEFER). A
  fetch failure with no earlier observation is ``UNRESOLVED``.
* ``None`` from the source (MISSING) is never cached, so a newly issued warrant
  is seen on the next request; it also drops any earlier cached state.
* An answer that is neither a ``Warrant`` nor ``None`` (a malformed payload)
  is a source fault like an exception: it is never cached or relied on.
* Concurrent requests for one norm share a single in-flight fetch
  (single-flight), so an expired entry cannot fan out into a burst of fetches.

The cache is built by the composition root (``assemble_governor``) from the
validated ``warrant`` thresholds; it is never a module-level singleton. It
decides freshness only; reliance eligibility stays with
``WarrantStandingVerifier``.
"""

from __future__ import annotations

import asyncio
import math
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum

from src.gateway.governance.seams.warrant import WarrantSource
from src.gateway.governance.warrant.model import Warrant
from src.gateway.governance.warrant.trust_anchor import (
    VerifiedKeyManifest,
    WarrantTrustAnchor,
)

#: Longest reliance window the frozen Warrant Contract v0.1/v0.2 permits (Q2).
CONTRACT_MAX_AGE_SECONDS: float = 60.0

#: Default reliance window: the contract maximum.
DEFAULT_MAX_AGE_SECONDS: float = CONTRACT_MAX_AGE_SECONDS

#: Default upper bound on one source fetch.
DEFAULT_FETCH_TIMEOUT_SECONDS: float = 2.0


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _positive_seconds(name: str, value: object) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, int | float)
        or not math.isfinite(value)
        or value <= 0
    ):
        raise ValueError(f"{name} must be a finite positive number, got {value!r}")
    return float(value)


@dataclass(frozen=True)
class WarrantClock:
    """The two clocks warrant reliance reads, injected once at assembly.

    ``monotonic`` measures how old a cached warrant state is (the freshness
    window). ``wall_clock`` (UTC, timezone-aware) stamps receipt and
    evaluation times in the reliance evidence and is the ``now`` the standing
    verifier checks a warrant's validity window against. The defaults are the
    process clocks; tests pass hand-advanced ones, so nothing sleeps.
    """

    monotonic: Callable[[], float] = time.monotonic
    wall_clock: Callable[[], datetime] = _utc_now


class WarrantFreshness(str, Enum):
    """Whether CAGE may rely on the observed warrant state at all."""

    #: Observed within ``max_age_seconds`` (a cache hit or a fresh fetch).
    FRESH = "FRESH"
    #: The window elapsed and the re-fetch failed; the last state is too old.
    STALE = "STALE"
    #: The fetch failed and no earlier state was ever observed.
    UNRESOLVED = "UNRESOLVED"


@dataclass(frozen=True)
class WarrantObservation:
    """The warrant state the cache hands to the stage for one norm.

    ``warrant`` is the source's answer (``None`` = MISSING) when ``FRESH``,
    the last observed warrant when ``STALE`` (evidence only, never relied
    on), and ``None`` when ``UNRESOLVED``. ``observed_at`` and
    ``age_seconds`` describe that answer's receipt; both are ``None`` when
    nothing was observed. ``error`` names the fetch failure, if any.
    ``key_manifest`` is the out-of-band verified key manifest when the source
    operates under Warrant Contract v0.2.
    """

    norm_id: str
    freshness: WarrantFreshness
    warrant: Warrant | None
    observed_at: datetime | None
    age_seconds: float | None
    max_age_seconds: float
    error: str = ""
    key_manifest: VerifiedKeyManifest | None = None
    manifest_error: str = ""

    @property
    def fresh(self) -> bool:
        return self.freshness is WarrantFreshness.FRESH


@dataclass(frozen=True)
class _Entry:
    warrant: Warrant
    observed_monotonic: float
    observed_at: datetime


@dataclass(frozen=True)
class _ManifestEntry:
    manifest: VerifiedKeyManifest
    observed_monotonic: float


class WarrantCache:
    """Read-through warrant cache enforcing the reliance freshness window."""

    def __init__(
        self,
        source: WarrantSource,
        *,
        max_age_seconds: float = DEFAULT_MAX_AGE_SECONDS,
        fetch_timeout_seconds: float = DEFAULT_FETCH_TIMEOUT_SECONDS,
        monotonic: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        if not isinstance(source, WarrantSource):
            raise TypeError(
                f"{type(source).__name__} does not implement the WarrantSource seam"
            )
        max_age = _positive_seconds("max_age_seconds", max_age_seconds)
        if max_age > CONTRACT_MAX_AGE_SECONDS:
            raise ValueError(
                f"max_age_seconds={max_age:g} exceeds the Warrant Contract v0.1 "
                f"freshness window of {CONTRACT_MAX_AGE_SECONDS:g}s"
            )
        timeout = _positive_seconds("fetch_timeout_seconds", fetch_timeout_seconds)
        if timeout >= max_age:
            raise ValueError(
                f"fetch_timeout_seconds={timeout:g} must be shorter than "
                f"max_age_seconds={max_age:g}"
            )
        self._source = source
        self._max_age = max_age
        self._timeout = timeout
        self._monotonic = monotonic
        self._wall_clock = wall_clock
        self._entries: dict[str, _Entry] = {}
        self._inflight: dict[str, asyncio.Task[WarrantObservation]] = {}
        self._manifest_entry: _ManifestEntry | None = None

    @property
    def provider_name(self) -> str:
        """The wrapped source's identifier (recorded in reliance evidence)."""
        return str(self._source.provider_name)

    @property
    def max_age_seconds(self) -> float:
        return self._max_age

    @property
    def fetch_timeout_seconds(self) -> float:
        return self._timeout

    async def observe(self, norm_id: str) -> WarrantObservation:
        """The warrant state for ``norm_id`` CAGE may rely on right now.

        Serves the cached warrant while it is within the window; otherwise
        re-fetches (single-flight per norm).
        """
        entry = self._entries.get(norm_id)
        if entry is not None:
            age = self._age_of(entry)
            if age <= self._max_age:
                obs = self._observation(norm_id, WarrantFreshness.FRESH, entry, age)
                return await self._attach_manifest(obs)
        obs = await self._refresh_once(norm_id)
        return await self._attach_manifest(obs)

    async def _attach_manifest(
        self, observation: WarrantObservation
    ) -> WarrantObservation:
        warrant = observation.warrant
        trust_anchor = getattr(self._source, "trust_anchor", None)
        if not observation.fresh or warrant is None:
            return observation
        if not warrant.is_v02 and trust_anchor is None:
            return observation
        manifest, manifest_error = await self._resolve_key_manifest(trust_anchor)
        return WarrantObservation(
            norm_id=observation.norm_id,
            freshness=observation.freshness,
            warrant=observation.warrant,
            observed_at=observation.observed_at,
            age_seconds=observation.age_seconds,
            max_age_seconds=observation.max_age_seconds,
            error=observation.error,
            key_manifest=manifest,
            manifest_error=manifest_error,
        )

    async def _resolve_key_manifest(
        self, trust_anchor: WarrantTrustAnchor | None
    ) -> tuple[VerifiedKeyManifest | None, str]:
        if trust_anchor is None:
            return (
                None,
                f"warrant source {self.provider_name!r} has no trust_anchor "
                "configured for v0.2 signature verification",
            )
        now = self._wall_clock()
        cached = self._manifest_entry
        if cached is not None:
            age = max(0.0, self._monotonic() - cached.observed_monotonic)
            if (
                age <= self._max_age
                and cached.manifest.anchor_fingerprint == trust_anchor.fingerprint
                and cached.manifest.is_valid_at(now)
            ):
                return cached.manifest, ""
        fetch_fn = getattr(self._source, "fetch_key_manifest", None)
        if not callable(fetch_fn):
            return (
                None,
                f"warrant source {self.provider_name!r} does not implement "
                "fetch_key_manifest()",
            )
        try:
            raw_manifest = await asyncio.wait_for(fetch_fn(), timeout=self._timeout)
            if raw_manifest is None:
                return None, "key manifest is missing"
            if isinstance(raw_manifest, VerifiedKeyManifest):
                if raw_manifest.anchor_fingerprint != trust_anchor.fingerprint:
                    return (
                        None,
                        "key manifest anchor fingerprint does not match source trust_anchor",
                    )
                if not raw_manifest.is_valid_at(now):
                    return None, "key manifest is outside its validity window"
                verified = raw_manifest
            else:
                verified = VerifiedKeyManifest.verify(
                    raw_manifest, trust_anchor, now=now
                )
        except Exception as exc:
            return None, f"{type(exc).__name__}: {exc}"
        self._manifest_entry = _ManifestEntry(
            manifest=verified, observed_monotonic=self._monotonic()
        )
        return verified, ""

    def _age_of(self, entry: _Entry) -> float:
        # A clock reading earlier than the receipt never yields a negative age.
        return max(0.0, self._monotonic() - entry.observed_monotonic)

    def _observation(
        self,
        norm_id: str,
        freshness: WarrantFreshness,
        entry: _Entry | None,
        age: float | None,
        error: str = "",
    ) -> WarrantObservation:
        return WarrantObservation(
            norm_id=norm_id,
            freshness=freshness,
            warrant=entry.warrant if entry is not None else None,
            observed_at=entry.observed_at if entry is not None else None,
            age_seconds=age,
            max_age_seconds=self._max_age,
            error=error,
        )

    async def _refresh_once(self, norm_id: str) -> WarrantObservation:
        loop = asyncio.get_running_loop()
        task = self._inflight.get(norm_id)
        if task is None or task.done() or task.get_loop() is not loop:
            task = loop.create_task(self._refresh(norm_id))
            self._inflight[norm_id] = task
            task.add_done_callback(lambda done: self._forget(norm_id, done))
        # ``shield``: one cancelled waiter must not cancel the shared fetch.
        return await asyncio.shield(task)

    def _forget(self, norm_id: str, task: asyncio.Task[WarrantObservation]) -> None:
        if self._inflight.get(norm_id) is task:
            del self._inflight[norm_id]

    async def _refresh(self, norm_id: str) -> WarrantObservation:
        try:
            warrant = await asyncio.wait_for(
                self._source.fetch(norm_id), timeout=self._timeout
            )
        except Exception as exc:  # timeout or source fault: never extends the state
            return self._failed(norm_id, exc)
        if warrant is not None and not isinstance(warrant, Warrant):
            # A malformed answer is a source fault, never a cached state.
            return self._failed(
                norm_id,
                TypeError(f"returned {type(warrant).__name__}, not a Warrant"),
            )
        received_monotonic = self._monotonic()
        received_at = self._wall_clock()
        if warrant is None:
            self._entries.pop(norm_id, None)  # MISSING is never cached
            return WarrantObservation(
                norm_id=norm_id,
                freshness=WarrantFreshness.FRESH,
                warrant=None,
                observed_at=received_at,
                age_seconds=0.0,
                max_age_seconds=self._max_age,
            )
        entry = _Entry(warrant, received_monotonic, received_at)
        self._entries[norm_id] = entry
        return self._observation(norm_id, WarrantFreshness.FRESH, entry, 0.0)

    def _failed(self, norm_id: str, exc: Exception) -> WarrantObservation:
        if isinstance(exc, TimeoutError):
            error = (
                f"warrant source {self.provider_name!r} did not answer within "
                f"{self._timeout:g}s"
            )
        else:
            error = (
                f"warrant source {self.provider_name!r} failed: "
                f"{type(exc).__name__}: {exc}"
            )
        entry = self._entries.get(norm_id)
        if entry is None:
            return self._observation(
                norm_id, WarrantFreshness.UNRESOLVED, None, None, error
            )
        return self._observation(
            norm_id, WarrantFreshness.STALE, entry, self._age_of(entry), error
        )


__all__ = [
    "CONTRACT_MAX_AGE_SECONDS",
    "DEFAULT_FETCH_TIMEOUT_SECONDS",
    "DEFAULT_MAX_AGE_SECONDS",
    "WarrantCache",
    "WarrantClock",
    "WarrantFreshness",
    "WarrantObservation",
]
