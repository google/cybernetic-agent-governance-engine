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

"""Background world-model refresher for the DoWhy Causal Gatekeeper (D1).

Moves telemetry ingestion and the 50-simulation DoWhy placebo refutation out of
the request path into a background refresher loop so the request path evaluates
only the per-request marginal risk boundary against the latest fresh
:class:`~src.gateway.governance.causal.gatekeeper.WorldModelVerdict`.

Freshness invariants (fail-closed, zero new policy thresholds):
- Before the first refresh completes, :meth:`WorldModelRefresher.current_verdict`
  returns an untrusted verdict with reason ``no_live_telemetry``.
- If ``now - computed_at > get_causal_cache_ttl_seconds()`` (60 s), the snapshot
  is rejected with reason ``stale_telemetry``.
- If ``telemetry_watermark is None`` or
  ``now - telemetry_watermark > get_telemetry_max_staleness_seconds()`` (300 s),
  a trusted verdict is downgraded to ``stale_telemetry``.
"""

from __future__ import annotations

import asyncio
import logging
import math
import os
import time
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
from typing import Any

import pandas as pd

from src.gateway.governance.causal import gatekeeper as gk_mod
from src.gateway.governance.causal.gatekeeper import (
    REASON_CHECK_ERROR,
    REASON_NO_LIVE_TELEMETRY,
    CausalGatekeeper,
    WorldModelVerdict,
    _extract_telemetry_watermark,
    validate_world_model,
)
from src.gateway.governance.schemas.thresholds import (
    get_causal_cache_ttl_seconds,
    get_causal_min_samples,
    get_telemetry_max_staleness_seconds,
)
from src.gateway.governance.telemetry_provider import BaseTelemetryProvider

logger = logging.getLogger(__name__)

DEFAULT_REFRESH_INTERVAL_SECONDS: float = 20.0
DEFAULT_TELEMETRY_WINDOW: int = 500
REASON_STALE_TELEMETRY = "stale_telemetry"
_DEFAULT_VALIDATE_FN = CausalGatekeeper._validate_world_model


def _resolve_refresh_interval(explicit: float | None) -> float:
    if explicit is not None:
        return max(0.05, float(explicit))
    raw = os.environ.get("CAGE_CAUSAL_REFRESH_INTERVAL_S")
    if raw is not None:
        try:
            return max(0.05, float(raw))
        except ValueError:
            pass
    return DEFAULT_REFRESH_INTERVAL_SECONDS


@dataclass(frozen=True)
class WorldModelSnapshot:
    """Immutable snapshot of a single background world-model validation cycle."""

    verdict: WorldModelVerdict
    computed_at: float
    telemetry_watermark: float | None
    provider_error: str | None = None


class WorldModelRefresher:
    """Periodic background refresher that computes :class:`WorldModelVerdict` off the event loop."""

    def __init__(
        self,
        gatekeeper: CausalGatekeeper,
        telemetry_provider: BaseTelemetryProvider | None = None,
        *,
        interval_seconds: float | None = None,
        telemetry_window: int = DEFAULT_TELEMETRY_WINDOW,
        use_process_pool: bool = True,
    ) -> None:
        self._gatekeeper = gatekeeper
        self._telemetry_provider = telemetry_provider
        self._interval_seconds = _resolve_refresh_interval(interval_seconds)
        self._telemetry_window = max(1, int(telemetry_window))
        self._use_process_pool = use_process_pool
        self._snapshot: WorldModelSnapshot | None = None
        self._executor: ProcessPoolExecutor | None = None
        self._refresh_lock = asyncio.Lock()

    @property
    def gatekeeper(self) -> CausalGatekeeper:
        return self._gatekeeper

    @property
    def telemetry_provider(self) -> BaseTelemetryProvider | None:
        return self._telemetry_provider

    @property
    def snapshot(self) -> WorldModelSnapshot | None:
        return self._snapshot

    def seed_snapshot(
        self,
        verdict: WorldModelVerdict,
        *,
        computed_at: float | None = None,
        telemetry_watermark: float | None = None,
        provider_error: str | None = None,
    ) -> WorldModelSnapshot:
        """Install an explicit snapshot (used by unit tests and warm-up hooks)."""
        now = time.time() if computed_at is None else float(computed_at)
        watermark = (
            now
            if (telemetry_watermark is None and verdict.trusted)
            else telemetry_watermark
        )
        snap = WorldModelSnapshot(
            verdict=verdict,
            computed_at=now,
            telemetry_watermark=watermark,
            provider_error=provider_error,
        )
        self._snapshot = snap
        return snap

    def current_verdict(
        self, *, now: float | None = None
    ) -> tuple[WorldModelVerdict, str | None]:
        """Return ``(verdict, provider_error)`` enforcing both freshness bounds.

        Fails closed when:
        - No snapshot has been computed yet -> ``no_live_telemetry``.
        - Snapshot age exceeds ``get_causal_cache_ttl_seconds()`` -> ``stale_telemetry``.
        - Snapshot verdict is ``trusted`` but ``telemetry_watermark`` is missing or
          older than ``get_telemetry_max_staleness_seconds()`` -> ``stale_telemetry``.
        """
        snap = self._snapshot
        if snap is None:
            return (
                WorldModelVerdict(False, None, REASON_NO_LIVE_TELEMETRY),
                None,
            )

        current_time = time.time() if now is None else float(now)
        cache_ttl = get_causal_cache_ttl_seconds()
        if cache_ttl > 0 and (current_time - snap.computed_at) > cache_ttl:
            logger.warning(
                "WorldModelRefresher: cached verdict is %.1fs old (ttl=%ds) — "
                "failing closed with stale_telemetry.",
                current_time - snap.computed_at,
                cache_ttl,
            )
            return (
                WorldModelVerdict(False, snap.verdict.beta, REASON_STALE_TELEMETRY),
                None,
            )

        if not snap.verdict.trusted:
            return snap.verdict, snap.provider_error

        max_staleness = get_telemetry_max_staleness_seconds()
        if (
            snap.telemetry_watermark is None
            or not math.isfinite(snap.telemetry_watermark)
            or (current_time - snap.telemetry_watermark) > max_staleness
        ):
            logger.warning(
                "WorldModelRefresher: telemetry watermark is stale or missing "
                "(max_staleness=%ds) — failing closed with stale_telemetry.",
                max_staleness,
            )
            return (
                WorldModelVerdict(False, snap.verdict.beta, REASON_STALE_TELEMETRY),
                None,
            )

        return snap.verdict, None

    async def refresh_once(self) -> WorldModelSnapshot:
        """Fetch the latest telemetry window and compute a fresh :class:`WorldModelSnapshot`."""
        async with self._refresh_lock:
            now = time.time()
            frame: pd.DataFrame | None = None
            if self._telemetry_provider is not None:
                window = max(get_causal_min_samples(), self._telemetry_window)
                try:
                    frame = await asyncio.to_thread(
                        self._telemetry_provider.get_latest_data, window
                    )
                except Exception as exc:
                    logger.error(
                        "WorldModelRefresher: telemetry provider failed (%s) — "
                        "recording fail-closed snapshot.",
                        exc,
                    )
                    snap = WorldModelSnapshot(
                        verdict=WorldModelVerdict(
                            False, None, REASON_NO_LIVE_TELEMETRY
                        ),
                        computed_at=time.time(),
                        telemetry_watermark=None,
                        provider_error=str(exc),
                    )
                    self._snapshot = snap
                    return snap

            no_live = frame is None or len(frame) == 0
            if no_live:
                if not self._gatekeeper._synthetic_telemetry_permitted():
                    snap = WorldModelSnapshot(
                        verdict=WorldModelVerdict(
                            False, None, REASON_NO_LIVE_TELEMETRY
                        ),
                        computed_at=time.time(),
                        telemetry_watermark=None,
                    )
                    self._snapshot = snap
                    return snap
                factory = self._gatekeeper.spec.synthetic_telemetry_factory
                if factory is None:
                    snap = WorldModelSnapshot(
                        verdict=WorldModelVerdict(
                            False, None, REASON_NO_LIVE_TELEMETRY
                        ),
                        computed_at=time.time(),
                        telemetry_watermark=None,
                    )
                    self._snapshot = snap
                    return snap
                try:
                    frame = await asyncio.to_thread(factory)
                except Exception as exc:
                    logger.error(
                        "WorldModelRefresher: synthetic_telemetry_factory failed (%s) — "
                        "failing closed.",
                        exc,
                    )
                    snap = WorldModelSnapshot(
                        verdict=WorldModelVerdict(False, None, REASON_CHECK_ERROR),
                        computed_at=time.time(),
                        telemetry_watermark=None,
                    )
                    self._snapshot = snap
                    return snap

            assert frame is not None
            watermark = _extract_telemetry_watermark(frame)
            try:
                verdict = await self._compute_verdict(frame)
            except Exception as exc:
                logger.error(
                    "WorldModelRefresher: world-model validation failed (%s) — "
                    "failing closed.",
                    exc,
                )
                verdict = WorldModelVerdict(False, None, REASON_CHECK_ERROR)

            now = time.time()
            snap = WorldModelSnapshot(
                verdict=verdict,
                computed_at=now,
                telemetry_watermark=watermark,
            )
            self._snapshot = snap
            return snap

    async def _compute_verdict(self, frame: pd.DataFrame) -> WorldModelVerdict:
        spec = self._gatekeeper.spec
        if not spec.graph_dot or not spec.treatment_col or not spec.outcome_col:
            return WorldModelVerdict(False, None, gk_mod.REASON_INCOMPLETE_SPEC)

        # If a test or caller monkeypatched _validate_world_model or _CausalModel
        # in-process, or disabled the process pool, run in a worker thread so
        # in-process monkeypatches take effect without blocking the event loop.
        validate_attr = getattr(type(self._gatekeeper), "_validate_world_model", None)
        custom_validate = (
            "_validate_world_model" in self._gatekeeper.__dict__
            or validate_attr is not _DEFAULT_VALIDATE_FN
            or not isinstance(gk_mod._CausalModel, type)
            or gk_mod._CausalModel.__module__.startswith("tests")
        )
        if not self._use_process_pool or custom_validate:
            return await asyncio.to_thread(
                self._gatekeeper._validate_world_model, frame
            )

        loop = asyncio.get_running_loop()
        if self._executor is None:
            self._executor = ProcessPoolExecutor(max_workers=1)
        return await loop.run_in_executor(
            self._executor,
            validate_world_model,
            spec.graph_dot,
            spec.treatment_col,
            spec.outcome_col,
            frame,
        )

    async def run_forever(self) -> None:
        """Background loop registered with ``background_tasks``."""
        try:
            while True:
                try:
                    await self.refresh_once()
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    logger.error(
                        "WorldModelRefresher cycle error (%s) — retaining fail-closed posture.",
                        exc,
                    )
                await asyncio.sleep(self._interval_seconds)
        finally:
            self.close()

    def close(self) -> None:
        """Shut down the worker process pool if one was started."""
        if self._executor is not None:
            self._executor.shutdown(wait=False, cancel_futures=True)
            self._executor = None
