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

"""Invariant-parametric ground-truth seam and deterministic simulation primitives.

This module defines the Layer 1 seam between the kernel's reconciliation
machinery (`GroundTruthReconciler`) and domain-contributed state sensors
(`GroundTruthProvider`). It has zero kernel imports so both Layer 1 and
Layer 2 plugins can depend on it without import cycles.
"""

from __future__ import annotations

import math
import os
import random
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Protocol, runtime_checkable


class FaultMode(StrEnum):
    """Deterministic fault injection modes for posture-completing ground-truth sources."""

    NONE = "none"
    TIMEOUT = "timeout"
    CONNECTION_ERROR = "connection_error"
    MALFORMED_PAYLOAD = "malformed_payload"
    NEGATIVE_VALUE = "negative_value"
    NAN_VALUE = "nan_value"
    STALE_TIMESTAMP = "stale_timestamp"
    FUTURE_TIMESTAMP = "future_timestamp"
    UNVERIFIED_SOURCE = "unverified_source"
    SCALAR_BELOW_BARRIER = "scalar_below_barrier"
    DISCREPANCY_SPIKE = "discrepancy_spike"


@dataclass(frozen=True)
class GroundTruthSnapshot:
    """Immutable point-in-time ground-truth reading for a single safety invariant."""

    invariant_id: str
    state_key: str
    scalar: float
    observed_at: float = field(default_factory=time.time)
    sequence: int = 1
    source_id: str = "simulated"
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @property
    def value(self) -> float:
        """Alias for ``scalar``."""
        return self.scalar

    @property
    def state_scalar(self) -> float:
        """Alias for ``scalar``."""
        return self.scalar

    @property
    def verified_at(self) -> float:
        """Alias for ``observed_at``."""
        return self.observed_at

    @property
    def source(self) -> str:
        """Alias for ``source_id``."""
        return self.source_id


@runtime_checkable
class GroundTruthProvider(Protocol):
    """Protocol implemented by domain ground-truth state providers."""

    invariant_id: str
    state_key: str

    async def fetch_snapshot(self) -> GroundTruthSnapshot:
        """Fetch the latest ground-truth snapshot for ``invariant_id``."""
        ...


class SimulatedSource:
    """Deterministic simulated ground-truth source with fault injection.

    Provides reproducible state evolution seeded by ``seed`` (or the
    ``CAGE_SIM_SEED`` environment variable) and supports all 10 :class:`FaultMode`
    failure modes so every fail-closed path in :class:`GroundTruthReconciler`
    and :class:`ControlBarrierFunction` can be verified hermetically.
    """

    def __init__(
        self,
        *,
        invariant_id: str,
        state_key: str = "",
        initial_scalar: float,
        barrier_floor: float = 0.0,
        source_id: str = "simulated",
        seed: int | None = None,
        jitter_amplitude: float = 0.0,
        drift_sigma: float = 0.0,
    ) -> None:
        if not math.isfinite(initial_scalar):
            raise ValueError("initial_scalar must be finite")
        self.invariant_id = invariant_id
        self.state_key = state_key or f"safety:{invariant_id}"
        self.initial_scalar = float(initial_scalar)
        self.barrier_floor = float(barrier_floor)
        self.source_id = source_id
        resolved_seed = (
            seed
            if seed is not None
            else int(os.environ.get("CAGE_SIM_SEED", "42"))
        )
        self.seed = resolved_seed
        self._rng = random.Random(resolved_seed)  # noqa: S311 - deterministic simulation RNG
        self._jitter_amplitude = float(jitter_amplitude or drift_sigma)
        self._sequence: int = 0
        self._journal_debits: list[float] = []
        self._fault_mode: FaultMode = FaultMode.NONE

    @property
    def fault_mode(self) -> FaultMode:
        """Currently active fault mode."""
        return self._fault_mode

    @property
    def current_scalar(self) -> float:
        """Current ground-truth scalar after applying recorded debits."""
        return self.initial_scalar - sum(self._journal_debits)

    def inject_fault(self, mode: FaultMode | str) -> None:
        """Configure the source to emit ``mode`` on subsequent fetches."""
        self._fault_mode = FaultMode(mode)

    def clear_fault(self) -> None:
        """Reset fault injection to :attr:`FaultMode.NONE`."""
        self._fault_mode = FaultMode.NONE

    def record_debit(self, magnitude: float) -> None:
        """Record an executed debit against the simulated ground-truth state."""
        if not math.isfinite(magnitude) or magnitude < 0.0:
            raise ValueError(f"Debit magnitude must be finite and non-negative, got {magnitude!r}")
        self._journal_debits.append(float(magnitude))

    def reset(self, *, scalar: float | None = None) -> None:
        """Reset journal debits, sequence counter, RNG, and fault mode."""
        if scalar is not None:
            if not math.isfinite(scalar):
                raise ValueError("scalar must be finite")
            self.initial_scalar = float(scalar)
        self._journal_debits.clear()
        self._sequence = 0
        self._rng = random.Random(self.seed)  # noqa: S311
        self._fault_mode = FaultMode.NONE

    def next_snapshot(
        self,
        *,
        now: float | None = None,
        extra_metadata: Mapping[str, Any] | None = None,
    ) -> GroundTruthSnapshot:
        """Produce the next :class:`GroundTruthSnapshot` or raise/corrupt per ``fault_mode``."""
        mode = self._fault_mode
        if mode == FaultMode.TIMEOUT:
            raise TimeoutError(
                f"Simulated ground-truth timeout for invariant {self.invariant_id!r}"
            )
        if mode == FaultMode.CONNECTION_ERROR:
            raise ConnectionError(
                f"Simulated ground-truth connection error for invariant {self.invariant_id!r}"
            )

        self._sequence += 1
        ts = time.time() if now is None else float(now)
        jitter = (
            self._rng.uniform(-self._jitter_amplitude, self._jitter_amplitude)
            if self._jitter_amplitude > 0.0
            else 0.0
        )
        base_scalar = self.current_scalar + jitter
        meta: dict[str, Any] = {
            "seed": self.seed,
            "barrier_floor": self.barrier_floor,
            "expected_scalar": self.current_scalar,
            "fault_mode": mode.value,
        }
        if extra_metadata:
            meta.update(extra_metadata)

        if mode == FaultMode.MALFORMED_PAYLOAD:
            meta["malformed"] = True
            return GroundTruthSnapshot(
                invariant_id="",
                state_key="malformed_unnamespaced_key",
                scalar=base_scalar,
                observed_at=ts,
                sequence=self._sequence,
                source_id=self.source_id,
                metadata=meta,
            )

        if mode == FaultMode.NEGATIVE_VALUE:
            return GroundTruthSnapshot(
                invariant_id=self.invariant_id,
                state_key=self.state_key,
                scalar=-abs(base_scalar) - 100.0,
                observed_at=ts,
                sequence=self._sequence,
                source_id=self.source_id,
                metadata=meta,
            )

        if mode == FaultMode.NAN_VALUE:
            return GroundTruthSnapshot(
                invariant_id=self.invariant_id,
                state_key=self.state_key,
                scalar=float("nan"),
                observed_at=ts,
                sequence=self._sequence,
                source_id=self.source_id,
                metadata=meta,
            )

        if mode == FaultMode.STALE_TIMESTAMP:
            return GroundTruthSnapshot(
                invariant_id=self.invariant_id,
                state_key=self.state_key,
                scalar=base_scalar,
                observed_at=ts - 3600.0,
                sequence=self._sequence,
                source_id=self.source_id,
                metadata=meta,
            )

        if mode == FaultMode.FUTURE_TIMESTAMP:
            return GroundTruthSnapshot(
                invariant_id=self.invariant_id,
                state_key=self.state_key,
                scalar=base_scalar,
                observed_at=ts + 3600.0,
                sequence=self._sequence,
                source_id=self.source_id,
                metadata=meta,
            )

        if mode == FaultMode.UNVERIFIED_SOURCE:
            meta["verified_source"] = False
            return GroundTruthSnapshot(
                invariant_id=self.invariant_id,
                state_key=self.state_key,
                scalar=base_scalar,
                observed_at=ts,
                sequence=self._sequence,
                source_id="unverified:rogue_feed",
                metadata=meta,
            )

        if mode == FaultMode.SCALAR_BELOW_BARRIER:
            below = (
                self.barrier_floor * 0.25
                if self.barrier_floor > 0.0
                else -1.0
            )
            meta["below_barrier"] = True
            return GroundTruthSnapshot(
                invariant_id=self.invariant_id,
                state_key=self.state_key,
                scalar=below,
                observed_at=ts,
                sequence=self._sequence,
                source_id=self.source_id,
                metadata=meta,
            )

        if mode == FaultMode.DISCREPANCY_SPIKE:
            meta["discrepancy_spike"] = True
            spiked = max(self.barrier_floor + 1.0, base_scalar * 0.05)
            return GroundTruthSnapshot(
                invariant_id=self.invariant_id,
                state_key=self.state_key,
                scalar=spiked,
                observed_at=ts,
                sequence=self._sequence,
                source_id=self.source_id,
                metadata=meta,
            )

        return GroundTruthSnapshot(
            invariant_id=self.invariant_id,
            state_key=self.state_key,
            scalar=base_scalar,
            observed_at=ts,
            sequence=self._sequence,
            source_id=self.source_id,
            metadata=meta,
        )


__all__ = [
    "FaultMode",
    "GroundTruthProvider",
    "GroundTruthSnapshot",
    "SimulatedSource",
]
