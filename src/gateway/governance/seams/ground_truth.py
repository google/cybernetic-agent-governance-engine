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

import json
import math
import os
import random
import time
import uuid
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
    SETTLEMENT_STALL = "settlement_stall"


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
    #: Attestation that every debit submitted at or before this instant is
    #: already reflected in ``scalar``. ``None`` means the source does not
    #: attest settlement and the reconciler falls back to a configured lag.
    settled_through: float | None = None

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


@runtime_checkable
class LedgerJournal(Protocol):
    """Where a simulated source keeps the debits it has been told about.

    The actuator (gateway process) records; the reconciler (worker process)
    reads. An in-memory journal serves hermetic tests; the Redis journal is
    the cross-process reference backend.
    """

    def record(self, *, debit_id: str, amount: float, submitted_at: float) -> None: ...

    def settled_total(self, through: float) -> float:
        """Sum of amounts with ``submitted_at <= through``."""
        ...

    def total(self) -> float: ...

    def clear(self) -> None: ...


class InMemoryLedgerJournal:
    """Process-local :class:`LedgerJournal`."""

    def __init__(self) -> None:
        self._entries: list[tuple[float, float, str]] = []

    def record(self, *, debit_id: str, amount: float, submitted_at: float) -> None:
        self._entries.append((float(submitted_at), float(amount), debit_id))

    def settled_total(self, through: float) -> float:
        return sum(amount for ts, amount, _ in self._entries if ts <= through)

    def total(self) -> float:
        return sum(amount for _, amount, _ in self._entries)

    def clear(self) -> None:
        self._entries.clear()

    def __len__(self) -> int:
        return len(self._entries)


class RedisLedgerJournal:
    """Cross-process :class:`LedgerJournal` on a Redis ZSET.

    Key ``sim:ledger:{invariant_id}``; score ``submitted_at``; member
    ``JSON{debit_id, amount}``. The client may be a raw ``redis.Redis`` or a
    wrapper exposing ``_get()``; it is unwrapped on every call so a lazily
    connecting wrapper never connects at construction time.
    """

    KEY_PREFIX = "sim:ledger:"

    def __init__(self, client: Any, invariant_id: str) -> None:
        self._client = client
        self.key = f"{self.KEY_PREFIX}{invariant_id}"

    def _raw(self) -> Any:
        getter = getattr(self._client, "_get", None)
        return getter() if callable(getter) else self._client

    @staticmethod
    def _amount(member: Any) -> float:
        if isinstance(member, (bytes, bytearray)):
            member = member.decode("utf-8")
        try:
            value = float(json.loads(member).get("amount", 0.0))
        except (TypeError, ValueError, AttributeError):
            return 0.0
        return value if math.isfinite(value) else 0.0

    def record(self, *, debit_id: str, amount: float, submitted_at: float) -> None:
        member = json.dumps({"debit_id": debit_id, "amount": float(amount)}, sort_keys=True)
        self._raw().zadd(self.key, {member: float(submitted_at)})

    def settled_total(self, through: float) -> float:
        members = self._raw().zrangebyscore(self.key, "-inf", float(through))
        return sum(self._amount(m) for m in members)

    def total(self) -> float:
        members = self._raw().zrange(self.key, 0, -1)
        return sum(self._amount(m) for m in members)

    def clear(self) -> None:
        self._raw().delete(self.key)


class SimulatedSource:
    """Deterministic simulated ground-truth source with fault injection.

    Provides reproducible state evolution seeded by ``seed`` (or the
    ``CAGE_SIM_SEED`` environment variable) and supports every non-``NONE``
    :class:`FaultMode` so each fail-closed path in :class:`GroundTruthReconciler`
    and :class:`ControlBarrierFunction` can be verified hermetically.

    Like a real custodian it *settles*: a debit recorded at ``submitted_at``
    is reflected in the reported scalar only once ``now - settlement_lag_s``
    has passed it, and every snapshot attests ``settled_through`` so the
    reconciler can prune the CBF's local-debit ledger exactly that far
    (ADR-010). With the default lag of ``0.0`` settlement is immediate.
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
        journal: LedgerJournal | None = None,
        settlement_lag_s: float = 0.0,
    ) -> None:
        if not math.isfinite(initial_scalar):
            raise ValueError("initial_scalar must be finite")
        if not math.isfinite(settlement_lag_s) or settlement_lag_s < 0.0:
            raise ValueError("settlement_lag_s must be finite and non-negative")
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
        self.journal: LedgerJournal = journal if journal is not None else InMemoryLedgerJournal()
        self.settlement_lag_s = float(settlement_lag_s)
        self._fault_mode: FaultMode = FaultMode.NONE
        self._stalled_settled_through: float | None = None

    @property
    def fault_mode(self) -> FaultMode:
        """Currently active fault mode."""
        return self._fault_mode

    @property
    def current_scalar(self) -> float:
        """Ground-truth scalar once every recorded debit has settled."""
        return self.initial_scalar - self.journal.total()

    def settled_through_at(self, now: float) -> float:
        """Settlement horizon the source attests for a snapshot taken at ``now``."""
        if self._fault_mode == FaultMode.SETTLEMENT_STALL:
            if self._stalled_settled_through is None:
                self._stalled_settled_through = now - self.settlement_lag_s
            return self._stalled_settled_through
        return now - self.settlement_lag_s

    def settled_scalar(self, now: float) -> float:
        """Scalar a custodian would report at ``now``: only settled debits applied."""
        return self.initial_scalar - self.journal.settled_total(self.settled_through_at(now))

    def inject_fault(self, mode: FaultMode | str) -> None:
        """Configure the source to emit ``mode`` on subsequent fetches."""
        self._fault_mode = FaultMode(mode)
        if self._fault_mode != FaultMode.SETTLEMENT_STALL:
            self._stalled_settled_through = None

    def clear_fault(self) -> None:
        """Reset fault injection to :attr:`FaultMode.NONE`."""
        self._fault_mode = FaultMode.NONE
        self._stalled_settled_through = None

    def record_debit(
        self,
        magnitude: float,
        *,
        submitted_at: float | None = None,
        debit_id: str | None = None,
    ) -> str:
        """Journal an executed debit; it settles ``settlement_lag_s`` after ``submitted_at``.

        Returns the ``debit_id`` the entry was journaled under.
        """
        if not math.isfinite(magnitude) or magnitude < 0.0:
            raise ValueError(f"Debit magnitude must be finite and non-negative, got {magnitude!r}")
        ts = time.time() if submitted_at is None else float(submitted_at)
        if not math.isfinite(ts):
            raise ValueError("submitted_at must be finite")
        entry_id = debit_id or uuid.uuid4().hex
        self.journal.record(debit_id=entry_id, amount=float(magnitude), submitted_at=ts)
        return entry_id

    def reset(self, *, scalar: float | None = None) -> None:
        """Reset journal debits, sequence counter, RNG, and fault mode."""
        if scalar is not None:
            if not math.isfinite(scalar):
                raise ValueError("scalar must be finite")
            self.initial_scalar = float(scalar)
        self.journal.clear()
        self._sequence = 0
        self._rng = random.Random(self.seed)  # noqa: S311
        self._fault_mode = FaultMode.NONE
        self._stalled_settled_through = None

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
        settled_through = self.settled_through_at(ts)
        settled_scalar = self.settled_scalar(ts)
        base_scalar = settled_scalar + jitter
        meta: dict[str, Any] = {
            "seed": self.seed,
            "barrier_floor": self.barrier_floor,
            "expected_scalar": settled_scalar,
            "fault_mode": mode.value,
            "settlement_lag_s": self.settlement_lag_s,
        }
        if mode == FaultMode.SETTLEMENT_STALL:
            meta["settlement_stalled"] = True
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
                settled_through=settled_through,
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
                settled_through=settled_through,
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
                settled_through=settled_through,
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
                settled_through=settled_through,
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
                settled_through=settled_through,
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
                settled_through=settled_through,
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
                settled_through=settled_through,
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
                settled_through=settled_through,
            )

        return GroundTruthSnapshot(
            invariant_id=self.invariant_id,
            state_key=self.state_key,
            scalar=base_scalar,
            observed_at=ts,
            sequence=self._sequence,
            source_id=self.source_id,
            metadata=meta,
            settled_through=settled_through,
        )


__all__ = [
    "FaultMode",
    "GroundTruthProvider",
    "GroundTruthSnapshot",
    "InMemoryLedgerJournal",
    "LedgerJournal",
    "RedisLedgerJournal",
    "SimulatedSource",
]
