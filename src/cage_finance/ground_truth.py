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

"""Finance domain simulated ground-truth cash-ledger provider (Layer 2)."""

from __future__ import annotations

import os

from src.cage_finance.invariants import CashBarrier
from src.gateway.governance.seams.ground_truth import (
    FaultMode,
    GroundTruthProvider,
    GroundTruthSnapshot,
    SimulatedSource,
)


class SimulatedCashLedgerProvider(GroundTruthProvider):
    """Deterministic simulated custody cash ledger for ``finance.cash_balance``."""

    def __init__(
        self,
        *,
        invariant_id: str = CashBarrier.invariant_id,
        state_key: str = CashBarrier.state_key,
        initial_scalar: float | None = None,
        barrier_floor: float = 10_000.0,
        account_id: str = "default",
        seed: int | None = None,
    ) -> None:
        if initial_scalar is None:
            env_val = os.environ.get("RECONCILIATION_STUB_BALANCE_USD")
            initial_scalar = float(env_val) if env_val is not None else CashBarrier.initial_state
        self.invariant_id = invariant_id
        self.state_key = state_key
        self.account_id = account_id
        self.barrier_floor = float(barrier_floor)
        self.source_id = "simulated:finance_cash_ledger"
        self._source = SimulatedSource(
            invariant_id=invariant_id,
            state_key=state_key,
            initial_scalar=float(initial_scalar),
            barrier_floor=float(barrier_floor),
            source_id=self.source_id,
            seed=seed,
        )
        self.source = self._source

    @property
    def fault_mode(self) -> FaultMode:
        """Active fault mode on the underlying simulated source."""
        return self._source.fault_mode

    def inject_fault(self, mode: FaultMode | str) -> None:
        """Configure the simulated ledger to emit ``mode`` on subsequent fetches."""
        self._source.inject_fault(mode)

    def clear_fault(self) -> None:
        """Reset fault injection to :attr:`FaultMode.NONE`."""
        self._source.clear_fault()

    def record_debit(self, amount_usd: float) -> None:
        """Record an executed trade debit against the simulated ledger."""
        self._source.record_debit(amount_usd)

    def reset(self, *, scalar: float | None = None) -> None:
        """Reset simulated ledger state and fault mode."""
        self._source.reset(scalar=scalar)

    def fetch_snapshot_sync(self) -> GroundTruthSnapshot:
        """Synchronously build the next cash-ledger snapshot."""
        return self._source.next_snapshot(
            extra_metadata={"account_id": self.account_id, "unit": "USD"}
        )

    async def fetch_snapshot(self) -> GroundTruthSnapshot:
        """Fetch the latest simulated cash-ledger snapshot."""
        return self.fetch_snapshot_sync()


__all__ = ["SimulatedCashLedgerProvider"]
