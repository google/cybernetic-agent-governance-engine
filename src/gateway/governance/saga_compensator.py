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

"""Domain-agnostic Saga compensator helpers and wrapper for STPA-compiled sagas."""

from __future__ import annotations

import hashlib
import inspect
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from src.gateway.governance.contracts import SagaCompensator


def derive_idempotency_key(transaction_id: str, compensating_action: str) -> str:
    """Derive a deterministic 32-character hex idempotency key for a rollback call."""
    raw = f"{transaction_id}:{compensating_action}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def next_sequence_id(state: dict[str, Any]) -> int:
    """Return the next monotonically increasing sequence_id for the WAL ledger."""
    existing = state.get("completed_transactions") or []
    if not existing:
        return 0
    return max(int(e.get("sequence_id", 0)) for e in existing) + 1


@dataclass(frozen=True)
class FunctionSagaCompensator:
    """Adapter wrapping a generated compensating node into :class:`SagaCompensator`."""

    action_name: str
    uca_id: str
    compensating_action: str
    compensate_fn: Callable[[dict[str, Any]], dict[str, Any]]

    async def compensate(self, params: dict[str, Any]) -> dict[str, Any]:
        """Execute the compensating action asynchronously or synchronously."""
        res = self.compensate_fn(params)
        if inspect.isawaitable(res):
            return await res
        return res

    def __call__(self, state: dict[str, Any]) -> dict[str, Any]:
        """Allow direct invocation as a synchronous LangGraph node."""
        return self.compensate_fn(state)


__all__ = [
    "FunctionSagaCompensator",
    "SagaCompensator",
    "derive_idempotency_key",
    "next_sequence_id",
]
