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

"""``govern()`` seals the params its stages evaluated, never the live dict.

Issue #379: ``govern()`` used to hand the caller's dict to the stages and to
seal generation. A concurrent holder of that dict could change a value while
the evidence commit was awaited, so the seal named params no stage had seen.
These tests simulate that holder and a misbehaving stage, and require the seal
to name the params as they were when ``govern()`` was called.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock

import pytest

from src.gateway.governance.contracts import ReadOnlyTier, Violation
from src.gateway.governance.governor import sealing as sealing_module
from src.gateway.governance.governor.stages.domain_tiers import order_stages
from tests.fixtures.governor import make_governor

pytestmark = [pytest.mark.unit, pytest.mark.local]

ACTION = "execute_trade"


class _Tier(ReadOnlyTier):
    """Read-only domain tier that claims every action and records what it saw."""

    def __init__(self, name: str) -> None:
        self._name = name
        self.seen: list[float] = []

    tier_name = property(lambda self: self._name)
    order = property(lambda self: 0)

    def claims_action(self, action: str, params: dict[str, Any]) -> bool:
        return True


class _ConcurrentMutator(_Tier):
    """Yields, then a 'concurrent holder' of the caller's dict edits it."""

    def __init__(self, caller_params: dict[str, Any]) -> None:
        super().__init__("concurrent_holder")
        self.caller_params = caller_params

    async def evaluate(self, action: str, params: dict[str, Any]) -> list[Violation]:
        self.seen.append(float(params["amount"]))
        await asyncio.sleep(0)
        self.caller_params["amount"] = 1_000_000.0  # the concurrent write
        return []


class _SelfMutator(_Tier):
    """Mutates its own input; that must not reach the seal."""

    def __init__(self) -> None:
        super().__init__("self_mutator")

    async def evaluate(self, action: str, params: dict[str, Any]) -> list[Violation]:
        self.seen.append(float(params["amount"]))
        params["amount"] = 1_000_000.0
        return []


@pytest.fixture
def seal(monkeypatch: pytest.MonkeyPatch) -> AsyncMock:
    mock = AsyncMock(return_value="sealed")
    monkeypatch.setattr(sealing_module, "issue_seal", mock)
    return mock


@pytest.mark.asyncio
async def test_concurrent_mutation_of_caller_dict_does_not_reach_seal(seal: AsyncMock) -> None:
    params = {"amount": 10.0, "agent_id": "agent-1"}
    holder = _ConcurrentMutator(params)
    gov = make_governor(core_stages=order_stages([holder]))

    assert await gov.govern(ACTION, params) == "sealed"

    assert holder.seen == [10.0]
    assert params["amount"] == 1_000_000.0  # the concurrent write did happen
    seal.assert_awaited_once_with(
        ACTION, {"amount": 10.0, "agent_id": "agent-1"}, path="govern"
    )


@pytest.mark.asyncio
async def test_stage_mutating_its_input_does_not_reach_seal(seal: AsyncMock) -> None:
    params = {"amount": 10.0, "agent_id": "agent-1"}
    tier = _SelfMutator()
    gov = make_governor(core_stages=order_stages([tier]))

    await gov.govern(ACTION, params)

    assert tier.seen == [10.0]
    assert params == {"amount": 10.0, "agent_id": "agent-1"}  # caller's dict untouched
    seal.assert_awaited_once_with(
        ACTION, {"amount": 10.0, "agent_id": "agent-1"}, path="govern"
    )
