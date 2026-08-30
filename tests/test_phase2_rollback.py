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

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.gateway.governance.contracts import GovernanceTierPlugin, Violation
from src.gateway.governance.symbolic_governor import SymbolicGovernor


class MockTier:
    def __init__(self, name: str):
        self._name = name
        self.rollback = AsyncMock()

    @property
    def tier_name(self) -> str:
        return self._name

    async def run_governance(self, *args, **kwargs):
        pass


@pytest.fixture
def governor():
    return SymbolicGovernor(
        opa_client=MagicMock(),
        safety_filter=MagicMock(),
        consensus_engine=MagicMock(),
    )


@pytest.mark.asyncio
@pytest.mark.local
@pytest.mark.unit
async def test_rollback_lifo_order(governor):
    tier_a = MockTier("TierA")
    tier_b = MockTier("TierB")
    tier_c = MockTier("TierC")

    committed = [tier_a, tier_b, tier_c]

    # Configure mock responses to track execution order
    execution_order = []

    async def rollback_a(*args, **kwargs):
        execution_order.append("A")

    async def rollback_b(*args, **kwargs):
        execution_order.append("B")

    async def rollback_c(*args, **kwargs):
        execution_order.append("C")

    tier_a.rollback.side_effect = rollback_a
    tier_b.rollback.side_effect = rollback_b
    tier_c.rollback.side_effect = rollback_c

    violations = await governor._rollback_committed(committed, "test_action", {})

    assert not violations
    assert execution_order == ["C", "B", "A"]


@pytest.mark.asyncio
@pytest.mark.local
@pytest.mark.unit
async def test_rollback_exception_does_not_stop_others(governor):
    tier_a = MockTier("TierA")
    tier_b = MockTier("TierB")
    tier_c = MockTier("TierC")

    committed = [tier_a, tier_b, tier_c]

    tier_b.rollback.side_effect = RuntimeError("failed")

    violations = await governor._rollback_committed(committed, "test_action", {})

    tier_c.rollback.assert_called_once()
    tier_a.rollback.assert_called_once()

    assert len(violations) == 1
    assert violations[0].tier == "TierB"
    assert violations[0].code == "ROLLBACK_FAILED"
    assert not violations[0].recoverable
    assert violations[0].needs_human_review


@pytest.mark.asyncio
@pytest.mark.local
@pytest.mark.unit
async def test_rollback_multiple_failures(governor):
    tier_a = MockTier("TierA")
    tier_b = MockTier("TierB")
    tier_c = MockTier("TierC")

    committed = [tier_a, tier_b, tier_c]

    tier_a.rollback.side_effect = Exception("failed A")
    tier_b.rollback.side_effect = Exception("failed B")
    tier_c.rollback.side_effect = Exception("failed C")

    violations = await governor._rollback_committed(committed, "test_action", {})

    assert len(violations) == 3
    # Order will be C, B, A
    assert violations[0].tier == "TierC"
    assert violations[1].tier == "TierB"
    assert violations[2].tier == "TierA"

    for v in violations:
        assert v.code == "ROLLBACK_FAILED"
        assert not v.recoverable
        assert v.needs_human_review


@pytest.mark.asyncio
@pytest.mark.local
@pytest.mark.unit
async def test_rollback_success_returns_empty(governor):
    tier_a = MockTier("TierA")
    tier_b = MockTier("TierB")
    tier_c = MockTier("TierC")

    committed = [tier_a, tier_b, tier_c]

    violations = await governor._rollback_committed(committed, "test_action", {})

    assert not violations


@pytest.mark.asyncio
@pytest.mark.local
@pytest.mark.unit
async def test_rollback_failed_violation_structure(governor):
    tier_a = MockTier("TierA")

    committed = [tier_a]

    tier_a.rollback.side_effect = ValueError("test error")

    violations = await governor._rollback_committed(committed, "test_action", {})

    assert len(violations) == 1
    violation = violations[0]

    assert violation.tier == "TierA"
    assert violation.code == "ROLLBACK_FAILED"
    assert "TierA" in violation.message
    assert "ValueError" in violation.message
    assert not violation.recoverable
    assert violation.needs_human_review
