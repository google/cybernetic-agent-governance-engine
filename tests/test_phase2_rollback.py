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

from src.gateway.governance.contracts import CommitReceipt, MutatingTier, Violation
from tests.fixtures.governor import make_governor


class MockTier(MutatingTier):
    """Mutating tier whose ``rollback`` is an AsyncMock the tests script."""

    order = 0

    def __init__(self, name: str):
        self._name = name
        self.rollback = AsyncMock()

    @property
    def tier_name(self) -> str:
        return self._name

    def claims_action(self, action: str, params: dict[str, Any]) -> bool:
        return True

    async def evaluate(self, action: str, params: dict[str, Any]) -> list[Violation]:
        return []

    async def commit(self, action: str, params: dict[str, Any]) -> tuple[list[Violation], CommitReceipt | None]:
        return [], None

    async def rollback(self, action: str, params: dict[str, Any], receipt: CommitReceipt) -> None:
        """Replaced per instance by an AsyncMock in ``__init__``."""

    async def confirm(self, action: str, params: dict[str, Any], receipt: CommitReceipt) -> None:
        pass


@pytest.fixture
def governor(classification_engine):
    return make_governor(
        classifier=classification_engine,
        opa=MagicMock(),
        safety_filter=MagicMock(),
        consensus=MagicMock(),
    )


@pytest.mark.asyncio
@pytest.mark.local
@pytest.mark.unit
async def test_rollback_lifo_order(governor, classification_engine):
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

    violations = await _rollback(committed)

    assert not violations
    assert execution_order == ["C", "B", "A"]


@pytest.mark.asyncio
@pytest.mark.local
@pytest.mark.unit
async def test_rollback_exception_does_not_stop_others(governor, classification_engine):
    tier_a = MockTier("TierA")
    tier_b = MockTier("TierB")
    tier_c = MockTier("TierC")

    committed = [tier_a, tier_b, tier_c]

    tier_b.rollback.side_effect = RuntimeError("failed")

    violations = await _rollback(committed)

    tier_c.rollback.assert_called_once()
    tier_a.rollback.assert_called_once()

    assert len(violations) == 1
    assert violations[0].tier == "TierB"
    assert violations[0].code == "ROLLBACK_FAILED"
    from src.gateway.governance.contracts import ViolationKind
    assert violations[0].kind == ViolationKind.HARD


@pytest.mark.asyncio
@pytest.mark.local
@pytest.mark.unit
async def test_rollback_multiple_failures(governor, classification_engine):
    tier_a = MockTier("TierA")
    tier_b = MockTier("TierB")
    tier_c = MockTier("TierC")

    committed = [tier_a, tier_b, tier_c]

    tier_a.rollback.side_effect = Exception("failed A")
    tier_b.rollback.side_effect = Exception("failed B")
    tier_c.rollback.side_effect = Exception("failed C")

    violations = await _rollback(committed)

    assert len(violations) == 3
    # Order will be C, B, A
    assert violations[0].tier == "TierC"
    assert violations[1].tier == "TierB"
    assert violations[2].tier == "TierA"

    from src.gateway.governance.contracts import ViolationKind
    for v in violations:
        assert v.code == "ROLLBACK_FAILED"
        assert v.kind == ViolationKind.HARD


@pytest.mark.asyncio
@pytest.mark.local
@pytest.mark.unit
async def test_rollback_success_returns_empty(governor, classification_engine):
    tier_a = MockTier("TierA")
    tier_b = MockTier("TierB")
    tier_c = MockTier("TierC")

    committed = [tier_a, tier_b, tier_c]

    violations = await _rollback(committed)

    assert not violations


@pytest.mark.asyncio
@pytest.mark.local
@pytest.mark.unit
async def test_rollback_failed_violation_structure(governor, classification_engine):
    tier_a = MockTier("TierA")

    committed = [tier_a]

    tier_a.rollback.side_effect = ValueError("test error")

    violations = await _rollback(committed)

    assert len(violations) == 1
    violation = violations[0]

    assert violation.tier == "TierA"
    assert violation.code == "ROLLBACK_FAILED"
    assert "TierA" in violation.message
    assert "ValueError" in violation.message
    from src.gateway.governance.contracts import ViolationKind
    assert violation.kind == ViolationKind.HARD


async def _rollback(committed):
    from src.gateway.governance.governor.pipeline import Profile, StageContext
    from src.gateway.governance.governor.stages.domain_tiers import DomainTierStage
    from tests.governor.scope_helpers import rollback_pairs
    ctx = StageContext(action="test_action", params={}, profile=Profile.FULL)
    return await rollback_pairs(
        [(DomainTierStage(t), _receipt(t)) for t in committed], ctx
    )


def _receipt(tier):
    """Deterministic per-tier receipt so assertions can name exactly what was undone."""
    from src.gateway.governance.contracts import CommitReceipt
    return CommitReceipt(tier=tier.tier_name, magnitude=1.0)
