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

"""Tier dispatch loop execution tests.

Validates that run_pipeline() domain-tier dispatch correctly orders tiers by
priority, filters by phase, executes only tiers that claim the action, and
aggregates violations.

Part of: PR A - Capability-Driven Tier Dispatch (Stage 8)
Gate: G1 (tier dispatch loop execution and ordering)
"""

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.gateway.governance.contracts import (
    CommitReceipt,
    MutatingTier,
    ReadOnlyTier,
    Violation,
    ViolationKind,
)
from src.gateway.governance.governor.governor import SymbolicGovernor
from tests.fixtures.governor import make_governor as build_governor


@pytest.fixture
def mock_governor(classification_engine) -> SymbolicGovernor:
    """Create a SymbolicGovernor with mock dependencies."""
    return make_governor(classification_engine=classification_engine)


def make_governor(*tiers: Any, classification_engine) -> SymbolicGovernor:
    """Create a SymbolicGovernor with mock dependencies and specified tiers."""
    return build_governor(
        opa=MagicMock(),
        safety_filter=MagicMock(),
        consensus=MagicMock(),
        classifier=classification_engine,
        domain_tiers=tiers,
    )


class OrderTrackingTier:
    """Tier behaviour that records when it was invoked, for ordering verification.

    Mixed into one of the two tier kinds below; build one with
    :func:`tracking_tier`.
    """

    execution_log: list[tuple[str, str]] = []

    def __init__(
        self,
        tier_name: str,
        order: int,
        claims_all: bool = True,
        violation_rule: str | None = None,
    ) -> None:
        self._tier_name = tier_name
        self._order = order
        self._claims_all = claims_all
        self._violation_rule = violation_rule

    @property
    def tier_name(self) -> str:
        return self._tier_name

    @property
    def order(self) -> int:
        return self._order

    def claims_action(self, action: str, params: dict[str, Any]) -> bool:
        return self._claims_all

    def _record(self, action: str) -> list[Violation]:
        OrderTrackingTier.execution_log.append((self._tier_name, action))
        if self._violation_rule:
            return [
                Violation(
                    tier=self._tier_name,
                    code=self._violation_rule,
                    message=f"Violation from {self._tier_name}",
                    kind=ViolationKind.HARD,
                )
            ]
        return []

    async def evaluate(self, action: str, params: dict[str, Any]) -> list[Violation]:
        # Phase 1 evaluation - log execution and check for violations
        return self._record(action)


class _ReadOnlyTracking(OrderTrackingTier, ReadOnlyTier):
    pass


class _MutatingTracking(OrderTrackingTier, MutatingTier):
    async def commit(
        self, action: str, params: dict[str, Any]
    ) -> tuple[list[Violation], CommitReceipt | None]:
        # Phase 2 commit - log execution and check for violations
        return self._record(action), None

    async def rollback(
        self, action: str, params: dict[str, Any], receipt: CommitReceipt
    ) -> None:
        pass

    async def confirm(
        self, action: str, params: dict[str, Any], receipt: CommitReceipt
    ) -> None:
        pass


def tracking_tier(
    tier_name: str, phase: int, order: int, **kwargs: Any
) -> OrderTrackingTier:
    """Build a read-only (phase 1) or mutating (phase 2) order-tracking tier."""
    kind = _ReadOnlyTracking if phase == 1 else _MutatingTracking
    return kind(tier_name, order, **kwargs)


@pytest.mark.local
class TestTierDispatchOrdering:
    """Tier dispatch loop ordering tests."""

    @pytest.fixture(autouse=True)
    def clear_execution_log(self) -> None:
        """Clear execution log before each test."""
        OrderTrackingTier.execution_log.clear()

    @pytest.mark.asyncio
    async def test_tiers_execute_in_ascending_order_priority(
        self, classification_engine
    ) -> None:
        """Tiers with lower order values execute first."""
        # Create governor with tiers in arbitrary order
        gov = make_governor(
            tracking_tier("tier_c", phase=1, order=300),
            tracking_tier("tier_a", phase=1, order=100),
            tracking_tier("tier_b", phase=1, order=200),
            classification_engine=classification_engine,
        )

        await _run_tiers(gov, "test_action", {}, phase=1)

        # Should execute in order: tier_a (100), tier_b (200), tier_c (300)
        assert OrderTrackingTier.execution_log == [
            ("tier_a", "test_action"),
            ("tier_b", "test_action"),
            ("tier_c", "test_action"),
        ]

    @pytest.mark.asyncio
    async def test_phase_filter_only_executes_matching_phase(
        self, classification_engine
    ) -> None:
        """Only tiers matching the requested phase execute."""
        gov = make_governor(
            tracking_tier("phase1_tier", phase=1, order=100),
            tracking_tier("phase2_tier", phase=2, order=100),
            classification_engine=classification_engine,
        )

        await _run_tiers(gov, "test_action", {}, phase=1)

        # Only phase 1 tier should execute
        executed_tiers = [name for name, _ in OrderTrackingTier.execution_log]
        assert executed_tiers == ["phase1_tier"]

    @pytest.mark.asyncio
    async def test_unclaimed_tiers_do_not_execute(self, classification_engine) -> None:
        """Tiers that do not claim the action are skipped."""
        gov = make_governor(
            tracking_tier("claiming_tier", phase=1, order=100, claims_all=True),
            tracking_tier("unclaimed_tier", phase=1, order=200, claims_all=False),
            classification_engine=classification_engine,
        )

        await _run_tiers(gov, "test_action", {}, phase=1)

        # Only the claiming tier should execute
        executed_tiers = [name for name, _ in OrderTrackingTier.execution_log]
        assert executed_tiers == ["claiming_tier"]

    @pytest.mark.asyncio
    async def test_violations_aggregated_across_tiers(
        self, classification_engine
    ) -> None:
        """When a tier returns violations, execution stops and violations are returned.

        With the v3.0 architecture, run_pipeline() returns early on first violation
        to enforce fail-fast semantics. This test verifies that behavior.
        """
        gov = make_governor(
            tracking_tier("tier1", phase=1, order=100, violation_rule="RULE_A"),
            tracking_tier("tier2", phase=1, order=200, violation_rule="RULE_B"),
            classification_engine=classification_engine,
        )

        violations = await _run_tiers(gov, "test_action", {}, phase=1)

        # Only tier1 violation is returned - tier2 never executes due to early return
        assert len(violations) == 1
        assert violations[0].tier == "tier1"
        assert violations[0].code == "RULE_A"

    @pytest.mark.asyncio
    async def test_empty_tier_registry_returns_no_violations(
        self, mock_governor: SymbolicGovernor
    ) -> None:
        """Dispatch with no registered tiers returns empty list."""
        gov = mock_governor
        violations = await _run_tiers(gov, "test_action", {}, phase=1)
        assert violations == []


@pytest.mark.local
class TestTierDispatchPhaseIsolation:
    """Phase isolation tests."""

    @pytest.fixture(autouse=True)
    def clear_execution_log(self) -> None:
        OrderTrackingTier.execution_log.clear()

    @pytest.mark.asyncio
    async def test_phase1_and_phase2_execute_independently(
        self, classification_engine
    ) -> None:
        """Phase 1 and phase 2 tiers execute in separate calls."""
        gov = make_governor(
            tracking_tier("p1_tier", phase=1, order=100),
            tracking_tier("p2_tier", phase=2, order=100),
            classification_engine=classification_engine,
        )

        # Execute phase 1
        OrderTrackingTier.execution_log.clear()
        await _run_tiers(gov, "test_action", {}, phase=1)
        assert OrderTrackingTier.execution_log == [("p1_tier", "test_action")]

        # Execute phase 2
        OrderTrackingTier.execution_log.clear()
        await _run_tiers(gov, "test_action", {}, phase=2)
        assert OrderTrackingTier.execution_log == [("p2_tier", "test_action")]

    @pytest.mark.asyncio
    async def test_multiple_phase1_tiers_sorted_by_order(
        self, classification_engine
    ) -> None:
        """Multiple phase 1 tiers execute in ascending order priority."""
        gov = make_governor(
            tracking_tier("p1_c", phase=1, order=300),
            tracking_tier("p1_a", phase=1, order=100),
            tracking_tier("p1_b", phase=1, order=200),
            classification_engine=classification_engine,
        )

        await _run_tiers(gov, "test_action", {}, phase=1)

        executed_tiers = [name for name, _ in OrderTrackingTier.execution_log]
        assert executed_tiers == ["p1_a", "p1_b", "p1_c"]


async def _run_tiers(gov, action, params, *, phase):
    """Run one phase of gov's domain tiers through the real pipeline."""
    from src.gateway.governance.governor.pipeline import Profile, StageContext
    from tests.governor.scope_helpers import run_scoped

    stages = [s for s in gov.stages if hasattr(s, "claims") and s.tier.phase == phase]
    ctx = StageContext(action=action, params=params, profile=Profile.FULL)
    result = await run_scoped(stages, ctx)
    return list(result.violations)
