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

Validates that SymbolicGovernor._run_domain_tiers() correctly orders tiers by
priority, filters by phase, executes only tiers that claim the action, and
aggregates violations.

Part of: PR A - Capability-Driven Tier Dispatch (Stage 8)
Gate: G1 (tier dispatch loop execution and ordering)
"""

import pytest
from typing import Any
from unittest.mock import AsyncMock, MagicMock

from src.gateway.governance.symbolic_governor import SymbolicGovernor
from src.gateway.governance.contracts import GovernanceTierPlugin, Violation


@pytest.fixture
def mock_governor() -> SymbolicGovernor:
    """Create a SymbolicGovernor with mock dependencies."""
    opa_client = MagicMock()
    safety_filter = MagicMock()
    consensus_engine = MagicMock()
    return SymbolicGovernor(opa_client, safety_filter, consensus_engine)


class OrderTrackingTier:
    """Tier that records when it was invoked for ordering verification."""

    execution_log: list[tuple[str, str]] = []

    def __init__(
        self,
        tier_name: str,
        phase: int,
        order: int,
        claims_all: bool = True,
        violation_rule: str | None = None,
    ) -> None:
        self._tier_name = tier_name
        self._phase = phase
        self._order = order
        self._claims_all = claims_all
        self._violation_rule = violation_rule

    @property
    def tier_name(self) -> str:
        return self._tier_name

    @property
    def phase(self) -> int:
        return self._phase

    @property
    def order(self) -> int:
        return self._order

    def claims_action(self, action: str, params: dict[str, Any]) -> bool:
        return self._claims_all

    async def evaluate(
        self, action: str, params: dict[str, Any]
    ) -> list[Violation]:
        return []

    async def commit(
        self, action: str, params: dict[str, Any]
    ) -> list[Violation]:
        OrderTrackingTier.execution_log.append((self._tier_name, action))
        if self._violation_rule:
            return [
                Violation(
                    tier=self._tier_name,
                    code=self._violation_rule,
                    message=f"Violation from {self._tier_name}",
                )
            ]
        return []

    async def rollback(self, action: str, params: dict[str, Any]) -> None:
        pass


@pytest.mark.local
class TestTierDispatchOrdering:
    """Tier dispatch loop ordering tests."""

    @pytest.fixture(autouse=True)
    def clear_execution_log(self) -> None:
        """Clear execution log before each test."""
        OrderTrackingTier.execution_log.clear()

    @pytest.mark.asyncio
    async def test_tiers_execute_in_ascending_order_priority(self, mock_governor: SymbolicGovernor) -> None:
        """Tiers with lower order values execute first."""
        gov = mock_governor
        
        # Register tiers in arbitrary order
        gov.register_domain_tier(OrderTrackingTier("tier_c", phase=1, order=300))
        gov.register_domain_tier(OrderTrackingTier("tier_a", phase=1, order=100))
        gov.register_domain_tier(OrderTrackingTier("tier_b", phase=1, order=200))

        await gov._run_domain_tiers("test_action", {}, phase=1)

        # Should execute in order: tier_a (100), tier_b (200), tier_c (300)
        assert OrderTrackingTier.execution_log == [
            ("tier_a", "test_action"),
            ("tier_b", "test_action"),
            ("tier_c", "test_action"),
        ]

    @pytest.mark.asyncio
    async def test_phase_filter_only_executes_matching_phase(self, mock_governor: SymbolicGovernor) -> None:
        """Only tiers matching the requested phase execute."""
        gov = mock_governor
        
        gov.register_domain_tier(OrderTrackingTier("phase1_tier", phase=1, order=100))
        gov.register_domain_tier(OrderTrackingTier("phase2_tier", phase=2, order=100))

        await gov._run_domain_tiers("test_action", {}, phase=1)

        # Only phase 1 tier should execute
        executed_tiers = [name for name, _ in OrderTrackingTier.execution_log]
        assert executed_tiers == ["phase1_tier"]

    @pytest.mark.asyncio
    async def test_unclaimed_tiers_do_not_execute(self, mock_governor: SymbolicGovernor) -> None:
        """Tiers that do not claim the action are skipped."""
        gov = mock_governor
        
        gov.register_domain_tier(
            OrderTrackingTier("claiming_tier", phase=1, order=100, claims_all=True)
        )
        gov.register_domain_tier(
            OrderTrackingTier("unclaimed_tier", phase=1, order=200, claims_all=False)
        )

        await gov._run_domain_tiers("test_action", {}, phase=1)

        # Only the claiming tier should execute
        executed_tiers = [name for name, _ in OrderTrackingTier.execution_log]
        assert executed_tiers == ["claiming_tier"]

    @pytest.mark.asyncio
    async def test_violations_aggregated_across_tiers(self, mock_governor: SymbolicGovernor) -> None:
        """Violations from multiple tiers are aggregated."""
        gov = mock_governor
        
        gov.register_domain_tier(
            OrderTrackingTier("tier1", phase=1, order=100, violation_rule="RULE_A")
        )
        gov.register_domain_tier(
            OrderTrackingTier("tier2", phase=1, order=200, violation_rule="RULE_B")
        )

        violations = await gov._run_domain_tiers("test_action", {}, phase=1)

        assert len(violations) == 2
        assert violations[0].tier == "tier1"
        assert violations[0].rule == "RULE_A"
        assert violations[1].tier == "tier2"
        assert violations[1].rule == "RULE_B"

    @pytest.mark.asyncio
    async def test_empty_tier_registry_returns_no_violations(self, mock_governor: SymbolicGovernor) -> None:
        """Dispatch with no registered tiers returns empty list."""
        gov = mock_governor
        violations = await gov._run_domain_tiers("test_action", {}, phase=1)
        assert violations == []


@pytest.mark.local
class TestTierDispatchPhaseIsolation:
    """Phase isolation tests."""

    @pytest.fixture(autouse=True)
    def clear_execution_log(self) -> None:
        OrderTrackingTier.execution_log.clear()

    @pytest.mark.asyncio
    async def test_phase1_and_phase2_execute_independently(self, mock_governor: SymbolicGovernor) -> None:
        """Phase 1 and phase 2 tiers execute in separate calls."""
        gov = mock_governor
        
        gov.register_domain_tier(OrderTrackingTier("p1_tier", phase=1, order=100))
        gov.register_domain_tier(OrderTrackingTier("p2_tier", phase=2, order=100))

        # Execute phase 1
        OrderTrackingTier.execution_log.clear()
        await gov._run_domain_tiers("test_action", {}, phase=1)
        assert OrderTrackingTier.execution_log == [("p1_tier", "test_action")]

        # Execute phase 2
        OrderTrackingTier.execution_log.clear()
        await gov._run_domain_tiers("test_action", {}, phase=2)
        assert OrderTrackingTier.execution_log == [("p2_tier", "test_action")]

    @pytest.mark.asyncio
    async def test_multiple_phase1_tiers_sorted_by_order(self, mock_governor: SymbolicGovernor) -> None:
        """Multiple phase 1 tiers execute in ascending order priority."""
        gov = mock_governor
        
        gov.register_domain_tier(OrderTrackingTier("p1_c", phase=1, order=300))
        gov.register_domain_tier(OrderTrackingTier("p1_a", phase=1, order=100))
        gov.register_domain_tier(OrderTrackingTier("p1_b", phase=1, order=200))

        await gov._run_domain_tiers("test_action", {}, phase=1)

        executed_tiers = [name for name, _ in OrderTrackingTier.execution_log]
        assert executed_tiers == ["p1_a", "p1_b", "p1_c"]
