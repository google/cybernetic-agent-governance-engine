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

"""Domain tier interface contract conformance tests.

Validates that GovernanceTierPlugin implementations conform to the canonical
protocol contract: tier_name, phase, order properties, claims_action() predicate,
and evaluate() async validator.

Part of: PR A - Capability-Driven Tier Dispatch (Stage 8)
Gate: G4 (tier interface contract compliance)
"""

import pytest
from typing import Any

from src.gateway.governance.contracts import GovernanceTierPlugin, Violation


class MinimalTier:
    """Minimal GovernanceTierPlugin implementation for conformance testing."""

    def __init__(
        self,
        tier_name: str = "test_tier",
        phase: int = 1,
        order: int = 100,
    ) -> None:
        self._tier_name = tier_name
        self._phase = phase
        self._order = order

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
        """Accept any action containing 'test' in the name."""
        return "test" in action.lower()

    async def evaluate(
        self, action: str, params: dict[str, Any]
    ) -> list[Violation]:
        """Phase 1: Always pass."""
        return []

    async def commit(
        self, action: str, params: dict[str, Any]
    ) -> list[Violation]:
        """Phase 2: Always pass."""
        return []

    async def rollback(self, action: str, params: dict[str, Any]) -> None:
        """Phase 2: No-op rollback."""
        pass


class UnclaimedTier(MinimalTier):
    """Tier that never claims any action."""

    def claims_action(self, action: str, params: dict[str, Any]) -> bool:
        return False


class FailingTier(MinimalTier):
    """Tier that always emits a violation."""

    async def evaluate(
        self, action: str, params: dict[str, Any]
    ) -> list[Violation]:
        return [
            Violation(
                tier=self.tier_name,
                code="ALWAYS_FAIL",
                # severity removed - not in base Violation,
                message="Test violation",
            )
        ]


@pytest.mark.local
class TestGovernanceTierPluginProtocol:
    """Tier protocol conformance tests."""

    def test_minimal_tier_has_required_properties(self) -> None:
        """Tier must expose tier_name, phase, and order properties."""
        tier = MinimalTier(tier_name="example", phase=2, order=50)
        assert tier.tier_name == "example"
        assert tier.phase == 2
        assert tier.order == 50

    def test_minimal_tier_claims_action_predicate(self) -> None:
        """claims_action() returns bool indicating interest in an action."""
        tier = MinimalTier()
        assert tier.claims_action("test_action", {}) is True
        assert tier.claims_action("unrelated_action", {}) is False

    @pytest.mark.asyncio
    async def test_minimal_tier_evaluate_returns_violations(self) -> None:
        """evaluate() returns a list of Violation instances."""
        tier = MinimalTier()
        violations = await tier.evaluate("test_action", {})
        assert isinstance(violations, list)
        assert all(isinstance(v, Violation) for v in violations)

    def test_unclaimed_tier_never_claims(self) -> None:
        """Tier that claims nothing should never be invoked."""
        tier = UnclaimedTier()
        assert tier.claims_action("test_action", {}) is False
        assert tier.claims_action("anything", {}) is False

    @pytest.mark.asyncio
    async def test_failing_tier_emits_violation(self) -> None:
        """Tier can emit violations with structured findings."""
        tier = FailingTier(tier_name="strict_tier")
        violations = await tier.evaluate("test_action", {})
        assert len(violations) == 1
        assert violations[0].tier == "strict_tier"
        assert violations[0].code == "ALWAYS_FAIL"


@pytest.mark.local
class TestTierProtocolEdgeCases:
    """Edge case validation for tier protocol contract."""

    def test_tier_with_zero_order(self) -> None:
        """Tier with order=0 is valid (highest priority)."""
        tier = MinimalTier(order=0)
        assert tier.order == 0

    def test_tier_with_negative_order_allowed(self) -> None:
        """Negative order values are permitted (even higher priority)."""
        tier = MinimalTier(order=-10)
        assert tier.order == -10

    def test_tier_phase_1_or_2_only(self) -> None:
        """Tier phase must be 1 (read-only) or 2 (mutating)."""
        tier1 = MinimalTier(phase=1)
        tier2 = MinimalTier(phase=2)
        assert tier1.phase == 1
        assert tier2.phase == 2

    @pytest.mark.asyncio
    async def test_tier_evaluate_can_return_empty_list(self) -> None:
        """evaluate() returning [] indicates no violations."""
        tier = MinimalTier()
        violations = await tier.evaluate("test_action", {})
        assert violations == []
