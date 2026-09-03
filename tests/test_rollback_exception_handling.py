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

"""D6 Regression Test: Phase 2 Rollback Exception Handling

Verifies the fix described in implementation_plan.md § 1.2.3:
- Rollback happens in LIFO order (reverse of commit order)
- Exceptions during rollback are isolated (one tier failure doesn't stop others)
- Failed rollback generates a ROLLBACK_FAILED violation with tier name
- Fail-closed semantics: action is blocked even if rollback partially fails

Coverage: src/gateway/governance/symbolic_governor.py:833-866
"""

from unittest.mock import AsyncMock, Mock

import pytest

from src.gateway.governance.contracts import Violation
from src.gateway.governance.symbolic_governor import SymbolicGovernor


@pytest.fixture
def mock_governor_with_tiers():
    """Create a governor with mock domain tiers for rollback testing."""
    mock_opa = Mock()
    mock_opa.evaluate_policy = AsyncMock(return_value={"allow": True})

    gov = SymbolicGovernor(opa_client=mock_opa)

    tier_a = Mock()
    tier_a.tier_name = "tier_a"
    tier_a.phase = 2
    tier_a.order = 1
    tier_a.commit = AsyncMock()
    tier_a.rollback = AsyncMock()

    tier_b = Mock()
    tier_b.tier_name = "tier_b"
    tier_b.phase = 2
    tier_b.order = 2
    tier_b.commit = AsyncMock()
    tier_b.rollback = AsyncMock()

    tier_c = Mock()
    tier_c.tier_name = "tier_c"
    tier_c.phase = 2
    tier_c.order = 3
    tier_c.commit = AsyncMock()
    tier_c.rollback = AsyncMock()

    gov._domain_tiers = [tier_a, tier_b, tier_c]
    gov._committed_tiers = []

    return gov, tier_a, tier_b, tier_c


class TestRollbackLifoOrder:
    """Verify rollback happens in LIFO order (reverse of commit)."""

    @pytest.mark.asyncio
    async def test_rollback_reverses_commit_order(self, mock_governor_with_tiers):
        """D6 FIX VERIFICATION: rollback must happen in LIFO order."""
        gov, tier_a, tier_b, tier_c = mock_governor_with_tiers

        committed = [tier_a, tier_b, tier_c]
        execution_order = []

        async def rollback_a(action, params):
            execution_order.append("tier_a")
            return []

        async def rollback_b(action, params):
            execution_order.append("tier_b")
            return []

        async def rollback_c(action, params):
            execution_order.append("tier_c")
            return []

        tier_a.rollback.side_effect = rollback_a
        tier_b.rollback.side_effect = rollback_b
        tier_c.rollback.side_effect = rollback_c

        # Trigger rollback
        violations = await gov._rollback_committed(committed, "test_action", {})

        # All three tiers should have been called
        tier_a.rollback.assert_awaited_once_with("test_action", {})
        tier_b.rollback.assert_awaited_once_with("test_action", {})
        tier_c.rollback.assert_awaited_once_with("test_action", {})

        # Verify LIFO order: C -> B -> A
        assert execution_order == ["tier_c", "tier_b", "tier_a"]
        assert len(violations) == 0


class TestRollbackExceptionIsolation:
    """Verify exceptions during rollback are isolated."""

    @pytest.mark.asyncio
    async def test_one_tier_failure_does_not_stop_others(
        self, mock_governor_with_tiers
    ):
        """D6 FIX VERIFICATION: exception in one tier's rollback must not stop others."""
        gov, tier_a, tier_b, tier_c = mock_governor_with_tiers

        committed = [tier_a, tier_b, tier_c]

        # Make tier_b's rollback fail
        tier_b.rollback.side_effect = RuntimeError("Redis connection lost")

        violations = await gov._rollback_committed(committed, "test_action", {})

        # All three tiers should have been ATTEMPTED
        tier_c.rollback.assert_awaited_once_with("test_action", {})
        tier_b.rollback.assert_awaited_once_with("test_action", {})
        tier_a.rollback.assert_awaited_once_with("test_action", {})

        # Violations list should contain a ROLLBACK_FAILED entry for tier_b
        assert len(violations) == 1
        assert violations[0].code == "ROLLBACK_FAILED"
        assert violations[0].tier == "tier_b"
        assert "RuntimeError" in violations[0].message

    @pytest.mark.asyncio
    async def test_multiple_tier_failures_all_recorded(self, mock_governor_with_tiers):
        """D6 FIX VERIFICATION: multiple rollback failures are all recorded."""
        gov, tier_a, tier_b, tier_c = mock_governor_with_tiers

        committed = [tier_a, tier_b, tier_c]

        # Make tier_b and tier_a fail
        tier_b.rollback.side_effect = RuntimeError("B failed")
        tier_a.rollback.side_effect = ValueError("A failed")

        violations = await gov._rollback_committed(committed, "test_action", {})

        # All tiers attempted
        tier_c.rollback.assert_awaited_once_with("test_action", {})
        tier_b.rollback.assert_awaited_once_with("test_action", {})
        tier_a.rollback.assert_awaited_once_with("test_action", {})

        # Both failures recorded (in LIFO order: tier_b first, tier_a second)
        assert len(violations) == 2
        assert violations[0].code == "ROLLBACK_FAILED"
        assert violations[0].tier == "tier_b"
        assert "RuntimeError" in violations[0].message
        assert violations[1].code == "ROLLBACK_FAILED"
        assert violations[1].tier == "tier_a"
        assert "ValueError" in violations[1].message


class TestRollbackFailClosedSemantics:
    """Verify fail-closed semantics when rollback partially fails."""

    @pytest.mark.asyncio
    async def test_partial_rollback_failure_still_blocks_action(
        self, mock_governor_with_tiers
    ):
        """D6 FIX VERIFICATION: action must be blocked even if rollback fails."""
        gov, tier_a, tier_b, tier_c = mock_governor_with_tiers

        committed = [tier_a, tier_b, tier_c]

        # Tier C rollback fails
        tier_c.rollback.side_effect = Exception("State corruption")

        violations = await gov._rollback_committed(committed, "test_action", {})

        # Action is blocked (violations list is populated)
        assert len(violations) == 1
        assert violations[0].code == "ROLLBACK_FAILED"
        assert violations[0].needs_human_review is True
        assert violations[0].recoverable is False


class TestRollbackViolationStructure:
    """Verify ROLLBACK_FAILED violations contain required fields."""

    @pytest.mark.asyncio
    async def test_rollback_violation_contains_tier_name(
        self, mock_governor_with_tiers
    ):
        """D6 FIX VERIFICATION: ROLLBACK_FAILED violation must include tier name."""
        gov, _tier_a, tier_b, _tier_c = mock_governor_with_tiers

        committed = [tier_b]
        tier_b.rollback.side_effect = RuntimeError("Rollback error")

        violations = await gov._rollback_committed(committed, "test_action", {})

        assert len(violations) == 1
        v = violations[0]
        assert isinstance(v, Violation)
        assert v.code == "ROLLBACK_FAILED"
        assert v.tier == "tier_b"
        assert v.message is not None
        assert "RuntimeError" in v.message

    @pytest.mark.asyncio
    async def test_successful_rollback_produces_no_violations(
        self, mock_governor_with_tiers
    ):
        """D6 FIX VERIFICATION: successful rollback must not produce violations."""
        gov, tier_a, tier_b, tier_c = mock_governor_with_tiers

        committed = [tier_a, tier_b, tier_c]

        # All rollbacks succeed (no exceptions)
        violations = await gov._rollback_committed(committed, "test_action", {})

        # No violations should be added
        assert len(violations) == 0

        # All tiers rolled back cleanly
        tier_c.rollback.assert_awaited_once_with("test_action", {})
        tier_b.rollback.assert_awaited_once_with("test_action", {})
        tier_a.rollback.assert_awaited_once_with("test_action", {})
