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

"""
test_symbolic_governor_hitl.py — Post-HITL Revalidation Security Tests

Tests for the STERA Pipeline Security Fixes, focusing on post-HITL revalidation
paths that must fail closed when CBF or OPA refuse to commit.

C1 Fix: Post-HITL revalidation must record violations for ALL CBF refusal reasons,
not just those starting with "UNSAFE".
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from src.gateway.governance.symbolic_governor import SymbolicGovernor, GovernanceError
from src.cage_finance.tiers.cbf_tier import CBFTierPlugin

# Test markers per AGENTS.md
pytestmark = [pytest.mark.unit, pytest.mark.local]


@pytest.fixture
def mock_governor(classification_engine):
    """Create a SymbolicGovernor instance with mocked dependencies."""
    with patch("src.gateway.governance.symbolic_governor.tracer"):
        # Create mocked dependencies
        mock_opa_client = MagicMock()
        mock_safety_filter = MagicMock()
        mock_consensus_engine = MagicMock()
        
        # Instantiate SymbolicGovernor with mocked dependencies
        gov = SymbolicGovernor(
            domain_tiers=[CBFTierPlugin(mock_safety_filter)],
            opa_client=mock_opa_client,
            safety_filter=mock_safety_filter,
            consensus_engine=mock_consensus_engine,
            classification_engine=classification_engine,
        )
        return gov


class TestC1PostHITLRevalidationFailClosed:
    """Test suite for C1: Post-HITL Revalidation Fail-Open Fix.
    
    Verifies that revalidate_post_hitl() records violations for ALL CBF
    refusal reasons, not just "UNSAFE" prefix matches.
    """

    @pytest.mark.asyncio
    async def test_revalidate_fails_on_reconciliation_unavailable(self, mock_governor):
        """C1: Assert DENY + violation when CBF returns (False, 'RECONCILIATION_UNAVAILABLE')."""
        # Setup: CBF refuses with RECONCILIATION_UNAVAILABLE
        mock_governor.safety_filter.atomic_verify_and_commit = AsyncMock(
            return_value=(False, "RECONCILIATION_UNAVAILABLE: Redis unavailable")
        )
        # OPA approves (to isolate CBF failure)
        mock_governor.opa_client.evaluate_policy = AsyncMock(
            return_value={"allow": "ALLOW"}
        )

        # Execute: revalidate_post_hitl should raise GovernanceError
        with pytest.raises(GovernanceError) as exc_info:
            await mock_governor.revalidate_post_hitl(
                action="execute_trade",
                params={"symbol": "AAPL", "amount": 100}
            )

        # Assert: Violation message contains the refusal reason
        assert "RECONCILIATION_UNAVAILABLE" in str(exc_info.value)
        assert exc_info.value.receipt is not None
        assert exc_info.value.receipt.violated_tier == "SYMBOLIC_GOVERNOR"

    @pytest.mark.asyncio
    async def test_revalidate_fails_on_fence_regression(self, mock_governor):
        """C1: Assert DENY + violation when CBF returns (False, 'Fence epoch regression')."""
        # Setup: CBF refuses with fence epoch regression (concurrent modification)
        mock_governor.safety_filter.atomic_verify_and_commit = AsyncMock(
            return_value=(False, "Fence epoch regression: expected 42, got 43")
        )
        # OPA approves
        mock_governor.opa_client.evaluate_policy = AsyncMock(
            return_value={"allow": "ALLOW"}
        )

        # Execute
        with pytest.raises(GovernanceError) as exc_info:
            await mock_governor.revalidate_post_hitl(
                action="execute_trade",
                params={"symbol": "AAPL", "amount": 100}
            )

        # Assert
        assert "Fence epoch regression" in str(exc_info.value)
        assert exc_info.value.receipt is not None

    @pytest.mark.asyncio
    async def test_revalidate_fails_on_balance_unavailable(self, mock_governor):
        """C1: Assert DENY + violation when CBF returns (False, 'Ground truth balance unavailable')."""
        # Setup: CBF refuses with balance fetch failure
        mock_governor.safety_filter.atomic_verify_and_commit = AsyncMock(
            return_value=(False, "Ground truth balance unavailable")
        )
        # OPA approves
        mock_governor.opa_client.evaluate_policy = AsyncMock(
            return_value={"allow": "ALLOW"}
        )

        # Execute
        with pytest.raises(GovernanceError) as exc_info:
            await mock_governor.revalidate_post_hitl(
                action="execute_trade",
                params={"symbol": "AAPL", "amount": 100}
            )

        # Assert
        assert "Ground truth balance unavailable" in str(exc_info.value)
        assert exc_info.value.receipt is not None

    @pytest.mark.asyncio
    async def test_revalidate_passes_on_cbf_commit_success(self, mock_governor):
        """C1: Assert ALLOW when CBF returns (True, 'OK') and OPA approves."""
        # Setup: CBF commits successfully
        mock_governor.safety_filter.atomic_verify_and_commit = AsyncMock(
            return_value=(True, "OK")
        )
        # OPA approves
        mock_governor.opa_client.evaluate_policy = AsyncMock(
            return_value={"allow": "ALLOW"}
        )

        # Mock generate_seal_with_evidence at the import location
        with patch("src.gateway.governance.routing_seal.generate_seal_with_evidence") as mock_seal:
            mock_seal.return_value = "mock_seal_12345"
            
            # Execute: should return a routing seal (non-empty string)
            seal = await mock_governor.revalidate_post_hitl(
                action="execute_trade",
                params={"symbol": "AAPL", "amount": 100}
            )

            # Assert: Seal issued means approval
            assert isinstance(seal, str)
            assert len(seal) > 0
            assert seal == "mock_seal_12345"

    @pytest.mark.asyncio
    async def test_revalidate_still_fails_on_unsafe_prefix(self, mock_governor):
        """C1: Assert existing UNSAFE behavior still works (regression check)."""
        # Setup: CBF refuses with UNSAFE prefix (original behavior)
        mock_governor.safety_filter.atomic_verify_and_commit = AsyncMock(
            return_value=(False, "UNSAFE: CBF barrier violated")
        )
        # OPA approves
        mock_governor.opa_client.evaluate_policy = AsyncMock(
            return_value={"allow": "ALLOW"}
        )

        # Execute
        with pytest.raises(GovernanceError) as exc_info:
            await mock_governor.revalidate_post_hitl(
                action="execute_trade",
                params={"symbol": "AAPL", "amount": 100}
            )

        # Assert
        assert "CBF_BARRIER_VIOLATED" in str(exc_info.value)
        assert exc_info.value.receipt is not None


class TestC2PostHITLSequentialOrdering:
    """Test suite for C2: Post-HITL Concurrent CBF/OPA Budget Leakage Fix.
    
    Verifies that revalidate_post_hitl() executes OPA first (read-only), then
    CBF commit only if OPA passes. This prevents budget leakage where CBF debits
    balance even when OPA subsequently denies.
    """

    @pytest.mark.asyncio
    async def test_opa_deny_prevents_cbf_commit(self, mock_governor):
        """C2: Assert CBF is never called when OPA denies (budget leakage prevented)."""
        # Setup: OPA denies
        mock_governor.opa_client.evaluate_policy = AsyncMock(
            return_value={"allow": "DENY", "reason": "Policy violation"}
        )
        # Setup: CBF mock (should never be called)
        mock_governor.safety_filter.atomic_verify_and_commit = AsyncMock(
            return_value=(True, "OK")
        )

        # Execute: revalidate_post_hitl should raise GovernanceError
        with pytest.raises(GovernanceError) as exc_info:
            await mock_governor.revalidate_post_hitl(
                action="execute_trade",
                params={"symbol": "AAPL", "amount": 100}
            )

        # Assert: OPA violation recorded
        assert "OPA Denied Action" in str(exc_info.value)
        assert exc_info.value.receipt is not None

        # C2 Critical Assertion: CBF was NEVER called (budget leak prevented)
        mock_governor.safety_filter.atomic_verify_and_commit.assert_not_called()

    @pytest.mark.asyncio
    async def test_opa_governance_violation_prevents_cbf_commit(self, mock_governor):
        """C2: Assert CBF is never called when OPA returns GOVERNANCE_VIOLATION."""
        # Setup: OPA returns GOVERNANCE_VIOLATION
        mock_governor.opa_client.evaluate_policy = AsyncMock(
            return_value={"allow": "GOVERNANCE_VIOLATION", "reason": "Regulatory breach"}
        )
        # Setup: CBF mock (should never be called)
        mock_governor.safety_filter.atomic_verify_and_commit = AsyncMock(
            return_value=(True, "OK")
        )

        # Execute
        with pytest.raises(GovernanceError) as exc_info:
            await mock_governor.revalidate_post_hitl(
                action="execute_trade",
                params={"symbol": "AAPL", "amount": 100}
            )

        # Assert: OPA violation recorded
        assert "OPA Denied Action" in str(exc_info.value)

        # C2 Critical Assertion: CBF was NEVER called
        mock_governor.safety_filter.atomic_verify_and_commit.assert_not_called()

    @pytest.mark.asyncio
    async def test_cbf_only_called_after_opa_allows(self, mock_governor):
        """C2: Assert CBF commit happens only after OPA passes."""
        # Setup: OPA allows
        mock_governor.opa_client.evaluate_policy = AsyncMock(
            return_value={"allow": "ALLOW"}
        )
        # Setup: CBF commits successfully
        mock_governor.safety_filter.atomic_verify_and_commit = AsyncMock(
            return_value=(True, "OK")
        )

        # Mock generate_seal_with_evidence
        with patch("src.gateway.governance.routing_seal.generate_seal_with_evidence") as mock_seal:
            mock_seal.return_value = "mock_seal_c2_test"
            
            # Execute
            seal = await mock_governor.revalidate_post_hitl(
                action="execute_trade",
                params={"symbol": "AAPL", "amount": 100}
            )

            # Assert: Seal issued (happy path)
            assert seal == "mock_seal_c2_test"

            # C2 Assertion: CBF was called exactly once (after OPA passed)
            mock_governor.safety_filter.atomic_verify_and_commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_opa_exception_prevents_cbf_commit(self, mock_governor):
        """C2: Assert CBF is never called when OPA raises an exception."""
        # Setup: OPA raises exception (network failure, etc.)
        mock_governor.opa_client.evaluate_policy = AsyncMock(
            side_effect=RuntimeError("OPA service unavailable")
        )
        # Setup: CBF mock (should never be called)
        mock_governor.safety_filter.atomic_verify_and_commit = AsyncMock(
            return_value=(True, "OK")
        )

        # Execute: revalidate_post_hitl should raise GovernanceError
        with pytest.raises(GovernanceError) as exc_info:
            await mock_governor.revalidate_post_hitl(
                action="execute_trade",
                params={"symbol": "AAPL", "amount": 100}
            )

        # Assert: Exception recorded as violation
        assert "OPA service unavailable" in str(exc_info.value)

        # C2 Critical Assertion: CBF was NEVER called (no budget leak on OPA failure)
        mock_governor.safety_filter.atomic_verify_and_commit.assert_not_called()

    @pytest.mark.asyncio
    async def test_sequential_ordering_observable_via_call_order(self, mock_governor):
        """C2: Assert OPA is called strictly before CBF (observable call order)."""
        call_order = []

        # Setup: OPA allows and records call
        async def opa_side_effect(*args, **kwargs):
            call_order.append("OPA")
            return {"allow": "ALLOW"}
        mock_governor.opa_client.evaluate_policy = AsyncMock(side_effect=opa_side_effect)

        # Setup: CBF commits and records call
        async def cbf_side_effect(*args, **kwargs):
            call_order.append("CBF")
            return (True, "OK")
        mock_governor.safety_filter.atomic_verify_and_commit = AsyncMock(side_effect=cbf_side_effect)

        # Mock generate_seal_with_evidence
        with patch("src.gateway.governance.routing_seal.generate_seal_with_evidence") as mock_seal:
            mock_seal.return_value = "mock_seal_order_test"
            
            # Execute
            await mock_governor.revalidate_post_hitl(
                action="execute_trade",
                params={"symbol": "AAPL", "amount": 100}
            )

            # C2 Critical Assertion: OPA called strictly before CBF
            assert call_order == ["OPA", "CBF"], (
                f"Expected OPA→CBF sequential order, got {call_order}"
            )
