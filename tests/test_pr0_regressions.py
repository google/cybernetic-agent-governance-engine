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
PR 0 regression tests for STERA fail-open vulnerabilities (C1, C2, H2, H3).

These tests verify the fix for critical security gaps where governance gates
could be bypassed or allow execution under failure conditions.
"""

from unittest.mock import AsyncMock, patch

import pytest

from src.cage_finance.tiers.cbf_tier import CBFTierPlugin
from src.cage_finance.tiers.consensus_tier import ConsensusTierPlugin
from src.gateway.governance import GovernanceError, SymbolicGovernor

pytestmark = [pytest.mark.unit, pytest.mark.local]


def _create_safe_ftra_result():
    """Create a safe FtraBoundaryResult for testing."""
    from src.gateway.governance.ftra.models import FtraBoundaryResult

    return FtraBoundaryResult(
        requires_hitl=False,
        irreversibility_score=0.0,
        classification="READ_ONLY",
        terminal_match="test_action",
        violations=[],
        bypassed_ftra_node=False,
    )


@pytest.fixture
def mock_ftra_safe():
    """Fixture that mocks FTRA boundary check to return safe result."""
    with patch(
        "src.gateway.governance.symbolic_governor.SymbolicGovernor._ftra_boundary_check",
        new_callable=AsyncMock,
        return_value=_create_safe_ftra_result(),
    ):
        yield


@pytest.mark.asyncio
async def test_c1_cbf_reconciliation_unavailable_blocks(mock_ftra_safe, classification_engine):
    """
    C1: Verify CBF reconciliation unavailable (Redis unreachable) blocks execution.
    
    When CBF returns (False, "RECONCILIATION_UNAVAILABLE: ..."), the govern()
    method must raise GovernanceError and include the CBF refusal in the receipt.
    
    This prevents the fail-open vulnerability where network failures could bypass
    the safety constraint verification.
    """
    opa_client = AsyncMock()
    opa_client.evaluate_policy.return_value = "ALLOW"

    # Mock CBF to return reconciliation unavailable
    safety_filter = AsyncMock()
    safety_filter.atomic_verify_and_commit = AsyncMock(
        return_value=(False, "RECONCILIATION_UNAVAILABLE: Redis unreachable")
    )

    consensus_engine = AsyncMock()
    consensus_engine.check_consensus.return_value = {"status": "APPROVE"}

    governor = SymbolicGovernor(
        opa_client=opa_client,
        safety_filter=safety_filter,
        consensus_engine=consensus_engine,
        classification_engine=classification_engine,
        domain_tiers=(
            CBFTierPlugin(safety_filter),
            ConsensusTierPlugin(consensus_engine),
        ),
    )

    params = {
        "symbol": "AAPL",
        "quantity": 10,
        "price": 150.0,
        "confidence": 0.95,
    }

    # Assert govern() raises GovernanceError
    with pytest.raises(GovernanceError) as exc_info:
        await governor.govern("execute_trade", params)

    # Verify the error message contains the CBF refusal
    error_message = str(exc_info.value)
    assert "RECONCILIATION_UNAVAILABLE" in error_message or "Redis unreachable" in error_message


@pytest.mark.asyncio
async def test_c2_opa_deny_skips_cbf_commit(mock_ftra_safe, classification_engine):
    """
    C2: Verify OPA DENY verdict skips CBF commit (no budget leakage).
    
    When OPA returns "DENY", the governor must NOT call CBF's atomic_verify_and_commit,
    preventing budget leakage where CBF debits balance but OPA later denies the action.
    
    This verifies the Phase 1/Phase 2 pipeline ordering fix: all read-only checks
    (OPA) must complete before any state mutations (CBF).
    """
    opa_client = AsyncMock()
    opa_client.evaluate_policy.return_value = "DENY"

    # Mock CBF as a spy to verify it was NEVER called
    safety_filter = AsyncMock()
    safety_filter.atomic_verify_and_commit = AsyncMock(
        return_value=(True, "SAFE")
    )

    consensus_engine = AsyncMock()
    consensus_engine.check_consensus.return_value = {"status": "APPROVE"}

    governor = SymbolicGovernor(
        opa_client=opa_client,
        safety_filter=safety_filter,
        consensus_engine=consensus_engine,
        classification_engine=classification_engine,
        domain_tiers=(
            CBFTierPlugin(safety_filter),
            ConsensusTierPlugin(consensus_engine),
        ),
    )

    params = {
        "symbol": "AAPL",
        "quantity": 10,
        "price": 150.0,
        "confidence": 0.95,
    }

    # Assert govern() raises GovernanceError due to OPA denial
    with pytest.raises(GovernanceError) as exc_info:
        await governor.govern("execute_trade", params)

    # Verify OPA denial is in the error message
    error_message = str(exc_info.value)
    assert "OPA" in error_message and "Denied" in error_message

    # CRITICAL: Verify CBF commit was NEVER called (no budget leakage)
    safety_filter.atomic_verify_and_commit.assert_not_called()


@pytest.mark.asyncio
async def test_h2_opa_unknown_verdict_denies(mock_ftra_safe, classification_engine):
    """
    H2: Verify OPA unknown/typo verdicts fail-closed (deny execution).
    
    When OPA returns an unexpected verdict like "UNKNOWN_VERDICT", the governor
    must fail-closed by raising GovernanceError and NOT allow execution.
    
    This prevents the fail-open vulnerability where typos or malformed responses
    could bypass governance checks.
    """
    opa_client = AsyncMock()
    opa_client.evaluate_policy.return_value = "UNKNOWN_VERDICT"

    safety_filter = AsyncMock()
    safety_filter.atomic_verify_and_commit = AsyncMock(
        return_value=(True, "SAFE")
    )

    consensus_engine = AsyncMock()
    consensus_engine.check_consensus.return_value = {"status": "APPROVE"}

    governor = SymbolicGovernor(
        opa_client=opa_client,
        safety_filter=safety_filter,
        consensus_engine=consensus_engine,
        classification_engine=classification_engine,
        domain_tiers=(
            CBFTierPlugin(safety_filter),
            ConsensusTierPlugin(consensus_engine),
        ),
    )

    params = {
        "symbol": "AAPL",
        "quantity": 10,
        "price": 150.0,
        "confidence": 0.95,
    }

    # Assert govern() raises GovernanceError with OPA denial
    with pytest.raises(GovernanceError) as exc_info:
        await governor.govern("execute_trade", params)

    # Verify it mentions OPA and unexpected verdict
    error_message = str(exc_info.value)
    assert "OPA" in error_message
    assert "UNKNOWN_VERDICT" in error_message or "Unexpected verdict" in error_message

    # Verify it does NOT ALLOW (fail-closed behavior)
    # If govern() raises GovernanceError, it did NOT return a routing seal
    # (which would indicate ALLOW)


@pytest.mark.asyncio
async def test_h3_confidence_nan_blocks(mock_ftra_safe, classification_engine):
    """
    H3: Verify NaN confidence scores fail-closed (block execution).
    
    When params contains confidence=float('nan'), the governor must detect this
    invalid value and raise an error (GovernanceError or ValueError from JCS).
    
    This prevents the fail-open vulnerability where NaN values could bypass
    numeric threshold comparisons (NaN < threshold evaluates to False in Python).
    
    Note: The JCS canonicalizer cannot serialize NaN values, so the error may
    be raised either during validation (GovernanceError) or during receipt
    creation (ValueError). Both are acceptable fail-closed behaviors.
    """
    opa_client = AsyncMock()
    opa_client.evaluate_policy.return_value = "ALLOW"

    safety_filter = AsyncMock()
    safety_filter.atomic_verify_and_commit = AsyncMock(
        return_value=(True, "SAFE")
    )

    consensus_engine = AsyncMock()
    consensus_engine.check_consensus.return_value = {"status": "APPROVE"}

    governor = SymbolicGovernor(
        opa_client=opa_client,
        safety_filter=safety_filter,
        consensus_engine=consensus_engine,
        classification_engine=classification_engine,
        domain_tiers=(
            CBFTierPlugin(safety_filter),
            ConsensusTierPlugin(consensus_engine),
        ),
    )

    # Pass NaN confidence score
    params = {
        "symbol": "AAPL",
        "quantity": 10,
        "price": 150.0,
        "confidence": float("nan"),
    }

    # Assert govern() raises an error (GovernanceError or ValueError from JCS)
    with pytest.raises((GovernanceError, ValueError)) as exc_info:
        await governor.govern("execute_trade", params)

    # Verify error message contains "Confidence score is NaN" or "Invalid JSON number: nan"
    error_message = str(exc_info.value)
    assert (
        "Confidence score is NaN" in error_message
        or "NaN" in error_message
        or "Invalid JSON number: nan" in error_message
    ), f"Expected NaN-related error message, got: {error_message}"
