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
H3 Security Fix: NaN Confidence Fail-Closed Validation Tests.

Comprehensive test suite ensuring confidence scores are validated fail-closed
to prevent NaN/undefined/invalid values from bypassing tier validation.
"""

import math
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.gateway.governance.governor.governor import SymbolicGovernor

pytestmark = [pytest.mark.unit, pytest.mark.local]


class _ClaimAllTier:
    """No-op phase-1 tier that claims every action, so the action is governed
    and ConfidenceStage runs (confidence is only enforced on governed actions)."""

    tier_name = "claim_all"
    phase = 1
    order = 0

    def claims_action(self, action, params):
        return True

    async def evaluate(self, action, params):
        return []

    async def commit(self, action, params):
        return []

    async def rollback(self, action, params):
        return None


@pytest.fixture
def mock_governor(classification_engine):
    """Create a SymbolicGovernor instance with mocked dependencies."""
    with patch("src.gateway.governance.governor.governor.tracer"):
        # Create mocked dependencies
        mock_opa_client = MagicMock()
        mock_opa_client.evaluate_policy = AsyncMock(return_value={
            "allow": True,
            "decision": "ALLOW",
            "violations": []
        })
        
        mock_safety_filter = MagicMock()
        mock_consensus_engine = MagicMock()
        
        # Create governor with mocked dependencies
        governor = SymbolicGovernor(
            classification_engine=classification_engine,
            domain_tiers=(_ClaimAllTier(),),
            opa_client=mock_opa_client,
            safety_filter=mock_safety_filter,
            consensus_engine=mock_consensus_engine
        )
        
        yield governor


class TestConfidenceValidPassCases:
    """Test cases for valid confidence scores that should pass."""
    
    @pytest.mark.asyncio
    async def test_valid_confidence_096_passes(self, mock_governor, classification_engine):
        """Valid confidence score 0.96 should pass validation."""
        result = await mock_governor._run_checks(
            tool_name="check_balance",
            params={"confidence": 0.96}
        )
        
        violations = result.get("violations", [])
        # Should not have confidence violation
        assert not any("confidence" in str(v).lower() for v in violations), \
            f"Unexpected confidence violation for 0.96: {violations}"
    
    @pytest.mark.asyncio
    async def test_valid_confidence_098_passes(self, mock_governor, classification_engine):
        """Valid confidence score 0.98 should pass validation."""
        result = await mock_governor._run_checks(
            tool_name="check_balance",
            params={"confidence": 0.98}
        )
        
        violations = result.get("violations", [])
        # Should not have confidence violation
        assert not any("confidence" in str(v).lower() for v in violations), \
            f"Unexpected confidence violation for 0.98: {violations}"
    
    @pytest.mark.asyncio
    async def test_valid_confidence_10_passes(self, mock_governor, classification_engine):
        """Valid confidence score 1.0 (maximum) should pass validation."""
        result = await mock_governor._run_checks(
            tool_name="check_balance",
            params={"confidence": 1.0}
        )
        
        violations = result.get("violations", [])
        # Should not have confidence violation
        assert not any("confidence" in str(v).lower() for v in violations), \
            f"Unexpected confidence violation for 1.0: {violations}"


class TestConfidenceFailClosedValidation:
    """Test cases for fail-closed confidence validation."""
    
    @pytest.mark.asyncio
    async def test_none_confidence_triggers_violation(self, mock_governor, classification_engine):
        """None confidence score should trigger fail-closed violation."""
        result = await mock_governor._run_checks(
            tool_name="check_balance",
            params={"confidence": None}
        )
        
        violations = result.get("violations", [])
        # Should have violation for missing confidence
        assert any("missing" in str(v).lower() for v in violations), \
            f"Expected missing confidence violation, got: {violations}"
    
    @pytest.mark.asyncio
    async def test_nan_confidence_triggers_violation(self, mock_governor, classification_engine):
        """NaN confidence score should trigger fail-closed violation."""
        result = await mock_governor._run_checks(
            tool_name="check_balance",
            params={"confidence": math.nan}
        )
        
        violations = result.get("violations", [])
        # Should have violation for NaN
        assert any("nan" in str(v).lower() for v in violations), \
            f"Expected NaN violation, got: {violations}"
    
    @pytest.mark.asyncio
    async def test_positive_inf_triggers_violation(self, mock_governor, classification_engine):
        """Positive infinity confidence should trigger fail-closed violation."""
        result = await mock_governor._run_checks(
            tool_name="check_balance",
            params={"confidence": math.inf}
        )
        
        violations = result.get("violations", [])
        # Should have violation for infinite
        assert any("infinite" in str(v).lower() for v in violations), \
            f"Expected infinite violation, got: {violations}"
    
    @pytest.mark.asyncio
    async def test_negative_inf_triggers_violation(self, mock_governor, classification_engine):
        """Negative infinity confidence should trigger fail-closed violation."""
        result = await mock_governor._run_checks(
            tool_name="check_balance",
            params={"confidence": -math.inf}
        )
        
        violations = result.get("violations", [])
        # Should have violation for either infinite or negative
        assert any(
            "infinite" in str(v).lower() or "negative" in str(v).lower() 
            for v in violations
        ), f"Expected infinite/negative violation, got: {violations}"
    
    @pytest.mark.asyncio
    async def test_negative_confidence_triggers_violation(self, mock_governor, classification_engine):
        """Negative confidence score should trigger fail-closed violation."""
        result = await mock_governor._run_checks(
            tool_name="check_balance",
            params={"confidence": -0.5}
        )
        
        violations = result.get("violations", [])
        # Should have violation for negative value
        assert any("negative" in str(v).lower() for v in violations), \
            f"Expected negative violation, got: {violations}"
    
    @pytest.mark.asyncio
    async def test_confidence_exceeds_max_triggers_violation(self, mock_governor, classification_engine):
        """Confidence score > 1.0 should trigger fail-closed violation."""
        result = await mock_governor._run_checks(
            tool_name="check_balance",
            params={"confidence": 1.5}
        )
        
        violations = result.get("violations", [])
        # Should have violation for exceeding maximum
        assert any("exceed" in str(v).lower() or "maximum" in str(v).lower() for v in violations), \
            f"Expected maximum exceeded violation, got: {violations}"
    
    @pytest.mark.asyncio
    async def test_string_confidence_triggers_violation(self, mock_governor, classification_engine):
        """String confidence score should trigger fail-closed violation."""
        result = await mock_governor._run_checks(
            tool_name="check_balance",
            params={"confidence": "0.8"}
        )
        
        violations = result.get("violations", [])
        # Should have violation for invalid type
        assert any("type" in str(v).lower() or "invalid" in str(v).lower() for v in violations), \
            f"Expected type violation, got: {violations}"
    
    @pytest.mark.asyncio
    async def test_list_confidence_triggers_violation(self, mock_governor, classification_engine):
        """List confidence score should trigger fail-closed violation."""
        result = await mock_governor._run_checks(
            tool_name="check_balance",
            params={"confidence": [0.8]}
        )
        
        violations = result.get("violations", [])
        # Should have violation for invalid type
        assert any("type" in str(v).lower() or "invalid" in str(v).lower() for v in violations), \
            f"Expected type violation, got: {violations}"
    
    @pytest.mark.asyncio
    async def test_dict_confidence_triggers_violation(self, mock_governor, classification_engine):
        """Dict confidence score should trigger fail-closed violation."""
        result = await mock_governor._run_checks(
            tool_name="check_balance",
            params={"confidence": {"score": 0.8}}
        )
        
        violations = result.get("violations", [])
        # Should have violation for invalid type
        assert any("type" in str(v).lower() or "invalid" in str(v).lower() for v in violations), \
            f"Expected type violation, got: {violations}"
    
    @pytest.mark.asyncio
    async def test_below_threshold_triggers_violation(self, mock_governor, classification_engine):
        """Confidence below threshold should trigger violation."""
        # Threshold is 0.95, so 0.5 should fail
        result = await mock_governor._run_checks(
            tool_name="check_balance",
            params={"confidence": 0.5}
        )
        
        violations = result.get("violations", [])
        # Should have violation for below threshold
        assert any("threshold" in str(v).lower() or "below" in str(v).lower() for v in violations), \
            f"Expected threshold violation, got: {violations}"


class TestConfidenceEdgeCases:
    """Test edge cases for confidence validation."""
    
    @pytest.mark.asyncio
    async def test_zero_confidence_valid_but_below_threshold(self, mock_governor, classification_engine):
        """Zero confidence is valid numeric value but should fail threshold check."""
        result = await mock_governor._run_checks(
            tool_name="check_balance",
            params={"confidence": 0.0}
        )
        
        violations = result.get("violations", [])
        # Should have violation for below threshold (not for invalid type)
        assert any(v.code == "CONFIDENCE_BELOW_THRESHOLD" for v in violations), f"Expected threshold violation for 0.0, got: {violations}"
        assert not any(v.code == "CONFIDENCE_INVALID" for v in violations)
    
    @pytest.mark.asyncio
    async def test_exactly_at_threshold_passes(self, mock_governor, classification_engine):
        """Confidence exactly at threshold (0.95) should pass."""
        result = await mock_governor._run_checks(
            tool_name="check_balance",
            params={"confidence": 0.95}
        )
        
        violations = result.get("violations", [])
        # Should not have confidence violation
        assert not any("confidence" in str(v).lower() for v in violations), \
            f"Unexpected confidence violation for 0.95 (threshold): {violations}"
    
    @pytest.mark.asyncio
    async def test_integer_confidence_valid(self, mock_governor, classification_engine):
        """Integer confidence score (1) should be valid."""
        result = await mock_governor._run_checks(
            tool_name="check_balance",
            params={"confidence": 1}  # Integer, not float
        )
        
        violations = result.get("violations", [])
        # Should not have confidence violation
        assert not any("confidence" in str(v).lower() for v in violations), \
            f"Unexpected confidence violation for integer 1: {violations}"
    
    @pytest.mark.asyncio
    async def test_missing_key_entirely_triggers_violation(self, mock_governor, classification_engine):
        """Missing confidence_score key entirely should trigger violation."""
        result = await mock_governor._run_checks(
            tool_name="check_balance",
            params={}  # No confidence_score key at all
        )
        
        violations = result.get("violations", [])
        # Should have violation for missing confidence
        assert any("missing" in str(v).lower() for v in violations), \
            f"Expected missing confidence violation, got: {violations}"
