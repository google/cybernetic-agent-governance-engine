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

import logging
from unittest import mock

import pytest

pytestmark = pytest.mark.unit

from src.gateway.governance.schemas.thresholds import (
    CbfThresholds,
    ConfidenceThresholds,
    ConsensusThresholds,
    DrawdownThresholds,
    GovernanceThresholds,
    StpaThresholds,
)
from src.governed_financial_advisor.governance import nemo_actions
from src.governed_financial_advisor.governance.nemo_actions import check_drawdown_limit

# Configure logging to capture output
logging.basicConfig(level=logging.INFO)


@pytest.fixture
def mock_thresholds():
    """
    Fixture to mock the threshold loading mechanism.
    """
    with mock.patch(
        "src.governed_financial_advisor.governance.nemo_actions.load_and_validate_thresholds"
    ) as mock_load:
        # Also reset cache to ensure clean state for each test
        nemo_actions._safety_params_cache = {}
        nemo_actions._last_check_time = 0.0
        yield mock_load


def _get_mock_thresholds(drawdown_limit: float) -> GovernanceThresholds:
    """Helper to create a GovernanceThresholds object with a specific drawdown limit."""
    return GovernanceThresholds(
        cbf=CbfThresholds(min_cash_balance=1000.0, gamma=0.9),
        drawdown=DrawdownThresholds(limit=drawdown_limit),
        stpa=StpaThresholds(
            uca5_drawdown_threshold_pct=4.5,
            uca6_max_order_volume_fraction=0.1,
            max_sell_portfolio_fraction=0.05,
            max_latency_ms=200.0,
        ),
        confidence=ConfidenceThresholds(min_trade_confidence=0.7),
        consensus=ConsensusThresholds(threshold_usd=10000.0),
        tier1_keywords=["AAPL", "GOOGL"],
    )


def test_standard_cbf_logic_default(mock_thresholds):
    """
    Test Case 1: Standard CBF Logic using Default Limit.
    If loader fails, it should use DEFAULT_DRAWDOWN_LIMIT (0.05).
    """
    mock_thresholds.side_effect = Exception("Load failure")

    # 4% Drawdown (0.04) < 0.05 -> Safe
    context_safe = {"drawdown_pct": 4.0}
    assert check_drawdown_limit(context_safe) is True

    # 6% Drawdown (0.06) > 0.05 -> Unsafe
    context_unsafe = {"drawdown_pct": 6.0}
    assert check_drawdown_limit(context_unsafe) is False


def test_hot_reload_dynamic_limit_with_cache(mock_thresholds):
    """
    Test Case 2: Hot-Reload with Caching.
    Update the mocked return value and verify the limit changes after TTL expiry.
    """
    # 1. Mock a strict limit (1% = 0.01)
    mock_thresholds.return_value = _get_mock_thresholds(0.01)

    # 2. Check 2% Drawdown (0.02)
    # Strict (0.01) should block it.
    context = {"drawdown_pct": 2.0}
    assert check_drawdown_limit(context) is False

    # 3. Update to loose limit (10% = 0.10)
    mock_thresholds.return_value = _get_mock_thresholds(0.10)

    # Force cache expiry by manually resetting
    nemo_actions._last_check_time = 0.0

    # 4. Check same 2% Drawdown
    # Now it should pass.
    assert check_drawdown_limit(context) is True


def test_invalid_data_sanitization(mock_thresholds):
    """
    Test Case 3: Invalid Data (Sanitization).
    Pydantic handles most validation, but if we somehow get a bad float, it should fallback.
    """
    # Case A: Loader fails -> Should fall back to 0.05
    mock_thresholds.side_effect = ValueError("Corrupt data")
    nemo_actions._last_check_time = 0.0

    # 6% Drawdown should fail (0.06 > 0.05)
    context = {"drawdown_pct": 6.0}
    assert check_drawdown_limit(context) is False

    # Case B: Mocked return value is within range
    mock_thresholds.side_effect = None
    mock_thresholds.return_value = _get_mock_thresholds(0.08)
    nemo_actions._last_check_time = 0.0

    # 4% Drawdown should pass
    context_safe = {"drawdown_pct": 4.0}
    assert check_drawdown_limit(context_safe) is True


def test_corrupt_file_resilience(mock_thresholds):
    """
    Test Case 4: Corrupt Data Resilience.
    """
    mock_thresholds.side_effect = Exception("JSON Decode Error")
    nemo_actions._last_check_time = 0.0

    # Should fall back to 0.05
    # 6% Drawdown should fail
    context = {"drawdown_pct": 6.0}
    assert check_drawdown_limit(context) is False
