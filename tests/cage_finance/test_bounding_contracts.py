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
Comprehensive test suite for Bounding Contracts B1-B10 and bounded execution.

Test Coverage:
- Unit tests for each contract (B1-B10)
- Edge cases: volatility spikes, drawdown limits, liquidity depth
- Integration tests: multi-contract validation
- Evidence Stream integration: verify seal generation
- Replay defense: duplicate trade detection
- Regional posture: jurisdiction filter tests (US_FED, EU_ECB, APAC_MAS)
"""

import os
from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.cage_finance.models.trade_order import TradeOrder
from src.cage_finance.safety.bounding import BoundingContractResult
from src.cage_finance.safety.bounding.b1_notional_cap import B1NotionalCap
from src.cage_finance.safety.bounding.b2_drawdown_limit import B2DrawdownLimit
from src.cage_finance.safety.bounding.b3_liquidity_depth import B3LiquidityDepth
from src.cage_finance.safety.bounding.b4_counterparty_concentration import (
    B4CounterpartyConcentration,
)
from src.cage_finance.safety.bounding.b5_volatility_sizing import B5VolatilitySizing
from src.cage_finance.safety.bounding.b6_delta_escalation import B6DeltaEscalation
from src.cage_finance.safety.bounding.b7_audit_sealing import B7AuditSealing
from src.cage_finance.safety.bounding.b8_slippage_bound import B8SlippageBound
from src.cage_finance.safety.bounding.b9_jurisdiction_filter import B9JurisdictionFilter
from src.cage_finance.safety.bounding.b10_rollback_window import B10RollbackWindow
from src.cage_finance.tools.bounded_execution import (
    clear_replay_cache,
    execute_trade_bounded,
)

# ---------------------------------------------------------
# Test Fixtures
# ---------------------------------------------------------


@pytest.fixture
def sample_order():
    """Sample trade order for testing."""
    return TradeOrder(
        symbol="AAPL",
        amount=100.0,
        currency="USD",
        confidence=0.97,
        side="buy",
    )


@pytest.fixture
def sample_limits():
    """Sample bounding contract limits."""
    return {
        "max_single_order_notional": 100000.0,
        "max_daily_drawdown": 0.10,  # 10%
        "max_depth_ratio": 0.20,  # 20%
        "max_concentration": 0.25,  # 25%
        "base_order_size": 100.0,
        "atr_multiplier": 2.0,
        "high_impact_threshold": 1000.0,
        "max_slippage": 0.05,  # 5%
    }


@pytest.fixture
def sample_market_data():
    """Sample market data for testing."""
    return {
        "current_price": 150.0,
        "order_notional": 15000.0,  # 100 shares * $150
        "execution_price": 150.0,
        "benchmark_price": 150.0,
        "order_book_depth": 1000.0,
        "current_volatility": 0.0,  # 0% volatility - avoid unintended B5 scaling
        "current_drawdown": 0.05,  # 5% drawdown
        "position_delta": 100.0,
        "counterparty_exposure": 50000.0,
        "total_exposure": 500000.0,
        "settlement_window_seconds": 300,
        "rollback_supported": True,
        "asset_category": "",
    }


@pytest.fixture(autouse=True)
def cleanup_replay_cache():
    """Clear replay cache before each test."""
    clear_replay_cache()
    yield
    clear_replay_cache()


# ---------------------------------------------------------
# B1 - Single-Order Notional Cap Tests
# ---------------------------------------------------------


def test_b1_notional_cap_pass():
    """B1 should pass when order notional is below cap."""
    contract = B1NotionalCap()
    trade_params = {
        "order_notional": 50000.0,
        "limits": {"max_single_order_notional": 100000.0},
    }

    result, violation = contract.validate(trade_params)

    assert result == BoundingContractResult.PASSED
    assert violation is None


def test_b1_notional_cap_fail():
    """B1 should fail when order notional exceeds cap."""
    contract = B1NotionalCap()
    trade_params = {
        "order_notional": 150000.0,
        "limits": {"max_single_order_notional": 100000.0},
    }

    result, violation = contract.validate(trade_params)

    assert result == BoundingContractResult.FAILED
    assert violation is not None
    assert violation.contract_id == "B1"
    assert violation.severity == "HARD_BLOCK"
    assert violation.actual == 150000.0
    assert violation.limit == 100000.0


def test_b1_notional_cap_boundary():
    """B1 should pass at exact limit (inclusive boundary)."""
    contract = B1NotionalCap()
    trade_params = {
        "order_notional": 100000.0,
        "limits": {"max_single_order_notional": 100000.0},
    }

    result, violation = contract.validate(trade_params)

    assert result == BoundingContractResult.PASSED
    assert violation is None


# ---------------------------------------------------------
# B2 - Daily Drawdown Limit Tests
# ---------------------------------------------------------


def test_b2_drawdown_limit_pass():
    """B2 should pass when drawdown is below limit."""
    contract = B2DrawdownLimit()
    trade_params = {
        "current_drawdown": 0.05,
        "limits": {"max_daily_drawdown": 0.10},
    }

    result, violation = contract.validate(trade_params)

    assert result == BoundingContractResult.PASSED
    assert violation is None


def test_b2_drawdown_limit_fail():
    """B2 should fail when drawdown exceeds limit (circuit breaker)."""
    contract = B2DrawdownLimit()
    trade_params = {
        "current_drawdown": 0.15,
        "limits": {"max_daily_drawdown": 0.10},
    }

    result, violation = contract.validate(trade_params)

    assert result == BoundingContractResult.FAILED
    assert violation is not None
    assert violation.contract_id == "B2"
    assert violation.severity == "CIRCUIT_BREAKER"


def test_b2_drawdown_limit_boundary():
    """B2 should pass at exact limit (inclusive boundary)."""
    contract = B2DrawdownLimit()
    trade_params = {
        "current_drawdown": 0.10,
        "limits": {"max_daily_drawdown": 0.10},
    }

    result, _violation = contract.validate(trade_params)

    assert result == BoundingContractResult.PASSED


# ---------------------------------------------------------
# B3 - Liquidity Depth Ratio Tests
# ---------------------------------------------------------


def test_b3_liquidity_depth_pass():
    """B3 should pass when depth ratio is acceptable."""
    contract = B3LiquidityDepth()
    trade_params = {
        "order_size": 100.0,
        "order_book_depth": 1000.0,  # 10% depth ratio
        "limits": {"max_depth_ratio": 0.20},
    }

    result, violation = contract.validate(trade_params)

    assert result == BoundingContractResult.PASSED
    assert violation is None


def test_b3_liquidity_depth_fail():
    """B3 should fail when depth ratio exceeds limit."""
    contract = B3LiquidityDepth()
    trade_params = {
        "order_size": 300.0,
        "order_book_depth": 1000.0,  # 30% depth ratio
        "limits": {"max_depth_ratio": 0.20},
    }

    result, violation = contract.validate(trade_params)

    assert result == BoundingContractResult.FAILED
    assert violation is not None
    assert violation.contract_id == "B3"
    assert violation.severity == "HARD_BLOCK"


def test_b3_liquidity_depth_zero_depth():
    """B3 should fail when order book depth is zero."""
    contract = B3LiquidityDepth()
    trade_params = {
        "order_size": 100.0,
        "order_book_depth": 0.0,
        "limits": {"max_depth_ratio": 0.20},
    }

    result, violation = contract.validate(trade_params)

    assert result == BoundingContractResult.FAILED
    assert violation is not None
    assert "zero or negative" in violation.message.lower()


# ---------------------------------------------------------
# B4 - Counterparty Concentration Tests
# ---------------------------------------------------------


def test_b4_counterparty_concentration_pass():
    """B4 should pass when concentration is below limit."""
    contract = B4CounterpartyConcentration()
    trade_params = {
        "counterparty_exposure": 50000.0,
        "total_exposure": 500000.0,  # 10% concentration
        "limits": {"max_concentration": 0.25},
    }

    result, violation = contract.validate(trade_params)

    assert result == BoundingContractResult.PASSED
    assert violation is None


def test_b4_counterparty_concentration_fail():
    """B4 should fail when concentration exceeds limit."""
    contract = B4CounterpartyConcentration()
    trade_params = {
        "counterparty_exposure": 150000.0,
        "total_exposure": 500000.0,  # 30% concentration
        "limits": {"max_concentration": 0.25},
    }

    result, violation = contract.validate(trade_params)

    assert result == BoundingContractResult.FAILED
    assert violation is not None
    assert violation.contract_id == "B4"


# ---------------------------------------------------------
# B5 - Volatility-Adjusted Sizing Tests
# ---------------------------------------------------------


def test_b5_volatility_sizing_pass():
    """B5 should pass when requested size is within volatility-adjusted limit."""
    contract = B5VolatilitySizing()
    trade_params = {
        "requested_size": 50.0,
        "base_order_size": 100.0,
        "current_volatility": 0.02,
        "atr_multiplier": 2.0,
    }

    result, violation = contract.validate(trade_params)

    assert result == BoundingContractResult.PASSED
    assert violation is None


def test_b5_volatility_sizing_scale():
    """B5 should scale order when volatility is high."""
    contract = B5VolatilitySizing()
    trade_params = {
        "requested_size": 100.0,
        "base_order_size": 100.0,
        "current_volatility": 0.50,  # 50% volatility (high)
        "atr_multiplier": 2.0,
    }

    result, violation = contract.validate(trade_params)

    assert result == BoundingContractResult.SCALED
    assert violation is not None
    assert violation.contract_id == "B5"
    assert violation.severity == "SCALE_DOWN"
    # Scaled size should be base_size / (1 + atr * volatility) = 100 / 2.0 = 50
    assert violation.limit == pytest.approx(50.0, rel=0.01)


def test_b5_volatility_sizing_high_volatility():
    """B5 should heavily reduce size during volatility spike."""
    contract = B5VolatilitySizing()
    trade_params = {
        "requested_size": 100.0,
        "base_order_size": 100.0,
        "current_volatility": 1.0,  # 100% volatility (extreme)
        "atr_multiplier": 2.0,
    }

    result, violation = contract.validate(trade_params)

    assert result == BoundingContractResult.SCALED
    # Scaled size should be 100 / (1 + 2*1.0) = 100 / 3 = 33.33
    assert violation.limit == pytest.approx(33.33, rel=0.01)


# ---------------------------------------------------------
# B6 - High-Impact Delta Escalation Tests
# ---------------------------------------------------------


def test_b6_delta_escalation_pass():
    """B6 should pass when position delta is below threshold."""
    contract = B6DeltaEscalation()
    trade_params = {
        "position_delta": 500.0,
        "limits": {"high_impact_threshold": 1000.0},
    }

    result, violation = contract.validate(trade_params)

    assert result == BoundingContractResult.PASSED
    assert violation is None


def test_b6_delta_escalation_escalate():
    """B6 should escalate to HITL when delta exceeds threshold."""
    contract = B6DeltaEscalation()
    trade_params = {
        "position_delta": 1500.0,
        "limits": {"high_impact_threshold": 1000.0},
    }

    result, violation = contract.validate(trade_params)

    assert result == BoundingContractResult.ESCALATED
    assert violation is not None
    assert violation.contract_id == "B6"
    assert violation.severity == "ESCALATION"


def test_b6_delta_escalation_negative_delta():
    """B6 should use absolute value for delta (handle sells)."""
    contract = B6DeltaEscalation()
    trade_params = {
        "position_delta": -1500.0,  # Negative delta (sell)
        "limits": {"high_impact_threshold": 1000.0},
    }

    result, violation = contract.validate(trade_params)

    assert result == BoundingContractResult.ESCALATED
    assert violation.actual == 1500.0  # Absolute value


# ---------------------------------------------------------
# B7 - Audit Sealing Tests
# ---------------------------------------------------------


def test_b7_audit_sealing_pass():
    """B7 should pass when Evidence Stream is available."""
    contract = B7AuditSealing()
    trade_params = {
        "evidence_stream_available": True,
    }

    result, violation = contract.validate(trade_params)

    assert result == BoundingContractResult.PASSED
    assert violation is None


def test_b7_audit_sealing_fail_closed():
    """B7 should fail-closed when Evidence Stream is unavailable."""
    contract = B7AuditSealing()
    trade_params = {
        "evidence_stream_available": False,
    }

    result, violation = contract.validate(trade_params)

    assert result == BoundingContractResult.FAILED
    assert violation is not None
    assert violation.contract_id == "B7"
    assert violation.severity == "FAIL_CLOSED"


# ---------------------------------------------------------
# B8 - TWAP Slippage Bound Tests
# ---------------------------------------------------------


def test_b8_slippage_buy_pass():
    """B8 should pass when buy slippage is acceptable."""
    contract = B8SlippageBound()
    trade_params = {
        "execution_price": 151.0,
        "benchmark_price": 150.0,
        "side": "buy",
        "limits": {"max_slippage": 0.05},
    }

    result, violation = contract.validate(trade_params)

    assert result == BoundingContractResult.PASSED
    assert violation is None


def test_b8_slippage_buy_fail():
    """B8 should fail when buy slippage exceeds limit."""
    contract = B8SlippageBound()
    trade_params = {
        "execution_price": 160.0,  # 6.67% slippage
        "benchmark_price": 150.0,
        "side": "buy",
        "limits": {"max_slippage": 0.05},
    }

    result, violation = contract.validate(trade_params)

    assert result == BoundingContractResult.FAILED
    assert violation is not None
    assert violation.contract_id == "B8"


def test_b8_slippage_sell_pass():
    """B8 should pass when sell slippage is acceptable."""
    contract = B8SlippageBound()
    trade_params = {
        "execution_price": 149.0,
        "benchmark_price": 150.0,
        "side": "sell",
        "limits": {"max_slippage": 0.05},
    }

    result, _violation = contract.validate(trade_params)

    assert result == BoundingContractResult.PASSED


def test_b8_slippage_favorable():
    """B8 should pass with favorable slippage (negative)."""
    contract = B8SlippageBound()
    trade_params = {
        "execution_price": 148.0,  # Better price (paid less)
        "benchmark_price": 150.0,
        "side": "buy",
        "limits": {"max_slippage": 0.05},
    }

    result, _violation = contract.validate(trade_params)

    assert result == BoundingContractResult.PASSED


# ---------------------------------------------------------
# B9 - Jurisdictional Filter Tests
# ---------------------------------------------------------


def test_b9_jurisdiction_local_pass():
    """B9 should pass all assets in LOCAL region."""
    contract = B9JurisdictionFilter()
    trade_params = {
        "symbol": "AAPL",
        "asset_category": "",
        "deployment_region": "LOCAL",
    }

    result, violation = contract.validate(trade_params)

    assert result == BoundingContractResult.PASSED
    assert violation is None


def test_b9_jurisdiction_us_fed_blocked_asset():
    """B9 should block USDT in US_FED region."""
    contract = B9JurisdictionFilter()
    trade_params = {
        "symbol": "USDT",
        "asset_category": "",
        "deployment_region": "US_FED",
    }

    result, violation = contract.validate(trade_params)

    assert result == BoundingContractResult.FAILED
    assert violation is not None
    assert violation.contract_id == "B9"
    assert violation.severity == "JURISDICTION_REJECT"


def test_b9_jurisdiction_eu_ecb_blocked_category():
    """B9 should block privacy coins in EU_ECB region."""
    contract = B9JurisdictionFilter()
    trade_params = {
        "symbol": "XMR",
        "asset_category": "privacy_coins",
        "deployment_region": "EU_ECB",
    }

    result, violation = contract.validate(trade_params)

    assert result == BoundingContractResult.FAILED
    assert "privacy_coins" in violation.message


def test_b9_jurisdiction_apac_mas_pass():
    """B9 should allow normal assets in APAC_MAS."""
    contract = B9JurisdictionFilter()
    trade_params = {
        "symbol": "AAPL",
        "asset_category": "",
        "deployment_region": "APAC_MAS",
    }

    result, _violation = contract.validate(trade_params)

    assert result == BoundingContractResult.PASSED


# ---------------------------------------------------------
# B10 - Rollback Window Validation Tests
# ---------------------------------------------------------


def test_b10_rollback_window_pass():
    """B10 should pass when rollback is supported with adequate window."""
    contract = B10RollbackWindow()
    trade_params = {
        "settlement_window_seconds": 300,
        "rollback_supported": True,
        "terminal_classification": "EXTERNALLY_REVERSIBLE",
    }

    result, violation = contract.validate(trade_params)

    assert result == BoundingContractResult.PASSED
    assert violation is None


def test_b10_rollback_window_fail_no_support():
    """B10 should fail when broker doesn't support rollback."""
    contract = B10RollbackWindow()
    trade_params = {
        "settlement_window_seconds": 300,
        "rollback_supported": False,
        "terminal_classification": "EXTERNALLY_REVERSIBLE",
    }

    result, violation = contract.validate(trade_params)

    assert result == BoundingContractResult.FAILED
    assert violation is not None
    assert violation.contract_id == "B10"
    assert violation.severity == "TERMINAL_RECLASSIFY"


def test_b10_rollback_window_fail_insufficient_window():
    """B10 should fail when settlement window is too short."""
    contract = B10RollbackWindow()
    trade_params = {
        "settlement_window_seconds": 30,  # Below 60s minimum
        "rollback_supported": True,
        "terminal_classification": "EXTERNALLY_REVERSIBLE",
    }

    result, _violation = contract.validate(trade_params)

    assert result == BoundingContractResult.FAILED


def test_b10_rollback_window_skip_irreversible():
    """B10 should skip validation for non-EXTERNALLY_REVERSIBLE trades."""
    contract = B10RollbackWindow()
    trade_params = {
        "settlement_window_seconds": 0,
        "rollback_supported": False,
        "terminal_classification": "IRREVERSIBLE_TERMINAL",
    }

    result, _violation = contract.validate(trade_params)

    assert result == BoundingContractResult.PASSED  # Not validated


# ---------------------------------------------------------
# Integration Tests: execute_trade_bounded
# ---------------------------------------------------------


@pytest.mark.asyncio
async def test_execute_trade_bounded_all_pass(
    sample_order, sample_limits, sample_market_data
):
    """All contracts pass - trade should execute."""
    with patch(
        "src.cage_finance.tools.bounded_execution.get_evidence_sink"
    ) as mock_sink:
        mock_sink.return_value.ingest = AsyncMock(return_value="evidence-id-123")

        result = await execute_trade_bounded(
            order=sample_order,
            market_data=sample_market_data,
            limits=sample_limits,
            dry_run=False,
        )

        assert result["status"] == "EXECUTED"
        assert result["evidence_id"] == "evidence-id-123"
        assert result["trade_id"] == sample_order.transaction_id
        assert result["terminal_classification"] == "EXTERNALLY_REVERSIBLE"
        assert len(result["violations"]) == 0


@pytest.mark.asyncio
async def test_execute_trade_bounded_dry_run(
    sample_order, sample_limits, sample_market_data
):
    """Dry run should validate without executing."""
    # Set volatility to 0 to avoid B5 scaling in this test
    sample_market_data["current_volatility"] = 0.0

    with patch(
        "src.cage_finance.tools.bounded_execution.get_evidence_sink"
    ) as mock_sink:
        mock_sink.return_value.ingest = AsyncMock(return_value="evidence-id-dry")

        result = await execute_trade_bounded(
            order=sample_order,
            market_data=sample_market_data,
            limits=sample_limits,
            dry_run=True,
        )

        assert result["status"] == "VALIDATED"
        assert "dry run" in result["message"].lower()
        assert "trade_id" not in result


@pytest.mark.asyncio
async def test_execute_trade_bounded_b1_violation(
    sample_order, sample_limits, sample_market_data
):
    """B1 violation should reject trade."""
    sample_market_data["order_notional"] = 200000.0  # Exceeds 100k cap

    with patch(
        "src.cage_finance.tools.bounded_execution.get_evidence_sink"
    ) as mock_sink:
        mock_sink.return_value.ingest = AsyncMock(return_value="evidence-id-reject")

        result = await execute_trade_bounded(
            order=sample_order,
            market_data=sample_market_data,
            limits=sample_limits,
            dry_run=False,
        )

        assert result["status"] == "REJECTED"
        assert len(result["violations"]) > 0
        assert any(v["contract_id"] == "B1" for v in result["violations"])


@pytest.mark.asyncio
async def test_execute_trade_bounded_b2_circuit_breaker(
    sample_order, sample_limits, sample_market_data
):
    """B2 drawdown violation should trigger circuit breaker."""
    sample_market_data["current_drawdown"] = 0.15  # Exceeds 10% limit

    with patch(
        "src.cage_finance.tools.bounded_execution.get_evidence_sink"
    ) as mock_sink:
        mock_sink.return_value.ingest = AsyncMock(return_value="evidence-id-breaker")

        result = await execute_trade_bounded(
            order=sample_order,
            market_data=sample_market_data,
            limits=sample_limits,
            dry_run=False,
        )

        assert result["status"] == "REJECTED"
        assert any(
            v["contract_id"] == "B2" and v["severity"] == "CIRCUIT_BREAKER"
            for v in result["violations"]
        )


@pytest.mark.asyncio
async def test_execute_trade_bounded_b5_scaling(
    sample_order, sample_limits, sample_market_data
):
    """B5 volatility scaling should reduce order size."""
    sample_market_data["current_volatility"] = 0.50  # High volatility

    with patch(
        "src.cage_finance.tools.bounded_execution.get_evidence_sink"
    ) as mock_sink:
        mock_sink.return_value.ingest = AsyncMock(return_value="evidence-id-scale")

        result = await execute_trade_bounded(
            order=sample_order,
            market_data=sample_market_data,
            limits=sample_limits,
            dry_run=False,
        )

        assert result["status"] == "SCALED"
        assert "scaled_size" in result
        assert result["scaled_size"] < result["original_size"]
        assert any(v["contract_id"] == "B5" for v in result["violations"])


@pytest.mark.asyncio
async def test_execute_trade_bounded_b6_escalation(
    sample_order, sample_limits, sample_market_data
):
    """B6 high delta should escalate to HITL."""
    sample_market_data["position_delta"] = 1500.0  # Exceeds 1000 threshold

    with patch(
        "src.cage_finance.tools.bounded_execution.get_evidence_sink"
    ) as mock_sink:
        mock_sink.return_value.ingest = AsyncMock(return_value="evidence-id-hitl")

        result = await execute_trade_bounded(
            order=sample_order,
            market_data=sample_market_data,
            limits=sample_limits,
            dry_run=False,
        )

        assert result["status"] == "ESCALATED"
        assert "human approval required" in result["message"].lower()
        assert any(v["contract_id"] == "B6" for v in result["violations"])


@pytest.mark.asyncio
async def test_execute_trade_bounded_b7_fail_closed(
    sample_order, sample_limits, sample_market_data
):
    """B7 Evidence Stream failure should fail-closed."""
    with patch(
        "src.cage_finance.tools.bounded_execution.get_evidence_sink"
    ) as mock_sink:
        mock_sink.return_value.ingest = AsyncMock(
            side_effect=RuntimeError("Redis unavailable")
        )

        result = await execute_trade_bounded(
            order=sample_order,
            market_data=sample_market_data,
            limits=sample_limits,
            dry_run=False,
        )

        assert result["status"] == "REJECTED"
        assert result["evidence_id"] is None
        assert any(v["contract_id"] == "B7" for v in result["violations"])


@pytest.mark.asyncio
async def test_execute_trade_bounded_replay_defense(
    sample_order, sample_limits, sample_market_data
):
    """Replay defense should block duplicate trades."""
    with patch(
        "src.cage_finance.tools.bounded_execution.get_evidence_sink"
    ) as mock_sink:
        mock_sink.return_value.ingest = AsyncMock(return_value="evidence-id-1")

        # First execution
        result1 = await execute_trade_bounded(
            order=sample_order,
            market_data=sample_market_data,
            limits=sample_limits,
            dry_run=False,
        )

        assert result1["status"] == "EXECUTED"

        # Replay attempt with same order (same transaction_id generates same receipt hash)
        # Note: In practice, each order has a unique transaction_id, but we test the cache mechanism
        result2 = await execute_trade_bounded(
            order=sample_order,
            market_data=sample_market_data,
            limits=sample_limits,
            dry_run=False,
        )

        # Second attempt should be rejected as replay
        assert result2["status"] == "REJECTED"
        assert any(
            v.get("contract_id") == "REPLAY_DEFENSE" for v in result2["violations"]
        )


@pytest.mark.asyncio
async def test_execute_trade_bounded_multi_violation(
    sample_order, sample_limits, sample_market_data
):
    """Multiple contract violations should all be reported."""
    sample_market_data["order_notional"] = 200000.0  # B1 violation
    sample_market_data["current_drawdown"] = 0.15  # B2 violation
    sample_market_data["order_book_depth"] = (
        100.0  # B3 violation (100/100 = 100% depth)
    )

    with patch(
        "src.cage_finance.tools.bounded_execution.get_evidence_sink"
    ) as mock_sink:
        mock_sink.return_value.ingest = AsyncMock(return_value="evidence-id-multi")

        result = await execute_trade_bounded(
            order=sample_order,
            market_data=sample_market_data,
            limits=sample_limits,
            dry_run=False,
        )

        assert result["status"] == "REJECTED"
        assert len(result["violations"]) >= 3
        violation_ids = {v["contract_id"] for v in result["violations"]}
        assert "B1" in violation_ids
        assert "B2" in violation_ids
        assert "B3" in violation_ids


@pytest.mark.asyncio
async def test_execute_trade_bounded_b9_us_fed(
    sample_order, sample_limits, sample_market_data
):
    """B9 should block USDT in US_FED region."""
    sample_order.symbol = "USDT"
    sample_market_data["deployment_region"] = "US_FED"

    # Override environment for this test
    with patch.dict(os.environ, {"CAGE_DEPLOYMENT_REGION": "US_FED"}):
        with patch(
            "src.cage_finance.tools.bounded_execution.get_evidence_sink"
        ) as mock_sink:
            mock_sink.return_value.ingest = AsyncMock(return_value="evidence-id-region")

            result = await execute_trade_bounded(
                order=sample_order,
                market_data=sample_market_data,
                limits=sample_limits,
                dry_run=False,
            )

            assert result["status"] == "REJECTED"
            assert any(v["contract_id"] == "B9" for v in result["violations"])


@pytest.mark.asyncio
async def test_execute_trade_bounded_b10_reclassify(
    sample_order, sample_limits, sample_market_data
):
    """B10 should re-classify to IRREVERSIBLE when rollback not available.

    Note: B10 is a special case - it re-classifies the terminal action to
    IRREVERSIBLE_TERMINAL when rollback is not supported, indicating higher
    governance scrutiny is required.
    """
    sample_market_data["rollback_supported"] = False

    with patch(
        "src.cage_finance.tools.bounded_execution.get_evidence_sink"
    ) as mock_sink:
        mock_sink.return_value.ingest = AsyncMock(return_value="evidence-id-b10")

        result = await execute_trade_bounded(
            order=sample_order,
            market_data=sample_market_data,
            limits=sample_limits,
            dry_run=False,
        )

        # Primary assertion: B10 re-classifies the terminal action
        assert result["terminal_classification"] == "IRREVERSIBLE_TERMINAL", (
            f"Expected IRREVERSIBLE_TERMINAL, got {result['terminal_classification']}"
        )

        # Trade should execute (B10 doesn't hard-block)
        assert result["status"] in ["EXECUTED", "VALIDATED"], (
            f"Expected EXECUTED/VALIDATED, got {result['status']}"
        )


# ---------------------------------------------------------
# Evidence Stream Integration Tests
# ---------------------------------------------------------


@pytest.mark.asyncio
async def test_evidence_stream_correlation(
    sample_order, sample_limits, sample_market_data
):
    """Evidence Stream should receive correct trace correlation."""
    with patch(
        "src.cage_finance.tools.bounded_execution.get_evidence_sink"
    ) as mock_sink:
        mock_ingest = AsyncMock(return_value="evidence-corr-123")
        mock_sink.return_value.ingest = mock_ingest

        await execute_trade_bounded(
            order=sample_order,
            market_data=sample_market_data,
            limits=sample_limits,
            dry_run=False,
        )

        # Verify ingest was called
        assert mock_ingest.called

        # Verify payload structure
        call_args = mock_ingest.call_args[0][0]
        assert "trace_id" in call_args
        assert "span_id" in call_args
        assert call_args["event_type"] == "BOUNDING_CONTRACT_VALIDATION"
        assert call_args["trade_id"] == sample_order.transaction_id
        assert "receipt_hash" in call_args


# ---------------------------------------------------------
# Regional Posture Tests
# ---------------------------------------------------------


@pytest.mark.parametrize(
    "region,expected_pass",
    [
        ("LOCAL", True),
        ("US_FED", True),  # AAPL allowed
        ("EU_ECB", True),
        ("APAC_MAS", True),
    ],
)
@pytest.mark.asyncio
async def test_regional_posture_aapl(
    region, expected_pass, sample_order, sample_limits, sample_market_data
):
    """AAPL should pass in all regions."""
    with patch.dict(os.environ, {"CAGE_DEPLOYMENT_REGION": region}):
        with patch(
            "src.cage_finance.tools.bounded_execution.get_evidence_sink"
        ) as mock_sink:
            mock_sink.return_value.ingest = AsyncMock(return_value=f"evidence-{region}")

            result = await execute_trade_bounded(
                order=sample_order,
                market_data=sample_market_data,
                limits=sample_limits,
                dry_run=False,
            )

            if expected_pass:
                assert result["status"] == "EXECUTED"
            else:
                assert result["status"] == "REJECTED"
