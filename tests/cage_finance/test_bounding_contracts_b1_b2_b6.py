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

"""Tests for bounding contracts B1, B2, B6 (self-contained contracts).

Phase 5 Step 4: Validates inclusive boundary semantics (Ratified Decision 1)
and fail-closed behavior for missing/invalid thresholds.
"""

import math

import pytest

from src.cage_finance.safety.bounding.contracts import (
    contract_b1_max_notional,
    contract_b2_drawdown_breaker,
    contract_b6_hitl_high_impact,
)
from src.cage_finance.safety.bounding.models import (
    BoundedTradeRequest,
    ContractSeverity,
)


class TestContractB1MaxNotional:
    """Tests for B1 — Maximum single-order notional value."""

    @pytest.fixture
    def valid_thresholds(self):
        """Standard threshold configuration for B1."""
        return {"bounding": {"max_single_order_usd": 10000.0}}

    def test_trade_below_limit_is_admitted(self, valid_thresholds):
        """Trade below max notional limit is admitted."""
        request = BoundedTradeRequest(
            symbol="AAPL", amount=5000.0, side="buy", venue="NASDAQ"
        )
        result = contract_b1_max_notional(request, valid_thresholds)

        assert result.contract_id == "B1"
        assert result.admitted is True
        assert result.severity == ContractSeverity.HARD_BLOCK
        assert len(result.findings) == 0

    def test_trade_exactly_at_limit_is_admitted(self, valid_thresholds):
        """Trade exactly at max notional limit is admitted (inclusive boundary).

        Per Ratified Decision 1: Boundaries use inclusive comparison (≤).
        """
        request = BoundedTradeRequest(
            symbol="AAPL", amount=10000.0, side="buy", venue="NASDAQ"
        )
        result = contract_b1_max_notional(request, valid_thresholds)

        assert result.admitted is True, (
            "Boundary check must be inclusive (amount <= limit) per Ratified Decision 1"
        )

    def test_trade_above_limit_is_rejected(self, valid_thresholds):
        """Trade above max notional limit is rejected with HARD_BLOCK."""
        request = BoundedTradeRequest(
            symbol="AAPL", amount=15000.0, side="buy", venue="NASDAQ"
        )
        result = contract_b1_max_notional(request, valid_thresholds)

        assert result.admitted is False
        assert result.severity == ContractSeverity.HARD_BLOCK
        assert len(result.findings) == 1
        assert (
            result.findings[0]["reason"]
            == "Trade notional exceeds maximum single-order limit"
        )
        assert result.findings[0]["amount_usd"] == 15000.0
        assert result.findings[0]["limit_usd"] == 10000.0
        assert result.findings[0]["excess_usd"] == 5000.0

    def test_missing_threshold_fails_closed(self):
        """Missing threshold configuration fails closed with HARD_BLOCK."""
        request = BoundedTradeRequest(
            symbol="AAPL", amount=1000.0, side="buy", venue="NASDAQ"
        )
        result = contract_b1_max_notional(request, {})

        assert result.admitted is False
        assert result.severity == ContractSeverity.HARD_BLOCK
        assert result.findings[0]["reason"] == "Missing threshold configuration"

    def test_nan_threshold_fails_closed(self):
        """NaN threshold value fails closed with HARD_BLOCK."""
        request = BoundedTradeRequest(
            symbol="AAPL", amount=1000.0, side="buy", venue="NASDAQ"
        )
        thresholds = {"bounding": {"max_single_order_usd": math.nan}}
        result = contract_b1_max_notional(request, thresholds)

        assert result.admitted is False
        assert result.severity == ContractSeverity.HARD_BLOCK
        assert result.findings[0]["reason"] == "Invalid threshold value"

    def test_inf_threshold_fails_closed(self):
        """Inf threshold value fails closed with HARD_BLOCK."""
        request = BoundedTradeRequest(
            symbol="AAPL", amount=1000.0, side="buy", venue="NASDAQ"
        )
        thresholds = {"bounding": {"max_single_order_usd": math.inf}}
        result = contract_b1_max_notional(request, thresholds)

        assert result.admitted is False
        assert result.severity == ContractSeverity.HARD_BLOCK


class TestContractB2DrawdownBreaker:
    """Tests for B2 — Daily drawdown portfolio circuit breaker."""

    @pytest.fixture
    def valid_thresholds(self):
        """Standard threshold configuration for B2 (reuses drawdown.limit)."""
        return {"drawdown": {"limit": 0.05}}  # 5% drawdown limit

    def test_drawdown_below_limit_is_admitted(self, valid_thresholds):
        """Drawdown below limit is admitted."""
        request = BoundedTradeRequest(
            symbol="AAPL", amount=1000.0, side="buy", venue="NASDAQ"
        )
        result = contract_b2_drawdown_breaker(
            request, valid_thresholds, current_drawdown=0.03
        )

        assert result.contract_id == "B2"
        assert result.admitted is True
        assert result.severity == ContractSeverity.HARD_BLOCK
        assert len(result.findings) == 0

    def test_drawdown_exactly_at_limit_is_admitted(self, valid_thresholds):
        """Drawdown exactly at limit is admitted (inclusive boundary).

        Per Ratified Decision 1: Boundaries use inclusive comparison (≤).
        """
        request = BoundedTradeRequest(
            symbol="AAPL", amount=1000.0, side="buy", venue="NASDAQ"
        )
        result = contract_b2_drawdown_breaker(
            request, valid_thresholds, current_drawdown=0.05
        )

        assert result.admitted is True, (
            "Boundary check must be inclusive (drawdown <= limit) per Ratified Decision 1"
        )

    def test_drawdown_above_limit_is_rejected(self, valid_thresholds):
        """Drawdown above limit triggers circuit breaker with HARD_BLOCK."""
        request = BoundedTradeRequest(
            symbol="AAPL", amount=1000.0, side="buy", venue="NASDAQ"
        )
        result = contract_b2_drawdown_breaker(
            request, valid_thresholds, current_drawdown=0.08
        )

        assert result.admitted is False
        assert result.severity == ContractSeverity.HARD_BLOCK
        assert len(result.findings) == 1
        assert (
            result.findings[0]["reason"]
            == "Portfolio drawdown exceeds circuit breaker limit"
        )
        assert result.findings[0]["current_drawdown_pct"] == 8.0
        assert result.findings[0]["limit_pct"] == 5.0
        assert result.findings[0]["excess_pct"] == 3.0

    def test_missing_current_drawdown_fails_closed(self, valid_thresholds):
        """Missing current_drawdown parameter fails closed with HARD_BLOCK."""
        request = BoundedTradeRequest(
            symbol="AAPL", amount=1000.0, side="buy", venue="NASDAQ"
        )
        result = contract_b2_drawdown_breaker(
            request, valid_thresholds, current_drawdown=None
        )

        assert result.admitted is False
        assert result.severity == ContractSeverity.HARD_BLOCK
        assert result.findings[0]["reason"] == "Missing current drawdown data"

    def test_nan_current_drawdown_fails_closed(self, valid_thresholds):
        """NaN current_drawdown fails closed with HARD_BLOCK."""
        request = BoundedTradeRequest(
            symbol="AAPL", amount=1000.0, side="buy", venue="NASDAQ"
        )
        result = contract_b2_drawdown_breaker(
            request, valid_thresholds, current_drawdown=math.nan
        )

        assert result.admitted is False
        assert result.severity == ContractSeverity.HARD_BLOCK
        assert result.findings[0]["reason"] == "Invalid current drawdown value"

    def test_missing_threshold_fails_closed(self):
        """Missing threshold configuration fails closed with HARD_BLOCK."""
        request = BoundedTradeRequest(
            symbol="AAPL", amount=1000.0, side="buy", venue="NASDAQ"
        )
        result = contract_b2_drawdown_breaker(request, {}, current_drawdown=0.03)

        assert result.admitted is False
        assert result.severity == ContractSeverity.HARD_BLOCK
        assert result.findings[0]["reason"] == "Missing threshold configuration"

    def test_zero_drawdown_is_admitted(self, valid_thresholds):
        """Zero drawdown (no loss) is admitted."""
        request = BoundedTradeRequest(
            symbol="AAPL", amount=1000.0, side="buy", venue="NASDAQ"
        )
        result = contract_b2_drawdown_breaker(
            request, valid_thresholds, current_drawdown=0.0
        )

        assert result.admitted is True


class TestContractB6HitlHighImpact:
    """Tests for B6 — Mandatory HITL escalation for high-impact deltas."""

    @pytest.fixture
    def valid_thresholds(self):
        """Standard threshold configuration for B6 (reuses consensus.threshold_usd)."""
        return {"consensus": {"threshold_usd": 10000.0}}

    def test_trade_below_threshold_is_admitted(self, valid_thresholds):
        """Trade below HITL threshold is admitted."""
        request = BoundedTradeRequest(
            symbol="AAPL", amount=5000.0, side="buy", venue="NASDAQ"
        )
        result = contract_b6_hitl_high_impact(request, valid_thresholds)

        assert result.contract_id == "B6"
        assert result.admitted is True
        assert result.severity == ContractSeverity.HITL_ESCALATE
        assert len(result.findings) == 0

    def test_trade_exactly_at_threshold_is_admitted(self, valid_thresholds):
        """Trade exactly at HITL threshold is admitted (inclusive boundary).

        Per Ratified Decision 1: Boundaries use inclusive comparison (≤).
        """
        request = BoundedTradeRequest(
            symbol="AAPL", amount=10000.0, side="buy", venue="NASDAQ"
        )
        result = contract_b6_hitl_high_impact(request, valid_thresholds)

        assert result.admitted is True, (
            "Boundary check must be inclusive (amount <= threshold) per Ratified Decision 1"
        )

    def test_high_impact_trade_escalates_to_hitl(self, valid_thresholds):
        """High-impact trade is rejected with HITL_ESCALATE (not HARD_BLOCK).

        Unlike B1/B2, B6 uses HITL_ESCALATE severity to route to human review
        rather than blocking outright.
        """
        request = BoundedTradeRequest(
            symbol="BTC",
            amount=50000.0,
            side="buy",
            venue="COINBASE",
            jurisdiction="US",
        )
        result = contract_b6_hitl_high_impact(request, valid_thresholds)

        assert result.admitted is False
        assert result.severity == ContractSeverity.HITL_ESCALATE  # Not HARD_BLOCK
        assert len(result.findings) == 1
        assert result.findings[0]["reason"] == "High-impact trade requires human review"
        assert result.findings[0]["amount_usd"] == 50000.0
        assert result.findings[0]["threshold_usd"] == 10000.0
        assert result.findings[0]["excess_usd"] == 40000.0
        assert result.findings[0]["jurisdiction"] == "US"

    def test_missing_threshold_fails_with_hitl_escalate(self):
        """Missing threshold fails with HITL_ESCALATE (not HARD_BLOCK).

        B6 uses HITL_ESCALATE for all failures to ensure human review.
        """
        request = BoundedTradeRequest(
            symbol="AAPL", amount=1000.0, side="buy", venue="NASDAQ"
        )
        result = contract_b6_hitl_high_impact(request, {})

        assert result.admitted is False
        assert result.severity == ContractSeverity.HITL_ESCALATE
        assert result.findings[0]["reason"] == "Missing threshold configuration"

    def test_nan_threshold_fails_with_hitl_escalate(self):
        """NaN threshold fails with HITL_ESCALATE."""
        request = BoundedTradeRequest(
            symbol="AAPL", amount=1000.0, side="buy", venue="NASDAQ"
        )
        thresholds = {"consensus": {"threshold_usd": math.nan}}
        result = contract_b6_hitl_high_impact(request, thresholds)

        assert result.admitted is False
        assert result.severity == ContractSeverity.HITL_ESCALATE


class TestContractInteractions:
    """Integration tests for B1, B2, B6 contract interactions."""

    def test_all_contracts_pass_for_small_safe_trade(self):
        """Small trade with low drawdown passes all three contracts."""
        request = BoundedTradeRequest(
            symbol="AAPL", amount=1000.0, side="buy", venue="NASDAQ"
        )
        thresholds = {
            "bounding": {"max_single_order_usd": 10000.0},
            "drawdown": {"limit": 0.05},
            "consensus": {"threshold_usd": 10000.0},
        }

        b1_result = contract_b1_max_notional(request, thresholds)
        b2_result = contract_b2_drawdown_breaker(
            request, thresholds, current_drawdown=0.02
        )
        b6_result = contract_b6_hitl_high_impact(request, thresholds)

        assert b1_result.admitted is True
        assert b2_result.admitted is True
        assert b6_result.admitted is True

    def test_b1_blocks_while_b2_and_b6_pass(self):
        """B1 blocks oversized trade while B2 and B6 pass."""
        request = BoundedTradeRequest(
            symbol="AAPL", amount=15000.0, side="buy", venue="NASDAQ"
        )
        thresholds = {
            "bounding": {"max_single_order_usd": 10000.0},
            "drawdown": {"limit": 0.05},
            "consensus": {"threshold_usd": 20000.0},  # Higher than B1 limit
        }

        b1_result = contract_b1_max_notional(request, thresholds)
        b2_result = contract_b2_drawdown_breaker(
            request, thresholds, current_drawdown=0.02
        )
        b6_result = contract_b6_hitl_high_impact(request, thresholds)

        assert b1_result.admitted is False
        assert b1_result.severity == ContractSeverity.HARD_BLOCK
        assert b2_result.admitted is True
        assert b6_result.admitted is True

    def test_b2_blocks_during_high_drawdown(self):
        """B2 blocks trade during high drawdown while B1 and B6 pass."""
        request = BoundedTradeRequest(
            symbol="AAPL", amount=5000.0, side="buy", venue="NASDAQ"
        )
        thresholds = {
            "bounding": {"max_single_order_usd": 10000.0},
            "drawdown": {"limit": 0.05},
            "consensus": {"threshold_usd": 10000.0},
        }

        b1_result = contract_b1_max_notional(request, thresholds)
        b2_result = contract_b2_drawdown_breaker(
            request, thresholds, current_drawdown=0.08
        )
        b6_result = contract_b6_hitl_high_impact(request, thresholds)

        assert b1_result.admitted is True
        assert b2_result.admitted is False
        assert b2_result.severity == ContractSeverity.HARD_BLOCK
        assert b6_result.admitted is True

    def test_b6_escalates_high_impact_while_b1_and_b2_pass(self):
        """B6 escalates high-impact trade while B1 and B2 pass."""
        request = BoundedTradeRequest(
            symbol="BTC", amount=50000.0, side="buy", venue="COINBASE"
        )
        thresholds = {
            "bounding": {"max_single_order_usd": 100000.0},
            "drawdown": {"limit": 0.05},
            "consensus": {"threshold_usd": 25000.0},
        }

        b1_result = contract_b1_max_notional(request, thresholds)
        b2_result = contract_b2_drawdown_breaker(
            request, thresholds, current_drawdown=0.02
        )
        b6_result = contract_b6_hitl_high_impact(request, thresholds)

        assert b1_result.admitted is True
        assert b2_result.admitted is True
        assert b6_result.admitted is False
        assert b6_result.severity == ContractSeverity.HITL_ESCALATE
