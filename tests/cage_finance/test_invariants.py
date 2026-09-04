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

"""Regression tests for finance domain invariants and cost resolver.

Phase 5 Step 1: Prevents silent fail-open where execute_trade_bounded bypasses
the CBF cash barrier by returning 0.0 cost (Issue #137, Master Plan Phase 5).
"""

import math

import pytest

from src.cage_finance.invariants import CashBarrier, finance_cost_resolver


class TestCashBarrierDeclaration:
    """Tests for the CashBarrier declarative invariant model."""

    def test_invariant_id_is_finance_scoped(self):
        """The barrier invariant_id must be finance-scoped for domain isolation."""
        assert CashBarrier.invariant_id == "finance.cash_balance"

    def test_state_key_points_to_redis_cash_key(self):
        """The state_key must match the Redis key used by the CBF engine."""
        assert CashBarrier.state_key == "safety:current_cash"

    def test_threshold_key_points_to_governance_config(self):
        """The threshold_key must match config/governance_thresholds.json path."""
        assert CashBarrier.threshold_key == "cbf.min_cash_balance"

    def test_gamma_default_is_0_5(self):
        """The gamma parameter (CBF time step coefficient) must match THRESHOLDS."""
        assert CashBarrier.gamma == 0.5


class TestFinanceCostResolver:
    """Tests for finance_cost_resolver — the critical CBF cost injection point."""

    # -------------------------------------------------------------------------
    # Regression tests for execute_trade (existing verb)
    # -------------------------------------------------------------------------

    def test_execute_trade_with_amount_field(self):
        """execute_trade with 'amount' field returns that amount as cost."""
        cost = finance_cost_resolver("execute_trade", {"amount": 1500.0})
        assert cost == 1500.0

    def test_execute_trade_with_amount_minor(self):
        """execute_trade with 'amount_minor' (cents) returns dollars."""
        cost = finance_cost_resolver(
            "execute_trade", {"amount_minor": 250000, "amount": 9999.0}
        )
        # amount_minor takes precedence: 250000 cents = 2500.0 dollars
        assert cost == 2500.0

    def test_execute_trade_zero_amount_returns_zero(self):
        """execute_trade with zero amount returns 0.0 cost (no barrier hit)."""
        cost = finance_cost_resolver("execute_trade", {"amount": 0.0})
        assert cost == 0.0

    def test_execute_trade_missing_amount_defaults_zero(self):
        """execute_trade with missing 'amount' field defaults to 0.0."""
        cost = finance_cost_resolver("execute_trade", {})
        assert cost == 0.0

    def test_execute_trade_rejects_nan_amount(self):
        """execute_trade with NaN amount raises ValueError (fail-closed)."""
        with pytest.raises(ValueError, match="invalid trade amount.*must be a finite"):
            finance_cost_resolver("execute_trade", {"amount": math.nan})

    def test_execute_trade_rejects_inf_amount(self):
        """execute_trade with inf amount raises ValueError (fail-closed)."""
        with pytest.raises(ValueError, match="invalid trade amount.*must be a finite"):
            finance_cost_resolver("execute_trade", {"amount": math.inf})

    def test_execute_trade_rejects_negative_amount(self):
        """execute_trade with negative amount raises ValueError (fail-closed)."""
        with pytest.raises(ValueError, match="invalid trade amount.*non-negative"):
            finance_cost_resolver("execute_trade", {"amount": -100.0})

    # -------------------------------------------------------------------------
    # Phase 5 Step 1: execute_trade_bounded regression tests (new verb)
    # -------------------------------------------------------------------------

    def test_execute_trade_bounded_with_amount_field(self):
        """execute_trade_bounded with 'amount' field returns that amount as cost.

        CRITICAL: This test prevents the silent fail-open where execute_trade_bounded
        was returning 0.0 and bypassing the CBF cash barrier (Phase 5 Step 1).
        """
        cost = finance_cost_resolver("execute_trade_bounded", {"amount": 1000.0})
        assert cost == 1000.0, (
            "execute_trade_bounded MUST return nonzero cost to hit CBF barrier — "
            "returning 0.0 is a silent fail-open vulnerability"
        )

    def test_execute_trade_bounded_with_amount_minor(self):
        """execute_trade_bounded with 'amount_minor' (cents) returns dollars."""
        cost = finance_cost_resolver(
            "execute_trade_bounded", {"amount_minor": 150000, "amount": 8888.0}
        )
        # amount_minor takes precedence: 150000 cents = 1500.0 dollars
        assert cost == 1500.0

    def test_execute_trade_bounded_zero_amount_returns_zero(self):
        """execute_trade_bounded with zero amount returns 0.0 cost (no barrier hit)."""
        cost = finance_cost_resolver("execute_trade_bounded", {"amount": 0.0})
        assert cost == 0.0

    def test_execute_trade_bounded_rejects_nan_amount(self):
        """execute_trade_bounded with NaN amount raises ValueError (fail-closed)."""
        with pytest.raises(ValueError, match="invalid trade amount.*must be a finite"):
            finance_cost_resolver("execute_trade_bounded", {"amount": math.nan})

    def test_execute_trade_bounded_rejects_inf_amount(self):
        """execute_trade_bounded with inf amount raises ValueError (fail-closed)."""
        with pytest.raises(ValueError, match="invalid trade amount.*must be a finite"):
            finance_cost_resolver("execute_trade_bounded", {"amount": math.inf})

    def test_execute_trade_bounded_rejects_negative_amount(self):
        """execute_trade_bounded with negative amount raises ValueError (fail-closed)."""
        with pytest.raises(ValueError, match="invalid trade amount.*non-negative"):
            finance_cost_resolver("execute_trade_bounded", {"amount": -200.0})

    # -------------------------------------------------------------------------
    # Other actions must return 0.0 (no cash cost)
    # -------------------------------------------------------------------------

    def test_non_trade_actions_return_zero_cost(self):
        """Non-trade actions (e.g., query_market) must return 0.0 cash cost."""
        test_cases = [
            ("query_market", {"symbol": "AAPL"}),
            ("get_portfolio", {}),
            ("analyze_risk", {"portfolio_id": "p123"}),
            ("unknown_action", {"foo": "bar"}),
        ]
        for action_name, payload in test_cases:
            cost = finance_cost_resolver(action_name, payload)
            assert cost == 0.0, f"{action_name} must return 0.0 cost"

    def test_empty_action_name_returns_zero(self):
        """Empty action name returns 0.0 cost (safe default)."""
        cost = finance_cost_resolver("", {"amount": 5000.0})
        assert cost == 0.0
