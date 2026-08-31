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
Tests for non-finite value rejection at ingress Pydantic models.

Covers:
  - TradeOrder: NaN/inf rejected for amount and confidence fields.
  - ValidateActionRequest: NaN/inf rejected via allow_inf_nan=False.
  - ToolExecutionRequest: NaN/inf rejected via allow_inf_nan=False.

These tests verify the defence-in-depth hardening that prevents IEEE-754
non-finite values (NaN, +inf, -inf) from reaching internal governance layers.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

pytestmark = [pytest.mark.unit, pytest.mark.local]


# ---------------------------------------------------------------------------
# TradeOrder — amount and confidence field validators
# ---------------------------------------------------------------------------

_VALID_TRADE_KWARGS = {
    "symbol": "AAPL",
    "amount": 100.0,
    "currency": "USD",
    "confidence": 0.95,
}


class TestTradeOrderFiniteness:
    """TradeOrder must reject NaN, +inf, and -inf for numeric fields."""

    @pytest.mark.parametrize("bad_value", [float("nan"), float("inf"), float("-inf")])
    def test_amount_nan_inf_rejected(self, bad_value: float) -> None:
        from src.cage_finance.models.trade_order import TradeOrder

        with pytest.raises(ValidationError, match="(?i)finite"):
            TradeOrder(**{**_VALID_TRADE_KWARGS, "amount": bad_value})

    @pytest.mark.parametrize("bad_value", [float("nan"), float("inf"), float("-inf")])
    def test_confidence_nan_inf_rejected(self, bad_value: float) -> None:
        from src.cage_finance.models.trade_order import TradeOrder

        with pytest.raises(ValidationError, match="(?i)finite"):
            TradeOrder(**{**_VALID_TRADE_KWARGS, "confidence": bad_value})

    def test_valid_finite_values_accepted(self) -> None:
        """Positive control: valid finite values must still be accepted."""
        from src.cage_finance.models.trade_order import TradeOrder

        order = TradeOrder(**_VALID_TRADE_KWARGS)
        assert order.amount == 100.0
        assert order.confidence == 0.95
        assert order.symbol == "AAPL"


# ---------------------------------------------------------------------------
# ValidateActionRequest — model_config = ConfigDict(allow_inf_nan=False)
# ---------------------------------------------------------------------------


class TestValidateActionRequestFiniteness:
    """ValidateActionRequest must reject NaN/inf in params dict."""

    @pytest.mark.parametrize("bad_value", [float("nan"), float("inf"), float("-inf")])
    def test_nan_inf_in_params_rejected(self, bad_value: float) -> None:
        from src.gateway.server.governance_middleware import ValidateActionRequest

        with pytest.raises(ValidationError, match="(?i)non-finite"):
            ValidateActionRequest(
                action="execute_trade",
                params={"latency_ms": bad_value},
            )

    def test_valid_finite_params_accepted(self) -> None:
        from src.gateway.server.governance_middleware import ValidateActionRequest

        req = ValidateActionRequest(
            action="execute_trade",
            params={"latency_ms": 42.0, "drawdown": 0.03},
        )
        assert req.params["latency_ms"] == 42.0
        assert req.params["drawdown"] == 0.03


# ---------------------------------------------------------------------------
# ToolExecutionRequest — model_config = ConfigDict(allow_inf_nan=False)
# ---------------------------------------------------------------------------


class TestToolExecutionRequestFiniteness:
    """ToolExecutionRequest must reject NaN/inf in params dict."""

    @pytest.mark.parametrize("bad_value", [float("nan"), float("inf"), float("-inf")])
    def test_nan_inf_in_params_rejected(self, bad_value: float) -> None:
        from src.gateway.server.mcp_tool_server import ToolExecutionRequest

        with pytest.raises(ValidationError, match="(?i)non-finite"):
            ToolExecutionRequest(
                tool_name="execute_trade_action",
                params={"amount": bad_value},
            )

    def test_valid_finite_params_accepted(self) -> None:
        from src.gateway.server.mcp_tool_server import ToolExecutionRequest

        req = ToolExecutionRequest(
            tool_name="execute_trade_action",
            params={"amount": 500.0, "symbol": "GOOG"},
        )
        assert req.params["amount"] == 500.0
