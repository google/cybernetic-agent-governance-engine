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
tests/test_security_fixes.py

Regression tests for Sprint 1 Critical security findings.

C-01 — Trade side inversion (tools.py):
    Verifies that execute_trade() uses the requested side ("sell") rather than
    the previously hardcoded "buy", and that an invalid side is rejected.

C-02 — CBF fail-closed on Redis unavailability (symbolic_governor.py):
    Verifies that SymbolicGovernor.pre_check() returns cbf_allowed=False when
    the CBF Redis call raises an exception, rather than the previous fail-open
    behaviour that returned True.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# C-01 — Trade side inversion
# ---------------------------------------------------------------------------


class TestC01TradeSide:
    """C-01: execute_trade() must forward the requested side, not hardcode 'buy'."""

    @pytest.mark.asyncio
    async def test_sell_order_sends_sell_to_broker(self):
        """A sell order must reach the broker with side='sell'."""
        from src.cage_finance.models.trade_order import TradeOrder
        from src.cage_finance.tools.trade_executor import execute_trade

        tx_id = str(uuid.uuid4())
        order = TradeOrder(
            symbol="AAPL",
            amount=50,
            currency="USD",
            side="sell",
            type="market",
            confidence=0.95,
            transaction_id=tx_id,
        )

        captured_payload: dict = {}

        def _fake_post(url, json=None, headers=None, **kwargs):
            captured_payload.update(json or {})
            mock_resp = MagicMock()
            mock_resp.json.return_value = {"id": "order-sell-001"}
            mock_resp.raise_for_status.return_value = None
            return mock_resp

        with (
            patch("src.cage_finance.tools.trade_executor.redis_client") as mock_redis,
            patch("requests.post", side_effect=_fake_post),
            patch.dict(
                os.environ,
                {
                    "BROKER_API_KEY": "test-key",
                    "BROKER_API_SECRET": "test-secret",
                    "USE_MOCK_BROKER": "false",
                },
            ),
        ):
            mock_redis.get.return_value = None  # no safety violation

            result = await execute_trade(order)

        assert captured_payload.get("side") == "sell", (
            f"Expected side='sell' in broker payload but got: {captured_payload}"
        )
        assert "EXECUTED" in result

    @pytest.mark.asyncio
    async def test_buy_order_sends_buy_to_broker(self):
        """A buy order must reach the broker with side='buy'."""
        from src.cage_finance.models.trade_order import TradeOrder
        from src.cage_finance.tools.trade_executor import execute_trade

        tx_id = str(uuid.uuid4())
        order = TradeOrder(
            symbol="MSFT",
            amount=10,
            currency="USD",
            side="buy",
            type="market",
            confidence=0.90,
            transaction_id=tx_id,
        )

        captured_payload: dict = {}

        def _fake_post(url, json=None, headers=None, **kwargs):
            captured_payload.update(json or {})
            mock_resp = MagicMock()
            mock_resp.json.return_value = {"id": "order-buy-001"}
            mock_resp.raise_for_status.return_value = None
            return mock_resp

        with (
            patch("src.cage_finance.tools.trade_executor.redis_client") as mock_redis,
            patch("requests.post", side_effect=_fake_post),
            patch.dict(
                os.environ,
                {
                    "BROKER_API_KEY": "test-key",
                    "BROKER_API_SECRET": "test-secret",
                    "USE_MOCK_BROKER": "false",
                },
            ),
        ):
            mock_redis.get.return_value = None

            result = await execute_trade(order)

        assert captured_payload.get("side") == "buy", (
            f"Expected side='buy' in broker payload but got: {captured_payload}"
        )
        assert "EXECUTED" in result

    @pytest.mark.asyncio
    async def test_invalid_side_raises_assertion_error(self):
        """An order with an invalid side must be rejected before any broker call."""
        from src.cage_finance.models.trade_order import TradeOrder
        from src.cage_finance.tools.trade_executor import execute_trade

        tx_id = str(uuid.uuid4())
        order = TradeOrder(
            symbol="TSLA",
            amount=5,
            currency="USD",
            side="short",  # invalid — not in {"buy", "sell"}
            type="market",
            confidence=0.80,
            transaction_id=tx_id,
        )

        with (
            patch("src.cage_finance.tools.trade_executor.redis_client") as mock_redis,
            patch("requests.post") as mock_post,
            patch.dict(
                os.environ,
                {
                    "BROKER_API_KEY": "test-key",
                    "BROKER_API_SECRET": "test-secret",
                    "USE_MOCK_BROKER": "false",
                },
            ),
        ):
            mock_redis.get.return_value = None

            with pytest.raises(AssertionError, match="Invalid trade side"):
                await execute_trade(order)

        # Broker must never be called for an invalid side.
        mock_post.assert_not_called()

    @pytest.mark.asyncio
    async def test_mock_broker_preserves_sell_side(self):
        """Mock broker fast-path must also reflect the requested side in its return value.

        _USE_MOCK_BROKER is a module-level constant evaluated at import time, so
        patch.dict(os.environ) cannot change it after the module is loaded.
        We patch the constant directly on the module instead.
        """
        import src.cage_finance.tools.trade_executor as tools_module
        from src.cage_finance.models.trade_order import TradeOrder
        from src.cage_finance.tools.trade_executor import execute_trade

        tx_id = str(uuid.uuid4())
        order = TradeOrder(
            symbol="NVDA",
            amount=20,
            currency="USD",
            side="sell",
            type="market",
            confidence=0.88,
            transaction_id=tx_id,
        )

        with (
            patch("src.cage_finance.tools.trade_executor.redis_client") as mock_redis,
            patch.object(tools_module, "_USE_MOCK_BROKER", True),
        ):
            mock_redis.get.return_value = None

            result = await execute_trade(order)

        # The mock result string includes the side from the order object.
        assert "sell" in result.lower(), (
            f"Mock broker result should mention 'sell' but got: {result}"
        )


# ---------------------------------------------------------------------------
# C-02 — CBF fail-closed on Redis unavailability
# ---------------------------------------------------------------------------


class TestC02CbfFailClosed:
    """C-02: pre_check() must return cbf_allowed=False when CBF/Redis raises."""

    def _make_governor(self):
        """Build a minimal SymbolicGovernor with mocked sub-components."""
        from src.gateway.governance.symbolic_governor import SymbolicGovernor

        mock_stpa = MagicMock()
        mock_stpa.validate.return_value = []  # no STPA violations

        mock_cbf = AsyncMock()
        mock_opa = AsyncMock()

        gov = SymbolicGovernor.__new__(SymbolicGovernor)
        gov.stpa_validator = mock_stpa
        gov.opa_client = mock_opa

        mock_cbf.tier_name = "cbf"
        mock_cbf.claims_action.return_value = True
        mock_cbf.verify_action = mock_cbf.evaluate
        gov.safety_filter = mock_cbf
        gov._domain_tiers = [mock_cbf]
        return gov, mock_cbf

    @pytest.mark.asyncio
    async def test_cbf_redis_error_returns_denied(self):
        """When CBF raises (Redis down), pre_check must return cbf_allowed=False."""
        gov, mock_cbf = self._make_governor()
        mock_cbf.evaluate.side_effect = ConnectionError("Redis connection refused")

        result = await gov.pre_check("execute_trade", {"symbol": "AAPL", "qty": 100})

        assert result["cbf_result"]["allowed"] is False, (
            "CBF fail-closed: allowed must be False when Redis is unavailable"
        )
        assert "CBF unavailable" in result["cbf_result"]["reason"], (
            f"Reason should mention 'CBF unavailable' but got: {result['cbf_result']['reason']}"
        )

    @pytest.mark.asyncio
    async def test_cbf_timeout_returns_denied(self):
        """A timeout from the CBF Redis call must also result in cbf_allowed=False."""
        import asyncio

        gov, mock_cbf = self._make_governor()
        mock_cbf.evaluate.side_effect = asyncio.TimeoutError("CBF timed out")

        result = await gov.pre_check("execute_trade", {"symbol": "MSFT", "qty": 50})

        assert result["cbf_result"]["allowed"] is False
        assert "CBF unavailable" in result["cbf_result"]["reason"]

    @pytest.mark.asyncio
    async def test_cbf_success_returns_allowed_when_safe(self):
        """When CBF returns SAFE, pre_check must return cbf_allowed=True."""
        gov, mock_cbf = self._make_governor()
        mock_cbf.evaluate.return_value = "SAFE"

        result = await gov.pre_check("execute_trade", {"symbol": "GOOG", "qty": 10})

        assert result["cbf_result"]["allowed"] is True
        assert result["cbf_result"]["reason"] == "SAFE"

    @pytest.mark.asyncio
    async def test_cbf_unsafe_result_returns_denied(self):
        """When CBF returns an UNSAFE verdict, pre_check must return cbf_allowed=False."""
        gov, mock_cbf = self._make_governor()
        mock_cbf.evaluate.return_value = "UNSAFE: position limit exceeded"

        result = await gov.pre_check("execute_trade", {"symbol": "TSLA", "qty": 9999})

        assert result["cbf_result"]["allowed"] is False

    @pytest.mark.asyncio
    async def test_cbf_error_does_not_propagate_exception(self):
        """A Redis error must be caught — pre_check must not raise to the caller."""
        gov, mock_cbf = self._make_governor()
        mock_cbf.evaluate.side_effect = RuntimeError("unexpected Redis failure")

        # Must not raise — the exception is swallowed and converted to a deny.
        result = await gov.pre_check("execute_trade", {"symbol": "AMZN", "qty": 1})

        assert isinstance(result, dict)
        assert "cbf_result" in result
        assert result["cbf_result"]["allowed"] is False
