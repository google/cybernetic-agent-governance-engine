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
Negative tests for execute_trade routing seal enforcement.

Validates fail-closed invariant: execute_trade() must reject calls with
missing, empty, or whitespace-only routing seals.
"""

import uuid
from unittest.mock import patch

import pytest

from src.cage_finance.models.trade_order import TradeOrder
from src.cage_finance.tools.trade_executor import execute_trade
from src.gateway.governance.routing_seal import SymbolicGovernorViolation

pytestmark = [pytest.mark.unit, pytest.mark.local]


class TestExecuteTradeRoutingSealEnforcement:
    """Fail-closed routing seal validation in execute_trade()."""

    @pytest.mark.asyncio
    async def test_execute_trade_rejects_none_seal(self):
        """execute_trade() with routing_seal=None must raise SymbolicGovernorViolation."""
        order = TradeOrder(
            symbol="AAPL",
            amount=100,
            currency="USD",
            side="buy",
            type="market",
            confidence=0.99,
            transaction_id=str(uuid.uuid4()),
        )

        with pytest.raises(SymbolicGovernorViolation) as exc_info:
            await execute_trade(order, routing_seal=None)  # type: ignore[arg-type]

        assert "CRITICAL" in str(exc_info.value)
        assert "Direct execution attempt rejected" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_execute_trade_rejects_empty_string_seal(self):
        """execute_trade() with routing_seal='' must raise SymbolicGovernorViolation."""
        order = TradeOrder(
            symbol="MSFT",
            amount=50,
            currency="USD",
            side="sell",
            type="market",
            confidence=0.95,
            transaction_id=str(uuid.uuid4()),
        )

        with pytest.raises(SymbolicGovernorViolation) as exc_info:
            await execute_trade(order, routing_seal="")

        assert "CRITICAL" in str(exc_info.value)
        assert "Direct execution attempt rejected" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_execute_trade_rejects_whitespace_only_seal(self):
        """execute_trade() with routing_seal='   ' must raise SymbolicGovernorViolation."""
        order = TradeOrder(
            symbol="TSLA",
            amount=25,
            currency="USD",
            side="buy",
            type="market",
            confidence=0.90,
            transaction_id=str(uuid.uuid4()),
        )

        with pytest.raises(SymbolicGovernorViolation) as exc_info:
            await execute_trade(order, routing_seal="   ")

        assert "CRITICAL" in str(exc_info.value)
        assert "Direct execution attempt rejected" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_execute_trade_rejects_tabs_and_newlines_seal(self):
        """execute_trade() with routing_seal='\\t\\n' must raise SymbolicGovernorViolation."""
        order = TradeOrder(
            symbol="GOOG",
            amount=10,
            currency="USD",
            side="buy",
            type="market",
            confidence=0.88,
            transaction_id=str(uuid.uuid4()),
        )

        with pytest.raises(SymbolicGovernorViolation) as exc_info:
            await execute_trade(order, routing_seal="\t\n")

        assert "CRITICAL" in str(exc_info.value)
        assert "Direct execution attempt rejected" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_execute_trade_rejects_non_string_seal(self):
        """execute_trade() with routing_seal=123 must raise SymbolicGovernorViolation."""
        order = TradeOrder(
            symbol="NVDA",
            amount=15,
            currency="USD",
            side="sell",
            type="market",
            confidence=0.92,
            transaction_id=str(uuid.uuid4()),
        )

        with pytest.raises(SymbolicGovernorViolation) as exc_info:
            await execute_trade(order, routing_seal=123)  # type: ignore[arg-type]

        assert "CRITICAL" in str(exc_info.value)
        assert "Direct execution attempt rejected" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_execute_trade_accepts_valid_seal(self):
        """execute_trade() with a non-empty routing_seal proceeds to Redis checks."""
        order = TradeOrder(
            symbol="AMZN",
            amount=5,
            currency="USD",
            side="buy",
            type="market",
            confidence=0.98,
            transaction_id=str(uuid.uuid4()),
        )

        # Mock Redis and broker to validate seal check passes
        with (
            patch("src.cage_finance.tools.trade_executor.redis_client") as mock_redis,
            patch("src.cage_finance.tools.trade_executor._USE_MOCK_BROKER", True),
        ):
            mock_redis.get.return_value = None  # No safety violation

            result = await execute_trade(order, routing_seal="valid-seal-abc123")

            # Should reach mock broker execution without raising seal error
            assert "EXECUTED" in result
            assert "AMZN" in result
