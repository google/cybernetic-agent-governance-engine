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

"""Advisor ``execute_trade`` forwards to the gateway's MCP tool, nothing more.

The advisor holds no governor: ``execute_trade`` must pass the order to
``execute_trade_action`` unchanged, return the gateway's answer verbatim, and
let every transport failure propagate to the caller (never swallow it).
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.governed_financial_advisor.tools.trades import execute_trade

pytestmark = [pytest.mark.unit, pytest.mark.local]

_ORDER = {
    "symbol": "AAPL",
    "amount": 10.0,
    "currency": "USD",
    "transaction_id": "test-txn-001",
    "confidence": 0.95,
}


def _mcp(call_tool: AsyncMock) -> MagicMock:
    client = MagicMock()
    client.call_tool = call_tool
    return client


@pytest.mark.asyncio
async def test_execute_trade_forwards_order_and_returns_gateway_answer() -> None:
    call_tool = AsyncMock(return_value="EXECUTED: AAPL x 10.0 (Receipt ID: r-1)")
    with patch(
        "src.gateway.infrastructure.mcp_client.get_mcp_client",
        return_value=_mcp(call_tool),
    ):
        result = await execute_trade(dict(_ORDER))

    assert result == "EXECUTED: AAPL x 10.0 (Receipt ID: r-1)"
    call_tool.assert_awaited_once_with("execute_trade_action", _ORDER)


@pytest.mark.asyncio
async def test_execute_trade_returns_gateway_refusal_verbatim() -> None:
    call_tool = AsyncMock(return_value="BLOCKED: governance refused")
    with patch(
        "src.gateway.infrastructure.mcp_client.get_mcp_client",
        return_value=_mcp(call_tool),
    ):
        assert await execute_trade(dict(_ORDER)) == "BLOCKED: governance refused"


@pytest.mark.asyncio
@pytest.mark.parametrize("exc", [ConnectionError("gateway down"), TimeoutError("slow")])
async def test_execute_trade_propagates_transport_failures(exc: Exception) -> None:
    call_tool = AsyncMock(side_effect=exc)
    with (
        patch(
            "src.gateway.infrastructure.mcp_client.get_mcp_client",
            return_value=_mcp(call_tool),
        ),
        pytest.raises(type(exc)),
    ):
        await execute_trade(dict(_ORDER))
