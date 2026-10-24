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

"""The gateway's MCP ToolAnnotations decide what GatewayMCPClient may resend (#514)."""

from __future__ import annotations

import importlib
import sys
from unittest.mock import MagicMock

import httpx
import pytest
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

from src.cage_finance.tools.tool_provider import FinancialToolProvider
from src.gateway.infrastructure.mcp_client import GatewayMCPClient

pytestmark = [pytest.mark.unit, pytest.mark.local]


def _finance_server() -> FastMCP:
    server = FastMCP(
        "annotations-test",
        stateless_http=True,
        json_response=True,
        streamable_http_path="/",
        transport_security=TransportSecuritySettings(allowed_hosts=["gateway:*"]),
    )
    FinancialToolProvider().register_tools(server, MagicMock())
    return server


@pytest.mark.asyncio
async def test_trade_tool_is_destructive_and_idempotent() -> None:
    """Destructive, but the mandatory transaction_id makes a resend a replay."""
    tools = {t.name: t.annotations for t in await _finance_server().list_tools()}

    trade = tools["execute_trade_action"]
    assert trade is not None
    assert trade.readOnlyHint is False
    assert trade.destructiveHint is True
    assert trade.idempotentHint is True


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["check_market_status", "get_market_sentiment"])
async def test_market_tools_are_read_only(name: str) -> None:
    tools = {t.name: t.annotations for t in await _finance_server().list_tools()}

    assert tools[name] is not None
    assert tools[name].readOnlyHint is True
    assert tools[name].idempotentHint is True


def _gateway_mcp_server() -> FastMCP:
    """The real gateway FastMCP server, re-imported if a test left a stubbed module."""
    name = "src.gateway.server.mcp_tool_server"
    module = sys.modules.get(name)
    if module is None or not isinstance(getattr(module, "mcp", None), FastMCP):
        sys.modules.pop(name, None)
        module = importlib.import_module(name)
    return module.mcp


@pytest.mark.asyncio
async def test_gateway_tool_annotations() -> None:
    tools = {t.name: t.annotations for t in await _gateway_mcp_server().list_tools()}

    simulate = tools["simulate_governance_check"]
    assert simulate is not None
    assert simulate.readOnlyHint is True
    assert simulate.idempotentHint is True
    intervention = tools["trigger_safety_intervention"]
    assert intervention is not None
    assert intervention.readOnlyHint is False
    assert intervention.idempotentHint is True


@pytest.mark.asyncio
async def test_client_reads_the_annotations_over_mcp() -> None:
    """The hints survive tools/list, and the client resends only what they allow."""
    server = _finance_server()
    client = GatewayMCPClient(
        "http://gateway:8080/",
        http_transport=httpx.ASGITransport(app=server.streamable_http_app()),
    )

    async with server.session_manager.run():
        assert await client._is_retry_safe("check_market_status") is True
        assert await client._is_retry_safe("get_market_sentiment") is True
        assert await client._is_retry_safe("execute_trade_action") is True
        assert await client._is_retry_safe("no_such_tool") is False
        await client.close()
