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

"""Evaluator tools answer typed MCP failures with their ERROR results (#514)."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.gateway.infrastructure.mcp_client import (
    MCPToolExecutionError,
    MCPToolOutcomeUnknownError,
)
from src.governed_financial_advisor.agents.evaluator import agent as evaluator_agent

pytestmark = [pytest.mark.unit, pytest.mark.local]


def _use_client(monkeypatch: pytest.MonkeyPatch, failure: Exception) -> AsyncMock:
    call_tool = AsyncMock(side_effect=failure)
    client = MagicMock()
    client.call_tool = call_tool
    monkeypatch.setattr(evaluator_agent, "get_mcp_client", lambda: client)
    return call_tool


def _unknown(tool: str) -> MCPToolOutcomeUnknownError:
    return MCPToolOutcomeUnknownError(tool, f"MCP tool {tool!r} may have run")


@pytest.mark.asyncio
async def test_market_status_tool_error(monkeypatch: pytest.MonkeyPatch) -> None:
    _use_client(monkeypatch, MCPToolExecutionError("check_market_status", "feed down"))

    result = await evaluator_agent.check_market_status("AAPL")

    assert result == "ERROR: Could not fetch market status: feed down"


@pytest.mark.asyncio
async def test_market_status_unknown_outcome(monkeypatch: pytest.MonkeyPatch) -> None:
    _use_client(monkeypatch, _unknown("check_market_status"))

    result = await evaluator_agent.check_market_status("AAPL")

    assert result.startswith("ERROR: Could not fetch market status:")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("failure", "message"),
    [
        (
            MCPToolExecutionError("simulate_governance_check", "governor offline"),
            "Gateway tool error: governor offline",
        ),
        (
            _unknown("simulate_governance_check"),
            str(_unknown("simulate_governance_check")),
        ),
    ],
    ids=["tool_error", "unknown_outcome"],
)
async def test_simulation_failure_is_an_error_verdict(
    monkeypatch: pytest.MonkeyPatch, failure: Exception, message: str
) -> None:
    _use_client(monkeypatch, failure)

    result: dict[str, Any] = await evaluator_agent.simulate_governance_check(
        "execute_trade", {"symbol": "AAPL", "amount": 10}
    )

    assert result == {
        "verdict": "ERROR",
        "message": message,
        "violations": ["System Error"],
    }


@pytest.mark.asyncio
async def test_intervention_refused_by_gateway(monkeypatch: pytest.MonkeyPatch) -> None:
    _use_client(
        monkeypatch,
        MCPToolExecutionError("trigger_safety_intervention", "Redis unavailable"),
    )

    result = await evaluator_agent.safety_intervention("drawdown breach")

    assert result == "ERROR: Intervention Failed: Redis unavailable"


@pytest.mark.asyncio
async def test_intervention_unknown_outcome_reports_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    call_tool = _use_client(monkeypatch, _unknown("trigger_safety_intervention"))

    result = await evaluator_agent.safety_intervention("drawdown breach")

    assert result.startswith("ERROR: Intervention Failed: outcome unknown")
    call_tool.assert_awaited_once()
