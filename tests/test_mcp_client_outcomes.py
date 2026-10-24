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

"""``GatewayMCPClient.call_tool`` never resends a request with an unknown outcome (#514).

The sessions are scripted fakes: each test decides whether the connect phase
fails (nothing was sent) or ``session.call_tool`` fails (the request may have
reached the gateway), and counts how many times the tool was invoked.
"""

from __future__ import annotations

import asyncio
from typing import Any

import anyio
import httpx
import pytest
from mcp import types
from mcp.shared.exceptions import McpError

from src.gateway.infrastructure import mcp_client as mcp_client_module
from src.gateway.infrastructure.mcp_client import (
    GatewayMCPClient,
    MCPToolExecutionError,
    MCPToolOutcomeUnknownError,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

_TRADE = "execute_trade_action"
_READ_ONLY = "check_market_status"
_IDEMPOTENT = "trigger_safety_intervention"
_UNANNOTATED = "unannotated_tool"
_UNLISTED = "unlisted_tool"

_TOOLS = [
    types.Tool(
        name=_TRADE,
        inputSchema={"type": "object"},
        annotations=types.ToolAnnotations(
            readOnlyHint=False, destructiveHint=True, idempotentHint=False
        ),
    ),
    types.Tool(
        name=_READ_ONLY,
        inputSchema={"type": "object"},
        annotations=types.ToolAnnotations(readOnlyHint=True, idempotentHint=True),
    ),
    types.Tool(
        name=_IDEMPOTENT,
        inputSchema={"type": "object"},
        annotations=types.ToolAnnotations(readOnlyHint=False, idempotentHint=True),
    ),
    types.Tool(name=_UNANNOTATED, inputSchema={"type": "object"}),
]


def _connection_closed() -> McpError:
    return McpError(
        types.ErrorData(code=types.CONNECTION_CLOSED, message="Connection closed")
    )


def _result(text: str, *, is_error: bool = False) -> types.CallToolResult:
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=text)], isError=is_error
    )


class _FakeSession:
    """Stands in for ``ClientSession``: scripted ``call_tool`` outcomes."""

    def __init__(self, client: _ScriptedClient) -> None:
        self._client = client
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def call_tool(
        self, name: str, arguments: dict[str, Any] | None = None, **_: Any
    ) -> types.CallToolResult:
        self.calls.append((name, dict(arguments or {})))
        outcome = self._client.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    async def list_tools(self) -> types.ListToolsResult:
        self._client.list_calls += 1
        if self._client.tools_listing_fails:
            raise httpx.ConnectError("tools/list unavailable")
        return types.ListToolsResult(tools=list(_TOOLS))


class _ScriptedClient(GatewayMCPClient):
    """A ``GatewayMCPClient`` whose connect phase opens scripted fake sessions."""

    def __init__(
        self,
        outcomes: list[Any],
        *,
        connect_failures: int = 0,
        tools_listing_fails: bool = False,
    ) -> None:
        super().__init__("http://gateway:8080/mcp/")
        self.outcomes = list(outcomes)
        self.connect_failures = connect_failures
        self.tools_listing_fails = tools_listing_fails
        self.list_calls = 0
        self.sessions: list[_FakeSession] = []

    async def _open_session_unlocked(self) -> Any:
        await self._reset_unlocked()
        if self.connect_failures:
            self.connect_failures -= 1
            raise httpx.ConnectError("gateway unreachable")
        session = _FakeSession(self)
        self.sessions.append(session)
        self.session = session  # type: ignore[assignment]
        return session

    @property
    def invocations(self) -> list[tuple[str, dict[str, Any]]]:
        return [call for session in self.sessions for call in session.calls]


@pytest.fixture(autouse=True)
def _no_connect_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mcp_client_module, "_CONNECT_BASE_BACKOFF_S", 0.0)


@pytest.mark.asyncio
@pytest.mark.parametrize("tool", [_TRADE, _UNANNOTATED, _UNLISTED])
@pytest.mark.parametrize(
    "failure",
    [_connection_closed(), httpx.ReadTimeout("read timed out"), TimeoutError("slow")],
    ids=["connection_closed", "read_timeout", "timeout"],
)
async def test_failure_after_send_is_not_resent(tool: str, failure: Exception) -> None:
    client = _ScriptedClient([failure, _result("EXECUTED: second run")])

    with pytest.raises(MCPToolOutcomeUnknownError) as excinfo:
        await client.call_tool(tool, {"transaction_id": "t-1"})

    assert client.invocations == [(tool, {"transaction_id": "t-1"})]
    assert excinfo.value.tool_name == tool
    assert excinfo.value.__cause__ is failure
    # The failed session is dropped so the next call reconnects first.
    assert client.session is not client.sessions[0]


@pytest.mark.asyncio
@pytest.mark.parametrize("tool", [_READ_ONLY, _IDEMPOTENT])
async def test_annotated_tool_is_resent_once(tool: str) -> None:
    client = _ScriptedClient([_connection_closed(), _result("OPEN")])

    assert await client.call_tool(tool, {"symbol": "AAPL"}) == "OPEN"

    assert client.invocations == [(tool, {"symbol": "AAPL"})] * 2
    assert len(client.sessions) == 2  # resent on a fresh session
    assert client.list_calls == 1  # annotations fetched once, then cached


@pytest.mark.asyncio
async def test_annotated_tool_is_resent_at_most_once() -> None:
    client = _ScriptedClient([_connection_closed(), httpx.ReadTimeout("again")])

    with pytest.raises(MCPToolOutcomeUnknownError):
        await client.call_tool(_READ_ONLY, {"symbol": "AAPL"})

    assert len(client.invocations) == 2


@pytest.mark.asyncio
async def test_unreadable_annotations_fail_closed() -> None:
    """Without the gateway's annotations even a read-only tool is not resent."""
    client = _ScriptedClient(
        [_connection_closed(), _result("OPEN")], tools_listing_fails=True
    )

    with pytest.raises(MCPToolOutcomeUnknownError):
        await client.call_tool(_READ_ONLY, {"symbol": "AAPL"})

    assert len(client.invocations) == 1


@pytest.mark.asyncio
async def test_is_error_raises_execution_error_without_resend() -> None:
    # A read-only tool would be eligible for a resend; a tool error never is.
    client = _ScriptedClient([_result("market feed down", is_error=True)])

    with pytest.raises(MCPToolExecutionError) as excinfo:
        await client.call_tool(_READ_ONLY, {"symbol": "AAPL"})

    assert excinfo.value.text == "market feed down"
    assert excinfo.value.tool_name == _READ_ONLY
    assert len(client.invocations) == 1


@pytest.mark.asyncio
async def test_connect_phase_failure_is_retried() -> None:
    # ensure_connected() makes three attempts; all three fail, so call_tool's
    # own retry is what reaches the gateway. Nothing was sent before that.
    client = _ScriptedClient(
        [_result("EXECUTED: AAPL x 10 (Receipt ID: r-1)")], connect_failures=3
    )

    result = await client.call_tool(_TRADE, {"transaction_id": "t-1"})

    assert result == "EXECUTED: AAPL x 10 (Receipt ID: r-1)"
    assert client.invocations == [(_TRADE, {"transaction_id": "t-1"})]


@pytest.mark.asyncio
async def test_connect_phase_failing_twice_raises_without_sending() -> None:
    client = _ScriptedClient([_result("unused")], connect_failures=6)

    with pytest.raises(httpx.ConnectError):
        await client.call_tool(_TRADE, {"transaction_id": "t-1"})

    assert client.invocations == []


@pytest.mark.asyncio
async def test_resent_call_failing_to_connect_reports_unknown_outcome() -> None:
    """Once a request may have reached the gateway, a later connect failure is still unknown."""
    client = _ScriptedClient([_connection_closed(), _result("OPEN")])
    # Warm the annotation cache so the resend's connect attempts are the only ones left.
    await client.list_tools()
    client.connect_failures = 3

    with pytest.raises(MCPToolOutcomeUnknownError) as excinfo:
        await client.call_tool(_READ_ONLY, {"symbol": "AAPL"})

    assert isinstance(excinfo.value.__cause__, httpx.ConnectError)
    assert len(client.invocations) == 1


@pytest.mark.asyncio
async def test_closed_transport_is_reestablished_before_sending() -> None:
    """A session whose transport closed is replaced before the request is sent."""
    client = _ScriptedClient([_result("EXECUTED: fresh session")])
    loop = asyncio.get_running_loop()
    client._bound_loop = loop
    client._connect_lock = asyncio.Lock()
    dead = _FakeSession(client)
    client.sessions.append(dead)
    client.session = dead  # type: ignore[assignment]
    send_stream, receive_stream = anyio.create_memory_object_stream[Any](0)
    client._write_stream = send_stream
    receive_stream.close()  # the transport's POST writer has exited

    result = await client.call_tool(_TRADE, {"transaction_id": "t-1"})

    assert result == "EXECUTED: fresh session"
    assert dead.calls == []
    assert client.invocations == [(_TRADE, {"transaction_id": "t-1"})]
    send_stream.close()


@pytest.mark.asyncio
async def test_success_joins_text_content() -> None:
    client = _ScriptedClient(
        [
            types.CallToolResult(
                content=[
                    types.TextContent(type="text", text="line 1"),
                    types.TextContent(type="text", text="line 2"),
                ]
            )
        ]
    )

    assert await client.call_tool(_READ_ONLY, {"symbol": "AAPL"}) == "line 1\nline 2"
    assert client.list_calls == 0  # no annotation lookup on the happy path
