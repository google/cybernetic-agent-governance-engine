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

"""Unit and multi-replica tests for stateless MCP Streamable HTTP transport (PR A3)."""

from __future__ import annotations

import asyncio
from contextlib import AsyncExitStack, asynccontextmanager
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from fastapi import FastAPI
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

from src.gateway.infrastructure.mcp_client import (
    GatewayMCPClient,
    _normalize_mcp_url,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]


def _build_stateless_replica_app(replica_id: str) -> tuple[FastAPI, FastMCP, list[str]]:
    """Build an independent FastAPI replica mounting a stateless FastMCP server at /mcp."""
    handled_requests: list[str] = []
    mcp_server = FastMCP(
        f"CAGE Governed Gateway ({replica_id})",
        stateless_http=True,
        json_response=True,
        streamable_http_path="/",
        transport_security=TransportSecuritySettings(
            allowed_hosts=["127.0.0.1:*", "localhost:*", "gateway:*"]
        ),
    )

    @mcp_server.tool()
    async def echo_governed(action: str, seq: int = 0) -> str:
        handled_requests.append(f"{action}:{seq}")
        return f"REPLICA={replica_id}:ACTION={action}:SEQ={seq}"

    @asynccontextmanager
    async def _lifespan(_app: FastAPI):
        if (
            getattr(mcp_server.session_manager, "_has_started", False)
            and getattr(mcp_server.session_manager, "_task_group", None) is None
        ):
            mcp_server.session_manager._has_started = False
        async with mcp_server.session_manager.run():
            yield

    app = FastAPI(lifespan=_lifespan)
    app.mount("/mcp", mcp_server.streamable_http_app())
    return app, mcp_server, handled_requests


class _RoundRobinASGITransport(httpx.AsyncBaseTransport):
    """Round-robin HTTP transport distributing each request across N independent ASGI replicas."""

    def __init__(self, apps: list[FastAPI]) -> None:
        self._transports = [httpx.ASGITransport(app=app) for app in apps]
        self._counter = 0

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        idx = self._counter % len(self._transports)
        self._counter += 1
        return await self._transports[idx].handle_async_request(request)


def test_normalize_mcp_url_converts_legacy_sse_and_bare_paths() -> None:
    assert (
        _normalize_mcp_url("http://gateway:8080/mcp/sse") == "http://gateway:8080/mcp/"
    )
    assert _normalize_mcp_url("http://gateway:8080/mcp") == "http://gateway:8080/mcp/"
    assert _normalize_mcp_url("http://gateway:8080/mcp/") == "http://gateway:8080/mcp/"


@pytest.mark.asyncio
async def test_two_stateless_replicas_round_robin_100_tool_calls_zero_404() -> None:
    """Two independent stateless MCP replicas behind a round-robin transport serve 100 calls with 0 session errors."""
    app_a, mcp_a, log_a = _build_stateless_replica_app("replica-a")
    app_b, mcp_b, log_b = _build_stateless_replica_app("replica-b")

    rr_transport = _RoundRobinASGITransport([app_a, app_b])
    client = GatewayMCPClient(
        "http://gateway:8080/mcp/",
        http_transport=rr_transport,
        tools_cache_ttl_s=300.0,
    )

    async with AsyncExitStack() as stack:
        await stack.enter_async_context(mcp_a.session_manager.run())
        await stack.enter_async_context(mcp_b.session_manager.run())

        tools = await client.list_tools()
        assert [t.name for t in tools] == ["echo_governed"]

        replicas_seen: set[str] = set()
        for seq in range(100):
            out = await client.call_tool(
                "echo_governed", {"action": "execute_trade", "seq": seq}
            )
            assert f"ACTION=execute_trade:SEQ={seq}" in out
            if "REPLICA=replica-a" in out:
                replicas_seen.add("replica-a")
            elif "REPLICA=replica-b" in out:
                replicas_seen.add("replica-b")

        await client.close()

    # Both replicas handled traffic and all 100 tool calls succeeded without 404 session errors
    assert replicas_seen == {"replica-a", "replica-b"}
    assert len(log_a) + len(log_b) == 100
    assert len(log_a) >= 40
    assert len(log_b) >= 40


@pytest.mark.asyncio
async def test_ensure_connected_serializes_concurrent_initializations() -> None:
    """Concurrent callers of ensure_connected() share a single session initialization."""
    app_a, mcp_a, _ = _build_stateless_replica_app("replica-a")
    transport = httpx.ASGITransport(app=app_a)
    client = GatewayMCPClient("http://gateway:8080/mcp/", http_transport=transport)

    open_count = 0
    orig_open = client._open_session_unlocked

    async def counted_open() -> Any:
        nonlocal open_count
        open_count += 1
        await asyncio.sleep(0.01)
        return await orig_open()

    client._open_session_unlocked = counted_open  # type: ignore[method-assign]

    async with mcp_a.session_manager.run():
        sessions = await asyncio.gather(*(client.ensure_connected() for _ in range(16)))
        assert open_count == 1
        assert len({id(s) for s in sessions}) == 1
        await client.close()


@pytest.mark.asyncio
async def test_connect_retries_with_backoff_on_transient_failure() -> None:
    """connect() retries transient initialization failures with exponential backoff."""
    app_a, mcp_a, _ = _build_stateless_replica_app("replica-a")
    transport = httpx.ASGITransport(app=app_a)
    client = GatewayMCPClient("http://gateway:8080/mcp/", http_transport=transport)

    attempts = 0
    orig_open = client._open_session_unlocked

    async def flaky_open() -> Any:
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise httpx.ConnectError("transient network error")
        return await orig_open()

    client._open_session_unlocked = flaky_open  # type: ignore[method-assign]

    async with mcp_a.session_manager.run():
        session = await client.connect()
        assert session is not None
        assert attempts == 3
        await client.close()


@pytest.mark.asyncio
async def test_tools_cache_ttl_avoids_repeated_rpc_and_refreshes_on_expiry() -> None:
    """list_tools() and get_tools() cache tool definitions for tools_cache_ttl_s."""
    app_a, mcp_a, _ = _build_stateless_replica_app("replica-a")
    transport = httpx.ASGITransport(app=app_a)
    client = GatewayMCPClient(
        "http://gateway:8080/mcp/",
        http_transport=transport,
        tools_cache_ttl_s=300.0,
    )

    async with mcp_a.session_manager.run():
        await client.ensure_connected()
        assert client.session is not None

        list_calls = 0
        orig_list_tools = client.session.list_tools

        async def counted_list_tools(*args: Any, **kwargs: Any) -> Any:
            nonlocal list_calls
            list_calls += 1
            return await orig_list_tools(*args, **kwargs)

        client.session.list_tools = counted_list_tools  # type: ignore[method-assign]

        t1 = await client.list_tools()
        t2 = await client.list_tools()
        assert len(t1) == 1
        assert len(t2) == 1
        assert list_calls == 1

        # Force refresh bypasses the TTL cache
        t3 = await client.list_tools(force_refresh=True)
        assert len(t3) == 1
        assert list_calls == 2

        # get_tools() caches LangChain tool wrappers across calls
        fake_lc_tool = MagicMock(name="lc_echo_governed")
        with patch(
            "langchain_mcp_adapters.tools.load_mcp_tools",
            new=AsyncMock(return_value=[fake_lc_tool]),
        ) as mock_load:
            lc1 = await client.get_tools()
            lc2 = await client.get_tools()
            assert lc1 == [fake_lc_tool]
            assert lc2 == [fake_lc_tool]
            assert mock_load.await_count == 1

        await client.close()


@pytest.mark.asyncio
async def test_session_manager_can_restart_across_multiple_lifespans() -> None:
    """Restarting the FastAPI lifespan resets _has_started when _task_group is None."""
    app_a, _mcp_a, _ = _build_stateless_replica_app("replica-a")
    transport = httpx.ASGITransport(app=app_a)

    for run_idx in range(2):
        async with app_a.router.lifespan_context(app_a):
            client = GatewayMCPClient(
                "http://gateway:8080/mcp/", http_transport=transport
            )
            out = await client.call_tool(
                "echo_governed", {"action": "restarted", "seq": run_idx}
            )
            assert f"ACTION=restarted:SEQ={run_idx}" in out
            await client.close()


def test_ensure_connected_reconnects_across_distinct_event_loops() -> None:
    """When GatewayMCPClient is reused across two distinct event loops, ensure_connected() discards the stale session and opens a fresh one."""
    app_a, mcp_a, _ = _build_stateless_replica_app("replica-a")
    transport = httpx.ASGITransport(app=app_a)
    client = GatewayMCPClient("http://gateway:8080/mcp/", http_transport=transport)

    async def _run_on_loop_1() -> tuple[Any, str]:
        if (
            getattr(mcp_a.session_manager, "_has_started", False)
            and getattr(mcp_a.session_manager, "_task_group", None) is None
        ):
            mcp_a.session_manager._has_started = False
        async with mcp_a.session_manager.run():
            session = await client.ensure_connected()
            out = await client.call_tool(
                "echo_governed", {"action": "cross_loop", "seq": 1}
            )
            await client.close()
            # Simulate an unclosed singleton from loop1 still holding a stale session reference
            client.session = session
            return session, out

    async def _run_on_loop_2() -> tuple[Any, str]:
        if (
            getattr(mcp_a.session_manager, "_has_started", False)
            and getattr(mcp_a.session_manager, "_task_group", None) is None
        ):
            mcp_a.session_manager._has_started = False
        async with mcp_a.session_manager.run():
            session = await client.ensure_connected()
            out = await client.call_tool(
                "echo_governed", {"action": "cross_loop", "seq": 2}
            )
            await client.close()
            return session, out

    loop1 = asyncio.new_event_loop()
    try:
        sess_1, out_1 = loop1.run_until_complete(_run_on_loop_1())
    finally:
        loop1.close()

    assert client.session is sess_1

    loop2 = asyncio.new_event_loop()
    try:
        sess_2, out_2 = loop2.run_until_complete(_run_on_loop_2())
    finally:
        loop2.close()

    assert "ACTION=cross_loop:SEQ=1" in out_1
    assert "ACTION=cross_loop:SEQ=2" in out_2
    assert sess_1 is not sess_2
