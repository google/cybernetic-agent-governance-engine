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

from __future__ import annotations

import asyncio
import logging
import os
import time
from contextlib import AsyncExitStack
from typing import Any

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from src.gateway.observability.attributes import (
    OBSERVATION_OUTPUT,
    OBSERVATION_TYPE,
    SPAN_ATTR_GEN_AI_OPERATION_NAME,
)

logger = logging.getLogger("Infrastructure.MCPClient")

_DEFAULT_MCP_URL = "http://gateway:8080/mcp/"
_TOOLS_CACHE_TTL_S = float(os.getenv("CAGE_MCP_TOOLS_CACHE_TTL_S", "300"))
_CONNECT_MAX_ATTEMPTS = 3
_CONNECT_BASE_BACKOFF_S = 0.05


class MCPToolCallError(Exception):
    """A ``tools/call`` that produced no successful result."""

    def __init__(self, tool_name: str, message: str) -> None:
        super().__init__(message)
        self.tool_name = tool_name


class MCPToolOutcomeUnknownError(MCPToolCallError):
    """The request may have reached the gateway, but no result came back.

    The tool may or may not have run. :meth:`GatewayMCPClient.call_tool` does
    not resend it, so the caller must reconcile (for example, look the action
    up by its idempotency key) before deciding whether to submit it again.
    The transport error is chained as ``__cause__``.
    """


class MCPToolExecutionError(MCPToolCallError):
    """The gateway answered the call with a tool error (``CallToolResult.isError``)."""

    def __init__(self, tool_name: str, text: str) -> None:
        super().__init__(tool_name, f"MCP tool {tool_name!r} returned an error: {text}")
        self.text = text


def _result_text(result: Any) -> str:
    """Join the text blocks of a ``CallToolResult``."""
    return "\n".join(
        content.text
        for content in getattr(result, "content", None) or []
        if hasattr(content, "text")
    )


def _outcome_unknown_message(name: str, exc: Exception) -> str:
    return (
        f"MCP tool {name!r} may have run: the request was sent but no result "
        f"came back ({type(exc).__name__}: {exc}); reconcile before resubmitting"
    )


def _normalize_mcp_url(raw_url: str | None) -> str:
    """Normalize an MCP endpoint URL to the stateless Streamable HTTP path (``/mcp/``)."""
    url = (raw_url or "").strip()
    if not url:
        url = (
            os.getenv("GATEWAY_MCP_URL", "").strip()
            or os.getenv("MCP_SERVER_SSE_URL", "").strip()
            or _DEFAULT_MCP_URL
        )
    if url.endswith("/mcp/sse"):
        url = url[: -len("sse")]
    elif url.endswith("/mcp"):
        url = f"{url}/"
    return url


class GatewayMCPClient:
    """Client for interacting with the Gateway's stateless MCP Streamable HTTP server.

    Maintains one pooled ``httpx.AsyncClient`` and one long-lived ``ClientSession``
    over ``streamable_http_client(url, http_client=...)``, guarded by an asyncio
    lock with automatic reconnect on transport failure and a 300s tool-list cache.
    :meth:`call_tool` never resends a request that may have reached the gateway
    unless the gateway annotates the tool read-only or idempotent.
    """

    def __init__(
        self,
        mcp_url: str | None = None,
        *,
        tools_cache_ttl_s: float | None = None,
        http_transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.mcp_url = _normalize_mcp_url(mcp_url)
        # Keep sse_url as an alias for callers that inspect the attribute.
        self.sse_url = self.mcp_url
        self.session: ClientSession | None = None
        self._exit_stack: AsyncExitStack | None = None
        self._http_client: httpx.AsyncClient | None = None
        # The transport write stream the session sends its requests into.
        self._write_stream: Any | None = None
        self._http_transport = http_transport
        self._connect_lock: asyncio.Lock | None = None
        self._bound_loop: asyncio.AbstractEventLoop | None = None
        self._tools_cache_ttl_s = (
            tools_cache_ttl_s
            if tools_cache_ttl_s is not None
            else float(os.getenv("CAGE_MCP_TOOLS_CACHE_TTL_S", str(_TOOLS_CACHE_TTL_S)))
        )
        self._cached_mcp_tools: list[Any] | None = None
        self._cached_mcp_tools_at: float = 0.0
        self._cached_lc_tools: list[Any] | None = None
        self._cached_lc_tools_at: float = 0.0

    def _get_lock(self) -> asyncio.Lock:
        loop = asyncio.get_running_loop()
        if self._connect_lock is None or self._bound_loop is not loop:
            self.session = None
            self._exit_stack = None
            self._http_client = None
            self._write_stream = None
            self._cached_lc_tools = None
            self._cached_lc_tools_at = 0.0
            self._connect_lock = asyncio.Lock()
            self._bound_loop = loop
        return self._connect_lock

    def _build_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {}
        id2_token = os.environ.get("CAGE_GEAP_ID2_OIDC_TOKEN", "").strip()
        if id2_token:
            headers["Authorization"] = f"Bearer {id2_token}"
        return headers

    def _build_http_client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            headers=self._build_headers(),
            timeout=httpx.Timeout(30.0, connect=3.0, read=60.0),
            limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
            transport=self._http_transport,
            follow_redirects=True,
        )

    def _transport_open(self) -> bool:
        """Whether the session's transport still accepts requests.

        mcp's streamable HTTP transport closes its write stream when its POST
        writer exits, for example after a transport error. A request sent into
        that session would fail before reaching the gateway, so the session is
        treated as gone and re-established first.
        """
        stream = self._write_stream
        if stream is None:
            return True
        stats = stream.statistics()
        return stats.open_send_streams > 0 and stats.open_receive_streams > 0

    async def _reset_unlocked(self) -> None:
        self.session = None
        self._write_stream = None
        self._cached_lc_tools = None
        self._cached_lc_tools_at = 0.0
        stack = self._exit_stack
        self._exit_stack = None
        self._http_client = None
        if stack is not None:
            try:
                await stack.aclose()
            except Exception as exc:
                logger.debug("Ignoring error while closing stale MCP stack: %s", exc)

    async def _open_session_unlocked(self) -> ClientSession:
        await self._reset_unlocked()
        stack = AsyncExitStack()
        try:
            http_client = await stack.enter_async_context(self._build_http_client())
            (
                read_stream,
                write_stream,
                _get_session_id,
            ) = await stack.enter_async_context(
                streamable_http_client(
                    self.mcp_url,
                    http_client=http_client,
                    terminate_on_close=False,
                )
            )
            session = await stack.enter_async_context(
                ClientSession(read_stream, write_stream)
            )
            self._http_client = http_client
            self._exit_stack = stack
            self._write_stream = write_stream
            self.session = session

            if getattr(self.session.call_tool, "_otel_patched", False):
                logger.debug("MCP ClientSession.call_tool already patched — skipping.")
            else:
                self._patch_call_tool()

            await self.session.initialize()
            logger.info(
                "✅ Connected to Gateway MCP via stateless Streamable HTTP at %s",
                self.mcp_url,
            )
            return self.session
        except Exception:
            self.session = None
            self._http_client = None
            self._exit_stack = None
            self._write_stream = None
            try:
                await stack.aclose()
            except Exception as close_exc:
                logger.debug("Error closing failed MCP stack: %s", close_exc)
            raise

    async def connect(self) -> ClientSession:
        """Connect (or reconnect) to the Gateway stateless MCP Streamable HTTP endpoint."""
        lock = self._get_lock()
        async with lock:
            last_exc: Exception | None = None
            for attempt in range(1, _CONNECT_MAX_ATTEMPTS + 1):
                try:
                    return await self._open_session_unlocked()
                except Exception as exc:
                    last_exc = exc
                    if attempt < _CONNECT_MAX_ATTEMPTS:
                        backoff = _CONNECT_BASE_BACKOFF_S * (2 ** (attempt - 1))
                        logger.warning(
                            "MCP connect attempt %d/%d failed (%s); retrying in %.2fs",
                            attempt,
                            _CONNECT_MAX_ATTEMPTS,
                            exc,
                            backoff,
                        )
                        await asyncio.sleep(backoff)
            assert last_exc is not None
            raise last_exc

    async def ensure_connected(self) -> ClientSession:
        """Return the active ``ClientSession``, connecting under a lock if needed.

        A session whose transport is known to have closed is re-established
        first instead of being handed out.
        """
        loop = asyncio.get_running_loop()
        if (
            self.session is not None
            and self._bound_loop is loop
            and self._transport_open()
        ):
            return self.session
        lock = self._get_lock()
        async with lock:
            if (
                self.session is not None
                and self._bound_loop is loop
                and self._transport_open()
            ):
                return self.session
            last_exc: Exception | None = None
            for attempt in range(1, _CONNECT_MAX_ATTEMPTS + 1):
                try:
                    return await self._open_session_unlocked()
                except Exception as exc:
                    last_exc = exc
                    if attempt < _CONNECT_MAX_ATTEMPTS:
                        backoff = _CONNECT_BASE_BACKOFF_S * (2 ** (attempt - 1))
                        await asyncio.sleep(backoff)
            assert last_exc is not None
            raise last_exc

    def _patch_call_tool(self) -> None:
        """Wraps ClientSession.call_tool with W3C traceparent injection exactly once."""
        assert self.session is not None
        original_call_tool = self.session.call_tool

        async def patched_call_tool(
            name: str, arguments: dict[str, Any] | None = None, **kwargs: Any
        ) -> Any:
            from opentelemetry.trace.propagation.tracecontext import (
                TraceContextTextMapPropagator,
            )

            carrier: dict[str, str] = {}
            TraceContextTextMapPropagator().inject(carrier)

            args = dict(arguments) if arguments else {}
            if "_otel_carrier" not in args:
                args["_otel_carrier"] = carrier

            return await original_call_tool(name, arguments=args, **kwargs)

        patched_call_tool._otel_patched = True  # type: ignore[attr-defined]
        self.session.call_tool = patched_call_tool  # type: ignore[method-assign,assignment]

    async def list_tools(self, *, force_refresh: bool = False) -> list[Any]:
        """Return MCP tool definitions, cached for ``tools_cache_ttl_s`` (default 300s)."""
        now = time.monotonic()
        if (
            not force_refresh
            and self._cached_mcp_tools is not None
            and (now - self._cached_mcp_tools_at) < self._tools_cache_ttl_s
        ):
            return list(self._cached_mcp_tools)

        await self.ensure_connected()
        lock = self._get_lock()
        async with lock:
            now = time.monotonic()
            if (
                not force_refresh
                and self._cached_mcp_tools is not None
                and (now - self._cached_mcp_tools_at) < self._tools_cache_ttl_s
            ):
                return list(self._cached_mcp_tools)
            if self.session is None:
                await self._open_session_unlocked()
            assert self.session is not None
            try:
                result = await self.session.list_tools()
            except Exception:
                await self._open_session_unlocked()
                assert self.session is not None
                result = await self.session.list_tools()

            tools = list(result.tools)
            self._cached_mcp_tools = tools
            self._cached_mcp_tools_at = time.monotonic()
            return list(tools)

    async def get_tools(self, *, force_refresh: bool = False) -> list[Any]:
        """Return LangChain-adapted MCP tools, cached for ``tools_cache_ttl_s`` (300s)."""
        await self.ensure_connected()
        now = time.monotonic()
        if (
            not force_refresh
            and self._cached_lc_tools is not None
            and (now - self._cached_lc_tools_at) < self._tools_cache_ttl_s
        ):
            return list(self._cached_lc_tools)

        lock = self._get_lock()
        async with lock:
            now = time.monotonic()
            if (
                not force_refresh
                and self._cached_lc_tools is not None
                and (now - self._cached_lc_tools_at) < self._tools_cache_ttl_s
            ):
                return list(self._cached_lc_tools)
            if self.session is None:
                await self._open_session_unlocked()
            assert self.session is not None
            from langchain_mcp_adapters.tools import load_mcp_tools

            try:
                lc_tools = await load_mcp_tools(self.session)
            except Exception:
                await self._open_session_unlocked()
                assert self.session is not None
                lc_tools = await load_mcp_tools(self.session)

            self._cached_lc_tools = list(lc_tools)
            self._cached_lc_tools_at = time.monotonic()
            return list(self._cached_lc_tools)

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> str:
        """Invoke an MCP tool and return the text of its result.

        A request that may have reached the gateway is never sent twice unless
        the gateway's ``ToolAnnotations`` declare the tool ``readOnlyHint`` or
        ``idempotentHint``. The call is retried at most once:

        * a failure while (re)establishing the session happens before the
          request is sent, so it is retried;
        * a failure once the request was handed to the session leaves the
          outcome unknown: the session is discarded and, unless the tool is
          annotated read-only or idempotent, ``MCPToolOutcomeUnknownError`` is
          raised without a resend;
        * a result with ``isError`` set raises ``MCPToolExecutionError`` and is
          never retried.

        Raises:
            MCPToolOutcomeUnknownError: The request may have reached the
                gateway and no result came back; the caller must reconcile.
            MCPToolExecutionError: The gateway reported a tool error.
            Exception: The session could not be established on either
                attempt; the request was never sent.
        """
        logger.info("📞 Calling MCP Tool: %s", name)

        from opentelemetry import trace

        tracer = trace.get_tracer(__name__)
        with tracer.start_as_current_span(f"mcp_tool:{name}") as span:
            span.set_attribute(OBSERVATION_TYPE, "generation")
            span.set_attribute(SPAN_ATTR_GEN_AI_OPERATION_NAME, "tool_call")

            try:
                result = await self._call_tool_at_most_once(name, arguments)
                text = _result_text(result)
                if getattr(result, "isError", False):
                    raise MCPToolExecutionError(name, text)
                span.set_attribute(OBSERVATION_OUTPUT, text)
                return text
            except Exception as e:
                span.record_exception(e)
                raise

    async def _call_tool_at_most_once(
        self, name: str, arguments: dict[str, Any]
    ) -> Any:
        """Send ``tools/call``, retrying once only when a resend cannot duplicate it."""
        sent = False
        retried = False
        while True:
            try:
                session = await self.ensure_connected()
            except Exception as exc:
                if not retried:
                    retried = True
                    logger.warning(
                        "MCP session for %s could not be established (%s); "
                        "nothing was sent, retrying once",
                        name,
                        exc,
                    )
                    continue
                if sent:
                    raise MCPToolOutcomeUnknownError(
                        name, _outcome_unknown_message(name, exc)
                    ) from exc
                raise
            try:
                return await session.call_tool(name, arguments)
            except Exception as exc:
                sent = True
                await self._discard_session(session)
                if not retried and await self._is_retry_safe(name):
                    retried = True
                    logger.warning(
                        "MCP call_tool(%s) failed after sending (%s); the gateway "
                        "annotates it read-only or idempotent, retrying once",
                        name,
                        exc,
                    )
                    continue
                logger.error(
                    "MCP call_tool(%s) failed after sending (%s); outcome unknown, "
                    "not retrying",
                    name,
                    exc,
                )
                raise MCPToolOutcomeUnknownError(
                    name, _outcome_unknown_message(name, exc)
                ) from exc

    async def _discard_session(self, session: ClientSession) -> None:
        """Drop ``session`` after a failed call so the next call reconnects first."""
        lock = self._get_lock()
        async with lock:
            if self.session is session:
                await self._reset_unlocked()

    async def _is_retry_safe(self, name: str) -> bool:
        """Whether the gateway annotates ``name`` ``readOnlyHint`` or ``idempotentHint``.

        Reads the cached ``tools/list`` metadata, fetching it when it is not
        cached. An unlisted or unannotated tool, or a failed lookup, answers
        False, so a tool is resent only when the gateway declares it safe.
        """
        try:
            tools = await self.list_tools()
        except Exception as exc:
            logger.warning(
                "MCP tool annotations for %s unavailable (%s); not resending",
                name,
                exc,
            )
            return False
        for tool in tools:
            if getattr(tool, "name", None) != name:
                continue
            annotations = getattr(tool, "annotations", None)
            if annotations is None:
                return False
            return (
                annotations.readOnlyHint is True or annotations.idempotentHint is True
            )
        return False

    async def close(self) -> None:
        lock = self._get_lock()
        async with lock:
            await self._reset_unlocked()
            self._cached_mcp_tools = None
            self._cached_mcp_tools_at = 0.0
            logger.info("MCP Client Closed.")


# Singleton Instance
_mcp_client_instance: GatewayMCPClient | None = None


def get_mcp_client() -> GatewayMCPClient:
    global _mcp_client_instance
    if not _mcp_client_instance:
        from config.settings import Config

        mcp_url = getattr(Config, "GATEWAY_MCP_URL", None) or getattr(
            Config, "MCP_SERVER_SSE_URL", None
        )
        if not mcp_url:
            logger.warning(
                "GATEWAY_MCP_URL not set — MCP client will use default %s",
                _DEFAULT_MCP_URL,
            )
        _mcp_client_instance = GatewayMCPClient(mcp_url)
    return _mcp_client_instance
