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

import asyncio
import logging
from typing import Any, Callable, Dict, List

from mcp import ClientSession, StdioServerParameters
from mcp.client.sse import sse_client

logger = logging.getLogger("Infrastructure.MCPClient")

class GatewayMCPClient:
    """
    Client for interacting with the Gateway's MCP Server via SSE.
    """
    def __init__(self, sse_url: str):
        self.sse_url = sse_url
        self.session: ClientSession | None = None
        self._exit_stack = None

    async def connect(self):
        """Connects to the Gateway MCP SSE endpoint."""
        logger.info(f"Connecting to Gateway MCP at {self.sse_url}...")
        from contextlib import AsyncExitStack
        self._exit_stack = AsyncExitStack()

        # Connect via SSE
        read_stream, write_stream = await self._exit_stack.enter_async_context(
            sse_client(self.sse_url)
        )
        
        self.session = await self._exit_stack.enter_async_context(
            ClientSession(read_stream, write_stream)
        )
        
        # --- MONKEY PATCH: Distributed Tracing for ALL callers (including LangChain Adapters) ---
        # Guard: skip if already patched to prevent double-wrapping on reconnect (ARCH-06).
        if getattr(self.session.call_tool, "_otel_patched", False):
            logger.debug("MCP ClientSession.call_tool already patched — skipping.")
        else:
            self._patch_call_tool()

        await self.session.initialize()
        logger.info("✅ Connected to Gateway MCP (distributed tracing enabled via ClientSession patch).")

    def _patch_call_tool(self) -> None:
        """Wraps ClientSession.call_tool with W3C traceparent injection exactly once."""
        original_call_tool = self.session.call_tool

        async def patched_call_tool(name: str, arguments: dict | None = None, **kwargs):
            from opentelemetry import trace
            from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

            # Inject W3C traceparent into arguments for distributed tracing
            carrier = {}
            TraceContextTextMapPropagator().inject(carrier)

            # Pass carrier into the special key that Gateway's patch_mcp_tools expects
            args = arguments or {}
            if "_otel_carrier" not in args:
                args["_otel_carrier"] = carrier

            return await original_call_tool(name, arguments=args, **kwargs)

        # Mark as patched before replacing to make the guard flag introspectable
        patched_call_tool._otel_patched = True
        self.session.call_tool = patched_call_tool

    async def list_tools(self) -> List[Any]:
        if not self.session:
            await self.connect()
        result = await self.session.list_tools()
        return result.tools

    async def call_tool(self, name: str, arguments: dict) -> Any:
        """
        Stateless per-call SSE connection.
        Opens a fresh SSE session for every tool call to avoid anyio
        cancel-scope reuse across asyncio event loops (test isolation).
        """
        logger.info(f"📞 Calling MCP Tool: {name}")

        from contextlib import AsyncExitStack
        from opentelemetry import trace

        tracer = trace.get_tracer(__name__)
        with tracer.start_as_current_span(f"mcp_tool:{name}") as span:
            span.set_attribute("langfuse.observation.type", "generation")
            span.set_attribute("gen_ai.operation.name", "tool_call")

            try:
                async with AsyncExitStack() as stack:
                    read_stream, write_stream = await stack.enter_async_context(
                        sse_client(self.sse_url)
                    )
                    session = await stack.enter_async_context(
                        ClientSession(read_stream, write_stream)
                    )
                    await session.initialize()
                    result = await session.call_tool(name, arguments)

                # Parse result (MCP returns a list of content objects)
                output = []
                if hasattr(result, 'content'):
                    for content in result.content:
                        if hasattr(content, 'text'):
                            output.append(content.text)

                final_output = "\n".join(output)
                span.set_attribute("langfuse.observation.output", final_output)
                return final_output
            except Exception as e:
                span.record_exception(e)
                raise


    async def close(self):
        if self._exit_stack:
            await self._exit_stack.aclose()
            logger.info("MCP Client Closed.")

# Singleton Instance
_mcp_client_instance = None

def get_mcp_client() -> GatewayMCPClient:
    global _mcp_client_instance
    if not _mcp_client_instance:
        from config.settings import Config
        # Ensure Config has MCP_SERVER_SSE_URL
        mcp_url = getattr(Config, "MCP_SERVER_SSE_URL", None)
        if not mcp_url:
            logger.warning("MCP_SSE_URL not set — MCP client will not connect to any server")
        _mcp_client_instance = GatewayMCPClient(mcp_url)
    return _mcp_client_instance

