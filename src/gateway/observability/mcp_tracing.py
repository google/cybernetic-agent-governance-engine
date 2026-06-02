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
MCP Distributed Tracing: W3C Trace Context Propagation

Extracts W3C traceparent from incoming MCP tool call arguments
and creates child spans linked to the caller's trace. This bridges
the SSE transport gap and produces a seamless Langfuse waterfall.

Client Side: GatewayMCPClient injects {'_otel_carrier': {traceparent: ...}}
Server Side: This module extracts it at the ToolManager level (before
             Pydantic validation strips it), rehydrates the OTel context,
             and wraps every tool execution with a traced span.

Architecture Note:
  The MCP SDK's Tool.run() validates arguments via a Pydantic model derived
  from the original function signature. Extra keys like _otel_carrier are
  silently dropped during model_validate(). Therefore, we MUST intercept
  at ToolManager.call_tool() — before validation — to extract the carrier.
"""

import json
import logging

from opentelemetry import trace
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

logger = logging.getLogger("Gateway.MCP.Tracing")
tracer = trace.get_tracer("mcp.server.tools")
propagator = TraceContextTextMapPropagator()


def patch_mcp_tools(mcp_server) -> None:
    """
    Monkey-patches ToolManager.call_tool to extract the W3C traceparent
    from arguments (before Pydantic validation strips it) and wrap
    tool execution in a distributed OTel span.

    Call AFTER all tools are registered but BEFORE mounting the MCP app.
    """
    tool_manager = mcp_server._tool_manager
    original_call_tool = tool_manager.call_tool

    async def traced_call_tool(name, arguments, context=None, convert_result=False):
        # 1. Extract carrier BEFORE Pydantic validation strips it
        carrier = arguments.pop("_otel_carrier", None) or {}
        otel_ctx = propagator.extract(carrier)

        # 2. Create a child span linked to the caller's trace
        with tracer.start_as_current_span(
            f"mcp.tool:{name}", context=otel_ctx
        ) as span:
            span.set_attribute("mcp.tool.name", name)
            span.set_attribute(
                "langfuse.observation.input",
                json.dumps({"tool": name, "args": _filter_args(arguments)})
            )

            # 3. Delegate to original (validates args, calls fn)
            result = await original_call_tool(
                name, arguments, context=context, convert_result=convert_result
            )

            # 4. Record output
            result_str = str(result)
            span.set_attribute("mcp.tool.result_length", len(result_str))
            span.set_attribute(
                "langfuse.observation.output", result_str[:4096]
            )
            return result

    # Replace the method on the instance
    tool_manager.call_tool = traced_call_tool

    tool_count = len(tool_manager.list_tools())
    logger.info(
        f"✅ Patched ToolManager.call_tool with distributed tracing "
        f"({tool_count} tools covered)"
    )


def _filter_args(kwargs: dict) -> dict:
    """Remove internal keys from args for cleaner logging."""
    return {k: v for k, v in kwargs.items() if not k.startswith("_")}
