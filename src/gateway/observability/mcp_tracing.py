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
the SSE transport gap and produces a seamless Telemetry waterfall.

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
from collections.abc import Mapping
from typing import Any

from opentelemetry import trace
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

from src.gateway.governance.governor.metrics import mark_request_refused
from src.gateway.governance.iso_control import stamp_iso_control
from src.gateway.governance.prompt_injection_detector import (
    detect_indirect_injection,
)
from src.gateway.observability.attributes import SPAN_ATTR_MCP_TOOL_RESULT_LENGTH

logger = logging.getLogger("Gateway.MCP.Tracing")
tracer = trace.get_tracer("mcp.server.tools")
propagator = TraceContextTextMapPropagator()

# CVE-2026-126360 / GHSA-mf5v-w3w3-f6cg defense-in-depth bounds on W3C Trace
# Context carriers (including JSON MCP `_otel_carrier` payloads that can carry
# embedded newlines and arbitrarily long strings).
MAX_TRACEPARENT_LENGTH = 512
MAX_TRACESTATE_LENGTH = 4096


def sanitize_trace_carrier(carrier: Any) -> dict[str, str]:
    """Filter an untrusted trace carrier to bounded, single-line string values."""
    if not isinstance(carrier, Mapping):
        return {}
    clean: dict[str, str] = {}
    for raw_key, raw_val in carrier.items():
        if not isinstance(raw_key, str) or not isinstance(raw_val, str):
            continue
        if "\r" in raw_val or "\n" in raw_val:
            continue
        key_lower = raw_key.lower()
        if key_lower == "traceparent" and len(raw_val) > MAX_TRACEPARENT_LENGTH:
            continue
        if key_lower == "tracestate" and len(raw_val) > MAX_TRACESTATE_LENGTH:
            continue
        clean[raw_key] = raw_val
    return clean


async def sanitize_mcp_tool_response(
    tool_name: str,
    response_text: Any,
    span: Any = None,
) -> str | None:
    """Sanitize an MCP tool response for indirect injection (AI 600-1 §2.3, AI600-003).

    Checks the tool response against ``detect_indirect_injection()`` using
    lightweight kernel imports (avoiding cold-importing FastAPI/middleware on
    the hot ``ToolManager.call_tool`` path) and skips ISO control stamping when
    *span* is non-recording.

    Returns:
        A violation description string if indirect injection was detected,
        ``None`` if the response is clean.
    """
    safe_text = (
        response_text
        if isinstance(response_text, str)
        else str(response_text if response_text is not None else "")
    )
    active_span = span
    if active_span is not None:
        is_rec = getattr(active_span, "is_recording", None)
        if callable(is_rec) and not is_rec():
            active_span = None
    result = detect_indirect_injection(tool_name, safe_text)
    if result.detected:
        stamp_iso_control(
            active_span, ingress_stage=2, control="A.9.2", outcome="BLOCK"
        )
        logger.warning(
            "🔴 [AI600-003] MCP tool response rejected: tool=%s pattern=%s "
            "(ISO 42001 A.9.2 — indirect injection blocked)",
            tool_name,
            result.pattern_matched,
        )
        return f"indirect_injection:{result.pattern_matched}"
    stamp_iso_control(active_span, ingress_stage=2, control="A.9.2", outcome="PASS")
    return None


def patch_mcp_tools(mcp_server) -> None:  # type: ignore[no-untyped-def]
    """
    Monkey-patches ToolManager.call_tool to extract the W3C traceparent
    from arguments (before Pydantic validation strips it) and wrap
    tool execution in a distributed OTel span.

    Call AFTER all tools are registered but BEFORE mounting the MCP app.
    """
    tool_manager = mcp_server._tool_manager
    original_call_tool = tool_manager.call_tool

    async def traced_call_tool(name, arguments, context=None, convert_result=False):  # type: ignore[no-untyped-def]
        # 1. Extract carrier BEFORE Pydantic validation strips it.
        # Create a shallow copy to avoid mutating the caller's dict.
        arguments = {**arguments} if isinstance(arguments, Mapping) else {}
        carrier = sanitize_trace_carrier(arguments.pop("_otel_carrier", None))
        otel_ctx = propagator.extract(carrier)

        # 2. Create a child span linked to the caller's trace
        with tracer.start_as_current_span(f"mcp.tool:{name}", context=otel_ctx) as span:
            # Tool arguments and results are content: only the tool name and
            # the result length go on the span.
            span.set_attribute("mcp.tool.name", name)

            # 3. Delegate to original (validates args, calls fn)
            result = await original_call_tool(
                name, arguments, context=context, convert_result=convert_result
            )

            # 4. Sanitize tool response against indirect prompt injection (AI 600-1 §2.3 / A.9.2)
            result_str = _extract_mcp_result_text(result)
            violation = await sanitize_mcp_tool_response(name, result_str, span=span)
            if violation is not None:
                mark_request_refused()
                span.set_attribute("mcp.tool.blocked_output", violation)
                span.set_attribute("mcp.tool.output_sanitized_after_execution", True)
                raise PermissionError(
                    f"MCP tool response blocked by indirect prompt-injection guard ({violation})"
                )

            # 5. Record the result size only — never raw content (#774)
            span.set_attribute(SPAN_ATTR_MCP_TOOL_RESULT_LENGTH, len(result_str))
            return result

    # Replace the method on the instance
    tool_manager.call_tool = traced_call_tool

    tool_count = len(tool_manager.list_tools())
    logger.info(
        f"✅ Patched ToolManager.call_tool with distributed tracing "
        f"({tool_count} tools covered)"
    )


def _extract_mcp_result_text(result: Any) -> str:
    """Extract scannable text from raw or FastMCP-converted tool outputs."""
    if isinstance(result, str):
        return result
    if isinstance(result, dict):
        return json.dumps(result, default=str)
    content_attr = getattr(result, "content", None)
    structured_attr = getattr(result, "structuredContent", None)
    if isinstance(content_attr, (list, tuple)) or isinstance(structured_attr, dict):
        extracted_parts: list[str] = []
        if isinstance(content_attr, (list, tuple)):
            extracted_parts.append(_extract_mcp_result_text(content_attr))
        if isinstance(structured_attr, dict):
            extracted_parts.append(json.dumps(structured_attr, default=str))
        return "\n".join(p for p in extracted_parts if p)
    if isinstance(result, (list, tuple)):
        parts: list[str] = []
        for item in result:
            text_attr = getattr(item, "text", None)
            if isinstance(text_attr, str):
                parts.append(text_attr)
            elif isinstance(item, (list, tuple, dict)):
                parts.append(_extract_mcp_result_text(item))
            elif item is not None:
                parts.append(str(item))
        return "\n".join(parts)
    return str(result)
