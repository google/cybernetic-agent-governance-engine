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

import json
import logging
import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from opentelemetry import trace as otel_trace
from opentelemetry.trace import Status, StatusCode
from pydantic import BaseModel

from src.cage_finance.models.trade_order import TradeOrder
from src.gateway.governance.langgraph_harness.nemo_node_factory import get_nemo_rails
from src.gateway.observability.attributes import (
    OBSERVATION_INPUT,
    OBSERVATION_NAME,
    OBSERVATION_OUTPUT,
    OBSERVATION_TYPE,
)
from src.governed_financial_advisor.graph.annotations import side_effect_node
from src.governed_financial_advisor.infrastructure.auth import require_api_key
from src.governed_financial_advisor.infrastructure.gateway_client import GatewayClient
from src.governed_financial_advisor.infrastructure.redis_client import redis_client
from src.governed_financial_advisor.tools.market_data_tool import get_market_data
from src.integrations.nemo.manager import validate_with_nemo

_tracer = otel_trace.get_tracer("gfa.tools")
_gateway_client = GatewayClient()

logger = logging.getLogger("ToolsRouter")


async def _gateway_tool(tool_name: str, params: dict[str, Any]) -> str:
    """Run a governed tool in the gateway and return its output string.

    Raises:
        RuntimeError: If the gateway reports a tool error, so the endpoint
            returns ``status: ERROR`` instead of a fabricated result.
    """
    result = await _gateway_client.execute_tool(tool_name, params)
    if result.get("status") != "SUCCESS":
        raise RuntimeError(f"gateway tool {tool_name} failed: {result.get('error')}")
    return str(result.get("output", ""))


tools_router = APIRouter(prefix="/tools", tags=["tools"])


class ToolExecutionRequest(BaseModel):
    tool_name: str
    params: dict[str, Any]


@tools_router.post("/execute")
@side_effect_node(kind="api_call", external_system="gateway_api")
async def execute_tool_endpoint(  # type: ignore[no-untyped-def]
    request: ToolExecutionRequest,
    http_request: Request,
    _auth: str = Depends(require_api_key),
):
    """
    Executes a named tool directly via HTTP.

    Governed tools (``simulate_governance_check``, ``evaluate_policy``,
    ``execute_trade``) are forwarded to the gateway, which hosts the only
    ``SymbolicGovernor``, OPA client and ``ActuatorRegistry`` (POAM-2026-079).
    The ``execute_trade`` branch opens an OTel root span (``cage.tool_execute``)
    whose W3C context ``GatewayClient`` propagates, so the gateway's governance
    spans attach to one trace in Langfuse.
    """
    logger.info(f"Tool Execution Request: {request.tool_name}")

    try:
        output = None
        tool = request.tool_name
        params = request.params

        # --- Dispatcher ---

        if tool == "check_market_status":
            symbol = params.get("symbol")
            if not symbol:
                raise ValueError("Missing 'symbol' parameter")
            output = get_market_data(symbol)

        elif tool == "get_market_sentiment":
            # Reuse get_market_data for now as it includes news
            symbol = params.get("symbol")
            output = get_market_data(symbol)  # type: ignore[arg-type]  # Fallback to same tool

        elif tool == "simulate_governance_check":
            # Dry-run preview runs in the gateway's governor (POAM-2026-079):
            # the advisor hosts no kernel and holds no signing identity.
            output = await _gateway_tool(
                "simulate_governance_check",
                {
                    "target_tool": params.get("target_tool"),
                    "target_params": params.get("target_params") or {},
                },
            )

        elif tool == "trigger_safety_intervention":
            reason = params.get("reason", "Unknown")
            await redis_client.set("safety_violation", reason)
            output = "INTERVENTION_ACK: System Locked."

        elif tool == "verify_content_safety":
            # Open a root span so NeMo child spans are captured in Langfuse.
            with _tracer.start_as_current_span("cage.tool_execute") as span:
                span.set_attribute("cage.tool_name", "verify_content_safety")
                span.set_attribute("cage.governance", True)
                span.set_attribute(OBSERVATION_TYPE, "span")
                span.set_attribute(OBSERVATION_NAME, "cage.tool_execute")
                text = params.get("text", "")
                is_safe, response, _deterministic = await validate_with_nemo(
                    text, get_nemo_rails()
                )
                if not is_safe:
                    span.set_attribute("cage.verdict", "BLOCKED")
                    output = f"BLOCKED: {response}"
                else:
                    span.set_attribute("cage.verdict", "SAFE")
                    output = "SAFE"

        elif tool == "evaluate_policy":
            # OPA evaluation runs against the gateway's OPA client.
            output = await _gateway_tool("evaluate_policy", params)

        elif tool == "execute_trade":
            # Validate the order shape locally, then hand the whole governed
            # execution to the gateway's execute_trade_action tool: governor
            # pipeline, seal issue/consume and ActuatorRegistry dispatch all
            # happen in the gateway process (ADR-008, POAM-2026-079).
            order = TradeOrder(**params)
            with _tracer.start_as_current_span("cage.tool_execute") as root_span:
                root_span.set_attribute("cage.tool_name", "execute_trade")
                root_span.set_attribute("cage.governance", True)
                root_span.set_attribute("cage.symbol", order.symbol)
                root_span.set_attribute(OBSERVATION_TYPE, "span")
                root_span.set_attribute(OBSERVATION_NAME, "cage.tool_execute")
                root_span.set_attribute(
                    OBSERVATION_INPUT,
                    json.dumps(
                        {
                            "symbol": order.symbol,
                            "amount": order.amount,
                            "confidence": order.confidence,
                            "currency": order.currency,
                        }
                    ),
                )
                t0 = time.perf_counter()
                output = await _gateway_tool(
                    "execute_trade_action",
                    {
                        "symbol": order.symbol,
                        "amount": order.amount,
                        "currency": order.currency,
                        "confidence": order.confidence,
                        "transaction_id": order.transaction_id,
                        "trader_id": order.trader_id or "agent_001",
                        "trader_role": order.trader_role or "junior",
                    },
                )
                root_span.set_attribute(
                    "cage.total_latency_ms",
                    round((time.perf_counter() - t0) * 1000, 2),
                )
                root_span.set_attribute(OBSERVATION_OUTPUT, str(output)[:500])
                if not str(output).startswith("EXECUTED"):
                    root_span.set_status(Status(StatusCode.ERROR))
                else:
                    root_span.set_status(Status(StatusCode.OK))

        else:
            raise HTTPException(status_code=404, detail=f"Tool '{tool}' not found")

        return {"status": "SUCCESS", "output": str(output)}

    except Exception as e:
        logger.error(
            "Tool Execution Error [%s]: %s",
            type(e).__name__,
            e,
            exc_info=True,
        )
        return {"status": "ERROR", "error": f"{type(e).__name__}: {e}"}
