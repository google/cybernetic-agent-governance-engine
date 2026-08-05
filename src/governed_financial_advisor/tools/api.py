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

from fastapi import APIRouter, Depends, HTTPException
from opentelemetry import trace as otel_trace
from opentelemetry.trace import Status, StatusCode
from pydantic import BaseModel

from src.gateway.governance.nemo.manager import load_rails, validate_with_nemo
from src.gateway.governance.singletons import opa_client, symbolic_governor
from src.governed_financial_advisor.graph.annotations import side_effect_node
from src.governed_financial_advisor.infrastructure.auth import require_api_key
from src.governed_financial_advisor.infrastructure.gateway_client import GatewayClient
from src.governed_financial_advisor.infrastructure.redis_client import redis_client
from src.governed_financial_advisor.tools.market_data_tool import get_market_data
from src.governed_financial_advisor.utils.routing_seal import (
    SymbolicGovernorViolation,
    verify_seal,
)

_tracer = otel_trace.get_tracer("gfa.tools")
_gateway_client = GatewayClient()

logger = logging.getLogger("ToolsRouter")

tools_router = APIRouter(prefix="/tools", tags=["tools"])

# Initialize Rails (Lazy load or use singleton if possible)
# In server.py, rails is initialized. We can try to import it or re-initialize.
# Re-initializing might be expensive. Best to share.
# For now, we'll load it here too or rely on caching.
_rails = None


def get_rails():
    global _rails
    if _rails is None:
        _rails = load_rails()
    return _rails


class ToolExecutionRequest(BaseModel):
    tool_name: str
    params: dict[str, Any]


@tools_router.post("/execute")
@side_effect_node(kind="api_call", external_system="gateway_api")
async def execute_tool_endpoint(
    request: ToolExecutionRequest,
    _auth: str = Depends(require_api_key),
):
    """
    Executes a named tool directly via HTTP.
    Matches the checks performed by GatewayClient.

    Each governed branch opens an explicit OTel root span (``cage.tool_execute``)
    so that ``symbolic_governor.govern()`` child spans (``cage.opa_pre_check``,
    ``cage.cbf_check``, ``cage.consensus_gate``, etc.) are attached to a live
    trace context and exported to Langfuse. Without the parent span, child spans
    are orphaned and silently dropped at the OTLP layer.
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
            output = get_market_data(symbol)  # Fallback to same tool

        elif tool in ("simulate_governance_check", "check_safety_constraints"):
            # "check_safety_constraints" kept as legacy alias — deprecated, use
            # "simulate_governance_check" for new callers.
            target_tool = params.get("target_tool")
            target_params = params.get("target_params") or {}
            # Call Symbolic Governor in sim (dry-run) mode — does NOT enforce
            result = await symbolic_governor.verify(target_tool, target_params)
            violations = (
                result.get("violations", []) if isinstance(result, dict) else []
            )
            if not violations:
                output = "APPROVED: No violations detected."
            else:
                output = f"REJECTED: {'; '.join(violations)}"

        elif tool == "trigger_safety_intervention":
            reason = params.get("reason", "Unknown")
            await redis_client.set("safety_violation", reason)
            output = "INTERVENTION_ACK: System Locked."

        elif tool == "verify_content_safety":
            # Open a root span so NeMo child spans are captured in Langfuse.
            with _tracer.start_as_current_span("cage.tool_execute") as span:
                span.set_attribute("cage.tool_name", "verify_content_safety")
                span.set_attribute("cage.governance", True)
                span.set_attribute("langfuse.observation.type", "span")
                span.set_attribute("langfuse.observation.name", "cage.tool_execute")
                text = params.get("text", "")
                is_safe, response, _deterministic = await validate_with_nemo(text, get_rails())
                if not is_safe:
                    span.set_attribute("cage.verdict", "BLOCKED")
                    output = f"BLOCKED: {response}"
                else:
                    span.set_attribute("cage.verdict", "SAFE")
                    output = "SAFE"

        elif tool == "evaluate_policy":
            # Open a root span to capture OPA child spans in Langfuse.
            with _tracer.start_as_current_span("cage.tool_execute") as span:
                span.set_attribute("cage.tool_name", "evaluate_policy")
                span.set_attribute("cage.governance", True)
                span.set_attribute("langfuse.observation.type", "span")
                span.set_attribute("langfuse.observation.name", "cage.tool_execute")
                span.set_attribute(
                    "langfuse.observation.input",
                    json.dumps(params)[:2000],
                )
                t0 = time.perf_counter()
                decision = await opa_client.evaluate_policy(params)
                latency_ms = (time.perf_counter() - t0) * 1000
                span.set_attribute("cage.opa_latency_ms", round(latency_ms, 2))
                span.set_attribute("cage.verdict", decision)
                span.set_attribute("langfuse.observation.output", decision)
                if decision == "ALLOW":
                    output = "APPROVED: Action matches policy."
                elif decision == "DENY":
                    output = "DENIED: Policy Violation."
                elif decision == "MANUAL_REVIEW":
                    output = "MANUAL_REVIEW: Requires human approval."
                else:
                    output = f"UNKNOWN: {decision}"

        elif tool == "execute_trade":
            # ── Option 2: Unified Gateway Governance Routing ──────────────────
            # All governance decisions (CBF + OPA) are delegated to the Hybrid
            # Gateway via POST /governance/validate-action.  The GFA no longer
            # calls OPA or the CBF engine directly — the Gateway is the Single
            # Choke Point.
            #
            # Trace continuity: the cage.tool_execute root span below is opened
            # FIRST so that when GatewayClient.validate_action() injects the
            # W3C 'traceparent' header, it carries the trace ID of this root span.
            # The Gateway extracts that header and attaches its cage.validate_action
            # + cage.cbf_action_check + cage.opa_action_check + cage.routing_seal
            # spans as children — producing one unified tree in Langfuse.
            import uuid

            from src.gateway.core.structs import TradeOrder
            from src.gateway.core.tools import execute_trade as core_execute_trade

            if "transaction_id" not in params:
                params["transaction_id"] = str(uuid.uuid4())

            order = TradeOrder(**params)

            with _tracer.start_as_current_span("cage.tool_execute") as root_span:
                root_span.set_attribute("cage.tool_name", "execute_trade")
                root_span.set_attribute("cage.governance", True)
                root_span.set_attribute("cage.symbol", params.get("symbol", ""))
                root_span.set_attribute("cage.amount", float(params.get("amount", 0)))
                root_span.set_attribute(
                    "cage.confidence", float(params.get("confidence", 0))
                )
                root_span.set_attribute("langfuse.observation.type", "span")
                root_span.set_attribute(
                    "langfuse.observation.name", "cage.tool_execute"
                )
                root_span.set_attribute(
                    "langfuse.observation.input",
                    json.dumps(
                        {
                            "symbol": params.get("symbol"),
                            "amount": params.get("amount"),
                            "confidence": params.get("confidence"),
                            "currency": params.get("currency"),
                        }
                    ),
                )

                t0 = time.perf_counter()

                # ── Governance via Unified Gateway (W3C traceparent propagated) ──
                gov_result = await _gateway_client.validate_action(
                    "execute_trade", params
                )
                seal = gov_result.get("seal", "")
                gov_ms = (time.perf_counter() - t0) * 1000
                root_span.set_attribute("cage.governance_latency_ms", round(gov_ms, 2))
                root_span.set_attribute(
                    "cage.gateway_verdict", gov_result.get("verdict", "")
                )

                # ── Verify routing seal before actuation ─────────────────────
                # verify_seal() raises SymbolicGovernorViolation on any failure —
                # no need to check the return value. This is the defense-in-depth
                # check (P3 fix); the wrapped actuation is never reached if the
                # seal is invalid.
                try:
                    verify_seal(seal, "execute_trade", params)
                except SymbolicGovernorViolation as exc:
                    root_span.set_attribute("cage.seal_valid", False)
                    root_span.set_status(Status(StatusCode.ERROR))
                    raise PermissionError(
                        "Routing seal invalid or expired — trade blocked "
                        f"(defense-in-depth): {exc.reason}"
                    ) from exc

                root_span.set_attribute("cage.seal_valid", True)

                # ── Actuate ───────────────────────────────────────────────────
                t1 = time.perf_counter()
                output = await core_execute_trade(order)
                exec_ms = (time.perf_counter() - t1) * 1000
                root_span.set_attribute("cage.execution_latency_ms", round(exec_ms, 2))
                root_span.set_attribute(
                    "cage.total_latency_ms", round(gov_ms + exec_ms, 2)
                )
                root_span.set_attribute(
                    "langfuse.observation.output", str(output)[:500]
                )
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
