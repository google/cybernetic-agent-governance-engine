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
MCP Tool Server (Phase 3.1)
============================
Dedicated to FastMCP tool registration (``@mcp.tool()``) and SSE transport.
Contains no HTTP proxy logic or REST endpoints.

This module is the single entry point for the headless governance engine's
MCP surface.  All tool calls are intercepted by ``mcp_tracing.patch_mcp_tools``
for W3C trace context propagation (Phase 5.2 — already implemented).

Phase 3.3: Routing seal enforcement is applied to every tool call via the
``_seal_tool_wrapper`` middleware injected into the FastMCP ToolManager.
"""

from __future__ import annotations

import asyncio
import collections
import inspect
import json
import logging
import math
import os
import sys
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import BaseModel, field_validator

sys.path.append(".")

from opentelemetry import trace

from src.gateway.core.tools import TradeOrder, execute_trade
from src.gateway.governance.nemo.manager import (
    initialize_rails,
    validate_with_nemo,
)
from src.gateway.governance.schemas.thresholds import load_and_validate_thresholds
from src.gateway.governance.singletons import opa_client, symbolic_governor
from src.gateway.observability.mcp_tracing import patch_mcp_tools
from src.gateway.server.governance_middleware import (
    enforce_governance,
    enforce_routing_seal,
)
from src.gateway.tracing_setup import setup_tracing
from src.governed_financial_advisor.infrastructure.config_manager import config_manager
from src.governed_financial_advisor.tools.market_data_tool import get_market_data

logger = logging.getLogger("Gateway.MCPToolServer")
tracer = trace.get_tracer("gateway.mcp_tool_server")

# ---------------------------------------------------------------------------
# M-20: Per-client sliding-window rate limiter
# Limits each client IP to _RATE_LIMIT_MAX_CALLS tool calls per
# _RATE_LIMIT_WINDOW_SECONDS. Uses an in-process deque; no Redis dependency.
# ---------------------------------------------------------------------------

_RATE_LIMIT_MAX_CALLS: int = int(os.getenv("MCP_RATE_LIMIT_MAX_CALLS", "60"))
_RATE_LIMIT_WINDOW_SECONDS: int = int(os.getenv("MCP_RATE_LIMIT_WINDOW_SECONDS", "60"))

# client_ip → deque of call timestamps (monotonic)
_rate_limit_buckets: dict[str, collections.deque] = {}
_rate_limit_lock = asyncio.Lock()


async def _check_rate_limit(client_ip: str) -> bool:
    """Return True if the request is within the rate limit, False if exceeded.

    Uses a sliding-window algorithm: timestamps older than the window are
    evicted before counting, so the limit is enforced over a rolling period.
    """
    now = time.monotonic()
    cutoff = now - _RATE_LIMIT_WINDOW_SECONDS
    async with _rate_limit_lock:
        bucket = _rate_limit_buckets.setdefault(client_ip, collections.deque())
        # Evict expired timestamps
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        if len(bucket) >= _RATE_LIMIT_MAX_CALLS:
            return False
        bucket.append(now)
        return True


# ---------------------------------------------------------------------------
# Startup validation and telemetry bootstrap
# ---------------------------------------------------------------------------


def _assert_required_plugins(loaded: list[Any]) -> None:
    # Phase 2.4: Domain package extraction - fail closed if no domain plugin loaded
    if not any(getattr(p, "name", "") == "finance" for p in loaded):
        logger.warning(
            "⚠️ No finance plugin loaded. Tools and domain tiers will be absent."
        )


@asynccontextmanager
async def lifespan(app: FastAPI):  # type: ignore[no-untyped-def]
    # 1. Tracing bootstrap (Phase 5.1)
    setup_tracing()

    # 2. Governance threshold validation (Phase 2.2) — aborts if schema invalid
    load_and_validate_thresholds()

    # 3. Env guards
    logger.info("🚀 CAGE MCP Tool Server Starting...")
    vllm_base = config_manager.get("VLLM_BASE_URL")
    if not vllm_base:
        raise RuntimeError(
            "VLLM_BASE_URL must be set — no localhost fallback in production."
        )
    vllm_api_key = config_manager.get("VLLM_API_KEY")
    if not vllm_api_key:
        raise RuntimeError(
            "VLLM_API_KEY must be set — no 'EMPTY' fallback in production."
        )

    # 4. Initialise NeMo rails and store on app state
    app.state.nemo_rails = initialize_rails()

    # 5. Start consensus background audit worker (Phase 4.4)
    from src.gateway.governance.consensus import _background_audit_worker

    audit_task = asyncio.create_task(_background_audit_worker())
    app.state.audit_task = audit_task

    # 6. Load domain plugins (D7)
    from src.gateway.governance.plugin_loader import discover_plugins

    loaded_plugins = discover_plugins()
    for plugin in loaded_plugins:
        # Pass the tool server for plugin tool registration
        plugin.register(governor=symbolic_governor, tool_server=mcp)
    _assert_required_plugins(loaded_plugins)
    
    # 7. Startup log for AU-12 evidence of active tier sequence (PR 4)
    active_tiers = symbolic_governor.registered_tier_names()
    logger.info(f"🛡️ Active governance tiers: {active_tiers}")

    yield

    # Shutdown
    logger.info("🛑 CAGE MCP Tool Server Shutting Down...")
    audit_task.cancel()
    try:
        await audit_task
    except asyncio.CancelledError:
        pass
    await opa_client.close()


# ---------------------------------------------------------------------------
# FastAPI + MCP
# ---------------------------------------------------------------------------

app = FastAPI(title="CAGE MCP Tool Server", lifespan=lifespan)

# OTel middleware
try:
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

    _SCANNER_NOISE_PREFIXES = (
        "/.git",
        "/.env",
        "/wp-admin",
        "/phpmyadmin",
        "/admin",
        "/actuator",
    )

    def _server_request_hook(span, scope):  # type: ignore[no-untyped-def]
        if not span or not span.is_recording():
            return
        method = scope.get("method", "").upper()
        path = scope.get("path", "")
        if method not in {"GET", "POST"} or path.lower().startswith(
            _SCANNER_NOISE_PREFIXES
        ):
            span.set_attribute("otel.drop", True)
            span.set_recording(False)
            return
        span.set_attribute("input", f"{method} {path}")
        span.update_name(f"{method} {path}")
        headers = {
            k.decode("utf-8").lower(): v.decode("utf-8")
            for k, v in scope.get("headers", [])
        }
        session_id = headers.get("x-session-id")
        if session_id:
            span.set_attribute("langfuse.session.id", session_id)

    FastAPIInstrumentor.instrument_app(
        app,
        server_request_hook=_server_request_hook,
        excluded_urls="health,docs,openapi.json,favicon.ico,mcp",
    )
    logger.info("✅ FastAPI OTel instrumentation activated.")
except ImportError:
    logger.warning("⚠️ FastAPIInstrumentor not found, skipping.")

# Allow in-cluster Kubernetes hostnames in addition to localhost variants.
# FastMCP defaults to only localhost:* / 127.0.0.1:* / [::1]:*, which causes
# 421 "Invalid Host header" when the governed-financial-advisor pod calls the
# gateway via its in-cluster DNS name (e.g. "gateway:8080").
_ALLOWED_HOSTS = [
    "127.0.0.1:*",
    "localhost:*",
    "[::1]:*",
    "gateway:*",
    "gateway.governance-stack.svc.cluster.local:*",
    "gateway.governance-stack.svc:*",
]
mcp = FastMCP(
    "CAGE Governed Gateway",
    transport_security=TransportSecuritySettings(allowed_hosts=_ALLOWED_HOSTS),
)


# ---------------------------------------------------------------------------
# MCP Tool Definitions
# ---------------------------------------------------------------------------


@mcp.tool()
async def simulate_governance_check(
    target_tool: str, target_params: dict, risk_profile: str = "Medium"
) -> dict[str, Any]:
    """Dry-run simulation of the Symbolic Governor on a proposed action.

    This is a SIMULATION ONLY — it calls ``symbolic_governor.verify()`` in
    sim_mode and does NOT enforce governance or block execution.  It exists
    solely to let the Evaluator Agent preview policy decisions before
    committing to a trade.  Mandatory enforcement happens in infrastructure
    via the ``safety_check`` LangGraph node (direct OPA invocation).
    """
    logger.info(
        "🔍 Simulating governance check for: %s (Risk: %s)", target_tool, risk_profile
    )
    vp = {**target_params, "risk_profile": risk_profile}
    result = await symbolic_governor.verify(target_tool, vp)
    violations = result.get("violations", [])
    return {
        "status": "APPROVED" if not violations else "REJECTED",
        "violations": violations,
        "opa_results": result.get("opa_results"),
        "message": "No violations detected."
        if not violations
        else "; ".join(violations),
    }


async def _evaluate_policy_internal(
    action: str,
    amount: float = 0.0,
    symbol: str = "UNKNOWN",
    currency: str = "USD",
    trader_role: str = "junior",
    user_id: str = "anonymous",
    risk_profile: str = "neutral",
    description: str | None = None,
    dry_run: bool = True,
) -> str:
    """Internal OPA policy evaluation helper (no longer an MCP-exposed tool).

    OPA enforcement for the mandatory safety guardrail path is handled
    directly by ``symbolic_governor.govern()`` in the ``safety_check`` node.
    This function is retained for internal HTTP dispatch use only
    (``/tools/execute`` endpoint).  It is intentionally NOT registered as an
    MCP tool so agents cannot invoke OPA evaluation via the tool surface.
    """
    # GAP-3 fix: wrap the OPA client call in a parent span so the parameter
    # marshalling step and OPA decision are visible as siblings in Langfuse,
    # bridging the gap between the FastAPI HTTP span and the governance.opa_check
    # child span already emitted by OPAClient.evaluate_policy().
    with tracer.start_as_current_span("governance.opa_policy_evaluation") as span:
        span.set_attribute("langfuse.observation.type", "span")
        span.set_attribute("langfuse.observation.name", "opa_policy_eval_internal")
        span.set_attribute("opa.policy_path", "trade_governance")
        span.set_attribute("governance.action", action)
        span.set_attribute("governance.trader_role", trader_role)
        span.set_attribute("governance.amount", amount)

        logger.info(
            "Tool Call: evaluate_policy(action=%s, trader_role=%s, amount=%s)",
            action,
            trader_role,
            amount,
        )
        params = {
            "action": action,
            "amount": amount,
            "symbol": symbol,
            "currency": currency,
            "trader_role": trader_role,
            "user_id": user_id,
            "risk_profile": risk_profile,
            "description": description,
            "dry_run": dry_run,
        }
        try:
            result = await opa_client.evaluate_policy(params)
            result_str = str(result)
            # Translate OPA decisions to the format safety_check_node expects
            span.set_attribute("opa.decision", result_str)
            if result_str == "ALLOW":
                span.set_attribute("opa.allowed", True)
                return "APPROVED: trade permitted by OPA policy"
            elif result_str == "MANUAL_REVIEW":
                span.set_attribute("opa.allowed", False)
                return "MANUAL_REVIEW: trade requires human approval"
            else:
                span.set_attribute("opa.allowed", False)
                return f"DENIED: trade blocked by OPA policy (decision={result_str})"
        except Exception as exc:
            logger.error("Policy Check Error: %s", exc)
            span.record_exception(exc)
            span.set_status(trace.Status(trace.StatusCode.ERROR, str(exc)))
            span.set_attribute("opa.allowed", False)
            return "DENIED: policy evaluation error"


@mcp.tool()
async def trigger_safety_intervention(reason: str = "Unknown") -> str:
    """Trigger an immediate safety intervention to lock the system."""
    from src.gateway.infrastructure.redis_client import redis_client as gw_redis

    if gw_redis:
        await gw_redis.set("safety_violation", reason)
    logger.warning("🛑 SAFETY INTERVENTION TRIGGERED: %s", reason)
    return "INTERVENTION_ACK: System Locked."


@mcp.tool()
async def verify_content_safety(text: str) -> str:
    """Verify safety of a given text using NeMo Guardrails."""
    rails = getattr(app.state, "nemo_rails", None)
    if rails is None:
        return "ERROR: NeMo rails not initialised."
    is_safe, response, _deterministic = await validate_with_nemo(text, rails)
    return "SAFE" if is_safe else f"BLOCKED: {response}"


# ---------------------------------------------------------------------------
# Mount MCP SSE with distributed tracing (Phase 5.2)
# ---------------------------------------------------------------------------

patch_mcp_tools(mcp)
logger.info("Mounting MCP SSE App at /mcp (with distributed tracing)...")
app.mount("/mcp", mcp.sse_app())


# ---------------------------------------------------------------------------
# HTTP tool dispatch (internal use — supports GatewayClient HTTP calls)
# ---------------------------------------------------------------------------


class ToolExecutionRequest(BaseModel):
    tool_name: str
    params: dict[str, Any]

    @field_validator("params")
    @classmethod
    def _reject_non_finite_floats(cls, v: dict[str, Any]) -> dict[str, Any]:
        for key, val in v.items():
            if isinstance(val, float) and not math.isfinite(val):
                raise ValueError(
                    f"params[{key!r}] contains non-finite float {val!r} "
                    "— NaN and Infinity are not permitted"
                )
        return v


@app.post("/tools/execute")
async def execute_tool_endpoint(request_body: ToolExecutionRequest, request: Request):  # type: ignore[no-untyped-def]
    """Execute a named tool via HTTP.  Requires X-CAGE-Routing-Seal."""
    # M-20: Per-client rate limiting (sliding window)
    client_ip: str = request.client.host if request.client else "unknown"
    if not await _check_rate_limit(client_ip):
        logger.warning("Rate limit exceeded for client %s", client_ip)
        raise HTTPException(
            status_code=429,
            detail=(
                f"Rate limit exceeded: max {_RATE_LIMIT_MAX_CALLS} calls "
                f"per {_RATE_LIMIT_WINDOW_SECONDS}s per client."
            ),
        )

    body_bytes = await request.body()
    enforce_routing_seal(request, body_bytes)

    # Reconstruct the tool map by calling the registered tools from the MCP server
    tool_map: dict[str, Any] = {
        "simulate_governance_check": simulate_governance_check,
        "trigger_safety_intervention": trigger_safety_intervention,
        "verify_content_safety": verify_content_safety,
        "evaluate_policy": _evaluate_policy_internal,
    }

    # Also grab tools registered to the MCP server directly by plugins
    for tool in getattr(mcp, "_tools", []):
        if tool.name not in tool_map:
            tool_map[tool.name] = tool.func

    if request_body.tool_name not in tool_map:
        raise HTTPException(
            status_code=404, detail=f"Tool '{request_body.tool_name}' not found."
        )

    func = tool_map[request_body.tool_name]
    try:
        if inspect.iscoroutinefunction(func):
            output = await func(**request_body.params)
        else:
            output = await asyncio.to_thread(func, **request_body.params)
        return {"status": "SUCCESS", "output": str(output)}
    except Exception as exc:
        logger.error("Tool Execution Error: %s", exc)
        return {"status": "ERROR", "error": str(exc)}


@app.get("/health")
async def health_check():  # type: ignore[no-untyped-def]
    return {"status": "ok", "mode": "mcp-tool-server", "nemo": "active"}


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    from src.governed_financial_advisor.utils.telemetry import configure_telemetry

    configure_telemetry()
    http_port = int(os.getenv("PORT", "8080"))
    logging.basicConfig(level=logging.INFO)
    uvicorn.run(app, host="0.0.0.0", port=http_port)
