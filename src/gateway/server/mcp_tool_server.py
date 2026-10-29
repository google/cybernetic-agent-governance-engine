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
Dedicated to FastMCP tool registration (``@mcp.tool()``) and stateless
Streamable HTTP transport at ``/mcp/``. Contains no HTTP proxy logic or REST endpoints.

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
import logging
import math
import os
import sys
import time
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations
from pydantic import BaseModel, field_validator

from src.gateway.observability.attributes import (
    OBSERVATION_NAME,
    OBSERVATION_TYPE,
    SESSION_ID,
    SPAN_ATTR_OPA_POLICY_PATH,
)

sys.path.append(".")

from opentelemetry import trace

from src.gateway.governance.content_safety import (
    CONTENT_SAFETY_ERROR,
    CONTENT_SAFETY_NO_INFERENCE_BACKEND,
    CONTENT_SAFETY_RAILS_UNAVAILABLE,
    SAFE_VERDICT,
    blocked_verdict,
    refusal_reason,
)
from src.gateway.governance.decisions import GovernanceDecision
from src.gateway.governance.governor.governor import SymbolicGovernor
from src.gateway.governance.inference_backend import (
    InferenceBackend,
    require_backend_settings,
    resolve_inference_backend,
)
from src.gateway.governance.schemas.thresholds import load_and_validate_thresholds
from src.gateway.infrastructure.config_manager import config_manager
from src.gateway.observability.mcp_tracing import patch_mcp_tools
from src.gateway.server.app_state import governor_of
from src.gateway.server.rate_limit import (
    _METRICS_AVAILABLE,
    RateLimitVerdict,
    build_rate_limit_redis_from_env,
    get_shared_rate_limiter,
    sanitize_principal,
)
from src.gateway.server.rate_limit import (
    rate_limit_active_buckets as _rate_limit_active_buckets,
)
from src.gateway.server.rate_limit import (
    rate_limit_hits_total as _rate_limit_hits_total,
)
from src.gateway.tracing_setup import setup_tracing

logger = logging.getLogger("Gateway.MCPToolServer")
tracer = trace.get_tracer("gateway.mcp_tool_server")

# ---------------------------------------------------------------------------
# A4 / M-20 & L-2: Shared dual-bucket GCRA rate limiter (identity + principal)
# Replaces the per-IP sliding-window bucket scan and the high-cardinality
# client_ip Prometheus label with (route, scope) labels and shared Redis Lua.
# ---------------------------------------------------------------------------

_RATE_LIMIT_MAX_CALLS: int = int(
    os.getenv(
        "CAGE_RATE_LIMIT_PRINCIPAL_PER_MIN",
        os.getenv("MCP_RATE_LIMIT_MAX_CALLS", "60"),
    )
)
_RATE_LIMIT_WINDOW_SECONDS: int = int(
    os.getenv(
        "CAGE_RATE_LIMIT_WINDOW_SECONDS",
        os.getenv("MCP_RATE_LIMIT_WINDOW_SECONDS", "60"),
    )
)
_INITIAL_RATE_LIMIT_MAX_CALLS: int = _RATE_LIMIT_MAX_CALLS
_INITIAL_RATE_LIMIT_WINDOW_SECONDS: int = _RATE_LIMIT_WINDOW_SECONDS
_rate_limit_buckets: Any = get_shared_rate_limiter()._fallback_tat


def _effective_mcp_rate_limits() -> tuple[int, float]:
    """Return effective ``(principal_per_min, window_seconds)`` for ``tools-execute``.

    Honors runtime ``CAGE_RATE_LIMIT_PRINCIPAL_PER_MIN`` and
    ``CAGE_RATE_LIMIT_WINDOW_SECONDS`` overrides when the module-level
    constants have not been explicitly mutated by a test.
    """
    if _RATE_LIMIT_MAX_CALLS != _INITIAL_RATE_LIMIT_MAX_CALLS:
        p_limit = _RATE_LIMIT_MAX_CALLS
    else:
        p_limit = int(
            os.getenv(
                "CAGE_RATE_LIMIT_PRINCIPAL_PER_MIN",
                os.getenv("MCP_RATE_LIMIT_MAX_CALLS", str(_RATE_LIMIT_MAX_CALLS)),
            )
        )
    if _RATE_LIMIT_WINDOW_SECONDS != _INITIAL_RATE_LIMIT_WINDOW_SECONDS:
        win = float(_RATE_LIMIT_WINDOW_SECONDS)
    else:
        win = float(
            os.getenv(
                "CAGE_RATE_LIMIT_WINDOW_SECONDS",
                os.getenv(
                    "MCP_RATE_LIMIT_WINDOW_SECONDS", str(_RATE_LIMIT_WINDOW_SECONDS)
                ),
            )
        )
    return p_limit, win


async def _check_rate_limit(target: Request | str) -> bool:
    """Return True if the request/caller is within the GCRA rate limit, False if exceeded."""
    global _rate_limit_buckets
    limiter = get_shared_rate_limiter()
    # Sync module-level fallback bucket reference in case a test reassigned _rate_limit_buckets = {}
    if limiter._fallback_tat is not _rate_limit_buckets:
        limiter.bind_redis(None)
        if isinstance(_rate_limit_buckets, dict):
            limiter._fallback_tat.clear()
            for k, v in _rate_limit_buckets.items():
                if isinstance(v, (int, float)):
                    limiter._fallback_tat[str(k)] = float(v)
        _rate_limit_buckets = limiter._fallback_tat
    p_limit, win = _effective_mcp_rate_limits()
    if isinstance(target, str):
        safe_id = sanitize_principal(target)
        verdict = await limiter.check(
            "tools-execute",
            identity=f"caller:{safe_id}",
            principal=safe_id,
            principal_per_min=p_limit,
            window_seconds=win,
        )
        return verdict.allowed
    verdict = await limiter.check_request(
        target,
        "tools-execute",
        principal_per_min=p_limit,
        window_seconds=win,
    )
    return verdict.allowed


_default_check_rate_limit = _check_rate_limit


# ---------------------------------------------------------------------------
# Startup validation and telemetry bootstrap
# ---------------------------------------------------------------------------


def _install_contributions(governor: SymbolicGovernor) -> None:
    """Apply the server hooks each domain contributed (tools, tasks, rails).

    Compliance overlays are process-wide and registered by ``bootstrap_governor``.
    """
    from src.gateway.governance.background_tasks import register_background_task
    from src.gateway.governance.semantic_rail_factory import (
        register_semantic_rail_provider as register_rail_provider,
    )

    for contribution in governor.components.contributions:
        for name, worker in contribution.background_tasks.items():
            register_background_task(name, worker)
        for rail_provider in contribution.rail_providers:
            register_rail_provider(rail_provider)
        if contribution.tool_provider is not None:
            contribution.tool_provider.register_tools(mcp, governor)


async def _activate_domain() -> SymbolicGovernor:
    """Assemble the governor for the single ``CAGE_DOMAIN`` and put it on ``app.state``.

    Fail closed at startup: an unset/unknown domain, a domain without a
    complete ``DomainConfig``, an unsafe contribution, null kernel slots, a
    failed production posture check, or an OPA server that lacks the
    domain's Rego package or required rules all raise instead of serving
    traffic.
    """
    from src.gateway.governance.governor.bootstrap import bootstrap_governor
    from src.gateway.governance.plugin_loader import active_domain_config

    governor = bootstrap_governor()
    config = active_domain_config()
    await governor.components.opa.verify_domain_policy(
        config.opa_package, config.opa_required_rules
    )
    _install_contributions(
        governor
    )  # after the handshake: never half-activate a domain
    app.state.governor = governor
    logger.info(
        "✅ Domain activated (startup readiness check passed): %s",
        governor.registered_tier_names(),
    )
    return governor


@asynccontextmanager
async def lifespan(app: FastAPI):  # type: ignore[no-untyped-def]
    from src.gateway.governance.semantic_rail_factory import (
        initialize_semantic_rails as initialize_rails,
    )
    from src.gateway.governance.semantic_rail_factory import (
        semantic_rails_refusal,
    )

    # 1. Tracing bootstrap (Phase 5.1)
    setup_tracing()

    # 2. Governance threshold validation (Phase 2.2) — aborts if schema invalid
    load_and_validate_thresholds()

    # 3. Inference backend (CAGE_INFERENCE_BACKEND). An unknown value fails
    #    startup. Under ``none`` no model settings are needed and no NeMo
    #    rails are built, so content safety refuses with a reason code.
    #    Otherwise a backend is required, as before the setting existed.
    logger.info("🚀 CAGE MCP Tool Server Starting...")
    if resolve_inference_backend() is InferenceBackend.NONE:
        logger.warning(
            "CAGE_INFERENCE_BACKEND=none: no model; NeMo rails are off and "
            "content safety refuses (%s).",
            CONTENT_SAFETY_NO_INFERENCE_BACKEND,
        )
        app.state.nemo_rails = None
    else:
        require_backend_settings(config_manager.get)
        # 4. Initialise NeMo rails only when semantic_rails_refusal() allows
        #    them, the same predicate every runtime construction path checks.
        refusal = semantic_rails_refusal()
        if refusal is None:
            app.state.nemo_rails = initialize_rails()
        else:
            logger.info("NeMo Colang rails are off (%s).", refusal[1])
            app.state.nemo_rails = None

    # 5. Start consensus background audit worker (Phase 4.4)
    from src.gateway.governance.consensus import _background_audit_worker

    audit_task = asyncio.create_task(_background_audit_worker())
    app.state.audit_task = audit_task

    # 6. Assemble the governor for the single CAGE_DOMAIN plugin (fail-closed
    #    readiness and posture checks, including the OPA package/rule handshake)
    governor = await _activate_domain()

    # 7. Bind shared Redis client for GCRA rate limiting (A4)
    rl_redis = None
    try:
        rl_redis = build_rate_limit_redis_from_env()
        app.state.rate_limit_redis = rl_redis
        get_shared_rate_limiter().bind_redis(rl_redis)
    except Exception as rl_exc:
        logger.warning(
            "⚠️ Rate-limit Redis client init failed (using local fallback): %s", rl_exc
        )

    from contextlib import AsyncExitStack, nullcontext

    session_mgr = getattr(mcp, "session_manager", None)
    run_fn = getattr(session_mgr, "run", None) if session_mgr is not None else None
    async with AsyncExitStack() as mcp_stack:
        if callable(run_fn):
            if (
                session_mgr is not None
                and getattr(session_mgr, "_has_started", False)
                and getattr(session_mgr, "_task_group", None) is None
            ):
                session_mgr._has_started = False
            ctx = run_fn()
            if hasattr(ctx, "__aenter__"):
                await mcp_stack.enter_async_context(ctx)
        else:
            await mcp_stack.enter_async_context(nullcontext())
        yield

    # Shutdown
    logger.info("🛑 CAGE MCP Tool Server Shutting Down...")
    audit_task.cancel()
    try:
        await audit_task
    except asyncio.CancelledError:
        pass
    if rl_redis is not None and hasattr(rl_redis, "aclose"):
        try:
            await rl_redis.aclose()
        except Exception as rl_close_exc:
            logger.debug("Rate-limit Redis close error: %s", rl_close_exc)
    await governor.components.opa.close()


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
            span.set_attribute(SESSION_ID, session_id)

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
    stateless_http=True,
    json_response=True,
    streamable_http_path="/",
    transport_security=TransportSecuritySettings(allowed_hosts=_ALLOWED_HOSTS),
)


# ---------------------------------------------------------------------------
# MCP Tool Definitions
# ---------------------------------------------------------------------------


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
async def simulate_governance_check(
    target_tool: str, target_params: dict, risk_profile: str = "Medium"
) -> dict[str, Any]:
    """Dry-run preview of the governor on a proposed action.

    Calls ``SymbolicGovernor.verify()``, which runs the pipeline under the
    ``DRY_RUN`` profile: stateless stages run normally and mutating stages
    (CBF, fiscal, dose/kinematic barriers) run only their side-effect-free
    ``evaluate()`` preview, so a refusal live execution would issue is
    reported here too. Nothing is committed, and this tool does not enforce
    or block execution — enforcement happens when the action is dispatched
    through ``validate_action`` / ``govern()``.

    ``verdict`` is a :class:`GovernanceDecision` value: ``ALLOW`` iff there
    are no violations, otherwise the classifier's decision over them. A NARROW
    here is an unverified candidate, and no approval token is parked for a
    REQUIRE_APPROVAL; ``POST /governance/validate-action`` does both.
    """
    logger.info(
        "🔍 Simulating governance check for: %s (Risk: %s)", target_tool, risk_profile
    )
    vp = {**target_params, "risk_profile": risk_profile}
    result = await governor_of(app).verify(target_tool, vp)
    violations = [v.to_dict() for v in result.get("violations", [])]
    if violations:
        # An unclassified refusal is a DENY (fail closed).
        verdict = GovernanceDecision(result.get("decision", GovernanceDecision.DENY))
    else:
        verdict = GovernanceDecision.ALLOW
    return {
        "verdict": verdict.value,
        "violations": violations,
        "opa_results": result.get("opa_results"),
        "message": "No violations detected."
        if not violations
        else "; ".join(f"[{v['code']}] {v['message']}" for v in violations),
    }


async def _evaluate_policy_internal(
    action: str,
    amount: float = 0.0,
    symbol: str = "UNKNOWN",
    currency: str = "USD",
    subject_role: str = "junior",
    user_id: str = "anonymous",
    risk_profile: str = "neutral",
    description: str | None = None,
    dry_run: bool = True,
    **extra_params: Any,
) -> str:
    """Internal OPA policy evaluation helper (no longer an MCP-exposed tool).

    OPA enforcement for the mandatory safety guardrail path is handled
    directly by ``SymbolicGovernor.govern()`` in the ``safety_check`` node.
    This function is retained for internal HTTP dispatch use only
    (``/tools/execute`` endpoint).  It is intentionally NOT registered as an
    MCP tool so agents cannot invoke OPA evaluation via the tool surface.
    """
    # GAP-3 fix: wrap the OPA client call in a parent span so the parameter
    # marshalling step and OPA decision are visible as siblings in Telemetry,
    # bridging the gap between the FastAPI HTTP span and the governance.opa_check
    # child span already emitted by OPAClient.evaluate_policy().
    with tracer.start_as_current_span("governance.opa_policy_evaluation") as span:
        span.set_attribute(OBSERVATION_TYPE, "span")
        span.set_attribute(OBSERVATION_NAME, "opa_policy_eval_internal")
        span.set_attribute(SPAN_ATTR_OPA_POLICY_PATH, "domain_governance")
        span.set_attribute("governance.action", action)
        span.set_attribute("governance.subject_role", subject_role)
        span.set_attribute("governance.amount", amount)

        logger.info(
            "Tool Call: evaluate_policy(action=%s, subject_role=%s, amount=%s)",
            action,
            subject_role,
            amount,
        )
        params = {
            "action": action,
            "amount": amount,
            "symbol": symbol,
            "currency": currency,
            "subject_role": subject_role,
            "user_id": user_id,
            "risk_profile": risk_profile,
            "description": description,
            "dry_run": dry_run,
            **extra_params,
        }
        try:
            result = await governor_of(app).components.opa.evaluate_policy(params)
            result_str = str(result)
            # Translate OPA decisions to the format safety_check_node expects
            span.set_attribute("opa.decision", result_str)
            if result_str == "ALLOW":
                span.set_attribute("opa.allowed", True)
                return "APPROVED: action permitted by OPA policy"
            elif result_str == "MANUAL_REVIEW":
                span.set_attribute("opa.allowed", False)
                return "MANUAL_REVIEW: action requires human approval"
            else:
                span.set_attribute("opa.allowed", False)
                return f"DENIED: action blocked by OPA policy (decision={result_str})"
        except Exception as exc:
            logger.error("Policy Check Error: %s", exc)
            span.record_exception(exc)
            span.set_status(trace.Status(trace.StatusCode.ERROR, str(exc)))
            span.set_attribute("opa.allowed", False)
            return "DENIED: policy evaluation error"


_SAFETY_INTERVENTION_TTL_SECONDS: int = int(
    os.getenv("CAGE_SAFETY_INTERVENTION_TTL_SECONDS", "3600")
)


# Setting the lock twice leaves the same state, so a resend is safe.
@mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, idempotentHint=True))
async def trigger_safety_intervention(reason: str = "Unknown") -> str:
    """Trigger an immediate safety intervention to lock the system."""
    from src.gateway.infrastructure.redis_client import redis_client as gw_redis

    if gw_redis is None:
        logger.error(
            "❌ SAFETY INTERVENTION FAILED: Redis unavailable; cannot persist lock for: %s",
            reason,
        )
        raise RuntimeError(
            "FAIL-CLOSED: Redis unavailable; cannot persist safety intervention lock"
        )
    setex_fn = getattr(gw_redis, "setex", None)
    if setex_fn is not None and inspect.iscoroutinefunction(setex_fn):
        await setex_fn("safety_violation", _SAFETY_INTERVENTION_TTL_SECONDS, reason)
    else:
        await gw_redis.set("safety_violation", reason)
    logger.warning(
        "🛑 SAFETY INTERVENTION TRIGGERED (ttl=%ds): %s",
        _SAFETY_INTERVENTION_TTL_SECONDS,
        reason,
    )
    return "INTERVENTION_ACK: System Locked."


@mcp.tool()
async def verify_content_safety(text: str) -> str:
    """Verify safety of a given text using NeMo Guardrails.

    Returns ``SAFE`` only when the rails ran and passed the text. Every
    other outcome is ``BLOCKED: <reason>`` with a reason code (POAM-2026-124),
    and the code says which fact applies:

    - ``CONTENT_SAFETY_NO_INFERENCE_BACKEND``: ``CAGE_INFERENCE_BACKEND=none``.
    - ``CONTENT_SAFETY_RAILS_DISABLED``: ``CAGE_NEMO_ENABLED`` is off. The
      rails are off by configuration; nothing failed.
    - ``CONTENT_SAFETY_RAILS_UNAVAILABLE``: the rails are enabled but not
      initialised.
    - ``CONTENT_SAFETY_ERROR``: the check raised.
    """
    from src.gateway.governance.semantic_rail_factory import (
        semantic_rails_refusal,
    )
    from src.gateway.governance.semantic_rail_factory import (
        validate_with_semantic_rail as validate_with_nemo,
    )

    refusal = semantic_rails_refusal()
    if refusal is not None:
        return blocked_verdict(refusal_reason(*refusal))
    rails = getattr(app.state, "nemo_rails", None)
    if rails is None:
        return blocked_verdict(
            refusal_reason(
                CONTENT_SAFETY_RAILS_UNAVAILABLE,
                "NeMo rails are enabled but not initialised.",
            )
        )
    try:
        is_safe, response, _deterministic = await validate_with_nemo(text, rails)
    except Exception as exc:
        logger.error("verify_content_safety: rail check raised — blocking: %s", exc)
        return blocked_verdict(
            refusal_reason(CONTENT_SAFETY_ERROR, "the rail check raised an error.")
        )
    return SAFE_VERDICT if is_safe is True else blocked_verdict(response)


# ---------------------------------------------------------------------------
# Mount Stateless MCP Streamable HTTP with distributed tracing (A3)
# ---------------------------------------------------------------------------

patch_mcp_tools(mcp)
logger.info(
    "Mounting Stateless MCP Streamable HTTP App at /mcp (with distributed tracing)..."
)
app.mount("/mcp", mcp.streamable_http_app())


# ---------------------------------------------------------------------------
# HTTP tool dispatch (internal use — supports GatewayClient HTTP calls)
# ---------------------------------------------------------------------------


class ToolExecutionRequest(BaseModel):
    tool_name: str
    params: dict[str, Any]

    @field_validator("params")
    @classmethod
    def _reject_non_finite_floats(cls, v: dict[str, Any]) -> dict[str, Any]:
        def _walk(obj: Any, path: str = "params") -> None:
            if isinstance(obj, float) and not math.isfinite(obj):
                raise ValueError(
                    f"{path} contains non-finite float {obj!r} "
                    "— NaN and Infinity are not permitted"
                )
            if isinstance(obj, dict):
                for key, val in obj.items():
                    _walk(val, f"{path}[{key!r}]")
            elif isinstance(obj, (list, tuple)):
                for idx, item in enumerate(obj):
                    _walk(item, f"{path}[{idx}]")

        _walk(v, "params")
        return v


@app.post("/tools/execute")
async def execute_tool_endpoint(request_body: ToolExecutionRequest, request: Request):  # type: ignore[no-untyped-def]
    """Execute a named tool via HTTP.

    The caller is authenticated by mesh workload identity before this handler
    runs (WorkloadIdentityMiddleware on the gateway root app, POAM-2026-080,
    and enforced directly here as defense-in-depth for GHSA-4x3x-w2m3-8mfh).
    """
    from src.gateway.server.workload_identity import (
        extract_client_identity,
        load_identity_policy,
    )

    try:
        caller_identity = extract_client_identity(request.scope)
        policy = load_identity_policy()
    except (ValueError, RuntimeError) as exc:
        logger.warning(
            "Gateway /tools/execute refused request without verified workload identity: %s",
            exc,
        )
        raise HTTPException(
            status_code=403,
            detail="trusted workload identity required",
        ) from exc
    if caller_identity not in policy.trusted:
        logger.warning(
            "Gateway /tools/execute refused untrusted workload identity: %s",
            caller_identity,
        )
        raise HTTPException(
            status_code=403,
            detail="trusted workload identity required",
        )

    # A4 / M-20: Shared dual-bucket GCRA rate limiting (identity + principal)
    if _check_rate_limit is not _default_check_rate_limit:
        allowed = await _check_rate_limit(request)
        rl_verdict = RateLimitVerdict(
            allowed=bool(allowed), retry_after_seconds=1 if not allowed else 0
        )
    else:
        p_limit, win = _effective_mcp_rate_limits()
        rl_verdict = await get_shared_rate_limiter().check_request(
            request,
            "tools-execute",
            principal_per_min=p_limit,
            window_seconds=win,
        )
    if not rl_verdict.allowed:
        retry_after = max(1, int(rl_verdict.retry_after_seconds or 1))
        logger.warning(
            "Rate limit exceeded on /tools/execute (identity=%s principal=%s scope=%s)",
            rl_verdict.identity or caller_identity,
            rl_verdict.principal,
            rl_verdict.scope,
        )
        return JSONResponse(
            status_code=429,
            headers={"Retry-After": str(retry_after)},
            content={
                "error": "rate_limit_exceeded",
                "scope": rl_verdict.scope or "principal",
                "retry_after_seconds": retry_after,
            },
        )

    # Reconstruct the tool map by calling the registered tools from the MCP server
    tool_map: dict[str, Any] = {
        "simulate_governance_check": simulate_governance_check,
        "trigger_safety_intervention": trigger_safety_intervention,
        "verify_content_safety": verify_content_safety,
        "evaluate_policy": _evaluate_policy_internal,
    }

    # Also grab tools registered to the MCP server directly by plugins
    # (e.g. execute_trade_action). FastMCP keeps them in its tool manager.
    for tool in mcp._tool_manager.list_tools():
        if tool.name not in tool_map:
            tool_map[tool.name] = tool.fn

    if request_body.tool_name not in tool_map:
        raise HTTPException(
            status_code=404, detail=f"Tool '{request_body.tool_name}' not found."
        )

    from src.gateway.server.governance_middleware import (
        get_last_refusal_proof_hash,
        reset_last_refusal_proof_hash,
        set_last_refusal_proof_hash,
    )

    func = tool_map[request_body.tool_name]
    refusal_token = set_last_refusal_proof_hash(None)
    try:
        if inspect.iscoroutinefunction(func):
            output = await func(**request_body.params)
        else:
            output = await asyncio.to_thread(func, **request_body.params)
        response: dict[str, Any] = {"status": "SUCCESS", "output": str(output)}
        proof_hash = get_last_refusal_proof_hash()
        if proof_hash:
            response["proof_hash"] = proof_hash
        return response
    except Exception as exc:
        logger.error("Tool Execution Error: %s", exc)
        err_response: dict[str, Any] = {"status": "ERROR", "error": str(exc)}
        proof_hash = get_last_refusal_proof_hash()
        if proof_hash:
            err_response["proof_hash"] = proof_hash
        return err_response
    finally:
        reset_last_refusal_proof_hash(refusal_token)


@app.get("/health")
async def health_check():  # type: ignore[no-untyped-def]
    nemo = "off" if getattr(app.state, "nemo_rails", None) is None else "active"
    return {"status": "ok", "mode": "mcp-tool-server", "nemo": nemo}


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    from src.gateway.infrastructure.telemetry_client import configure_telemetry
    from src.gateway.server.workload_identity import (
        WorkloadIdentityMiddleware,
        load_identity_policy,
    )

    configure_telemetry()
    app.add_middleware(WorkloadIdentityMiddleware, policy=load_identity_policy())
    http_port = int(os.getenv("PORT", "8080"))
    logging.basicConfig(level=logging.INFO)
    uvicorn.run(app, host="0.0.0.0", port=http_port)
