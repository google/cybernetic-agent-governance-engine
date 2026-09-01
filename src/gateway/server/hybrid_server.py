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
Hybrid Gateway — Composition Root (Phase 3.2)
=============================================
This file is now a **thin composition root** that assembles the three
decomposed sub-applications:

  * ``mcp_tool_server.app``   — FastMCP tool registration + SSE transport
  * ``inference_proxy.inference_app``  — /v1/chat/completions vLLM proxy
  * ``governance_middleware.governance_app`` — internal governance check API

The external REST endpoints ``/agent/query`` and ``/api/chat`` have been
**removed**. The engine now
acts strictly as an internal backend for upstream agent orchestrators that
communicate via MCP over SSE.

To start the gateway:
    python src/gateway/server/hybrid_server.py

Or via Docker/Kubernetes:
    uvicorn src.gateway.server.hybrid_server:root_app --host 0.0.0.0 --port 8080
"""

import logging
import os
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from src.gateway.server.governance_middleware import governance_app
from src.gateway.server.inference_proxy import inference_app
from src.gateway.server.mcp_tool_server import app as mcp_app
from src.gateway.tracing_setup import setup_tracing

logger = logging.getLogger("Gateway.HybridServer")


# ---------------------------------------------------------------------------
# Lifespan — initialise OTel tracing before the first request is served,
# regardless of whether the server is started via __main__ or uvicorn CLI.
# ---------------------------------------------------------------------------


@asynccontextmanager
async def _gateway_lifespan(app: FastAPI):  # type: ignore[no-untyped-def]
    """Ensure tracing is initialised for every launch path (uvicorn or __main__).

    Also performs proactive pre-warming to completely eliminate cold-start latencies:
      1. Pre-warms and shares NeMo Rails across all sub-apps (avoiding isolated JITs).
      2. Triggers a synthetic OPA evaluation to warm the Rego schema and HTTP connection.
      3. Handles External Normative Provider boot-time fetches if active.
    """
    import asyncio

    setup_tracing()
    logger.info("✅ Gateway tracing initialised via lifespan hook")

    # ── Evidence Stream Precondition Check (R-06) ──────────────────────────────
    # Fail fast if EVIDENCE_CHAIN_BLOCKING=true but EVIDENCE_STREAM_ENABLED=false.
    # This invalid configuration would cause all seal issuances to fail at runtime.
    from src.compliance_bridge.evidence_stream import (
        ConfigurationError,
        validate_evidence_stream_preconditions,
    )

    try:
        validate_evidence_stream_preconditions()
    except ConfigurationError as cfg_err:
        logger.critical(
            "🚨 STARTUP FAILURE: Evidence stream precondition check failed: %s",
            cfg_err,
        )
        raise

    # ── Pre-warm and share NeMo Rails ──────────────────────────────────────
    from src.gateway.governance.nemo.manager import initialize_rails

    logger.info("🔥 Pre-warming NeMo rails at gateway boot...")
    nemo_rails = initialize_rails()

    # Store on root and sub-app states
    app.state.nemo_rails = nemo_rails
    inference_app.state.nemo_rails = nemo_rails
    mcp_app.state.nemo_rails = nemo_rails
    logger.info("✅ NeMo rails pre-warmed and shared across sub-applications")

    # ── Pre-warm OPA Policy Engine ──────────────────────────────────────────
    from src.gateway.governance.singletons import opa_client

    logger.info("🔥 Pre-warming OPA policy evaluation...")
    synthetic_params = {
        "action": "system_warmup_test",
        "resource": "test_resource",
        "amount": 100.0,
        "user_id": "system_warmup",
        "dry_run": True,
    }
    try:
        await opa_client.evaluate_policy(synthetic_params)
        logger.info("✅ OPA policy engine pre-warmed successfully")
    except Exception as e:
        logger.warning("⚠️ OPA pre-warm failed (non-blocking): %s", e)

    # ── Startup assertion: confirm trade_governance.rego is active ──────────
    # REC-5: The gateway must not silently start without the RBAC trade-size
    # policy (junior ≤ $5k, senior ≤ $500k) loaded in OPA.  This check is
    # non-blocking — a missing or unreachable policy logs a WARNING but does
    # NOT prevent startup (test environments may not have OPA running).
    try:
        trade_policy_active = await opa_client.check_policy_exists("trade/governance")
        if trade_policy_active:
            logger.info("✅ OPA trade governance policy confirmed active")
        else:
            logger.warning(
                "⚠️ trade_governance.rego policy not confirmed active — "
                "OPA_POLICY_PATH may not include trade governance rules. "
                "Trade size RBAC will not be enforced."
            )
    except Exception:
        logger.warning(
            "⚠️ trade_governance.rego policy not confirmed active — "
            "OPA_POLICY_PATH may not include trade governance rules. "
            "Trade size RBAC will not be enforced."
        )

    # ── Pre-warm Token Quota Proxy and UCA Logger (CTRL_TQP_007) ───────────────
    try:
        from src.gateway.governance.token_quota_proxy import TokenQuotaProxy
        from src.gateway.governance.uca_logger import UCALogger

        app.state.token_quota_proxy = TokenQuotaProxy.from_env()
        app.state.uca_logger = UCALogger.from_env()
        logger.info("✅ Token Quota Proxy and UCA Logger pre-warmed")
    except Exception as e:
        logger.warning("⚠️ Token Quota Proxy pre-warm failed (non-blocking): %s", e)

    # ── Production guard: enforce KMS signer activation (H-05) ────────────────
    # assert_kms_active_in_production() raises RuntimeError if KMS is not
    # configured in prod, preventing silent fallback to no-op stub signing.
    # C-25 fix: standardise on CAGE_ENV throughout — ENVIRONMENT is no longer
    # consulted here to avoid the split-brain where CAGE_ENV=production but
    # ENVIRONMENT is unset, silently skipping the KMS and salt guards.
    cage_env = os.getenv("CAGE_ENV", "production").lower()
    _is_production = cage_env not in ("development", "test", "dev", "ci")

    if _is_production:
        try:
            from src.gateway.governance.kms_signer import (
                assert_kms_active_in_production,
            )

            assert_kms_active_in_production()
            logger.info("✅ KMS signer activation confirmed at startup")
        except RuntimeError as kms_err:
            logger.critical(
                "🚨 STARTUP FAILURE: KMS signer not active in production: %s", kms_err
            )
            raise

        # C-04 fix: assert_custom_salt_in_production() was previously never
        # called automatically, allowing the well-known default GOVERNANCE_SALT
        # to be used in production — enabling routing seal forgery.
        try:
            from src.gateway.governance.routing_seal import (
                assert_custom_salt_in_production,
            )

            assert_custom_salt_in_production()
            logger.info("✅ GOVERNANCE_SALT custom value confirmed at startup")
        except RuntimeError as salt_err:
            logger.critical(
                "🚨 STARTUP FAILURE: GOVERNANCE_SALT is the default value in "
                "production — routing seals can be forged. Set a strong random "
                "secret via the GOVERNANCE_SALT environment variable: %s",
                salt_err,
            )
            raise

    # ── Production guard: prohibit log-mode seal enforcement (BLOCKER-03) ──────
    # C-25 fix: use CAGE_ENV (not ENVIRONMENT) for consistency.
    if _is_production:
        if os.getenv("CAGE_SEAL_ENFORCEMENT") == "log":
            raise RuntimeError(
                "CAGE_SEAL_ENFORCEMENT=log is prohibited in production — "
                "set CAGE_SEAL_ENFORCEMENT=enforce or remove the variable."
            )

    # ── Production guard: prohibit stub ledger provider (BLOCKER-06) ───────────
    # The stub provider fabricates a static $100k balance; the CBF would evaluate
    # against fake data, making the safety barrier meaningless in production.
    # C-25 fix: use CAGE_ENV (not ENVIRONMENT) for consistency.
    if _is_production and os.getenv("RECONCILIATION_PROVIDER", "stub") == "stub":
        raise RuntimeError(
            "RECONCILIATION_PROVIDER=stub is not allowed in production. "
            "Set a real ledger provider (e.g. RECONCILIATION_PROVIDER=anchorage)."
        )

    # External Normative Provider integration (§2.5)
    provider_name = os.getenv("CAGE_NORMATIVE_PROVIDER", "static")
    polling_task = None

    if provider_name != "static":
        from src.gateway.governance.normative_provider import NormativeProviderDaemon

        daemon = NormativeProviderDaemon.from_env()
        await daemon.boot_fetch()
        polling_task = asyncio.create_task(daemon.start_polling())
        logger.info(
            "✅ Normative provider '%s' initialized with background polling",
            provider_name,
        )

    # GCP Adaptation: Agent Registry daemon (no-op if CAGE_AGENT_REGISTRY_PROJECT not set)
    registry_daemon: Any = None
    try:
        from src.gateway.governance.ingress.agent_registry_adapter import (
            AgentRegistryDaemon,
        )

        registry_daemon = AgentRegistryDaemon()
        await registry_daemon.start()
    except ImportError:
        logger.warning(
            "⚠️ agent_registry_adapter not available — using static agent catalog."
        )
    except Exception as reg_err:
        logger.error("❌ AgentRegistryDaemon failed to start: %s", reg_err)

    # ── Start consensus background audit worker (HIGH-06) ──────────────────
    from src.cage_finance.consensus.consensus import _background_audit_worker

    asyncio.create_task(_background_audit_worker())
    logger.info("✅ Consensus background audit worker started")

    yield

    # Shutdown: stop Agent Registry daemon if running
    if registry_daemon is not None:
        await registry_daemon.stop()

    # Shutdown: cancel polling task if running
    if polling_task is not None:
        polling_task.cancel()
        try:
            await polling_task
        except asyncio.CancelledError:
            pass
    # No shutdown work required for tracing (BatchSpanProcessor flushes on GC).


# ---------------------------------------------------------------------------
# M-16: Debug endpoint guard middleware
# Gate all /debug/* paths behind CAGE_ENV=dev. In production, return HTTP 404
# so internal governance state is never exposed to external callers.
# ---------------------------------------------------------------------------


class _DebugEndpointGuard(BaseHTTPMiddleware):
    """Return 404 for /debug/* paths unless CAGE_ENV is 'dev' or 'test'."""

    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        if request.url.path.startswith("/debug"):
            cage_env = os.getenv("CAGE_ENV", "prod").lower()
            if cage_env not in ("dev", "test", "local"):
                return JSONResponse(
                    status_code=404,
                    content={"detail": "Not found"},
                )
        return await call_next(request)


# ---------------------------------------------------------------------------
# Root application — mount decomposed sub-apps
# ---------------------------------------------------------------------------

root_app = FastAPI(
    title="CAGE Governed Gateway (Hybrid)",
    description=(
        "Headless Python governance engine.  "
        "External REST endpoints removed — use MCP over SSE or the internal "
        "/governance/* and /v1/* surfaces."
    ),
    version="0.1.0",
    lifespan=_gateway_lifespan,
)

# M-16: Block /debug/* in non-dev environments
root_app.add_middleware(_DebugEndpointGuard)


@root_app.get("/healthz")
async def healthz():  # type: ignore[no-untyped-def]
    """Health check endpoint that verifies KMS connectivity.

    Returns 200 with kms_active=true when KMS signing is available.
    Returns 200 with kms_active=false in dev/test environments.
    Returns 503 if KMS is required but unavailable.
    """
    from fastapi.responses import JSONResponse as _JSONResponse

    cage_env = os.getenv("CAGE_ENV", os.getenv("ENVIRONMENT", "production")).lower()
    is_prod = cage_env not in ("development", "test", "dev", "ci")

    try:
        from src.gateway.governance.kms_signer import get_governance_signer

        signer = get_governance_signer()
        kms_active = signer.is_kms_active
        if is_prod and not kms_active:
            return _JSONResponse(
                status_code=503,
                content={
                    "status": "unhealthy",
                    "kms_active": False,
                    "reason": "KMS signer not active in production environment",
                },
            )
        return _JSONResponse(
            status_code=200,
            content={"status": "healthy", "kms_active": kms_active, "env": cage_env},
        )
    except Exception as exc:
        logger.error("healthz: KMS check failed: %s", exc)
        if is_prod:
            return _JSONResponse(
                status_code=503,
                content={
                    "status": "unhealthy",
                    "kms_active": False,
                    "reason": "KMS check failed",
                },
            )
        return _JSONResponse(
            status_code=200,
            content={"status": "healthy", "kms_active": False, "env": cage_env},
        )


# ---------------------------------------------------------------------------
# PAUSE Resume Endpoints (Phase 1.4)
# ---------------------------------------------------------------------------


@root_app.post("/v1/pause/{pause_token}/resume")
async def resume_paused_request(
    pause_token: str,
    request: Request,
) -> JSONResponse:
    """Resume a paused execution.

    Calls handle_resume_request() from agent_gateway_adapter.py to process
    the resume request. The body may optionally contain an override_action field.

    Args:
        pause_token: The pause token UUID from the original PAUSE response.
        request: The incoming HTTP request (body may contain override_action).

    Returns:
        JSON response with resume result:
            - 200 OK: Resume successful (RESUMED or ALREADY_RESUMED)
            - 404 Not Found: pause_token invalid or not found
            - 410 Gone: pause_token expired (must retry original request)
            - 500 Internal Server Error: Redis unavailable
    """
    from src.gateway.server.agent_gateway_adapter import handle_resume_request

    # Parse optional JSON body (may contain override_action)
    try:
        body = await request.json()
    except Exception:
        body = None

    status_code, response_body = await handle_resume_request(pause_token, body)
    return JSONResponse(status_code=status_code, content=response_body)


@root_app.get("/v1/pause/{pause_token}")
async def get_pause_state(pause_token: str) -> JSONResponse:
    """Get current pause state.

    Calls handle_get_pause_state() from agent_gateway_adapter.py to retrieve
    the current state of a paused request.

    Args:
        pause_token: The pause token UUID to query.

    Returns:
        JSON response with pause state:
            - 200 OK: Pause state found (includes status, reason, timestamps)
            - 404 Not Found: pause_token invalid or not found
            - 500 Internal Server Error: Redis unavailable
    """
    from src.gateway.server.agent_gateway_adapter import handle_get_pause_state

    status_code, response_body = await handle_get_pause_state(pause_token)
    return JSONResponse(status_code=status_code, content=response_body)


# Inference proxy handles /v1/chat/completions
root_app.mount("/inference", inference_app)

# Governance middleware handles /governance/check
root_app.mount("/governance", governance_app)

# MCP tool server handles /, /mcp, /tools/execute, /health
root_app.mount("/", mcp_app)

logger.info(
    "✅ CAGE Hybrid Gateway assembled: MCP=%s  Inference=%s  Governance=%s",
    mcp_app.title,
    inference_app.title,
    governance_app.title,
)

# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    from src.gateway.infrastructure.telemetry_client import configure_telemetry

    configure_telemetry()
    http_port = int(os.getenv("PORT", "8080"))
    logging.basicConfig(level=logging.INFO)
    uvicorn.run(root_app, host="0.0.0.0", port=http_port)
