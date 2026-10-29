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

  * ``mcp_tool_server.app``   — FastMCP tool registration + stateless Streamable HTTP transport
  * ``inference_proxy.inference_app``  — /v1/chat/completions vLLM proxy
  * ``governance_middleware.governance_app`` — internal governance check API

The external REST endpoints ``/agent/query`` and ``/api/chat`` have been
**removed**. The engine now
acts strictly as an internal backend for upstream agent orchestrators that
communicate via MCP over Streamable HTTP.

To start the gateway:
    python src/gateway/server/hybrid_server.py

Or via Docker/Kubernetes:
    uvicorn src.gateway.server.hybrid_server:root_app --host 0.0.0.0 --port 8080 --loop uvloop --http httptools
"""

import json
import logging
import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

# Ensure both workspace root and src/ are in sys.path so both
# 'src.gateway...' and domain plugin entrypoints resolve cleanly.
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
for _p in [str(_REPO_ROOT), str(_REPO_ROOT / "src")]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from src.gateway.infrastructure.telemetry_client import configure_telemetry
from src.gateway.server.governance_middleware import governance_app
from src.gateway.server.inference_proxy import inference_app
from src.gateway.server.mcp_tool_server import app as mcp_app
from src.gateway.server.workload_identity import (
    WorkloadIdentityMiddleware,
    load_identity_policy,
)

logger = logging.getLogger("Gateway.HybridServer")


# ---------------------------------------------------------------------------
# Lifespan — initialise OTel tracing before the first request is served,
# regardless of whether the server is started via __main__ or uvicorn CLI.
# ---------------------------------------------------------------------------


@asynccontextmanager
async def _gateway_lifespan(app: FastAPI):  # type: ignore[no-untyped-def]
    """Ensure canonical telemetry is initialised for every launch path (uvicorn or __main__).

    Also performs proactive pre-warming to completely eliminate cold-start latencies:
      1. Pre-warms and shares NeMo Rails across all sub-apps (avoiding isolated JITs).
      2. Triggers a synthetic OPA evaluation to warm the Rego schema and HTTP connection.
      3. Handles External Normative Provider boot-time fetches if active.
    """
    import asyncio

    os.environ.setdefault(
        "SERVICE_NAME", os.getenv("OTEL_SERVICE_NAME", "hybrid-gateway")
    )
    configure_telemetry()
    logger.info("✅ Gateway telemetry initialised via lifespan hook")

    # ── Prometheus Metrics Server & Event-Loop Lag Monitor (A1) ───────────────
    # Starts the threaded Prometheus WSGI server on CAGE_METRICS_PORT (default
    # 9090) so /metrics remains scrapeable even when the asyncio event loop is
    # blocked, alongside a 250 ms loop-lag sampling task.
    from src.gateway.observability.loop_monitor import (
        run_loop_lag_monitor,
        start_metrics_http_server,
    )

    metrics_server = start_metrics_http_server()
    app.state.metrics_server = metrics_server
    loop_lag_task: asyncio.Task[None] | None = None

    try:
        # ── Inference backend (CAGE_INFERENCE_BACKEND) ──────────────────────
        # An unknown value fails startup here, before anything connects.
        from src.gateway.governance.inference_backend import (
            InferenceBackend,
            require_backend_settings,
            resolve_inference_backend,
        )

        inference_backend = resolve_inference_backend()

        # ── Evidence Stream Precondition Check (R-06) ──────────────────────────
        # Fail fast if EVIDENCE_CHAIN_BLOCKING=true but EVIDENCE_STREAM_ENABLED=false.
        # This invalid configuration would cause all seal issuances to fail at runtime.
        from src.gateway.governance.evidence.stream import (
            ConfigurationError,
            start_evidence_sink,
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

        # ── Evidence Stream Sink ───────────────────────────────────────────────
        # Refusal receipts, pause receipts and blocking seals all write through
        # the get_evidence_sink() singleton, so it must be connected before the
        # first request. Fails startup under an enforcing posture if Redis is
        # unreachable.
        evidence_sink = await start_evidence_sink()

        # ── Pre-warm and share NeMo Rails ──────────────────────────────────────
        # Under ``none`` no rails are built: NeMo is off and visible, and
        # content safety refuses with a reason code. An explicit ``vllm`` /
        # ``external`` needs its URL and key now, not at first use. Unset
        # keeps the behaviour from before the setting existed. Rails are built
        # only when semantic_rails_refusal() allows them: the same predicate
        # the inference proxy, the rail nodes and the hot-reload path check.
        from src.gateway.governance.semantic_rail_factory import (
            semantic_rails_refusal,
        )

        if inference_backend is InferenceBackend.NONE:
            logger.warning("CAGE_INFERENCE_BACKEND=none: no model; NeMo rails are off.")
            nemo_rails = None
        else:
            if inference_backend is not None:
                from src.gateway.infrastructure.config_manager import (
                    config_manager,
                )

                require_backend_settings(config_manager.get)
            rails_refusal = semantic_rails_refusal()
            if rails_refusal is None:
                from src.gateway.governance.semantic_rail_factory import (
                    initialize_semantic_rails as initialize_rails,
                )

                logger.info("🔥 Pre-warming NeMo rails at gateway boot...")
                nemo_rails = initialize_rails()
            else:
                logger.info("NeMo Colang rails are off (%s).", rails_refusal[1])
                nemo_rails = None

        # Store on root and sub-app states
        app.state.nemo_rails = nemo_rails
        inference_app.state.nemo_rails = nemo_rails
        mcp_app.state.nemo_rails = nemo_rails
        if nemo_rails is not None:
            logger.info("✅ NeMo rails pre-warmed and shared across sub-applications")

        # ── Pre-warm Token Quota Proxy, UCA Logger, and shared DeferQueue ──────
        try:
            from src.gateway.governance.defer_queue import get_shared_defer_queue
            from src.gateway.governance.token_quota_proxy import TokenQuotaProxy
            from src.gateway.governance.uca_logger import UCALogger

            app.state.token_quota_proxy = TokenQuotaProxy.from_env()
            app.state.uca_logger = UCALogger.from_env()
            app.state.defer_queue = get_shared_defer_queue()
            governance_app.state.defer_queue = app.state.defer_queue
            logger.info("✅ Token Quota Proxy, UCA Logger, and DeferQueue pre-warmed")
        except Exception as e:
            # 'Token Quota Proxy' is a component name; logs the startup error only.
            # nosemgrep: python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure
            logger.warning("⚠️ Token Quota Proxy pre-warm failed (non-blocking): %s", e)

        # ── Production guards not owned by the governor posture check ──────────
        # KMS signing mode (K3), KMS/Redis readiness, the POAM-023 stub
        # reconciliation guard and the default GOVERNANCE_SALT guard (C-04) run in
        # assert_production_posture() when the governor is assembled
        # (_activate_domain below). NeMo guardrails always fail closed (no log-only
        # mode exists).

        # External Normative Provider integration (§2.5)
        provider_name = os.getenv("CAGE_NORMATIVE_PROVIDER", "static")
        normative_polling_task = None

        if provider_name != "static":
            from src.gateway.governance.normative_provider import (
                NormativeProviderDaemon,
            )

            daemon = NormativeProviderDaemon.from_env()
            await daemon.boot_fetch()
            normative_polling_task = asyncio.create_task(daemon.start_polling())
            app.state.normative_polling_task = normative_polling_task
            logger.info(
                "✅ Normative provider '%s' initialized with background polling",
                provider_name,
            )
        else:
            app.state.normative_polling_task = None

        # ── Attestation Aggregator Boot & Polling ──────────────────────────────
        from src.gateway.governance.attestation_aggregator import AttestationAggregator

        attestation_aggregator = AttestationAggregator.from_env()
        attestation_polling_task = None
        if attestation_aggregator.provider_count > 0:
            await attestation_aggregator.boot_fetch()
            attestation_polling_task = asyncio.create_task(
                attestation_aggregator.start_poll_loop()
            )
            app.state.attestation_aggregator = attestation_aggregator
            app.state.attestation_polling_task = attestation_polling_task
            logger.info(
                "Attestation aggregator initialized with %d provider(s)",
                attestation_aggregator.provider_count,
            )
        else:
            app.state.attestation_aggregator = attestation_aggregator
            app.state.attestation_polling_task = None

        # ── Actuator Registry Initialization ────────────────────────────────────
        from src.gateway.governance.execution_actuator import load_actuators_from_env

        actuator_registry = load_actuators_from_env()
        app.state.actuator_registry = actuator_registry
        logger.info(
            "Actuator registry initialized with %d actuator(s): %s",
            len(actuator_registry.list_actuators()),
            ", ".join(actuator_registry.list_actuators()),
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

        # ── Activate the single CAGE_DOMAIN plugin (fail-closed readiness, ─────
        #    including the OPA package/rule handshake)
        from src.gateway.server.mcp_tool_server import _activate_domain

        governor = await _activate_domain()  # also sets mcp_app.state.governor
        app.state.governor = governor
        governance_app.state.governor = governor

        # ── State-commitment service (POST /governance/state-commitments) ──────
        # Retains sanitized state preimages through the evidence sink above; the
        # gateway itself holds no cold store. Refused here under an enforcing
        # posture when the sink is absent or disconnected.
        from src.gateway.governance.evidence.state_commitment import (
            build_state_commitment_service,
        )

        state_commitments = build_state_commitment_service(evidence_sink)
        app.state.state_commitments = state_commitments
        governance_app.state.state_commitments = state_commitments

        # ── Pre-warm OPA Policy Engine ──────────────────────────────────────────
        logger.info("🔥 Pre-warming OPA policy evaluation...")
        synthetic_params = {
            "action": "system_warmup_test",
            "resource": "test_resource",
            "amount": 100.0,
            "user_id": "system_warmup",
            "dry_run": True,
        }
        try:
            await governor.components.opa.evaluate_policy(synthetic_params)
            logger.info("✅ OPA policy engine pre-warmed successfully")
        except Exception as e:
            logger.warning("⚠️ OPA pre-warm failed (non-blocking): %s", e)

        # The active domain's OPA package/rules are verified fail-closed in
        # _activate_domain() (mcp_tool_server); no domain-specific probe here.

        # ── Start plugin-registered background tasks (PR B, T-B6) ──────────────
        from src.gateway.governance.background_tasks import (
            start_all as start_background_tasks,
        )

        bg_tasks = start_background_tasks()
        app.state.background_tasks = bg_tasks
        logger.info("✅ Plugin background tasks started")

        # ── Bind shared Redis client for GCRA rate limiting (PR A4) ────────────
        from src.gateway.server.rate_limit import (
            build_rate_limit_redis_from_env,
            get_shared_rate_limiter,
        )

        rl_redis = None
        try:
            rl_redis = build_rate_limit_redis_from_env()
            app.state.rate_limit_redis = rl_redis
            governance_app.state.rate_limit_redis = rl_redis
            mcp_app.state.rate_limit_redis = rl_redis
            get_shared_rate_limiter().bind_redis(rl_redis)
        except Exception as rl_exc:
            logger.warning(
                "⚠️ Rate-limit Redis client init failed (using local GCRA fallback): %s",
                rl_exc,
            )

        # ── Shared Redis client & NeMo reload Pub/Sub subscriber (PR A5) ───────
        from src.gateway.governance.quarantine_actuator import bind_quarantine_redis

        shared_redis = _build_shared_redis_from_env()
        app.state.redis = shared_redis
        inference_app.state.redis = shared_redis
        governance_app.state.redis = shared_redis
        mcp_app.state.redis = shared_redis
        bind_quarantine_redis(shared_redis)

        nemo_reload_task = _start_nemo_reload_subscriber(shared_redis, app)
        if nemo_reload_task is not None:
            app.state.nemo_reload_task = nemo_reload_task

        loop_lag_task = asyncio.create_task(run_loop_lag_monitor())
        app.state.loop_lag_task = loop_lag_task
    except BaseException:
        if metrics_server is not None:
            metrics_server.stop()
        raise

    # ── Start Stateless MCP Session Manager (A3) ───────────────────────────
    # Mounted sub-application lifespans do not run automatically in Starlette/FastAPI,
    # so the root lifespan must run mcp.session_manager.run() explicitly.
    from contextlib import AsyncExitStack, nullcontext

    from src.gateway.server.mcp_tool_server import mcp as _mcp_server

    session_mgr = getattr(_mcp_server, "session_manager", None)
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

    # Shutdown: cancel event-loop lag monitor task if running
    if loop_lag_task is not None:
        loop_lag_task.cancel()
        try:
            await loop_lag_task
        except asyncio.CancelledError:
            pass

    # Shutdown: stop out-of-band Prometheus metrics HTTP server if running
    if metrics_server is not None:
        metrics_server.stop()

    # Shutdown: cancel NeMo reload subscriber task if running
    if nemo_reload_task is not None:
        nemo_reload_task.cancel()
        try:
            await nemo_reload_task
        except asyncio.CancelledError:
            pass

    if shared_redis is not None and hasattr(shared_redis, "aclose"):
        try:
            await shared_redis.aclose()
        except Exception as redis_close_exc:
            logger.debug("Shared Redis close error: %s", redis_close_exc)

    # Shutdown: stop Agent Registry daemon if running
    if registry_daemon is not None:
        await registry_daemon.stop()

    # Shutdown: cancel normative provider polling task if running
    if normative_polling_task is not None:
        normative_polling_task.cancel()
        try:
            await normative_polling_task
        except asyncio.CancelledError:
            pass

    # Shutdown: cancel attestation aggregator polling task if running
    attestation_task = getattr(app.state, "attestation_polling_task", None)
    if attestation_task is not None:
        attestation_task.cancel()
        try:
            await attestation_task
        except asyncio.CancelledError:
            pass
        logger.info("Attestation aggregator polling task cancelled cleanly.")

    # Shutdown: cancel plugin-registered background tasks if running
    for bg_task in getattr(app.state, "background_tasks", ()) or ():
        bg_task.cancel()
        try:
            await bg_task
        except asyncio.CancelledError:
            pass

    # Shutdown: close OPA HTTP client pool if present
    opa_client = getattr(getattr(governor, "components", None), "opa", None)
    if opa_client is not None and hasattr(opa_client, "close"):
        import inspect

        close_res = opa_client.close()
        if inspect.isawaitable(close_res):
            await close_res

    # Shutdown: close shared inference proxy HTTP client pool
    from src.gateway.server.inference_proxy import _shutdown_http_client

    await _shutdown_http_client()

    if rl_redis is not None and hasattr(rl_redis, "aclose"):
        try:
            await rl_redis.aclose()
        except Exception as rl_close_exc:
            logger.debug("Rate-limit Redis close error: %s", rl_close_exc)

    from src.gateway.governance.defer_queue import close_shared_defer_queue

    await close_shared_defer_queue()

    if evidence_sink is not None:
        await evidence_sink.stop()

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
        "External REST endpoints removed — use MCP over Streamable HTTP or the internal "
        "/governance/* and /v1/* surfaces."
    ),
    version="0.1.0",
    lifespan=_gateway_lifespan,
)

# M-16: Block /debug/* in non-dev environments
root_app.add_middleware(_DebugEndpointGuard)

# POAM-2026-080: deny by default. Every path except the open list in
# workload_identity.py requires a trusted Linkerd workload identity
# (l5d-client-id). Added last so it runs first, ahead of every mounted app.
# load_identity_policy() raises at import without CAGE_TRUSTED_CLIENT_IDENTITIES,
# so the gateway cannot start unprotected in any environment.
root_app.add_middleware(WorkloadIdentityMiddleware, policy=load_identity_policy())


@root_app.get("/metrics")
async def prometheus_metrics():  # type: ignore[no-untyped-def]
    """Expose Prometheus metrics in-band on port 8080 as well as on the dedicated metrics port."""
    from fastapi.responses import Response as _Response

    try:
        from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

        return _Response(
            content=generate_latest(),
            media_type=CONTENT_TYPE_LATEST,
        )
    except ImportError:
        return _Response(content=b"", media_type="text/plain; version=0.0.4")


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
# NeMo Refinement Proposal/Approval Flow (Gateway-owned NeMo rails, PR A5)
# ---------------------------------------------------------------------------

import asyncio as _asyncio
import uuid as _uuid
from datetime import datetime, timezone

from fastapi import HTTPException
from opentelemetry import trace as _otel_trace
from pydantic import BaseModel as _BaseModel


class NeMoApplyRefinementRequest(_BaseModel):
    """Request body for POST /v1/nemo/apply-refinement and /v1/nemo/propose-refinement."""

    control_id: str
    verdict: str
    source: str = "unknown"


class NeMoApproveRequest(_BaseModel):
    """Request body for POST /v1/nemo/approve-refinement/{proposal_id}."""

    approved: bool
    reviewer: str
    rationale: str


_REFINEMENT_PROPOSALS_REDIS_KEY = "cage:nemo:refinement_proposals"
NEMO_RELOAD_CHANNEL = "cage:nemo:reload"


def _build_shared_redis_from_env() -> Any:
    """Resolve the shared async Redis client via ``build_async_redis`` when configured."""
    from src.gateway.infrastructure.redis_client import build_async_redis

    url = os.environ.get("REDIS_URL", "").strip()
    if not url:
        host = os.environ.get("REDIS_HOST", "").strip()
        if not host:
            return None
        port = os.environ.get("REDIS_PORT", "6379").strip() or "6379"
        scheme = (
            "rediss"
            if os.environ.get("REDIS_TLS", "").lower() in ("true", "1", "yes")
            else "redis"
        )
        url = f"{scheme}://{host}:{port}"
    db = int(os.environ.get("REDIS_DB", "0"))
    try:
        return build_async_redis(url, db=db)
    except Exception as exc:
        logger.warning("⚠️ Shared Redis client init failed: %s", exc)
        return None


def _get_refinement_redis(app_instance: FastAPI | None = None) -> Any:
    """Return the shared async Redis client from ``app.state.redis``."""
    target_app = app_instance or root_app
    state = getattr(target_app, "state", None)
    if state is not None:
        for attr in ("redis", "redis_client"):
            client = getattr(state, attr, None)
            if client is not None:
                return client
        governor = getattr(state, "governor", None)
        components = getattr(governor, "components", None)
        comp_redis = getattr(components, "redis", None)
        if comp_redis is not None:
            return comp_redis
    return None


async def _reload_app_nemo_rails(target_app: FastAPI | None = None) -> Any:
    """Reload NeMo rails off the event loop and update app states.

    Refuses before touching any app state when semantic rails are off, so a
    reload broadcast or an approved refinement cannot build rails the startup
    configuration turned off.

    Raises:
        InferenceBackendUnavailable: under ``CAGE_INFERENCE_BACKEND=none``.
        SemanticRailsDisabled: when ``CAGE_NEMO_ENABLED`` is off.
    """
    from src.gateway.governance.langgraph_harness.nemo_node_factory import (
        get_nemo_rails,
        reload_nemo_rails,
    )
    from src.gateway.governance.semantic_rail_factory import (
        refuse_unless_semantic_rails_enabled,
    )

    refuse_unless_semantic_rails_enabled()
    await reload_nemo_rails()
    new_rails = get_nemo_rails()
    app_obj = target_app or root_app
    app_obj.state.nemo_rails = new_rails
    inference_app.state.nemo_rails = new_rails
    mcp_app.state.nemo_rails = new_rails
    return new_rails


def _start_nemo_reload_subscriber(
    redis_client: Any, target_app: FastAPI | None = None
) -> _asyncio.Task[None] | None:
    """Start the ``cage:nemo:reload`` subscriber, or return ``None``.

    Starts it only when semantic rails may be built and the client supports
    Pub/Sub. With rails off there is nothing to reload, and a subscriber
    would rebuild them on the first broadcast.
    """
    from src.gateway.governance.semantic_rail_factory import semantic_rails_refusal

    if redis_client is None or not hasattr(redis_client, "pubsub"):
        return None
    refusal = semantic_rails_refusal()
    if refusal is not None:
        logger.info("[NeMo/Refinement] Reload subscriber not started (%s).", refusal[0])
        return None
    return _asyncio.create_task(_subscribe_nemo_reload(redis_client, target_app))


async def _subscribe_nemo_reload(
    redis_client: Any, target_app: FastAPI | None = None
) -> None:
    """Subscribe to ``cage:nemo:reload`` and reload NeMo rails off the loop on each message."""
    pubsub = redis_client.pubsub()
    try:
        sub_res = pubsub.subscribe(NEMO_RELOAD_CHANNEL)
        if _asyncio.iscoroutine(sub_res) or hasattr(sub_res, "__await__"):
            await sub_res
        while True:
            msg_res = pubsub.get_message(ignore_subscribe_messages=True, timeout=0.25)
            msg = (
                await msg_res
                if (_asyncio.iscoroutine(msg_res) or hasattr(msg_res, "__await__"))
                else msg_res
            )
            if isinstance(msg, dict) and msg.get("type") == "message":
                try:
                    await _reload_app_nemo_rails(target_app)
                    logger.info(
                        "[NeMo/Refinement] Reloaded NeMo rails from %s broadcast",
                        NEMO_RELOAD_CHANNEL,
                    )
                except Exception as exc:
                    logger.error("[NeMo/Refinement] Broadcast reload failed: %s", exc)
            else:
                await _asyncio.sleep(0.05)
    except _asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.debug("[NeMo/Refinement] PubSub subscriber exited: %s", exc)
    finally:
        try:
            unsub_res = pubsub.unsubscribe(NEMO_RELOAD_CHANNEL)
            if _asyncio.iscoroutine(unsub_res) or hasattr(unsub_res, "__await__"):
                await unsub_res
            if hasattr(pubsub, "aclose"):
                aclose_res = pubsub.aclose()
                if _asyncio.iscoroutine(aclose_res) or hasattr(aclose_res, "__await__"):
                    await aclose_res
            elif hasattr(pubsub, "close"):
                res = pubsub.close()
                if _asyncio.iscoroutine(res):
                    await res
        except Exception as exc:
            logger.debug("[NeMo/Refinement] PubSub cleanup error: %s", exc)


async def _save_refinement_proposal(
    proposal: dict[str, Any], app_instance: FastAPI | None = None
) -> None:
    """Persist a NeMo refinement proposal to Redis only."""
    proposal_id = str(proposal["proposal_id"])
    redis_client = _get_refinement_redis(app_instance)
    if redis_client is None or not hasattr(redis_client, "hset"):
        raise HTTPException(
            status_code=503,
            detail="Shared Redis backend unavailable for NeMo refinement proposals.",
        )
    try:
        await redis_client.hset(
            _REFINEMENT_PROPOSALS_REDIS_KEY,
            proposal_id,
            json.dumps(proposal),
        )
    except Exception as exc:
        logger.error(
            "[NeMo/Refinement] Failed to persist proposal %s to Redis: %s",
            proposal_id,
            exc,
        )
        raise HTTPException(
            status_code=503,
            detail="Failed to persist NeMo refinement proposal to Redis.",
        ) from exc


async def _load_refinement_proposal(
    proposal_id: str, app_instance: FastAPI | None = None
) -> dict[str, Any] | None:
    """Load a NeMo refinement proposal from Redis only."""
    redis_client = _get_refinement_redis(app_instance)
    if redis_client is None or not hasattr(redis_client, "hget"):
        raise HTTPException(
            status_code=503,
            detail="Shared Redis backend unavailable for NeMo refinement proposals.",
        )
    try:
        raw = await redis_client.hget(_REFINEMENT_PROPOSALS_REDIS_KEY, proposal_id)
        if raw:
            loaded = json.loads(raw if isinstance(raw, str) else raw.decode("utf-8"))
            if isinstance(loaded, dict):
                return loaded
    except Exception as exc:
        logger.error(
            "[NeMo/Refinement] Failed to load proposal %s from Redis: %s",
            proposal_id,
            exc,
        )
        raise HTTPException(
            status_code=503,
            detail="Failed to read NeMo refinement proposal from Redis.",
        ) from exc
    return None


@root_app.post("/v1/nemo/propose-refinement")
async def propose_nemo_refinement(
    request: Request, req: NeMoApplyRefinementRequest
) -> dict[str, Any]:
    """Stage a NeMo Guardrails refinement proposal for human review."""
    from src.gateway.server.workload_identity import extract_client_identity

    try:
        proposer_identity = extract_client_identity(request.scope)
    except ValueError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    proposal_id = str(_uuid.uuid4())
    proposal = {
        "proposal_id": proposal_id,
        "control_id": req.control_id,
        "verdict": req.verdict,
        "source": req.source,
        "proposer_identity": proposer_identity,
        "staged_at": datetime.now(timezone.utc).isoformat(),
        "status": "staged",
        "reviewer": None,
        "approver_identity": None,
        "rationale": None,
    }
    await _save_refinement_proposal(proposal, request.app)

    logger.info(
        "[NeMo/Refinement] Proposal STAGED: id=%s control_id=%s source=%s proposer=%s",
        proposal_id,
        req.control_id,
        req.source,
        proposer_identity,
    )

    current_span = _otel_trace.get_current_span()
    if current_span and current_span.is_recording():
        current_span.set_attribute("ai.refinement.proposal_id", proposal_id)
        current_span.set_attribute("ai.refinement.apply.control_id", req.control_id)
        current_span.set_attribute("ai.refinement.apply.source", req.source)
        current_span.set_attribute("ai.refinement.proposer_identity", proposer_identity)
        current_span.set_attribute("ai.refinement.status", "staged")

    return {
        "status": "staged",
        "proposal_id": proposal_id,
        "control_id": req.control_id,
        "proposer_identity": proposer_identity,
        "message": (
            "Refinement proposal staged. A risk officer must approve via "
            f"POST /v1/nemo/approve-refinement/{proposal_id}"
        ),
    }


@root_app.post("/v1/nemo/approve-refinement/{proposal_id}")
async def approve_nemo_refinement(
    proposal_id: str,
    req: NeMoApproveRequest,
    request: Request,
) -> dict[str, Any]:
    """Approve or reject a staged NeMo refinement proposal and reload gateway NeMo rails."""
    from src.gateway.server.workload_identity import extract_client_identity

    try:
        approver_identity = extract_client_identity(request.scope)
    except ValueError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    allowed_approvers_raw = os.environ.get("CAGE_NEMO_APPROVER_IDENTITIES", "").strip()
    if allowed_approvers_raw:
        allowed_approvers = {
            part.strip() for part in allowed_approvers_raw.split(",") if part.strip()
        }
        if approver_identity not in allowed_approvers:
            raise HTTPException(
                status_code=403,
                detail="Forbidden: caller workload identity is not authorized to approve NeMo refinements.",
            )

    reviewer = req.reviewer.strip() if req.reviewer else ""
    if not reviewer:
        raise HTTPException(
            status_code=400,
            detail="reviewer is required — provide the risk officer identity approving or rejecting this proposal.",
        )

    if not req.rationale or not req.rationale.strip():
        raise HTTPException(
            status_code=400,
            detail="rationale is required — provide the business justification "
            "for this governance configuration change.",
        )

    proposal = await _load_refinement_proposal(proposal_id, request.app)
    if proposal is None or proposal["status"] != "staged":
        raise HTTPException(
            status_code=404,
            detail=f"Proposal '{proposal_id}' not found or already processed.",
        )

    proposer_identity = proposal.get("proposer_identity")
    if proposer_identity and approver_identity == proposer_identity:
        raise HTTPException(
            status_code=403,
            detail=(
                "Separation-of-duties violation: the workload identity that staged "
                "a NeMo refinement proposal cannot approve or reject its own proposal."
            ),
        )

    proposal["reviewer"] = reviewer
    proposal["approver_identity"] = approver_identity
    proposal["rationale"] = req.rationale.strip()
    proposal["reviewed_at"] = datetime.now(timezone.utc).isoformat()

    if not req.approved:
        proposal["status"] = "rejected"
        await _save_refinement_proposal(proposal, request.app)
        logger.info(
            "[NeMo/Refinement] Proposal REJECTED: id=%s reviewer=%s approver_identity=%s",
            proposal_id,
            reviewer,
            approver_identity,
        )
        return {
            "status": "rejected",
            "proposal_id": proposal_id,
            "reviewer": reviewer,
            "approver_identity": approver_identity,
        }

    # Applying a refinement rebuilds the rails. When they are off by
    # configuration, refuse before saving anything: the proposal stays
    # ``staged`` (nothing failed) and can be applied once the rails are on.
    from src.gateway.governance.semantic_rail_factory import semantic_rails_refusal

    rails_refusal = semantic_rails_refusal()
    if rails_refusal is not None:
        reason_code, detail = rails_refusal
        logger.info(
            "[NeMo/Refinement] Proposal NOT APPLIED: id=%s reason_code=%s",
            proposal_id,
            reason_code,
        )
        raise HTTPException(
            status_code=409,
            detail={
                "reason_code": reason_code,
                "message": f"NeMo refinement not applied: {detail}",
                "proposal_id": proposal_id,
                "status": "staged",
            },
        )

    try:
        await _reload_app_nemo_rails(request.app)
        proposal["status"] = "applied"
        await _save_refinement_proposal(proposal, request.app)
        redis_client = _get_refinement_redis(request.app)
        if redis_client is not None and hasattr(redis_client, "publish"):
            await redis_client.publish(
                NEMO_RELOAD_CHANNEL,
                json.dumps(
                    {
                        "proposal_id": proposal_id,
                        "control_id": proposal["control_id"],
                        "applied_at": proposal["reviewed_at"],
                    }
                ),
            )
        logger.info(
            "[NeMo/Refinement] Proposal APPLIED: id=%s reviewer=%s approver_identity=%s control_id=%s",
            proposal_id,
            reviewer,
            approver_identity,
            proposal["control_id"],
        )
    except Exception as exc:
        proposal["status"] = "apply_failed"
        await _save_refinement_proposal(proposal, request.app)
        logger.error("[NeMo/Refinement] Rails reload failed after approval: %s", exc)
        raise HTTPException(
            status_code=500,
            detail=f"NeMo rails reload failed: {exc}",
        ) from exc

    return {
        "status": "applied",
        "proposal_id": proposal_id,
        "control_id": proposal["control_id"],
        "reviewer": reviewer,
        "approver_identity": approver_identity,
    }


@root_app.get("/v1/nemo/proposals/pending")
async def list_pending_nemo_proposals(request: Request) -> dict[str, Any]:
    """List all staged NeMo refinement proposals awaiting human review."""
    redis_client = _get_refinement_redis(request.app)
    if redis_client is None or not hasattr(redis_client, "hgetall"):
        raise HTTPException(
            status_code=503,
            detail="Shared Redis backend unavailable for NeMo refinement proposals.",
        )
    pending: list[dict[str, Any]] = []
    try:
        raw_map = await redis_client.hgetall(_REFINEMENT_PROPOSALS_REDIS_KEY)
        if isinstance(raw_map, dict):
            for raw_val in raw_map.values():
                val_str = (
                    raw_val if isinstance(raw_val, str) else raw_val.decode("utf-8")
                )
                loaded = json.loads(val_str)
                if isinstance(loaded, dict) and loaded.get("status") == "staged":
                    pending.append(loaded)
    except Exception as exc:
        logger.error("[NeMo/Refinement] Failed to list proposals from Redis: %s", exc)
        raise HTTPException(
            status_code=503,
            detail="Failed to list NeMo refinement proposals from Redis.",
        ) from exc
    return {"pending": pending, "count": len(pending)}


@root_app.post("/v1/nemo/apply-refinement")
async def apply_nemo_refinement(
    request: Request, req: NeMoApplyRefinementRequest
) -> dict[str, Any]:
    """Stage a NeMo refinement proposal and return pending_approval."""
    from src.gateway.server.workload_identity import extract_client_identity

    try:
        proposer_identity = extract_client_identity(request.scope)
    except ValueError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    logger.info(
        "[NeMo/Refinement] Routing to proposal flow. control_id=%s source=%s proposer=%s",
        req.control_id,
        req.source,
        proposer_identity,
    )

    proposal_id = str(_uuid.uuid4())
    proposal = {
        "proposal_id": proposal_id,
        "control_id": req.control_id,
        "verdict": req.verdict,
        "source": req.source,
        "proposer_identity": proposer_identity,
        "staged_at": datetime.now(timezone.utc).isoformat(),
        "status": "staged",
        "reviewer": None,
        "approver_identity": None,
        "rationale": None,
    }
    await _save_refinement_proposal(proposal, request.app)

    current_span = _otel_trace.get_current_span()
    if current_span and current_span.is_recording():
        current_span.set_attribute("ai.refinement.apply.control_id", req.control_id)
        current_span.set_attribute("ai.refinement.apply.source", req.source)
        current_span.set_attribute("ai.refinement.proposer_identity", proposer_identity)
        current_span.set_attribute("ai.refinement.proposal_id", proposal_id)

    return {
        "status": "pending_approval",
        "proposal_id": proposal_id,
        "control_id": req.control_id,
        "proposer_identity": proposer_identity,
        "message": (
            "Refinement proposal staged. A risk officer must "
            f"approve via POST /v1/nemo/approve-refinement/{proposal_id}"
        ),
    }


# Inference proxy handles /v1/chat/completions
root_app.mount("/inference", inference_app)

# Governance middleware handles /governance/validate-action
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


def run_gateway_server(host: str = "0.0.0.0", port: int | None = None) -> None:
    """Start the CAGE Hybrid Gateway on uvloop and httptools."""
    import uvicorn

    os.environ.setdefault(
        "SERVICE_NAME", os.getenv("OTEL_SERVICE_NAME", "hybrid-gateway")
    )
    configure_telemetry()
    http_port = port if port is not None else int(os.getenv("PORT", "8080"))
    logging.basicConfig(level=logging.INFO)
    uvicorn.run(
        root_app,
        host=host,
        port=http_port,
        loop="uvloop",
        http="httptools",
    )


if __name__ == "__main__":
    run_gateway_server()
