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

import logging
import os
import traceback
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

from contextlib import asynccontextmanager

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from langgraph.types import Command
from opentelemetry import trace
from pydantic import BaseModel, model_validator

try:
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

    _FASTAPI_INSTRUMENTOR_AVAILABLE = True
except ImportError:
    FastAPIInstrumentor = None  # type: ignore[assignment,misc]
    _FASTAPI_INSTRUMENTOR_AVAILABLE = False

try:
    from opentelemetry.instrumentation.langchain import LangchainInstrumentor

    _LANGCHAIN_INSTRUMENTOR_AVAILABLE = True
except ImportError:
    LangchainInstrumentor = None  # type: ignore[assignment,misc]
    _LANGCHAIN_INSTRUMENTOR_AVAILABLE = False

from config.settings import Config
from src.gateway.infrastructure.mcp_client import get_mcp_client
from src.gateway.infrastructure.telemetry_client import configure_telemetry
from src.gateway.observability.attributes import (
    AI_WEBHOOK_COOLDOWN_ACTIVE,
    AI_WEBHOOK_COOLDOWN_SECONDS_REMAINING,
    AI_WEBHOOK_SCORE_NAME,
    AI_WEBHOOK_SCORE_VALUE,
    AI_WEBHOOK_TRACE_ID,
    OBSERVATION_TYPE,
    SPAN_ATTR_CAGE_PRINCIPAL_VERIFIED,
    SPAN_ATTR_CONTENT_INPUT_LENGTH,
    SPAN_ATTR_CONTENT_OUTPUT_LENGTH,
    SPAN_ATTR_THREAD_ID,
    WEBHOOK_THRESHOLD_BREACH,
)
from src.governed_financial_advisor.graph.checkpointer import CheckpointDurabilityError
from src.governed_financial_advisor.graph.graph import create_graph
from src.governed_financial_advisor.infrastructure.auth import (
    ADVISOR_DEFAULT_THREAD_PREFIX,
    CallerCredentialKind,
    require_api_key_or_user_token,
    require_service_api_key,
    require_thread_owner,
    resolve_request_principal,
)
from src.governed_financial_advisor.models.principal import (
    PRINCIPAL_MAX_LEN,
    PRINCIPAL_PATTERN,
)
from src.governed_financial_advisor.models.query import QueryRequest, QueryResponse
from src.governed_financial_advisor.utils.context import (
    principal_verified_context,
    user_context,
)

# Observability
ENABLE_TRACING = os.environ.get("ENABLE_TRACING", "true").lower() == "true"

if ENABLE_TRACING:
    configure_telemetry()
    if _LANGCHAIN_INSTRUMENTOR_AVAILABLE and LangchainInstrumentor is not None:
        LangchainInstrumentor().instrument()  # Traces Graph nodes (including Agent calls)


# --- LIFESPAN (Startup/Shutdown) ---
@asynccontextmanager
async def lifespan(app: FastAPI):  # type: ignore[no-untyped-def]
    # Startup: refuse to run with any signing identity (POAM-2026-079). The
    # advisor is an untrusted client of the gateway; it hosts no governor.
    import asyncio

    from src.gateway.governance.pii_redactor_factory import ensure_pii_engines
    from src.gateway.observability.langfuse_utils import get_prompt_registry
    from src.governed_financial_advisor.infrastructure.identity_guard import (
        assert_no_signing_identity,
    )

    assert_no_signing_identity()

    # Warm Presidio PII engines off the event loop and pre-populate PromptRegistry
    await asyncio.to_thread(ensure_pii_engines)
    prompt_registry = get_prompt_registry()
    try:
        await prompt_registry.start()
        logger.info("✅ PromptRegistry warmed and background refresh started")
    except Exception as _prompt_exc:
        logger.warning(
            "⚠️ PromptRegistry startup refresh failed (using static fallbacks): %s",
            _prompt_exc,
        )

    logger.info("Initializing Agent Graph...")
    from src.gateway.governance.env_posture import is_enforcing
    from src.governed_financial_advisor.graph.checkpointer import (
        CheckpointDurabilityError,
        GatewayCheckpointSaver,
    )

    app.state.graph = create_graph()
    cp = getattr(app.state.graph, "checkpointer", None)
    if isinstance(cp, GatewayCheckpointSaver):
        await cp.verify_ready()
        logger.info(
            "✅ GatewayCheckpointSaver verified (ttl_seconds=%s)", cp.ttl_seconds
        )
    elif is_enforcing():
        raise CheckpointDurabilityError(
            "Enforcing posture requires durable GatewayCheckpointSaver; refusing startup"
        )

    logger.info("Agent Graph Initialized")
    yield
    # Shutdown
    logger.info("Shutting down...")
    try:
        await prompt_registry.stop()
    except Exception as exc:
        logger.debug("PromptRegistry stop error: %s", exc)
    await get_mcp_client().close()
    if isinstance(cp, GatewayCheckpointSaver):
        try:
            await cp.aclose()
        except Exception as exc:
            logger.debug("GatewayCheckpointSaver close error: %s", exc)


app = FastAPI(
    title="Governed Financial Advisor (Graph Orchestrated)", lifespan=lifespan
)


def server_request_hook(span, scope):  # type: ignore[no-untyped-def]
    if not span or not span.is_recording():
        return

    method = scope.get("method", "GET").upper()
    path = scope.get("path", "/")
    span.update_name(f"{method} {path}")


if (
    ENABLE_TRACING
    and _FASTAPI_INSTRUMENTOR_AVAILABLE
    and FastAPIInstrumentor is not None
):
    FastAPIInstrumentor.instrument_app(
        app,
        server_request_hook=server_request_hook,
        excluded_urls="health,docs,openapi.json,favicon.ico,mcp",
    )  # Only trace meaningful agent routes; health/docs/scanners are excluded
# The advisor exposes no tool-dispatch route. Governed tools run in the gateway,
# whose own /tools/execute and /mcp admit only trusted workload identities; the
# advisor reaches them only from inside the graph after /agent/query has verified
# the end user's principal and thread ownership.

if (
    os.environ.get("CAGE_ENV", "prod").lower() == "dev"
):  # Default to "prod" to fail-secure: missing CAGE_ENV must not silently disable enforcement
    from src.governed_financial_advisor.demo.router import demo_router

    app.include_router(demo_router)
    logger.warning("Demo endpoints enabled — do not use in production")
# Graph is now in app.state.graph


from src.governed_financial_advisor.graph.nodes.approval_contract import (
    ApprovalDecision as ApprovalResumeRequest,
)

# Deprecated class definition removed. Use ApprovalDecision directly.


class RefinementTriggerRequest(BaseModel):
    """Request body for POST /v1/refinement/trigger (R-17).

    Attributes:
        pipeline_id:    Identifier of the KFP pipeline to trigger.
        trigger_reason: Human-readable reason for triggering the refinement run.
        trace_ids:      List of Langfuse / OTel trace IDs that motivated this run.
    """

    pipeline_id: str
    trigger_reason: str
    trace_ids: list[str] = []


class LangfuseWebhookEvent(BaseModel):
    """Payload shape for Langfuse outgoing webhook events.

    Langfuse fires webhook POSTs when a score event matching the configured
    filter is created.  We only act on ``score`` events whose name is
    ``iso_42001_safety_rate`` and whose numeric value drops below the
    configured ``NEMO_SAFETY_THRESHOLD`` (default 0.95).

    All other event types are acknowledged (HTTP 200) and ignored so that
    Langfuse doesn't retry them indefinitely.

    See: https://langfuse.com/docs/scores/webhooks
    """

    type: str  # e.g. "score-created", "trace-created"
    # Score-specific fields — present only when type == "score-created"
    name: str = ""
    value: float = 0.0
    traceId: str = ""
    data: dict = {}  # full event payload for forwarding as a trace_id


@app.get("/")
def read_root():  # type: ignore[no-untyped-def]
    return {"status": "ok", "message": "Governed Financial Advisor API"}


@app.get("/health")
async def health_check(request: Request):  # type: ignore[no-untyped-def]
    from src.gateway.governance.env_posture import is_enforcing
    from src.governed_financial_advisor.graph.checkpointer import (
        GatewayCheckpointSaver,
        checkpointer_type_of,
        get_checkpointer_type,
    )

    graph = getattr(request.app.state, "graph", None)
    cp = getattr(graph, "checkpointer", None) if graph is not None else None
    cp_type = checkpointer_type_of(cp) if cp is not None else get_checkpointer_type()
    durable = cp_type == "gateway"

    if is_enforcing() and not durable:
        return JSONResponse(
            status_code=503,
            content={
                "status": "unhealthy",
                "reason": "non_durable_checkpointer",
                "service": "financial-advisor-graph-agent",
                "project_id": Config.GOOGLE_CLOUD_PROJECT,
                "checkpointer": cp_type,
                "durable": False,
            },
        )

    if isinstance(cp, GatewayCheckpointSaver):
        try:
            await cp.verify_ready()
        except Exception as exc:
            logger.error("/health gateway checkpointer probe failed: %s", exc)
            return JSONResponse(
                status_code=503,
                content={
                    "status": "unhealthy",
                    "reason": "gateway_checkpointer_unreachable",
                    "service": "financial-advisor-graph-agent",
                    "project_id": Config.GOOGLE_CLOUD_PROJECT,
                    "checkpointer": cp_type,
                    "durable": False,
                },
            )

    payload: dict[str, object] = {
        "status": "ok",
        "service": "financial-advisor-graph-agent",
        "project_id": Config.GOOGLE_CLOUD_PROJECT,
        "checkpointer": cp_type,
        "durable": durable,
    }
    if isinstance(cp, GatewayCheckpointSaver) and cp.ttl_seconds is not None:
        payload["checkpoint_ttl_seconds"] = cp.ttl_seconds
    return payload


@app.post("/agent/query", response_model=QueryResponse)
async def query_agent(  # type: ignore[no-untyped-def]
    req: QueryRequest,
    request: Request,
    _auth: CallerCredentialKind = Depends(require_api_key_or_user_token),
):
    """
    Main agent query endpoint.

    The only route that accepts an end-user OIDC JWT as its credential
    (:func:`require_api_key_or_user_token`); every other route is service-only.

    NeMo guardrails are enforced exclusively inside the LangGraph:
      - ``nemo_guardrail_node``    : mandatory first node — input rail
      - ``nemo_output_rail_node``  : mandatory last node  — output rail + PII mask

    This endpoint does NOT duplicate those guardrail calls.  The graph is the
    single source of truth for guardrail enforcement, which avoids:
      - double-blocking (guardrail node blocks → server tries to mask user input)
      - CAGE_SEAL_ENFORCEMENT inconsistency between HTTP layer and graph layer
    """
    principal = resolve_request_principal(request, req.user_id)
    effective_thread_id = req.thread_id or f"advisor_session_{principal.user_id}"
    try:
        await require_thread_owner(
            request.app.state.graph, effective_thread_id, principal.user_id
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except CheckpointDurabilityError as exc:
        logger.error("Checkpoint store unavailable during thread-owner check: %s", exc)
        raise HTTPException(
            status_code=503,
            detail={"error": "checkpoint_store_unavailable", "detail": str(exc)},
        ) from exc
    token = user_context.set(principal.user_id)
    verified_token = principal_verified_context.set(principal.verified)
    try:
        # The span never carries the prompt, the response or the end-user
        # identifier: anything exported reaches the retention-locked telemetry
        # event bucket. It records whether the principal was verified and the
        # content lengths instead.
        current_span = trace.get_current_span()
        trace_id = None
        if current_span and current_span.is_recording():
            current_span.set_attribute(
                SPAN_ATTR_CAGE_PRINCIPAL_VERIFIED, principal.verified
            )
            if not effective_thread_id.startswith(ADVISOR_DEFAULT_THREAD_PREFIX):
                # A default (advisor_session_<user_id>) thread id embeds the
                # user id, so only another thread id is recorded.
                current_span.set_attribute(SPAN_ATTR_THREAD_ID, effective_thread_id)
            current_span.set_attribute(OBSERVATION_TYPE, "generation")
            current_span.set_attribute("gen_ai.operation.name", "chat")
            current_span.set_attribute(SPAN_ATTR_CONTENT_INPUT_LENGTH, len(req.prompt))
            current_span.set_attribute("gen_ai.system", "financial-advisor-gateway")
            ctx = current_span.get_span_context()
            if ctx.trace_flags.sampled:
                trace_id = f"{ctx.trace_id:032x}"

        # Query Cache Layer (2026-03-14) — Intelligent caching for educational queries
        # Only caches deterministic responses (definitions, regulations, concepts).
        # Market data and personalized advice are NEVER cached.
        from config.settings import Config as _Config
        from src.governed_financial_advisor.infrastructure.query_cache import (
            get_query_cache,
        )

        query_cache = await get_query_cache(
            redis_client=None
        )  # Will use Redis if available

        # Build governance context for cache key (M-01: prevent stale governance decisions)
        _governance_context = {
            "risk_threshold": getattr(_Config, "RISK_THRESHOLD", None),
            "safety_threshold": os.environ.get("NEMO_SAFETY_THRESHOLD", "0.95"),
            "cage_env": os.environ.get(
                "CAGE_ENV", "prod"
            ),  # Default to "prod" to fail-secure: missing CAGE_ENV must not silently disable enforcement
            "thread_id": effective_thread_id,
        }

        # Check cache first (only for cacheable query types)
        # Governance context included in cache key to prevent stale decisions
        cached_response = await query_cache.get(
            req.prompt, governance_context=_governance_context
        )
        if cached_response:
            logger.info(
                "Cache HIT - returning cached response (skipping graph execution)"
            )
            final_response_text = cached_response
            # Still record telemetry for cache hits
            if current_span and current_span.is_recording():
                current_span.set_attribute("gen_ai.system", "langchain")
                current_span.set_attribute("gen_ai.request.model", "cached")
                current_span.set_attribute(
                    SPAN_ATTR_CONTENT_OUTPUT_LENGTH, len(cached_response)
                )
                current_span.set_attribute("cache.hit", True)

            return {"response": final_response_text, "trace_id": trace_id}

        # Cache miss or non-cacheable query - execute full graph
        logger.debug("Cache MISS or non-cacheable - executing full governance pipeline")

        # Graph Execution — guardrails are enforced inside the graph nodes.
        # Wrap graph.ainvoke() in asyncio.wait_for() with a hard wall-clock
        # deadline.  Default is 240 s (overridable via GRAPH_TIMEOUT_SECONDS)
        # to accommodate complex multi-step governance chains (OPA + NeMo +
        # vLLM reasoning) on spot-pool nodes that may have cold-start latency.
        # The primary cap (litellm timeout in vllm_client.py) limits individual
        # LLM calls; this is the secondary safety net for the full graph.
        import asyncio as _asyncio

        _GRAPH_TIMEOUT_SECONDS = float(os.environ.get("GRAPH_TIMEOUT_SECONDS", "240"))
        logger.debug("Invoking Graph with prompt '%s'", req.prompt)
        try:
            res = await _asyncio.wait_for(
                request.app.state.graph.ainvoke(
                    {"messages": [("user", req.prompt)], "user_id": principal.user_id},
                    {
                        "recursion_limit": 100,
                        "configurable": {"thread_id": effective_thread_id},
                    },
                ),
                timeout=_GRAPH_TIMEOUT_SECONDS,
            )
        except _asyncio.TimeoutError:
            logger.error(
                "graph.ainvoke exceeded %.0fs deadline for prompt %r — returning timeout error",
                _GRAPH_TIMEOUT_SECONDS,
                req.prompt[:80],
            )
            raise HTTPException(
                status_code=504,
                detail=(
                    f"The governance engine did not respond within "
                    f"{int(_GRAPH_TIMEOUT_SECONDS)} seconds. "
                    "Please try a simpler query or retry later."
                ),
            )
        logger.debug("Graph result keys: %s", res.keys() if res else "None")

        # Extract the final response.  When the guardrail node blocks, the graph
        # terminates early via END without adding an AI message — the last message
        # is the user input.  In that case we surface the guardrail reason instead.
        messages = res.get("messages", []) if res else []
        if messages:
            last_msg = messages[-1]
            if hasattr(last_msg, "content"):
                final_response_text = str(last_msg.content)
            elif isinstance(last_msg, dict):
                final_response_text = str(last_msg.get("content", ""))
            elif isinstance(last_msg, tuple) and len(last_msg) >= 2:
                final_response_text = str(last_msg[1])
            else:
                final_response_text = str(last_msg)
        else:
            final_response_text = "No response generated."

        # If the guardrail blocked the request, return a safe user-facing message.
        if res and res.get("guardrail_blocked"):
            reason = res.get("guardrail_reason", "")
            logger.warning("nemo_guardrail blocked request — reason: %s", reason)
            final_response_text = (
                "I'm sorry, I can't assist with that request."
                if not reason or reason == final_response_text
                else reason
            )
        elif not res or res.get("safety_status") in (None, "APPROVED", "SKIPPED"):
            # Cache successful responses (only if query was cacheable)
            # Blocked, deferred, hard-paused, and gateway-error responses are not cached
            await query_cache.set(
                req.prompt, final_response_text, governance_context=_governance_context
            )

        if current_span and current_span.is_recording():
            current_span.set_attribute("gen_ai.system", "langchain")
            current_span.set_attribute(
                "gen_ai.request.model",
                os.environ.get("VLLM_REASONING_MODEL", "unknown"),
            )
            current_span.set_attribute(
                SPAN_ATTR_CONTENT_OUTPUT_LENGTH, len(final_response_text)
            )

        return {"response": final_response_text, "trace_id": trace_id}

    except HTTPException:
        # Re-raise HTTPException (e.g. 504 timeout) without wrapping in 500.
        raise
    except CheckpointDurabilityError as exc:
        logger.error("Checkpoint store unavailable during graph execution: %s", exc)
        raise HTTPException(
            status_code=503,
            detail={"error": "checkpoint_store_unavailable", "detail": str(exc)},
        ) from exc
    except Exception as e:
        logger.error("Error invoking agent graph: %s", e)
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        principal_verified_context.reset(verified_token)
        user_context.reset(token)


# ---------------------------------------------------------------------------
# Approval endpoints (Phase 1b — LangGraph interrupt / Command)
# ---------------------------------------------------------------------------

#: Interrupt payload fields the owner of a pending approval sees. Gateway
#: deferral handles (``deferred_id``, ``defer_id``) are never included at any
#: depth: they belong to reviewers at the compliance bridge
#: (``GET /v1/defer/pending``, ``POST /v1/defer/{deferred_id}/escalate``), not
#: to the end user.
_PENDING_APPROVAL_FIELDS: tuple[str, ...] = (
    "reason",
    "trade",
    "timestamp",
    "expires_at",
    "ctrl_id",
    "ftra_result",
)
_REDACTED_DEFER_KEYS: frozenset[str] = frozenset({"deferred_id", "defer_id"})


def _without_deferred_ids(value: Any) -> Any:
    """Return ``value`` with every nested ``deferred_id`` / ``defer_id`` key removed."""
    if isinstance(value, Mapping):
        return {
            key: _without_deferred_ids(item)
            for key, item in value.items()
            if key not in _REDACTED_DEFER_KEYS
        }
    if isinstance(value, list):
        return [_without_deferred_ids(item) for item in value]
    return value


def _pending_approval_view(payload: Any) -> dict[str, Any]:
    """The part of an approval interrupt payload its owner may see."""
    if not isinstance(payload, Mapping):
        return {}
    return {
        field: _without_deferred_ids(payload[field])
        for field in _PENDING_APPROVAL_FIELDS
        if field in payload
    }


@app.get("/v1/approvals/pending")
async def list_pending_approvals(  # type: ignore[no-untyped-def]
    request: Request,
    user_id: str = Query(
        min_length=1,
        max_length=PRINCIPAL_MAX_LEN,
        pattern=PRINCIPAL_PATTERN,
        description="End-user principal whose pending approvals are listed.",
    ),
    _auth: CallerCredentialKind = Depends(require_service_api_key),
):
    """
    List one end user's graph threads that are interrupted awaiting human approval.

    Service-only: the caller authenticates with ``CAGE_API_KEY``
    (:func:`require_service_api_key`), never with an end-user token. The
    listing is scoped to the end-user principal the service acts for, resolved
    as ``POST /agent/query`` resolves it (:func:`resolve_request_principal`):
    in an enforcing posture that is a verified ``X-CAGE-User-Token`` whose
    subject must equal ``user_id``. Only threads whose checkpoint ``user_id``
    is that principal are listed, and no entry carries the gateway
    ``deferred_id``. Reviewers find and approve deferrals at the compliance
    bridge (``GET /v1/defer/pending``).

    Iterates over stored checkpoints via the graph's checkpointer and filters
    for threads whose state snapshot has a non-empty ``next`` step AND contains
    interrupt payloads. Every snapshot is read, including other principals',
    so a checkpoint store failure is never reported as an empty listing.

    Returns:
        {"pending": [{"thread_id": str, "interrupt_payload": dict, "interrupted_at": str}, ...]}
    """
    principal = resolve_request_principal(request, user_id)
    graph = request.app.state.graph
    checkpointer = graph.checkpointer

    pending: list[dict] = []

    try:
        # list_namespaces / list are synchronous on MemorySaver;
        # AsyncRedisSaver exposes alist_checkpoints.  We try both.
        checkpoints_iter = None
        if hasattr(checkpointer, "alist"):
            # AsyncRedisSaver / any async checkpointer
            checkpoints_iter = checkpointer.alist(None, limit=500)
        elif hasattr(checkpointer, "list"):
            checkpoints_iter = checkpointer.list(None, limit=500)

        if checkpoints_iter is None:
            return {"pending": []}

        seen_threads: set[str] = set()

        async def _iter():  # type: ignore[no-untyped-def]
            if hasattr(checkpoints_iter, "__aiter__"):
                async for cp in checkpoints_iter:
                    yield cp
            else:
                for cp in checkpoints_iter:
                    yield cp

        async for checkpoint_tuple in _iter():
            thread_id: str = (
                checkpoint_tuple.config.get("configurable", {}).get("thread_id", "")
                if checkpoint_tuple.config
                else ""
            )
            if not thread_id or thread_id in seen_threads:
                continue
            seen_threads.add(thread_id)

            # Fetch the current state snapshot for this thread. Never swallow
            # checkpointer or state-read failures: returning HTTP 200 with a
            # partial list would under-report pending human approvals (POAM-2026-226).
            config = {"configurable": {"thread_id": thread_id}}
            snapshot = await graph.aget_state(config)

            if snapshot is None:
                continue
            owner = (
                snapshot.values.get("user_id")
                if isinstance(snapshot.values, Mapping)
                else None
            )
            if owner != principal.user_id:
                continue

            # Filter: must be interrupted (has next step) with interrupt payloads
            interrupt_payloads = [
                interrupt_obj
                for task in (snapshot.tasks or [])
                for interrupt_obj in (getattr(task, "interrupts", None) or [])
            ]

            if snapshot.next and interrupt_payloads:
                pending.append(
                    {
                        "thread_id": thread_id,
                        "interrupt_payload": _pending_approval_view(
                            getattr(interrupt_payloads[0], "value", None)
                        ),
                        "interrupted_at": (
                            checkpoint_tuple.checkpoint.get("ts", "")
                            if checkpoint_tuple.checkpoint
                            else ""
                        ),
                    }
                )

    except HTTPException:
        raise
    except CheckpointDurabilityError as exc:
        logger.error(
            "Checkpoint store unavailable while listing pending approvals: %s", exc
        )
        raise HTTPException(
            status_code=503,
            detail={"error": "checkpoint_store_unavailable", "detail": str(exc)},
        ) from exc
    except Exception as exc:
        logger.error("Failed to list pending approvals: %s", exc)
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(exc))

    return {"pending": pending}


# ---------------------------------------------------------------------------
# Refinement pipeline trigger endpoint (R-17 + Action-3 FIXED)
# ---------------------------------------------------------------------------


def _submit_kfp_run(pipeline_id: str, trigger_reason: str, trace_ids: list) -> dict:
    """Submit a Kubeflow Pipelines run for the governance refinement pipeline.

    Attempts to connect to the KFP API server at ``KFP_ENDPOINT``.  If the
    endpoint is not configured (local dev) or the ``kfp`` package is absent,
    logs a warning and returns a ``dry_run`` status so the endpoint remains
    callable in all environments.

    Returns a dict with ``run_id``, ``status``, and ``kfp_endpoint`` keys.
    """
    kfp_endpoint = os.environ.get("KFP_ENDPOINT", "")
    if not kfp_endpoint:
        logger.warning(
            "[Refinement] KFP_ENDPOINT not set — skipping live pipeline submission "
            "(pipeline_id=%s). Set KFP_ENDPOINT to enable live KFP runs.",
            pipeline_id,
        )
        return {"run_id": None, "status": "dry_run", "kfp_endpoint": ""}

    try:
        import kfp  # type: ignore[import-untyped]

        from src.governed_financial_advisor.pipelines.green_stack_pipeline import (
            governance_pipeline,
        )

        client = kfp.Client(host=kfp_endpoint)
        run = client.create_run_from_pipeline_func(
            governance_pipeline,  # type: ignore[arg-type]
            arguments={
                "compliance_bridge_url": os.environ.get(
                    "COMPLIANCE_BRIDGE_URL", "http://compliance-bridge/"
                ),
                "backend_url": os.environ.get(
                    "BACKEND_URL",
                    os.environ.get("GATEWAY_URL", "http://cage-gateway:8080"),
                ),
                "control_id": pipeline_id,
            },
            run_name=f"refinement-{pipeline_id}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}",
            experiment_name="governance-refinement",
        )
        run_id: str = str(run.run_id)
        logger.info("[Refinement] KFP run submitted: run_id=%s", run_id)
        return {"run_id": run_id, "status": "submitted", "kfp_endpoint": kfp_endpoint}
    except ModuleNotFoundError:
        logger.warning(
            "[Refinement] kfp package not installed — skipping live pipeline submission. "
            "Install with: pip install kfp"
        )
        return {
            "run_id": None,
            "status": "kfp_not_installed",
            "kfp_endpoint": kfp_endpoint,
        }
    except Exception as exc:
        logger.error("[Refinement] KFP run submission failed: %s", exc)
        raise HTTPException(
            status_code=502, detail=f"KFP pipeline submission failed: {exc}"
        ) from exc


@app.post("/v1/refinement/trigger")
async def trigger_refinement(  # type: ignore[no-untyped-def]
    req: RefinementTriggerRequest,
    _auth: CallerCredentialKind = Depends(require_service_api_key),
):
    """Trigger the Green-Stack KFP refinement pipeline.

    Service-only (:func:`require_service_api_key`): refinement is an operator
    function, so an end-user OIDC JWT is never accepted here.

    Accepts a JSON body with ``pipeline_id``, ``trigger_reason``, and an
    optional list of ``trace_ids`` that motivated this refinement run.

    Wires to Kubeflow Pipelines via ``kfp.Client`` when ``KFP_ENDPOINT`` is
    set.  Degrades gracefully to ``dry_run`` in local dev environments where
    KFP is not available.
    """
    logger.info(
        "[Refinement] Trigger received: pipeline_id=%s reason=%r trace_count=%d",
        req.pipeline_id,
        req.trigger_reason,
        len(req.trace_ids),
    )

    current_span = trace.get_current_span()
    if current_span and current_span.is_recording():
        current_span.set_attribute("ai.refinement.pipeline_id", req.pipeline_id)
        current_span.set_attribute("ai.refinement.trigger_reason", req.trigger_reason)
        current_span.set_attribute("ai.refinement.trace_count", len(req.trace_ids))
        current_span.add_event(
            "refinement.triggered",
            {
                "pipeline_id": req.pipeline_id,
                "trigger_reason": req.trigger_reason,
                "trace_ids": ",".join(req.trace_ids),
            },
        )

    kfp_result = _submit_kfp_run(req.pipeline_id, req.trigger_reason, req.trace_ids)

    if current_span and current_span.is_recording():
        current_span.set_attribute(
            "ai.refinement.kfp_run_id", kfp_result.get("run_id") or ""
        )
        current_span.set_attribute(
            "ai.refinement.kfp_status", kfp_result.get("status", "")
        )

    return {
        "status": "accepted",
        "pipeline_id": req.pipeline_id,
        "message": "Refinement pipeline triggered",
        "kfp": kfp_result,
    }


# ---------------------------------------------------------------------------
# Langfuse webhook receiver — maps score events to KFP pipeline triggers
# ---------------------------------------------------------------------------

_NEMO_SAFETY_THRESHOLD: float = float(os.environ.get("NEMO_SAFETY_THRESHOLD", "0.95"))
_LANGFUSE_SCORE_NAME: str = os.environ.get(
    "LANGFUSE_WATCH_SCORE_NAME", "iso_42001_safety_rate"
)

# ---------------------------------------------------------------------------
# Anti-flapping controls
#
# REFINEMENT_COOLDOWN_SECONDS (default: 300)
#   After a KFP run is accepted, all subsequent webhook triggers are rejected
#   for this many seconds.  Prevents rapid-fire hot-reloads during noisy
#   score bursts (policy flapping / thundering-herd into the inference pod).
#
# REFINEMENT_MIN_SAMPLES (default: 10)
#   The score event payload *may* carry a ``sample_size`` field in ``data``.
#   If present and below this minimum, the trigger is deferred — a single
#   low-scoring trace during a quiet window is not statistically significant.
#   When the field is absent the guard is skipped (Langfuse does not always
#   include sample metadata).
#
# Both values are read at module load time; set env vars before pod startup.
# ---------------------------------------------------------------------------
_REFINEMENT_COOLDOWN_SECONDS: float = float(
    os.environ.get("REFINEMENT_COOLDOWN_SECONDS", "300")
)
_REFINEMENT_MIN_SAMPLES: int = int(os.environ.get("REFINEMENT_MIN_SAMPLES", "10"))

# Module-level monotonic timestamp of the last accepted KFP trigger.
# Initialised to -1e9 so the very first qualifying event always fires
# even on newly-booted systems where time.monotonic() < cooldown.
# asyncio is single-threaded: the check + update is atomic at the Python
# coroutine boundary — no lock needed.
_last_refinement_triggered_at: float = -1e9


@app.post("/v1/webhooks/langfuse")
async def langfuse_webhook(  # type: ignore[no-untyped-def]
    req: LangfuseWebhookEvent,
    _auth: CallerCredentialKind = Depends(require_service_api_key),
):
    """Receive Langfuse outgoing webhook events and trigger KFP refinement.

    Service-only (:func:`require_service_api_key`): the webhook sender
    authenticates with ``Authorization: Bearer <CAGE_API_KEY>``, and an
    end-user OIDC JWT is never accepted, so no end user can submit a score
    event or arm the cooldown below.

    Configure in the Langfuse UI under **Settings → Webhooks** with:
      - URL: ``https://<governed-financial-advisor>/v1/webhooks/langfuse``
      - Filter: ``Event type: score-created``

    When Langfuse fires a ``score-created`` event whose score name matches
    ``LANGFUSE_WATCH_SCORE_NAME`` (default: ``iso_42001_safety_rate``) and
    whose value is below ``NEMO_SAFETY_THRESHOLD`` (default: ``0.95``), this
    endpoint enqueues a KFP governance pipeline run — subject to two
    anti-flapping guards:

    **Cooldown gate** (``REFINEMENT_COOLDOWN_SECONDS``, default 300 s)
        Only one KFP run is accepted per cooldown window.  Subsequent score
        events during the window are acknowledged (HTTP 200) with
        ``{"status": "cooldown", "seconds_remaining": N}`` so Langfuse does
        not retry.  The cooldown resets when the window expires.

    **Minimum-sample guard** (``REFINEMENT_MIN_SAMPLES``, default 10)
        If the webhook payload includes a ``sample_size`` field and it is
        below the minimum, the trigger is deferred.  A single blocked trace
        in a quiet window is not statistically meaningful.

    All other event types are acknowledged with ``{"status": "ignored"}``.

    Returns:
        ``{"status": "triggered" | "cooldown" | "deferred" | "ignored" | "threshold_ok"}``
    """
    global _last_refinement_triggered_at

    import time

    logger.info(
        "[Webhook/Langfuse] event received: type=%s name=%s value=%s traceId=%s",
        req.type,
        req.name,
        req.value,
        req.traceId,
    )

    # Acknowledge all non-score events immediately to prevent Langfuse retries.
    if req.type != "score-created":
        return {"status": "ignored", "reason": f"event type '{req.type}' not handled"}

    # Only act on the watched score name.
    if req.name != _LANGFUSE_SCORE_NAME:
        return {"status": "ignored", "reason": f"score name '{req.name}' not watched"}

    # Threshold check — only trigger refinement when the rate is below the bar.
    if req.value >= _NEMO_SAFETY_THRESHOLD:
        logger.debug(
            "[Webhook/Langfuse] safety_rate=%.4f >= threshold=%.2f — no action.",
            req.value,
            _NEMO_SAFETY_THRESHOLD,
        )
        return {
            "status": "threshold_ok",
            "safety_rate": req.value,
            "threshold": _NEMO_SAFETY_THRESHOLD,
        }

    # ── Minimum-sample guard ─────────────────────────────────────────────────
    # Langfuse may include a numeric sample_size in the event's data dict.
    # If it does and it's below the minimum, defer the trigger.
    sample_size: int | None = (
        req.data.get("sample_size") if isinstance(req.data, dict) else None
    )
    if sample_size is not None and sample_size < _REFINEMENT_MIN_SAMPLES:
        logger.info(
            "[Webhook/Langfuse] sample_size=%d < min_samples=%d — deferring trigger.",
            sample_size,
            _REFINEMENT_MIN_SAMPLES,
        )
        return {
            "status": "deferred",
            "reason": "insufficient_samples",
            "sample_size": sample_size,
            "min_samples": _REFINEMENT_MIN_SAMPLES,
            "safety_rate": req.value,
        }

    # ── Cooldown gate ────────────────────────────────────────────────────────
    # Block rapid re-fires during noisy bursts (policy flapping prevention).
    now = time.monotonic()
    elapsed = now - _last_refinement_triggered_at
    if elapsed < _REFINEMENT_COOLDOWN_SECONDS:
        seconds_remaining = _REFINEMENT_COOLDOWN_SECONDS - elapsed
        logger.info(
            "[Webhook/Langfuse] cooldown active — %.0fs remaining (cooldown=%.0fs). "
            "Acknowledging without re-triggering KFP.",
            seconds_remaining,
            _REFINEMENT_COOLDOWN_SECONDS,
        )
        current_span = trace.get_current_span()
        if current_span and current_span.is_recording():
            current_span.set_attribute(AI_WEBHOOK_COOLDOWN_ACTIVE, True)
            current_span.set_attribute(
                AI_WEBHOOK_COOLDOWN_SECONDS_REMAINING, seconds_remaining
            )
        return {
            "status": "cooldown",
            "safety_rate": req.value,
            "seconds_remaining": round(seconds_remaining, 1),
            "cooldown_seconds": _REFINEMENT_COOLDOWN_SECONDS,
        }

    # ── Trigger accepted — arm the cooldown clock before the async call ──────
    # Update the timestamp *before* awaiting _submit_kfp_run so that any
    # concurrent webhook event arriving while KFP submission is in-flight
    # is also gated.  asyncio cooperative scheduling means no true race here,
    # but being explicit keeps the intent clear.
    _last_refinement_triggered_at = now

    trigger_reason = (
        f"Langfuse webhook: {_LANGFUSE_SCORE_NAME}={req.value:.4f} "
        f"below threshold={_NEMO_SAFETY_THRESHOLD:.2f}"
        + (f" (n={sample_size})" if sample_size is not None else "")
    )
    trace_ids = [req.traceId] if req.traceId else []

    logger.warning(
        "[Webhook/Langfuse] 🚨 Safety rate %.4f < %.2f — triggering KFP refinement pipeline "
        "(cooldown window now active for %.0fs).",
        req.value,
        _NEMO_SAFETY_THRESHOLD,
        _REFINEMENT_COOLDOWN_SECONDS,
    )

    current_span = trace.get_current_span()
    if current_span and current_span.is_recording():
        current_span.set_attribute(AI_WEBHOOK_SCORE_NAME, req.name)
        current_span.set_attribute(AI_WEBHOOK_SCORE_VALUE, req.value)
        current_span.set_attribute(AI_WEBHOOK_TRACE_ID, req.traceId)
        current_span.set_attribute(AI_WEBHOOK_COOLDOWN_ACTIVE, False)
        current_span.add_event(
            WEBHOOK_THRESHOLD_BREACH,
            {
                "score_name": req.name,
                "score_value": req.value,
                "threshold": _NEMO_SAFETY_THRESHOLD,
                "cooldown_seconds": _REFINEMENT_COOLDOWN_SECONDS,
                "sample_size": sample_size if sample_size is not None else -1,
            },
        )

    kfp_result = _submit_kfp_run(
        pipeline_id="A.5.2",
        trigger_reason=trigger_reason,
        trace_ids=trace_ids,
    )

    return {
        "status": "triggered",
        "score_name": req.name,
        "score_value": req.value,
        "threshold": _NEMO_SAFETY_THRESHOLD,
        "cooldown_seconds": _REFINEMENT_COOLDOWN_SECONDS,
        "kfp": kfp_result,
    }


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=Config.PORT, log_config=None)
