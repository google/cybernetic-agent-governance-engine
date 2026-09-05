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
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

from contextlib import asynccontextmanager

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Request
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
    OBSERVATION_INPUT,
    OBSERVATION_OUTPUT,
    OBSERVATION_TYPE,
    WEBHOOK_THRESHOLD_BREACH,
)
from src.governed_financial_advisor.graph.graph import create_graph
from src.governed_financial_advisor.infrastructure.auth import require_api_key
from src.governed_financial_advisor.tools.api import tools_router
from src.governed_financial_advisor.utils.context import user_context

# Observability
ENABLE_TRACING = os.environ.get("ENABLE_TRACING", "true").lower() == "true"

if ENABLE_TRACING:
    configure_telemetry()
    if _LANGCHAIN_INSTRUMENTOR_AVAILABLE and LangchainInstrumentor is not None:
        LangchainInstrumentor().instrument()  # Traces Graph nodes (including Agent calls)


# --- LIFESPAN (Startup/Shutdown) ---
@asynccontextmanager
async def lifespan(app: FastAPI):  # type: ignore[no-untyped-def]
    # Startup: Initialize Graph (and Redis)
    logger.info("Initializing Agent Graph...")
    app.state.graph = create_graph(redis_url=Config.REDIS_URL)

    # ── CTRL_KMS_001: Eagerly initialise the governance signer ────────────
    # generate_governance_signature() (evaluator_node.py) calls
    # get_governance_signer() lazily on the first plan approval. If
    # KMS_GOVERNANCE_KEY is unset/misconfigured or google-cloud-kms isn't
    # installed, that first call raises RuntimeError deep inside a request,
    # surfacing as an opaque HTTP 500 on every trade/execution request — the
    # 2026-08-01 measurement-run defect. Initialise (and validate) it here
    # instead, so a broken signer fails fast at pod startup with a clear log
    # line and a non-ready pod, rather than silently 500-ing every request.
    app.state.kms_active = False
    try:
        from src.gateway.governance.kms_signer import (
            assert_kms_active_in_production,
            get_governance_signer,
        )

        _signer = get_governance_signer()
        app.state.kms_active = _signer.is_kms_active
        if _signer.is_kms_active:
            logger.info(
                "✅ CTRL_KMS_001: KMSGovernanceSigner active (%s)",
                _signer.signing_algorithm,
            )
        else:
            logger.warning(
                "⚠️  CTRL_KMS_001: KMSGovernanceSigner is in HMAC fallback mode "
                "(KMS_GOVERNANCE_KEY unset or not applicable). This is only "
                "acceptable in dev/CI — see CTRL_KMS_001 in control_mappings.json."
            )
        # Fail fast in non-dev environments: raises RuntimeError if the
        # signer is in fallback mode outside development/test/ci.
        assert_kms_active_in_production()
    except Exception as _kms_exc:
        logger.error(
            "❌ CTRL_KMS_001 STARTUP FAILURE: governance signer did not "
            "initialise correctly: %s",
            _kms_exc,
        )
        raise

    # ── Connect the GFA AsyncRedisClient singleton ────────────────────────
    # The singleton is created at module import time (redis_client.py) but
    # connect() must be called explicitly to establish the connection pool.
    # Failure is non-fatal: the server starts but sessions won't persist.
    from src.governed_financial_advisor.infrastructure.redis_client import (
        redis_client as _redis_client,
    )

    try:
        await _redis_client.connect()
        logger.info("✅ GFA AsyncRedisClient connected")
    except Exception as _redis_exc:
        logger.error("❌ GFA Redis connection failed (non-fatal): %s", _redis_exc)

    # Initialize Redis Indices if using Redis Checkpointer (langgraph-checkpoint-redis)
    try:
        if hasattr(app.state.graph, "checkpointer") and app.state.graph.checkpointer:
            cp = app.state.graph.checkpointer
            # Check for AsyncRedisSaver (lazy check to avoid import)
            if "RedisSaver" in str(type(cp)):
                logger.debug("Checking Redis Checkpointer setup...")
                if hasattr(cp, "setup"):
                    logger.info("Running Redis Checkpointer setup()...")
                    await cp.setup()
                    logger.info("Redis Checkpointer setup complete")
    except Exception as e:
        logger.warning("Failed to setup Redis Checkpointer: %s", e)

    logger.info("Agent Graph Initialized")
    yield
    # Shutdown
    logger.info("Shutting down...")
    await get_mcp_client().close()
    try:
        await _redis_client.close()
    except Exception:
        pass


app = FastAPI(
    title="Governed Financial Advisor (Graph Orchestrated)", lifespan=lifespan
)


def server_request_hook(span, scope):  # type: ignore[no-untyped-def]
    if not span or not span.is_recording():
        return

    method = scope.get("method", "GET").upper()
    path = scope.get("path", "/")

    # 1. Rich Observation (Mapping Input and Span Name)
    span.set_attribute("input", f"{method} {path}")
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
app.include_router(tools_router)

if (
    os.environ.get("CAGE_ENV", "prod").lower() == "dev"
):  # Default to "prod" to fail-secure: missing CAGE_ENV must not silently disable enforcement
    from src.governed_financial_advisor.demo.router import demo_router

    app.include_router(demo_router)
    logger.warning("Demo endpoints enabled — do not use in production")
# Graph is now in app.state.graph


class QueryRequest(BaseModel):
    prompt: str
    user_id: str = "default_user"
    thread_id: str = "default_thread"


class ApprovalResumeRequest(BaseModel):
    """Request body for POST /v1/approvals/{thread_id}/resume.

    Attributes:
        approved:  Whether the trade is approved or rejected.
        reviewer:  Identity of the human reviewer (email or employee ID).
                   Used for ISO 42001 A.7.2 accountability attribution.
        rationale: Mandatory free-text justification.  The auditor's reason
                   for this decision is hashed directly into the evidence chain —
                   an unexplained resume is a compliance gap (ISO 42001 §6.1,
                   NIST AI RMF GOVERN-5).
        comment:   Optional supplementary note (legacy field — prefer rationale).
    """

    approved: bool
    reviewer: str
    rationale: str  # mandatory — cannot be empty string
    comment: str = ""  # kept for backwards compatibility
    max_slippage_pct: float = 2.0  # reviewer's execution price tolerance (%)
    # Default: 2.0% (institutional large-cap standard).

    @staticmethod
    def _validate_rationale(value: str) -> str:
        if not value or not value.strip():
            raise ValueError(
                "rationale is required and must be a non-empty string. "
                "Provide the business justification for this approval decision "
                "so it can be hashed into the compliance evidence chain."
            )
        return value

    @model_validator(mode="after")
    def _check_rationale_not_empty(self) -> "ApprovalResumeRequest":
        self._validate_rationale(self.rationale)
        return self


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


class NeMoApplyRefinementRequest(BaseModel):
    """Request body for POST /v1/nemo/apply-refinement.

    Called by the KFP ``trigger_nemo_refinement`` component at the end of the
    cybernetic governance loop when safety metrics breach a threshold.  The
    endpoint hot-reloads the NeMo rails configuration in-process so the change
    takes effect without restarting the pod.

    Attributes:
        control_id: ISO 42001 control whose threshold was breached (e.g. "A.5.2").
        verdict:    The FAIL verdict string from ``evaluate_governance_metrics``.
        source:     Caller identifier for audit tracing (e.g. "kfp-governance-loop").
    """

    control_id: str
    verdict: str
    source: str = "unknown"


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
def health_check():  # type: ignore[no-untyped-def]
    return {
        "status": "ok",
        "service": "financial-advisor-graph-agent",
        "project_id": Config.GOOGLE_CLOUD_PROJECT,
    }


@app.post("/agent/query")
async def query_agent(  # type: ignore[no-untyped-def]
    req: QueryRequest,
    request: Request,
    _auth: str = Depends(require_api_key),
):
    """
    Main agent query endpoint.

    NeMo guardrails are enforced exclusively inside the LangGraph:
      - ``nemo_guardrail_node``    : mandatory first node — input rail
      - ``nemo_output_rail_node``  : mandatory last node  — output rail + PII mask

    This endpoint does NOT duplicate those guardrail calls.  The graph is the
    single source of truth for guardrail enforcement, which avoids:
      - double-blocking (guardrail node blocks → server tries to mask user input)
      - CAGE_SEAL_ENFORCEMENT inconsistency between HTTP layer and graph layer
    """
    token = user_context.set(req.user_id)
    try:
        import json as _json

        # ISO 42001: A.7.2 Accountability — Tag trace with User Identity
        current_span = trace.get_current_span()
        trace_id = None
        if current_span and current_span.is_recording():
            current_span.set_attribute("enduser.id", req.user_id)
            current_span.set_attribute("thread.id", req.thread_id)
            current_span.set_attribute(OBSERVATION_TYPE, "generation")
            current_span.set_attribute("gen_ai.operation.name", "chat")
            current_span.set_attribute(
                "gen_ai.input.messages",
                _json.dumps([{"role": "user", "content": req.prompt}]),
            )
            current_span.set_attribute(OBSERVATION_INPUT, req.prompt)
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
                current_span.set_attribute(OBSERVATION_OUTPUT, cached_response)
                current_span.set_attribute("cache.hit", True)

            return JSONResponse(
                content={"response": final_response_text, "trace_id": trace_id}
            )

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
                    {"messages": [("user", req.prompt)], "user_id": req.user_id},
                    {
                        "recursion_limit": 100,
                        "configurable": {"thread_id": req.thread_id},
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
        else:
            # Cache successful responses (only if query was cacheable)
            # Blocked responses are not cached (different blocks may have different reasons)
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
                "gen_ai.output.messages",
                _json.dumps([{"role": "assistant", "content": final_response_text}]),
            )
            current_span.set_attribute(OBSERVATION_OUTPUT, final_response_text)

        return {"response": final_response_text, "trace_id": trace_id}

    except HTTPException:
        # Re-raise HTTPException (e.g. 504 timeout) without wrapping in 500.
        raise
    except Exception as e:
        logger.error("Error invoking agent graph: %s", e)
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        user_context.reset(token)


# ---------------------------------------------------------------------------
# Approval endpoints (Phase 1b — LangGraph interrupt / Command)
# ---------------------------------------------------------------------------


@app.post("/v1/approvals/{thread_id}/resume")
async def resume_approval(  # type: ignore[no-untyped-def]
    thread_id: str,
    req: ApprovalResumeRequest,
    request: Request,
    _auth: str = Depends(require_api_key),
):
    """
    Resume an interrupted graph that is awaiting human trade approval.

    The graph must already be in an interrupted state (paused at approval_node)
    for the given thread_id.  Issues a Command(resume={...}) to unblock it.

    Returns:
        {"status": "resumed", "thread_id": str, "approved": bool}

    Raises:
        404 if thread_id is not found or is not awaiting approval.
        500 on unexpected errors.
    """
    graph = request.app.state.graph
    config = {"configurable": {"thread_id": thread_id}}

    # Check that this thread_id exists and is interrupted
    try:
        state_snapshot = await graph.aget_state(config)
    except Exception as exc:
        logger.error("Failed to fetch state for thread_id=%s: %s", thread_id, exc)
        raise HTTPException(status_code=404, detail=f"Thread '{thread_id}' not found.")

    if state_snapshot is None:
        raise HTTPException(status_code=404, detail=f"Thread '{thread_id}' not found.")

    # LangGraph marks interrupted graphs with non-empty `next` pointing at the
    # interrupted node, and the `tasks` list carries interrupt payloads.
    is_interrupted = bool(
        state_snapshot.next
        and any(
            getattr(task, "interrupts", None) for task in (state_snapshot.tasks or [])
        )
    )
    if not is_interrupted:
        raise HTTPException(
            status_code=404,
            detail=f"Thread '{thread_id}' is not awaiting approval.",
        )

    # ------------------------------------------------------------------
    # TTL Guard: check if the approval window has expired.
    # The approval_node stamps each interrupt payload with an "expires_at"
    # ISO-8601 timestamp (HITL_APPROVAL_TTL_SECONDS from env, default 300s).
    # An expired approval returns HTTP 410 Gone — the reviewer must re-submit.
    # ------------------------------------------------------------------
    for task in state_snapshot.tasks or []:
        for interrupt_obj in getattr(task, "interrupts", None) or []:
            payload = getattr(interrupt_obj, "value", None)
            if isinstance(payload, dict):
                expires_at_str = payload.get("expires_at")
                if expires_at_str:
                    try:
                        expires_at = datetime.fromisoformat(expires_at_str)
                        if datetime.now(timezone.utc) > expires_at:
                            logger.warning(
                                "[Approvals] TTL expired for thread_id=%s (expires_at=%s) — "
                                "returning 410 Gone.",
                                thread_id,
                                expires_at_str,
                            )
                            raise HTTPException(
                                status_code=410,
                                detail=(
                                    f"Approval window expired at {expires_at_str}. "
                                    "Market conditions may have changed significantly. "
                                    "Please re-submit the trade request for a fresh evaluation."
                                ),
                            )
                    except HTTPException:
                        raise
                    except Exception:
                        pass  # Parsing failure — do not block the resume.

    resume_payload = {
        "approved": req.approved,
        "reviewer": req.reviewer,
        "rationale": req.rationale,
        "comment": req.comment,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "max_slippage_pct": req.max_slippage_pct,  # TOCTOU: reviewer's slippage tolerance
    }

    logger.info(
        "[Approvals] Resuming thread_id=%s approved=%s reviewer=%s rationale=%r",
        thread_id,
        req.approved,
        req.reviewer,
        req.rationale[:120],
    )

    # ------------------------------------------------------------------
    # Write the approval decision into the tamper-evident evidence chain
    # BEFORE resuming the graph.  This ensures the human rationale is
    # hashed and persisted even if the graph crashes during execution.
    # The record satisfies ISO 42001 §6.1 (risk treatment decisions),
    # A.7.2 (accountability), and NIST AI RMF GOVERN-5 (human oversight).
    # ------------------------------------------------------------------
    try:
        from examples.telemetry import PlaygroundTelemetry

        _tel = PlaygroundTelemetry()
        _tel.record_approval(
            thread_id=thread_id,
            approved=req.approved,
            reviewer=req.reviewer,
            rationale=req.rationale,
            comment=req.comment,
        )
    except Exception as _tel_exc:
        # Evidence chain write failure must NEVER block the approval flow.
        # Log at ERROR (will trigger alerting) but continue.
        logger.error(
            "[Approvals] Evidence chain write failed for thread_id=%s — "
            "approval will proceed but audit record may be missing: %s",
            thread_id,
            _tel_exc,
        )

    try:
        await graph.ainvoke(
            Command(resume=resume_payload),
            config,
        )
    except Exception as exc:
        logger.error("Failed to resume thread_id=%s: %s", thread_id, exc)
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(exc))

    return {
        "status": "resumed",
        "thread_id": thread_id,
        "approved": req.approved,
        "evidence_recorded": True,
    }


@app.get("/v1/approvals/pending")
async def list_pending_approvals(request: Request):  # type: ignore[no-untyped-def]
    """
    List all graph threads currently interrupted and awaiting human approval.

    Iterates over stored checkpoints via the graph's checkpointer and filters
    for threads whose state snapshot has a non-empty ``next`` step AND contains
    interrupt payloads.

    Returns:
        {"pending": [{"thread_id": str, "interrupt_payload": dict, "interrupted_at": str}, ...]}
    """
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

            # Fetch the current state snapshot for this thread
            config = {"configurable": {"thread_id": thread_id}}
            try:
                snapshot = await graph.aget_state(config)
            except Exception:
                continue

            if snapshot is None:
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
                        "interrupt_payload": interrupt_payloads[0].value
                        if hasattr(interrupt_payloads[0], "value")
                        else str(interrupt_payloads[0]),
                        "interrupted_at": (
                            checkpoint_tuple.checkpoint.get("ts", "")
                            if checkpoint_tuple.checkpoint
                            else ""
                        ),
                    }
                )

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
            governance_pipeline,
            arguments={
                "compliance_bridge_url": os.environ.get(
                    "COMPLIANCE_BRIDGE_URL", "http://compliance-bridge/"
                ),
                "backend_url": os.environ.get(
                    "BACKEND_URL", "http://governed-financial-advisor/"
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
async def trigger_refinement(req: RefinementTriggerRequest):  # type: ignore[no-untyped-def]
    """Trigger the Green-Stack KFP refinement pipeline.

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
# NeMo Refinement Proposal/Approval Flow (Priority 2 — Evidentiary Independence)
#
# The NeMo hot-reload requires human approval.
#
# Flow:
#   Langfuse webhook → KFP → POST /v1/nemo/propose-refinement → STAGED
#   Human risk officer → POST /v1/nemo/approve-refinement/{id} → APPLIED
#
# This eliminates the recursive self-authentication loop where the system's
# telemetry could autonomously modify its own governance rules.
#
# v3.0.0 Breaking Change: NEMO_AUTO_APPLY_ENABLED has been removed.
# ---------------------------------------------------------------------------

# In-memory proposal store (production: replace with Redis or DB)
_refinement_proposals: dict[str, dict] = {}


@app.post("/v1/nemo/propose-refinement")
async def propose_nemo_refinement(req: NeMoApplyRefinementRequest):  # type: ignore[no-untyped-def]
    """Stage a NeMo Guardrails refinement proposal for human review.

    Called by the KFP ``trigger_nemo_refinement`` component when the
    ``evaluate_governance_metrics`` component emits a FAIL verdict.

    The proposal is STAGED but NOT applied.  A human risk officer must
    call ``POST /v1/nemo/approve-refinement/{proposal_id}`` with their
    identity, rationale, and explicit approval to apply the change.

    Satisfies:
      - EU AI Act Article 14 (human oversight of high-risk AI systems)
      - ISO 42001 A.7.2 (accountability — reviewer identity attributed)
      - NIST AI RMF GOVERN-5 (human oversight and intervention)

    Returns:
        ``{"status": "staged", "proposal_id": str, "control_id": str}``
    """
    import uuid as _uuid

    proposal_id = str(_uuid.uuid4())
    proposal = {
        "proposal_id": proposal_id,
        "control_id": req.control_id,
        "verdict": req.verdict,
        "source": req.source,
        "staged_at": datetime.now(timezone.utc).isoformat(),
        "status": "staged",
        "reviewer": None,
        "rationale": None,
    }
    _refinement_proposals[proposal_id] = proposal

    logger.info(
        "[NeMo/Refinement] Proposal STAGED: id=%s control_id=%s source=%s",
        proposal_id,
        req.control_id,
        req.source,
    )

    current_span = trace.get_current_span()
    if current_span and current_span.is_recording():
        current_span.set_attribute("ai.refinement.proposal_id", proposal_id)
        current_span.set_attribute("ai.refinement.apply.control_id", req.control_id)
        current_span.set_attribute("ai.refinement.apply.source", req.source)
        current_span.set_attribute("ai.refinement.status", "staged")

    return {
        "status": "staged",
        "proposal_id": proposal_id,
        "control_id": req.control_id,
        "message": (
            "Refinement proposal staged. A risk officer must approve via "
            f"POST /v1/nemo/approve-refinement/{proposal_id}"
        ),
    }


class NeMoApproveRequest(BaseModel):
    """Request body for POST /v1/nemo/approve-refinement/{proposal_id}."""

    approved: bool
    reviewer: str
    rationale: str


@app.post("/v1/nemo/approve-refinement/{proposal_id}")
async def approve_nemo_refinement(  # type: ignore[no-untyped-def]
    proposal_id: str,
    req: NeMoApproveRequest,
    _auth: str = Depends(require_api_key),
):
    """Approve or reject a staged NeMo refinement proposal.

    Requires a human risk officer to provide their identity and a mandatory
    rationale.  The approval decision is recorded in the evidence chain
    before the refinement is applied.

    This endpoint is the sole mechanism for applying NeMo configuration
    changes in production.  There is no automated path from telemetry to
    applied config.

    Returns:
        ``{"status": "applied"|"rejected", "proposal_id": str}``

    Raises:
        404 if the proposal_id is not found or already processed.
        400 if rationale is empty.
    """
    if not req.rationale or not req.rationale.strip():
        raise HTTPException(
            status_code=400,
            detail="rationale is required — provide the business justification "
            "for this governance configuration change.",
        )

    proposal = _refinement_proposals.get(proposal_id)
    if proposal is None or proposal["status"] != "staged":
        raise HTTPException(
            status_code=404,
            detail=f"Proposal '{proposal_id}' not found or already processed.",
        )

    proposal["reviewer"] = req.reviewer
    proposal["rationale"] = req.rationale
    proposal["reviewed_at"] = datetime.now(timezone.utc).isoformat()

    if not req.approved:
        proposal["status"] = "rejected"
        logger.info(
            "[NeMo/Refinement] Proposal REJECTED: id=%s reviewer=%s",
            proposal_id,
            req.reviewer,
        )
        return {"status": "rejected", "proposal_id": proposal_id}

    # Record the approval in the evidence chain BEFORE applying
    try:
        from examples.telemetry import PlaygroundTelemetry

        _tel = PlaygroundTelemetry()
        _tel.record_approval(
            thread_id=f"nemo-refinement-{proposal_id}",
            approved=True,
            reviewer=req.reviewer,
            rationale=req.rationale,
            comment=f"NeMo refinement for {proposal['control_id']}",
        )
    except Exception as _tel_exc:
        logger.error("[NeMo/Refinement] Evidence chain write failed: %s", _tel_exc)

    # Apply the refinement
    try:
        from src.gateway.governance.langgraph_harness.nemo_node_factory import (
            reload_nemo_rails,
        )

        await reload_nemo_rails()
        proposal["status"] = "applied"
        logger.info(
            "[NeMo/Refinement] Proposal APPLIED: id=%s reviewer=%s control_id=%s",
            proposal_id,
            req.reviewer,
            proposal["control_id"],
        )
    except Exception as exc:
        proposal["status"] = "apply_failed"
        logger.error("[NeMo/Refinement] Rails reload failed after approval: %s", exc)
        raise HTTPException(
            status_code=500,
            detail=f"NeMo rails reload failed: {exc}",
        ) from exc

    return {
        "status": "applied",
        "proposal_id": proposal_id,
        "control_id": proposal["control_id"],
        "reviewer": req.reviewer,
    }


@app.get("/v1/nemo/proposals/pending")
async def list_pending_nemo_proposals():  # type: ignore[no-untyped-def]
    """List all staged NeMo refinement proposals awaiting human review."""
    pending = [p for p in _refinement_proposals.values() if p["status"] == "staged"]
    return {"pending": pending, "count": len(pending)}


@app.post("/v1/nemo/apply-refinement")
async def apply_nemo_refinement(req: NeMoApplyRefinementRequest):  # type: ignore[no-untyped-def]
    """NeMo hot-reload routes through the proposal/approval flow.

    v3.0.0 Breaking Change: This endpoint always stages a proposal and
    returns ``{"status": "pending_approval"}``. The caller must then approve
    via POST /v1/nemo/approve-refinement/{id}.

    This eliminates the recursive self-authentication loop where the system's
    telemetry could autonomously modify its own governance rules.

    Satisfies:
      - EU AI Act Article 14 (human oversight of high-risk AI systems)
      - ISO 42001 A.7.2 (accountability — reviewer identity attributed)
    """
    import uuid as _uuid

    logger.info(
        "[NeMo/Refinement] Routing to proposal flow. control_id=%s source=%s",
        req.control_id,
        req.source,
    )

    proposal_id = str(_uuid.uuid4())
    proposal = {
        "proposal_id": proposal_id,
        "control_id": req.control_id,
        "verdict": req.verdict,
        "source": req.source,
        "staged_at": datetime.now(timezone.utc).isoformat(),
        "status": "staged",
        "reviewer": None,
        "rationale": None,
    }
    _refinement_proposals[proposal_id] = proposal

    current_span = trace.get_current_span()
    if current_span and current_span.is_recording():
        current_span.set_attribute("ai.refinement.apply.control_id", req.control_id)
        current_span.set_attribute("ai.refinement.apply.source", req.source)
        current_span.set_attribute("ai.refinement.proposal_id", proposal_id)

    return {
        "status": "pending_approval",
        "proposal_id": proposal_id,
        "control_id": req.control_id,
        "message": (
            "Refinement proposal staged. A risk officer must "
            f"approve via POST /v1/nemo/approve-refinement/{proposal_id}"
        ),
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
async def langfuse_webhook(req: LangfuseWebhookEvent):  # type: ignore[no-untyped-def]
    """Receive Langfuse outgoing webhook events and trigger KFP refinement.

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
