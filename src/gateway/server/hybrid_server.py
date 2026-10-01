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

from src.gateway.server.governance_middleware import governance_app
from src.gateway.server.inference_proxy import inference_app
from src.gateway.server.mcp_tool_server import app as mcp_app
from src.gateway.server.workload_identity import (
    WorkloadIdentityMiddleware,
    load_identity_policy,
)
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
    from src.integrations.nemo.manager import initialize_rails

    logger.info("🔥 Pre-warming NeMo rails at gateway boot...")
    nemo_rails = initialize_rails()

    # Store on root and sub-app states
    app.state.nemo_rails = nemo_rails
    inference_app.state.nemo_rails = nemo_rails
    mcp_app.state.nemo_rails = nemo_rails
    logger.info("✅ NeMo rails pre-warmed and shared across sub-applications")

    # ── Pre-warm Token Quota Proxy and UCA Logger (CTRL_TQP_007) ───────────────
    try:
        from src.gateway.governance.token_quota_proxy import TokenQuotaProxy
        from src.gateway.governance.uca_logger import UCALogger

        app.state.token_quota_proxy = TokenQuotaProxy.from_env()
        app.state.uca_logger = UCALogger.from_env()
        logger.info("✅ Token Quota Proxy and UCA Logger pre-warmed")
    except Exception as e:
        logger.warning("⚠️ Token Quota Proxy pre-warm failed (non-blocking): %s", e)

    # ── Production guards not owned by the governor posture check ──────────
    # KMS signing mode (K3), KMS/Redis readiness, the POAM-023 stub
    # reconciliation guard and the default GOVERNANCE_SALT guard (C-04) run in
    # assert_production_posture() when the governor is assembled
    # (_activate_domain below). NeMo guardrails always fail closed (no log-only
    # mode exists).

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

    # ── Attestation Aggregator Boot & Polling ──────────────────────────────
    from src.gateway.governance.attestation_aggregator import AttestationAggregator

    attestation_aggregator = AttestationAggregator.from_env()
    if attestation_aggregator.provider_count > 0:
        await attestation_aggregator.boot_fetch()
        polling_task = asyncio.create_task(attestation_aggregator.start_poll_loop())
        app.state.attestation_aggregator = attestation_aggregator
        app.state.attestation_polling_task = polling_task
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

    yield

    # Shutdown: stop Agent Registry daemon if running
    if registry_daemon is not None:
        await registry_daemon.stop()

    # Shutdown: cancel normative provider polling task if running
    if polling_task is not None:
        polling_task.cancel()
        try:
            await polling_task
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
        "External REST endpoints removed — use MCP over SSE or the internal "
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
# NeMo Refinement Proposal/Approval Flow (Gateway-owned NeMo rails)
# ---------------------------------------------------------------------------

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


_refinement_proposals: dict[str, dict[str, Any]] = {}


@root_app.post("/v1/nemo/propose-refinement")
async def propose_nemo_refinement(req: NeMoApplyRefinementRequest) -> dict[str, Any]:
    """Stage a NeMo Guardrails refinement proposal for human review."""
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

    current_span = _otel_trace.get_current_span()
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


@root_app.post("/v1/nemo/approve-refinement/{proposal_id}")
async def approve_nemo_refinement(
    proposal_id: str,
    req: NeMoApproveRequest,
) -> dict[str, Any]:
    """Approve or reject a staged NeMo refinement proposal and reload gateway NeMo rails."""
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

    try:
        from src.gateway.governance.langgraph_harness.nemo_node_factory import (
            get_nemo_rails,
            reload_nemo_rails,
        )

        await reload_nemo_rails()
        new_rails = get_nemo_rails()
        root_app.state.nemo_rails = new_rails
        inference_app.state.nemo_rails = new_rails
        mcp_app.state.nemo_rails = new_rails
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


@root_app.get("/v1/nemo/proposals/pending")
async def list_pending_nemo_proposals() -> dict[str, Any]:
    """List all staged NeMo refinement proposals awaiting human review."""
    pending = [p for p in _refinement_proposals.values() if p["status"] == "staged"]
    return {"pending": pending, "count": len(pending)}


@root_app.post("/v1/nemo/apply-refinement")
async def apply_nemo_refinement(req: NeMoApplyRefinementRequest) -> dict[str, Any]:
    """Stage a NeMo refinement proposal and return pending_approval."""
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

    current_span = _otel_trace.get_current_span()
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
