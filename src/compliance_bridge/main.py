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
main.py — FastAPI compliance bridge (Python replacement for langfuse-bridge TypeScript).

Ports src/langfuse-bridge/src/index.ts (Express service) → FastAPI + uvicorn.

4 routes:
  GET  /health
  GET  /v1/metrics/{control_id}?window_hours=24
  POST /v1/audit/ingest              body: {oscal_yaml, audit_id?}
  GET  /v1/prompts/{name}?label=production&cache_ttl_seconds=300

Entry point:
  uvicorn compliance_bridge.main:app --host 0.0.0.0 --port 3001
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from collections import OrderedDict
from contextlib import asynccontextmanager
from typing import Any, Literal

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse

# Langfuse is imported lazily to avoid loading google.protobuf at module
# corrupting the protobuf package for compliance_bridge tests that run later.
#
# The name ``Langfuse`` is defined here at module level so that
# ``patch("src.compliance_bridge.main.Langfuse")`` in tests works correctly.
# When first accessed, it is populated by ``_ensure_langfuse_imported()``.
Langfuse = None


def _ensure_langfuse_imported() -> None:
    """Populate the module-level ``Langfuse`` name on first call."""
    global Langfuse
    if Langfuse is None:
        from langfuse import Langfuse as _LF

        Langfuse = _LF


from .audit_workflow import run_audit_workflow
from .auth import require_internal_token
from .cmek_guard import validate_cmek_configuration
from .lula_scheduler import run_lula_scheduler
from .metrics import get_compliance_metrics
from .oscal_exporter import build_oscal_assessment_results, findings_from_metrics_dict
from .sla_monitor import run_sla_monitor
from .sse_events import event_bus
from .types import (
    CONTROL_META,
    CRITICAL_CONTROLS,
    SUPPORTED_CONTROLS,
    ComplianceMetrics,
    get_control_meta,
)

# ---------------------------------------------------------------------------
# In-process audit status registry
# Keyed by audit_id, capped at _AUDIT_STATUS_MAXSIZE (LRU eviction).
# Sufficient for a typical audit cadence (one CronJob run every 6-24 hours).
# ---------------------------------------------------------------------------

_AUDIT_STATUS_MAXSIZE = 256
_audit_status: OrderedDict[str, dict] = OrderedDict()

AuditPhase = Literal["pending", "running", "done", "error"]


def _set_audit_status(audit_id: str, payload: dict) -> None:
    """Upsert an audit status record, evicting the oldest entry when full."""
    _audit_status[audit_id] = payload
    _audit_status.move_to_end(audit_id)
    while len(_audit_status) > _AUDIT_STATUS_MAXSIZE:
        _audit_status.popitem(last=False)


# ---------------------------------------------------------------------------
# Logging configuration
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger("compliance_bridge")


# ---------------------------------------------------------------------------
# Application Langfuse client — initialised once at startup.
# Used ONLY by the GET /v1/prompts/:name proxy endpoint.
# The compliance project client lives in audit_workflow.py.
# ---------------------------------------------------------------------------

# Typed as Any because Langfuse is a lazy-loaded sentinel (None at module load).
# Using a specific type here would make the static checker infer the annotation
# from the None initialiser, causing false-positive attribute errors on call sites.
_app_langfuse: Any = None


def _get_app_langfuse() -> Any:
    """Return the singleton application Langfuse client, initialising on first call."""
    global _app_langfuse
    if _app_langfuse is None:
        # Populate the module-level Langfuse name (no-op if already patched by tests)
        _ensure_langfuse_imported()
        import sys as _sys

        _LangfuseCls = _sys.modules[__name__].Langfuse
        _app_langfuse = _LangfuseCls(
            public_key=os.environ.get("LANGFUSE_PUBLIC_KEY", ""),
            secret_key=os.environ.get("LANGFUSE_SECRET_KEY", ""),
            host=os.environ.get("LANGFUSE_HOST", "https://cloud.langfuse.com"),
        )
    return _app_langfuse


# ---------------------------------------------------------------------------
# Lifespan — initialise Langfuse on startup
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("🔄 compliance-bridge starting up…")

    # ------------------------------------------------------------------
    # POAM-012 / NIST SC-12: Fail fast if CAGE_ROUTING_SEAL_SECRET is
    # absent or is a known development default in non-dev environments.
    # ------------------------------------------------------------------
    _env = os.environ.get("ENVIRONMENT", "development").lower()
    _seal = os.environ.get("CAGE_ROUTING_SEAL_SECRET", "")
    _DEV_DEFAULTS = {"dev", "development", "changeme", "secret", "test", ""}
    if _env not in ("development", "dev", "test", "ci") and _seal in _DEV_DEFAULTS:
        raise RuntimeError(
            "[compliance-bridge] CAGE_ROUTING_SEAL_SECRET is absent or set to a "
            "known development default in a non-development environment. "
            "Set a strong secret to enable cryptographic enforcement of governance "
            "routing seals. (POAM-012 / NIST SC-12)"
        )

    # ------------------------------------------------------------------
    # POAM-014 / NIST SC-28: CMEK validation for evidence artifact storage.
    # Hard-fails in non-dev on missing/malformed key; GCS check is best-effort.
    # ------------------------------------------------------------------
    _cmek = validate_cmek_configuration()
    for _warn in _cmek.get("warnings", []):
        logger.warning("%s", _warn)
    if _cmek["cmek_enabled"]:
        logger.info(
            "✅ CMEK enabled: %s (bucket_verified=%s)",
            _cmek["key_name"],
            _cmek["bucket_verified"],
        )

    _get_app_langfuse()  # eager init so first request isn't slow

    # ------------------------------------------------------------------
    # C-08: Start KMS batch signer for evidence chain signing.
    # The signer is disabled by default (KMS_BATCH_ENABLED=false) and
    # must be explicitly enabled in production via env var.
    # assert_kms_active_in_production() enforces KMS mode in prod.
    # ------------------------------------------------------------------
    from .kms_batch_signer import _ENABLED as _KMS_ENABLED
    from .kms_batch_signer import get_batch_signer as _get_batch_signer

    _batch_signer = _get_batch_signer()
    if _KMS_ENABLED:
        await _batch_signer.start()
        logger.info("✅ KMS batch signer started")
        _env_for_kms = os.environ.get(
            "CAGE_ENV", "prod"
        ).lower()  # Default to "prod" to fail-secure: missing CAGE_ENV must not silently disable enforcement
        if _env_for_kms == "prod":
            _batch_signer.assert_kms_active_in_production()
    else:
        logger.info("[INFO] KMS batch signer disabled (KMS_BATCH_ENABLED != true)")

    # Start background tasks
    _sla_task = asyncio.create_task(run_sla_monitor(), name="sla-monitor")
    _lula_task = asyncio.create_task(run_lula_scheduler(), name="lula-scheduler")

    logger.info(
        "✅ compliance-bridge ready on port %s. Supported controls: %s",
        os.environ.get("PORT", "3001"),
        ", ".join(SUPPORTED_CONTROLS),
    )
    try:
        yield
    finally:
        for _task in (_sla_task, _lula_task):
            _task.cancel()
            try:
                await _task
            except asyncio.CancelledError:
                pass
        logger.info("🛑 compliance-bridge shutting down.")
        if _app_langfuse is not None:
            _app_langfuse.flush()


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Compliance Bridge + AARM Conformance",
    description=(
        "ISO 42001 Compliance Evidence Aggregator + CSA AARM Conformance Engine — "
        "Python FastAPI replacement for langfuse-bridge (TypeScript). CAGE v0.1.0."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

# ---------------------------------------------------------------------------
# CORS — the agentsight-ui dev server (Vite, :5173) and production UI origin
# both need cross-origin access to the SSE stream.
# ---------------------------------------------------------------------------

# M-13: Build CORS origin list without empty strings (empty string allows all origins)
_cors_origins: list[str] = [
    "http://localhost:5173",  # Vite dev server default
    "http://localhost:3000",  # Alternative dev port
    "http://127.0.0.1:5173",
    "http://127.0.0.1:3000",
]
_ui_origin = os.environ.get("UI_ORIGIN", "").strip()
if _ui_origin:
    _cors_origins.append(_ui_origin)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# GET /v1/events/stream — SSE governance event stream
#
# Primary real-time feed consumed by the agentsight-ui KernelDashboard.
# Each event is emitted as:
#   event: governance-event
#   data:  <JSON-serialised GovernanceEvent>
#
# The endpoint also sends a periodic heartbeat comment to keep the
# connection alive through proxies/load-balancers that time out idle HTTP.
#
# Client disconnects are handled gracefully: the async generator exits
# and the subscriber queue is removed from GovernanceEventBus automatically.
# ---------------------------------------------------------------------------


@app.get("/v1/events/stream", tags=["events"], summary="SSE governance event stream")
async def events_stream(request: Request) -> EventSourceResponse:
    """Stream governance events as Server-Sent Events.

    Consumed by ``KernelDashboard.tsx`` via::

        const es = new EventSource(`${BACKEND_URL}/v1/events/stream`);
        es.addEventListener('governance-event', handler);
    """

    async def _generator():
        logger.info(
            "[events_stream] New SSE client connected. Active subscribers: %d",
            event_bus.subscriber_count + 1,
        )
        try:
            async for gov_event in event_bus.subscribe():
                if await request.is_disconnected():
                    logger.info(
                        "[events_stream] SSE client disconnected (detected in loop)."
                    )
                    break
                yield {
                    "event": "governance-event",
                    "data": json.dumps(gov_event),
                }
        except asyncio.CancelledError:
            pass
        finally:
            logger.info(
                "[events_stream] SSE client disconnected. Remaining subscribers: %d",
                event_bus.subscriber_count,
            )

    return EventSourceResponse(
        _generator(),
        ping=30,  # send SSE comment ping every 30 s to prevent proxy timeouts
        ping_message_factory=lambda: ": heartbeat",
    )


# ---------------------------------------------------------------------------
# GET /health — liveness probe for Kubernetes
# ---------------------------------------------------------------------------


@app.get("/health", tags=["health"])
async def health() -> dict:
    """Liveness + dependency connectivity check (POAM-018).

    Returns HTTP 200 with detailed dependency status so Kubernetes health
    probes and operators can detect silent configuration failures without
    tailing pod logs.

    Fields:
        status:                      "ok" if the service is alive.
        service:                     Service name.
        version:                     CAGE compliance-bridge version.
        langfuse_compliance_configured: True if LANGFUSE_COMPLIANCE_PUBLIC_KEY
                                      and LANGFUSE_COMPLIANCE_SECRET_KEY are set.
        langfuse_app_configured:     True if LANGFUSE_PUBLIC_KEY and
                                      LANGFUSE_SECRET_KEY are set.
        oscal_storage_configured:    True if OSCAL_S3_ENDPOINT is set,
                                      indicating artifact storage is available.
        environment:                 Active CAGE_ENV / ENVIRONMENT value.
    """
    langfuse_compliance_configured = bool(
        os.environ.get("LANGFUSE_COMPLIANCE_PUBLIC_KEY")
        and os.environ.get("LANGFUSE_COMPLIANCE_SECRET_KEY")
    )
    langfuse_app_configured = bool(
        os.environ.get("LANGFUSE_PUBLIC_KEY") and os.environ.get("LANGFUSE_SECRET_KEY")
    )
    oscal_storage_configured = bool(os.environ.get("OSCAL_S3_ENDPOINT"))
    active_env = os.environ.get(
        "CAGE_ENV", os.environ.get("ENVIRONMENT", "prod")
    ).lower()  # Default to "prod" to fail-secure: missing CAGE_ENV must not silently disable enforcement

    return {
        "status": "ok",
        "service": "compliance-bridge",
        "version": "0.1.0",
        "langfuse_compliance_configured": langfuse_compliance_configured,
        "langfuse_app_configured": langfuse_app_configured,
        "oscal_storage_configured": oscal_storage_configured,
        "environment": active_env,
    }


# ---------------------------------------------------------------------------
# GET /v1/controls  (Tier 1.2)
#
# Discovery endpoint — returns the registry of supported controls filtered by
# CAGE_DEPLOYMENT_REGION.  Avoids callers (Lula, agentsight-ui) hard-coding
# the control list.
#
# FINDING-06 (MEDIUM): Previously returned all entries from SUPPORTED_CONTROLS
# (which included NIST/FedRAMP/EU AI Act) without filtering by
# CAGE_DEPLOYMENT_REGION.  Now reads the active region at request time and
# filters through get_control_meta(region) so each deployment only exposes
# its applicable controls.  Adds X-CAGE-Deployment-Region response header.
# ---------------------------------------------------------------------------


@app.get(
    "/v1/controls",
    tags=["compliance"],
    summary="List supported compliance controls for the active deployment region",
)
async def list_controls(
    framework: str | None = Query(
        default=None,
        description=(
            "Filter controls by framework short-name. "
            "Supported values depend on CAGE_DEPLOYMENT_REGION. "
            "Universal: iso42001, aarm. "
            "US_FED adds: fedramp, nist_ai_rmf. "
            "EU_ECB adds: eu_ai_act. "
            "APAC_MAS adds: mas_feat."
        ),
    ),
) -> dict:
    """Return the registry of supported controls for the active deployment region.

    The response is filtered by ``CAGE_DEPLOYMENT_REGION`` so that each
    deployment only exposes its applicable compliance framework controls.
    The active region is returned in the ``X-CAGE-Deployment-Region`` response
    header so API consumers know which region's controls are being returned.

    Pass ``?framework=iso42001`` to filter to universal ISO 42001 controls.
    Pass ``?framework=fedramp`` (US_FED only) to filter to FedRAMP controls.

    Response shape (unfiltered)::\n
        {\n
          \"controls\": [\n
            {\n
              \"control_id\": \"A.5.2\",\n
              \"name\": \"Social Impact Assessment\",\n
              \"iso_clause\": \"ISO/IEC 42001:2023 Annex A.5.2\",\n
              \"score_name\": \"iso42001.A.5.2.passed\",\n
              \"critical\": false,\n
              \"frameworks\": {\"iso42001\": \"Annex A.5.2\", ...}\n
            },\n
            ...\n
          ],\n
          \"total\": 9,\n
          \"framework_filter\": null,\n
          \"deployment_region\": \"US_FED\"\n
        }\n
    """
    from fastapi.responses import (
        JSONResponse,
    )

    # Default to "" (empty string) when CAGE_DEPLOYMENT_REGION is not set so that
    # get_control_meta("") returns only universal ISO 42001 controls.  Defaulting
    # to "US_FED" was incorrect — it caused NIST SP 800-53 controls to appear in
    # region-agnostic contexts (e.g. test environments, APAC_MAS deployments).
    active_region = os.environ.get("CAGE_DEPLOYMENT_REGION", "").strip().upper()
    region_controls = get_control_meta(active_region)

    # Build the set of framework names available for this region
    region_frameworks: set[str] = set()
    for _meta in region_controls.values():
        region_frameworks.update(_meta.get("frameworks", {}).keys())

    if framework is not None and framework not in region_frameworks:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "UNSUPPORTED_FRAMEWORK",
                "message": (
                    f"Framework '{framework}' is not recognised for region "
                    f"'{active_region}'. "
                    f"Supported: {', '.join(sorted(region_frameworks))}"
                ),
            },
        )

    if framework is not None:
        active_ids = [
            cid
            for cid, meta in region_controls.items()
            if framework in meta.get("frameworks", {})
        ]
    else:
        active_ids = list(region_controls.keys())

    controls = [
        {
            "control_id": cid,
            "name": region_controls[cid]["name"],
            "iso_clause": region_controls[cid]["iso_clause"],
            "score_name": region_controls[cid]["scoreName"],
            "critical": cid in CRITICAL_CONTROLS,
            "frameworks": region_controls[cid].get("frameworks", {}),
        }
        for cid in active_ids
    ]
    response_body = {
        "controls": controls,
        "total": len(controls),
        "framework_filter": framework,
        "deployment_region": active_region,
    }
    return JSONResponse(
        content=response_body,
        headers={"X-CAGE-Deployment-Region": active_region},
    )


# ---------------------------------------------------------------------------
# GET /v1/metrics/summary  (Tier 2.6)
#
# Aggregate endpoint — returns compliance posture across ALL supported controls
# in a single response.  Eliminates the need for N individual /v1/metrics calls
# from Lula and agentsight-ui.
# ---------------------------------------------------------------------------


@app.get(
    "/v1/metrics/summary",
    tags=["compliance"],
    summary="Aggregate compliance metrics across all controls",
)
async def get_metrics_summary(
    window_hours: int = Query(
        default=24, ge=1, le=720, description="Look-back window in hours"
    ),
) -> dict:
    """Return a single compliance posture snapshot across all supported controls.

    The control set is filtered by CAGE_DEPLOYMENT_REGION so that the summary
    only includes controls relevant to the active deployment region — consistent
    with the /v1/controls endpoint.

    Response shape::\n
        {\n
          \"overall_pass_rate\": 0.94,\n
          \"total_controls\":    9,\n
          \"passing_controls\":  8,\n
          \"failing_controls\":  [\"A.9.2\"],\n
          \"critical_fails\":    [\"A.9.2\"],\n
          \"window_hours\":      24,\n
          \"controls\":          { \"A.5.2\": <ComplianceMetrics>, ... }\n
        }\n
    """
    # Use region-filtered controls — consistent with /v1/controls endpoint.
    # CAGE_DEPLOYMENT_REGION="" returns universal ISO 42001 controls only.
    active_region = os.environ.get("CAGE_DEPLOYMENT_REGION", "").strip().upper()
    region_control_ids: list[str] = list(get_control_meta(active_region).keys())

    results: dict = {}
    failing: list[str] = []
    critical_fails: list[str] = []

    # Fetch all controls concurrently
    async def _fetch(cid: str) -> None:
        try:
            m = await get_compliance_metrics(cid, window_hours)
            results[cid] = m.model_dump()
            # A control is "failing" when safety_rate < 1.0 and not in grace period
            # M-10: safety_rate is None when no traces exist — treat as not-failing
            if (
                m.safety_rate is not None
                and m.safety_rate < 1.0
                and not m.startup_grace_active
            ):
                failing.append(cid)
                if cid in CRITICAL_CONTROLS:
                    critical_fails.append(cid)
        except Exception as exc:
            logger.warning("[metrics/summary] Failed to fetch %s: %s", cid, exc)
            results[cid] = {"error": str(exc)}

    try:
        await asyncio.wait_for(
            asyncio.gather(*[_fetch(cid) for cid in region_control_ids]),
            timeout=25.0,
        )
    except asyncio.TimeoutError:
        logger.warning(
            "[metrics/summary] gather timed out after 25s — returning partial results"
        )

    passing_count = len(region_control_ids) - len(failing)
    overall_rate = (
        passing_count / len(region_control_ids) if region_control_ids else 1.0
    )

    return {
        "overall_pass_rate": round(overall_rate, 4),
        "total_controls": len(region_control_ids),
        "passing_controls": passing_count,
        "failing_controls": sorted(failing),
        "critical_fails": sorted(critical_fails),
        "window_hours": window_hours,
        "controls": results,
    }


# ---------------------------------------------------------------------------
# GET /v1/oscal/assessment-results  (Tier 2.3)
#
# Generates a standards-compliant OSCAL 1.1.2 Assessment Results document
# from the current compliance posture.  Closes the loop with Lula — Lula can
# consume this output for automated re-validation without a CronJob run.
#
# Query params:
#   window_hours (int, default 24)  — evidence look-back window
#   format (str, default "json")    — "json" or "yaml"
#   audit_id (str, optional)        — supply a stable ID; auto-generated if absent
# ---------------------------------------------------------------------------


@app.get(
    "/v1/oscal/assessment-results",
    tags=["compliance"],
    summary="Export current compliance posture as OSCAL Assessment Results (NIST OSCAL 1.1.2)",
)
async def export_oscal_assessment_results(
    window_hours: int = Query(
        default=24, ge=1, le=720, description="Evidence look-back window"
    ),
    format: str = Query(
        default="json",
        pattern="^(json|yaml)$",
        description="Response format: json or yaml",
    ),
    audit_id: str | None = Query(
        default=None, description="Audit ID (auto-generated if absent)"
    ),
) -> JSONResponse:
    """Generate an OSCAL Assessment Results document from live metrics.

    The document is standards-compliant with NIST OSCAL 1.1.2 and can be
    consumed directly by Lula for automated re-validation.

    Each finding includes:
      - ``target.target-id`` — ISO 42001 / NIST control ID
      - ``target.status.state`` — ``satisfied`` (PASS) | ``not-satisfied`` (FAIL)
      - ``props.safety_rate`` — Langfuse-aggregated safety rate
      - ``props.evidence_age_seconds`` — seconds since last evidence trace
      - ``props.framework`` — cross-reference to EU AI Act / NIST AI RMF / FedRAMP
    """
    _audit_id = audit_id or f"cage-export-{int(time.time())}"
    controls_data: dict = {}

    async def _fetch(cid: str) -> None:
        try:
            # Per-fetch timeout (8s) ensures each Langfuse call gives up independently.
            # asyncio.to_thread() tasks cannot be cancelled once the OS thread is running,
            # so the outer gather timeout alone is insufficient — the event loop stays
            # blocked until all threads complete.  This inner timeout guarantees the
            # coroutine yields control back within 8s regardless of thread state.
            m = await asyncio.wait_for(
                get_compliance_metrics(cid, window_hours),
                timeout=8.0,
            )
            controls_data[cid] = m.model_dump()
        except asyncio.TimeoutError:
            logger.warning(
                "[oscal-export] Per-fetch timeout for %s — storing error result", cid
            )
            controls_data[cid] = {"error": f"fetch timeout after 8s for {cid}"}
        except Exception as exc:
            logger.warning("[oscal-export] Failed to fetch %s: %s", cid, exc)
            controls_data[cid] = {"error": str(exc)}

    try:
        await asyncio.wait_for(
            asyncio.gather(*[_fetch(cid) for cid in SUPPORTED_CONTROLS]),
            timeout=25.0,
        )
    except asyncio.TimeoutError:
        logger.warning(
            "[oscal-export] gather timed out after 25s — returning partial results"
        )

    findings = findings_from_metrics_dict(controls_data, _audit_id)
    doc = build_oscal_assessment_results(
        findings=findings,
        audit_id=_audit_id,
        window_hours=window_hours,
    )

    if format == "yaml":
        try:
            import yaml

            content = yaml.dump(doc, default_flow_style=False, allow_unicode=True)
            return JSONResponse(
                content={"yaml": content, "audit_id": _audit_id},
                headers={
                    "Content-Disposition": f'attachment; filename="assessment-results-{_audit_id}.yaml"'
                },
            )
        except ImportError:
            logger.warning("[oscal-export] PyYAML not installed — falling back to JSON")

    return JSONResponse(
        content={"document": doc, "audit_id": _audit_id},
        headers={
            "Content-Disposition": f'attachment; filename="assessment-results-{_audit_id}.json"'
        },
    )


# ---------------------------------------------------------------------------
# GET /v1/audit/status/{audit_id}  (Tier 1.3)
#
# Poll endpoint for async audit results.  POST /v1/audit/ingest stores results
# here so callers can retrieve them after an async ingest.
# ---------------------------------------------------------------------------


@app.get(
    "/v1/audit/status/{audit_id}",
    tags=["compliance"],
    summary="Poll the status of a previously submitted audit",
)
async def get_audit_status(audit_id: str) -> JSONResponse:
    """Return the current status of an audit submitted via POST /v1/audit/ingest.

    States:
      - ``pending``  — the audit_id was accepted but processing has not started.
      - ``running``  — the 5-step pipeline is in progress.
      - ``done``     — pipeline completed successfully.
      - ``error``    — pipeline failed (see ``error`` field).

    Returns 404 when the audit_id is unknown (not yet submitted, or evicted
    from the in-process LRU cache after 256 entries).
    """
    record = _audit_status.get(audit_id)
    if record is None:
        raise HTTPException(
            status_code=404,
            detail={"error": "AUDIT_NOT_FOUND", "audit_id": audit_id},
        )
    return JSONResponse(content=record)


# ---------------------------------------------------------------------------
# GET /v1/metrics/{control_id}
#
# Primary endpoint queried by Lula's `api` domain provider.
# Returns: ComplianceMetrics JSON (see types.py)
# Lula Rego accesses this as: input.langfuse_metrics_<controlId>
# ---------------------------------------------------------------------------


@app.get(
    "/v1/metrics/{control_id}",
    response_model=ComplianceMetrics,
    tags=["compliance"],
    summary="Get compliance metrics for a control ID",
)
async def get_metrics(
    control_id: str,
    window_hours: int = Query(
        default=24, ge=1, le=720, description="Look-back window in hours"
    ),
) -> ComplianceMetrics:
    if control_id not in SUPPORTED_CONTROLS:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "UNSUPPORTED_CONTROL",
                "message": (
                    f"Control ID '{control_id}' is not supported. "
                    f"Supported: {', '.join(SUPPORTED_CONTROLS)}"
                ),
            },
        )

    try:
        metrics = await get_compliance_metrics(control_id, window_hours)
        return metrics
    except Exception as exc:
        logger.error(
            "[compliance-bridge] Failed to fetch metrics for %s: %s", control_id, exc
        )
        raise HTTPException(
            status_code=500,
            detail={"error": "METRICS_FETCH_FAILED", "message": str(exc)},
        )


# ---------------------------------------------------------------------------
# POST /v1/audit/ingest
#
# Accepts OSCAL Assessment Result YAML from the Lula CronJob output,
# parses deterministically, persists to GCS, and ingests into Langfuse.
#
# Body: { oscal_yaml: str, audit_id?: str }
# ---------------------------------------------------------------------------


class AuditIngestRequest(BaseModel):
    oscal_yaml: str | None = None
    audit_id: str | None = None


async def _run_audit_workflow_background(oscal_yaml: str, audit_id: str) -> None:
    """Wrapper to run the audit workflow asynchronously in a background task."""
    try:
        result = await run_audit_workflow(oscal_yaml, audit_id)
        payload = {
            "phase": "done",
            "status": "ok",
            "audit_id": audit_id,
            "findings_count": result["findings_count"],
            "artifact_key": result["artifact_key"],
            "ingested": result["ingested"],
            "alerted": result["alerted"],
            "alert_targets": result["alert_targets"],
            "remediation_sent": result["remediation_sent"],
            "remediation_text": result["remediation_text"],
            "advisor_error": result["advisor_error"],
            "remediation_per_control": result.get("per_control", []),
            # CAGE v0.1.0 AARM fields
            "chain_root": result.get("chain_root"),
            "chain_length": result.get("chain_length"),
            "chain_integrity_valid": result.get("chain_integrity_valid"),
            "aarm_report_artifact": result.get("aarm_report_artifact"),
        }
        _set_audit_status(audit_id, payload)
    except ValueError as exc:
        logger.error("[compliance-bridge] Async Audit ingest parse error: %s", exc)
        _set_audit_status(
            audit_id,
            {
                "phase": "error",
                "audit_id": audit_id,
                "error": "OSCAL_PARSE_ERROR",
                "message": str(exc),
            },
        )
    except Exception as exc:
        logger.error("[compliance-bridge] Async Audit ingest failed: %s", exc)
        _set_audit_status(
            audit_id,
            {
                "phase": "error",
                "audit_id": audit_id,
                "error": "AUDIT_INGEST_FAILED",
                "message": str(exc),
            },
        )


@app.post("/v1/audit/ingest", tags=["compliance"], summary="Ingest OSCAL audit result")
async def audit_ingest(
    body: AuditIngestRequest,
    background_tasks: BackgroundTasks,
    background: bool = Query(
        default=False, description="Run ingestion in the background asynchronously"
    ),
    _auth: str = Depends(require_internal_token),
) -> JSONResponse:
    if not body.oscal_yaml or not body.oscal_yaml.strip():
        raise HTTPException(
            status_code=400,
            detail={
                "error": "MISSING_OSCAL_YAML",
                "message": "Request body must contain { oscal_yaml: string }",
            },
        )

    # Generate a stable auditId from the caller or derive from timestamp
    audit_id = (
        body.audit_id.strip()
        if (body.audit_id and body.audit_id.strip())
        else f"auto-{int(time.time() * 1000)}"
    )

    # Register the audit as "running" immediately so GET /v1/audit/status
    # returns a meaningful state even before the pipeline completes.
    _set_audit_status(audit_id, {"phase": "running", "audit_id": audit_id})

    if background:
        background_tasks.add_task(
            _run_audit_workflow_background, body.oscal_yaml, audit_id
        )
        return JSONResponse(
            content={
                "phase": "running",
                "status": "ok",
                "audit_id": audit_id,
                "findings_count": 0,
                "alerted": False,
                "remediation_sent": False,
                "advisor_error": None,
                "remediation_per_control": [],
            }
        )

    try:
        result = await run_audit_workflow(body.oscal_yaml, audit_id)
        payload = {
            "phase": "done",
            "status": "ok",
            "audit_id": audit_id,
            "findings_count": result["findings_count"],
            "artifact_key": result["artifact_key"],
            "ingested": result["ingested"],
            "alerted": result["alerted"],
            "alert_targets": result["alert_targets"],
            "remediation_sent": result["remediation_sent"],
            "remediation_text": result["remediation_text"],
            "advisor_error": result["advisor_error"],
            # Per-control advisory breakdown (Tier 3.1). Empty list when
            # no LLM advisory was generated (VLLM_BASE_URL unset, etc.).
            "remediation_per_control": result.get("per_control", []),
            # CAGE v0.1.0 AARM fields
            "chain_root": result.get("chain_root"),
            "chain_length": result.get("chain_length"),
            "chain_integrity_valid": result.get("chain_integrity_valid"),
            "aarm_report_artifact": result.get("aarm_report_artifact"),
        }
        _set_audit_status(audit_id, payload)
        return JSONResponse(content=payload)
    except ValueError as exc:
        # parse_oscal_yaml raises ValueError on invalid YAML
        logger.error("[compliance-bridge] Audit ingest parse error: %s", exc)
        _set_audit_status(
            audit_id,
            {
                "phase": "error",
                "audit_id": audit_id,
                "error": "OSCAL_PARSE_ERROR",
                "message": str(exc),
            },
        )
        raise HTTPException(
            status_code=422,
            detail={"error": "OSCAL_PARSE_ERROR", "message": str(exc)},
        )
    except Exception as exc:
        logger.error("[compliance-bridge] Audit ingest failed: %s", exc)
        _set_audit_status(
            audit_id,
            {
                "phase": "error",
                "audit_id": audit_id,
                "error": "AUDIT_INGEST_FAILED",
                "message": str(exc),
            },
        )
        raise HTTPException(
            status_code=500,
            detail={"error": "AUDIT_INGEST_FAILED", "message": str(exc)},
        )


# ---------------------------------------------------------------------------
# GET /v1/aarm/conformance-report  (CAGE v0.1.0)
#
# Returns the AARM Conformance Report Card as JSON or YAML.
# Dual-path: on-demand via this endpoint AND auto-generated by the audit pipeline.
# ---------------------------------------------------------------------------


@app.get(
    "/v1/aarm/conformance-report",
    tags=["compliance"],
    summary="AARM Conformance Report Card (CSA AARM v1.0 — 11 threat vectors)",
)
async def get_aarm_conformance_report(
    window_hours: int = Query(
        default=24, ge=1, le=720, description="Evidence look-back window"
    ),
    format: str = Query(
        default="json", pattern="^(json|yaml)$", description="Response format"
    ),
    include_narrative: bool = Query(
        default=False,
        description="Enrich with vLLM prose narratives (11 concurrent calls, Semaphore=3)",
    ),
    audit_id: str | None = Query(
        default=None, description="Audit ID (auto-generated if absent)"
    ),
) -> JSONResponse:
    """Generate an on-demand AARM Conformance Report Card.

    Joins the static 11-vector AARM threat ledger against live Lula compliance
    findings to produce per-vector verdicts: NEUTRALIZED | PARTIAL | EXPOSED.

    The report is also auto-generated and persisted to GCS/S3 at the end of
    every Lula-scheduled audit run (``<audit_id>/aarm_conformance.json``).

    When ``include_narrative=true`` and ``VLLM_BASE_URL`` is set, the vLLM
    diagnostic sidecar generates prose for each vector (asyncio.Semaphore(3)
    concurrency cap to prevent 429 saturation).
    """
    from .aarm_mapper import build_aarm_conformance_report
    from .aarm_report_generator import enrich_report_with_narratives
    from .oscal_exporter import (
        findings_from_metrics_dict,
    )

    _audit_id = audit_id or f"aarm-ondemand-{int(time.time())}"
    controls_data: dict = {}

    async def _fetch(cid: str) -> None:
        try:
            m = await get_compliance_metrics(cid, window_hours)
            controls_data[cid] = m.model_dump()
        except Exception as exc:
            logger.warning("[aarm-report] Failed to fetch %s: %s", cid, exc)
            controls_data[cid] = {"error": str(exc)}

    try:
        await asyncio.wait_for(
            asyncio.gather(*[_fetch(cid) for cid in SUPPORTED_CONTROLS]),
            timeout=25.0,
        )
    except asyncio.TimeoutError:
        logger.warning(
            "[aarm-report] gather timed out after 25s — returning partial results"
        )

    findings = findings_from_metrics_dict(controls_data, _audit_id)
    report = build_aarm_conformance_report(findings, audit_id=_audit_id)
    report_dict = report.model_dump()

    if include_narrative:
        narratives = await enrich_report_with_narratives(report)
        for vector in report_dict["vectors"]:
            vid = vector["vector_id"]
            if vid in narratives:
                vector["narrative"] = narratives[vid]

    if format == "yaml":
        try:
            import yaml

            content = yaml.dump(
                report_dict, default_flow_style=False, allow_unicode=True
            )
            return JSONResponse(
                content={"yaml": content, "audit_id": _audit_id},
                headers={
                    "Content-Disposition": f'attachment; filename="aarm-conformance-{_audit_id}.yaml"'
                },
            )
        except ImportError:
            logger.warning("[aarm-report] PyYAML not installed — falling back to JSON")

    return JSONResponse(
        content={"report": report_dict, "audit_id": _audit_id},
        headers={
            "Content-Disposition": f'attachment; filename="aarm-conformance-{_audit_id}.json"'
        },
    )


# ---------------------------------------------------------------------------
# GET  /v1/defer/pending         — list parked DEFER tokens
# POST /v1/defer/{id}/inject     — inject data to resolve a deferred token
# POST /v1/defer/{id}/escalate   — escalate to MANUAL_REVIEW
# (CAGE v0.1.0 — DEFER State Machine endpoints)
# ---------------------------------------------------------------------------


@app.get(
    "/v1/defer/pending",
    tags=["governance"],
    summary="List pending DEFER queue tokens (parked execution contexts)",
)
async def list_defer_pending(
    limit: int = Query(
        default=50, ge=1, le=200, description="Maximum tokens to return"
    ),
) -> JSONResponse:
    """Return all execution contexts currently parked in the DEFER queue.

    Tokens are returned in TTL-ascending order (soonest-expiring first).
    DEFER tokens are stored in Redis db=1 with noeviction policy.
    """
    redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379")
    # Return a lightweight stub when Redis is unavailable in non-production environments
    if not redis_url:
        return JSONResponse(
            content={"pending": [], "count": 0, "note": "REDIS_URL not configured"}
        )

    try:
        import redis.asyncio as aioredis

        from src.gateway.governance.defer_queue import DeferQueue

        client = aioredis.from_url(redis_url, db=1, decode_responses=True)
        queue = DeferQueue(client)
        tokens = await queue.list_pending(limit=limit)
        await client.aclose()

        return JSONResponse(
            content={
                "pending": [t.model_dump() for t in tokens],
                "count": len(tokens),
            }
        )
    except Exception as exc:
        logger.warning("[defer/pending] Failed to fetch pending tokens: %s", exc)
        raise HTTPException(
            status_code=503,
            detail={"error": "DEFER_QUEUE_UNAVAILABLE", "message": str(exc)},
        )


class DeferResolveRequest(BaseModel):
    injection_data: dict | None = None
    note: str | None = None


@app.post(
    "/v1/defer/{defer_id}/inject",
    tags=["governance"],
    summary="Inject data to resolve a deferred execution context",
)
async def defer_inject(
    defer_id: str,
    body: DeferResolveRequest,
) -> JSONResponse:
    """Resolve a parked DEFER token via automated data injection sweep.

    The resolved token's thread will be eligible for re-evaluation by
    the governing agent with the injected data appended to its context.
    """
    redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379")

    # Import DeferQueue — isolate ImportError / RuntimeError (e.g. missing
    # optional gateway deps like 'dowhy') from the token-not-found 404 path.
    try:
        import redis.asyncio as aioredis

        try:
            from src.gateway.governance.defer_queue import DeferQueue
        except ImportError:
            from gateway.governance.defer_queue import DeferQueue
    except (ImportError, RuntimeError) as exc:
        logger.warning("[defer/inject] DeferQueue import failed: %s", exc)
        raise HTTPException(
            status_code=503,
            detail={"error": "DEFER_QUEUE_UNAVAILABLE", "message": str(exc)},
        )

    try:
        client = aioredis.from_url(redis_url, db=1, decode_responses=True)
        queue = DeferQueue(client)
        resolved = await queue.resolve(
            defer_id, "INJECTED", injection_data=body.injection_data
        )
        await client.aclose()
        if resolved is None:
            raise HTTPException(
                status_code=404,
                detail={"error": "DEFER_TOKEN_NOT_FOUND", "defer_id": defer_id},
            )
    except HTTPException:
        raise
    except Exception as exc:
        # redis.exceptions.ConnectionError inherits from RedisError → Exception,
        # NOT from Python's built-in ConnectionError.  Detect by errno or message
        # so the integration test's skip guard fires on 503 instead of 500:
        #   if r.status_code == 503: pytest.skip("Redis db=1 unavailable")
        exc_str = str(exc)
        is_conn_err = (
            isinstance(exc, (ConnectionError, OSError))
            or "Connect call failed" in exc_str
            or "Connection refused" in exc_str
            or "Cannot assign requested address" in exc_str
            or "ConnectionError" in type(exc).__name__
        )
        if is_conn_err:
            logger.warning("[defer/inject] Redis connection error: %s", exc)
            raise HTTPException(
                status_code=503,
                detail={"error": "DEFER_QUEUE_UNAVAILABLE", "message": exc_str},
            )
        raise HTTPException(
            status_code=500, detail={"error": "DEFER_INJECT_FAILED", "message": exc_str}
        )

    # Publish DEFER_RESOLVED SSE event
    try:
        await event_bus.publish(
            {
                "type": "DEFER_RESOLVED",
                "traceId": resolved.defer_id,
                "controlId": "A.8.4",
                "result": None,
                "safetyRate": None,
                "auditId": resolved.thread_id,
                "resolution": "INJECTED",
                "timestamp": resolved.resolved_at_utc or "",
            }
        )
    except Exception:
        pass

    return JSONResponse(
        content={"status": "resolved", "defer_id": defer_id, "resolution": "INJECTED"}
    )


@app.post(
    "/v1/defer/{defer_id}/escalate",
    tags=["governance"],
    summary="Escalate a deferred token to MANUAL_REVIEW",
)
async def defer_escalate(
    defer_id: str,
) -> JSONResponse:
    """Escalate a DEFER-parked token to full HITL MANUAL_REVIEW.

    Use when automated data injection cannot resolve the ambiguity and
    a human operator must make the final judgment call.
    """
    redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379")

    # Import DeferQueue — isolate ImportError / RuntimeError (e.g. missing
    # optional gateway deps like 'dowhy') from the token-not-found 404 path.
    try:
        import redis.asyncio as aioredis

        try:
            from src.gateway.governance.defer_queue import DeferQueue
        except ImportError:
            from gateway.governance.defer_queue import DeferQueue
    except (ImportError, RuntimeError) as exc:
        logger.warning("[defer/escalate] DeferQueue import failed: %s", exc)
        raise HTTPException(
            status_code=503,
            detail={"error": "DEFER_QUEUE_UNAVAILABLE", "message": str(exc)},
        )

    try:
        client = aioredis.from_url(redis_url, db=1, decode_responses=True)
        queue = DeferQueue(client)
        resolved = await queue.resolve(defer_id, "ESCALATED")
        await client.aclose()
        if resolved is None:
            raise HTTPException(
                status_code=404,
                detail={"error": "DEFER_TOKEN_NOT_FOUND", "defer_id": defer_id},
            )
    except HTTPException:
        raise
    except Exception as exc:
        # redis.exceptions.ConnectionError inherits from RedisError → Exception,
        # NOT from Python's built-in ConnectionError.  Detect by message pattern.
        exc_str = str(exc)
        is_conn_err = (
            isinstance(exc, (ConnectionError, OSError))
            or "Connect call failed" in exc_str
            or "Connection refused" in exc_str
            or "Cannot assign requested address" in exc_str
            or "ConnectionError" in type(exc).__name__
        )
        if is_conn_err:
            logger.warning("[defer/escalate] Redis connection error: %s", exc)
            raise HTTPException(
                status_code=503,
                detail={"error": "DEFER_QUEUE_UNAVAILABLE", "message": exc_str},
            )
        raise HTTPException(
            status_code=500,
            detail={"error": "DEFER_ESCALATE_FAILED", "message": exc_str},
        )

    # Publish DEFER_RESOLVED SSE event
    try:
        await event_bus.publish(
            {
                "type": "DEFER_RESOLVED",
                "traceId": resolved.defer_id,
                "controlId": "A.8.4",
                "result": None,
                "safetyRate": None,
                "auditId": resolved.thread_id,
                "resolution": "ESCALATED",
                "timestamp": resolved.resolved_at_utc or "",
            }
        )
    except Exception:
        pass

    return JSONResponse(
        content={"status": "escalated", "defer_id": defer_id, "resolution": "ESCALATED"}
    )


# ---------------------------------------------------------------------------
# GET /v1/prompts/{name}
#
# Proxy endpoint — allows internal services to fetch Langfuse prompts via HTTP
# instead of using the SDK directly. Uses the *application* Langfuse client.
#
# Query params:
#   label             (default: "production")
#   cache_ttl_seconds (default: 300)
# ---------------------------------------------------------------------------


@app.get(
    "/v1/prompts/{name}", tags=["prompts"], summary="Fetch a Langfuse prompt by name"
)
async def get_prompt(
    name: str,
    label: str = Query(default="production", description="Langfuse prompt label"),
    cache_ttl_seconds: int = Query(
        default=300, ge=0, description="Cache TTL in seconds"
    ),
) -> dict:
    langfuse = _get_app_langfuse()

    def _fetch_sync() -> dict:
        prompt = langfuse.get_prompt(
            name, label=label, cache_ttl_seconds=cache_ttl_seconds
        )
        text = (
            prompt.prompt
            if isinstance(prompt.prompt, str)
            else __import__("json").dumps(prompt.prompt)
        )
        return {"name": name, "text": text, "version": str(prompt.version)}

    try:
        result = await asyncio.to_thread(_fetch_sync)
        logger.info("[prompts] fetched %s@%s", name, label)
        return result
    except Exception as exc:
        msg = str(exc)
        if "not found" in msg.lower() or "404" in msg:
            raise HTTPException(status_code=404, detail={"error": "prompt not found"})
        logger.error("[prompts] error fetching %s@%s: %s", name, label, msg)
        raise HTTPException(status_code=500, detail={"error": msg})


# ---------------------------------------------------------------------------
# Compliance Telemetry History API
# ---------------------------------------------------------------------------


def _get_compliance_api() -> Any:
    """Initialize the Langfuse API client for the compliance project."""
    _ensure_langfuse_imported()
    from langfuse.api import LangfuseAPI

    return LangfuseAPI(
        username=os.environ.get("LANGFUSE_COMPLIANCE_PUBLIC_KEY", ""),
        password=os.environ.get("LANGFUSE_COMPLIANCE_SECRET_KEY", ""),
        base_url=os.environ.get(
            "LANGFUSE_COMPLIANCE_HOST",
            os.environ.get("LANGFUSE_HOST", "https://cloud.langfuse.com"),
        ),
    )


def safe_map_trace(t: Any) -> dict:
    """Safely map a Langfuse trace to the dashboard TelemetryItem shape."""
    metadata = t.metadata or {}
    control_id = metadata.get("iso_42001_control", "")
    result = metadata.get("lula_result", None)
    safety_rate = metadata.get("safety_rate", None)
    audit_id = metadata.get("audit_id", "")

    # Safely identify event type
    event_type = "AUDIT_FINDING"
    tags = t.tags or []
    if (t.name == "remediation-advisory") or ("llm-remediation" in tags):
        event_type = "REMEDIATION_GENERATED"
    elif result == "FAIL" and control_id in CRITICAL_CONTROLS:
        event_type = "GOVERNANCE_VIOLATION"

    # Get control name
    control_name = control_id
    if control_id in CONTROL_META:
        control_name = CONTROL_META[control_id].get("name", control_id)

    timestamp_str = ""
    if t.timestamp:
        if hasattr(t.timestamp, "isoformat"):
            timestamp_str = t.timestamp.isoformat()
        else:
            timestamp_str = str(t.timestamp)

    model_name = metadata.get("model", None)

    return {
        "id": f"{audit_id}-{control_id}-{timestamp_str}"
        if audit_id and control_id
        else t.id,
        "traceId": t.id,
        "spanName": control_name or t.name or "Compliance Trace",
        "timestamp": timestamp_str,
        "safetyRate": safety_rate if safety_rate is not None else -1,
        "totalTraces": 0,
        "blockedTraces": 0,
        "type": event_type,
        "result": result,
        "auditId": audit_id,
        "modelName": model_name,
    }


@app.get(
    "/v1/telemetry/history",
    tags=["compliance"],
    summary="Fetch paginated historical telemetry from Langfuse compliance project",
)
async def get_telemetry_history(
    page: int = Query(default=1, ge=1, description="Page number"),
    limit: int = Query(default=20, ge=1, le=100, description="Items per page"),
    before_timestamp: str | None = Query(
        default=None, description="Cursor timestamp for pagination"
    ),
) -> dict:
    """Fetch paginated historical compliance telemetry.

    Supports optional `before_timestamp` cursor parameter to anchor pagination
    and protect against race conditions from concurrent live SSE streams.
    """
    from datetime import datetime

    to_ts = None
    if before_timestamp:
        try:
            # Parse ISO 8601 strings (replacing Zulu if needed)
            to_ts = datetime.fromisoformat(before_timestamp.replace("Z", "+00:00"))
        except Exception as e:
            logger.warning(
                "[telemetry/history] Failed to parse before_timestamp: %s", e
            )

    try:
        api = _get_compliance_api()

        def _fetch():
            return api.trace.list(page=page, limit=limit, to_timestamp=to_ts)

        traces = await asyncio.to_thread(_fetch)

        mapped = [safe_map_trace(t) for t in traces.data]

        # Determine if more pages exist using traces.meta if available, otherwise fallback to limit length
        has_more = len(mapped) == limit
        if hasattr(traces, "meta") and traces.meta:
            page_val = getattr(traces.meta, "page", None)
            total_pages = getattr(traces.meta, "total_pages", None)
            if page_val is not None and total_pages is not None:
                has_more = page_val < total_pages

        return {
            "telemetry": mapped,
            "hasMore": has_more,
            "page": page,
            "limit": limit,
        }
    except Exception as exc:
        logger.error("[telemetry/history] Failed to fetch compliance history: %s", exc)
        raise HTTPException(
            status_code=500,
            detail={"error": "HISTORY_FETCH_FAILED", "message": str(exc)},
        )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", "3001"))
    uvicorn.run(
        "compliance_bridge.main:app",
        host="0.0.0.0",
        port=port,
        log_config=None,  # use our logging config above
    )
