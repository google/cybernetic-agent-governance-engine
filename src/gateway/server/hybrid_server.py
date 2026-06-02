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

from fastapi import FastAPI

from src.gateway.server.mcp_tool_server import app as mcp_app
from src.gateway.server.inference_proxy import inference_app
from src.gateway.server.governance_middleware import governance_app
from src.gateway.tracing_setup import setup_tracing

logger = logging.getLogger("Gateway.HybridServer")


# ---------------------------------------------------------------------------
# Lifespan — initialise OTel tracing before the first request is served,
# regardless of whether the server is started via __main__ or uvicorn CLI.
# ---------------------------------------------------------------------------

@asynccontextmanager
async def _gateway_lifespan(app: FastAPI):
    """Ensure tracing is initialised for every launch path (uvicorn or __main__).

    Also performs proactive pre-warming to completely eliminate cold-start latencies:
      1. Pre-warms and shares NeMo Rails across all sub-apps (avoiding isolated JITs).
      2. Triggers a synthetic OPA evaluation to warm the Rego schema and HTTP connection.
      3. Handles External Normative Provider boot-time fetches if active.
    """
    import asyncio

    setup_tracing()
    logger.info("✅ Gateway tracing initialised via lifespan hook")

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
        "action": "execute_trade",
        "symbol": "AAPL",
        "amount": 100.0,
        "currency": "USD",
        "trader_role": "junior",
        "user_id": "system_warmup",
        "risk_profile": "moderate",
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
            logger.info(
                "✅ OPA trade governance policy confirmed active"
            )
        else:
            logger.warning(
                "⚠️ trade_governance.rego policy not confirmed active — "
                "OPA_POLICY_PATH may not include trade governance rules. "
                "Trade size RBAC will not be enforced."
            )
    except Exception as e:
        logger.warning(
            "⚠️ trade_governance.rego policy not confirmed active — "
            "OPA_POLICY_PATH may not include trade governance rules. "
            "Trade size RBAC will not be enforced."
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

    yield

    # Shutdown: cancel polling task if running
    if polling_task is not None:
        polling_task.cancel()
        try:
            await polling_task
        except asyncio.CancelledError:
            pass
    # No shutdown work required for tracing (BatchSpanProcessor flushes on GC).


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
    version="2.0.0",
    lifespan=_gateway_lifespan,
)

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
    from src.governed_financial_advisor.utils.telemetry import configure_telemetry

    configure_telemetry()
    http_port = int(os.getenv("PORT", "8080"))
    logging.basicConfig(level=logging.INFO)
    uvicorn.run(root_app, host="0.0.0.0", port=http_port)
