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

"""Unit tests for src/gateway/server/hybrid_server.py.

Covers:
  - _DebugEndpointGuard middleware (blocks /debug/* in prod, passes in dev)
  - healthz endpoint (KMS active, KMS inactive, exception paths)
  - _gateway_lifespan production startup guards (seal enforcement, governor
    posture refusals from _activate_domain)

All external dependencies are patched at both import time AND request-time to
ensure locally-imported modules inside the lifespan/endpoint coroutines use the
mocks rather than the real implementations.
"""

from __future__ import annotations

import os
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

pytestmark = pytest.mark.local


@pytest.fixture(autouse=True)
def _trusted_client_identities(monkeypatch):
    """Several tests import hybrid_server in a production posture, where
    ``load_identity_policy()`` refuses to start without trusted identities
    (POAM-2026-080). Supply one so those imports reach the code under test."""
    monkeypatch.setenv(
        "CAGE_TRUSTED_CLIENT_IDENTITIES",
        "advisor.cage.serviceaccount.identity.linkerd.cluster.local",
    )


# ---------------------------------------------------------------------------
# sys.modules stubs — allow hybrid_server to import without live services
# ---------------------------------------------------------------------------


def _make_hybrid_stubs() -> dict:
    """Build the minimal sys.modules patches needed for hybrid_server import."""
    mock_mcp_app = MagicMock()
    mock_mcp_app.title = "CAGE MCP Tool Server"
    mock_mcp_app.state = MagicMock()

    mock_inference_app = MagicMock()
    mock_inference_app.title = "CAGE Inference Proxy"
    mock_inference_app.state = MagicMock()

    mock_governance_app = MagicMock()
    mock_governance_app.title = "CAGE Governance Middleware"

    mock_kms_mod = MagicMock()
    mock_kms_mod.get_governance_signer = MagicMock(
        return_value=MagicMock(is_kms_active=True)
    )

    mock_seal_mod = MagicMock()
    mock_seal_mod.assert_custom_salt_in_production = MagicMock()
    mock_seal_mod.verify_seal = MagicMock()
    mock_seal_mod.SymbolicGovernorViolation = Exception

    mock_governor = MagicMock()
    mock_governor.components.opa.evaluate_policy = AsyncMock()

    return {
        # Sub-apps
        "src.gateway.server.mcp_tool_server": MagicMock(
            app=mock_mcp_app,
            mcp=MagicMock(),
            _activate_domain=AsyncMock(return_value=mock_governor),
        ),
        "src.gateway.governance.background_tasks": MagicMock(
            start_all=MagicMock(return_value=[])
        ),
        "src.gateway.server.inference_proxy": MagicMock(
            inference_app=mock_inference_app
        ),
        "src.gateway.server.governance_middleware": MagicMock(
            governance_app=mock_governance_app,
            enforce_governance=AsyncMock(return_value=MagicMock()),
        ),
        # Tracing
        "src.gateway.tracing_setup": MagicMock(setup_tracing=MagicMock()),
        # NeMo
        "src.integrations.nemo.manager": MagicMock(
            initialize_rails=MagicMock(return_value=MagicMock()),
            validate_with_nemo=AsyncMock(return_value=(True, "SAFE", True)),
        ),
        # Consensus
        "src.cage_finance.consensus.consensus": MagicMock(
            _background_audit_worker=AsyncMock()
        ),
        # KMS + Seal
        "src.gateway.governance.kms_signer": mock_kms_mod,
        "src.gateway.governance.routing_seal": mock_seal_mod,
        # Token quota + UCA
        "src.gateway.governance.token_quota_proxy": MagicMock(
            TokenQuotaProxy=MagicMock(from_env=MagicMock(return_value=MagicMock()))
        ),
        "src.gateway.governance.uca_logger": MagicMock(
            UCALogger=MagicMock(from_env=MagicMock(return_value=MagicMock()))
        ),
        # OTel
        "opentelemetry.instrumentation.fastapi": MagicMock(),
        "src.gateway.infrastructure.redis_client": MagicMock(
            redis_client=MagicMock(set=AsyncMock())
        ),
        "src.gateway.infrastructure.telemetry_client": MagicMock(
            configure_telemetry=MagicMock()
        ),
        "src.gateway.infrastructure.config_manager": MagicMock(
            config_manager=MagicMock(get=MagicMock(return_value="http://vllm:8000/v1"))
        ),
        # Agent registry (optional import)
        "src.gateway.governance.ingress.agent_registry_adapter": None,
        # Normative provider (only used if != static)
        "src.gateway.governance.normative_provider": MagicMock(
            NormativeProviderDaemon=MagicMock(
                from_env=MagicMock(
                    return_value=MagicMock(
                        boot_fetch=AsyncMock(),
                        start_polling=AsyncMock(),
                    )
                )
            )
        ),
    }


# ---------------------------------------------------------------------------
# _DebugEndpointGuard middleware — tests use the class directly
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_debug_guard_allows_debug_path_in_dev(monkeypatch):
    """In dev mode, requests to /debug/* pass through the middleware."""
    monkeypatch.setenv("CAGE_ENV", "dev")

    import httpx
    from fastapi import FastAPI
    from fastapi.responses import JSONResponse

    stubs = _make_hybrid_stubs()
    sys.modules.pop("src.gateway.server.hybrid_server", None)

    with patch.dict("sys.modules", stubs):
        from src.gateway.server.hybrid_server import _DebugEndpointGuard

    app = FastAPI()
    app.add_middleware(_DebugEndpointGuard)

    @app.get("/debug/state")
    async def _debug():
        return JSONResponse({"state": "ok"})

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get("/debug/state")

    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_debug_guard_blocks_debug_path_in_production(monkeypatch):
    """In production, requests to /debug/* return 404."""
    monkeypatch.setenv("CAGE_ENV", "production")

    import httpx
    from fastapi import FastAPI
    from fastapi.responses import JSONResponse

    stubs = _make_hybrid_stubs()
    sys.modules.pop("src.gateway.server.hybrid_server", None)

    with patch.dict("sys.modules", stubs):
        from src.gateway.server.hybrid_server import _DebugEndpointGuard

    app = FastAPI()
    app.add_middleware(_DebugEndpointGuard)

    @app.get("/debug/state")
    async def _debug():
        return JSONResponse({"state": "ok"})

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get("/debug/state")

    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_debug_guard_allows_non_debug_path_in_production(monkeypatch):
    """Non-/debug/* paths are always passed through."""
    monkeypatch.setenv("CAGE_ENV", "production")

    import httpx
    from fastapi import FastAPI
    from fastapi.responses import JSONResponse

    stubs = _make_hybrid_stubs()
    sys.modules.pop("src.gateway.server.hybrid_server", None)

    with patch.dict("sys.modules", stubs):
        from src.gateway.server.hybrid_server import _DebugEndpointGuard

    app = FastAPI()
    app.add_middleware(_DebugEndpointGuard)

    @app.get("/healthz")
    async def _health():
        return JSONResponse({"status": "ok"})

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get("/healthz")

    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_debug_guard_passes_test_mode(monkeypatch):
    """In test/local mode, /debug/* paths are passed through."""
    monkeypatch.setenv("CAGE_ENV", "test")

    import httpx
    from fastapi import FastAPI
    from fastapi.responses import JSONResponse

    stubs = _make_hybrid_stubs()
    sys.modules.pop("src.gateway.server.hybrid_server", None)

    with patch.dict("sys.modules", stubs):
        from src.gateway.server.hybrid_server import _DebugEndpointGuard

    app = FastAPI()
    app.add_middleware(_DebugEndpointGuard)

    @app.get("/debug/info")
    async def _debug():
        return JSONResponse({"info": "here"})

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get("/debug/info")

    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# healthz endpoint — tested by calling the handler function directly
# The handler does local imports, so we keep sys.modules patched during call.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_healthz_returns_200_kms_active_in_dev(monkeypatch):
    """In dev mode, /healthz returns 200 when KMS is active."""
    monkeypatch.setenv("CAGE_ENV", "dev")

    stubs = _make_hybrid_stubs()
    mock_signer = MagicMock()
    mock_signer.is_kms_active = True
    stubs["src.gateway.governance.kms_signer"].get_governance_signer = MagicMock(
        return_value=mock_signer
    )

    sys.modules.pop("src.gateway.server.hybrid_server", None)
    with patch.dict("sys.modules", stubs):
        from src.gateway.server.hybrid_server import healthz

        result = await healthz()

    assert result.status_code == 200
    import json

    body = json.loads(result.body)
    assert body["status"] == "healthy"


@pytest.mark.asyncio
async def test_healthz_returns_200_kms_active_in_prod(monkeypatch):
    """In production with KMS active, /healthz returns 200."""
    monkeypatch.setenv("CAGE_ENV", "production")

    stubs = _make_hybrid_stubs()
    mock_signer = MagicMock()
    mock_signer.is_kms_active = True
    stubs["src.gateway.governance.kms_signer"].get_governance_signer = MagicMock(
        return_value=mock_signer
    )

    sys.modules.pop("src.gateway.server.hybrid_server", None)
    with patch.dict("sys.modules", stubs):
        from src.gateway.server.hybrid_server import healthz

        result = await healthz()

    import json

    assert result.status_code == 200
    body = json.loads(result.body)
    assert body["kms_active"] is True


@pytest.mark.asyncio
async def test_healthz_returns_503_kms_inactive_in_prod(monkeypatch):
    """In production with KMS inactive, /healthz returns 503."""
    monkeypatch.setenv("CAGE_ENV", "production")

    stubs = _make_hybrid_stubs()
    mock_signer = MagicMock()
    mock_signer.is_kms_active = False
    stubs["src.gateway.governance.kms_signer"].get_governance_signer = MagicMock(
        return_value=mock_signer
    )

    sys.modules.pop("src.gateway.server.hybrid_server", None)
    with patch.dict("sys.modules", stubs):
        from src.gateway.server.hybrid_server import healthz

        result = await healthz()

    import json

    assert result.status_code == 503
    body = json.loads(result.body)
    assert body["status"] == "unhealthy"
    assert body["kms_active"] is False


@pytest.mark.asyncio
async def test_healthz_returns_503_on_kms_exception_in_prod(monkeypatch):
    """When KMS raises in production, /healthz returns 503."""
    monkeypatch.setenv("CAGE_ENV", "production")

    stubs = _make_hybrid_stubs()
    stubs["src.gateway.governance.kms_signer"].get_governance_signer = MagicMock(
        side_effect=RuntimeError("KMS unavailable")
    )

    sys.modules.pop("src.gateway.server.hybrid_server", None)
    with patch.dict("sys.modules", stubs):
        from src.gateway.server.hybrid_server import healthz

        result = await healthz()

    import json

    assert result.status_code == 503
    body = json.loads(result.body)
    assert body["status"] == "unhealthy"


@pytest.mark.asyncio
async def test_healthz_returns_200_on_kms_exception_in_dev(monkeypatch):
    """When KMS raises in dev mode, /healthz still returns 200."""
    monkeypatch.setenv("CAGE_ENV", "dev")

    stubs = _make_hybrid_stubs()
    stubs["src.gateway.governance.kms_signer"].get_governance_signer = MagicMock(
        side_effect=RuntimeError("KMS unavailable")
    )

    sys.modules.pop("src.gateway.server.hybrid_server", None)
    with patch.dict("sys.modules", stubs):
        from src.gateway.server.hybrid_server import healthz

        result = await healthz()

    import json

    assert result.status_code == 200
    body = json.loads(result.body)
    assert body["kms_active"] is False


# ---------------------------------------------------------------------------
# _gateway_lifespan — production startup guards.
# Keep sys.modules stubs active during the async execution.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("env", "refusal"),
    [
        (
            {"RECONCILIATION_PROVIDER": "stub"},
            "reconciliation_provider: RECONCILIATION_PROVIDER=stub",
        ),
        (
            {"RECONCILIATION_PROVIDER": "anchorage"},
            "kms_signing_mode: governance signer is in HMAC fallback mode",
        ),
    ],
    ids=["stub_ledger", "kms_not_active"],
)
@pytest.mark.asyncio
async def test_lifespan_aborts_when_governor_posture_is_refused(monkeypatch, env, refusal):
    """A PostureViolation from governor assembly aborts startup before serving.

    The stub-ledger (POAM-023) and KMS-signing-mode (K3) guards run in
    ``assert_production_posture`` inside ``_activate_domain``; the lifespan must
    propagate the refusal, never yield, and never start background tasks.
    """
    from src.gateway.governance.governor.posture import PostureViolation

    monkeypatch.setenv("CAGE_ENV", "production")
    monkeypatch.setenv("CAGE_NORMATIVE_PROVIDER", "static")
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    # The evidence sink's own enforcing-posture guard is covered in
    # tests/test_evidence_stream.py; stub it so this test reaches the governor.
    import src.gateway.governance.evidence.stream as _stream_mod

    monkeypatch.setattr(_stream_mod, "start_evidence_sink", AsyncMock(return_value=None))

    stubs = _make_hybrid_stubs()
    activate = AsyncMock(
        side_effect=PostureViolation(f"startup posture 'production' refused: {refusal}")
    )
    stubs["src.gateway.server.mcp_tool_server"]._activate_domain = activate
    start_all = stubs["src.gateway.governance.background_tasks"].start_all

    sys.modules.pop("src.gateway.server.hybrid_server", None)

    with patch.dict("sys.modules", stubs):
        from src.gateway.server.hybrid_server import _gateway_lifespan

        app_mock = MagicMock()
        app_mock.state = MagicMock()
        served = False

        with pytest.raises(PostureViolation, match=refusal):
            async with _gateway_lifespan(app_mock):
                served = True

    activate.assert_awaited_once()
    assert served is False
    start_all.assert_not_called()


# ---------------------------------------------------------------------------
# _gateway_lifespan — dev mode: lifespan completes without guards triggering
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_lifespan_succeeds_in_dev_mode(monkeypatch):
    """In dev mode, _gateway_lifespan yields without raising."""
    monkeypatch.setenv("CAGE_ENV", "ci")
    monkeypatch.setenv("RECONCILIATION_PROVIDER", "stub")  # only blocked in prod
    monkeypatch.setenv("CAGE_NORMATIVE_PROVIDER", "static")  # skip normative daemon

    stubs = _make_hybrid_stubs()

    sys.modules.pop("src.gateway.server.hybrid_server", None)

    with patch.dict("sys.modules", stubs):
        from src.gateway.server.hybrid_server import _gateway_lifespan

        app_mock = MagicMock()
        app_mock.state = MagicMock()

        async with _gateway_lifespan(app_mock):
            pass


@pytest.mark.asyncio
async def test_lifespan_installs_state_commitment_service(monkeypatch):
    """The lifespan exposes the kernel state-commitment service on app state.

    Development posture with no evidence sink still yields a service (it fails
    closed per request); enforcing postures refuse at startup instead
    (covered by ``tests/test_state_commitment_service.py``).
    """
    monkeypatch.setenv("CAGE_ENV", "ci")
    monkeypatch.setenv("RECONCILIATION_PROVIDER", "stub")
    monkeypatch.setenv("CAGE_NORMATIVE_PROVIDER", "static")

    stubs = _make_hybrid_stubs()
    sys.modules.pop("src.gateway.server.hybrid_server", None)

    with patch.dict("sys.modules", stubs):
        from src.gateway.governance.evidence.state_commitment import (
            StateCommitmentService,
        )
        from src.gateway.server.hybrid_server import _gateway_lifespan

        app_mock = MagicMock()
        app_mock.state = MagicMock()

        async with _gateway_lifespan(app_mock):
            assert isinstance(app_mock.state.state_commitments, StateCommitmentService)
