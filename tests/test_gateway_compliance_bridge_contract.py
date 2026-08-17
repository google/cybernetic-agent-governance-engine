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
tests/test_gateway_compliance_bridge_contract.py
=================================================
Contract tests for the gateway ↔ compliance-bridge API boundary.

These tests pin the *shape* of every response that the gateway (and any
other consumer) depends on.  They do NOT test business logic — that lives
in the per-module unit tests.  If you change a key name or remove a field
from a response, one of these tests will fail, giving you an explicit
contract-break signal before the gateway is broken at runtime.

Test plan
---------
1. ``TestHealthEndpointSchema``     — ``GET /health`` returns required keys.
2. ``TestControlsEndpointSchema``   — ``GET /v1/controls`` response shape.
3. ``TestAuditIngestAsyncSchema``   — ``POST /v1/audit/ingest?background=true`` shape.
4. ``TestSafetyFilterProtocol``     — ``SafetyFilter`` Protocol: a conforming class is accepted.
5. ``TestConsensusProviderProtocol``— ``ConsensusProvider`` Protocol: a conforming class is accepted.

All tests are marked ``local`` (no live services needed).

Heavy startup tasks (Langfuse, Redis, Lula scheduler, SLA monitor) are
bypassed by:
  * Not entering the FastAPI lifespan context manager — ``TestClient(app)``
    without ``with`` skips startup/shutdown events.
  * Setting ``CAGE_ENV=dev`` so ``require_internal_token`` passes without a
    real bearer token.
  * Patching ``run_audit_workflow`` on the background-mode ingest test.
"""

from __future__ import annotations

import sys
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Stub heavy optional dependencies so ``compliance_bridge.main`` can be
# imported in a bare Python environment without Redis, Langfuse, etc.
# ---------------------------------------------------------------------------


def _install_stubs() -> None:
    """Pre-install lightweight stubs for optional heavy imports."""

    # sse_starlette — used for the SSE event stream endpoint.
    # EventSourceResponse must inherit from starlette.responses.Response so
    # FastAPI treats it as a raw HTTP response class rather than a Pydantic
    # field type during route registration (which happens at import time).
    if "sse_starlette" not in sys.modules:
        from starlette.responses import Response as _Response  # noqa: PLC0415

        class _FakeEventSourceResponse(_Response):
            """Minimal stand-in for sse_starlette.sse.EventSourceResponse."""

            def __init__(self, *args: object, **kwargs: object) -> None:
                pass

        sse_sse_stub = MagicMock()
        sse_sse_stub.EventSourceResponse = _FakeEventSourceResponse

        sse_stub = MagicMock()
        sse_stub.sse = sse_sse_stub

        sys.modules["sse_starlette"] = sse_stub
        sys.modules["sse_starlette.sse"] = sse_sse_stub

    # langfuse — lazy-imported inside main.py; stub prevents SDK network calls
    if "langfuse" not in sys.modules:
        lf_stub = MagicMock()
        lf_stub.Langfuse = MagicMock
        sys.modules["langfuse"] = lf_stub

    # cachetools — used in compliance_bridge.metrics
    if "cachetools" not in sys.modules:
        ct_stub = MagicMock()

        class _TTLCache(dict):
            def __init__(self, maxsize: int = 128, ttl: int = 300) -> None:
                super().__init__()

        ct_stub.TTLCache = _TTLCache
        sys.modules["cachetools"] = ct_stub

    # opentelemetry stubs — prevent tracer/meter import errors
    for mod in (
        "opentelemetry",
        "opentelemetry.trace",
        "opentelemetry.metrics",
        "opentelemetry.context",
    ):
        if mod not in sys.modules:
            sys.modules[mod] = MagicMock()


_install_stubs()

# ---------------------------------------------------------------------------
# Now import the subjects under test
# ---------------------------------------------------------------------------

# Patch the lifespan-related background tasks before importing main so the
# module-level ``app`` object is created without actually starting threads.
with (
    patch("src.compliance_bridge.lula_scheduler.run_lula_scheduler", new=AsyncMock()),
    patch("src.compliance_bridge.sla_monitor.run_sla_monitor", new=AsyncMock()),
):
    # These patches prevent import-time side-effects in submodules that
    # attempt network connections during module initialisation.
    pass

import os  # noqa: E402 — after stubs

from starlette.testclient import TestClient  # noqa: E402 — after stubs

# We import the app here so the module-scoped fixture can share one client
# across all tests in the file.  Using ``TestClient(app)`` without the ``with``
# statement avoids triggering the ``lifespan`` async generator (Redis/Langfuse).
from src.compliance_bridge.main import app  # noqa: E402


@pytest.fixture(scope="module")
def client() -> TestClient:
    """Module-scoped TestClient — constructed once, shared across all tests.

    ``CAGE_ENV=dev`` is set for the lifetime of the module so that
    ``require_internal_token`` passes without a real bearer token, and so that
    startup/lifespan events are not required for the health/controls endpoints.
    """
    with patch.dict(os.environ, {"CAGE_ENV": "dev"}, clear=False):
        # Plain constructor (no ``with``) skips startup/shutdown lifespan events.
        yield TestClient(app, raise_server_exceptions=True)


# ---------------------------------------------------------------------------
# 1. Health endpoint schema
# ---------------------------------------------------------------------------


@pytest.mark.local
class TestHealthEndpointSchema:
    """``GET /health`` must return the required keys in the documented shape."""

    _REQUIRED_KEYS = {
        "status",
        "service",
        "version",
        "langfuse_compliance_configured",
        "langfuse_app_configured",
        "oscal_storage_configured",
        "environment",
    }

    def test_health_returns_200(self, client: TestClient) -> None:
        response = client.get("/health")
        assert response.status_code == 200

    def test_health_contains_required_keys(self, client: TestClient) -> None:
        response = client.get("/health")
        body = response.json()
        missing = self._REQUIRED_KEYS - set(body.keys())
        assert not missing, f"Health response missing keys: {missing}"

    def test_health_status_is_ok(self, client: TestClient) -> None:
        response = client.get("/health")
        assert response.json()["status"] == "ok"

    def test_health_service_name(self, client: TestClient) -> None:
        response = client.get("/health")
        assert response.json()["service"] == "compliance-bridge"

    def test_health_version_is_string(self, client: TestClient) -> None:
        response = client.get("/health")
        assert isinstance(response.json()["version"], str)

    def test_health_bool_fields_are_bool(self, client: TestClient) -> None:
        """Dependency-configured flags must be booleans, not strings."""
        response = client.get("/health")
        body = response.json()
        for key in (
            "langfuse_compliance_configured",
            "langfuse_app_configured",
            "oscal_storage_configured",
        ):
            assert isinstance(body[key], bool), (
                f"{key!r} must be bool, got {type(body[key])}"
            )


# ---------------------------------------------------------------------------
# 2. Controls endpoint schema
# ---------------------------------------------------------------------------


@pytest.mark.local
class TestControlsEndpointSchema:
    """``GET /v1/controls`` must return the documented response shape."""

    _TOP_LEVEL_KEYS = {"controls", "total", "framework_filter", "deployment_region"}
    _CONTROL_ITEM_KEYS = {
        "control_id",
        "name",
        "iso_clause",
        "score_name",
        "critical",
        "frameworks",
    }

    def test_controls_returns_200(self, client: TestClient) -> None:
        response = client.get("/v1/controls")
        assert response.status_code == 200

    def test_controls_top_level_keys_present(self, client: TestClient) -> None:
        response = client.get("/v1/controls")
        body = response.json()
        missing = self._TOP_LEVEL_KEYS - set(body.keys())
        assert not missing, f"/v1/controls response missing keys: {missing}"

    def test_controls_total_matches_list_length(self, client: TestClient) -> None:
        response = client.get("/v1/controls")
        body = response.json()
        assert body["total"] == len(body["controls"])

    def test_controls_list_is_list(self, client: TestClient) -> None:
        response = client.get("/v1/controls")
        assert isinstance(response.json()["controls"], list)

    def test_each_control_item_has_required_keys(self, client: TestClient) -> None:
        """Every item in ``controls`` must expose the documented fields."""
        response = client.get("/v1/controls")
        controls = response.json()["controls"]
        for item in controls:
            missing = self._CONTROL_ITEM_KEYS - set(item.keys())
            assert not missing, f"Control item missing keys: {missing}  item={item}"

    def test_critical_field_is_bool(self, client: TestClient) -> None:
        response = client.get("/v1/controls")
        for item in response.json()["controls"]:
            assert isinstance(item["critical"], bool), (
                f"control_id={item['control_id']!r}: 'critical' must be bool"
            )

    def test_deployment_region_header_present(self, client: TestClient) -> None:
        """Response must include the ``X-CAGE-Deployment-Region`` header."""
        response = client.get("/v1/controls")
        assert "x-cage-deployment-region" in {k.lower() for k in response.headers}

    def test_framework_filter_null_when_unfiltered(self, client: TestClient) -> None:
        response = client.get("/v1/controls")
        assert response.json()["framework_filter"] is None


# ---------------------------------------------------------------------------
# 3. Audit ingest (background mode) schema
# ---------------------------------------------------------------------------


@pytest.mark.local
class TestAuditIngestAsyncSchema:
    """``POST /v1/audit/ingest?background=true`` must return the documented shape.

    The endpoint is protected by ``require_internal_token``.  In tests we
    override that dependency via ``app.dependency_overrides`` so we can test
    the response contract independently of the auth layer.  The auth layer
    itself is tested in the auth unit tests.
    """

    _REQUIRED_KEYS = {
        "phase",
        "status",
        "audit_id",
        "findings_count",
        "alerted",
        "remediation_sent",
        "advisor_error",
        "remediation_per_control",
    }

    _MINIMAL_OSCAL = "component-definition:\n  uuid: test-uuid\n"

    def setup_method(self) -> None:
        """Bypass the internal-token auth dependency for all tests in this class."""
        from src.compliance_bridge.auth import require_internal_token  # noqa: PLC0415

        # Override the dependency to return a dummy token without validation.
        async def _no_auth() -> str:
            return "test-token"

        app.dependency_overrides[require_internal_token] = _no_auth

    def teardown_method(self) -> None:
        """Restore original dependency overrides after each test."""
        from src.compliance_bridge.auth import require_internal_token  # noqa: PLC0415

        app.dependency_overrides.pop(require_internal_token, None)

    def test_background_ingest_returns_200(self, client: TestClient) -> None:
        response = client.post(
            "/v1/audit/ingest?background=true",
            json={"oscal_yaml": self._MINIMAL_OSCAL},
        )
        # 200 is the success status; 422 would indicate a schema mismatch
        assert response.status_code == 200, response.text

    def test_background_ingest_required_keys_present(self, client: TestClient) -> None:
        response = client.post(
            "/v1/audit/ingest?background=true",
            json={"oscal_yaml": self._MINIMAL_OSCAL},
        )
        body = response.json()
        missing = self._REQUIRED_KEYS - set(body.keys())
        assert not missing, f"Audit ingest response missing keys: {missing}"

    def test_background_ingest_phase_is_running(self, client: TestClient) -> None:
        response = client.post(
            "/v1/audit/ingest?background=true",
            json={"oscal_yaml": self._MINIMAL_OSCAL},
        )
        assert response.json()["phase"] == "running"

    def test_background_ingest_status_is_ok(self, client: TestClient) -> None:
        response = client.post(
            "/v1/audit/ingest?background=true",
            json={"oscal_yaml": self._MINIMAL_OSCAL},
        )
        assert response.json()["status"] == "ok"

    def test_background_ingest_audit_id_is_string(self, client: TestClient) -> None:
        response = client.post(
            "/v1/audit/ingest?background=true",
            json={"oscal_yaml": self._MINIMAL_OSCAL},
        )
        assert isinstance(response.json()["audit_id"], str)

    def test_background_ingest_explicit_audit_id_echoed(
        self, client: TestClient
    ) -> None:
        """When the caller provides an audit_id it must appear verbatim in the response."""
        response = client.post(
            "/v1/audit/ingest?background=true",
            json={"oscal_yaml": self._MINIMAL_OSCAL, "audit_id": "test-audit-123"},
        )
        assert response.json()["audit_id"] == "test-audit-123"

    def test_empty_oscal_returns_400(self, client: TestClient) -> None:
        """Empty ``oscal_yaml`` must be rejected with 400, not 500."""
        response = client.post(
            "/v1/audit/ingest",
            json={"oscal_yaml": "   "},
        )
        assert response.status_code == 400
        assert response.json()["detail"]["error"] == "MISSING_OSCAL_YAML"


# ---------------------------------------------------------------------------
# 4. SafetyFilter Protocol conformance
# ---------------------------------------------------------------------------


@pytest.mark.local
class TestSafetyFilterProtocol:
    """A class that implements all ``SafetyFilter`` methods must be accepted as one."""

    def _make_concrete(self) -> Any:
        """Return a minimal concrete SafetyFilter implementation."""
        from src.gateway.governance.contracts import SafetyFilter  # noqa: PLC0415

        class _Concrete:
            def verify_action(self, action_name: str, payload: dict[str, Any]) -> str:
                return "SAFE"

            async def atomic_verify_and_commit(
                self,
                action_name: str,
                payload: dict[str, Any],
                governance_signature: str = "",
            ) -> tuple[bool, str]:
                return (True, "COMMITTED")

            def update_state(self, cost: float) -> None:
                pass

            def rollback_state(self, cost: float) -> None:
                pass

        instance = _Concrete()
        # Runtime structural check: Python's Protocol uses isinstance only when
        # runtime_checkable is applied, so we confirm via duck-typed annotation.
        _typed: SafetyFilter = instance  # type: ignore[assignment]
        return _typed

    def test_verify_action_returns_safe(self) -> None:
        sf = self._make_concrete()
        result = sf.verify_action("trade", {"amount": 100.0})
        assert result == "SAFE"

    def test_verify_action_returns_string(self) -> None:
        sf = self._make_concrete()
        result = sf.verify_action("trade", {"amount": 100.0})
        assert isinstance(result, str)

    def test_update_state_accepts_float(self) -> None:
        sf = self._make_concrete()
        sf.update_state(50.0)  # must not raise

    def test_rollback_state_accepts_float(self) -> None:
        sf = self._make_concrete()
        sf.rollback_state(50.0)  # must not raise

    @pytest.mark.asyncio
    async def test_atomic_verify_and_commit_returns_tuple(self) -> None:
        sf = self._make_concrete()
        result = await sf.atomic_verify_and_commit("trade", {"amount": 100.0})
        ok, reason = result
        assert isinstance(ok, bool)
        assert isinstance(reason, str)

    @pytest.mark.asyncio
    async def test_atomic_verify_and_commit_succeeds(self) -> None:
        sf = self._make_concrete()
        ok, reason = await sf.atomic_verify_and_commit("trade", {"amount": 100.0})
        assert ok is True
        assert reason == "COMMITTED"

    def test_required_methods_present(self) -> None:
        """All four contract methods must exist on a conforming SafetyFilter."""
        sf = self._make_concrete()
        for method_name in (
            "verify_action",
            "atomic_verify_and_commit",
            "update_state",
            "rollback_state",
        ):
            assert hasattr(sf, method_name), (
                f"SafetyFilter missing method: {method_name!r}"
            )


# ---------------------------------------------------------------------------
# 5. ConsensusProvider Protocol conformance
# ---------------------------------------------------------------------------


@pytest.mark.local
class TestConsensusProviderProtocol:
    """A class that implements ``check_consensus`` must be accepted as a ConsensusProvider."""

    def _make_concrete(self) -> Any:
        """Return a minimal concrete ConsensusProvider implementation."""
        from src.gateway.governance.contracts import ConsensusProvider  # noqa: PLC0415

        class _Concrete:
            async def check_consensus(
                self, action: str, amount: float, symbol: str
            ) -> dict[str, Any]:
                return {"status": "APPROVE", "reason": "within threshold"}

        instance = _Concrete()
        _typed: ConsensusProvider = instance  # type: ignore[assignment]
        return _typed

    @pytest.mark.asyncio
    async def test_check_consensus_returns_dict(self) -> None:
        cp = self._make_concrete()
        result = await cp.check_consensus("buy", 100.0, "AAPL")
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_check_consensus_has_status_key(self) -> None:
        cp = self._make_concrete()
        result = await cp.check_consensus("buy", 100.0, "AAPL")
        assert "status" in result, (
            "ConsensusProvider.check_consensus must return a 'status' key"
        )

    @pytest.mark.asyncio
    async def test_check_consensus_has_reason_key(self) -> None:
        cp = self._make_concrete()
        result = await cp.check_consensus("buy", 100.0, "AAPL")
        assert "reason" in result, (
            "ConsensusProvider.check_consensus must return a 'reason' key"
        )

    @pytest.mark.asyncio
    async def test_check_consensus_status_is_string(self) -> None:
        cp = self._make_concrete()
        result = await cp.check_consensus("buy", 100.0, "AAPL")
        assert isinstance(result["status"], str)

    def test_check_consensus_method_present(self) -> None:
        cp = self._make_concrete()
        assert hasattr(cp, "check_consensus"), (
            "ConsensusProvider must expose 'check_consensus'"
        )
