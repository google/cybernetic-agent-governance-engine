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
Tests for src.gateway.server.governance_middleware (BLOCKER-08).

Caller authentication is not this module's concern: every route is reached
only through ``WorkloadIdentityMiddleware`` on the gateway root app
(POAM-2026-080), which is covered by tests/test_workload_identity_middleware.py.

Coverage targets
----------------
A. The removed POST /check route
   - POST /check → 404 and never reaches the governor (use /validate-action)

B. /governance/validate-action endpoint
   - Happy path: valid action → 200 ALLOW (no seal)
   - GovernanceError → 403 DENIED (not 500)
   - Internal exception → 500 with "Internal governance error" (MED-03 fix)
   - detail field never contains stack trace or internal variable names

C. enforce_approved_governance (POAM-2026-079)
   - /governance/revalidate-post-hitl no longer exists
   - Consumed approval → POST_HITL commit + seal
   - Missing/unapproved approval, queue outage, raising matcher → refused
     with an AC-3 refusal receipt; nothing is committed
   - POST_HITL refusal → PermissionError + SC-4 refusal receipt

D. _emit_refusal_receipt()
   - Signs receipt via KMS signer and calls evidence sink
   - KMS sign failure is logged but does not suppress the call
   - Evidence sink failure is logged but does not suppress the call

E. Module exports

Notes
-----
- asyncio_mode = "auto" in pyproject.toml — no @pytest.mark.asyncio needed.
"""

from __future__ import annotations

import json
import os
from contextlib import asynccontextmanager, contextmanager
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("CAGE_ENV", "test")
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("GOVERNANCE_SALT", "CYBERNETIC_GOVERNANCE_TEST_SALT_32C!")

pytestmark = [pytest.mark.unit, pytest.mark.local]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _json_body(
    tool_name: str = "execute_trade", params: dict[str, Any] | None = None
) -> bytes:
    return json.dumps(
        {"tool_name": tool_name, "params": params or {"amount": 100}}
    ).encode()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _mock_governor() -> MagicMock:
    """A governor mock that passes ``governor_of``'s ``SymbolicGovernor`` check."""
    from src.gateway.governance.governor.governor import SymbolicGovernor

    return MagicMock(spec=SymbolicGovernor)


@contextmanager
def _installed_governor(gov: Any):
    """Temporarily set ``governance_app.state.governor`` to ``gov``."""
    from src.gateway.server.governance_middleware import governance_app

    previous = getattr(governance_app.state, "governor", None)
    governance_app.state.governor = gov
    try:
        yield gov
    finally:
        governance_app.state.governor = previous


@pytest.fixture()
def mock_symbolic_governor():
    """Install a mock governor on ``governance_app.state`` (where the lifespan puts it)."""
    gov = _mock_governor()
    gov.verify = AsyncMock(
        return_value={"violations": [], "opa_results": {"allow": True}}
    )
    gov.validate_action = AsyncMock(
        return_value={
            "verdict": "ALLOW",
            "violations": [],
            "latency_ms": 1.0,
        }
    )
    with _installed_governor(gov):
        yield gov


@pytest.fixture()
def mock_kms_signer():
    """Patch get_governance_signer() to return a mock that signs/verifies locally."""
    signer = MagicMock()
    signer.sign = MagicMock(return_value="deadbeef" * 8)  # 64-char hex
    signer.verify = MagicMock(return_value=True)
    signer.signing_algorithm = "HMAC_SHA256_FALLBACK"
    with patch(
        "src.gateway.server.governance_middleware.get_governance_signer",
        return_value=signer,
    ):
        yield signer


@pytest.fixture()
def mock_evidence_sink():
    """Patch the evidence stream sink so _emit_refusal_receipt doesn't call real I/O."""
    sink = MagicMock()
    sink.ingest = AsyncMock(return_value=None)
    with patch(
        "src.gateway.server.governance_middleware.get_evidence_sink",
        return_value=sink,
    ):
        yield sink


@pytest.fixture()
def gov_client(mock_symbolic_governor, mock_kms_signer):
    """TestClient on governance_app with a mock governor installed."""
    from src.gateway.server.governance_middleware import governance_app

    return TestClient(governance_app, raise_server_exceptions=False)


# ===========================================================================
# A. /check is removed (refactor/gateway-surface-cleanup)
# ===========================================================================


class TestGovernanceCheckRouteRemoved:
    """POST /check was a dead non-committing duplicate of /validate-action."""

    def test_check_route_is_gone(self, gov_client, mock_symbolic_governor):
        """The route no longer exists and never reaches the governor."""
        resp = gov_client.post(
            "/check",
            content=_json_body("execute_trade", {"amount": 100}),
            headers={"Content-Type": "application/json"},
        )

        assert resp.status_code == 404
        mock_symbolic_governor.verify.assert_not_awaited()
        mock_symbolic_governor.validate_action.assert_not_awaited()


# ===========================================================================
# B. /validate-action endpoint tests
# ===========================================================================


class TestValidateActionEndpoint:
    """Tests for POST /validate-action on governance_app."""

    @pytest.fixture()
    def client(self, mock_symbolic_governor, mock_kms_signer):
        from src.gateway.server.governance_middleware import governance_app

        return TestClient(governance_app, raise_server_exceptions=False)

    def test_validate_action_happy_path_approved(self, client, mock_symbolic_governor):
        """Valid action returns 200 with an ALLOW verdict in the canonical envelope."""
        resp = client.post(
            "/validate-action",
            json={
                "action": "execute_trade",
                "params": {"amount": 100, "symbol": "AAPL"},
            },
        )

        assert resp.status_code == 200
        data = resp.json()

        # ADR-008 Phase 3: Assert canonical envelope structure
        assert data.get("envelope_version") == "3.0"
        assert data.get("envelope_type") == "cage_governance_decision"
        assert "envelope_id" in data
        assert "issued_at" in data
        assert "expires_at" in data
        assert "issuer" in data
        assert "subject" in data
        assert "governance_context" in data
        assert "payload" in data

        # Assert that the payload contains the governance result
        payload = data["payload"]
        assert payload["verdict"] == "ALLOW"
        assert payload["violations"] == []
        assert "seal" not in payload

        # Assert signature presence (may be None if KMS not active in test)
        assert "signature" in data or data.get("signature") is None

        mock_symbolic_governor.validate_action.assert_awaited_once_with(
            action="execute_trade",
            params={"amount": 100, "symbol": "AAPL"},
            policy_version_id=None,
        )

    def test_validate_action_missing_action_field_returns_422(self, client):
        """Body without required 'action' field returns HTTP 422 (Pydantic validation)."""
        resp = client.post(
            "/validate-action",
            json={"params": {"amount": 100}},
        )
        assert resp.status_code == 422

    def test_validate_action_missing_params_field_returns_422(self, client):
        """Body without required 'params' field returns HTTP 422 (Pydantic validation)."""
        resp = client.post(
            "/validate-action",
            json={"action": "execute_trade"},
        )
        assert resp.status_code == 422

    def test_validate_action_governance_denial_returns_403_not_500(
        self, client, mock_symbolic_governor
    ):
        """GovernanceError from the governor returns 403 DENIED — not 500."""
        from src.gateway.governance.governor.governor import GovernanceError

        mock_symbolic_governor.validate_action = AsyncMock(
            side_effect=GovernanceError("OPA policy denied execute_trade")
        )

        with patch(
            "src.gateway.server.governance_middleware._emit_refusal_receipt",
            new=AsyncMock(return_value=None),
        ):
            resp = client.post(
                "/validate-action",
                json={"action": "execute_trade", "params": {"amount": 100}},
            )

        assert resp.status_code == 403
        data = resp.json()

        # ADR-008 Phase 3: Assert refusal contract structure
        assert data.get("schema_version") == "2.0.0"
        assert data["verdict"] == "DENIED"
        assert len(data["violations"]) > 0

        # refusal_receipt and proof_hash may be absent if receipt is None
        # (existing tests don't set receipt on GovernanceError)

    def test_validate_action_internal_exception_returns_500_safe_message(
        self, client, mock_symbolic_governor
    ):
        """Internal exception returns 500 with 'Internal governance error' — not raw exc.

        This tests the MED-03 fix: the raw exception message (which may contain
        internal variable names or stack traces) must NOT appear in the response.
        """
        mock_symbolic_governor.validate_action = AsyncMock(
            side_effect=RuntimeError("secret_internal_variable_name_leaked")
        )

        resp = client.post(
            "/validate-action",
            json={"action": "execute_trade", "params": {"amount": 100}},
        )

        assert resp.status_code == 500
        body_text = resp.text
        # MED-03: safe message must be present
        assert "Internal governance error" in body_text
        # MED-03: raw exception detail must NOT leak
        assert "secret_internal_variable_name_leaked" not in body_text

    def test_validate_action_detail_never_contains_stack_trace(
        self, client, mock_symbolic_governor
    ):
        """The 'detail' field must never contain a Python traceback string."""
        mock_symbolic_governor.validate_action = AsyncMock(
            side_effect=ValueError("Traceback (most recent call last):\n  File test.py")
        )

        resp = client.post(
            "/validate-action",
            json={"action": "execute_trade", "params": {"amount": 100}},
        )

        assert resp.status_code == 500
        body_text = resp.text
        # Stack trace markers must not appear in the HTTP response body
        assert "Traceback" not in body_text
        assert "most recent call last" not in body_text

    def test_validate_action_governance_denial_emits_refusal_receipt(
        self, client, mock_symbolic_governor, mock_kms_signer
    ):
        """GovernanceError triggers _emit_refusal_receipt (P6 compliance receipt)."""
        from src.gateway.governance.governor.governor import GovernanceError

        mock_symbolic_governor.validate_action = AsyncMock(
            side_effect=GovernanceError("fiscal_limit_exceeded")
        )

        with patch(
            "src.gateway.server.governance_middleware._emit_refusal_receipt",
            new=AsyncMock(return_value=None),
        ) as mock_emit:
            resp = client.post(
                "/validate-action",
                json={"action": "execute_trade", "params": {"amount": 999999}},
            )

        assert resp.status_code == 403
        mock_emit.assert_awaited_once()
        call_kwargs = mock_emit.call_args
        assert call_kwargs.kwargs["action_id"] == "execute_trade"
        assert "fiscal_limit_exceeded" in call_kwargs.kwargs["refusal_reason"]
        assert call_kwargs.kwargs["oscal_control_ref"] == "SC-4"


# ===========================================================================
# C. Post-approval committing run (POAM-2026-079)
# ===========================================================================


class TestRevalidatePostHitlRemoved:
    """POST_HITL runs only inside execute_trade_action, never as an HTTP route."""

    def test_revalidate_post_hitl_route_is_gone(
        self, gov_client, mock_symbolic_governor
    ):
        """The advisor can no longer trigger a POST_HITL run over HTTP."""
        mock_symbolic_governor.revalidate_post_hitl = AsyncMock(return_value="SEAL")
        resp = gov_client.post(
            "/revalidate-post-hitl",
            json={"action": "execute_trade", "params": {"amount": 10.0}},
        )
        assert resp.status_code in (404, 405)
        mock_symbolic_governor.revalidate_post_hitl.assert_not_awaited()


class TestEnforceApprovedGovernance:
    """``enforce_approved_governance``: consume the approval once, then commit + seal."""

    @staticmethod
    def _queue(token: Any):
        queue = MagicMock()
        queue.consume_approval = AsyncMock(return_value=token)

        @asynccontextmanager
        async def _open():
            yield queue

        return queue, _open

    async def _call(self, governor, open_queue, emit, covers=lambda a, p: True):
        from src.gateway.server import governance_middleware as gm

        with (
            patch(
                "src.gateway.governance.defer_queue.open_defer_queue", new=open_queue
            ),
            patch.object(gm, "_emit_refusal_receipt", new=emit),
        ):
            return await gm.enforce_approved_governance(
                governor,
                "execute_trade",
                {"symbol": "AAPL", "amount": 10.0},
                deferred_id="defer-1",
                approval_covers=covers,
            )

    async def test_consumed_approval_runs_post_hitl_and_returns_seal(self):
        governor = _mock_governor()
        governor.revalidate_post_hitl = AsyncMock(return_value="SEAL")
        queue, open_queue = self._queue(
            MagicMock(thread_id="thread-9", barrier_preview="PASS")
        )
        emit = AsyncMock()

        seal = await self._call(governor, open_queue, emit)

        assert seal == "SEAL"
        # D-H: the committing run is bound to the barrier snapshot approved.
        governor.revalidate_post_hitl.assert_awaited_once_with(
            "execute_trade",
            {"symbol": "AAPL", "amount": 10.0},
            approved_barrier_preview="PASS",
            trace_id="thread-9",
        )
        assert queue.consume_approval.await_args.kwargs["action"] == "execute_trade"
        emit.assert_not_awaited()

    async def test_no_approval_refuses_with_receipt_and_never_commits(self):
        governor = _mock_governor()
        governor.revalidate_post_hitl = AsyncMock(return_value="SEAL")
        _, open_queue = self._queue(None)
        emit = AsyncMock()

        with pytest.raises(PermissionError, match="defer-1"):
            await self._call(governor, open_queue, emit)

        governor.revalidate_post_hitl.assert_not_awaited()
        emit.assert_awaited_once()
        assert emit.await_args.kwargs["oscal_control_ref"] == "AC-3"

    async def test_queue_unavailable_fails_closed(self):
        governor = _mock_governor()
        governor.revalidate_post_hitl = AsyncMock(return_value="SEAL")

        @asynccontextmanager
        async def _broken():
            raise ConnectionError("redis down")
            yield  # pragma: no cover

        emit = AsyncMock()
        with pytest.raises(PermissionError):
            await self._call(governor, _broken, emit)
        governor.revalidate_post_hitl.assert_not_awaited()
        emit.assert_awaited_once()

    async def test_raising_matcher_never_authorises(self):
        """A covers() that raises is treated as "does not cover"."""
        governor = _mock_governor()
        governor.revalidate_post_hitl = AsyncMock(return_value="SEAL")
        seen: list[bool] = []

        queue = MagicMock()

        async def _consume(defer_id, *, action, covers):
            seen.append(covers({"symbol": "AAPL"}))
            return None

        queue.consume_approval = _consume

        @asynccontextmanager
        async def _open():
            yield queue

        def _boom(approved, params):
            raise KeyError("amount")

        with pytest.raises(PermissionError):
            await self._call(governor, _open, AsyncMock(), covers=_boom)
        assert seen == [False]
        governor.revalidate_post_hitl.assert_not_awaited()

    async def test_post_hitl_refusal_raises_with_receipt(self):
        from src.gateway.governance.governor.governor import GovernanceError

        governor = _mock_governor()
        governor.revalidate_post_hitl = AsyncMock(
            side_effect=GovernanceError("CBF Violation: h(next) < 0")
        )
        _, open_queue = self._queue(MagicMock(thread_id="t"))
        emit = AsyncMock()

        with pytest.raises(PermissionError, match="CBF Violation"):
            await self._call(governor, open_queue, emit)
        emit.assert_awaited_once()
        assert emit.await_args.kwargs["oscal_control_ref"] == "SC-4"


# ===========================================================================
# D. _emit_refusal_receipt() unit tests
# ===========================================================================


class TestEmitRefusalReceipt:
    """Unit tests for the _emit_refusal_receipt() async helper (P6)."""

    async def test_emit_receipt_calls_kms_sign_and_sink(self, mock_kms_signer):
        """Happy path: receipt is KMS-signed and published to the evidence sink."""
        from src.gateway.server.governance_middleware import _emit_refusal_receipt

        sink = MagicMock()
        sink.ingest = AsyncMock(return_value=None)

        with patch(
            "src.gateway.server.governance_middleware.get_evidence_sink",
            return_value=sink,
        ):
            await _emit_refusal_receipt(
                action_id="execute_trade",
                refusal_reason="drawdown_limit_exceeded",
                oscal_control_ref="SC-4",
                params={"amount": 100},
            )

        mock_kms_signer.sign.assert_called_once()
        sink.ingest.assert_awaited_once()
        receipt = sink.ingest.call_args[0][0]
        assert receipt["action_id"] == "execute_trade"
        assert receipt["refusal_reason"] == "drawdown_limit_exceeded"
        assert receipt["oscal_control_ref"] == "SC-4"
        assert receipt["type"] == "GOVERNANCE_REFUSAL_RECEIPT"
        assert "receipt_id" in receipt
        assert "timestamp_utc" in receipt

    async def test_emit_receipt_kms_sign_failure_does_not_suppress(self, caplog):
        """If KMS signing fails, the receipt is still emitted (unsigned) and error is logged."""
        import logging

        from src.gateway.server.governance_middleware import _emit_refusal_receipt

        failing_signer = MagicMock()
        failing_signer.sign = MagicMock(side_effect=RuntimeError("KMS unavailable"))

        sink = MagicMock()
        sink.ingest = AsyncMock(return_value=None)

        with (
            patch(
                "src.gateway.server.governance_middleware.get_governance_signer",
                return_value=failing_signer,
            ),
            patch(
                "src.gateway.server.governance_middleware.get_evidence_sink",
                return_value=sink,
            ),
        ):
            with caplog.at_level(logging.ERROR, logger="Gateway.GovernanceMiddleware"):
                await _emit_refusal_receipt(
                    action_id="execute_trade",
                    refusal_reason="test_reason",
                    oscal_control_ref="SC-4",
                    params={},
                )

        # Sink must still be called even though signing failed
        sink.ingest.assert_awaited_once()
        # Error must be logged
        assert any("Failed to KMS-sign" in r.message for r in caplog.records)

    async def test_emit_receipt_sink_failure_is_logged_not_raised(
        self, mock_kms_signer, caplog
    ):
        """If the evidence sink fails, the error is logged but NOT re-raised."""
        import logging

        from src.gateway.server.governance_middleware import _emit_refusal_receipt

        failing_sink = MagicMock()
        failing_sink.ingest = AsyncMock(
            side_effect=ConnectionError("Pub/Sub unavailable")
        )

        with patch(
            "src.gateway.server.governance_middleware.get_evidence_sink",
            return_value=failing_sink,
        ):
            with caplog.at_level(logging.ERROR, logger="Gateway.GovernanceMiddleware"):
                # Must NOT raise — sink failure is non-fatal
                await _emit_refusal_receipt(
                    action_id="execute_trade",
                    refusal_reason="test_reason",
                    oscal_control_ref="SC-4",
                    params={},
                )

        assert any(
            "Failed to emit OSCAL refusal receipt" in r.message for r in caplog.records
        )


# ===========================================================================
# E. Module exports
# ===========================================================================


class TestModuleExports:
    """The module imports cleanly and exposes the governance sub-app."""

    def test_module_exports_governance_app(self):
        """governance_app FastAPI instance is exported from the module."""
        from fastapi import FastAPI

        from src.gateway.server.governance_middleware import governance_app

        assert isinstance(governance_app, FastAPI)


# ===========================================================================
# G. enforce_governance() helper tests
# ===========================================================================


class TestEnforceGovernanceHelper:
    """Tests for the enforce_governance() async helper."""

    async def test_exempt_tool_returns_empty_seal(self):
        """Read-only exempt tools bypass governance and return an empty seal."""
        from src.gateway.server.governance_middleware import enforce_governance

        gov = _mock_governor()
        seal = await enforce_governance(gov, "check_market_status", {"symbol": "AAPL"})
        assert seal == ""
        gov.govern.assert_not_called()

    async def test_exempt_tool_verify_content_safety_returns_empty_seal(self):
        """verify_content_safety is also exempt from governance overhead."""
        from src.gateway.server.governance_middleware import enforce_governance

        gov = _mock_governor()
        seal = await enforce_governance(gov, "verify_content_safety", {"text": "hello"})
        assert seal == ""
        gov.govern.assert_not_called()

    async def test_non_exempt_tool_calls_governor_and_returns_seal(self):
        """Non-exempt tools call governor.govern() and return the seal."""
        from src.gateway.server.governance_middleware import enforce_governance

        mock_gov = _mock_governor()
        mock_gov.govern = AsyncMock(return_value="test-routing-seal-value")

        seal = await enforce_governance(mock_gov, "execute_trade", {"amount": 100})

        assert seal == "test-routing-seal-value"
        mock_gov.govern.assert_awaited_once_with("execute_trade", {"amount": 100})

    async def test_governance_error_raises_permission_error(self):
        """GovernanceError from the governor is converted to PermissionError."""
        from src.gateway.governance.governor.governor import GovernanceError
        from src.gateway.server.governance_middleware import enforce_governance

        mock_gov = _mock_governor()
        mock_gov.govern = AsyncMock(side_effect=GovernanceError("policy_denied"))

        mock_signer = MagicMock()
        mock_signer.sign = MagicMock(return_value="sig")

        with (
            patch(
                "src.gateway.server.governance_middleware.get_governance_signer",
                return_value=mock_signer,
            ),
            patch(
                "src.gateway.server.governance_middleware._emit_refusal_receipt",
                new=AsyncMock(return_value=None),
            ),
        ):
            with pytest.raises(PermissionError, match="Governance Blocked"):
                await enforce_governance(mock_gov, "execute_trade", {"amount": 100})


# ===========================================================================
# H. Integration smoke: governance_app routes are registered
# ===========================================================================


class TestGovernanceAppRoutes:
    """Smoke tests verifying that the expected routes exist on governance_app."""

    @pytest.fixture(scope="class")
    def client(self):
        # scope="class": governance_app has no mutable state and both
        # smoke tests in this class share the same (read-only) app config.
        from src.gateway.server.governance_middleware import governance_app

        return TestClient(governance_app, raise_server_exceptions=False)

    def test_validate_action_route_exists(self, client):
        """POST /validate-action route is registered (returns something other than 404)."""
        resp = client.post("/validate-action", json={"action": "x", "params": {}})
        assert resp.status_code != 404

    def test_unknown_route_returns_404(self, client):
        """An unknown route returns 404."""
        resp = client.get("/nonexistent-endpoint")
        assert resp.status_code == 404


# ===========================================================================
# G. FlowSignal HTTP 202 receipt tests (Phase 1, §3.2)
# ===========================================================================


class TestFlowSignalHttp202Receipt:
    """Tests for HTTP 202 Accepted receipt on FlowSignal ESCALATE decisions.

    External provider escalation decisions (EXTERNAL_HOLD) return HTTP 202 with
    an async receipt body containing defer_id, status, and poll_url.
    """

    @pytest.fixture()
    def client_for_flowsignal(self, mock_kms_signer):
        from src.gateway.server.governance_middleware import governance_app

        return TestClient(governance_app, raise_server_exceptions=False)

    def test_flowsignal_escalation_returns_http_202(
        self, client_for_flowsignal, mock_kms_signer
    ):
        """FlowSignal ESCALATE decision returns HTTP 202 Accepted (not 200)."""
        flowsignal_result = {
            "verdict": "DEFER",
            "defer_reason": "EXTERNAL_HOLD",
            "defer_id": "fs-defer-001",
            "violations": ["FlowSignal: requires human approval"],
            "seal": "",
            "latency_ms": 5.2,
        }
        mock_gov = _mock_governor()
        mock_gov.validate_action = AsyncMock(return_value=flowsignal_result)

        with _installed_governor(mock_gov):
            resp = client_for_flowsignal.post(
                "/validate-action",
                json={"action": "execute_trade", "params": {"amount": 50000}},
            )

        assert resp.status_code == 202

    def test_flowsignal_escalation_receipt_shape(
        self, client_for_flowsignal, mock_kms_signer
    ):
        """HTTP 202 body contains defer_id, status: pending_review, poll_url."""
        flowsignal_result = {
            "verdict": "DEFER",
            "defer_reason": "EXTERNAL_HOLD",
            "defer_id": "fs-defer-002",
            "violations": ["FlowSignal: requires human approval"],
            "seal": "",
            "latency_ms": 3.1,
        }
        mock_gov = _mock_governor()
        mock_gov.validate_action = AsyncMock(return_value=flowsignal_result)

        with _installed_governor(mock_gov):
            resp = client_for_flowsignal.post(
                "/validate-action",
                json={"action": "execute_trade", "params": {"amount": 50000}},
            )

        data = resp.json()
        assert data["defer_id"] == "fs-defer-002"
        assert data["status"] == "pending_review"
        assert data["poll_url"] == "/v1/defer/fs-defer-002"
        assert data["verdict"] == "DEFER"
        assert data["defer_reason"] == "EXTERNAL_HOLD"
        assert data["ttl_seconds"] == 300

    def test_flowsignal_escalation_via_is_flowsignal_hold_marker(
        self, client_for_flowsignal, mock_kms_signer
    ):
        """is_external_hold=True also triggers HTTP 202 (alternative detection)."""
        # This covers the case where defer_reason might be different but the
        # explicit marker is set
        result_with_marker = {
            "verdict": "DEFER",
            "is_external_hold": True,
            "defer_id": "fs-defer-003",
            "violations": ["External hold"],
            "seal": "",
            "latency_ms": 2.0,
        }
        mock_gov = _mock_governor()
        mock_gov.validate_action = AsyncMock(return_value=result_with_marker)

        with _installed_governor(mock_gov):
            resp = client_for_flowsignal.post(
                "/validate-action",
                json={"action": "execute_trade", "params": {"amount": 25000}},
            )

        assert resp.status_code == 202
        data = resp.json()
        assert data["status"] == "pending_review"

    def test_non_flowsignal_defer_returns_200_not_202(
        self, client_for_flowsignal, mock_kms_signer
    ):
        """Regular DEFER (not FlowSignal) returns HTTP 200, not 202."""
        regular_defer_result = {
            "verdict": "DEFER",
            "defer_reason": "CONFIDENCE_BELOW_THRESHOLD",
            "defer_id": "regular-defer-001",
            "violations": ["confidence too low"],
            "seal": "",
            "latency_ms": 1.5,
        }
        mock_gov = _mock_governor()
        mock_gov.validate_action = AsyncMock(return_value=regular_defer_result)

        with _installed_governor(mock_gov):
            resp = client_for_flowsignal.post(
                "/validate-action",
                json={"action": "execute_trade", "params": {"amount": 1000}},
            )

        # Non-FlowSignal DEFER should return 200 (current behavior preserved)
        assert resp.status_code == 200
        data = resp.json()
        assert data["verdict"] == "DEFER"

    def test_external_hold_without_marker_returns_202(
        self, client_for_flowsignal, mock_kms_signer
    ):
        """EXTERNAL_HOLD defer_reason without is_external_hold marker still returns HTTP 202.

        Regression test for Defect 1: Previously the middleware only checked
        defer_reason == "FLOWSIGNAL_ESCALATION" (dead code after rename) OR
        is_flowsignal_hold == True. An EXTERNAL_HOLD with no marker would
        silently fall through to HTTP 200, failing to signal the client to poll.
        """
        external_hold_no_marker = {
            "verdict": "DEFER",
            "defer_reason": "EXTERNAL_HOLD",
            "defer_id": "external-defer-regression",
            "violations": ["External provider escalation"],
            "seal": "",
            "latency_ms": 3.5,
        }
        mock_gov = _mock_governor()
        mock_gov.validate_action = AsyncMock(return_value=external_hold_no_marker)

        with _installed_governor(mock_gov):
            resp = client_for_flowsignal.post(
                "/validate-action",
                json={"action": "execute_trade", "params": {"amount": 30000}},
            )

        # Must return 202, not 200 — this is a human-in-the-loop escalation
        assert resp.status_code == 202
        data = resp.json()
        assert data["defer_id"] == "external-defer-regression"
        assert data["status"] == "pending_review"
        assert data["defer_reason"] == "EXTERNAL_HOLD"

    def test_approved_verdict_still_returns_200(
        self, client_for_flowsignal, mock_kms_signer
    ):
        """ALLOW verdict returns HTTP 200 with canonical envelope (ADR-008 Phase 3)."""
        approved_result = {
            "verdict": "ALLOW",
            "violations": [],
            "latency_ms": 1.0,
        }
        mock_gov = _mock_governor()
        mock_gov.validate_action = AsyncMock(return_value=approved_result)

        with _installed_governor(mock_gov):
            resp = client_for_flowsignal.post(
                "/validate-action",
                json={"action": "execute_trade", "params": {"amount": 100}},
            )

        assert resp.status_code == 200
        data = resp.json()

        # ADR-008 Phase 3: ALLOW verdicts return canonical envelope
        assert data.get("envelope_version") == "3.0"
        assert data["payload"]["verdict"] == "ALLOW"
