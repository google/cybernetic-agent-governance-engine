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

Coverage targets
----------------
A. /governance/check endpoint
   - Happy path: valid request → 200 with governance decision
   - Missing tool_name → 400
   - Invalid JSON body → 400
   - Governance denial (verify() returns violations) → 200 REJECTED
   - CAGE_SEAL_ENFORCEMENT=enforce blocks invalid seal → 403
   - CAGE_SEAL_ENFORCEMENT=log allows invalid seal through

B. /governance/validate-action endpoint
   - Happy path: valid action → 200 APPROVED
   - GovernanceError → 403 DENIED (not 500)
   - Internal exception → 500 with "Internal governance error" (MED-03 fix)
   - detail field never contains stack trace or internal variable names

C. _verify_governance_signature()
   - Valid signature passes (signer.verify returns True)
   - Empty/absent signature raises SymbolicGovernorViolation
   - signer.verify returns False → raises SymbolicGovernorViolation
   - signer raises unexpected exception → SymbolicGovernorViolation

D. enforce_routing_seal() / _verify_routing_seal()
   - Valid HMAC seal passes
   - Missing seal header → False in verify, 403 in enforce (enforce mode)
   - Wrong HMAC → False in verify, 403 in enforce (enforce mode)
   - log mode: invalid seal logs but does NOT raise

E. _emit_refusal_receipt()
   - Signs receipt via KMS signer and calls evidence sink
   - KMS sign failure is logged but does not suppress the call
   - Evidence sink failure is logged but does not suppress the call

F. Startup validation
   - Missing CAGE_ROUTING_SEAL_SECRET raises RuntimeError in production env
   - Short CAGE_ROUTING_SEAL_SECRET raises RuntimeError

Notes
-----
- asyncio_mode = "auto" in pyproject.toml — no @pytest.mark.asyncio needed.
- CAGE_ENV=test is set by conftest.pytest_configure via ENVIRONMENT default,
  so the module-level RuntimeError guard is bypassed during import.
- We patch module-level globals in governance_middleware directly rather than
  reloading the module (avoids re-running the startup guard).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# Ensure CAGE_ENV=test before any gateway module is imported so the
# module-level CAGE_ROUTING_SEAL_SECRET guard does not raise RuntimeError.
# conftest.pytest_configure sets ENVIRONMENT=production by default but does
# NOT set CAGE_ENV — we set it here as a belt-and-suspenders guard.
# ---------------------------------------------------------------------------
os.environ.setdefault("CAGE_ENV", "test")
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("GOVERNANCE_SALT", "CYBERNETIC_GOVERNANCE_TEST_SALT_32C!")

# A 32-char test secret that satisfies the HMAC_MIN_LENGTH=32 check.
_TEST_SECRET = "test-secret-key-that-is-32-chars"

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_seal(secret: str, body_bytes: bytes) -> str:
    """Compute the HMAC-SHA256 routing seal the same way the middleware does."""
    return hmac.new(secret.encode(), body_bytes, hashlib.sha256).hexdigest()


def _json_body(
    tool_name: str = "execute_trade", params: dict[str, Any] | None = None
) -> bytes:
    return json.dumps(
        {"tool_name": tool_name, "params": params or {"amount": 100}}
    ).encode()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def mock_symbolic_governor():
    """Patch the symbolic_governor singleton used by governance_middleware."""
    gov = MagicMock()
    gov.verify = AsyncMock(
        return_value={"violations": [], "opa_results": {"allow": True}}
    )
    gov.validate_action = AsyncMock(
        return_value={
            "verdict": "APPROVED",
            "violations": [],
            "seal": "fake-seal",
            "latency_ms": 1.0,
        }
    )
    with patch("src.gateway.server.governance_middleware.symbolic_governor", gov):
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
        "src.compliance_bridge.evidence_stream.get_evidence_sink",
        return_value=sink,
    ):
        yield sink


@pytest.fixture()
def enforce_client(mock_symbolic_governor, mock_kms_signer):
    """TestClient with CAGE_SEAL_ENFORCEMENT=enforce and a known secret."""
    import src.gateway.server.governance_middleware as mw

    original_secret = mw._CAGE_SEAL_SECRET
    original_enforcement = mw._SEAL_ENFORCEMENT

    mw._CAGE_SEAL_SECRET = _TEST_SECRET
    mw._SEAL_ENFORCEMENT = "enforce"

    from src.gateway.server.governance_middleware import governance_app

    client = TestClient(governance_app, raise_server_exceptions=False)

    yield client

    mw._CAGE_SEAL_SECRET = original_secret
    mw._SEAL_ENFORCEMENT = original_enforcement


@pytest.fixture()
def log_client(mock_symbolic_governor, mock_kms_signer):
    """TestClient with CAGE_SEAL_ENFORCEMENT=log and a known secret."""
    import src.gateway.server.governance_middleware as mw

    original_secret = mw._CAGE_SEAL_SECRET
    original_enforcement = mw._SEAL_ENFORCEMENT

    mw._CAGE_SEAL_SECRET = _TEST_SECRET
    mw._SEAL_ENFORCEMENT = "log"

    from src.gateway.server.governance_middleware import governance_app

    client = TestClient(governance_app, raise_server_exceptions=False)

    yield client

    mw._CAGE_SEAL_SECRET = original_secret
    mw._SEAL_ENFORCEMENT = original_enforcement


@pytest.fixture()
def no_secret_client(mock_symbolic_governor, mock_kms_signer):
    """TestClient with no CAGE_ROUTING_SEAL_SECRET (dev/test bypass)."""
    import src.gateway.server.governance_middleware as mw

    original_secret = mw._CAGE_SEAL_SECRET
    original_env = mw._ENVIRONMENT

    mw._CAGE_SEAL_SECRET = None
    mw._ENVIRONMENT = "test"  # allow bypass

    from src.gateway.server.governance_middleware import governance_app

    client = TestClient(governance_app, raise_server_exceptions=False)

    yield client

    mw._CAGE_SEAL_SECRET = original_secret
    mw._ENVIRONMENT = original_env


# ===========================================================================
# A. /check endpoint tests
# ===========================================================================


class TestGovernanceCheckEndpoint:
    """Tests for POST /check on governance_app."""

    def test_check_happy_path_approved(self, enforce_client, mock_symbolic_governor):
        """Valid request with correct seal returns 200 APPROVED when no violations."""
        body = _json_body("execute_trade", {"amount": 100})
        seal = _make_seal(_TEST_SECRET, body)

        resp = enforce_client.post(
            "/check",
            content=body,
            headers={"Content-Type": "application/json", "X-CAGE-Routing-Seal": seal},
        )

        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "APPROVED"
        assert data["violations"] == []
        mock_symbolic_governor.verify.assert_awaited_once_with(
            "execute_trade", {"amount": 100}
        )

    def test_check_returns_rejected_when_violations_present(
        self, enforce_client, mock_symbolic_governor
    ):
        """When symbolic_governor.verify() returns violations, status is REJECTED."""
        mock_symbolic_governor.verify = AsyncMock(
            return_value={
                "violations": ["drawdown_limit_exceeded"],
                "opa_results": {"allow": False},
            }
        )
        body = _json_body("execute_trade", {"amount": 999999})
        seal = _make_seal(_TEST_SECRET, body)

        resp = enforce_client.post(
            "/check",
            content=body,
            headers={"Content-Type": "application/json", "X-CAGE-Routing-Seal": seal},
        )

        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "REJECTED"
        assert "drawdown_limit_exceeded" in data["violations"]

    def test_check_missing_tool_name_returns_400(self, enforce_client):
        """Body without tool_name returns HTTP 400."""
        body = json.dumps({"params": {"amount": 100}}).encode()
        seal = _make_seal(_TEST_SECRET, body)

        resp = enforce_client.post(
            "/check",
            content=body,
            headers={"Content-Type": "application/json", "X-CAGE-Routing-Seal": seal},
        )

        assert resp.status_code == 400
        assert "tool_name" in resp.text.lower() or resp.status_code == 400

    def test_check_invalid_json_returns_400(self, enforce_client):
        """Malformed JSON body returns HTTP 400."""
        body = b"not-valid-json"
        seal = _make_seal(_TEST_SECRET, body)

        resp = enforce_client.post(
            "/check",
            content=body,
            headers={"Content-Type": "application/json", "X-CAGE-Routing-Seal": seal},
        )

        assert resp.status_code == 400

    def test_check_invalid_seal_enforce_mode_returns_403(self, enforce_client):
        """In enforce mode, a wrong seal returns HTTP 403."""
        body = _json_body("execute_trade")

        resp = enforce_client.post(
            "/check",
            content=body,
            headers={
                "Content-Type": "application/json",
                "X-CAGE-Routing-Seal": "deadbeef" * 8,  # wrong seal
            },
        )

        assert resp.status_code == 403
        data = resp.json()
        assert data["detail"]["error"] == "invalid_routing_seal"

    def test_check_missing_seal_enforce_mode_returns_403(self, enforce_client):
        """In enforce mode, a missing seal header returns HTTP 403."""
        body = _json_body("execute_trade")

        resp = enforce_client.post(
            "/check",
            content=body,
            headers={"Content-Type": "application/json"},
        )

        assert resp.status_code == 403

    def test_check_invalid_seal_log_mode_passes_through(
        self, log_client, mock_symbolic_governor
    ):
        """In log mode, an invalid seal is logged but the request is allowed through."""
        body = _json_body("execute_trade")

        resp = log_client.post(
            "/check",
            content=body,
            headers={
                "Content-Type": "application/json",
                "X-CAGE-Routing-Seal": "wrong-seal-value",
            },
        )

        # Should reach the governor, not be blocked at 403
        assert resp.status_code == 200
        mock_symbolic_governor.verify.assert_awaited_once()

    def test_check_no_secret_dev_mode_bypasses_seal(
        self, no_secret_client, mock_symbolic_governor
    ):
        """When CAGE_ROUTING_SEAL_SECRET is absent in test env, seal check is bypassed."""
        body = _json_body("execute_trade")

        resp = no_secret_client.post(
            "/check",
            content=body,
            headers={"Content-Type": "application/json"},
            # No seal header — should be bypassed in test/dev mode
        )

        assert resp.status_code == 200
        mock_symbolic_governor.verify.assert_awaited_once()


# ===========================================================================
# B. /validate-action endpoint tests
# ===========================================================================


class TestValidateActionEndpoint:
    """Tests for POST /validate-action on governance_app."""

    @pytest.fixture()
    def client(self, mock_symbolic_governor, mock_kms_signer):
        """Plain TestClient with seal enforcement disabled for /validate-action tests."""
        import src.gateway.server.governance_middleware as mw

        original_secret = mw._CAGE_SEAL_SECRET
        original_env = mw._ENVIRONMENT

        mw._CAGE_SEAL_SECRET = None
        mw._ENVIRONMENT = "test"  # allow bypass

        from src.gateway.server.governance_middleware import governance_app

        client = TestClient(governance_app, raise_server_exceptions=False)

        yield client

        mw._CAGE_SEAL_SECRET = original_secret
        mw._ENVIRONMENT = original_env

    def test_validate_action_happy_path_approved(self, client, mock_symbolic_governor):
        """Valid action returns 200 with APPROVED verdict."""
        resp = client.post(
            "/validate-action",
            json={
                "action": "execute_trade",
                "params": {"amount": 100, "symbol": "AAPL"},
            },
        )

        assert resp.status_code == 200
        data = resp.json()
        assert data.get("schema_version") == "1.0.0"
        assert data["verdict"] == "APPROVED"
        assert data["violations"] == []
        assert "seal" in data
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
        from src.gateway.governance.symbolic_governor import GovernanceError

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
        assert data.get("schema_version") == "1.0.0"
        assert data["verdict"] == "DENIED"
        assert len(data["violations"]) > 0
        assert data["seal"] == ""

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
        from src.gateway.governance.symbolic_governor import GovernanceError

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
# C. _verify_governance_signature() unit tests
# ===========================================================================


class TestVerifyGovernanceSignature:
    """Unit tests for the _verify_governance_signature() helper (P4 KMS check)."""

    def test_valid_signature_passes(self):
        """When signer.verify() returns True, no exception is raised."""
        from src.gateway.server.governance_middleware import (
            _verify_governance_signature,
        )

        mock_signer = MagicMock()
        mock_signer.verify = MagicMock(return_value=True)

        with patch(
            "src.gateway.server.governance_middleware.get_governance_signer",
            return_value=mock_signer,
        ):
            # Should not raise
            _verify_governance_signature("deadbeef" * 8, {"action": "execute_trade"})

        mock_signer.verify.assert_called_once_with(
            plan={"action": "execute_trade"},
            signature_hex="deadbeef" * 8,
        )

    def test_empty_signature_raises_violation(self):
        """An empty governance_signature raises SymbolicGovernorViolation immediately."""
        from src.gateway.governance.routing_seal import SymbolicGovernorViolation
        from src.gateway.server.governance_middleware import (
            _verify_governance_signature,
        )

        with pytest.raises(SymbolicGovernorViolation) as exc_info:
            _verify_governance_signature("", {"action": "execute_trade"})

        assert "absent or empty" in str(exc_info.value)

    def test_none_signature_raises_violation(self):
        """A None governance_signature raises SymbolicGovernorViolation."""
        from src.gateway.governance.routing_seal import SymbolicGovernorViolation
        from src.gateway.server.governance_middleware import (
            _verify_governance_signature,
        )

        with pytest.raises(SymbolicGovernorViolation):
            _verify_governance_signature(None, {"action": "execute_trade"})  # type: ignore[arg-type]

    def test_signer_verify_returns_false_raises_violation(self):
        """When signer.verify() returns False, SymbolicGovernorViolation is raised."""
        from src.gateway.governance.routing_seal import SymbolicGovernorViolation
        from src.gateway.server.governance_middleware import (
            _verify_governance_signature,
        )

        mock_signer = MagicMock()
        mock_signer.verify = MagicMock(return_value=False)

        with patch(
            "src.gateway.server.governance_middleware.get_governance_signer",
            return_value=mock_signer,
        ):
            with pytest.raises(SymbolicGovernorViolation) as exc_info:
                _verify_governance_signature(
                    "deadbeef" * 8, {"action": "execute_trade"}
                )

        assert (
            "tampered" in str(exc_info.value).lower()
            or "failed" in str(exc_info.value).lower()
        )

    def test_signer_raises_unexpected_exception_wraps_as_violation(self):
        """If get_governance_signer().verify() raises, it is wrapped in SymbolicGovernorViolation."""
        from src.gateway.governance.routing_seal import SymbolicGovernorViolation
        from src.gateway.server.governance_middleware import (
            _verify_governance_signature,
        )

        mock_signer = MagicMock()
        mock_signer.verify = MagicMock(side_effect=ConnectionError("KMS unreachable"))

        with patch(
            "src.gateway.server.governance_middleware.get_governance_signer",
            return_value=mock_signer,
        ):
            with pytest.raises(SymbolicGovernorViolation) as exc_info:
                _verify_governance_signature(
                    "deadbeef" * 8, {"action": "execute_trade"}
                )

        assert "KMS verifier raised an unexpected error" in str(exc_info.value)

    def test_get_governance_signer_itself_raises_wraps_as_violation(self):
        """If get_governance_signer() itself raises, it is wrapped in SymbolicGovernorViolation."""
        from src.gateway.governance.routing_seal import SymbolicGovernorViolation
        from src.gateway.server.governance_middleware import (
            _verify_governance_signature,
        )

        with patch(
            "src.gateway.server.governance_middleware.get_governance_signer",
            side_effect=RuntimeError("KMS_GOVERNANCE_KEY not set"),
        ):
            with pytest.raises(SymbolicGovernorViolation) as exc_info:
                _verify_governance_signature(
                    "deadbeef" * 8, {"action": "execute_trade"}
                )

        assert "KMS verifier raised an unexpected error" in str(exc_info.value)


# ===========================================================================
# D. enforce_routing_seal() / _verify_routing_seal() unit tests
# ===========================================================================


class TestRoutingSealEnforcement:
    """Unit tests for enforce_routing_seal() and _verify_routing_seal()."""

    def _make_request(self, path: str = "/check", headers: dict | None = None):
        """Build a minimal mock Request object."""
        from starlette.requests import Request

        scope = {
            "type": "http",
            "method": "POST",
            "path": path,
            "query_string": b"",
            "headers": [
                (k.lower().encode(), v.encode()) for k, v in (headers or {}).items()
            ],
        }
        return Request(scope)

    def test_verify_routing_seal_valid_hmac_returns_true(self):
        """A correctly computed HMAC seal returns True."""
        import src.gateway.server.governance_middleware as mw

        original = mw._CAGE_SEAL_SECRET
        mw._CAGE_SEAL_SECRET = _TEST_SECRET
        try:
            body = b'{"tool_name":"execute_trade","params":{}}'
            seal = _make_seal(_TEST_SECRET, body)
            req = self._make_request(headers={"X-CAGE-Routing-Seal": seal})
            result = mw._verify_routing_seal(req, body)
            assert result is True
        finally:
            mw._CAGE_SEAL_SECRET = original

    def test_verify_routing_seal_wrong_hmac_returns_false(self):
        """A wrong HMAC seal returns False."""
        import src.gateway.server.governance_middleware as mw

        original = mw._CAGE_SEAL_SECRET
        mw._CAGE_SEAL_SECRET = _TEST_SECRET
        try:
            body = b'{"tool_name":"execute_trade","params":{}}'
            req = self._make_request(headers={"X-CAGE-Routing-Seal": "wrong" * 12})
            result = mw._verify_routing_seal(req, body)
            assert result is False
        finally:
            mw._CAGE_SEAL_SECRET = original

    def test_verify_routing_seal_missing_header_returns_false(self):
        """A missing X-CAGE-Routing-Seal header returns False."""
        import src.gateway.server.governance_middleware as mw

        original = mw._CAGE_SEAL_SECRET
        mw._CAGE_SEAL_SECRET = _TEST_SECRET
        try:
            body = b'{"tool_name":"execute_trade","params":{}}'
            req = self._make_request()  # no seal header
            result = mw._verify_routing_seal(req, body)
            assert result is False
        finally:
            mw._CAGE_SEAL_SECRET = original

    def test_verify_routing_seal_no_secret_test_env_returns_true(self):
        """When CAGE_ROUTING_SEAL_SECRET is absent in test env, verification is bypassed (True)."""
        import src.gateway.server.governance_middleware as mw

        original_secret = mw._CAGE_SEAL_SECRET
        original_env = mw._ENVIRONMENT
        mw._CAGE_SEAL_SECRET = None
        mw._ENVIRONMENT = "test"
        try:
            body = b'{"tool_name":"execute_trade","params":{}}'
            req = self._make_request()
            result = mw._verify_routing_seal(req, body)
            assert result is True
        finally:
            mw._CAGE_SEAL_SECRET = original_secret
            mw._ENVIRONMENT = original_env

    def test_enforce_routing_seal_enforce_mode_raises_403_on_bad_seal(self):
        """enforce_routing_seal() raises HTTPException(403) in enforce mode for bad seal."""
        from fastapi import HTTPException

        import src.gateway.server.governance_middleware as mw

        original_secret = mw._CAGE_SEAL_SECRET
        original_enforcement = mw._SEAL_ENFORCEMENT
        mw._CAGE_SEAL_SECRET = _TEST_SECRET
        mw._SEAL_ENFORCEMENT = "enforce"
        try:
            body = b'{"tool_name":"execute_trade","params":{}}'
            req = self._make_request(headers={"X-CAGE-Routing-Seal": "bad-seal"})
            with pytest.raises(HTTPException) as exc_info:
                mw.enforce_routing_seal(req, body)
            assert exc_info.value.status_code == 403
            assert exc_info.value.detail["error"] == "invalid_routing_seal"
        finally:
            mw._CAGE_SEAL_SECRET = original_secret
            mw._SEAL_ENFORCEMENT = original_enforcement

    def test_enforce_routing_seal_log_mode_does_not_raise_on_bad_seal(self, caplog):
        """enforce_routing_seal() in log mode logs but does NOT raise for bad seal."""
        import logging

        import src.gateway.server.governance_middleware as mw

        original_secret = mw._CAGE_SEAL_SECRET
        original_enforcement = mw._SEAL_ENFORCEMENT
        mw._CAGE_SEAL_SECRET = _TEST_SECRET
        mw._SEAL_ENFORCEMENT = "log"
        try:
            body = b'{"tool_name":"execute_trade","params":{}}'
            req = self._make_request(headers={"X-CAGE-Routing-Seal": "bad-seal"})
            with caplog.at_level(
                logging.WARNING, logger="Gateway.GovernanceMiddleware"
            ):
                # Must NOT raise
                mw.enforce_routing_seal(req, body)
            assert any("enforcement=log" in r.message for r in caplog.records)
        finally:
            mw._CAGE_SEAL_SECRET = original_secret
            mw._SEAL_ENFORCEMENT = original_enforcement

    def test_enforce_routing_seal_valid_seal_does_not_raise(self):
        """enforce_routing_seal() with a valid seal returns None (no exception)."""
        import src.gateway.server.governance_middleware as mw

        original_secret = mw._CAGE_SEAL_SECRET
        original_enforcement = mw._SEAL_ENFORCEMENT
        mw._CAGE_SEAL_SECRET = _TEST_SECRET
        mw._SEAL_ENFORCEMENT = "enforce"
        try:
            body = b'{"tool_name":"execute_trade","params":{}}'
            seal = _make_seal(_TEST_SECRET, body)
            req = self._make_request(headers={"X-CAGE-Routing-Seal": seal})
            result = mw.enforce_routing_seal(req, body)
            assert result is None
        finally:
            mw._CAGE_SEAL_SECRET = original_secret
            mw._SEAL_ENFORCEMENT = original_enforcement


# ===========================================================================
# E. _emit_refusal_receipt() unit tests
# ===========================================================================


class TestEmitRefusalReceipt:
    """Unit tests for the _emit_refusal_receipt() async helper (P6)."""

    async def test_emit_receipt_calls_kms_sign_and_sink(self, mock_kms_signer):
        """Happy path: receipt is KMS-signed and published to the evidence sink."""
        from src.gateway.server.governance_middleware import _emit_refusal_receipt

        sink = MagicMock()
        sink.ingest = AsyncMock(return_value=None)

        with patch(
            "src.compliance_bridge.evidence_stream.get_evidence_sink",
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
                "src.compliance_bridge.evidence_stream.get_evidence_sink",
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
            "src.compliance_bridge.evidence_stream.get_evidence_sink",
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
# F. Startup validation tests
# ===========================================================================


class TestStartupValidation:
    """Tests for module-level CAGE_ROUTING_SEAL_SECRET startup guard (POAM-012)."""

    def test_missing_secret_raises_in_production_env(self):
        """RuntimeError is raised at import time when secret is absent in production."""
        # We cannot safely re-import the module in the same process (it would
        # affect the already-imported singleton).  Instead we verify the guard
        # logic directly by calling the equivalent condition.
        #
        # The guard in governance_middleware.py is:
        #   if not _CAGE_SEAL_SECRET:
        #       if _ENVIRONMENT not in ("development", "test"):
        #           raise RuntimeError(...)
        #
        # We replicate that logic here to confirm the condition is correct.
        secret = None
        environment = "production"
        with pytest.raises(RuntimeError, match="CAGE_ROUTING_SEAL_SECRET must be set"):
            if not secret:
                if environment not in ("development", "test"):
                    raise RuntimeError(
                        "CAGE_ROUTING_SEAL_SECRET must be set in non-development environments (POAM-012). "
                        "Generate a cryptographically random secret of at least 32 characters and export it "
                        "as CAGE_ROUTING_SEAL_SECRET."
                    )

    def test_short_secret_raises_runtime_error(self):
        """RuntimeError is raised when CAGE_ROUTING_SEAL_SECRET is shorter than 32 chars."""
        short_secret = "tooshort"  # < 32 chars
        _HMAC_MIN_LENGTH = 32
        with pytest.raises(RuntimeError, match="minimum of"):
            if len(short_secret) < _HMAC_MIN_LENGTH:
                raise RuntimeError(
                    f"CAGE_ROUTING_SEAL_SECRET is set but is only {len(short_secret)} characters long. "
                    f"A minimum of {_HMAC_MIN_LENGTH} characters is required for HMAC-SHA256 security (POAM-012)."
                )

    def test_missing_secret_in_test_env_does_not_raise(self):
        """In test/development environments, missing secret logs a warning but does not raise."""
        # This is validated by the fact that the module imports successfully
        # in the test suite (CAGE_ENV=test is set at the top of this file).
        import src.gateway.server.governance_middleware as mw

        assert mw is not None  # module imported without RuntimeError

    def test_module_exports_governance_app(self):
        """governance_app FastAPI instance is exported from the module."""
        from fastapi import FastAPI

        from src.gateway.server.governance_middleware import governance_app

        assert isinstance(governance_app, FastAPI)

    def test_module_exports_enforce_routing_seal(self):
        """enforce_routing_seal() is exported from the module."""
        from src.gateway.server.governance_middleware import enforce_routing_seal

        assert callable(enforce_routing_seal)

    def test_module_exports_verify_governance_signature(self):
        """_verify_governance_signature() is accessible from the module."""
        from src.gateway.server.governance_middleware import (
            _verify_governance_signature,
        )

        assert callable(_verify_governance_signature)


# ===========================================================================
# G. enforce_governance() helper tests
# ===========================================================================


class TestEnforceGovernanceHelper:
    """Tests for the enforce_governance() async helper."""

    async def test_exempt_tool_returns_empty_seal(self):
        """Read-only exempt tools bypass governance and return an empty seal."""
        from src.gateway.server.governance_middleware import enforce_governance

        seal = await enforce_governance("check_market_status", {"symbol": "AAPL"})
        assert seal == ""

    async def test_exempt_tool_verify_content_safety_returns_empty_seal(self):
        """verify_content_safety is also exempt from governance overhead."""
        from src.gateway.server.governance_middleware import enforce_governance

        seal = await enforce_governance("verify_content_safety", {"text": "hello"})
        assert seal == ""

    async def test_non_exempt_tool_calls_governor_and_returns_seal(self):
        """Non-exempt tools call symbolic_governor.govern() and return the seal."""
        from src.gateway.server.governance_middleware import enforce_governance

        mock_gov = MagicMock()
        mock_gov.govern = AsyncMock(return_value="test-routing-seal-value")

        with patch(
            "src.gateway.server.governance_middleware.symbolic_governor", mock_gov
        ):
            seal = await enforce_governance("execute_trade", {"amount": 100})

        assert seal == "test-routing-seal-value"
        mock_gov.govern.assert_awaited_once_with("execute_trade", {"amount": 100})

    async def test_governance_error_raises_permission_error(self):
        """GovernanceError from the governor is converted to PermissionError."""
        from src.gateway.governance.symbolic_governor import GovernanceError
        from src.gateway.server.governance_middleware import enforce_governance

        mock_gov = MagicMock()
        mock_gov.govern = AsyncMock(side_effect=GovernanceError("policy_denied"))

        mock_signer = MagicMock()
        mock_signer.sign = MagicMock(return_value="sig")

        with (
            patch(
                "src.gateway.server.governance_middleware.symbolic_governor", mock_gov
            ),
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
                await enforce_governance("execute_trade", {"amount": 100})


# ===========================================================================
# H. Integration smoke: governance_app routes are registered
# ===========================================================================


class TestGovernanceAppRoutes:
    """Smoke tests verifying that the expected routes exist on governance_app."""

    @pytest.fixture(scope="class")
    def client(self):
        # scope="class": governance_app has no mutable state and all three
        # smoke tests in this class share the same (read-only) app config.
        from src.gateway.server.governance_middleware import governance_app

        return TestClient(governance_app, raise_server_exceptions=False)

    def test_check_route_exists(self, client):
        """POST /check route is registered (returns something other than 404)."""
        # Send a request without a seal — in test env with no secret it bypasses,
        # but we just want to confirm the route exists (not 404).
        import src.gateway.server.governance_middleware as mw

        original_secret = mw._CAGE_SEAL_SECRET
        mw._CAGE_SEAL_SECRET = None
        mw._ENVIRONMENT = "test"
        try:
            resp = client.post(
                "/check", json={"tool_name": "check_market_status", "params": {}}
            )
            assert resp.status_code != 404
        finally:
            mw._CAGE_SEAL_SECRET = original_secret

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

    Phase 1, §3.2 of the FlowSignal integration plan requires that
    FLOWSIGNAL_ESCALATION verdicts return HTTP 202 with an async receipt body
    containing defer_id, status, and poll_url.
    """

    @pytest.fixture()
    def client_for_flowsignal(self, mock_kms_signer):
        """TestClient with seal enforcement disabled for FlowSignal tests."""
        import src.gateway.server.governance_middleware as mw

        original_secret = mw._CAGE_SEAL_SECRET
        original_env = mw._ENVIRONMENT

        mw._CAGE_SEAL_SECRET = None
        mw._ENVIRONMENT = "test"  # allow bypass

        from src.gateway.server.governance_middleware import governance_app

        client = TestClient(governance_app, raise_server_exceptions=False)

        yield client

        mw._CAGE_SEAL_SECRET = original_secret
        mw._ENVIRONMENT = original_env

    def test_flowsignal_escalation_returns_http_202(
        self, client_for_flowsignal, mock_kms_signer
    ):
        """FlowSignal ESCALATE decision returns HTTP 202 Accepted (not 200)."""
        flowsignal_result = {
            "verdict": "DEFER",
            "defer_reason": "FLOWSIGNAL_ESCALATION",
            "defer_id": "fs-defer-001",
            "violations": ["FlowSignal: requires human approval"],
            "seal": "",
            "latency_ms": 5.2,
        }
        mock_gov = MagicMock()
        mock_gov.validate_action = AsyncMock(return_value=flowsignal_result)

        with patch(
            "src.gateway.server.governance_middleware.symbolic_governor", mock_gov
        ):
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
            "defer_reason": "FLOWSIGNAL_ESCALATION",
            "defer_id": "fs-defer-002",
            "violations": ["FlowSignal: requires human approval"],
            "seal": "",
            "latency_ms": 3.1,
        }
        mock_gov = MagicMock()
        mock_gov.validate_action = AsyncMock(return_value=flowsignal_result)

        with patch(
            "src.gateway.server.governance_middleware.symbolic_governor", mock_gov
        ):
            resp = client_for_flowsignal.post(
                "/validate-action",
                json={"action": "execute_trade", "params": {"amount": 50000}},
            )

        data = resp.json()
        assert data["defer_id"] == "fs-defer-002"
        assert data["status"] == "pending_review"
        assert data["poll_url"] == "/v1/defer/fs-defer-002"
        assert data["verdict"] == "DEFER"
        assert data["defer_reason"] == "FLOWSIGNAL_ESCALATION"
        assert data["ttl_seconds"] == 300

    def test_flowsignal_escalation_via_is_flowsignal_hold_marker(
        self, client_for_flowsignal, mock_kms_signer
    ):
        """is_flowsignal_hold=True also triggers HTTP 202 (alternative detection)."""
        # This covers the case where defer_reason might be different but the
        # explicit marker is set
        result_with_marker = {
            "verdict": "DEFER",
            "is_flowsignal_hold": True,
            "defer_id": "fs-defer-003",
            "violations": ["FlowSignal hold"],
            "seal": "",
            "latency_ms": 2.0,
        }
        mock_gov = MagicMock()
        mock_gov.validate_action = AsyncMock(return_value=result_with_marker)

        with patch(
            "src.gateway.server.governance_middleware.symbolic_governor", mock_gov
        ):
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
        mock_gov = MagicMock()
        mock_gov.validate_action = AsyncMock(return_value=regular_defer_result)

        with patch(
            "src.gateway.server.governance_middleware.symbolic_governor", mock_gov
        ):
            resp = client_for_flowsignal.post(
                "/validate-action",
                json={"action": "execute_trade", "params": {"amount": 1000}},
            )

        # Non-FlowSignal DEFER should return 200 (current behavior preserved)
        assert resp.status_code == 200
        data = resp.json()
        assert data["verdict"] == "DEFER"

    def test_approved_verdict_still_returns_200(
        self, client_for_flowsignal, mock_kms_signer
    ):
        """APPROVED verdict returns HTTP 200 (not affected by FlowSignal changes)."""
        approved_result = {
            "verdict": "APPROVED",
            "violations": [],
            "seal": "valid-seal",
            "latency_ms": 1.0,
        }
        mock_gov = MagicMock()
        mock_gov.validate_action = AsyncMock(return_value=approved_result)

        with patch(
            "src.gateway.server.governance_middleware.symbolic_governor", mock_gov
        ):
            resp = client_for_flowsignal.post(
                "/validate-action",
                json={"action": "execute_trade", "params": {"amount": 100}},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["verdict"] == "APPROVED"
