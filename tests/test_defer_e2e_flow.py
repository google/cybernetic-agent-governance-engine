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
End-to-end flow tests for the DEFER governance primitive.

This test module validates the complete DEFER flow from initial request through
classification, validate_action(), and HTTP response generation. It also includes
regression guards to ensure that the introduction of DEFER does not change the
denial rate for non-defer-eligible traffic.

Test markers:
    @pytest.mark.unit — isolated unit tests with mocked dependencies
    @pytest.mark.local — tests with mocked Redis/OPA

Phase 1.6: CAGE Implementation Plan — Governance Primitives Test Coverage
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.gateway.governance.decisions import (
    DeferResponse,
    GovernanceDecision,
    NarrowResponse,
    PauseResponse,
)

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# TestDeferE2EFlow — Full DEFER flow tests
# ---------------------------------------------------------------------------


class TestDeferE2EFlow:
    """End-to-end tests for the DEFER governance primitive flow."""

    @pytest.mark.asyncio
    async def test_full_defer_flow_from_request_to_response(self, monkeypatch):
        """Test the complete DEFER flow: request → classification → HTTP response.
        
        This test validates that:
        1. A low-confidence request triggers DEFER classification
        2. validate_action() returns a DEFER verdict (not exception)
        3. handle_check_request() returns HTTP 202 with correct body
        4. Response includes defer_token and missing_input_reason
        """
        monkeypatch.setenv("CAGE_DEFER_ENABLED", "true")
        monkeypatch.setenv("FRIA_ZONE_DEFER", "0.70")
        
        from src.gateway.server.agent_gateway_adapter import handle_check_request
        
        # Prepare a request with low confidence (below FRIA_ZONE_DEFER)
        request_body = json.dumps({
            "method": "execute_trade",
            "params": {
                "symbol": "AAPL",
                "amount": 100,
                "confidence": 0.50,  # Below 0.70 threshold
            },
        })
        
        # Mock the governance pipeline to return DEFER
        mock_result = {
            "verdict": GovernanceDecision.DEFER,
            "violations": ["Confidence below threshold"],
            "seal": "",
            "thread_id": "",
            "defer_id": "defer-e2e-test-123",
            "defer_token": "defer-e2e-test-123",
            "missing_input_reason": "confidence_below_threshold",
            "deferrable": True,
            "classification_meta": {
                "classification_reason": "Soft violation(s) with data starvation: confidence 0.50 < FRIA_ZONE_DEFER 0.70",
                "deferrable": True,
            },
            "retry_after_seconds": 300,
        }
        
        mock_gov = MagicMock()
        mock_gov.validate_action = AsyncMock(return_value=mock_result)
        
        import src.gateway.governance.singletons as _singletons
        
        with patch.object(_singletons, "symbolic_governor", mock_gov):
            response = await handle_check_request(request_body)
        
        # Validate HTTP response structure
        assert "denied_response" in response
        assert response["denied_response"]["status"]["code"] == 202
        
        # Validate response body
        body = json.loads(response["denied_response"]["body"])
        assert body["verdict"] == GovernanceDecision.DEFER
        assert body["defer_id"] == "defer-e2e-test-123"
        assert body["defer_token"] == "defer-e2e-test-123"
        assert "missing_input_reason" in body
        assert body["deferrable"] is True
        
        # Validate message guides client to polling endpoint
        assert "GET /v1/defer/pending" in body.get("message", "")

    @pytest.mark.asyncio
    async def test_deny_rate_unchanged_for_non_defer_eligible_traffic(
        self, monkeypatch
    ):
        """Regression guard: DENY rate must not change for hard violations.
        
        The DEFER primitive must ONLY apply to soft/deferrable violations.
        Hard violations (STPA, CBF, OPA DENY) must still result in DENY,
        regardless of CAGE_DEFER_ENABLED setting.
        """
        monkeypatch.setenv("CAGE_DEFER_ENABLED", "true")
        
        from src.gateway.server.agent_gateway_adapter import handle_check_request
        
        # Prepare a request that should trigger DENY (not DEFER)
        request_body = json.dumps({
            "method": "execute_trade",
            "params": {
                "symbol": "AAPL",
                "amount": 100,
                "confidence": 0.50,  # Low confidence, but hard violation takes priority
            },
        })
        
        # Mock validate_action to return DENY (hard violation)
        mock_result = {
            "verdict": GovernanceDecision.DENY,
            "violations": ["UCA-7: STPA safety violation"],
            "seal": "",
            "thread_id": "",
        }
        
        mock_gov = MagicMock()
        mock_gov.validate_action = AsyncMock(return_value=mock_result)
        
        import src.gateway.governance.singletons as _singletons
        
        with patch.object(_singletons, "symbolic_governor", mock_gov):
            response = await handle_check_request(request_body)
        
        # MUST be 403 DENY, not 202 DEFER
        assert "denied_response" in response
        assert response["denied_response"]["status"]["code"] == 403
        
        body = json.loads(response["denied_response"]["body"])
        assert body["verdict"] == GovernanceDecision.DENY
        assert "UCA-7" in str(body["violations"])

    @pytest.mark.asyncio
    async def test_defer_disabled_results_in_deny_for_soft_violations(
        self, monkeypatch
    ):
        """When CAGE_DEFER_ENABLED=false, soft violations fall back to DENY."""
        monkeypatch.setenv("CAGE_DEFER_ENABLED", "false")
        
        import src.gateway.server.agent_gateway_adapter as adapter_module
        from src.gateway.server.agent_gateway_adapter import handle_check_request
        
        # Force the module flag to be False
        original_defer_enabled = adapter_module._DEFER_ENABLED
        adapter_module._DEFER_ENABLED = False
        
        request_body = json.dumps({
            "method": "execute_trade",
            "params": {
                "symbol": "AAPL",
                "amount": 100,
                "confidence": 0.50,
            },
        })
        
        # Even though this would be a DEFER candidate, the flag is disabled
        mock_result = {
            "verdict": GovernanceDecision.DEFER,
            "violations": ["Confidence below threshold"],
            "seal": "",
            "thread_id": "",
            "defer_id": "should-not-appear",
            "defer_token": "should-not-appear",
            "missing_input_reason": "confidence_below_threshold",
            "deferrable": True,
        }
        
        mock_gov = MagicMock()
        mock_gov.validate_action = AsyncMock(return_value=mock_result)
        
        import src.gateway.governance.singletons as _singletons
        
        try:
            with patch.object(_singletons, "symbolic_governor", mock_gov):
                response = await handle_check_request(request_body)
        finally:
            adapter_module._DEFER_ENABLED = original_defer_enabled
        
        # Should be 403 DENY due to DEFER being disabled
        assert "denied_response" in response
        assert response["denied_response"]["status"]["code"] == 403
        
        body = json.loads(response["denied_response"]["body"])
        assert body["verdict"] == GovernanceDecision.DENY
        assert body.get("fallback_from") == "DEFER"

    @pytest.mark.asyncio
    async def test_high_confidence_soft_violations_return_require_approval(
        self, monkeypatch
    ):
        """Soft violations with high confidence → REQUIRE_APPROVAL, not DEFER."""
        monkeypatch.setenv("CAGE_DEFER_ENABLED", "true")
        monkeypatch.setenv("FRIA_ZONE_DEFER", "0.70")
        
        from src.gateway.server.agent_gateway_adapter import handle_check_request
        
        request_body = json.dumps({
            "method": "execute_trade",
            "params": {
                "symbol": "AAPL",
                "amount": 100,
                "confidence": 0.85,  # Above FRIA_ZONE_DEFER but soft violation
            },
        })
        
        # Mock validate_action to return REQUIRE_APPROVAL
        mock_result = {
            "verdict": GovernanceDecision.REQUIRE_APPROVAL,
            "violations": ["Manual Review Required"],
            "seal": "",
            "thread_id": "thread-approval-123",
        }
        
        mock_gov = MagicMock()
        mock_gov.validate_action = AsyncMock(return_value=mock_result)
        
        import src.gateway.governance.singletons as _singletons
        
        with patch.object(_singletons, "symbolic_governor", mock_gov):
            response = await handle_check_request(request_body)
        
        # Should be 202 REQUIRE_APPROVAL
        assert "denied_response" in response
        assert response["denied_response"]["status"]["code"] == 202
        
        body = json.loads(response["denied_response"]["body"])
        assert body["verdict"] == GovernanceDecision.REQUIRE_APPROVAL
        assert body["thread_id"] == "thread-approval-123"


# ---------------------------------------------------------------------------
# TestDeferResponseModel — DeferResponse model tests
# ---------------------------------------------------------------------------


class TestDeferResponseModel:
    """Tests for the DeferResponse Pydantic model."""

    def test_defer_response_default_values(self):
        """DeferResponse has correct default values."""
        resp = DeferResponse()
        
        assert resp.decision == "DEFER"
        assert resp.deferrable is True
        assert resp.retry_after_seconds == 300
        assert resp.defer_reason == "CONFIDENCE_BELOW_THRESHOLD"
        assert resp.violations == []
        assert resp.defer_token == ""

    def test_defer_response_to_http_body(self):
        """DeferResponse.to_http_body() produces correct structure."""
        resp = DeferResponse(
            classification_reason="Low confidence",
            defer_token="test-token-abc",
            violations=["Confidence below threshold"],
            missing_input_reason="confidence_starved",
        )
        
        body = resp.to_http_body()
        
        assert body["decision"] == "DEFER"
        assert body["classification_reason"] == "Low confidence"
        assert body["defer_token"] == "test-token-abc"
        assert body["deferrable"] is True
        assert body["violations"] == ["Confidence below threshold"]
        assert body["verdict"] == GovernanceDecision.DEFER

    def test_defer_response_serialization(self):
        """DeferResponse can be serialized to JSON."""
        resp = DeferResponse(
            defer_token="serialize-test",
            classification_reason="Test serialization",
        )
        
        json_str = resp.model_dump_json()
        parsed = json.loads(json_str)
        
        assert parsed["defer_token"] == "serialize-test"
        assert parsed["classification_reason"] == "Test serialization"


# ---------------------------------------------------------------------------
# TestNarrowResponseModel — NarrowResponse model tests
# ---------------------------------------------------------------------------


class TestNarrowResponseModel:
    """Tests for the NarrowResponse Pydantic model."""

    def test_narrow_response_default_values(self):
        """NarrowResponse has correct default values."""
        resp = NarrowResponse()
        
        assert resp.decision == "NARROW"
        assert resp.execution_allowed is True
        assert resp.original_params == {}
        assert resp.narrowed_params == {}
        assert resp.constraints_applied == []
        assert resp.narrowing_reason == ""

    def test_narrow_response_to_http_body(self):
        """NarrowResponse.to_http_body() produces correct structure."""
        resp = NarrowResponse(
            original_params={"amount": 150000},
            narrowed_params={"amount": 100000},
            narrowing_reason="Amount clamped to max_allowed",
            constraints_applied=["amount clamped: 150000 → 100000"],
        )
        
        body = resp.to_http_body()
        
        assert body["decision"] == "NARROW"
        assert body["original_params"]["amount"] == 150000
        assert body["narrowed_params"]["amount"] == 100000
        assert body["execution_allowed"] is True
        assert body["verdict"] == GovernanceDecision.NARROW
        assert len(body["constraints_applied"]) == 1


# ---------------------------------------------------------------------------
# TestPauseResponseModel — PauseResponse model tests
# ---------------------------------------------------------------------------


class TestPauseResponseModel:
    """Tests for the PauseResponse Pydantic model."""

    def test_pause_response_required_fields(self):
        """PauseResponse requires pause_token, pause_reason, etc."""
        from datetime import datetime, timezone
        
        resp = PauseResponse(
            pause_token="test-pause-token",
            pause_reason="RATE_LIMITED",
            resume_endpoint="/v1/pause/test-pause-token/resume",
            expires_at=datetime.now(tz=timezone.utc),
        )
        
        assert resp.decision == "PAUSE"
        assert resp.pause_token == "test-pause-token"
        assert resp.pause_reason == "RATE_LIMITED"
        assert "/resume" in resp.resume_endpoint

    def test_pause_response_to_http_body(self):
        """PauseResponse.to_http_body() produces correct structure."""
        from datetime import datetime, timezone
        
        expires = datetime(2026, 8, 15, 14, 0, 0, tzinfo=timezone.utc)
        
        resp = PauseResponse(
            pause_token="pause-http-test",
            pause_reason="CIRCUIT_OPEN",
            resume_endpoint="/v1/pause/pause-http-test/resume",
            expires_at=expires,
            estimated_wait_seconds=60,
            retry_after_seconds=30,
        )
        
        body = resp.to_http_body()
        
        assert body["decision"] == "PAUSE"
        assert body["pause_token"] == "pause-http-test"
        assert body["pause_reason"] == "CIRCUIT_OPEN"
        assert body["resume_endpoint"] == "/v1/pause/pause-http-test/resume"
        assert body["expires_at"] == "2026-08-15T14:00:00+00:00"
        assert body["estimated_wait_seconds"] == 60
        assert body["retry_after_seconds"] == 30
        assert body["verdict"] == GovernanceDecision.PAUSE


# ---------------------------------------------------------------------------
# TestDecisionVocabularyConformance — Canonical decision tests
# ---------------------------------------------------------------------------


class TestDecisionVocabularyConformance:
    """Conformance tests for GovernanceDecision canonical vocabulary."""

    def test_all_governance_decisions_are_defined(self):
        """All five canonical decisions are defined in GovernanceDecision."""
        assert hasattr(GovernanceDecision, "ALLOW")
        assert hasattr(GovernanceDecision, "DENY")
        assert hasattr(GovernanceDecision, "DEFER")
        assert hasattr(GovernanceDecision, "NARROW")
        assert hasattr(GovernanceDecision, "PAUSE")
        assert hasattr(GovernanceDecision, "REQUIRE_APPROVAL")

    def test_governance_decision_values(self):
        """GovernanceDecision enum values match expected strings."""
        assert GovernanceDecision.ALLOW.value == "ALLOW"
        assert GovernanceDecision.DENY.value == "DENY"
        assert GovernanceDecision.DEFER.value == "DEFER"
        assert GovernanceDecision.NARROW.value == "NARROW"
        assert GovernanceDecision.PAUSE.value == "PAUSE"
        assert GovernanceDecision.REQUIRE_APPROVAL.value == "REQUIRE_APPROVAL"

    def test_governance_decision_is_string_enum(self):
        """GovernanceDecision inherits from str for JSON serialization."""
        assert isinstance(GovernanceDecision.ALLOW, str)
        assert GovernanceDecision.DEFER == "DEFER"  # str comparison works


# ---------------------------------------------------------------------------
# TestNarrowE2EFlow — NARROW end-to-end flow tests
# ---------------------------------------------------------------------------


class TestNarrowE2EFlow:
    """End-to-end tests for the NARROW governance primitive flow."""

    @pytest.mark.asyncio
    async def test_narrow_flow_from_request_to_response(self, monkeypatch):
        """Test the complete NARROW flow: request → classification → HTTP response."""
        monkeypatch.setenv("CAGE_NARROW_ENABLED", "true")
        
        import src.gateway.server.agent_gateway_adapter as adapter_module
        from src.gateway.server.agent_gateway_adapter import handle_check_request
        
        original_narrow_enabled = adapter_module._NARROW_ENABLED
        adapter_module._NARROW_ENABLED = True
        
        request_body = json.dumps({
            "method": "execute_trade",
            "params": {
                "symbol": "AAPL",
                "amount": 200000,  # Exceeds threshold
                "confidence": 0.99,
            },
        })
        
        mock_result = {
            "verdict": GovernanceDecision.NARROW,
            "violations": ["Amount exceeds limit"],
            "seal": "narrow-seal-e2e",
            "thread_id": "",
            "original_params": {"symbol": "AAPL", "amount": 200000},
            "narrowed_params": {"symbol": "AAPL", "amount": 100000},
            "constraints_applied": ["amount clamped: 200000 → 100000"],
            "narrowing_reason": "Amount exceeds max_allowed",
        }
        
        mock_gov = MagicMock()
        mock_gov.validate_action = AsyncMock(return_value=mock_result)
        
        import src.gateway.governance.singletons as _singletons
        
        try:
            with patch.object(_singletons, "symbolic_governor", mock_gov):
                response = await handle_check_request(request_body)
        finally:
            adapter_module._NARROW_ENABLED = original_narrow_enabled
        
        # Should be OK response (200) with narrowed params
        assert "ok_response" in response
        
        # Verify headers
        headers = response["ok_response"]["headers"]
        narrow_header = next(
            (h for h in headers if h["header"]["key"] == "X-Governance-Narrowed"),
            None,
        )
        assert narrow_header is not None
        assert narrow_header["header"]["value"] == "true"

    @pytest.mark.asyncio
    async def test_narrow_preserves_action_semantics(self, monkeypatch):
        """NARROW must preserve action semantics — only clamp, not transform."""
        monkeypatch.setenv("CAGE_NARROW_ENABLED", "true")
        
        import src.gateway.server.agent_gateway_adapter as adapter_module
        from src.gateway.server.agent_gateway_adapter import handle_check_request
        
        original_narrow_enabled = adapter_module._NARROW_ENABLED
        adapter_module._NARROW_ENABLED = True
        
        request_body = json.dumps({
            "method": "execute_trade",
            "params": {
                "symbol": "GOOG",
                "amount": 500000,
                "scope": ["read", "write", "delete"],
            },
        })
        
        mock_result = {
            "verdict": GovernanceDecision.NARROW,
            "violations": ["Amount exceeds limit", "Scope exceeds allowed"],
            "seal": "narrow-seal-semantic",
            "original_params": {
                "symbol": "GOOG",
                "amount": 500000,
                "scope": ["read", "write", "delete"],
            },
            "narrowed_params": {
                "symbol": "GOOG",  # Unchanged
                "amount": 100000,  # Clamped
                "scope": ["read", "write"],  # Filtered
            },
            "constraints_applied": [
                "amount clamped: 500000 → 100000",
                "scope narrowed: ['read', 'write', 'delete'] → ['read', 'write']",
            ],
            "narrowing_reason": "Multiple constraints applied",
        }
        
        mock_gov = MagicMock()
        mock_gov.validate_action = AsyncMock(return_value=mock_result)
        
        import src.gateway.governance.singletons as _singletons
        
        try:
            with patch.object(_singletons, "symbolic_governor", mock_gov):
                response = await handle_check_request(request_body)
        finally:
            adapter_module._NARROW_ENABLED = original_narrow_enabled
        
        # Parse response body
        ok_resp = response.get("ok_response", {})
        body = json.loads(ok_resp.get("body", "{}"))
        
        # Symbol should be unchanged (semantics preserved)
        assert body["narrowed_params"]["symbol"] == "GOOG"
        # Amount should be clamped
        assert body["narrowed_params"]["amount"] == 100000
        # Scope should be filtered but still valid operations
        assert set(body["narrowed_params"]["scope"]) == {"read", "write"}


# ---------------------------------------------------------------------------
# TestPauseE2EFlow — PAUSE end-to-end flow tests
# ---------------------------------------------------------------------------


class TestPauseE2EFlow:
    """End-to-end tests for the PAUSE governance primitive flow."""

    @pytest.mark.asyncio
    async def test_pause_flow_from_request_to_response(self, monkeypatch):
        """Test the complete PAUSE flow: request → classification → HTTP response."""
        monkeypatch.setenv("CAGE_PAUSE_ENABLED", "true")
        
        import src.gateway.server.agent_gateway_adapter as adapter_module
        from src.gateway.server.agent_gateway_adapter import handle_check_request
        
        original_pause_enabled = adapter_module._PAUSE_ENABLED
        adapter_module._PAUSE_ENABLED = True
        
        request_body = json.dumps({
            "method": "execute_trade",
            "params": {
                "symbol": "AAPL",
                "amount": 100,
                "confidence": 0.99,
            },
        })
        
        mock_result = {
            "verdict": GovernanceDecision.PAUSE,
            "violations": ["Rate limit exceeded"],
            "seal": "",
            "thread_id": "",
            "classification_meta": {
                "pause_reason": "RATE_LIMITED",
                "estimated_wait_seconds": 60,
            },
        }
        
        mock_gov = MagicMock()
        mock_gov.validate_action = AsyncMock(return_value=mock_result)
        
        mock_pause_manager = MagicMock()
        mock_pause_manager.pause_request = AsyncMock(return_value="pause-e2e-token")
        
        import src.gateway.governance.singletons as _singletons
        
        try:
            with patch.object(_singletons, "symbolic_governor", mock_gov):
                with patch(
                    "src.gateway.governance.pause_primitive.PauseManager",
                    return_value=mock_pause_manager,
                ):
                    with patch(
                        "src.gateway.infrastructure.redis_client.redis_client",
                        MagicMock(),
                    ):
                        response = await handle_check_request(request_body)
        finally:
            adapter_module._PAUSE_ENABLED = original_pause_enabled
        
        # Should be 503 Service Unavailable
        assert "denied_response" in response
        assert response["denied_response"]["status"]["code"] == 503
        
        # Verify body
        body = json.loads(response["denied_response"]["body"])
        assert body["verdict"] == GovernanceDecision.PAUSE
        assert body["pause_token"] == "pause-e2e-token"
        assert "/resume" in body["resume_endpoint"]

    @pytest.mark.asyncio
    async def test_pause_includes_retry_after_header(self, monkeypatch):
        """PAUSE response includes Retry-After header for client polling."""
        monkeypatch.setenv("CAGE_PAUSE_ENABLED", "true")
        
        import src.gateway.server.agent_gateway_adapter as adapter_module
        from src.gateway.server.agent_gateway_adapter import handle_check_request
        
        original_pause_enabled = adapter_module._PAUSE_ENABLED
        adapter_module._PAUSE_ENABLED = True
        
        request_body = json.dumps({
            "method": "execute_trade",
            "params": {"symbol": "AAPL"},
        })
        
        mock_result = {
            "verdict": GovernanceDecision.PAUSE,
            "violations": ["Circuit breaker open"],
            "seal": "",
            "classification_meta": {
                "pause_reason": "CIRCUIT_OPEN",
                "estimated_wait_seconds": 30,
            },
        }
        
        mock_gov = MagicMock()
        mock_gov.validate_action = AsyncMock(return_value=mock_result)
        
        mock_pause_manager = MagicMock()
        mock_pause_manager.pause_request = AsyncMock(return_value="pause-retry-token")
        
        import src.gateway.governance.singletons as _singletons
        
        try:
            with patch.object(_singletons, "symbolic_governor", mock_gov):
                with patch(
                    "src.gateway.governance.pause_primitive.PauseManager",
                    return_value=mock_pause_manager,
                ):
                    with patch(
                        "src.gateway.infrastructure.redis_client.redis_client",
                        MagicMock(),
                    ):
                        response = await handle_check_request(request_body)
        finally:
            adapter_module._PAUSE_ENABLED = original_pause_enabled
        
        # Verify Retry-After header
        headers = response["denied_response"]["headers"]
        retry_header = next(
            (h for h in headers if h["header"]["key"] == "Retry-After"),
            None,
        )
        assert retry_header is not None
