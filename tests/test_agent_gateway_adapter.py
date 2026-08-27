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

"""Tests for src/gateway/server/agent_gateway_adapter.py — Phase B Work Stream D."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.gateway.governance.decisions import GovernanceDecision
from src.gateway.server.agent_gateway_adapter import (
    ParseError,
    _build_denied_response,
    _build_ok_response,
    handle_check_request,
    parse_jsonrpc_body,
)

# ---------------------------------------------------------------------------
# parse_jsonrpc_body tests
# ---------------------------------------------------------------------------


class TestParseJsonRpcBody:
    """Tests for the JSON-RPC 2.0 body parser (SI-10 input validation)."""

    def test_empty_body_raises(self):
        with pytest.raises(ParseError, match="empty body"):
            parse_jsonrpc_body("")

    def test_empty_bytes_raises(self):
        with pytest.raises(ParseError, match="empty body"):
            parse_jsonrpc_body(b"")

    def test_invalid_json_raises(self):
        with pytest.raises(ParseError, match="invalid JSON"):
            parse_jsonrpc_body("not json")

    def test_non_object_raises(self):
        with pytest.raises(ParseError, match="must be a JSON object"):
            parse_jsonrpc_body(json.dumps([1, 2, 3]))

    def test_missing_params_raises(self):
        with pytest.raises(ParseError, match="'params' field must be a JSON object"):
            parse_jsonrpc_body(json.dumps({"method": "tools/call"}))

    def test_params_not_dict_raises(self):
        with pytest.raises(ParseError, match="'params' field must be a JSON object"):
            parse_jsonrpc_body(json.dumps({"method": "tools/call", "params": "bad"}))

    def test_mcp_tools_call_shape(self):
        """MCP tools/call shape: params.name + params.arguments."""
        body = json.dumps(
            {
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {
                    "name": "execute_trade",
                    "arguments": {"symbol": "AAPL", "amount": 100},
                },
            }
        )
        tool_name, params = parse_jsonrpc_body(body)
        assert tool_name == "execute_trade"
        assert params == {"symbol": "AAPL", "amount": 100}

    def test_simplified_shape(self):
        """Simplified shape: method is tool name, params is arguments."""
        body = json.dumps(
            {
                "method": "market_analysis",
                "params": {"ticker": "GOOG"},
            }
        )
        tool_name, params = parse_jsonrpc_body(body)
        assert tool_name == "market_analysis"
        assert params == {"ticker": "GOOG"}

    def test_bytes_input_accepted(self):
        body = json.dumps(
            {
                "method": "get_portfolio",
                "params": {},
            }
        ).encode()
        tool_name, params = parse_jsonrpc_body(body)
        assert tool_name == "get_portfolio"
        assert params == {}

    def test_body_too_large_raises(self):
        """Body exceeding 64KB limit must raise ParseError (fail-closed)."""
        large_body = json.dumps(
            {
                "method": "execute_trade",
                "params": {"data": "x" * 70000},
            }
        )
        with pytest.raises(ParseError, match="exceeds limit"):
            parse_jsonrpc_body(large_body)

    def test_empty_tool_name_raises(self):
        body = json.dumps({"method": "", "params": {}})
        with pytest.raises(ParseError, match="could not extract tool_name"):
            parse_jsonrpc_body(body)

    def test_no_tool_name_in_params_raises(self):
        body = json.dumps({"method": "tools/call", "params": {"arguments": {}}})
        # name is missing from params — falls back to method "tools/call"
        # which is a valid tool name in this path
        tool_name, _ = parse_jsonrpc_body(body)
        assert tool_name == "tools/call"


# ---------------------------------------------------------------------------
# Response builder tests
# ---------------------------------------------------------------------------


class TestResponseBuilders:
    """Tests for OkHttpResponse and DeniedHttpResponse builders."""

    def test_ok_response_has_routing_seal_header(self):
        resp = _build_ok_response("abc123seal")
        assert "ok_response" in resp
        headers = resp["ok_response"]["headers"]
        seal_header = next(
            (h for h in headers if h["header"]["key"] == "x-cage-routing-seal"),
            None,
        )
        assert seal_header is not None
        assert seal_header["header"]["value"] == "abc123seal"
        assert seal_header["append"] is False

    def test_ok_response_empty_seal_still_valid(self):
        resp = _build_ok_response("")
        assert "ok_response" in resp

    def test_denied_response_has_status_code(self):
        resp = _build_denied_response(403, {"error": "denied"})
        assert "denied_response" in resp
        assert resp["denied_response"]["status"]["code"] == 403

    def test_denied_response_body_is_json_string(self):
        body_dict = {"verdict": "DENIED", "violations": ["test"]}
        resp = _build_denied_response(403, body_dict)
        body_str = resp["denied_response"]["body"]
        parsed = json.loads(body_str)
        assert parsed["verdict"] == "DENIED"

    def test_denied_response_202_for_require_approval(self):
        resp = _build_denied_response(
            202, {"verdict": GovernanceDecision.REQUIRE_APPROVAL, "thread_id": "t1"}
        )
        assert resp["denied_response"]["status"]["code"] == 202
        body = json.loads(resp["denied_response"]["body"])
        assert body["verdict"] == GovernanceDecision.REQUIRE_APPROVAL

    def test_denied_response_202_for_defer(self):
        resp = _build_denied_response(
            202,
            {
                "verdict": GovernanceDecision.DEFER,
                "defer_id": "d1",
                "missing_input_reason": "confidence_below_threshold",
            },
        )
        assert resp["denied_response"]["status"]["code"] == 202
        body = json.loads(resp["denied_response"]["body"])
        assert body["verdict"] == GovernanceDecision.DEFER

    def test_denied_response_has_content_type_header(self):
        resp = _build_denied_response(403, {})
        headers = resp["denied_response"]["headers"]
        ct_header = next(
            (h for h in headers if h["header"]["key"] == "content-type"),
            None,
        )
        assert ct_header is not None
        assert ct_header["header"]["value"] == "application/json"


# ---------------------------------------------------------------------------
# handle_check_request tests
# ---------------------------------------------------------------------------


class TestHandleCheckRequest:
    """Tests for the core handle_check_request() coroutine."""

    @pytest.mark.asyncio
    async def test_parse_error_returns_denied_403(self):
        """Parse error → DeniedHttpResponse(403) fail-closed."""
        resp = await handle_check_request("not json")
        assert "denied_response" in resp
        assert resp["denied_response"]["status"]["code"] == 403
        body = json.loads(resp["denied_response"]["body"])
        assert body["error"] == "parse_error"

    @pytest.mark.asyncio
    async def test_empty_body_returns_denied_403(self):
        """Empty body → DeniedHttpResponse(403) fail-closed."""
        resp = await handle_check_request("")
        assert "denied_response" in resp
        assert resp["denied_response"]["status"]["code"] == 403

    @pytest.mark.asyncio
    async def test_body_too_large_returns_denied_403(self):
        """Body > 64KB → DeniedHttpResponse(403) fail-closed."""
        large_body = json.dumps(
            {
                "method": "execute_trade",
                "params": {"data": "x" * 70000},
            }
        )
        resp = await handle_check_request(large_body)
        assert "denied_response" in resp
        assert resp["denied_response"]["status"]["code"] == 403

    @pytest.mark.asyncio
    async def test_governance_allow_returns_ok_with_seal(self):
        """ALLOW verdict → OkHttpResponse with x-cage-routing-seal header."""
        body = json.dumps(
            {
                "method": "execute_trade",
                "params": {"symbol": "AAPL", "amount": 100},
            }
        )
        mock_result = {
            "verdict": GovernanceDecision.ALLOW,
            "violations": [],
            "seal": "test-seal-abc123",
            "thread_id": "",
        }
        mock_gov = MagicMock()
        mock_gov.validate_action = AsyncMock(return_value=mock_result)
        # The adapter does `from src.gateway.governance.singletons import symbolic_governor`
        # inside handle_check_request(). Patch the singletons module attribute so the
        # lazy import picks up the mock object.
        import src.gateway.governance.singletons as _singletons

        with patch.object(_singletons, "symbolic_governor", mock_gov):
            resp = await handle_check_request(
                body, caller_principal="spiffe://test/agent"
            )

        assert "ok_response" in resp
        headers = resp["ok_response"]["headers"]
        seal_header = next(
            h for h in headers if h["header"]["key"] == "x-cage-routing-seal"
        )
        assert seal_header["header"]["value"] == "test-seal-abc123"

    @pytest.mark.asyncio
    async def test_governance_deny_returns_denied_403(self):
        """DENY verdict → DeniedHttpResponse(403) with violation detail."""
        body = json.dumps(
            {
                "method": "execute_trade",
                "params": {"symbol": "AAPL", "amount": 9999999},
            }
        )
        mock_result = {
            "verdict": GovernanceDecision.DENY,
            "violations": ["trade amount exceeds limit"],
            "seal": "",
            "thread_id": "",
        }
        mock_gov = MagicMock()
        mock_gov.validate_action = AsyncMock(return_value=mock_result)
        import src.gateway.governance.singletons as _singletons

        with patch.object(_singletons, "symbolic_governor", mock_gov):
            resp = await handle_check_request(body)

        assert "denied_response" in resp
        assert resp["denied_response"]["status"]["code"] == 403
        body_parsed = json.loads(resp["denied_response"]["body"])
        assert body_parsed["verdict"] == GovernanceDecision.DENY
        assert "trade amount exceeds limit" in body_parsed["violations"]

    @pytest.mark.asyncio
    async def test_require_approval_returns_202_with_require_approval_verdict(self):
        """REQUIRE_APPROVAL verdict → DeniedHttpResponse(202) with REQUIRE_APPROVAL body.

        Conformance test: the adapter must NOT collapse REQUIRE_APPROVAL into
        DEFERRED or any other alias.  The body verdict field must exactly match
        GovernanceDecision.REQUIRE_APPROVAL so clients can distinguish a
        human-sign-off request from a context-hydration deferral.
        """
        body = json.dumps(
            {
                "method": "execute_trade",
                "params": {"symbol": "AAPL", "amount": 7500},
            }
        )
        mock_result = {
            "verdict": GovernanceDecision.REQUIRE_APPROVAL,
            "violations": ["[CTRL_OPA_001] Manual Review Required."],
            "seal": "",
            "thread_id": "thread-abc-123",
        }
        mock_gov = MagicMock()
        mock_gov.validate_action = AsyncMock(return_value=mock_result)
        import src.gateway.governance.singletons as _singletons

        with patch.object(_singletons, "symbolic_governor", mock_gov):
            resp = await handle_check_request(body)

        assert "denied_response" in resp
        assert resp["denied_response"]["status"]["code"] == 202
        body_parsed = json.loads(resp["denied_response"]["body"])
        # Conformance assertion: verdict must be REQUIRE_APPROVAL, not DEFERRED
        assert body_parsed["verdict"] == GovernanceDecision.REQUIRE_APPROVAL, (
            f"Expected verdict={GovernanceDecision.REQUIRE_APPROVAL!r}, "
            f"got {body_parsed['verdict']!r}. "
            "REQUIRE_APPROVAL must not be collapsed into DEFERRED."
        )
        assert body_parsed["thread_id"] == "thread-abc-123"
        # Must NOT contain defer_id (that belongs to DEFER responses only)
        assert "defer_id" not in body_parsed

    @pytest.mark.asyncio
    async def test_defer_returns_202_with_canonical_decision_field(self):
        """DEFER verdict → DeniedHttpResponse(202) with DEFER body and defer_token.

        Conformance test: the adapter must NOT collapse DEFER into REQUIRE_APPROVAL
        or DEFERRED.  The body decision field must exactly match GovernanceDecision.DEFER
        and must include defer_token and classification_reason so clients can route to
        GET /v1/defer/pending (data-hydration path), not GET /v1/approvals/pending.
        """
        body = json.dumps(
            {
                "method": "execute_trade",
                "params": {"symbol": "AAPL", "amount": 100, "confidence": 0.55},
            }
        )
        mock_result = {
            "verdict": GovernanceDecision.DEFER,
            "violations": [],
            "seal": "",
            "thread_id": "",
            "defer_token": "defer-xyz-789",
            "classification_reason": "confidence_below_threshold",
        }
        mock_gov = MagicMock()
        mock_gov.validate_action = AsyncMock(return_value=mock_result)
        import src.gateway.governance.singletons as _singletons

        with patch.object(_singletons, "symbolic_governor", mock_gov):
            resp = await handle_check_request(body)

        assert "denied_response" in resp
        assert resp["denied_response"]["status"]["code"] == 202
        body_parsed = json.loads(resp["denied_response"]["body"])
        # Conformance assertion: decision must be DEFER, not DEFERRED or REQUIRE_APPROVAL
        assert body_parsed["decision"] == GovernanceDecision.DEFER, (
            f"Expected decision={GovernanceDecision.DEFER!r}, "
            f"got {body_parsed['decision']!r}. "
            "DEFER must not be collapsed into REQUIRE_APPROVAL or DEFERRED."
        )
        assert body_parsed["defer_token"] == "defer-xyz-789"
        # Legacy fields must be absent
        assert "verdict" not in body_parsed
        assert "defer_id" not in body_parsed
        assert "missing_input_reason" not in body_parsed
        # Must NOT contain thread_id (that belongs to REQUIRE_APPROVAL responses only)
        assert body_parsed.get("thread_id", "") == ""

    @pytest.mark.asyncio
    async def test_validate_action_exception_returns_denied_403(self):
        """Unexpected exception in validate_action → DeniedHttpResponse(403) fail-closed."""
        body = json.dumps(
            {
                "method": "execute_trade",
                "params": {},
            }
        )
        mock_gov = MagicMock()
        mock_gov.validate_action = AsyncMock(side_effect=RuntimeError("unexpected"))
        import src.gateway.governance.singletons as _singletons

        with patch.object(_singletons, "symbolic_governor", mock_gov):
            resp = await handle_check_request(body)

        assert "denied_response" in resp
        assert resp["denied_response"]["status"]["code"] == 403
        body_parsed = json.loads(resp["denied_response"]["body"])
        assert body_parsed["error"] == "internal_error"

    @pytest.mark.asyncio
    async def test_caller_principal_injected_into_params(self):
        """caller_principal is injected as _caller_principal in params."""
        body = json.dumps(
            {
                "method": "execute_trade",
                "params": {"symbol": "AAPL"},
            }
        )
        captured_params: dict = {}

        async def _capture_validate(action, params, **kwargs):
            captured_params.update(params)
            return {
                "verdict": GovernanceDecision.ALLOW,
                "violations": [],
                "seal": "s",
                "thread_id": "",
            }

        mock_gov = MagicMock()
        mock_gov.validate_action = _capture_validate
        import src.gateway.governance.singletons as _singletons

        with patch.object(_singletons, "symbolic_governor", mock_gov):
            await handle_check_request(body, caller_principal="spiffe://trust/agent")

        assert captured_params.get("_caller_principal") == "spiffe://trust/agent"


# ---------------------------------------------------------------------------
# Conformance: every GovernanceDecision value produces a distinct HTTP response
# ---------------------------------------------------------------------------


class TestGovernanceDecisionConformance:
    """Conformance tests ensuring every canonical decision maps to a distinct
    HTTP response shape.  These tests guard against future regressions where
    REQUIRE_APPROVAL and DEFER collapse back into the same external state.
    """

    @pytest.mark.asyncio
    async def test_all_decisions_produce_distinct_verdict_fields(self):
        """Each GovernanceDecision value must produce a structurally distinct
        HTTP response body with a ``verdict`` field that matches the canonical
        enum value — not a translated alias.
        """
        import src.gateway.governance.singletons as _singletons

        decision_to_mock = {
            GovernanceDecision.ALLOW: {
                "verdict": GovernanceDecision.ALLOW,
                "violations": [],
                "seal": "seal-xyz",
                "thread_id": "",
            },
            GovernanceDecision.DENY: {
                "verdict": GovernanceDecision.DENY,
                "decision": GovernanceDecision.DENY,
                "violations": ["policy violation"],
                "seal": "",
                "thread_id": "",
            },
            GovernanceDecision.REQUIRE_APPROVAL: {
                "verdict": GovernanceDecision.REQUIRE_APPROVAL,
                "decision": GovernanceDecision.REQUIRE_APPROVAL,
                "violations": [],
                "seal": "",
                "thread_id": "t-123",
            },
            GovernanceDecision.DEFER: {
                "verdict": GovernanceDecision.DEFER,
                "decision": GovernanceDecision.DEFER,
                "violations": [],
                "seal": "",
                "thread_id": "",
                "defer_token": "d-456",
                "classification_reason": "confidence_below_threshold",
            },
        }

        body = json.dumps({"method": "execute_trade", "params": {"symbol": "AAPL"}})
        seen_verdicts: set[str] = set()

        for decision, mock_result in decision_to_mock.items():
            mock_gov = MagicMock()
            mock_gov.validate_action = AsyncMock(return_value=mock_result)

            with patch.object(_singletons, "symbolic_governor", mock_gov):
                resp = await handle_check_request(body)

            if decision == GovernanceDecision.ALLOW:
                assert "ok_response" in resp, (
                    f"ALLOW must produce ok_response, got: {list(resp.keys())}"
                )
                seen_verdicts.add("ok_response")
            else:
                assert "denied_response" in resp, (
                    f"{decision} must produce denied_response"
                )
                body_parsed = json.loads(resp["denied_response"]["body"])
                decision_in_body = body_parsed.get("decision", "")
                assert decision_in_body == decision, (
                    f"Expected decision={decision!r} in body, got {decision_in_body!r}. "
                    "Canonical decision must be preserved end-to-end."
                )
                assert decision_in_body not in seen_verdicts, (
                    f"Decision {decision_in_body!r} appeared in multiple responses — "
                    "decisions must map to distinct external states."
                )
                seen_verdicts.add(decision_in_body)


# ---------------------------------------------------------------------------
# TestDeferHTTPResponse — DEFER HTTP layer tests (Phase 1.6)
# ---------------------------------------------------------------------------


class TestDeferHTTPResponse:
    """Tests for DEFER decision HTTP response handling.

    DEFER decisions return HTTP 202 Accepted with a defer_token for
    later resumption via the data-hydration path.
    """

    @pytest.mark.asyncio
    async def test_defer_returns_202_accepted(self):
        """DEFER verdict → HTTP 202 Accepted."""
        body = json.dumps(
            {
                "method": "execute_trade",
                "params": {"symbol": "AAPL", "amount": 100, "confidence": 0.50},
            }
        )
        mock_result = {
            "verdict": GovernanceDecision.DEFER,
            "violations": ["Confidence below threshold"],
            "seal": "",
            "thread_id": "",
            "defer_id": "defer-abc-123",
            "defer_token": "defer-abc-123",
            "missing_input_reason": "confidence_below_threshold",
            "deferrable": True,
            "classification_meta": {
                "classification_reason": "Low confidence triggers DEFER",
            },
        }
        mock_gov = MagicMock()
        mock_gov.validate_action = AsyncMock(return_value=mock_result)
        import src.gateway.governance.singletons as _singletons

        with patch.object(_singletons, "symbolic_governor", mock_gov):
            resp = await handle_check_request(body)

        assert "denied_response" in resp
        assert resp["denied_response"]["status"]["code"] == 202

    @pytest.mark.asyncio
    async def test_defer_response_includes_defer_token(self):
        """DEFER response body includes defer_token for tracking."""
        body = json.dumps(
            {
                "method": "execute_trade",
                "params": {"symbol": "AAPL", "confidence": 0.50},
            }
        )
        mock_result = {
            "verdict": GovernanceDecision.DEFER,
            "violations": [],
            "seal": "",
            "thread_id": "",
            "defer_token": "defer-xyz-789",
            "classification_reason": "confidence_below_threshold",
            "deferrable": True,
        }
        mock_gov = MagicMock()
        mock_gov.validate_action = AsyncMock(return_value=mock_result)
        import src.gateway.governance.singletons as _singletons

        with patch.object(_singletons, "symbolic_governor", mock_gov):
            resp = await handle_check_request(body)

        body_parsed = json.loads(resp["denied_response"]["body"])
        assert body_parsed.get("defer_token") == "defer-xyz-789"
        # Legacy fields must be absent
        assert "verdict" not in body_parsed
        assert "defer_id" not in body_parsed
        assert "missing_input_reason" not in body_parsed

    @pytest.mark.asyncio
    async def test_defer_disabled_returns_403(self, monkeypatch):
        """When CAGE_DEFER_ENABLED=false, DEFER fallback returns HTTP 403.

        This test patches the module-level feature flag to simulate
        disabled DEFER functionality.
        """
        monkeypatch.setenv("CAGE_DEFER_ENABLED", "false")

        body = json.dumps(
            {
                "method": "execute_trade",
                "params": {"symbol": "AAPL", "confidence": 0.50},
            }
        )
        mock_result = {
            "verdict": GovernanceDecision.DEFER,
            "violations": ["Confidence below threshold"],
            "seal": "",
            "thread_id": "",
            "defer_id": "defer-test",
            "defer_token": "defer-test",
            "missing_input_reason": "confidence_below_threshold",
            "deferrable": True,
        }
        mock_gov = MagicMock()
        mock_gov.validate_action = AsyncMock(return_value=mock_result)
        import src.gateway.governance.singletons as _singletons
        import src.gateway.server.agent_gateway_adapter as adapter_module

        # Patch the module-level _DEFER_ENABLED flag
        original_defer_enabled = adapter_module._DEFER_ENABLED
        adapter_module._DEFER_ENABLED = False

        try:
            with patch.object(_singletons, "symbolic_governor", mock_gov):
                resp = await handle_check_request(body)
        finally:
            adapter_module._DEFER_ENABLED = original_defer_enabled

        assert "denied_response" in resp
        assert resp["denied_response"]["status"]["code"] == 403
        body_parsed = json.loads(resp["denied_response"]["body"])
        assert body_parsed.get("fallback_from") == "DEFER"

    @pytest.mark.asyncio
    async def test_defer_response_includes_retry_after_seconds(self):
        """DEFER response includes retry_after_seconds hint."""
        body = json.dumps(
            {
                "method": "execute_trade",
                "params": {"symbol": "AAPL", "confidence": 0.50},
            }
        )
        mock_result = {
            "verdict": GovernanceDecision.DEFER,
            "violations": [],
            "seal": "",
            "thread_id": "",
            "defer_id": "defer-test",
            "defer_token": "defer-test",
            "missing_input_reason": "confidence_below_threshold",
            "deferrable": True,
            "retry_after_seconds": 300,
        }
        mock_gov = MagicMock()
        mock_gov.validate_action = AsyncMock(return_value=mock_result)
        import src.gateway.governance.singletons as _singletons

        with patch.object(_singletons, "symbolic_governor", mock_gov):
            resp = await handle_check_request(body)

        body_parsed = json.loads(resp["denied_response"]["body"])
        assert body_parsed.get("retry_after_seconds") == 300


# ---------------------------------------------------------------------------
# TestNarrowHTTPResponse — NARROW HTTP layer tests (Phase 1.6)
# ---------------------------------------------------------------------------


class TestNarrowHTTPResponse:
    """Tests for NARROW decision HTTP response handling.

    NARROW decisions return HTTP 200 OK with X-Governance-Narrowed header
    and include both original and narrowed parameters in the response body.
    """

    @pytest.mark.asyncio
    async def test_narrow_returns_200_ok(self, monkeypatch):
        """NARROW verdict → HTTP 200 OK."""
        monkeypatch.setenv("CAGE_NARROW_ENABLED", "true")

        body = json.dumps(
            {
                "method": "execute_trade",
                "params": {"symbol": "AAPL", "amount": 150000},
            }
        )
        mock_result = {
            "verdict": GovernanceDecision.NARROW,
            "violations": ["Amount exceeds limit"],
            "seal": "narrow-seal-abc123",
            "thread_id": "",
            "original_params": {"symbol": "AAPL", "amount": 150000},
            "narrowed_params": {"symbol": "AAPL", "amount": 100000},
            "constraints_applied": ["amount clamped: 150000 → 100000"],
            "narrowing_reason": "Amount exceeds max_allowed",
        }
        mock_gov = MagicMock()
        mock_gov.validate_action = AsyncMock(return_value=mock_result)
        import src.gateway.governance.singletons as _singletons
        import src.gateway.server.agent_gateway_adapter as adapter_module

        original_narrow_enabled = adapter_module._NARROW_ENABLED
        adapter_module._NARROW_ENABLED = True

        try:
            with patch.object(_singletons, "symbolic_governor", mock_gov):
                resp = await handle_check_request(body)
        finally:
            adapter_module._NARROW_ENABLED = original_narrow_enabled

        assert "ok_response" in resp

    @pytest.mark.asyncio
    async def test_narrow_response_includes_x_governance_narrowed_header(
        self, monkeypatch
    ):
        """NARROW response includes X-Governance-Narrowed: true header."""
        monkeypatch.setenv("CAGE_NARROW_ENABLED", "true")

        body = json.dumps(
            {
                "method": "execute_trade",
                "params": {"symbol": "AAPL", "amount": 150000},
            }
        )
        mock_result = {
            "verdict": GovernanceDecision.NARROW,
            "violations": ["Amount exceeds limit"],
            "seal": "narrow-seal-abc123",
            "thread_id": "",
            "original_params": {"symbol": "AAPL", "amount": 150000},
            "narrowed_params": {"symbol": "AAPL", "amount": 100000},
            "constraints_applied": ["amount clamped: 150000 → 100000"],
            "narrowing_reason": "Amount exceeds max_allowed",
        }
        mock_gov = MagicMock()
        mock_gov.validate_action = AsyncMock(return_value=mock_result)
        import src.gateway.governance.singletons as _singletons
        import src.gateway.server.agent_gateway_adapter as adapter_module

        original_narrow_enabled = adapter_module._NARROW_ENABLED
        adapter_module._NARROW_ENABLED = True

        try:
            with patch.object(_singletons, "symbolic_governor", mock_gov):
                resp = await handle_check_request(body)
        finally:
            adapter_module._NARROW_ENABLED = original_narrow_enabled

        # Check for X-Governance-Narrowed header
        headers = resp.get("ok_response", {}).get("headers", [])
        narrow_header = next(
            (h for h in headers if h["header"]["key"] == "X-Governance-Narrowed"),
            None,
        )
        assert narrow_header is not None
        assert narrow_header["header"]["value"] == "true"

    @pytest.mark.asyncio
    async def test_narrow_disabled_falls_back_appropriately(self, monkeypatch):
        """When CAGE_NARROW_ENABLED=false, NARROW fallback returns HTTP 403."""
        monkeypatch.setenv("CAGE_NARROW_ENABLED", "false")

        body = json.dumps(
            {
                "method": "execute_trade",
                "params": {"symbol": "AAPL", "amount": 150000},
            }
        )
        mock_result = {
            "verdict": GovernanceDecision.NARROW,
            "violations": ["Amount exceeds limit"],
            "seal": "",
            "thread_id": "",
            "original_params": {"symbol": "AAPL", "amount": 150000},
            "narrowed_params": {"symbol": "AAPL", "amount": 100000},
            "constraints_applied": ["amount clamped"],
            "narrowing_reason": "Amount exceeds max_allowed",
        }
        mock_gov = MagicMock()
        mock_gov.validate_action = AsyncMock(return_value=mock_result)
        import src.gateway.governance.singletons as _singletons
        import src.gateway.server.agent_gateway_adapter as adapter_module

        original_narrow_enabled = adapter_module._NARROW_ENABLED
        adapter_module._NARROW_ENABLED = False

        try:
            with patch.object(_singletons, "symbolic_governor", mock_gov):
                resp = await handle_check_request(body)
        finally:
            adapter_module._NARROW_ENABLED = original_narrow_enabled

        assert "denied_response" in resp
        assert resp["denied_response"]["status"]["code"] == 403
        body_parsed = json.loads(resp["denied_response"]["body"])
        assert body_parsed.get("fallback_from") == "NARROW"

    @pytest.mark.asyncio
    async def test_narrow_response_includes_original_and_narrowed_params(
        self, monkeypatch
    ):
        """NARROW response body includes both original_params and narrowed_params."""
        monkeypatch.setenv("CAGE_NARROW_ENABLED", "true")

        body = json.dumps(
            {
                "method": "execute_trade",
                "params": {"symbol": "AAPL", "amount": 200000},
            }
        )
        mock_result = {
            "verdict": GovernanceDecision.NARROW,
            "violations": ["Amount exceeds limit"],
            "seal": "narrow-seal-xyz",
            "thread_id": "",
            "original_params": {"symbol": "AAPL", "amount": 200000},
            "narrowed_params": {"symbol": "AAPL", "amount": 100000},
            "constraints_applied": ["amount clamped: 200000 → 100000"],
            "narrowing_reason": "Amount exceeds max_allowed",
        }
        mock_gov = MagicMock()
        mock_gov.validate_action = AsyncMock(return_value=mock_result)
        import src.gateway.governance.singletons as _singletons
        import src.gateway.server.agent_gateway_adapter as adapter_module

        original_narrow_enabled = adapter_module._NARROW_ENABLED
        adapter_module._NARROW_ENABLED = True

        try:
            with patch.object(_singletons, "symbolic_governor", mock_gov):
                resp = await handle_check_request(body)
        finally:
            adapter_module._NARROW_ENABLED = original_narrow_enabled

        # Parse the response body
        ok_resp = resp.get("ok_response", {})
        response_body = ok_resp.get("body", "{}")
        body_parsed = json.loads(response_body)

        assert body_parsed.get("original_params", {}).get("amount") == 200000
        assert body_parsed.get("narrowed_params", {}).get("amount") == 100000
        assert len(body_parsed.get("constraints_applied", [])) > 0


# ---------------------------------------------------------------------------
# TestPauseHTTPResponse — PAUSE HTTP layer tests (Phase 1.6)
# ---------------------------------------------------------------------------


class TestPauseHTTPResponse:
    """Tests for PAUSE decision HTTP response handling.

    PAUSE decisions return HTTP 503 Service Unavailable with Retry-After
    header and include pause_token and resume_endpoint in the response body.
    """

    @pytest.mark.asyncio
    async def test_pause_returns_503_service_unavailable(self, monkeypatch):
        """PAUSE verdict → HTTP 503 Service Unavailable."""
        monkeypatch.setenv("CAGE_PAUSE_ENABLED", "true")

        body = json.dumps(
            {
                "method": "execute_trade",
                "params": {"symbol": "AAPL", "amount": 100},
            }
        )
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
        import src.gateway.governance.singletons as _singletons
        import src.gateway.server.agent_gateway_adapter as adapter_module
        from src.gateway.governance.pause_primitive import PauseManager

        original_pause_enabled = adapter_module._PAUSE_ENABLED
        adapter_module._PAUSE_ENABLED = True

        # Mock the PauseManager to avoid Redis dependency
        mock_pause_manager = MagicMock()
        mock_pause_manager.pause_request = AsyncMock(return_value="pause-token-abc123")

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
                        resp = await handle_check_request(body)
        finally:
            adapter_module._PAUSE_ENABLED = original_pause_enabled

        assert "denied_response" in resp
        assert resp["denied_response"]["status"]["code"] == 503

    @pytest.mark.asyncio
    async def test_pause_response_includes_retry_after_header(self, monkeypatch):
        """PAUSE response includes Retry-After header."""
        monkeypatch.setenv("CAGE_PAUSE_ENABLED", "true")

        body = json.dumps(
            {
                "method": "execute_trade",
                "params": {"symbol": "AAPL", "amount": 100},
            }
        )
        mock_result = {
            "verdict": GovernanceDecision.PAUSE,
            "violations": ["Rate limit exceeded"],
            "seal": "",
            "thread_id": "",
            "classification_meta": {
                "pause_reason": "RATE_LIMITED",
                "estimated_wait_seconds": 120,
            },
        }
        mock_gov = MagicMock()
        mock_gov.validate_action = AsyncMock(return_value=mock_result)
        import src.gateway.governance.singletons as _singletons
        import src.gateway.server.agent_gateway_adapter as adapter_module

        original_pause_enabled = adapter_module._PAUSE_ENABLED
        adapter_module._PAUSE_ENABLED = True

        mock_pause_manager = MagicMock()
        mock_pause_manager.pause_request = AsyncMock(return_value="pause-token-xyz")

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
                        resp = await handle_check_request(body)
        finally:
            adapter_module._PAUSE_ENABLED = original_pause_enabled

        # Check for Retry-After header
        headers = resp.get("denied_response", {}).get("headers", [])
        retry_header = next(
            (h for h in headers if h["header"]["key"] == "Retry-After"),
            None,
        )
        assert retry_header is not None
        # Retry-After should be a number (seconds)
        assert (
            retry_header["header"]["value"].isdigit()
            or retry_header["header"]["value"] == "120"
        )

    @pytest.mark.asyncio
    async def test_pause_response_includes_resume_endpoint(self, monkeypatch):
        """PAUSE response body includes resume_endpoint for client action."""
        monkeypatch.setenv("CAGE_PAUSE_ENABLED", "true")

        body = json.dumps(
            {
                "method": "execute_trade",
                "params": {"symbol": "AAPL", "amount": 100},
            }
        )
        mock_result = {
            "verdict": GovernanceDecision.PAUSE,
            "violations": ["Circuit breaker open"],
            "seal": "",
            "thread_id": "",
            "classification_meta": {
                "pause_reason": "CIRCUIT_OPEN",
                "estimated_wait_seconds": 30,
            },
        }
        mock_gov = MagicMock()
        mock_gov.validate_action = AsyncMock(return_value=mock_result)
        import src.gateway.governance.singletons as _singletons
        import src.gateway.server.agent_gateway_adapter as adapter_module

        original_pause_enabled = adapter_module._PAUSE_ENABLED
        adapter_module._PAUSE_ENABLED = True

        mock_pause_manager = MagicMock()
        mock_pause_manager.pause_request = AsyncMock(return_value="pause-token-resume")

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
                        resp = await handle_check_request(body)
        finally:
            adapter_module._PAUSE_ENABLED = original_pause_enabled

        body_parsed = json.loads(resp["denied_response"]["body"])
        assert "resume_endpoint" in body_parsed
        assert "/v1/pause/" in body_parsed["resume_endpoint"]
        assert "/resume" in body_parsed["resume_endpoint"]

    @pytest.mark.asyncio
    async def test_pause_disabled_falls_back_to_deny(self, monkeypatch):
        """When CAGE_PAUSE_ENABLED=false, PAUSE fallback returns HTTP 403."""
        monkeypatch.setenv("CAGE_PAUSE_ENABLED", "false")

        body = json.dumps(
            {
                "method": "execute_trade",
                "params": {"symbol": "AAPL", "amount": 100},
            }
        )
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
        import src.gateway.governance.singletons as _singletons
        import src.gateway.server.agent_gateway_adapter as adapter_module

        original_pause_enabled = adapter_module._PAUSE_ENABLED
        adapter_module._PAUSE_ENABLED = False

        try:
            with patch.object(_singletons, "symbolic_governor", mock_gov):
                resp = await handle_check_request(body)
        finally:
            adapter_module._PAUSE_ENABLED = original_pause_enabled

        assert "denied_response" in resp
        assert resp["denied_response"]["status"]["code"] == 403
        body_parsed = json.loads(resp["denied_response"]["body"])
        assert body_parsed.get("fallback_from") == "PAUSE"

    @pytest.mark.asyncio
    async def test_pause_response_includes_pause_token(self, monkeypatch):
        """PAUSE response body includes pause_token for resumption."""
        monkeypatch.setenv("CAGE_PAUSE_ENABLED", "true")

        body = json.dumps(
            {
                "method": "execute_trade",
                "params": {"symbol": "AAPL", "amount": 100},
            }
        )
        mock_result = {
            "verdict": GovernanceDecision.PAUSE,
            "violations": ["Resource unavailable"],
            "seal": "",
            "thread_id": "",
            "classification_meta": {
                "pause_reason": "RESOURCE_UNAVAILABLE",
                "estimated_wait_seconds": 180,
            },
        }
        mock_gov = MagicMock()
        mock_gov.validate_action = AsyncMock(return_value=mock_result)
        import src.gateway.governance.singletons as _singletons
        import src.gateway.server.agent_gateway_adapter as adapter_module

        original_pause_enabled = adapter_module._PAUSE_ENABLED
        adapter_module._PAUSE_ENABLED = True

        mock_pause_manager = MagicMock()
        mock_pause_manager.pause_request = AsyncMock(return_value="pause-uuid-12345678")

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
                        resp = await handle_check_request(body)
        finally:
            adapter_module._PAUSE_ENABLED = original_pause_enabled

        body_parsed = json.loads(resp["denied_response"]["body"])
        assert body_parsed.get("pause_token") == "pause-uuid-12345678"

    @pytest.mark.asyncio
    async def test_pause_redis_error_falls_back_to_deny(self, monkeypatch):
        """When Redis is unavailable for PAUSE, fallback to HTTP 403 DENY."""
        monkeypatch.setenv("CAGE_PAUSE_ENABLED", "true")

        body = json.dumps(
            {
                "method": "execute_trade",
                "params": {"symbol": "AAPL", "amount": 100},
            }
        )
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
        import src.gateway.governance.singletons as _singletons
        import src.gateway.server.agent_gateway_adapter as adapter_module

        original_pause_enabled = adapter_module._PAUSE_ENABLED
        adapter_module._PAUSE_ENABLED = True

        # Mock PauseManager to raise an exception (Redis unavailable)
        mock_pause_manager = MagicMock()
        mock_pause_manager.pause_request = AsyncMock(
            side_effect=ConnectionError("Redis connection refused")
        )

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
                        resp = await handle_check_request(body)
        finally:
            adapter_module._PAUSE_ENABLED = original_pause_enabled

        # Should fall back to DENY when Redis is unavailable
        assert "denied_response" in resp
        assert resp["denied_response"]["status"]["code"] == 403
        body_parsed = json.loads(resp["denied_response"]["body"])
        assert body_parsed.get("error") == "pause_storage_error"


pytestmark = [pytest.mark.unit, pytest.mark.local]
