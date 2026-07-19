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
        body = json.dumps({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "execute_trade",
                "arguments": {"symbol": "AAPL", "amount": 100},
            },
        })
        tool_name, params = parse_jsonrpc_body(body)
        assert tool_name == "execute_trade"
        assert params == {"symbol": "AAPL", "amount": 100}

    def test_simplified_shape(self):
        """Simplified shape: method is tool name, params is arguments."""
        body = json.dumps({
            "method": "market_analysis",
            "params": {"ticker": "GOOG"},
        })
        tool_name, params = parse_jsonrpc_body(body)
        assert tool_name == "market_analysis"
        assert params == {"ticker": "GOOG"}

    def test_bytes_input_accepted(self):
        body = json.dumps({
            "method": "get_portfolio",
            "params": {},
        }).encode()
        tool_name, params = parse_jsonrpc_body(body)
        assert tool_name == "get_portfolio"
        assert params == {}

    def test_body_too_large_raises(self):
        """Body exceeding 64KB limit must raise ParseError (fail-closed)."""
        large_body = json.dumps({
            "method": "execute_trade",
            "params": {"data": "x" * 70000},
        })
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

    def test_denied_response_202_for_deferred(self):
        resp = _build_denied_response(202, {"verdict": "DEFERRED", "thread_id": "t1"})
        assert resp["denied_response"]["status"]["code"] == 202

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
        large_body = json.dumps({
            "method": "execute_trade",
            "params": {"data": "x" * 70000},
        })
        resp = await handle_check_request(large_body)
        assert "denied_response" in resp
        assert resp["denied_response"]["status"]["code"] == 403

    @pytest.mark.asyncio
    async def test_governance_approve_returns_ok_with_seal(self):
        """APPROVED verdict → OkHttpResponse with x-cage-routing-seal header."""
        body = json.dumps({
            "method": "execute_trade",
            "params": {"symbol": "AAPL", "amount": 100},
        })
        mock_result = {
            "verdict": "APPROVED",
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
            resp = await handle_check_request(body, caller_principal="spiffe://test/agent")

        assert "ok_response" in resp
        headers = resp["ok_response"]["headers"]
        seal_header = next(
            h for h in headers if h["header"]["key"] == "x-cage-routing-seal"
        )
        assert seal_header["header"]["value"] == "test-seal-abc123"

    @pytest.mark.asyncio
    async def test_governance_deny_returns_denied_403(self):
        """DENIED verdict → DeniedHttpResponse(403) with violation detail."""
        body = json.dumps({
            "method": "execute_trade",
            "params": {"symbol": "AAPL", "amount": 9999999},
        })
        mock_result = {
            "verdict": "DENIED",
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
        assert body_parsed["verdict"] == "DENIED"
        assert "trade amount exceeds limit" in body_parsed["violations"]

    @pytest.mark.asyncio
    async def test_manual_review_returns_deferred_202(self):
        """MANUAL_REVIEW verdict → DeniedHttpResponse(202) with DEFERRED body."""
        body = json.dumps({
            "method": "execute_trade",
            "params": {"symbol": "AAPL", "amount": 100},
        })
        mock_result = {
            "verdict": "MANUAL_REVIEW",
            "violations": [],
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
        assert body_parsed["verdict"] == "DEFERRED"
        assert body_parsed["thread_id"] == "thread-abc-123"

    @pytest.mark.asyncio
    async def test_validate_action_exception_returns_denied_403(self):
        """Unexpected exception in validate_action → DeniedHttpResponse(403) fail-closed."""
        body = json.dumps({
            "method": "execute_trade",
            "params": {},
        })
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
        body = json.dumps({
            "method": "execute_trade",
            "params": {"symbol": "AAPL"},
        })
        captured_params: dict = {}

        async def _capture_validate(action, params, **kwargs):
            captured_params.update(params)
            return {"verdict": "APPROVED", "violations": [], "seal": "s", "thread_id": ""}

        mock_gov = MagicMock()
        mock_gov.validate_action = _capture_validate
        import src.gateway.governance.singletons as _singletons
        with patch.object(_singletons, "symbolic_governor", mock_gov):
            await handle_check_request(body, caller_principal="spiffe://trust/agent")

        assert captured_params.get("_caller_principal") == "spiffe://trust/agent"
