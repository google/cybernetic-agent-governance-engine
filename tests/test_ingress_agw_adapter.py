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
Unit tests for src/gateway/governance/ingress/agw_adapter.py.

Tests AgwRequest, AgwAdapterResult dataclasses, AgwAdapter methods,
and the get_agw_adapter() singleton factory — all without live OIDC/network.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

# ---------------------------------------------------------------------------
# Dataclass tests
# ---------------------------------------------------------------------------


@pytest.mark.local
class TestAgwRequestDataclass:
    """Tests for the AgwRequest dataclass."""

    def test_required_fields_only(self):
        """AgwRequest can be constructed with only required fields."""
        from src.gateway.governance.ingress.agw_adapter import AgwRequest

        req = AgwRequest(
            agent_id="agent-001",
            tool_name="execute_trade",
            parameters={"symbol": "AAPL", "amount": 100},
        )

        assert req.agent_id == "agent-001"
        assert req.tool_name == "execute_trade"
        assert req.parameters == {"symbol": "AAPL", "amount": 100}
        assert req.oidc_token == ""
        assert req.trace_id == ""

    def test_optional_fields_defaults(self):
        """oidc_token and trace_id default to empty strings; metadata defaults to {}."""
        from src.gateway.governance.ingress.agw_adapter import AgwRequest

        req = AgwRequest(agent_id="a", tool_name="t", parameters={})

        assert req.oidc_token == ""
        assert req.trace_id == ""
        assert req.metadata == {}

    def test_full_construction(self):
        """AgwRequest accepts all fields."""
        from src.gateway.governance.ingress.agw_adapter import AgwRequest

        req = AgwRequest(
            agent_id="agent-xyz",
            tool_name="check_market_status",
            parameters={"symbol": "TSLA"},
            oidc_token="eyJ...",
            trace_id="trace-abc",
            metadata={"region": "us-fed"},
        )

        assert req.oidc_token == "eyJ..."
        assert req.trace_id == "trace-abc"
        assert req.metadata["region"] == "us-fed"


@pytest.mark.local
class TestAgwAdapterResultDataclass:
    """Tests for the AgwAdapterResult dataclass."""

    def test_required_fields(self):
        """AgwAdapterResult captures success/agent_id/tool_name/parameters."""
        from src.gateway.governance.ingress.agw_adapter import AgwAdapterResult

        result = AgwAdapterResult(
            success=True,
            agent_id="agent-001",
            tool_name="execute_trade",
            parameters={"amount": 500},
        )

        assert result.success is True
        assert result.agent_id == "agent-001"
        assert result.tool_name == "execute_trade"
        assert result.identity_verified is False
        assert result.error == ""

    def test_error_field_populated(self):
        """AgwAdapterResult can carry an error message."""
        from src.gateway.governance.ingress.agw_adapter import AgwAdapterResult

        result = AgwAdapterResult(
            success=False,
            agent_id="unknown",
            tool_name="",
            parameters={},
            error="OIDC validation failed",
        )

        assert result.success is False
        assert "OIDC" in result.error


# ---------------------------------------------------------------------------
# AgwAdapter.translate_request tests
# ---------------------------------------------------------------------------


@pytest.mark.local
class TestAgwAdapterTranslateRequest:
    """Tests for AgwAdapter.translate_request()."""

    @pytest.mark.asyncio
    async def test_translate_well_formed_request(self):
        """translate_request extracts agent_id, tool name and parameters correctly."""
        from src.gateway.governance.ingress.agw_adapter import AgwAdapter

        adapter = AgwAdapter()
        raw = {
            "agent_id": "advisor-001",
            "tool": {
                "name": "get_market_sentiment",
                "parameters": {"symbol": "NVDA"},
            },
            "auth": {"token": "tok-123"},
            "trace_id": "trace-xyz",
            "metadata": {"env": "prod"},
        }

        req = await adapter.translate_request(raw)

        assert req.agent_id == "advisor-001"
        assert req.tool_name == "get_market_sentiment"
        assert req.parameters == {"symbol": "NVDA"}
        assert req.oidc_token == "tok-123"
        assert req.trace_id == "trace-xyz"
        assert req.metadata["env"] == "prod"

    @pytest.mark.asyncio
    async def test_translate_missing_fields_use_defaults(self):
        """translate_request gracefully handles missing optional keys."""
        from src.gateway.governance.ingress.agw_adapter import AgwAdapter

        adapter = AgwAdapter()
        raw = {}  # completely empty

        req = await adapter.translate_request(raw)

        assert req.agent_id == "unknown"
        assert req.tool_name == ""
        assert req.parameters == {}
        assert req.oidc_token == ""
        assert req.trace_id == ""

    @pytest.mark.asyncio
    async def test_translate_nested_tool_dict(self):
        """tool.name and tool.parameters are extracted from the nested dict."""
        from src.gateway.governance.ingress.agw_adapter import AgwAdapter

        adapter = AgwAdapter()
        raw = {
            "agent_id": "a",
            "tool": {"name": "verify_content_safety", "parameters": {"text": "hello"}},
        }
        req = await adapter.translate_request(raw)

        assert req.tool_name == "verify_content_safety"
        assert req.parameters["text"] == "hello"


# ---------------------------------------------------------------------------
# AgwAdapter.validate_oidc_token tests
# ---------------------------------------------------------------------------


@pytest.mark.local
class TestAgwAdapterValidateOidcToken:
    """Tests for AgwAdapter.validate_oidc_token()."""

    @pytest.mark.asyncio
    async def test_no_issuer_returns_false(self):
        """Returns (False, {}) when AGW_OIDC_ISSUER is not configured."""
        with patch("src.gateway.governance.ingress.agw_adapter.AGW_OIDC_ISSUER", ""):
            from src.gateway.governance.ingress.agw_adapter import AgwAdapter

            adapter = AgwAdapter()
            is_valid, claims = await adapter.validate_oidc_token("any-token")

        assert is_valid is False
        assert claims == {}

    @pytest.mark.asyncio
    async def test_with_issuer_stub_returns_false(self):
        """Current stub implementation returns fail-closed (False, {}) even with issuer set."""
        with patch(
            "src.gateway.governance.ingress.agw_adapter.AGW_OIDC_ISSUER",
            "https://issuer.example.com",
        ):
            from src.gateway.governance.ingress.agw_adapter import AgwAdapter

            adapter = AgwAdapter()
            is_valid, claims = await adapter.validate_oidc_token("eyJ...")

        assert is_valid is False
        assert isinstance(claims, dict)


# ---------------------------------------------------------------------------
# AgwAdapter.process tests
# ---------------------------------------------------------------------------


@pytest.mark.local
class TestAgwAdapterProcess:
    """Tests for AgwAdapter.process()."""

    @pytest.mark.asyncio
    async def test_process_returns_adapter_result(self):
        """process() returns an AgwAdapterResult with fail-closed semantics.
        
        Issue #2 remediation: success is now coupled to identity_verified.
        When OIDC validation fails (identity_verified=False), success is also False.
        """
        from src.gateway.governance.ingress.agw_adapter import (
            AgwAdapter,
            AgwAdapterResult,
        )

        adapter = AgwAdapter()
        raw = {
            "agent_id": "agent-abc",
            "tool": {"name": "check_market_status", "parameters": {"symbol": "AAPL"}},
            "auth": {"token": ""},
        }
        result = await adapter.process(raw)

        assert isinstance(result, AgwAdapterResult)
        # Issue #2: success is now False when OIDC validation fails (fail-closed)
        assert result.success is False
        assert result.agent_id == "agent-abc"
        assert result.tool_name == "check_market_status"
        assert result.identity_verified is False  # OIDC stub returns False
        assert "OIDC token validation failed" in result.error

    @pytest.mark.asyncio
    async def test_process_propagates_parameters(self):
        """process() passes through the parameters dict correctly."""
        from src.gateway.governance.ingress.agw_adapter import AgwAdapter

        adapter = AgwAdapter()
        raw = {
            "agent_id": "a",
            "tool": {"name": "t", "parameters": {"key": "val", "num": 42}},
        }
        result = await adapter.process(raw)

        assert result.parameters["key"] == "val"
        assert result.parameters["num"] == 42


# ---------------------------------------------------------------------------
# Singleton factory
# ---------------------------------------------------------------------------


@pytest.mark.local
class TestGetAgwAdapter:
    """Tests for get_agw_adapter() lazy singleton."""

    def test_returns_agw_adapter_instance(self):
        """get_agw_adapter() returns an AgwAdapter."""
        import src.gateway.governance.ingress.agw_adapter as mod

        mod._agw_adapter = None  # reset singleton

        from src.gateway.governance.ingress.agw_adapter import (
            AgwAdapter,
            get_agw_adapter,
        )

        result = get_agw_adapter()

        assert isinstance(result, AgwAdapter)

    def test_returns_same_instance_on_second_call(self):
        """get_agw_adapter() is a singleton — same object on repeated calls."""
        import src.gateway.governance.ingress.agw_adapter as mod

        mod._agw_adapter = None  # reset

        from src.gateway.governance.ingress.agw_adapter import get_agw_adapter

        a1 = get_agw_adapter()
        a2 = get_agw_adapter()

        assert a1 is a2
