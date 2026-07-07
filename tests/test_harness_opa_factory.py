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
Unit tests for the OPA safety-node factory in the LangGraph governance harness.

Tests verify that create_opa_safety_node() produces a node with correct:
  - APPROVED / BLOCKED / ESCALATED / SKIPPED decision paths
  - Fail-closed on unexpected exceptions
  - Configurable state keys and span attributes
  - Domain-agnostic payload extraction
"""

import asyncio
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from src.gateway.governance.langgraph_harness import (
    OpaNodeConfig,
    create_opa_safety_node,
    create_opa_safety_router,
)
from src.gateway.governance.symbolic_governor import GovernanceError

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _trade_extractor(state: dict[str, Any]) -> dict[str, Any]:
    """Test payload extractor — mirrors the financial advisor's pattern."""
    plan = state.get("plan") or {}
    return {
        "action": plan.get("action", "unknown"),
        "amount": plan.get("amount", 0),
        "symbol": plan.get("symbol", "UNKNOWN"),
    }


def _make_config(**overrides) -> OpaNodeConfig:
    defaults = dict(
        policy_action_name="execute_trade",
        payload_extractor=_trade_extractor,
        plan_state_key="plan",
        status_state_key="safety_status",
        error_state_key="error",
    )
    defaults.update(overrides)
    return OpaNodeConfig(**defaults)


def _state_with_plan(**plan_fields) -> dict[str, Any]:
    return {
        "plan": {
            "action": "execute_trade",
            "amount": 5000,
            "symbol": "AAPL",
            **plan_fields,
        },
        "thread_id": "test-thread",
    }


# ---------------------------------------------------------------------------
# Tests — create_opa_safety_node
# ---------------------------------------------------------------------------


class TestOpaNodeFactory:
    """Unit tests for create_opa_safety_node()."""

    @pytest.mark.asyncio
    async def test_approved_when_govern_succeeds(self):
        """govern() returning None (no exception) → APPROVED."""
        config = _make_config()
        node = create_opa_safety_node(config)

        mock_gov = AsyncMock()
        mock_gov.govern = AsyncMock(return_value=None)

        with patch(
            "src.gateway.governance.langgraph_harness.opa_node_factory.symbolic_governor",
            mock_gov,
        ):
            result = await node(_state_with_plan())

        assert result["safety_status"] == "APPROVED"
        assert "error" not in result
        mock_gov.govern.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_skipped_when_plan_absent(self):
        """Missing plan_state_key → SKIPPED without invoking govern()."""
        config = _make_config()
        node = create_opa_safety_node(config)

        mock_gov = AsyncMock()
        mock_gov.govern = AsyncMock(return_value=None)

        with patch(
            "src.gateway.governance.langgraph_harness.opa_node_factory.symbolic_governor",
            mock_gov,
        ):
            result = await node({"thread_id": "test"})

        assert result["safety_status"] == "SKIPPED"
        mock_gov.govern.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_blocked_on_governance_error(self):
        """GovernanceError (DENY) without Manual Review → BLOCKED."""
        config = _make_config()
        node = create_opa_safety_node(config)

        mock_gov = AsyncMock()
        mock_gov.govern = AsyncMock(
            side_effect=GovernanceError(
                "ISO 42001 Policy Violation: OPA Denied Action."
            )
        )

        with patch(
            "src.gateway.governance.langgraph_harness.opa_node_factory.symbolic_governor",
            mock_gov,
        ):
            result = await node(_state_with_plan())

        assert result["safety_status"] == "BLOCKED"
        assert "error" in result

    @pytest.mark.asyncio
    async def test_escalated_on_manual_review(self):
        """GovernanceError with 'Manual Review' → ESCALATED."""
        config = _make_config()
        node = create_opa_safety_node(config)

        mock_gov = AsyncMock()
        mock_gov.govern = AsyncMock(
            side_effect=GovernanceError(
                "ISO 42001 Policy Check: Manual Review Required."
            )
        )

        with patch(
            "src.gateway.governance.langgraph_harness.opa_node_factory.symbolic_governor",
            mock_gov,
        ):
            result = await node(_state_with_plan())

        assert result["safety_status"] == "ESCALATED"
        assert "error" in result

    @pytest.mark.asyncio
    async def test_fail_closed_on_unexpected_exception(self):
        """Unexpected RuntimeError → BLOCKED (fail-closed)."""
        config = _make_config()
        node = create_opa_safety_node(config)

        mock_gov = AsyncMock()
        mock_gov.govern = AsyncMock(side_effect=RuntimeError("unexpected"))

        with patch(
            "src.gateway.governance.langgraph_harness.opa_node_factory.symbolic_governor",
            mock_gov,
        ):
            result = await node(_state_with_plan())

        assert result["safety_status"] == "BLOCKED"

    @pytest.mark.asyncio
    async def test_fail_closed_on_timeout(self):
        """asyncio.TimeoutError → BLOCKED (fail-closed)."""
        config = _make_config()
        node = create_opa_safety_node(config)

        mock_gov = AsyncMock()
        mock_gov.govern = AsyncMock(side_effect=asyncio.TimeoutError("timeout"))

        with patch(
            "src.gateway.governance.langgraph_harness.opa_node_factory.symbolic_governor",
            mock_gov,
        ):
            result = await node(_state_with_plan())

        assert result["safety_status"] == "BLOCKED"

    @pytest.mark.asyncio
    async def test_custom_state_keys(self):
        """Factory respects custom status/error/plan state keys."""
        config = _make_config(
            status_state_key="my_safety",
            error_state_key="my_error",
            plan_state_key="my_plan",
        )
        node = create_opa_safety_node(config)

        mock_gov = AsyncMock()
        mock_gov.govern = AsyncMock(side_effect=GovernanceError("denied"))

        state = {"my_plan": {"action": "foo"}, "thread_id": "t"}
        with patch(
            "src.gateway.governance.langgraph_harness.opa_node_factory.symbolic_governor",
            mock_gov,
        ):
            result = await node(state)

        assert result["my_safety"] == "BLOCKED"
        assert "my_error" in result

    @pytest.mark.asyncio
    async def test_custom_payload_extractor(self):
        """Factory uses the provided payload_extractor, not a hardcoded schema."""
        extracted = {}

        def capture_extractor(state):
            payload = {"action": "custom_action", "data": state.get("custom_field")}
            extracted.update(payload)
            return payload

        config = _make_config(
            payload_extractor=capture_extractor,
            policy_action_name="custom_policy",
        )
        node = create_opa_safety_node(config)

        mock_gov = AsyncMock()
        mock_gov.govern = AsyncMock(return_value=None)

        state = {"plan": {"action": "ignored"}, "custom_field": "hello"}
        with patch(
            "src.gateway.governance.langgraph_harness.opa_node_factory.symbolic_governor",
            mock_gov,
        ):
            await node(state)

        # govern was called with the custom policy name and extracted payload
        mock_gov.govern.assert_awaited_once_with("custom_policy", extracted)

    @pytest.mark.asyncio
    async def test_status_key_always_present(self):
        """The status state key must always be in the returned dict."""
        config = _make_config()
        node = create_opa_safety_node(config)

        mock_gov = AsyncMock()
        mock_gov.govern = AsyncMock(return_value=None)

        with patch(
            "src.gateway.governance.langgraph_harness.opa_node_factory.symbolic_governor",
            mock_gov,
        ):
            result = await node(_state_with_plan())

        assert "safety_status" in result


# ---------------------------------------------------------------------------
# Tests — create_opa_safety_router
# ---------------------------------------------------------------------------


class TestOpaRouterFactory:
    """Tests for the deterministic routing function factory."""

    def test_approved_routes_to_approved_target(self):
        router = create_opa_safety_router(approved_target="trader")
        assert router({"safety_status": "APPROVED"}) == "trader"

    def test_skipped_routes_to_approved_target(self):
        router = create_opa_safety_router(approved_target="trader")
        assert router({"safety_status": "SKIPPED"}) == "trader"

    def test_blocked_routes_to_blocked_target(self):
        router = create_opa_safety_router(blocked_target="planner")
        assert router({"safety_status": "BLOCKED"}) == "planner"

    def test_escalated_routes_to_blocked_target(self):
        router = create_opa_safety_router(blocked_target="planner")
        assert router({"safety_status": "ESCALATED"}) == "planner"

    def test_custom_state_key(self):
        router = create_opa_safety_router(
            status_state_key="my_status",
            approved_target="next",
            blocked_target="fallback",
        )
        assert router({"my_status": "APPROVED"}) == "next"
        assert router({"my_status": "BLOCKED"}) == "fallback"
