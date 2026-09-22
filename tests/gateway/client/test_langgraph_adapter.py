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

"""Hermetic test suite for LangGraph integration adapter.

Tests @cage_guard decorator wrapping mock LangGraph nodes without
requiring live gateway or LangGraph runtime dependencies.
"""

from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.gateway.client.adapters.langgraph import cage_guard
from src.gateway.client.core import CageClient
from src.gateway.client.envelope import GovernanceEnvelope
from src.gateway.client.exceptions import (
    DeferralPending,
    PolicyViolationException,
)

pytestmark = [pytest.mark.unit, pytest.mark.local, pytest.mark.asyncio]


@pytest.fixture
def mock_cage_client():
    """Create mock CageClient for hermetic testing."""
    client = MagicMock(spec=CageClient)
    # Configure async mock for validate_action
    client.validate_action = AsyncMock()
    return client


@pytest.fixture
def mock_allow_envelope() -> GovernanceEnvelope:
    """Create mock ALLOW governance envelope."""
    now = datetime.now(timezone.utc)
    expires = now + timedelta(minutes=5)

    return GovernanceEnvelope(
        envelope_version="3.0",
        envelope_type="cage_governance_decision",
        issued_at=now,
        expires_at=expires,
        issuer={
            "service": "cage-gateway",
            "instance_id": "test-instance-001",
            "region": "us-central1",
        },
        subject={
            "action": "execute_trade",
            "action_hash": "abc123",
            "record_hash": "def456",
            "agent_id": "test-agent",
        },
        governance_context={
            "policy_version": "1.0",
            "tiers_passed": ["tier_1", "tier_2"],
        },
        payload={
            "decision": "ALLOW",
            "execution_token": "mock-token-123",
        },
        signature={
            "algorithm": "RS256",
            "value": "mock-signature-base64",
            "kid": "test-key-001",
        },
    )


async def test_cage_guard_allow_executes_node(
    mock_cage_client: MagicMock,
    mock_allow_envelope: GovernanceEnvelope,
):
    """Test @cage_guard allows node execution when client returns ALLOW."""
    # Configure mock to return ALLOW envelope
    mock_cage_client.validate_action.return_value = mock_allow_envelope

    # Define mock LangGraph node
    @cage_guard(client=mock_cage_client, action="execute_trade")
    async def trade_execution_node(state: dict[str, Any]) -> dict[str, Any]:
        """Mock LangGraph node that executes a trade."""
        trade_result = f"Executed trade: {state['proposed_action']}"
        return {"trade_result": trade_result, "status": "completed"}

    # Mock LangGraph state
    state = {
        "agent_id": "test-agent-007",
        "proposed_action": {"symbol": "AAPL", "amount": 1000},
        "context": {"session_id": "session-abc123"},
    }

    # Execute decorated node
    result = await trade_execution_node(state)

    # Verify governance was invoked
    mock_cage_client.validate_action.assert_called_once_with(
        action="execute_trade",
        parameters={"symbol": "AAPL", "amount": 1000},
        agent_id="test-agent-007",
        context={"session_id": "session-abc123"},
    )

    # Verify node executed successfully
    assert result["status"] == "completed"
    assert "Executed trade" in result["trade_result"]

    # Verify governance envelope was injected into state
    assert "governance_envelope" in state
    assert state["governance_envelope"] == mock_allow_envelope
    assert state["governance_status"] == "ALLOWED"


async def test_cage_guard_deny_raises_policy_violation(
    mock_cage_client: MagicMock,
):
    """Test @cage_guard bubbles up PolicyViolationException on DENY."""
    # Configure mock to raise PolicyViolationException
    mock_cage_client.validate_action.side_effect = PolicyViolationException(
        reason_code="TIER_3_BLOCKED",
        violation_details={
            "failed_tier": "tier_3",
            "policy_rule": "high_value_trade_limit",
            "evidence": "Trade amount exceeds $10,000 threshold",
        },
        audit_id="audit-deny-12345",
        recoverable=True,
    )

    # Define mock LangGraph node
    @cage_guard(client=mock_cage_client, action="execute_trade")
    async def trade_execution_node(state: dict[str, Any]) -> dict[str, Any]:
        """This node should never execute when DENY is raised."""
        pytest.fail("Node should not execute when governance denies action")
        return {"status": "should_not_reach"}

    # Mock LangGraph state
    state = {
        "agent_id": "test-agent-blocked",
        "proposed_action": {"symbol": "TSLA", "amount": 50000},
        "context": {},
    }

    # Execute decorated node and verify exception is raised
    with pytest.raises(PolicyViolationException) as exc_info:
        await trade_execution_node(state)

    # Verify exception details
    exc = exc_info.value
    assert exc.reason_code == "TIER_3_BLOCKED"
    assert exc.audit_id == "audit-deny-12345"
    assert exc.recoverable is True
    assert exc.violation_details["failed_tier"] == "tier_3"

    # Verify governance was attempted
    mock_cage_client.validate_action.assert_called_once()

    # Verify state was NOT modified (node never executed)
    assert "governance_envelope" not in state
    assert "governance_status" not in state


async def test_cage_guard_defer_raises_deferral_pending(
    mock_cage_client: MagicMock,
):
    """Test @cage_guard bubbles up DeferralPending on DEFER."""
    # Configure mock to raise DeferralPending
    expires_at = datetime.now(timezone.utc) + timedelta(hours=4)
    mock_cage_client.validate_action.side_effect = DeferralPending(
        ticket_id="defer-ticket-xyz789",
        defer_reason="High-value trade requires manual approval",
        expires_at=expires_at,
        ttl_seconds=14400,
    )

    # Define mock LangGraph node
    @cage_guard(client=mock_cage_client, action="execute_trade")
    async def trade_execution_node(state: dict[str, Any]) -> dict[str, Any]:
        """This node should never execute when DEFER is raised."""
        pytest.fail("Node should not execute when governance defers action")
        return {"status": "should_not_reach"}

    # Mock LangGraph state
    state = {
        "agent_id": "test-agent-deferred",
        "proposed_action": {"symbol": "GOOGL", "amount": 100000},
        "context": {"requires_approval": True},
    }

    # Execute decorated node and verify exception is raised
    with pytest.raises(DeferralPending) as exc_info:
        await trade_execution_node(state)

    # Verify exception details
    exc = exc_info.value
    assert exc.ticket_id == "defer-ticket-xyz789"
    assert exc.defer_reason == "High-value trade requires manual approval"
    assert exc.ttl_seconds == 14400
    assert exc.expires_at == expires_at

    # Verify governance was attempted
    mock_cage_client.validate_action.assert_called_once()

    # Verify state was NOT modified (node never executed)
    assert "governance_envelope" not in state
    assert "governance_status" not in state


async def test_cage_guard_missing_agent_id_defaults_to_unknown(
    mock_cage_client: MagicMock,
    mock_allow_envelope: GovernanceEnvelope,
):
    """Test @cage_guard defaults to 'unknown' agent_id when missing from state."""
    # Configure mock to return ALLOW envelope
    mock_cage_client.validate_action.return_value = mock_allow_envelope

    # Define mock LangGraph node
    @cage_guard(client=mock_cage_client, action="test_action")
    async def test_node(state: dict[str, Any]) -> dict[str, Any]:
        return {"result": "success"}

    # Mock LangGraph state WITHOUT agent_id
    state = {
        "proposed_action": {"param": "value"},
        # No agent_id field
    }

    # Execute decorated node
    await test_node(state)

    # Verify governance was called with "unknown" agent_id
    mock_cage_client.validate_action.assert_called_once_with(
        action="test_action",
        parameters={"param": "value"},
        agent_id="unknown",
        context={},
    )


async def test_cage_guard_custom_agent_id_key(
    mock_cage_client: MagicMock,
    mock_allow_envelope: GovernanceEnvelope,
):
    """Test @cage_guard with custom agent_id_key parameter."""
    # Configure mock to return ALLOW envelope
    mock_cage_client.validate_action.return_value = mock_allow_envelope

    # Define mock LangGraph node with custom agent_id_key
    @cage_guard(
        client=mock_cage_client,
        action="custom_action",
        agent_id_key="custom_agent_identifier",
    )
    async def custom_node(state: dict[str, Any]) -> dict[str, Any]:
        return {"result": "custom"}

    # Mock LangGraph state with custom agent_id key
    state = {
        "custom_agent_identifier": "custom-agent-999",
        "proposed_action": {"data": "test"},
        "context": {},
    }

    # Execute decorated node
    await custom_node(state)

    # Verify governance was called with custom agent_id
    mock_cage_client.validate_action.assert_called_once_with(
        action="custom_action",
        parameters={"data": "test"},
        agent_id="custom-agent-999",
        context={},
    )


async def test_cage_guard_empty_proposed_action_defaults_to_empty_dict(
    mock_cage_client: MagicMock,
    mock_allow_envelope: GovernanceEnvelope,
):
    """Test @cage_guard handles missing proposed_action gracefully."""
    # Configure mock to return ALLOW envelope
    mock_cage_client.validate_action.return_value = mock_allow_envelope

    # Define mock LangGraph node
    @cage_guard(client=mock_cage_client, action="empty_action")
    async def empty_node(state: dict[str, Any]) -> dict[str, Any]:
        return {"result": "empty"}

    # Mock LangGraph state WITHOUT proposed_action
    state = {
        "agent_id": "test-agent",
        # No proposed_action field
    }

    # Execute decorated node
    await empty_node(state)

    # Verify governance was called with empty parameters
    mock_cage_client.validate_action.assert_called_once_with(
        action="empty_action",
        parameters={},
        agent_id="test-agent",
        context={},
    )


async def test_cage_guard_preserves_original_function_metadata(
    mock_cage_client: MagicMock,
):
    """Test @cage_guard preserves function name and docstring."""

    @cage_guard(client=mock_cage_client, action="test_action")
    async def original_function(state: dict[str, Any]) -> dict[str, Any]:
        """Original function docstring."""
        return {"result": "test"}

    # Verify functools.wraps preserved metadata
    assert original_function.__name__ == "original_function"
    assert original_function.__doc__ == "Original function docstring."


async def test_cage_guard_state_mutation_on_allow(
    mock_cage_client: MagicMock,
    mock_allow_envelope: GovernanceEnvelope,
):
    """Test @cage_guard correctly mutates state with governance metadata on ALLOW."""
    # Configure mock to return ALLOW envelope
    mock_cage_client.validate_action.return_value = mock_allow_envelope

    # Define mock LangGraph node that inspects state
    @cage_guard(client=mock_cage_client, action="state_mutation_test")
    async def node_with_state_inspection(state: dict[str, Any]) -> dict[str, Any]:
        # Verify governance metadata was injected BEFORE node execution
        assert "governance_envelope" in state
        assert "governance_status" in state
        assert state["governance_status"] == "ALLOWED"
        assert isinstance(state["governance_envelope"], GovernanceEnvelope)
        return {"node_executed": True}

    # Mock LangGraph state
    state = {
        "agent_id": "test-agent",
        "proposed_action": {"test": "data"},
    }

    # Execute node
    result = await node_with_state_inspection(state)

    # Verify node executed
    assert result["node_executed"] is True

    # Verify state mutations persisted after node execution
    assert state["governance_envelope"] == mock_allow_envelope
    assert state["governance_status"] == "ALLOWED"
