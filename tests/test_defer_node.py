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
tests/test_defer_node.py — Unit tests for the turn-terminal DeferNode.

The gateway owns ``DeferQueue``; ``defer_node`` records the gateway-issued
``deferral_ticket_id``, emits a truthful reason-specific turn-terminal hold
message without dead ``checkpoint_payload`` state or false HITL auto-resumption
claims, and fails closed if ``deferral_ticket_id`` is missing or blank.
"""

from __future__ import annotations

from typing import Any

import pytest

from src.governed_financial_advisor.graph.nodes.defer_node import defer_node

pytestmark = [pytest.mark.unit, pytest.mark.local]


def _make_state(
    ticket_id: Any = "ticket-12345",
    *,
    deferral_reason: Any = "CONFIDENCE_BELOW_THRESHOLD",
    confidence: float = 0.55,
    thread_id: str = "thread-defer-test",
    include_reason: bool = True,
) -> dict[str, Any]:
    """Build a minimal AgentState dict for defer_node."""
    state: dict[str, Any] = {
        "thread_id": thread_id,
        "execution_plan_output": {
            "action": "execute_trade",
            "symbol": "TSLA",
            "confidence": confidence,
            "amount_usd": 15000,
        },
        "timestamp": "2026-09-27T00:00:00Z",
    }
    if include_reason:
        state["deferral_reason"] = deferral_reason
    if ticket_id is not None:
        state["deferral_ticket_id"] = ticket_id
    return state


@pytest.mark.asyncio
async def test_defer_node_confidence_below_threshold_turn_terminal_hold() -> None:
    """CONFIDENCE_BELOW_THRESHOLD emits an epistemic turn-terminal hold without checkpoint_payload."""
    state = _make_state(
        ticket_id="  ticket-abc-999  ",
        deferral_reason="CONFIDENCE_BELOW_THRESHOLD",
    )
    result = await defer_node(state)

    assert result["safety_status"] == "DEFERRED"
    assert result["deferral_ticket_id"] == "ticket-abc-999"
    assert result["next_step"] == "FINISH"
    assert "checkpoint_payload" not in result
    assert set(result.keys()) == {
        "safety_status",
        "deferral_ticket_id",
        "messages",
        "next_step",
    }

    assert len(result["messages"]) == 1
    msg = result["messages"][0].content
    assert "TSLA" in msg
    assert "turn-terminal governance hold" in msg
    assert "will not execute in this turn or auto-resume via human approval" in msg
    assert "Ticket ID: `ticket-abc-999`" in msg
    assert "Reason: CONFIDENCE_BELOW_THRESHOLD" in msg
    assert "< 0.70" in msg
    assert "REQUIRE_APPROVAL" in msg
    assert "resume automatically" not in msg
    assert "approved by a human reviewer" not in msg
    assert "HITL review queue" not in msg


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "warrant_reason",
    ["WARRANT_INELIGIBLE", "WARRANT_INELIGIBLE: missing standing warrant"],
)
async def test_defer_node_warrant_ineligible_turn_terminal_hold(
    warrant_reason: str,
) -> None:
    """WARRANT_INELIGIBLE emits a reliance/warrant precondition hold message."""
    state = _make_state(ticket_id="ticket-warrant-42", deferral_reason=warrant_reason)
    result = await defer_node(state)

    assert result["safety_status"] == "DEFERRED"
    assert result["deferral_ticket_id"] == "ticket-warrant-42"
    assert result["next_step"] == "FINISH"
    assert "checkpoint_payload" not in result

    msg = result["messages"][0].content
    assert "TSLA" in msg
    assert "turn-terminal governance hold" in msg
    assert "will not execute in this turn or auto-resume via human approval" in msg
    assert "Ticket ID: `ticket-warrant-42`" in msg
    assert f"Reason: {warrant_reason}" in msg
    assert "external reliance or warrant precondition" in msg
    assert "cannot be overridden by human approval" in msg
    assert "resume automatically" not in msg
    assert "approved by a human reviewer" not in msg
    assert "< 0.70" not in msg


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("include_reason", "raw_reason"),
    [
        (False, None),
        (True, None),
        (True, ""),
        (True, "   "),
    ],
)
async def test_defer_node_defaults_missing_or_blank_reason(
    include_reason: bool, raw_reason: str | None
) -> None:
    """Missing or blank deferral_reason defaults to CONFIDENCE_BELOW_THRESHOLD."""
    state = _make_state(
        ticket_id="ticket-default-1",
        deferral_reason=raw_reason,
        include_reason=include_reason,
    )
    result = await defer_node(state)

    msg = result["messages"][0].content
    assert "Reason: CONFIDENCE_BELOW_THRESHOLD" in msg
    assert "< 0.70" in msg
    assert "checkpoint_payload" not in result


@pytest.mark.asyncio
@pytest.mark.parametrize("missing_ticket", [None, "", "   ", 123])
async def test_defer_node_fails_closed_without_gateway_ticket(
    missing_ticket: Any,
) -> None:
    """If deferral_ticket_id is missing, blank, or non-string, defer_node raises RuntimeError."""
    state = _make_state(ticket_id=missing_ticket)
    with pytest.raises(RuntimeError, match="deferral_ticket_id"):
        await defer_node(state)
