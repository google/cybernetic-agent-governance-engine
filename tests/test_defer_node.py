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
tests/test_defer_node.py — Unit tests for the DeferNode LangGraph integration.

The gateway owns DeferQueue; defer_node packages the gateway-issued
deferral_ticket_id into the LangGraph checkpoint payload and fails closed if
deferral_ticket_id is absent from state.
"""

from __future__ import annotations

import pytest

from src.governed_financial_advisor.graph.nodes.defer_node import defer_node

pytestmark = [pytest.mark.unit, pytest.mark.local]


def _make_state(
    ticket_id: str | None = "ticket-12345",
    confidence: float = 0.82,
    thread_id: str = "thread-defer-test",
) -> dict:
    """Build a minimal AgentState dict for defer_node."""
    state: dict = {
        "thread_id": thread_id,
        "execution_plan_output": {
            "action": "execute_trade",
            "symbol": "TSLA",
            "confidence": confidence,
            "amount_usd": 15000,
        },
        "deferral_reason": "High-value trade requires supervisor approval",
        "timestamp": "2026-09-27T00:00:00Z",
    }
    if ticket_id is not None:
        state["deferral_ticket_id"] = ticket_id
    return state


@pytest.mark.asyncio
async def test_defer_node_packages_gateway_ticket() -> None:
    """When deferral_ticket_id is present, defer_node packages checkpoint metadata and finishes."""
    state = _make_state(ticket_id="ticket-abc-999")
    result = await defer_node(state)

    assert result["safety_status"] == "DEFERRED"
    assert result["deferral_ticket_id"] == "ticket-abc-999"
    assert result["next_step"] == "FINISH"
    assert result["checkpoint_payload"] == {
        "ticket_id": "ticket-abc-999",
        "thread_id": "thread-defer-test",
        "defer_reason": "High-value trade requires supervisor approval",
        "execution_plan_snapshot": state["execution_plan_output"],
        "parked_at": "2026-09-27T00:00:00Z",
    }
    assert len(result["messages"]) == 1
    assert "ticket-abc-999" in result["messages"][0].content


@pytest.mark.asyncio
@pytest.mark.parametrize("missing_ticket", [None, ""])
async def test_defer_node_fails_closed_without_gateway_ticket(
    missing_ticket: str | None,
) -> None:
    """If deferral_ticket_id is missing or empty, defer_node raises RuntimeError (fail-closed)."""
    state = _make_state(ticket_id=missing_ticket)
    with pytest.raises(RuntimeError, match="deferral_ticket_id"):
        await defer_node(state)
