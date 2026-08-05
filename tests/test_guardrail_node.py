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
Tests for the mandatory NeMo guardrail graph node.

ADR 2026-03-09: nemo_guardrail_node is the mandatory first node in the
financial advisor graph.  These tests verify the fail-closed contract:
  - unsafe input → guardrail_blocked == True
  - safe input   → guardrail_blocked == False
  - exception    → guardrail_blocked == True  (fail-closed)
  - empty input  → guardrail_blocked == True  (fail-closed)

State format mirrors AgentState: messages is a list of BaseMessage-like objects.
The helper _build_state() wraps a string into the list format expected by
_extract_user_input() in guardrail_node.py.
"""

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

pytestmark = pytest.mark.unit

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _FakeHumanMessage:
    """Minimal stand-in for langchain_core.messages.HumanMessage."""

    def __init__(self, content: str):
        self.content = content


def _build_state(user_text: str) -> dict:
    """Build a minimal AgentState dict with the given user message."""
    return {
        "messages": [_FakeHumanMessage(user_text)],
        "guardrail_blocked": False,
        "guardrail_reason": "",
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_guardrail_blocks_unsafe_input():
    """validate_with_nemo returning (False, reason) → state.guardrail_blocked == True."""
    from src.governed_financial_advisor.graph.nodes.guardrail_node import (
        nemo_guardrail_node,
    )

    with patch.dict(os.environ, {"CAGE_SEAL_ENFORCEMENT": "enforce"}):
        with patch(
            "src.gateway.governance.langgraph_harness.nemo_node_factory.get_nemo_rails",
            return_value=MagicMock(),
        ):
            with patch(
                "src.gateway.governance.langgraph_harness.nemo_node_factory.validate_with_nemo",
                new_callable=AsyncMock,
                return_value=(
                    False,
                    "STPA Violation UCA-7: bypass attempt detected",
                    True,
                ),
            ):
                result = await nemo_guardrail_node(
                    _build_state("BYPASS-ALL-LIMITS now")
                )

    assert result["guardrail_blocked"] is True
    assert (
        "STPA" in result["guardrail_reason"]
        or "bypass" in result["guardrail_reason"].lower()
    )


@pytest.mark.asyncio
async def test_guardrail_passes_safe_input():
    """validate_with_nemo returning (True, '') → state.guardrail_blocked == False."""
    from src.governed_financial_advisor.graph.nodes.guardrail_node import (
        nemo_guardrail_node,
    )

    with patch(
        "src.gateway.governance.langgraph_harness.nemo_node_factory.get_nemo_rails",
        return_value=MagicMock(),
    ):
        with patch(
            "src.gateway.governance.langgraph_harness.nemo_node_factory.validate_with_nemo",
            new_callable=AsyncMock,
            return_value=(True, "", False),
        ):
            result = await nemo_guardrail_node(
                _build_state("What is the current price of AAPL?")
            )

    assert result["guardrail_blocked"] is False
    assert result["guardrail_reason"] == ""


@pytest.mark.asyncio
async def test_guardrail_fail_closed_on_exception():
    """If validate_with_nemo raises, the node must block (fail-closed)."""
    from src.governed_financial_advisor.graph.nodes.guardrail_node import (
        nemo_guardrail_node,
    )

    with patch.dict(os.environ, {"CAGE_SEAL_ENFORCEMENT": "enforce"}):
        with patch(
            "src.gateway.governance.langgraph_harness.nemo_node_factory.get_nemo_rails",
            return_value=MagicMock(),
        ):
            with patch(
                "src.gateway.governance.langgraph_harness.nemo_node_factory.validate_with_nemo",
                new_callable=AsyncMock,
                side_effect=RuntimeError("vLLM connection refused"),
            ):
                result = await nemo_guardrail_node(_build_state("safe-looking input"))

    assert result["guardrail_blocked"] is True
    assert "GUARDRAIL_ERROR" in result["guardrail_reason"]


@pytest.mark.asyncio
async def test_guardrail_blocks_empty_input():
    """Empty user message content → block by default (fail-closed on empty input)."""
    from src.governed_financial_advisor.graph.nodes.guardrail_node import (
        nemo_guardrail_node,
    )

    # State with an empty message — no NeMo call should be made
    result = await nemo_guardrail_node(_build_state(""))

    assert result["guardrail_blocked"] is True
    assert (
        "STPA" in result["guardrail_reason"]
        or "empty" in result["guardrail_reason"].lower()
    )


@pytest.mark.asyncio
async def test_guardrail_blocks_whitespace_only_input():
    """Whitespace-only input is treated the same as empty (fail-closed)."""
    from src.governed_financial_advisor.graph.nodes.guardrail_node import (
        nemo_guardrail_node,
    )

    result = await nemo_guardrail_node(_build_state("   "))

    assert result["guardrail_blocked"] is True


@pytest.mark.asyncio
async def test_guardrail_propagates_existing_state_fields():
    """Existing state fields must be preserved unchanged after guardrail pass."""
    from src.governed_financial_advisor.graph.nodes.guardrail_node import (
        nemo_guardrail_node,
    )

    base_state = {
        "messages": [_FakeHumanMessage("What ETFs are diversified?")],
        "guardrail_blocked": False,
        "guardrail_reason": "",
        "risk_attitude": "conservative",
        "user_id": "user-42",
    }

    with patch(
        "src.gateway.governance.langgraph_harness.nemo_node_factory.get_nemo_rails",
        return_value=MagicMock(),
    ):
        with patch(
            "src.gateway.governance.langgraph_harness.nemo_node_factory.validate_with_nemo",
            new_callable=AsyncMock,
            return_value=(True, "", False),
        ):
            result = await nemo_guardrail_node(base_state)

    assert result["guardrail_blocked"] is False
    assert result["risk_attitude"] == "conservative"
    assert result["user_id"] == "user-42"


@pytest.mark.asyncio
async def test_guardrail_fail_closed_when_rails_init_fails():
    """If get_nemo_rails() raises RuntimeError, the node must block (fail-closed)."""
    from src.governed_financial_advisor.graph.nodes.guardrail_node import (
        nemo_guardrail_node,
    )

    with patch.dict(os.environ, {"CAGE_SEAL_ENFORCEMENT": "enforce"}):
        with patch(
            "src.gateway.governance.langgraph_harness.nemo_node_factory.get_nemo_rails",
            side_effect=RuntimeError("NeMo manager not available"),
        ):
            result = await nemo_guardrail_node(
                _build_state("What is my portfolio balance?")
            )

    assert result["guardrail_blocked"] is True
    assert "GUARDRAIL_ERROR" in result["guardrail_reason"]
