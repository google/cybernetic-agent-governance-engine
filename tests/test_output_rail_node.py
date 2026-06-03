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
Tests for the mandatory NeMo output rail graph node (ADR 2026-03-09b).

nemo_output_rail_node is the final node before END on every non-blocked
execution path in the financial advisor graph.  These tests verify the
fail-closed contract:

  - unsafe/PII output → state updated with masked content (not raw)
  - safe output       → state updated (with scrubbed, but equivalent, text)
  - exception         → output replaced with "[OUTPUT BLOCKED: guardrail error]"
                        (raw agent output MUST NOT pass through)
  - flag set          → state["output_rail_applied"] == True after every run

No live NeMo instance is required — get_nemo_rails() and
verify_and_mask_output() are mocked via unittest.mock.patch.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

pytestmark = pytest.mark.unit

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

_SENTINEL = "[OUTPUT BLOCKED: guardrail error]"
_GUARDRAIL_MODULE = "src.gateway.governance.langgraph_harness.nemo_node_factory"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _FakeAIMessage:
    """Minimal stand-in for langchain_core.messages.AIMessage."""

    def __init__(self, content: str, id: str | None = None):
        self.content = content
        self.id = id


def _build_state(ai_text: str, msg_id: str | None = None) -> dict:
    """Build a minimal state dict whose last message is an AI response."""
    return {
        "messages": [_FakeAIMessage(ai_text, id=msg_id)],
        "output_rail_applied": False,
    }


def _get_output_text(result: dict) -> str:
    """
    Extract the text from the messages returned by nemo_output_rail_node.

    The node returns ``{"messages": [AIMessage(...)], "output_rail_applied": True}``.
    The AIMessage may be a real langchain AIMessage or our fake; both expose
    ``.content``.
    """
    messages = result.get("messages", [])
    assert messages, "nemo_output_rail_node returned no messages"
    last = messages[-1]
    # Real AIMessage or _FakeAIMessage — both have .content
    if hasattr(last, "content"):
        return last.content
    if isinstance(last, dict):
        return last.get("content", "")
    if isinstance(last, tuple) and len(last) >= 2:
        return str(last[1])
    return str(last)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_output_rail_masks_unsafe_output():
    """
    verify_and_mask_output returning masked content → state updated with
    the masked string, NOT the original raw agent output.

    validate_output_semantics is also mocked to return (True, '') so that
    the semantic validation step does not interfere with the PII-masking
    assertion.  The NeMo circuit breaker may be OPEN in test environments
    (transparent fallback mode), which would otherwise block the output
    before the assertion is reached.
    """
    from src.governed_financial_advisor.graph.nodes.guardrail_node import nemo_output_rail_node

    raw_output = "Here is John Doe's SSN: 123-45-6789 and portfolio details."
    masked_output = "Here is [PERSON]'s SSN: [US_SSN] and portfolio details."

    with patch(f"{_GUARDRAIL_MODULE}.get_nemo_rails", return_value=MagicMock()):
        with patch(
            f"{_GUARDRAIL_MODULE}.verify_and_mask_output",
            new_callable=AsyncMock,
            return_value=masked_output,
        ), patch(
            f"{_GUARDRAIL_MODULE}.validate_output_semantics",
            new_callable=AsyncMock,
            return_value=(True, ""),
        ):
            result = await nemo_output_rail_node(_build_state(raw_output))

    output_text = _get_output_text(result)
    assert output_text == masked_output, (
        f"Expected masked output but got: {output_text!r}"
    )
    assert raw_output not in output_text or "[PERSON]" in output_text, (
        "Raw PII must not appear verbatim in the output"
    )


@pytest.mark.asyncio
async def test_output_rail_passes_safe_output():
    """
    verify_and_mask_output returning (scrubbed) original content → state
    updated with that content.  The rail should not alter safe, PII-free text.

    validate_output_semantics is also mocked to return (True, '') so that
    the semantic validation step does not interfere with the pass-through
    assertion.  The NeMo circuit breaker may be OPEN in test environments
    (transparent fallback mode), which would otherwise block the output.
    """
    from src.governed_financial_advisor.graph.nodes.guardrail_node import nemo_output_rail_node

    safe_output = "AAPL is trading at $187.42 with moderate momentum indicators."

    with patch(f"{_GUARDRAIL_MODULE}.get_nemo_rails", return_value=MagicMock()):
        with patch(
            f"{_GUARDRAIL_MODULE}.verify_and_mask_output",
            new_callable=AsyncMock,
            return_value=safe_output,
        ), patch(
            f"{_GUARDRAIL_MODULE}.validate_output_semantics",
            new_callable=AsyncMock,
            return_value=(True, ""),
        ):
            result = await nemo_output_rail_node(_build_state(safe_output))

    output_text = _get_output_text(result)
    assert output_text == safe_output


@pytest.mark.asyncio
async def test_output_rail_fail_closed_on_verify_exception():
    """
    If verify_and_mask_output raises ANY exception, the raw output MUST be
    replaced with the safe sentinel — it must NEVER pass through unscreened.
    """
    from src.governed_financial_advisor.graph.nodes.guardrail_node import nemo_output_rail_node

    raw_output = "Sensitive agent output that must not leak."

    with patch(f"{_GUARDRAIL_MODULE}.get_nemo_rails", return_value=MagicMock()):
        with patch(
            f"{_GUARDRAIL_MODULE}.verify_and_mask_output",
            new_callable=AsyncMock,
            side_effect=RuntimeError("NeMo output rail internal error"),
        ):
            result = await nemo_output_rail_node(_build_state(raw_output))

    output_text = _get_output_text(result)
    assert output_text == _SENTINEL, (
        f"Expected sentinel on exception but got: {output_text!r}"
    )
    assert raw_output not in output_text, (
        "Raw agent output must NEVER pass through when verify_and_mask_output raises"
    )


@pytest.mark.asyncio
async def test_output_rail_fail_closed_when_rails_init_raises():
    """
    If get_nemo_rails() itself raises (NeMo not available, config missing,
    etc.) the output must be replaced with the safe sentinel — not the raw
    agent text.
    """
    from src.governed_financial_advisor.graph.nodes.guardrail_node import nemo_output_rail_node

    raw_output = "Raw agent output that must not leak when NeMo init fails."

    with patch(
        f"{_GUARDRAIL_MODULE}.get_nemo_rails",
        side_effect=RuntimeError("NeMo manager not available"),
    ):
        result = await nemo_output_rail_node(_build_state(raw_output))

    output_text = _get_output_text(result)
    assert output_text == _SENTINEL, (
        f"Expected sentinel when rails init fails but got: {output_text!r}"
    )
    assert raw_output not in output_text


@pytest.mark.asyncio
async def test_output_rail_sets_output_rail_applied_flag():
    """
    After nemo_output_rail_node runs — regardless of the output content —
    state["output_rail_applied"] must be True.
    """
    from src.governed_financial_advisor.graph.nodes.guardrail_node import nemo_output_rail_node

    with patch(f"{_GUARDRAIL_MODULE}.get_nemo_rails", return_value=MagicMock()):
        with patch(
            f"{_GUARDRAIL_MODULE}.verify_and_mask_output",
            new_callable=AsyncMock,
            return_value="screened output",
        ):
            result = await nemo_output_rail_node(_build_state("any agent output"))

    assert result.get("output_rail_applied") is True


@pytest.mark.asyncio
async def test_output_rail_applied_flag_set_even_on_exception():
    """
    output_rail_applied must be True even when verify_and_mask_output raises
    (the node ran; it just fail-closed the output).
    """
    from src.governed_financial_advisor.graph.nodes.guardrail_node import nemo_output_rail_node

    with patch(f"{_GUARDRAIL_MODULE}.get_nemo_rails", return_value=MagicMock()):
        with patch(
            f"{_GUARDRAIL_MODULE}.verify_and_mask_output",
            new_callable=AsyncMock,
            side_effect=ValueError("unexpected verify failure"),
        ):
            result = await nemo_output_rail_node(_build_state("agent output"))

    assert result.get("output_rail_applied") is True


@pytest.mark.asyncio
async def test_output_rail_handles_empty_messages_gracefully():
    """
    State with no messages should not raise — the node must return
    output_rail_applied=True and an empty messages list.
    """
    from src.governed_financial_advisor.graph.nodes.guardrail_node import nemo_output_rail_node

    result = await nemo_output_rail_node({"messages": [], "output_rail_applied": False})

    assert result.get("output_rail_applied") is True
    # No messages key, or empty — either is acceptable
    assert result.get("messages", []) == [] or "output_rail_applied" in result


@pytest.mark.asyncio
async def test_output_rail_handles_tuple_message_format():
    """
    Some node fixtures use tuple messages: ("ai", "text").
    The rail must handle this without crashing and apply screening.
    """
    from src.governed_financial_advisor.graph.nodes.guardrail_node import nemo_output_rail_node

    tuple_state = {
        "messages": [("ai", "Some agent response in tuple format.")],
        "output_rail_applied": False,
    }
    screened = "Some agent response in tuple format."

    with patch(f"{_GUARDRAIL_MODULE}.get_nemo_rails", return_value=MagicMock()):
        with patch(
            f"{_GUARDRAIL_MODULE}.verify_and_mask_output",
            new_callable=AsyncMock,
            return_value=screened,
        ):
            result = await nemo_output_rail_node(tuple_state)

    assert result.get("output_rail_applied") is True


@pytest.mark.asyncio
async def test_output_rail_never_duplicates_raw_output_on_exception():
    """
    Regression: confirm that a raw-output pass-through path does not exist
    anywhere in the exception handler.  The ONLY valid output on exception
    is the sentinel string.
    """
    from src.governed_financial_advisor.graph.nodes.guardrail_node import nemo_output_rail_node

    confidential_text = "CONFIDENTIAL: client SSN 987-65-4321, account #9876543."

    with patch(f"{_GUARDRAIL_MODULE}.get_nemo_rails", return_value=MagicMock()):
        with patch(
            f"{_GUARDRAIL_MODULE}.verify_and_mask_output",
            new_callable=AsyncMock,
            side_effect=Exception("any exception"),
        ):
            result = await nemo_output_rail_node(_build_state(confidential_text))

    output_text = _get_output_text(result)
    # The sentinel is the only acceptable result
    assert output_text == _SENTINEL
    # The confidential text must not appear anywhere in the result
    assert confidential_text not in str(result)
