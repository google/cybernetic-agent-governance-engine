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

"""A content-safety check that reaches no verdict is a refusal (POAM-2026-124).

Before this change two paths reported a check that did not run as passed:
absent rails (the gateway tool answered an error string the advisor labelled
SAFE) and NeMo raising "No main flow found" (``validate_with_nemo()``,
``verify_input()`` and ``validate_output_semantics()`` returned safe). Each
test below pins one no-verdict path to a refusal with its reason code.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from src.gateway.governance.content_safety import (
    CONTENT_SAFETY_ERROR,
    CONTENT_SAFETY_NO_MAIN_FLOW,
    CONTENT_SAFETY_RAILS_UNAVAILABLE,
    SAFE_VERDICT,
    is_safe_verdict,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

_NO_MAIN_FLOW = "No main flow found"


def _rails_raising(message: str) -> AsyncMock:
    rails = AsyncMock()
    rails.is_transparent_fallback = False
    rails.generate_async.side_effect = RuntimeError(message)
    rails.llm.ainvoke.side_effect = RuntimeError(message)
    return rails


def _rails_returning(response: dict[str, Any]) -> AsyncMock:
    rails = AsyncMock()
    rails.is_transparent_fallback = False
    rails.generate_async.return_value = response
    return rails


# ---------------------------------------------------------------------------
# Rail provider: "No main flow found" is refused in all three functions
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_validate_with_nemo_no_main_flow_is_refused() -> None:
    from src.integrations.nemo.manager import validate_with_nemo

    is_safe, reason, deterministic = await validate_with_nemo(
        "hello", _rails_raising(_NO_MAIN_FLOW)
    )

    assert is_safe is False
    assert reason.startswith(CONTENT_SAFETY_NO_MAIN_FLOW)
    assert deterministic is False


@pytest.mark.asyncio
async def test_verify_input_no_main_flow_is_refused() -> None:
    from src.integrations.nemo.manager import verify_input

    result = await verify_input(_rails_raising(_NO_MAIN_FLOW), "hello")

    assert result.is_safe is False
    assert result.reason.startswith(CONTENT_SAFETY_NO_MAIN_FLOW)


@pytest.mark.asyncio
async def test_validate_output_semantics_no_main_flow_is_refused() -> None:
    from src.integrations.nemo.manager import validate_output_semantics

    is_safe, reason = await validate_output_semantics(
        _rails_raising(_NO_MAIN_FLOW), "some model output"
    )

    assert is_safe is False
    assert reason.startswith(CONTENT_SAFETY_NO_MAIN_FLOW)


# ---------------------------------------------------------------------------
# Rail provider: absent rails and other errors carry their own codes
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rail_functions_without_rails_are_refused() -> None:
    from src.integrations.nemo.manager import (
        validate_output_semantics,
        validate_with_nemo,
        verify_input,
    )

    is_safe, reason, _ = await validate_with_nemo("hello", None)
    assert (is_safe, reason.split(":")[0]) == (False, CONTENT_SAFETY_RAILS_UNAVAILABLE)

    result = await verify_input(None, "hello")
    assert (result.is_safe, result.reason.split(":")[0]) == (
        False,
        CONTENT_SAFETY_RAILS_UNAVAILABLE,
    )

    is_safe, reason = await validate_output_semantics(None, "output")
    assert (is_safe, reason.split(":")[0]) == (False, CONTENT_SAFETY_RAILS_UNAVAILABLE)


@pytest.mark.asyncio
async def test_rail_function_errors_carry_the_error_code() -> None:
    from src.integrations.nemo.manager import (
        validate_output_semantics,
        validate_with_nemo,
        verify_input,
    )

    rails = _rails_raising("backend exploded")

    is_safe, reason, _ = await validate_with_nemo("hello", rails)
    assert (is_safe, reason.split(":")[0]) == (False, CONTENT_SAFETY_ERROR)

    result = await verify_input(rails, "hello")
    assert (result.is_safe, result.reason.split(":")[0]) == (
        False,
        CONTENT_SAFETY_ERROR,
    )

    is_safe, reason = await validate_output_semantics(rails, "output")
    assert (is_safe, reason.split(":")[0]) == (False, CONTENT_SAFETY_ERROR)


# ---------------------------------------------------------------------------
# Gateway tool: SAFE only for a verdict
# ---------------------------------------------------------------------------


@pytest.fixture
def gateway_tool_module(monkeypatch):
    """The gateway tool module with semantic rails switched on.

    These tests exercise what the tool reports once the rails are enabled.
    The off-by-configuration path (``CONTENT_SAFETY_RAILS_DISABLED``) is
    covered in tests/test_nemo_flag_binding.py.
    """
    import src.gateway.server.mcp_tool_server as mod

    monkeypatch.setenv("CAGE_NEMO_ENABLED", "true")
    monkeypatch.delenv("CAGE_INFERENCE_BACKEND", raising=False)
    saved = getattr(mod.app.state, "nemo_rails", None)
    yield mod
    mod.app.state.nemo_rails = saved


@pytest.mark.asyncio
async def test_verify_content_safety_without_rails_is_blocked(
    gateway_tool_module,
) -> None:
    """Enabled but not initialised is RAILS_UNAVAILABLE, not RAILS_DISABLED."""
    gateway_tool_module.app.state.nemo_rails = None

    verdict = await gateway_tool_module.verify_content_safety("hello")

    assert verdict.startswith(f"BLOCKED: {CONTENT_SAFETY_RAILS_UNAVAILABLE}")


@pytest.mark.asyncio
async def test_verify_content_safety_no_main_flow_is_blocked(
    gateway_tool_module,
) -> None:
    """End to end through the real rail provider, as POAM-2026-124 path 2."""
    gateway_tool_module.app.state.nemo_rails = _rails_raising(_NO_MAIN_FLOW)

    verdict = await gateway_tool_module.verify_content_safety("hello")

    assert verdict.startswith(f"BLOCKED: {CONTENT_SAFETY_NO_MAIN_FLOW}")


@pytest.mark.asyncio
async def test_verify_content_safety_when_check_raises_is_blocked(
    gateway_tool_module,
) -> None:
    gateway_tool_module.app.state.nemo_rails = _rails_returning({"response": []})
    with patch(
        "src.gateway.governance.semantic_rail_factory.validate_with_semantic_rail",
        AsyncMock(side_effect=RuntimeError("provider import failed")),
    ):
        verdict = await gateway_tool_module.verify_content_safety("hello")

    assert verdict.startswith(f"BLOCKED: {CONTENT_SAFETY_ERROR}")


@pytest.mark.asyncio
async def test_verify_content_safety_reports_rail_verdicts(
    gateway_tool_module,
) -> None:
    gateway_tool_module.app.state.nemo_rails = _rails_returning({"response": []})
    assert await gateway_tool_module.verify_content_safety("hello") == SAFE_VERDICT

    gateway_tool_module.app.state.nemo_rails = _rails_returning(
        {"response": [{"content": "I cannot help with that."}]}
    )
    assert (
        await gateway_tool_module.verify_content_safety("hello")
        == "BLOCKED: I cannot help with that."
    )


# ---------------------------------------------------------------------------
# Only the exact SAFE verdict is safe
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("output", "safe"),
    [
        (SAFE_VERDICT, True),
        # What the gateway answered for absent rails before POAM-2026-124.
        ("ERROR: NeMo rails not initialised.", False),
        ("BLOCKED: unsafe", False),
        ("SAFE, probably", False),
    ],
)
def test_only_the_exact_safe_verdict_is_safe(output: str, safe: bool) -> None:
    assert is_safe_verdict(output) is safe


# ---------------------------------------------------------------------------
# Advisor graph: the in-process input rail node blocks a no-main-flow check
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_harness_input_rail_blocks_when_no_main_flow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from src.gateway.governance.langgraph_harness import nemo_node_factory

    monkeypatch.setenv("CAGE_NEMO_ENABLED", "true")
    with patch.object(nemo_node_factory, "_ensure_presidio_engines", lambda: None):
        node = nemo_node_factory.create_nemo_guardrail_node()
    with (
        patch.object(
            nemo_node_factory,
            "get_nemo_rails",
            return_value=_rails_raising(_NO_MAIN_FLOW),
        ),
        patch.object(nemo_node_factory, "_redact_pii", lambda text: (text, [])),
    ):
        update = await node({"messages": [{"role": "user", "content": "hello"}]})

    assert update["guardrail_blocked"] is True
    assert update["guardrail_reason"].startswith(CONTENT_SAFETY_NO_MAIN_FLOW)
