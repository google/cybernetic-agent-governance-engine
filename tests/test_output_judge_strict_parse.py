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

"""The output-safety judge's reply is parsed strictly (POAM-2026-125).

Before this change ``validate_output_semantics()`` read an empty reply, and
any reply that did not start with ``UNSAFE``, as safe. A reasoning model
writes its trace before its verdict, so even its correct ``UNSAFE`` was read
as ``SAFE``. Free text is no longer read as safe unless it says otherwise.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from src.gateway.governance.content_safety import CONTENT_SAFETY_UNPARSEABLE_VERDICT

pytestmark = [pytest.mark.unit, pytest.mark.local]

_REASONED_UNSAFE = (
    "<think>The output cites SEC Rule 99z, which does not exist.</think>\n"
    "UNSAFE: fabricated regulation"
)
# A chat template that opens the trace leaves only its end in the reply.
_TEMPLATE_OPENED_UNSAFE = (
    "The output cites SEC Rule 99z, which does not exist.\n</think>\n\n"
    "UNSAFE: fabricated regulation"
)


def _rails_returning(content: str) -> AsyncMock:
    rails = AsyncMock()
    rails.is_transparent_fallback = False
    rails.generate_async.return_value = (
        {"response": [{"content": content}]} if content else {"response": []}
    )
    return rails


async def _judge(content: str) -> tuple[bool, str]:
    from src.integrations.nemo.manager import validate_output_semantics

    return await validate_output_semantics(_rails_returning(content), "output")


@pytest.mark.parametrize("reply", [_REASONED_UNSAFE, _TEMPLATE_OPENED_UNSAFE])
@pytest.mark.asyncio
async def test_reasoning_model_unsafe_verdict_is_refused(reply: str) -> None:
    is_safe, reason = await _judge(reply)

    assert is_safe is False
    assert reason == "fabricated regulation"


@pytest.mark.parametrize(
    "reply",
    [
        "",
        "I think this output is unsafe: it fabricates SEC Rule 99z.",
        "The output contains harmful advice.",
        "<think>analysing</think>",
        "<think>analysing",
        "SAFE\nUNSAFE: it contradicts itself",
        "SAFE, although it cites a rule I cannot verify",
    ],
    ids=[
        "empty",
        "verdict-in-prose",
        "no-verdict-word",
        "trace-only",
        "unclosed-trace",
        "contradiction",
        "qualified-safe",
    ],
)
@pytest.mark.asyncio
async def test_degenerate_replies_are_refused(reply: str) -> None:
    is_safe, reason = await _judge(reply)

    assert is_safe is False
    assert reason.startswith(CONTENT_SAFETY_UNPARSEABLE_VERDICT)


@pytest.mark.parametrize(
    "reply",
    ["UNSAFE: fabricated regulation", "Unsafe \u2014 hallucinated citation"],
)
@pytest.mark.asyncio
async def test_unsafe_verdicts_are_refused(reply: str) -> None:
    is_safe, reason = await _judge(reply)

    assert is_safe is False
    assert not reason.startswith(CONTENT_SAFETY_UNPARSEABLE_VERDICT)


@pytest.mark.parametrize(
    "reply",
    ["SAFE", "safe.", "<think>Checked; nothing harmful.</think>\nSAFE"],
    ids=["bare", "lowercase-period", "reasoned"],
)
@pytest.mark.asyncio
async def test_conforming_safe_replies_pass(reply: str) -> None:
    assert await _judge(reply) == (True, "")


@pytest.mark.asyncio
async def test_output_rail_blocks_a_reasoning_model_unsafe_verdict() -> None:
    """The advisor graph's output rail replaces the answer with its sentinel."""
    from src.gateway.governance.langgraph_harness import nemo_node_factory
    from src.gateway.governance.langgraph_harness.types import NemoNodeConfig

    rails = AsyncMock()
    rails.is_transparent_fallback = False
    rails.generate_async.side_effect = [
        {"response": []},  # call 1: masking pass leaves the text unchanged
        {"response": [{"content": _REASONED_UNSAFE}]},  # call 2: the judge
    ]
    cfg = NemoNodeConfig()
    node = nemo_node_factory.create_nemo_output_rail_node(cfg)
    state: dict[str, Any] = {
        "messages": [{"role": "assistant", "content": "Buy under SEC Rule 99z."}]
    }
    with (
        patch.object(nemo_node_factory, "get_nemo_rails", return_value=rails),
        patch.object(nemo_node_factory, "_redact_pii", lambda text: (text, [])),
    ):
        update = await node(state)

    (message,) = update["messages"]
    content = message.content if hasattr(message, "content") else message["content"]
    assert content == cfg.output_blocked_sentinel
