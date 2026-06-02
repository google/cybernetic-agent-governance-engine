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
NeMo Guardrail Nodes — mandatory, non-bypassable input and output gates.

This module is a thin domain-specific wrapper around the generic NeMo governance
harness (:mod:`src.gateway.governance.langgraph_harness`).  It provides:

  - ``_extract_user_input``: domain extractor that reads the last user message
    from the financial advisor's ``AgentState["messages"]`` list.
  - ``nemo_guardrail_node``: mandatory first node (input rail) — produced by
    :func:`create_nemo_guardrail_node`.
  - ``nemo_output_rail_node``: mandatory final node (output rail) — produced by
    :func:`create_nemo_output_rail_node`.

nemo_guardrail_node:
  MUST be the first node executed in the graph after START.
  Calls validate_with_nemo() directly (in-process, Option C) which includes:
    - _detect_bypass(): hardcoded bypass-phrase detection (pre-LLM)
    - NeMo input rails: options={"rails": ["input"]} (LLM-backed filter)
    - OTel instrumentation: guardrails.validate_input span
    - ISO 42001 stamps via stamp_iso_control()
    - Langfuse trace metadata
  Fail-closed: any exception → block.

nemo_output_rail_node:
  MUST be the last node before END on every non-blocked execution path.
  Calls verify_and_mask_output() which runs NeMo output rails (PII detection,
  policy compliance). Fail-closed: any exception → output replaced with the
  safe sentinel string "[OUTPUT BLOCKED: guardrail error]" rather than
  passing raw agent output through.

The gateway inference_proxy.py already enforces NeMo at the HTTP layer.
These nodes enforce it at the agent-graph layer for defense-in-depth.

ADR 2026-03-09: verify_semantic_nemo() removed from evaluator tools list.
                NeMo is no longer an optional LLM tool — it is infrastructure.
ADR 2026-03-09b: nemo_output_rail_node added as mandatory final node before END.
                 evaluator_node.py fail-open output rail removed in favour of
                 this canonical, fail-closed implementation.
"""

from __future__ import annotations

import logging
from typing import Any

from src.gateway.governance.langgraph_harness import (
    NemoNodeConfig,
    create_nemo_guardrail_node,
    create_nemo_output_rail_node,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Domain-specific message extractors — financial advisor AgentState
# ---------------------------------------------------------------------------

def _extract_user_input(state: dict[str, Any]) -> str:
    """Extract the most recent user message text from AgentState.

    AgentState stores conversation history in ``messages: list[BaseMessage]``
    (annotated with add_messages reducer).  There is no standalone ``user_input``
    field — the last message in the list is the current user turn.

    Handles both BaseMessage objects (with ``.content`` attribute) and raw
    dict-style tuples/dicts (``{"role": "...", "content": "..."}``) that
    LangGraph may inject during testing.
    """
    messages = state.get("messages", [])
    if not messages:
        return ""

    last_msg = messages[-1]

    # BaseMessage object (normal runtime path)
    if hasattr(last_msg, "content"):
        return str(last_msg.content)

    # Raw dict: {"role": "human", "content": "..."}
    if isinstance(last_msg, dict):
        return str(last_msg.get("content", ""))

    # Tuple: ("human", "text") — used in some tests
    if isinstance(last_msg, tuple) and len(last_msg) >= 2:
        return str(last_msg[1])

    return str(last_msg)


# ---------------------------------------------------------------------------
# Re-export get_nemo_rails from the harness so existing test mock targets work
# ---------------------------------------------------------------------------

from src.gateway.governance.langgraph_harness.nemo_node_factory import (  # noqa: E402
    get_nemo_rails,
)

# Re-export validate_with_nemo for test mock targets
try:
    from src.gateway.governance.nemo.manager import (  # noqa: E402
        validate_with_nemo,
        verify_and_mask_output,
    )
except ImportError:
    pass  # fail-closed at runtime via the harness


# ---------------------------------------------------------------------------
# Nodes — produced by the governance harness factories
# ---------------------------------------------------------------------------

nemo_guardrail_node = create_nemo_guardrail_node(NemoNodeConfig(
    message_extractor=_extract_user_input,
    blocked_state_key="guardrail_blocked",
    reason_state_key="guardrail_reason",
    pass_through_state=True,
))
"""Async LangGraph node — mandatory NeMo input rail (ADR 2026-03-09)."""

nemo_output_rail_node = create_nemo_output_rail_node(NemoNodeConfig(
    output_rail_applied_key="output_rail_applied",
    output_blocked_sentinel="[OUTPUT BLOCKED: guardrail error]",
    pass_through_state=False,
))
"""Async LangGraph node — mandatory NeMo output rail (ADR 2026-03-09b)."""
