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

"""Governed Trader Agent — trade execution agent with governance guardrails.

The governed trader is implemented as a LangGraph subgraph in
``src/governed_financial_advisor/graph/subgraphs/governed_trader_graph.py``.
This module provides the ``create_governed_trader_agent`` factory used by the
``__init__.py`` public API.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


def create_governed_trader_agent(**kwargs: Any) -> Any:
    """Return the compiled governed-trader LangGraph subgraph.

    This is a thin factory wrapper around the subgraph defined in
    ``governed_trader_graph``.  Keyword arguments are forwarded to the
    subgraph compiler (e.g. ``checkpointer``, ``interrupt_before``).

    Returns
    -------
    CompiledStateGraph
        A compiled LangGraph state machine ready for ``ainvoke`` / ``astream``.
    """
    from src.governed_financial_advisor.graph.subgraphs.governed_trader_graph import (
        governed_trader_graph,
    )

    logger.debug("create_governed_trader_agent: returning compiled subgraph")
    return governed_trader_graph
