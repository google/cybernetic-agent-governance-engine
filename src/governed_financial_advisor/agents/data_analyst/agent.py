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
Data Analyst Agent — factory function returning the compiled Data Analyst subgraph.

The actual thinker/doer/reporter pipeline lives in
``src.governed_financial_advisor.graph.subgraphs.data_analyst_graph``.
This module exposes the ``create_data_analyst_agent`` factory so that
the package ``__init__.py`` can re-export it in the standard way.
"""

from __future__ import annotations

from typing import Any


def create_data_analyst_agent() -> Any:
    """Return the compiled Data Analyst LangGraph subgraph.

    The subgraph is built lazily on first call to avoid circular imports
    at module load time.  The returned object is a
    ``langgraph.graph.CompiledStateGraph`` that accepts a
    ``DataAnalystState`` dict and returns the same type.
    """
    from src.governed_financial_advisor.graph.subgraphs.data_analyst_graph import (  # noqa: PLC0415
        data_analyst_graph,
    )

    return data_analyst_graph


__all__ = ["create_data_analyst_agent"]
