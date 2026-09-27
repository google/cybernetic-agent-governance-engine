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

"""Domain-neutral knowledge graph validator (Layer 1 kernel)."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


class KnowledgeGraphValidator:
    """Domain-neutral validator over an injected domain knowledge graph.

    Fails closed when no domain knowledge graph is injected or when queried
    with an unknown predicate or action.
    """

    def __init__(self, graph: Any | None = None) -> None:
        self.graph = graph

    def validate(self, action: str, params: dict[str, Any] | None = None) -> bool:
        """Validate an action against the injected domain knowledge graph.

        Returns False (fail-closed) when no domain graph is configured or
        when the action/predicate is unknown to the graph.
        """
        if self.graph is None:
            logger.warning(
                "KnowledgeGraphValidator.validate: no domain graph configured for action=%r — failing closed",
                action,
            )
            return False

        if hasattr(self.graph, "get_constraints_for_action"):
            constraints = self.graph.get_constraints_for_action(action)
            if not constraints:
                return False
            return True

        return False

    def check_predicate(self, predicate: str) -> bool:
        """Check whether a predicate/constraint ID is registered in the domain graph.

        Returns False (fail-closed) when no graph is configured or when the
        predicate is unknown.
        """
        if self.graph is None:
            return False

        constraints = getattr(self.graph, "constraints", {}) or {}
        ucas = getattr(self.graph, "ucas", {}) or {}
        return predicate in constraints or predicate in ucas

    def get_constraints_for_action(self, action: str) -> list[Any]:
        """Return constraints for ``action`` or raise ValueError if unconfigured."""
        if self.graph is None:
            raise ValueError(
                "KnowledgeGraphValidator has no domain knowledge graph configured — failing closed"
            )
        if not hasattr(self.graph, "get_constraints_for_action"):
            raise ValueError(
                "Configured knowledge graph does not implement get_constraints_for_action — failing closed"
            )
        return list(self.graph.get_constraints_for_action(action))


__all__ = ["KnowledgeGraphValidator"]
