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
Tests for Recursive Governance Risk Mitigation — AI 600-1 §2.1, §2.5.3
(POAM AI600-001 secondary).

The ConsensusGate uses LLM inference to govern LLM outputs — creating a
recursive governance risk where confabulation in the governance layer
propagates to the governed system.  These tests verify that:

1. Low-confidence outputs are blocked by ``is_confabulation_blocked()`` at
   ``CONFIDENCE_THRESHOLD``.
2. ``AGENTIC_SCOPE_STATEMENT.md`` documents the recursive governance risk.
"""

from __future__ import annotations

import pathlib

import pytest

pytest.importorskip("src", reason="src package required")

from src.gateway.governance.confabulation_scorer import (
    CONFIDENCE_THRESHOLD,
    is_confabulation_blocked,
)

SCOPE_STATEMENT_PATH = pathlib.Path("docs/governance/AGENTIC_SCOPE_STATEMENT.md")


# ---------------------------------------------------------------------------
# §7.3 — Confabulation threshold enforcement
# ---------------------------------------------------------------------------


class TestAdvisorConfabulationBlock:
    """Verify is_confabulation_blocked() enforces CONFIDENCE_THRESHOLD."""

    def test_advisor_confabulation_blocked_below_threshold(self):
        """Confidence below CONFIDENCE_THRESHOLD is blocked for confabulation risk."""
        assert is_confabulation_blocked(0.50) is True

    def test_advisor_confabulation_not_blocked_at_threshold(self):
        """Confidence at CONFIDENCE_THRESHOLD is not blocked."""
        assert is_confabulation_blocked(CONFIDENCE_THRESHOLD) is False


# ---------------------------------------------------------------------------
# §7.3 — Agentic scope statement documents recursive governance risk
# ---------------------------------------------------------------------------


class TestRecursiveGovernanceRiskDocumented:
    """Verify docs/AGENTIC_SCOPE_STATEMENT.md documents recursive governance risk."""

    def test_scope_statement_exists(self):
        """docs/AGENTIC_SCOPE_STATEMENT.md must exist."""
        assert SCOPE_STATEMENT_PATH.exists(), (
            f"Agentic scope statement not found at {SCOPE_STATEMENT_PATH}"
        )

    def test_scope_statement_mentions_recursive_governance(self):
        """Scope statement must mention recursive governance risk."""
        content = SCOPE_STATEMENT_PATH.read_text(encoding="utf-8")
        assert "recursive" in content.lower() or "Recursive" in content, (
            "docs/AGENTIC_SCOPE_STATEMENT.md does not document recursive governance risk"
        )

    def test_scope_statement_mentions_consensus_gate(self):
        """Scope statement must reference ConsensusGate in governance risk context."""
        content = SCOPE_STATEMENT_PATH.read_text(encoding="utf-8")
        assert (
            "ConsensusGate" in content
            or "ConsensusEngine" in content
            or "consensus" in content.lower()
        ), "docs/AGENTIC_SCOPE_STATEMENT.md does not reference ConsensusGate"

    def test_scope_statement_mentions_ai600_section(self):
        """Scope statement must reference AI 600-1 §2.1 or §2.5."""
        content = SCOPE_STATEMENT_PATH.read_text(encoding="utf-8")
        has_ref = (
            "AI 600-1" in content
            or "§2.1" in content
            or "§2.5" in content
            or "600-1" in content
        )
        assert has_ref, (
            "docs/AGENTIC_SCOPE_STATEMENT.md does not reference AI 600-1 §2.1/§2.5"
        )


pytestmark = [pytest.mark.unit, pytest.mark.local]
