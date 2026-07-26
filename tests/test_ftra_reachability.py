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

"""Tests for FTRA Tier 0.5 commencement reachability gate (FTRA-001).

All tests are hermetic (no live services required) and marked @pytest.mark.local.
"""

import pytest

pytest.importorskip("networkx", reason="networkx required for FTRA reachability tests")

from src.gateway.governance.ftra_reachability import (
    FtraReachabilityGate,
    FtraVerdict,
    get_ftra_gate,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def gate() -> FtraReachabilityGate:
    """Fresh FtraReachabilityGate instance per test."""
    return FtraReachabilityGate()


# ---------------------------------------------------------------------------
# Test 1: CLEAR verdict when direct path with no HITL/blocked nodes
# ---------------------------------------------------------------------------


@pytest.mark.local
def test_clear_verdict_when_direct_path(gate: FtraReachabilityGate) -> None:
    """Direct path from entry to target with no HITL or blocked nodes → CLEAR."""
    gate.build_graph(
        {
            "entry": ["validate", "execute"],
            "validate": ["execute"],
            "execute": ["done"],
            "done": [],
        }
    )
    result = gate.analyze("entry", "done")
    assert result.verdict == FtraVerdict.CLEAR, (
        f"Expected CLEAR, got {result.verdict}: {result.reason}"
    )
    assert "entry" not in result.blocked_paths or result.blocked_paths == []


# ---------------------------------------------------------------------------
# Test 2: HITL_REQUIRED when path goes through hitl_escalator
# ---------------------------------------------------------------------------


@pytest.mark.local
def test_hitl_required_when_path_through_hitl_node(gate: FtraReachabilityGate) -> None:
    """Path through hitl_escalator → HITL_REQUIRED verdict."""
    gate.build_graph(
        {
            "entry": ["hitl_escalator"],
            "hitl_escalator": ["execute"],
            "execute": ["done"],
            "done": [],
        }
    )
    result = gate.analyze("entry", "done")
    assert result.verdict == FtraVerdict.HITL_REQUIRED, (
        f"Expected HITL_REQUIRED, got {result.verdict}: {result.reason}"
    )
    assert "hitl_escalator" in result.reason


# ---------------------------------------------------------------------------
# Test 3: BLOCKED when no path between nodes
# ---------------------------------------------------------------------------


@pytest.mark.local
def test_blocked_when_no_path(gate: FtraReachabilityGate) -> None:
    """No path from entry to target → BLOCKED verdict."""
    gate.build_graph(
        {
            "entry": ["validate"],
            "validate": [],
            # "done" is disconnected — no path from entry
            "done": [],
        }
    )
    result = gate.analyze("entry", "done")
    assert result.verdict == FtraVerdict.BLOCKED, (
        f"Expected BLOCKED, got {result.verdict}: {result.reason}"
    )
    assert "No path" in result.reason


# ---------------------------------------------------------------------------
# Test 4: BLOCKED when all paths go through circuit_breaker
# ---------------------------------------------------------------------------


@pytest.mark.local
def test_blocked_when_all_paths_through_blocked_node(
    gate: FtraReachabilityGate,
) -> None:
    """All paths pass through circuit_breaker → BLOCKED verdict."""
    gate.build_graph(
        {
            "entry": ["circuit_breaker"],
            "circuit_breaker": ["execute"],
            "execute": ["done"],
            "done": [],
        }
    )
    result = gate.analyze("entry", "done")
    assert result.verdict == FtraVerdict.BLOCKED, (
        f"Expected BLOCKED, got {result.verdict}: {result.reason}"
    )
    # The blocked path should be recorded
    assert len(result.blocked_paths) > 0, "Expected at least one blocked path recorded"
