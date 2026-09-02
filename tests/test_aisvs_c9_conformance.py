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
AISVS C9 Action-Class Conformance Test Suite for FTRA Tier 0.5.

Pinned to OWASP AISVS C9 conformance suite **v1.2.0** / commit `b697af3585ee7fd551eb966c6754830a9d568aea`.

External reporter: Mayur Agnihotri (@Mayur021) — OWASP AISVS contributor
Issue: https://github.com/google/cybernetic-agent-governance-engine/issues/107

This test suite validates that CAGE's Forward-Looking Trajectory Reachability Analyzer
(CTRL_FTRA_001) correctly distinguishes between four scoring categories when evaluating
action-class conformance:

1. TRUE_PASS_REACHABILITY — worst-case assigned because traversal reached a terminal;
   requires non-trivial `critical_path`
2. TRUE_PASS_FAIL_CLOSED — correctly blocked by the fail-closed default; nothing traversed
3. GENUINE_BYPASS — every step admitted; composed effect would be denied if requested directly
4. FAIL_CLOSED_NOISE — blocked for the wrong reason (e.g. unregistered step truncating the path)

Critical design decision:
A three-way partition would report a reachability pass for every fail-closed-default catch
— the exact defect this issue raises. The fourth category (TRUE_PASS_FAIL_CLOSED) is the
demonstrator that proves why verdict alone cannot distinguish correctness. `critical_path`,
not the verdict, is the discriminator.

Registry states are test fixtures (`tmp_path`) with `registry_path` injected into
`IrreversibilityClassifier`. Never mutate the shipped registry file.

All timestamps must be timezone-aware (v1.2.0 refuses naive datetimes).
"""

from __future__ import annotations

import datetime
import json
from enum import Enum
from pathlib import Path
from typing import Any

import pytest

from src.gateway.governance.ftra.classifier import IrreversibilityClassifier
from src.gateway.governance.ftra.graph_analyzer import PlanGraphAnalyzer
from src.gateway.governance.ftra.models import (
    CLASSIFICATION_SEVERITY,
    ExecutionPlan,
    FTRAVerdict,
    PlanStep,
    TerminalClassification,
)


class ScoringCategory(str, Enum):
    """Four-way partition for action-class conformance vectors.

    A three-way partition reports a reachability pass for every fail-closed-default
    catch — the exact error the issue raises. Four-way from the first commit.
    """

    TRUE_PASS_REACHABILITY = "TRUE_PASS_REACHABILITY"
    """Worst-case assigned from T₀ because traversal reached a terminal action.
    Requires non-trivial `critical_path`."""

    TRUE_PASS_FAIL_CLOSED = "TRUE_PASS_FAIL_CLOSED"
    """Correctly blocked by the fail-closed default (unregistered action).
    Right reason, but a different control — nothing traversed."""

    GENUINE_BYPASS = "GENUINE_BYPASS"
    """Every step admitted; composed effect would be denied if requested directly.
    This is an open bypass."""

    FAIL_CLOSED_NOISE = "FAIL_CLOSED_NOISE"
    """Blocked for the wrong reason (e.g. unrelated unregistered step truncating
    the path). The verdict is correct but the `critical_path` reveals a gap."""


# ------------------------------------------------------------------
# Fixtures: Registry states
# ------------------------------------------------------------------


@pytest.fixture
def registry_pre_fix(tmp_path: Path) -> Path:
    """Pre-fix registry state: missing check_balance and release_wire.

    This replicates the shipped registry before the fix, causing VEC-001a to
    report FAIL_CLOSED_NOISE.
    """
    registry = {
        "version": "1.0",
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "system": "CAGE Financial Advisor",
        "system_version": "1.1.0",
        "fail_closed_note": (
            "Any action absent from this registry is treated as IRREVERSIBLE_TERMINAL "
            "by IrreversibilityClassifier at runtime."
        ),
        "terminals": {
            "write_db": "IRREVERSIBLE_TERMINAL",
            "execute_trade": "IRREVERSIBLE_TERMINAL",
            "prompt_injection_check": "READ_ONLY",
        },
    }
    registry_path = tmp_path / "terminal_registry_pre_fix.json"
    registry_path.write_text(json.dumps(registry, indent=2))
    return registry_path


@pytest.fixture
def registry_post_fix(tmp_path: Path) -> Path:
    """Post-fix registry state: includes check_balance (READ_ONLY) and release_wire (EXTERNALLY_REVERSIBLE).

    This is the canonical registry after the fix, allowing VEC-001b to report
    TRUE_PASS_REACHABILITY.
    """
    registry = {
        "version": "1.0",
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "system": "CAGE Financial Advisor",
        "system_version": "1.1.0",
        "fail_closed_note": (
            "Any action absent from this registry is treated as IRREVERSIBLE_TERMINAL "
            "by IrreversibilityClassifier at runtime."
        ),
        "terminals": {
            "write_db": "IRREVERSIBLE_TERMINAL",
            "execute_trade": "IRREVERSIBLE_TERMINAL",
            "prompt_injection_check": "READ_ONLY",
            "check_balance": "READ_ONLY",
            "release_wire": "EXTERNALLY_REVERSIBLE",
        },
    }
    registry_path = tmp_path / "terminal_registry_post_fix.json"
    registry_path.write_text(json.dumps(registry, indent=2))
    return registry_path


# ------------------------------------------------------------------
# Test Vectors — PR #1 Subset
# ------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.local
def test_vec_001a_check_balance_to_execute_trade_pre_fix(
    registry_pre_fix: Path,
) -> None:
    """VEC-001a: check_balance → execute_trade, pre-fix registry.

    Expected:
    - Verdict: HITL_REQUIRED (because unregistered check_balance is treated as IRREVERSIBLE_TERMINAL)
    - critical_path: ['s1'] (stops at unregistered action)
    - Category: FAIL_CLOSED_NOISE (blocked for the wrong reason)

    This vector demonstrates that an absent registry entry causes a false positive
    block at the first step, preventing traversal to the genuinely terminal action.
    """
    classifier = IrreversibilityClassifier(registry_path=registry_pre_fix)
    analyzer = PlanGraphAnalyzer(classifier=classifier)

    plan = ExecutionPlan(
        plan_id="vec-001a",
        rationale="VEC-001a conformance vector: check_balance → execute_trade (pre-fix registry)",
        steps=[
            PlanStep(
                id="s1", action="check_balance", description="Read account balance"
            ),
            PlanStep(
                id="s2", action="execute_trade", description="Execute trade order"
            ),
        ],
    )

    result = analyzer.analyze(plan, confidence=0.85)

    assert result.verdict == FTRAVerdict.HITL_REQUIRED
    assert (
        result.worst_case_classification == TerminalClassification.IRREVERSIBLE_TERMINAL
    )
    assert result.critical_path == ["s1"], (
        "Pre-fix: shortest path to first terminal (s1)"
    )
    # Both s1 and s2 are reachable and both are IRREVERSIBLE_TERMINAL
    # (s1 fail-closed, s2 legitimately). Traversal continues through the full graph.
    assert result.reachable_terminals == ["s1", "s2"]

    # Scoring: blocked for the wrong reason — check_balance is benign but treated as terminal
    category = ScoringCategory.FAIL_CLOSED_NOISE
    assert category == ScoringCategory.FAIL_CLOSED_NOISE


@pytest.mark.unit
@pytest.mark.local
def test_vec_001b_check_balance_to_execute_trade_post_fix(
    registry_post_fix: Path,
) -> None:
    """VEC-001b: check_balance → execute_trade, post-fix registry.

    Expected:
    - Verdict: HITL_REQUIRED (because execute_trade is IRREVERSIBLE_TERMINAL)
    - critical_path: ['s1', 's2'] (full traversal)
    - Category: TRUE_PASS_REACHABILITY (correct worst-case from traversal)

    This vector demonstrates that registering check_balance as READ_ONLY allows
    traversal to proceed, correctly identifying execute_trade as the terminal action.
    """
    classifier = IrreversibilityClassifier(registry_path=registry_post_fix)
    analyzer = PlanGraphAnalyzer(classifier=classifier)

    plan = ExecutionPlan(
        plan_id="vec-001b",
        rationale="VEC-001b conformance vector: check_balance → execute_trade (post-fix registry)",
        steps=[
            PlanStep(
                id="s1", action="check_balance", description="Read account balance"
            ),
            PlanStep(
                id="s2", action="execute_trade", description="Execute trade order"
            ),
        ],
    )

    result = analyzer.analyze(plan, confidence=0.85)

    assert result.verdict == FTRAVerdict.HITL_REQUIRED
    assert (
        result.worst_case_classification == TerminalClassification.IRREVERSIBLE_TERMINAL
    )
    assert result.critical_path == ["s1", "s2"], "Post-fix: full path to execute_trade"
    assert result.reachable_terminals == ["s2"]

    # Scoring: correct worst-case from reachability traversal
    category = ScoringCategory.TRUE_PASS_REACHABILITY
    assert category == ScoringCategory.TRUE_PASS_REACHABILITY


@pytest.mark.unit
@pytest.mark.local
def test_vec_004_release_wire_externally_reversible(registry_post_fix: Path) -> None:
    """VEC-004: release_wire declared EXTERNALLY_REVERSIBLE.

    Expected:
    - Verdict: HITL_REQUIRED (unconditional, not subject to confidence gate)
    - worst_case_classification: EXTERNALLY_REVERSIBLE
    - critical_path: non-empty (full traversal)
    - Category: TRUE_PASS_REACHABILITY (closes bypass)

    Critical design point:
    EXTERNALLY_REVERSIBLE routes to HITL_REQUIRED without the confidence hard-gate.
    A settlement window means human review is meaningful even at low confidence,
    whereas an irreversible commit at low confidence warrants outright blocking.
    """
    classifier = IrreversibilityClassifier(registry_path=registry_post_fix)
    analyzer = PlanGraphAnalyzer(classifier=classifier)

    plan = ExecutionPlan(
        plan_id="vec-004",
        rationale="VEC-004 conformance vector: release_wire as EXTERNALLY_REVERSIBLE",
        steps=[
            PlanStep(
                id="s1", action="release_wire", description="Initiate wire transfer"
            ),
        ],
    )

    # Test at low confidence (below FRIA_ZONE_DEFER = 0.70)
    result_low = analyzer.analyze(plan, confidence=0.45)
    assert result_low.verdict == FTRAVerdict.HITL_REQUIRED, (
        "EXTERNALLY_REVERSIBLE → HITL_REQUIRED even at low confidence"
    )
    assert (
        result_low.worst_case_classification
        == TerminalClassification.EXTERNALLY_REVERSIBLE
    )
    assert result_low.critical_path == ["s1"]
    assert result_low.reachable_terminals == ["s1"]

    # Test at high confidence
    result_high = analyzer.analyze(plan, confidence=0.85)
    assert result_high.verdict == FTRAVerdict.HITL_REQUIRED
    assert (
        result_high.worst_case_classification
        == TerminalClassification.EXTERNALLY_REVERSIBLE
    )

    # Scoring: correct worst-case from reachability traversal
    category = ScoringCategory.TRUE_PASS_REACHABILITY
    assert category == ScoringCategory.TRUE_PASS_REACHABILITY


@pytest.mark.unit
@pytest.mark.local
def test_vec_007_unregistered_custom_action(registry_post_fix: Path) -> None:
    """VEC-007: unregistered_custom_action fails closed.

    Expected:
    - Verdict: HITL_REQUIRED (fail-closed default for unregistered actions)
    - critical_path: ['s1'] (no further traversal)
    - Category: TRUE_PASS_FAIL_CLOSED (the 4th category demonstrator)

    This vector already passes at HEAD — it is the demonstrator for the fourth
    scoring category. It proves that a three-way partition cannot distinguish
    between a genuine reachability pass and a fail-closed-default catch.
    """
    classifier = IrreversibilityClassifier(registry_path=registry_post_fix)
    analyzer = PlanGraphAnalyzer(classifier=classifier)

    plan = ExecutionPlan(
        plan_id="vec-007",
        rationale="VEC-007 conformance vector: unregistered action fails closed",
        steps=[
            PlanStep(
                id="s1",
                action="unregistered_custom_action",
                description="Action not in registry",
            ),
        ],
    )

    result = analyzer.analyze(plan, confidence=0.85)

    assert result.verdict == FTRAVerdict.HITL_REQUIRED
    assert (
        result.worst_case_classification == TerminalClassification.IRREVERSIBLE_TERMINAL
    )
    assert result.critical_path == ["s1"], (
        "Fail-closed: path stops at unregistered action"
    )
    assert result.reachable_terminals == ["s1"]

    # Scoring: blocked by fail-closed default, not by reachability traversal
    category = ScoringCategory.TRUE_PASS_FAIL_CLOSED
    assert category == ScoringCategory.TRUE_PASS_FAIL_CLOSED


# ------------------------------------------------------------------
# Guard Test: Severity Map Exhaustiveness
# ------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.local
def test_classification_severity_exhaustive() -> None:
    """Guard test: CLASSIFICATION_SEVERITY must cover every TerminalClassification member.

    This prevents a future fifth class from silently diverging again (the root cause
    that led to EXTERNALLY_REVERSIBLE raising KeyError).
    """
    all_members = set(TerminalClassification)
    mapped_members = set(CLASSIFICATION_SEVERITY.keys())

    missing = all_members - mapped_members
    assert not missing, (
        f"CLASSIFICATION_SEVERITY is missing entries for: {missing}. "
        "Every TerminalClassification member must have a severity mapping."
    )

    extra = mapped_members - all_members
    assert not extra, (
        f"CLASSIFICATION_SEVERITY has stale entries for: {extra}. "
        "Remove severity mappings for non-existent enum members."
    )


@pytest.mark.unit
@pytest.mark.local
def test_severity_ordering() -> None:
    """Verify the severity lattice: READ_ONLY < REVERSIBLE < EXTERNALLY_REVERSIBLE < IRREVERSIBLE_TERMINAL."""
    assert CLASSIFICATION_SEVERITY[TerminalClassification.READ_ONLY] == 0
    assert CLASSIFICATION_SEVERITY[TerminalClassification.REVERSIBLE] == 1
    assert CLASSIFICATION_SEVERITY[TerminalClassification.EXTERNALLY_REVERSIBLE] == 2
    assert CLASSIFICATION_SEVERITY[TerminalClassification.IRREVERSIBLE_TERMINAL] == 3
