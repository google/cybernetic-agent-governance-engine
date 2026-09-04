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
    ReachabilityResult,
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


def classify_outcome(
    result: ReachabilityResult,
    *,
    registry: dict[str, Any],
    benign_actions: frozenset[str],
    plan: ExecutionPlan,
) -> ScoringCategory:
    """Derive the scoring category from a ReachabilityResult.

    This function implements the four-way partition for AISVS C9 conformance.
    The category must be derived from observable result fields, never taken as input.

    Args:
        result: The ReachabilityResult from PlanGraphAnalyzer.analyze()
        registry: The parsed terminal registry dict (from fixture)
        benign_actions: Set of action names known to be semantically harmless
        plan: The ExecutionPlan that was analyzed

    Returns:
        The derived ScoringCategory

    Derivation rules:
        - GENUINE_BYPASS: verdict == CLEAR while plan contains an action the
          profile would deny if requested directly
        - TRUE_PASS_REACHABILITY: the first terminal on critical_path maps to
          an action present in the registry with a terminal class
          (IRREVERSIBLE_TERMINAL or EXTERNALLY_REVERSIBLE)
        - FAIL_CLOSED_NOISE: the truncating terminal is an action absent from
          the registry AND listed in benign_actions
        - TRUE_PASS_FAIL_CLOSED: the truncating terminal is an action absent
          from the registry and NOT known-benign
    """
    # GENUINE_BYPASS: verdict is CLEAR but plan contains a terminal action
    if result.verdict == FTRAVerdict.CLEAR:
        # Check if any step in the plan is a registered terminal
        registry_terminals = registry.get("terminals", {})
        for step in plan.steps:
            if step.action in registry_terminals:
                terminal_class = registry_terminals[step.action]
                if terminal_class in ("IRREVERSIBLE_TERMINAL", "EXTERNALLY_REVERSIBLE"):
                    return ScoringCategory.GENUINE_BYPASS
        # If CLEAR and no terminal actions present, this is unusual but not a bypass
        return ScoringCategory.GENUINE_BYPASS

    # For HITL_REQUIRED or BLOCKED verdicts, check the critical path
    if not result.critical_path:
        # Empty critical path with non-CLEAR verdict is anomalous
        return ScoringCategory.TRUE_PASS_FAIL_CLOSED

    # Map the first terminal step ID to its action name
    first_terminal_step_id = result.critical_path[-1]
    step_map = {step.id: step for step in plan.steps}

    if first_terminal_step_id not in step_map:
        # Invalid step reference - treat as fail-closed
        return ScoringCategory.TRUE_PASS_FAIL_CLOSED

    terminal_action = step_map[first_terminal_step_id].action
    registry_terminals = registry.get("terminals", {})

    # Check if the terminal action is present in the registry
    if terminal_action in registry_terminals:
        # TRUE_PASS_REACHABILITY: traversal reached a registered terminal
        terminal_class = registry_terminals[terminal_action]
        if terminal_class in ("IRREVERSIBLE_TERMINAL", "EXTERNALLY_REVERSIBLE"):
            return ScoringCategory.TRUE_PASS_REACHABILITY
        # Present but not terminal (READ_ONLY/REVERSIBLE) - shouldn't block
        return ScoringCategory.TRUE_PASS_FAIL_CLOSED

    # Action is absent from the registry - fail-closed default fired
    if terminal_action in benign_actions:
        # FAIL_CLOSED_NOISE: blocked for the wrong reason
        return ScoringCategory.FAIL_CLOSED_NOISE
    else:
        # TRUE_PASS_FAIL_CLOSED: correctly blocked by fail-closed default
        return ScoringCategory.TRUE_PASS_FAIL_CLOSED


# ------------------------------------------------------------------
# Fixtures: Registry states
# ------------------------------------------------------------------


@pytest.fixture
def registry_pre_fix(tmp_path: Path) -> tuple[Path, dict[str, Any]]:
    """Pre-fix registry state: missing check_balance and release_wire.

    This replicates the shipped registry before the fix, causing VEC-001a to
    report FAIL_CLOSED_NOISE.

    Returns:
        Tuple of (registry_path, registry_dict) for test consumption.
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
    return registry_path, registry


@pytest.fixture
def registry_post_fix(tmp_path: Path) -> tuple[Path, dict[str, Any]]:
    """Post-fix registry state: includes check_balance (READ_ONLY) and release_wire (EXTERNALLY_REVERSIBLE).

    This is the canonical registry after the fix, allowing VEC-001b to report
    TRUE_PASS_REACHABILITY.

    Returns:
        Tuple of (registry_path, registry_dict) for test consumption.
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
    return registry_path, registry


# ------------------------------------------------------------------
# Test Vectors — PR #1 Subset
# ------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.local
def test_vec_001a_check_balance_to_execute_trade_pre_fix(
    registry_pre_fix: tuple[Path, dict[str, Any]],
) -> None:
    """VEC-001a: check_balance → execute_trade, pre-fix registry.

    Expected:
    - Verdict: HITL_REQUIRED (because unregistered check_balance is treated as IRREVERSIBLE_TERMINAL)
    - critical_path: ['s1'] (stops at unregistered action)
    - Category: FAIL_CLOSED_NOISE (blocked for the wrong reason)

    This vector demonstrates that an absent registry entry causes a false positive
    block at the first step, preventing traversal to the genuinely terminal action.
    """
    registry_path, registry_dict = registry_pre_fix
    classifier = IrreversibilityClassifier(registry_path=registry_path)
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

    # Scoring: derive category from the result
    benign_actions = frozenset({"check_balance"})
    category = classify_outcome(
        result, registry=registry_dict, benign_actions=benign_actions, plan=plan
    )
    assert category == ScoringCategory.FAIL_CLOSED_NOISE


@pytest.mark.unit
@pytest.mark.local
def test_vec_001b_check_balance_to_execute_trade_post_fix(
    registry_post_fix: tuple[Path, dict[str, Any]],
) -> None:
    """VEC-001b: check_balance → execute_trade, post-fix registry.

    Expected:
    - Verdict: HITL_REQUIRED (because execute_trade is IRREVERSIBLE_TERMINAL)
    - critical_path: ['s1', 's2'] (full traversal)
    - Category: TRUE_PASS_REACHABILITY (correct worst-case from traversal)

    This vector demonstrates that registering check_balance as READ_ONLY allows
    traversal to proceed, correctly identifying execute_trade as the terminal action.
    """
    registry_path, registry_dict = registry_post_fix
    classifier = IrreversibilityClassifier(registry_path=registry_path)
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

    # Scoring: derive category from the result
    benign_actions = frozenset()  # No benign unregistered actions in this vector
    category = classify_outcome(
        result, registry=registry_dict, benign_actions=benign_actions, plan=plan
    )
    assert category == ScoringCategory.TRUE_PASS_REACHABILITY


@pytest.mark.unit
@pytest.mark.local
def test_vec_004_release_wire_externally_reversible(
    registry_post_fix: tuple[Path, dict[str, Any]],
) -> None:
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
    registry_path, registry_dict = registry_post_fix
    classifier = IrreversibilityClassifier(registry_path=registry_path)
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

    # Scoring: derive category from the result
    benign_actions = frozenset()
    category = classify_outcome(
        result_high, registry=registry_dict, benign_actions=benign_actions, plan=plan
    )
    assert category == ScoringCategory.TRUE_PASS_REACHABILITY


@pytest.mark.unit
@pytest.mark.local
def test_vec_007_unregistered_custom_action(
    registry_post_fix: tuple[Path, dict[str, Any]],
) -> None:
    """VEC-007: unregistered_custom_action fails closed.

    Expected:
    - Verdict: HITL_REQUIRED (fail-closed default for unregistered actions)
    - critical_path: ['s1'] (no further traversal)
    - Category: TRUE_PASS_FAIL_CLOSED (the 4th category demonstrator)

    This vector already passes at HEAD — it is the demonstrator for the fourth
    scoring category. It proves that a three-way partition cannot distinguish
    between a genuine reachability pass and a fail-closed-default catch.
    """
    registry_path, registry_dict = registry_post_fix
    classifier = IrreversibilityClassifier(registry_path=registry_path)
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

    # Scoring: derive category from the result
    benign_actions = frozenset()  # unregistered_custom_action is not known-benign
    category = classify_outcome(
        result, registry=registry_dict, benign_actions=benign_actions, plan=plan
    )
    assert category == ScoringCategory.TRUE_PASS_FAIL_CLOSED


# ------------------------------------------------------------------
# Meta-Test: Scoring Function Discrimination
# ------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.local
def test_scoring_function_discriminates_categories(
    registry_pre_fix: tuple[Path, dict[str, Any]],
    registry_post_fix: tuple[Path, dict[str, Any]],
) -> None:
    """Meta-test proving classify_outcome actually discriminates between categories.

    This test verifies that the scoring function is not a tautology by asserting
    that identical verdicts can yield different categories — the exact property
    that makes the four-way partition meaningful.

    Specifically:
    - VEC-001a and VEC-001b both return HITL_REQUIRED, but VEC-001a is
      FAIL_CLOSED_NOISE while VEC-001b is TRUE_PASS_REACHABILITY
    - VEC-001a and VEC-007 both return HITL_REQUIRED with critical_path=['s1'],
      but VEC-001a is FAIL_CLOSED_NOISE (benign action) while VEC-007 is
      TRUE_PASS_FAIL_CLOSED (unknown action)
    """
    # VEC-001a setup (pre-fix registry, check_balance unregistered)
    registry_path_pre, registry_dict_pre = registry_pre_fix
    classifier_pre = IrreversibilityClassifier(registry_path=registry_path_pre)
    analyzer_pre = PlanGraphAnalyzer(classifier=classifier_pre)
    plan_vec001a = ExecutionPlan(
        plan_id="vec-001a-meta",
        rationale="Meta-test: VEC-001a check_balance → execute_trade (pre-fix)",
        steps=[
            PlanStep(id="s1", action="check_balance", description="Read balance"),
            PlanStep(id="s2", action="execute_trade", description="Execute trade"),
        ],
    )
    result_vec001a = analyzer_pre.analyze(plan_vec001a, confidence=0.85)
    category_vec001a = classify_outcome(
        result_vec001a,
        registry=registry_dict_pre,
        benign_actions=frozenset({"check_balance"}),
        plan=plan_vec001a,
    )

    # VEC-001b setup (post-fix registry, check_balance registered as READ_ONLY)
    registry_path_post, registry_dict_post = registry_post_fix
    classifier_post = IrreversibilityClassifier(registry_path=registry_path_post)
    analyzer_post = PlanGraphAnalyzer(classifier=classifier_post)
    plan_vec001b = ExecutionPlan(
        plan_id="vec-001b-meta",
        rationale="Meta-test: VEC-001b check_balance → execute_trade (post-fix)",
        steps=[
            PlanStep(id="s1", action="check_balance", description="Read balance"),
            PlanStep(id="s2", action="execute_trade", description="Execute trade"),
        ],
    )
    result_vec001b = analyzer_post.analyze(plan_vec001b, confidence=0.85)
    category_vec001b = classify_outcome(
        result_vec001b,
        registry=registry_dict_post,
        benign_actions=frozenset(),
        plan=plan_vec001b,
    )

    # VEC-007 setup (unregistered_custom_action, not known-benign)
    plan_vec007 = ExecutionPlan(
        plan_id="vec-007-meta",
        rationale="Meta-test: VEC-007 unregistered action fails closed",
        steps=[
            PlanStep(
                id="s1",
                action="unregistered_custom_action",
                description="Unknown action",
            ),
        ],
    )
    result_vec007 = analyzer_post.analyze(plan_vec007, confidence=0.85)
    category_vec007 = classify_outcome(
        result_vec007,
        registry=registry_dict_post,
        benign_actions=frozenset(),
        plan=plan_vec007,
    )

    # Assert same verdict, different categories
    assert result_vec001a.verdict == result_vec001b.verdict == FTRAVerdict.HITL_REQUIRED
    assert category_vec001a != category_vec001b, (
        "VEC-001a and VEC-001b have the same verdict but must yield different "
        "categories — this is the critical discriminator"
    )
    assert category_vec001a == ScoringCategory.FAIL_CLOSED_NOISE
    assert category_vec001b == ScoringCategory.TRUE_PASS_REACHABILITY

    # Assert VEC-001a and VEC-007 differ despite similar critical_path
    assert result_vec001a.verdict == result_vec007.verdict == FTRAVerdict.HITL_REQUIRED
    assert result_vec001a.critical_path == result_vec007.critical_path == ["s1"]
    assert category_vec001a != category_vec007, (
        "VEC-001a (benign unregistered) and VEC-007 (unknown unregistered) must "
        "yield different categories"
    )
    assert category_vec001a == ScoringCategory.FAIL_CLOSED_NOISE
    assert category_vec007 == ScoringCategory.TRUE_PASS_FAIL_CLOSED


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
