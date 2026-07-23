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
FTRA Pydantic models — TerminalClassification, ReachabilityResult, FTRAVerdict.

These are the canonical data contracts for the Forward-Looking Trajectory
Reachability Analyzer (CTRL_FTRA_001).
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class TerminalClassification(str, Enum):
    """Classification of an action's reversibility.

    Fail-closed: IrreversibilityClassifier returns IRREVERSIBLE_TERMINAL for
    any action not present in the compiled terminal registry.
    """

    IRREVERSIBLE_TERMINAL = "IRREVERSIBLE_TERMINAL"
    """Action commits an external, unalterable state change (e.g. execute_trade,
    write_db).  Any plan that can reach this action inherits worst-case
    classification from T₀."""

    REVERSIBLE = "REVERSIBLE"
    """Action modifies state that can be undone via a compensating action
    (e.g. a database write with a known rollback path)."""

    READ_ONLY = "READ_ONLY"
    """Action reads external state without modifying it (e.g. market_analysis,
    check_balance, prompt_injection_check)."""


class FTRAVerdict(str, Enum):
    """Commencement-time verdict for an ExecutionPlan.

    Routing semantics (enforced by create_ftra_node):
      CLEAR          → proceed to safety_check OPA gate
      HITL_REQUIRED  → park in DeferQueue db=1; resume after human clearance
      BLOCKED        → route to explainer; plan cannot proceed
    """

    CLEAR = "CLEAR"
    """No IRREVERSIBLE_TERMINAL node is reachable from step[0].  The plan may
    proceed to the per-action OPA safety gate."""

    HITL_REQUIRED = "HITL_REQUIRED"
    """An IRREVERSIBLE_TERMINAL node is reachable AND the Evaluator confidence
    score is >= FRIA_ZONE_DEFER (0.70).  The thread is parked in DeferQueue
    db=1 pending synchronous human-in-the-loop clearance."""

    BLOCKED = "BLOCKED"
    """An IRREVERSIBLE_TERMINAL node is reachable AND the Evaluator confidence
    score is < FRIA_ZONE_DEFER (0.70).  The plan is blocked outright — the
    confidence is too low to even warrant human review."""


class ReachabilityResult(BaseModel):
    """Output of PlanGraphAnalyzer.analyze().

    Captures the full reachability analysis result for a single ExecutionPlan,
    including the worst-case classification, the set of reachable terminal
    step IDs, the critical path to the first terminal, and the final verdict.
    """

    plan_id: str = Field(description="ExecutionPlan.plan_id being analyzed.")

    worst_case_classification: TerminalClassification = Field(
        description=(
            "Most restrictive classification across all reachable nodes. "
            "IRREVERSIBLE_TERMINAL if any reachable step has that classification."
        )
    )

    reachable_terminals: list[str] = Field(
        default_factory=list,
        description="Step IDs of all reachable IRREVERSIBLE_TERMINAL nodes.",
    )

    critical_path: list[str] = Field(
        default_factory=list,
        description=(
            "Ordered list of step IDs on the shortest path from step[0] to "
            "the first reachable IRREVERSIBLE_TERMINAL node. "
            "Empty when worst_case_classification != IRREVERSIBLE_TERMINAL."
        ),
    )

    verdict: FTRAVerdict = Field(
        description="Commencement-time routing verdict for this plan."
    )

    confidence_at_analysis: float = Field(
        description=(
            "Evaluator confidence score at the time of FTRA analysis. "
            "Used to determine HITL_REQUIRED vs BLOCKED when an irreversible "
            "terminal is reachable."
        )
    )

    total_steps: int = Field(
        description="Total number of steps in the analyzed plan."
    )

    reachable_step_count: int = Field(
        description="Number of steps reachable from step[0] via DFS."
    )
