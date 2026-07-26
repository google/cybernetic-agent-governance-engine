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
PlanGraphAnalyzer — NetworkX-based reachability analysis for ExecutionPlan.

Phase 1 topology
----------------
Steps are treated as a linear chain: step[i] → step[i+1].  This is the
conservative baseline that matches the current ExecutionPlan schema (no
``depends_on`` field).

Phase 2 forward-compatibility
------------------------------
If a ``PlanStep`` carries a ``depends_on: list[str]`` field (step IDs), the
analyzer will use those edges instead of the linear chain.  The field is
ignored silently when absent, so Phase 1 plans continue to work unchanged.

Fail-closed contract
--------------------
Any exception during graph construction or DFS traversal causes the analyzer
to return a ``ReachabilityResult`` with ``worst_case_classification =
IRREVERSIBLE_TERMINAL`` and ``verdict = HITL_REQUIRED`` (or ``BLOCKED`` if
confidence is below threshold).  This mirrors the OPA ``default stpa_allow =
false`` pattern.

Usage::

    from src.governed_financial_advisor.agents.execution_analyst.agent import ExecutionPlan
    from src.gateway.governance.ftra.graph_analyzer import PlanGraphAnalyzer

    analyzer = PlanGraphAnalyzer()
    result = analyzer.analyze(plan, confidence=0.85)
    # result.verdict → FTRAVerdict.HITL_REQUIRED
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from src.gateway.governance.ftra.classifier import IrreversibilityClassifier
from src.gateway.governance.ftra.models import (
    FTRAVerdict,
    ReachabilityResult,
    TerminalClassification,
)

if TYPE_CHECKING:
    from src.governed_financial_advisor.agents.execution_analyst.agent import (
        ExecutionPlan,
        PlanStep,
    )

logger = logging.getLogger("Gateway.Governance.FTRA.GraphAnalyzer")

# ---------------------------------------------------------------------------
# Threshold constants
# ---------------------------------------------------------------------------

#: Evaluator confidence score below which a plan with reachable
#: IRREVERSIBLE_TERMINAL nodes is BLOCKED outright rather than HITL_REQUIRED.
FRIA_ZONE_DEFER: float = 0.70

# ---------------------------------------------------------------------------
# PlanGraphAnalyzer
# ---------------------------------------------------------------------------


class PlanGraphAnalyzer:
    """Builds a directed graph from an ExecutionPlan and runs DFS reachability.

    Args:
        classifier: Optional :class:`IrreversibilityClassifier` instance.
                    Defaults to a new instance using the default registry path.
    """

    def __init__(self, classifier: IrreversibilityClassifier | None = None) -> None:
        self._classifier = classifier or IrreversibilityClassifier()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, plan: ExecutionPlan, confidence: float) -> ReachabilityResult:
        """Run commencement-time reachability analysis on *plan*.

        Builds a directed graph from ``plan.steps``, runs DFS from ``step[0]``,
        classifies each reachable node via :class:`IrreversibilityClassifier`,
        and returns a :class:`ReachabilityResult` with the worst-case
        classification and routing verdict.

        Args:
            plan:       The :class:`ExecutionPlan` to analyze.
            confidence: Evaluator confidence score at analysis time.
                        Used to determine ``HITL_REQUIRED`` vs ``BLOCKED``
                        when an irreversible terminal is reachable.

        Returns:
            :class:`ReachabilityResult` — never raises.
        """
        try:
            return self._analyze_internal(plan, confidence)
        except Exception as exc:
            logger.error(
                "FTRA graph analysis failed for plan '%s' (%s) — "
                "failing closed (IRREVERSIBLE_TERMINAL).",
                getattr(plan, "plan_id", "<unknown>"),
                exc,
            )
            verdict = (
                FTRAVerdict.HITL_REQUIRED
                if confidence >= FRIA_ZONE_DEFER
                else FTRAVerdict.BLOCKED
            )
            return ReachabilityResult(
                plan_id=getattr(plan, "plan_id", "<unknown>"),
                worst_case_classification=TerminalClassification.IRREVERSIBLE_TERMINAL,
                reachable_terminals=[],
                critical_path=[],
                verdict=verdict,
                confidence_at_analysis=confidence,
                total_steps=len(getattr(plan, "steps", [])),
                reachable_step_count=0,
            )

    # ------------------------------------------------------------------
    # Internal implementation
    # ------------------------------------------------------------------

    def _analyze_internal(
        self, plan: ExecutionPlan, confidence: float
    ) -> ReachabilityResult:
        """Core analysis — may raise; caller wraps in try/except."""
        import networkx as nx  # lazy import — networkx is an optional dep

        steps: list[PlanStep] = plan.steps
        plan_id: str = plan.plan_id

        if not steps:
            # Empty plan — trivially CLEAR (nothing irreversible can be reached)
            return ReachabilityResult(
                plan_id=plan_id,
                worst_case_classification=TerminalClassification.READ_ONLY,
                reachable_terminals=[],
                critical_path=[],
                verdict=FTRAVerdict.CLEAR,
                confidence_at_analysis=confidence,
                total_steps=0,
                reachable_step_count=0,
            )

        # ----------------------------------------------------------------
        # Build directed graph
        # ----------------------------------------------------------------
        G: nx.DiGraph = nx.DiGraph()

        # Add all step nodes with their action attribute
        for step in steps:
            G.add_node(step.id, action=step.action)

        # Determine edges: Phase 2 depends_on or Phase 1 linear chain
        has_depends_on = any(
            hasattr(step, "depends_on") and step.depends_on for step in steps
        )

        if has_depends_on:
            # Phase 2: explicit dependency edges
            for step in steps:
                deps: list[str] = getattr(step, "depends_on", None) or []
                for dep_id in deps:
                    if G.has_node(dep_id):
                        G.add_edge(dep_id, step.id)
                    else:
                        logger.warning(
                            "FTRA: step '%s' depends_on unknown step '%s' — edge skipped.",
                            step.id,
                            dep_id,
                        )
        else:
            # Phase 1: linear chain step[i] → step[i+1]
            for i in range(len(steps) - 1):
                G.add_edge(steps[i].id, steps[i + 1].id)

        # ----------------------------------------------------------------
        # DFS reachability from step[0]
        # ----------------------------------------------------------------
        source_id: str = steps[0].id
        reachable_ids: list[str] = list(nx.dfs_preorder_nodes(G, source=source_id))

        # ----------------------------------------------------------------
        # Classify each reachable node
        # ----------------------------------------------------------------
        reachable_terminals: list[str] = []
        worst_case = TerminalClassification.READ_ONLY

        _severity: dict[TerminalClassification, int] = {
            TerminalClassification.READ_ONLY: 0,
            TerminalClassification.REVERSIBLE: 1,
            TerminalClassification.IRREVERSIBLE_TERMINAL: 2,
        }

        for step_id in reachable_ids:
            action: str = G.nodes[step_id].get("action", step_id)
            classification = self._classifier.classify(action)

            if _severity[classification] > _severity[worst_case]:
                worst_case = classification

            if classification == TerminalClassification.IRREVERSIBLE_TERMINAL:
                reachable_terminals.append(step_id)

        # ----------------------------------------------------------------
        # Critical path to first IRREVERSIBLE_TERMINAL node
        # ----------------------------------------------------------------
        critical_path: list[str] = []
        if reachable_terminals:
            first_terminal = reachable_terminals[0]
            try:
                critical_path = nx.shortest_path(
                    G, source=source_id, target=first_terminal
                )
            except nx.NetworkXNoPath:
                # Should not happen since first_terminal is in reachable_ids,
                # but guard defensively.
                critical_path = [first_terminal]
            except Exception as exc:
                logger.warning(
                    "FTRA: shortest_path failed for plan '%s' (%s) — "
                    "critical_path will be empty.",
                    plan_id,
                    exc,
                )

        # ----------------------------------------------------------------
        # Determine verdict
        # ----------------------------------------------------------------
        if worst_case == TerminalClassification.IRREVERSIBLE_TERMINAL:
            if confidence >= FRIA_ZONE_DEFER:
                verdict = FTRAVerdict.HITL_REQUIRED
            else:
                verdict = FTRAVerdict.BLOCKED
        else:
            verdict = FTRAVerdict.CLEAR

        logger.info(
            "FTRA analysis complete: plan='%s' steps=%d reachable=%d "
            "terminals=%d worst_case=%s confidence=%.3f verdict=%s",
            plan_id,
            len(steps),
            len(reachable_ids),
            len(reachable_terminals),
            worst_case.value,
            confidence,
            verdict.value,
        )

        return ReachabilityResult(
            plan_id=plan_id,
            worst_case_classification=worst_case,
            reachable_terminals=reachable_terminals,
            critical_path=critical_path,
            verdict=verdict,
            confidence_at_analysis=confidence,
            total_steps=len(steps),
            reachable_step_count=len(reachable_ids),
        )

    # ------------------------------------------------------------------
    # Diagnostic helpers
    # ------------------------------------------------------------------

    def explain(self, plan: ExecutionPlan, confidence: float) -> dict[str, Any]:
        """Return a human-readable explanation dict for debugging / audit logs.

        Calls :meth:`analyze` and augments the result with per-step
        classification details.  Not called on the hot path.
        """
        result = self.analyze(plan, confidence)
        step_details: list[dict[str, str]] = []
        for step in plan.steps:
            classification = self._classifier.classify(step.action)
            step_details.append(
                {
                    "id": step.id,
                    "action": step.action,
                    "classification": classification.value,
                }
            )
        return {
            "plan_id": result.plan_id,
            "verdict": result.verdict.value,
            "worst_case_classification": result.worst_case_classification.value,
            "confidence_at_analysis": result.confidence_at_analysis,
            "reachable_terminals": result.reachable_terminals,
            "critical_path": result.critical_path,
            "total_steps": result.total_steps,
            "reachable_step_count": result.reachable_step_count,
            "step_details": step_details,
        }
