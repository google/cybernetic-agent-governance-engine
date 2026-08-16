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
FTRA Pydantic models — TerminalClassification, ReachabilityResult, FTRAVerdict,
ParseResult, ParseFailureClass.

These are the canonical data contracts for the Forward-Looking Trajectory
Reachability Analyzer (CTRL_FTRA_001).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

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

    total_steps: int = Field(description="Total number of steps in the analyzed plan.")

    reachable_step_count: int = Field(
        description="Number of steps reachable from step[0] via DFS."
    )


# ---------------------------------------------------------------------------
# Parse Result Models (BUG-FTRA-SCHEMA-001, BUG-FTRA-JSON-001)
# ---------------------------------------------------------------------------


class ParseFailureClass(str, Enum):
    """Classification of parse failures for structured error handling.

    These failure classes enable differentiated handling:
    - SUCCESS: Parsing succeeded
    - JSON_DECODE_ERROR: Raw JSON syntax error (after sanitization)
    - SCHEMA_VALIDATION_ERROR: Valid JSON but fails ExecutionPlan validation
    - EMPTY_STEPS: Valid plan with no steps (not a failure, may be intentional)
    - TRUNCATED_PLAN: Plan appears cut off (incomplete JSON structure)
    - TOKENIZER_ARTIFACT: Input contains tokenizer artifacts that were sanitized
    """

    SUCCESS = "SUCCESS"
    """Parsing succeeded without errors."""

    JSON_DECODE_ERROR = "JSON_DECODE_ERROR"
    """Raw JSON could not be decoded even after sanitization.
    This is a hard failure — the input is not valid JSON."""

    SCHEMA_VALIDATION_ERROR = "SCHEMA_VALIDATION_ERROR"
    """JSON decoded successfully but failed ExecutionPlan Pydantic validation.
    May indicate missing required fields or type mismatches."""

    EMPTY_STEPS = "EMPTY_STEPS"
    """Plan parsed successfully but contains zero steps.
    This is a WARNING, not a blocking failure — an empty plan may be a valid
    choice when no action is required."""

    TRUNCATED_PLAN = "TRUNCATED_PLAN"
    """Plan appears truncated — JSON structure is incomplete.
    This is a WARNING indicating the LLM output may have been cut off."""

    TOKENIZER_ARTIFACT = "TOKENIZER_ARTIFACT"
    """Input contained tokenizer artifacts (markdown fences, incomplete tokens)
    that were sanitized before parsing. This is informational — the parse may
    have succeeded after sanitization."""


@dataclass
class ParseResult:
    """Result of parsing LLM output into an ExecutionPlan.

    This dataclass provides structured failure classification for defensive
    parsing (BUG-FTRA-SCHEMA-001, BUG-FTRA-JSON-001), enabling the FTRA node
    to distinguish between blocking errors and recoverable warnings.

    Attributes:
        plan: The parsed ExecutionPlan dict/list if successful, None on failure.
        failure_class: Classification of the parse outcome.
        raw_input: Original input string for debugging.
        sanitized_input: Input after sanitization (if different from raw).
        error_message: Human-readable error message on failure.
        sanitization_applied: Whether sanitization was performed.
    """

    plan: dict[str, Any] | list[Any] | None
    """Parsed plan if successful, None on parse failure."""

    failure_class: ParseFailureClass
    """Classification of the parse outcome."""

    raw_input: str
    """Original input for debugging and audit logging."""

    sanitized_input: str | None = None
    """Input after sanitization, if sanitization was applied."""

    error_message: str | None = None
    """Human-readable error message when failure_class != SUCCESS."""

    sanitization_applied: bool = False
    """True if any sanitization was performed on the input."""

    @property
    def is_success(self) -> bool:
        """Return True if parsing succeeded (plan is available)."""
        return self.failure_class == ParseFailureClass.SUCCESS

    @property
    def is_blocking_error(self) -> bool:
        """Return True if this failure should trigger BLOCKED/DEFER routing.

        JSON_DECODE_ERROR and SCHEMA_VALIDATION_ERROR are blocking errors.
        EMPTY_STEPS and TRUNCATED_PLAN are warnings that do not block.
        """
        return self.failure_class in (
            ParseFailureClass.JSON_DECODE_ERROR,
            ParseFailureClass.SCHEMA_VALIDATION_ERROR,
        )

    @property
    def is_warning(self) -> bool:
        """Return True if this is a warning rather than a blocking error.

        EMPTY_STEPS with high confidence → ALLOW (empty plan is valid choice).
        TRUNCATED_PLAN → DEFER for human review (not auto-BLOCKED).
        """
        return self.failure_class in (
            ParseFailureClass.EMPTY_STEPS,
            ParseFailureClass.TRUNCATED_PLAN,
            ParseFailureClass.TOKENIZER_ARTIFACT,
        )


# ---------------------------------------------------------------------------
# FTRA Boundary Check Result (Phase 3.3: Controller-Boundary Enforcement)
# ---------------------------------------------------------------------------


@dataclass
class FtraBoundaryResult:
    """Result of FTRA boundary check at the HTTP/controller boundary.

    This dataclass captures the outcome of an FTRA validation check performed
    at the controller boundary (e.g., validate_action() or ext_authz), rather
    than within the LangGraph flow where ftra_node operates.

    Risk R-03 identifies that ftra_node only fires if the host agent wires it
    into its own LangGraph. Direct HTTP access to /validate-action or ext_authz
    bypasses it entirely. This boundary check closes that gap.

    The boundary check uses the same IrreversibilityClassifier and
    terminal_registry.json as the in-graph ftra_node, ensuring consistent
    classification semantics.

    Attributes:
        requires_hitl: True if the action requires Human-In-The-Loop review
                       (IRREVERSIBLE_TERMINAL classification).
        irreversibility_score: Numeric score representing irreversibility
                               (1.0 for IRREVERSIBLE_TERMINAL, 0.5 for
                               REVERSIBLE, 0.0 for READ_ONLY).
        classification: String representation of the classification.
        terminal_match: The matched terminal pattern from the registry,
                        or None if action is not in registry (fail-closed).
        violations: List of violation strings to be added to the governance
                    pipeline violations list.
        bypassed_ftra_node: True if this boundary check detected an action
                            that would have bypassed the in-graph ftra_node.
    """

    requires_hitl: bool
    """True if the action is classified as IRREVERSIBLE_TERMINAL and requires
    Human-In-The-Loop review before execution."""

    irreversibility_score: float
    """Numeric score [0.0, 1.0] representing irreversibility:
       - 1.0: IRREVERSIBLE_TERMINAL (highest risk)
       - 0.5: REVERSIBLE (can be undone)
       - 0.0: READ_ONLY (no state change)
    """

    classification: str
    """String representation of TerminalClassification (IRREVERSIBLE_TERMINAL,
    REVERSIBLE, READ_ONLY)."""

    terminal_match: str | None
    """The action name that matched in terminal_registry.json, or None if the
    action was not found in the registry (fail-closed to IRREVERSIBLE_TERMINAL)."""

    violations: list[str] = field(default_factory=list)
    """List of violation strings to be added to the governance pipeline's
    violations list. Non-empty when requires_hitl=True."""

    bypassed_ftra_node: bool = False
    """True if this boundary check detected an action that would have bypassed
    the in-graph ftra_node. Used for WARN-level logging and telemetry."""

    @property
    def is_safe(self) -> bool:
        """Return True if the action is safe to proceed without HITL review.

        An action is safe if it does not require human review, meaning it is
        classified as READ_ONLY or REVERSIBLE.
        """
        return not self.requires_hitl

    @classmethod
    def from_classification(
        cls,
        classification: TerminalClassification,
        action_name: str,
        *,
        in_registry: bool = True,
        bypassed_ftra_node: bool = False,
    ) -> "FtraBoundaryResult":
        """Factory method to create FtraBoundaryResult from a TerminalClassification.

        Args:
            classification: The TerminalClassification from IrreversibilityClassifier.
            action_name: The action name being classified.
            in_registry: Whether the action was found in the terminal registry.
            bypassed_ftra_node: Whether this check caught a bypass of ftra_node.

        Returns:
            FtraBoundaryResult with appropriate field values.
        """
        # Map classification to irreversibility score
        score_map = {
            TerminalClassification.IRREVERSIBLE_TERMINAL: 1.0,
            TerminalClassification.REVERSIBLE: 0.5,
            TerminalClassification.READ_ONLY: 0.0,
        }
        score = score_map.get(classification, 1.0)  # Fail-closed: unknown = 1.0

        requires_hitl = classification == TerminalClassification.IRREVERSIBLE_TERMINAL
        violations: list[str] = []

        if requires_hitl:
            if in_registry:
                violations.append(
                    f"FTRA Boundary Check: Action '{action_name}' is classified as "
                    f"{classification.value} in terminal_registry.json. "
                    "Human-in-the-loop review required before execution."
                )
            else:
                violations.append(
                    f"FTRA Boundary Check: Action '{action_name}' not found in "
                    "terminal_registry.json — failing closed to IRREVERSIBLE_TERMINAL. "
                    "Human-in-the-loop review required before execution."
                )

        return cls(
            requires_hitl=requires_hitl,
            irreversibility_score=score,
            classification=classification.value,
            terminal_match=action_name if in_registry else None,
            violations=violations,
            bypassed_ftra_node=bypassed_ftra_node,
        )
