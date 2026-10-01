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
from enum import Enum, StrEnum
from typing import Any
from src.gateway.governance.contracts import Violation, ViolationKind

from pydantic import BaseModel, Field


class TerminalClassification(str, Enum):
    """Classification of an action's reversibility.

    Fail-closed: IrreversibilityClassifier returns IRREVERSIBLE_TERMINAL for
    any action not present in the compiled terminal registry.
    """

    IRREVERSIBLE_TERMINAL = "IRREVERSIBLE_TERMINAL"
    """Action commits an external, unalterable state change (e.g. execute_action,
    write_db).  Any plan that can reach this action inherits worst-case
    classification from T₀."""

    REVERSIBLE = "REVERSIBLE"
    """Action modifies state that can be undone via a compensating action
    (e.g. a database write with a known rollback path)."""

    EXTERNALLY_REVERSIBLE = "EXTERNALLY_REVERSIBLE"
    """Action is reversible but requires an external settlement window,
    counterparty approval, or human-in-the-loop intervention."""

    READ_ONLY = "READ_ONLY"
    """Action reads external state without modifying it (e.g. market_analysis,
    check_balance, prompt_injection_check)."""


# Shared exhaustive severity mapping for FTRA classification ordering.
# Used by PlanGraphAnalyzer and STPA compiler to ensure consistent restrictiveness
# ordering across the codebase. A guard test asserts this covers every enum member.
CLASSIFICATION_SEVERITY: dict[TerminalClassification, int] = {
    TerminalClassification.READ_ONLY: 0,
    TerminalClassification.REVERSIBLE: 1,
    TerminalClassification.EXTERNALLY_REVERSIBLE: 2,
    TerminalClassification.IRREVERSIBLE_TERMINAL: 3,
}


class RegistryState(StrEnum):
    """Where a classification came from.

    Only ``REGISTERED`` is a classification the domain authored. Every other
    state is a fail-closed fallback to IRREVERSIBLE_TERMINAL, and the FTRA
    violation code names which fallback fired so a reviewer can tell
    "the registry says this is irreversible" from "the registry is silent".
    """

    REGISTERED = "registered"
    """The action has a valid entry in the active domain's registry."""

    UNREGISTERED = "unregistered"
    """The registry loaded but has no entry for the action."""

    INVALID_ENTRY = "invalid_entry"
    """The registry has an entry whose classification string is unrecognised."""

    UNAVAILABLE = "unavailable"
    """The registry could not be loaded (missing, malformed, digest mismatch)."""


#: FTRA violation code per (registry state, classification) that needs a human.
FTRA_REGISTERED_IRREVERSIBLE = "FTRA_REGISTERED_IRREVERSIBLE"
FTRA_REGISTERED_EXTERNALLY_REVERSIBLE = "FTRA_REGISTERED_EXTERNALLY_REVERSIBLE"
FTRA_UNREGISTERED_ACTION = "FTRA_UNREGISTERED_ACTION"
FTRA_REGISTRY_ENTRY_INVALID = "FTRA_REGISTRY_ENTRY_INVALID"
FTRA_REGISTRY_UNAVAILABLE = "FTRA_REGISTRY_UNAVAILABLE"


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
    score is >= confidence.defer_floor (0.70).  The thread is parked in DeferQueue
    db=1 pending synchronous human-in-the-loop clearance."""

    BLOCKED = "BLOCKED"
    """An IRREVERSIBLE_TERMINAL node is reachable AND the Evaluator confidence
    score is < confidence.defer_floor (0.70).  The plan is blocked outright — the
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
        description=(
            "Step IDs of all reachable terminal nodes (IRREVERSIBLE_TERMINAL or "
            "EXTERNALLY_REVERSIBLE). Terminal actions remain on the critical path "
            "regardless of how their resolution is brokered (internal rollback vs "
            "external settlement window)."
        ),
    )

    critical_path: list[str] = Field(
        default_factory=list,
        description=(
            "Ordered list of step IDs on the shortest path from step[0] to "
            "the first reachable terminal node (IRREVERSIBLE_TERMINAL or "
            "EXTERNALLY_REVERSIBLE). Empty when worst_case_classification is "
            "READ_ONLY or REVERSIBLE."
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

    auto_cleared_terminals: list[str] = Field(
        default_factory=list,
        description=(
            "Step IDs of reachable registered terminals that cleared inside "
            "their autonomous envelope (conditional FTRA). They stay in "
            "reachable_terminals but do not drive the verdict."
        ),
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
       - 0.8: EXTERNALLY_REVERSIBLE (requires external action/time window)
       - 0.5: REVERSIBLE (can be undone)
       - 0.0: READ_ONLY (no state change)
    """

    classification: str
    """String representation of TerminalClassification (IRREVERSIBLE_TERMINAL,
    EXTERNALLY_REVERSIBLE, REVERSIBLE, READ_ONLY)."""

    terminal_match: str | None
    """The action name that matched in terminal_registry.json, or None if the
    action was not found in the registry (fail-closed to IRREVERSIBLE_TERMINAL)."""

    violations: list[Violation] = field(default_factory=list)
    """List of violation strings to be added to the governance pipeline's
    violations list. Non-empty when requires_hitl=True."""

    bypassed_ftra_node: bool = False
    """True if this boundary check detected an action that would have bypassed
    the in-graph ftra_node. Used for WARN-level logging and telemetry."""

    registry_state: RegistryState | None = None
    """Provenance of ``classification`` (see :class:`RegistryState`)."""

    auto_cleared: bool = False
    """True if a registered terminal cleared inside its autonomous envelope
    (conditional FTRA); ``requires_hitl`` is then False."""

    clear_reason: str | None = None
    """Why the terminal cleared autonomously; ``None`` unless ``auto_cleared``."""

    @property
    def is_safe(self) -> bool:
        """Return True if the action is safe to proceed without HITL review.

        An action is safe if it does not require human review: it is
        classified READ_ONLY or REVERSIBLE, or it is a registered terminal
        inside its autonomous envelope.
        """
        return not self.requires_hitl

    @classmethod
    def from_classification(
        cls,
        classification: TerminalClassification,
        action_name: str,
        *,
        registry_state: RegistryState,
        bypassed_ftra_node: bool = False,
        clear_reason: str | None = None,
    ) -> FtraBoundaryResult:
        """Build the boundary result for a classification and its provenance.

        Violation per provenance:

        ==========================  =========================================  ======
        registry_state              code                                       kind
        ==========================  =========================================  ======
        REGISTERED, irreversible    ``FTRA_REGISTERED_IRREVERSIBLE``           HITL
        REGISTERED, ext-reversible  ``FTRA_REGISTERED_EXTERNALLY_REVERSIBLE``  HITL
        UNREGISTERED                ``FTRA_UNREGISTERED_ACTION``               HITL
        INVALID_ENTRY               ``FTRA_REGISTRY_ENTRY_INVALID``            HITL
        UNAVAILABLE                 ``FTRA_REGISTRY_UNAVAILABLE``              HARD
        ==========================  =========================================  ======

        A REGISTERED terminal with a ``clear_reason`` (computed by
        ``autonomy.conditional_clear_reason``) is auto-cleared: no violation.

        Raises:
            ValueError: ``clear_reason`` given for anything but a REGISTERED
                terminal. Only the domain's own classification can be cleared
                autonomously (UNREGISTERED_NEVER_AUTO_CLEARS).
        """
        terminal = classification in (
            TerminalClassification.IRREVERSIBLE_TERMINAL,
            TerminalClassification.EXTERNALLY_REVERSIBLE,
        )
        if clear_reason is not None and not (
            registry_state is RegistryState.REGISTERED and terminal
        ):
            raise ValueError(
                f"only a registered terminal can clear autonomously; "
                f"{action_name!r} is {registry_state.value}/{classification.value}"
            )

        score_map = {
            TerminalClassification.IRREVERSIBLE_TERMINAL: 1.0,
            TerminalClassification.EXTERNALLY_REVERSIBLE: 0.8,
            TerminalClassification.REVERSIBLE: 0.5,
            TerminalClassification.READ_ONLY: 0.0,
        }
        score = score_map.get(classification, 1.0)  # Fail-closed: unknown = 1.0
        auto_cleared = clear_reason is not None
        violation = None if auto_cleared else _provenance_violation(
            classification, action_name, registry_state
        )

        return cls(
            requires_hitl=violation is not None,
            irreversibility_score=score,
            classification=classification.value,
            terminal_match=action_name if registry_state is RegistryState.REGISTERED else None,
            violations=[violation] if violation is not None else [],
            bypassed_ftra_node=bypassed_ftra_node and not auto_cleared,
            registry_state=registry_state,
            auto_cleared=auto_cleared,
            clear_reason=clear_reason,
        )


def _provenance_violation(
    classification: TerminalClassification,
    action_name: str,
    registry_state: RegistryState,
) -> Violation | None:
    """The FTRA violation for an uncleared classification, or None if it needs no human."""
    if registry_state is RegistryState.UNAVAILABLE:
        return Violation(
            tier="ftra",
            code=FTRA_REGISTRY_UNAVAILABLE,
            message=(
                f"FTRA Boundary Check: the terminal registry could not be loaded; "
                f"refusing '{action_name}' (fail-closed)."
            ),
            kind=ViolationKind.HARD,
        )
    if registry_state is RegistryState.UNREGISTERED:
        return Violation(
            tier="ftra",
            code=FTRA_UNREGISTERED_ACTION,
            message=(
                f"FTRA Boundary Check: Action '{action_name}' is not in the domain's "
                "terminal registry — failing closed to IRREVERSIBLE_TERMINAL. "
                "Human-in-the-loop review required before execution."
            ),
            kind=ViolationKind.HITL,
        )
    if registry_state is RegistryState.INVALID_ENTRY:
        return Violation(
            tier="ftra",
            code=FTRA_REGISTRY_ENTRY_INVALID,
            message=(
                f"FTRA Boundary Check: the registry entry for '{action_name}' has an "
                "unrecognised classification — failing closed to IRREVERSIBLE_TERMINAL. "
                "Human-in-the-loop review required before execution."
            ),
            kind=ViolationKind.HITL,
        )
    code = {
        TerminalClassification.IRREVERSIBLE_TERMINAL: FTRA_REGISTERED_IRREVERSIBLE,
        TerminalClassification.EXTERNALLY_REVERSIBLE: FTRA_REGISTERED_EXTERNALLY_REVERSIBLE,
    }.get(classification)
    if code is None:
        return None  # READ_ONLY / REVERSIBLE: no human needed
    return Violation(
        tier="ftra",
        code=code,
        message=(
            f"FTRA Boundary Check: Action '{action_name}' is registered as "
            f"{classification.value} and is outside its autonomous envelope. "
            "Human-in-the-loop review required before execution."
        ),
        kind=ViolationKind.HITL,
    )


class PlanStep(BaseModel):
    id: str = Field(default="", description="Unique identifier for the step")
    action: str = Field(
        description="Action to perform (e.g., execute_action, check_state)"
    )
    description: str = Field(description="Description of what this step does")
    parameters: dict[str, Any] = Field(
        default_factory=dict, description="Parameters for the action"
    )


class ExecutionPlan(BaseModel):
    plan_id: str = Field(default="", description="Unique identifier for the plan")
    strategy_name: str = Field(
        default="",
        description="Name of the strategy (e.g., 'Conservative Dividend Growth')",
    )
    rationale: str = Field(
        description="Detailed explanation of why this strategy fits the user profile"
    )
    risk_factors: list[str] = Field(
        default_factory=list, description="List of identified risk factors"
    )
    steps: list[PlanStep] = Field(description="Ordered list of execution steps")
    user_risk_attitude: str | None = Field(
        default=None, description="Derived or stated risk attitude"
    )
    confidence: float = Field(
        default=0.0, description="Agent's confidence in this plan [0.0, 1.0]"
    )
    violations: list[Violation] = Field(
        default_factory=list, description="Policy violations detected"
    )
