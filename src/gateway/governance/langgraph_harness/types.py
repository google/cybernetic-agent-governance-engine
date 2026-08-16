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
Type definitions and configuration dataclasses for the LangGraph governance harness.

These types decouple the governance infrastructure (OTel, ISO stamps, fail-closed
handling) from domain-specific agent state schemas by using extractor callables
that the consuming agent provides.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeAlias

# ---------------------------------------------------------------------------
# Generic type aliases
# ---------------------------------------------------------------------------

#: Any dict-like LangGraph state.  Factory-generated nodes accept and return
#: ``StateDict`` so they are agnostic to the concrete ``AgentState`` TypedDict.
StateDict: TypeAlias = dict[str, Any]

#: Callable that extracts an OPA-compatible payload dict from agent state.
PayloadExtractor: TypeAlias = Callable[[StateDict], dict[str, Any]]

#: Callable that extracts a user/AI message string from agent state.
MessageExtractor: TypeAlias = Callable[[StateDict], str]

#: Callable that extracts a thread/trace identifier for compliance scoring.
ThreadIdExtractor: TypeAlias = Callable[[StateDict], str]

#: Callable that extracts an execution plan (dict/list/None) from agent state.
PlanExtractor: TypeAlias = Callable[[StateDict], dict[str, Any] | list[Any] | None]

#: Callable that extracts a confidence score (float) from agent state.
ConfidenceExtractor: TypeAlias = Callable[[StateDict], float]


# ---------------------------------------------------------------------------
# OPA safety node configuration
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class OpaNodeConfig:
    """Configuration for :func:`create_opa_safety_node`.

    Args:
        policy_action_name: The OPA action name passed to
            ``symbolic_governor.govern(action, payload)``, e.g.
            ``"execute_trade"`` or ``"approve_request"``.
        payload_extractor: Callable that receives the full agent state dict
            and returns a flat dict of fields for the OPA policy input.
        plan_state_key: State key that holds the plan/action to validate.
            When this key is ``None`` or absent the node returns ``SKIPPED``.
        status_state_key: State key the node writes its decision into
            (``APPROVED`` / ``BLOCKED`` / ``ESCALATED`` / ``SKIPPED``).
        error_state_key: State key the node writes error messages into
            when the decision is ``BLOCKED`` or ``ESCALATED``.
        iso_control: ISO 42001 Annex A control identifier stamped on the
            OTel span, e.g. ``"A.10.1"``.
        iso_tier: ISO enforcement tier (1 = heuristic, 2 = semantic, 3 = OPA).
        thread_id_extractor: Optional callable to extract a thread/trace id
            for compliance scoring.  Defaults to ``state.get("thread_id", "")``.
        span_attributes: Extra OTel span attributes to set on every invocation.
            Keys and values must be strings.
    """

    policy_action_name: str
    payload_extractor: PayloadExtractor
    plan_state_key: str = "execution_plan_output"
    status_state_key: str = "safety_status"
    error_state_key: str = "error"
    iso_control: str = "A.10.1"
    iso_tier: int = 2
    thread_id_extractor: ThreadIdExtractor | None = None
    span_attributes: dict[str, str] = dataclasses.field(default_factory=dict)


# ---------------------------------------------------------------------------
# NeMo guardrail node configuration
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class NemoNodeConfig:
    """Configuration for :func:`create_nemo_guardrail_node` and
    :func:`create_nemo_output_rail_node`.

    Args:
        message_extractor: Callable that extracts the relevant user or AI
            message from state.  For input rails this should return the last
            user message; for output rails the last AI message.  When ``None``
            the factory uses a built-in default extractor.
        blocked_state_key: State key set to ``True`` when the input rail
            blocks.
        reason_state_key: State key set to the block reason string.
        output_rail_applied_key: State key set to ``True`` after the output
            rail executes (success or failure).
        output_blocked_sentinel: Sentinel string returned when the output
            rail itself errors (fail-closed).  Must NOT contain any
            agent-generated content.
        pass_through_state: If ``True``, the generated node returns the
            entire input state merged with its updates (``{**state, ...}``).
            If ``False``, it returns only the update dict.  Set to ``True``
            for input rail nodes that need state pass-through for downstream
            conditional edges.
    """

    message_extractor: MessageExtractor | None = None
    blocked_state_key: str = "guardrail_blocked"
    reason_state_key: str = "guardrail_reason"
    output_rail_applied_key: str = "output_rail_applied"
    output_blocked_sentinel: str = "[OUTPUT BLOCKED: guardrail error]"
    pass_through_state: bool = True


# ---------------------------------------------------------------------------
# FTRA node configuration (Tier 0.5 Forward-Looking Trajectory Reachability)
# ---------------------------------------------------------------------------


def default_plan_extractor(state: StateDict) -> dict[str, Any] | list[Any] | None:
    """Default extractor for GFA AgentState schema.

    Attempts ``state["execution_plan_output"]`` first (GFA's canonical field),
    then ``state["plan"]`` as a fallback for simpler integrations.

    Returns:
        The raw plan dict/list, or ``None`` if neither key is present.
    """
    return state.get("execution_plan_output") or state.get("plan")


def default_confidence_extractor(state: StateDict) -> float:
    """Default extractor returning evaluation confidence or default 0.5.

    Reads ``state["evaluation_result"]["confidence"]`` (GFA's canonical path).
    Falls back to 0.5 (neutral confidence) if unavailable.

    Returns:
        Confidence score in [0.0, 1.0].
    """
    eval_result = state.get("evaluation_result", {})
    if isinstance(eval_result, dict):
        return float(eval_result.get("confidence", 0.5))
    return 0.5


@dataclasses.dataclass(frozen=True)
class FtraNodeConfig:
    """Configuration for :func:`create_ftra_node`.

    This dataclass decouples the FTRA Tier 0.5 gate from the GFA ``AgentState``
    schema by allowing consuming agents to provide custom extractor callables.
    Mitigates R-07 (Schema/Version Coupling) from the risk matrix.

    Args:
        plan_extractor: Callable that extracts the execution plan (dict/list)
            from agent state.  When ``None``, uses :func:`default_plan_extractor`.
        confidence_extractor: Callable that extracts the evaluator confidence
            score (float) from agent state.  When ``None``, uses
            :func:`default_confidence_extractor`.
        plan_key: State key fallback for plan extraction if ``plan_extractor``
            is not provided.  Defaults to ``"execution_plan_output"``.
        confidence_key: State key fallback for confidence extraction.  Used
            when ``confidence_extractor`` is not provided and the default
            extractor cannot find ``evaluation_result.confidence``.
        evaluation_result_key: State key where evaluation result dict is
            stored.  Used by the default confidence extractor.
        registry_path: Path to the terminal registry JSON file.  Defaults to
            ``config/ftra/terminal_registry.json``.
        validate_plan_schema: Whether to validate the extracted plan against
            a JSON Schema before analysis.  Defaults to ``True``.
        plan_schema: Optional JSON Schema dict for plan validation.  When
            ``None`` and ``validate_plan_schema`` is ``True``, the factory
            uses the built-in ExecutionPlan Pydantic validation.
        span_attributes: Extra OTel span attributes to set on every analysis.
            Keys and values must be strings.
    """

    # Extractor functions — signature: (state: dict) -> Any
    plan_extractor: PlanExtractor | None = None
    confidence_extractor: ConfidenceExtractor | None = None

    # State key overrides (fallbacks if extractors not provided)
    plan_key: str = "execution_plan_output"
    confidence_key: str = "confidence_score"
    evaluation_result_key: str = "evaluation_result"

    # Registry path override
    registry_path: str | Path = "config/ftra/terminal_registry.json"

    # Optional validation
    validate_plan_schema: bool = True
    plan_schema: dict[str, Any] | None = None  # JSON Schema for plan validation

    # OTel span attributes
    span_attributes: dict[str, str] = dataclasses.field(default_factory=dict)

    def get_plan_extractor(self) -> PlanExtractor:
        """Return the plan extractor, using default if not configured."""
        if self.plan_extractor is not None:
            return self.plan_extractor
        # Build extractor using configured plan_key
        plan_key = self.plan_key

        def _key_based_extractor(state: StateDict) -> dict[str, Any] | list[Any] | None:
            return state.get(plan_key) or state.get("plan")

        return _key_based_extractor

    def get_confidence_extractor(self) -> ConfidenceExtractor:
        """Return the confidence extractor, using default if not configured."""
        if self.confidence_extractor is not None:
            return self.confidence_extractor
        # Build extractor using configured keys
        eval_key = self.evaluation_result_key
        conf_key = self.confidence_key

        def _key_based_extractor(state: StateDict) -> float:
            eval_result = state.get(eval_key, {})
            if isinstance(eval_result, dict):
                return float(eval_result.get("confidence", 0.5))
            # Fallback to direct confidence_key lookup
            return float(state.get(conf_key, 0.5))

        return _key_based_extractor
