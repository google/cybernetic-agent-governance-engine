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
create_ftra_node() — LangGraph node factory for the FTRA Tier 0.5 gate.

Placement in the graph
-----------------------
The FTRA node is inserted between ``evaluator`` and ``safety_check``:

    evaluator → ftra_node → safety_check   (CLEAR)
                          → explainer       (BLOCKED)
                          → [parked]        (HITL_REQUIRED — DeferQueue db=1)

The node reads ``execution_plan_output`` and ``evaluation_result`` from
``AgentState``, runs :class:`PlanGraphAnalyzer`, and writes back:

    ftra_status   — "CLEAR" | "HITL_REQUIRED" | "BLOCKED"
    ftra_result   — serialised :class:`ReachabilityResult` dict
    ftra_defer_id — DeferQueue token ID when verdict is HITL_REQUIRED

Routing
-------
``route_after_ftra()`` (also exported from this module) is the conditional
edge function that reads ``ftra_status`` and returns the next node name.
It is registered in ``graph.py`` via::

    workflow.add_conditional_edges("ftra_node", route_after_ftra)

OTel spans
----------
Every analysis emits a ``cage.ftra_analysis`` span with attributes:

    cage.ftra.plan_id
    cage.ftra.verdict
    cage.ftra.worst_case_classification
    cage.ftra.reachable_terminal_count
    cage.ftra.confidence_at_analysis
    cage.ftra.ctrl_id  → "CTRL_FTRA_001"

Usage (graph.py)::

    from src.gateway.governance.ftra.node_factory import create_ftra_node, route_after_ftra

    ftra_node_fn = create_ftra_node()
    workflow.add_node("ftra_node", ftra_node_fn)
    workflow.add_conditional_edges("ftra_node", route_after_ftra)
"""

from __future__ import annotations

import json
import logging
import os
import re
import uuid
import warnings
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from src.gateway.governance.langgraph_harness.types import FtraNodeConfig

logger = logging.getLogger("Gateway.Governance.FTRA.NodeFactory")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_CTRL_FTRA_001 = "CTRL_FTRA_001"
_DEFAULT_REGISTRY_PATH = "config/ftra/terminal_registry.json"

# Environment variable to control tokenizer artifact sanitization
_ENV_SANITIZE_TOKENIZER_ARTIFACTS = "FTRA_SANITIZE_TOKENIZER_ARTIFACTS"

# ---------------------------------------------------------------------------
# Prometheus Metrics (optional — degrades gracefully if prometheus_client unavailable)
# ---------------------------------------------------------------------------

_PROM_AVAILABLE = False
FTRA_PARSE_FAILURES = None

try:
    from prometheus_client import Counter

    FTRA_PARSE_FAILURES = Counter(
        "cage_ftra_parse_failures_total",
        "Total count of FTRA parse failures by failure class",
        ["failure_class"],
    )
    _PROM_AVAILABLE = True
except ImportError:
    logger.debug("prometheus_client not available — FTRA metrics disabled")


def _increment_parse_failure_counter(failure_class: str) -> None:
    """Increment the parse failure counter if prometheus_client is available."""
    if _PROM_AVAILABLE and FTRA_PARSE_FAILURES is not None:
        FTRA_PARSE_FAILURES.labels(failure_class=failure_class).inc()

# ---------------------------------------------------------------------------
# route_after_ftra — conditional edge function
# ---------------------------------------------------------------------------


def route_after_ftra(state: dict[str, Any]) -> str:
    """Conditional edge: read ``ftra_status`` and return the next node name.

    Routing table:
        CLEAR         → "safety_check"
        HITL_REQUIRED → "ftra_hitl_park"  (handled inside the node; this
                         branch should not be reached in normal flow because
                         the node raises ``NodeInterrupt`` for HITL parking)
        BLOCKED       → "explainer"
        <missing>     → "explainer"  (fail-closed)
    """
    status = state.get("ftra_status", "BLOCKED")
    if status == "CLEAR":
        return "safety_check"
    if status == "HITL_REQUIRED":
        # The node raises NodeInterrupt before returning state for HITL_REQUIRED,
        # so this branch is a safety fallback only.
        return "explainer"
    # BLOCKED or unknown
    return "explainer"


# ---------------------------------------------------------------------------
# create_ftra_node — node factory
# ---------------------------------------------------------------------------


def create_ftra_node(
    config: "FtraNodeConfig | None" = None,
) -> Callable[[dict[str, Any]], dict[str, Any]]:
    """Return a LangGraph node function that performs FTRA analysis.

    Args:
        config: Optional :class:`FtraNodeConfig` providing extractor functions
            and configuration.  When ``None``, uses default config (matching
            GFA's ``AgentState`` schema).

    Returns:
        An async-compatible node function ``ftra_node(state) -> state_patch``.

    Example:
        Using default config::

            ftra_node_fn = create_ftra_node()

        Using explicit config::

            from src.gateway.governance.langgraph_harness.types import FtraNodeConfig

            config = FtraNodeConfig(
                plan_extractor=lambda s: s.get("my_plan_field"),
                confidence_extractor=lambda s: s.get("my_confidence", 0.5),
                registry_path="custom/registry.json",
            )
            ftra_node_fn = create_ftra_node(config=config)
    """
    from opentelemetry import trace

    from src.gateway.governance.ftra.classifier import IrreversibilityClassifier
    from src.gateway.governance.ftra.graph_analyzer import PlanGraphAnalyzer
    from src.gateway.governance.langgraph_harness.types import FtraNodeConfig

    # Determine config source for telemetry
    if config is not None:
        config_source = "explicit"
        effective_config = config
    else:
        config_source = "default"
        effective_config = FtraNodeConfig(
            registry_path=_DEFAULT_REGISTRY_PATH,
            plan_key="execution_plan_output",
        )

    # Extract extractors from config
    plan_extractor = effective_config.get_plan_extractor()
    confidence_extractor = effective_config.get_confidence_extractor()

    # Build analyzer with configured registry path
    classifier = IrreversibilityClassifier(registry_path=effective_config.registry_path)
    analyzer = PlanGraphAnalyzer(classifier=classifier)

    # Capture span attributes from config
    extra_span_attrs = dict(effective_config.span_attributes)

    def ftra_node(state: dict[str, Any]) -> dict[str, Any]:
        """FTRA Tier 0.5 governance gate — commencement-time reachability check.

        Reads from state using configured extractors (defaults to GFA schema):
            execution_plan_output  — raw plan dict or JSON string from execution_analyst
            evaluation_result      — Evaluator verdict dict (must contain ``confidence``)

        Writes:
            ftra_status    — "CLEAR" | "HITL_REQUIRED" | "BLOCKED"
            ftra_result    — serialised ReachabilityResult dict
            ftra_defer_id  — DeferQueue token ID (HITL_REQUIRED only)
        """
        try:
            return _run_ftra(
                state,
                analyzer,
                plan_extractor=plan_extractor,
                confidence_extractor=confidence_extractor,
                config_source=config_source,
                extra_span_attrs=extra_span_attrs,
            )
        except Exception as exc:
            # CRITICAL: NodeInterrupt (and its parent GraphInterrupt) are
            # subclasses of Exception in LangGraph — they are the mechanism
            # by which _raise_node_interrupt() suspends the thread for HITL
            # review. They must propagate to the LangGraph runtime, not be
            # swallowed here. A prior version of this handler caught them
            # unconditionally, silently converting every HITL_REQUIRED
            # verdict into a fail-closed BLOCKED response and defeating the
            # DeferQueue human-in-the-loop pathway entirely.
            try:
                from langgraph.errors import GraphInterrupt

                if isinstance(exc, GraphInterrupt):
                    raise
            except ImportError:
                pass
            logger.error(
                "FTRA node: unhandled exception (%s) — failing closed (BLOCKED).", exc
            )
            return {
                "ftra_status": "BLOCKED",
                "ftra_result": {
                    "error": str(exc),
                    "verdict": "BLOCKED",
                    "ctrl_id": _CTRL_FTRA_001,
                },
                "ftra_defer_id": None,
            }

    return ftra_node


# ---------------------------------------------------------------------------
# Internal implementation
# ---------------------------------------------------------------------------


def _run_ftra(
    state: dict[str, Any],
    analyzer: Any,
    *,
    plan_extractor: Callable[[dict[str, Any]], Any],
    confidence_extractor: Callable[[dict[str, Any]], float],
    config_source: str = "default",
    extra_span_attrs: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Core FTRA logic — may raise; caller wraps in try/except.

    Args:
        state: LangGraph agent state dict.
        analyzer: PlanGraphAnalyzer instance.
        plan_extractor: Callable to extract raw plan from state.
        confidence_extractor: Callable to extract confidence from state.
        config_source: Source of configuration ("explicit" or "default")
            for OTel telemetry.
        extra_span_attrs: Additional OTel span attributes from config.
    """
    from opentelemetry import trace

    from src.gateway.governance.ftra.models import FTRAVerdict, ParseFailureClass
    from src.governed_financial_advisor.agents.execution_analyst.agent import (
        ExecutionPlan,
    )

    tracer = trace.get_tracer("cage.ftra")

    # ----------------------------------------------------------------
    # 1. Extract execution plan using configured extractor
    # ----------------------------------------------------------------
    raw_plan = plan_extractor(state)

    if raw_plan is None:
        logger.warning(
            "FTRA node: plan extractor returned None — failing closed (BLOCKED)."
        )
        _increment_parse_failure_counter(ParseFailureClass.SCHEMA_VALIDATION_ERROR.value)
        return {
            "ftra_status": "BLOCKED",
            "ftra_result": {
                "error": "plan extractor returned None (no plan in state)",
                "verdict": "BLOCKED",
                "ctrl_id": _CTRL_FTRA_001,
                "parse_failure_class": ParseFailureClass.SCHEMA_VALIDATION_ERROR.value,
            },
            "ftra_defer_id": None,
        }

    # ----------------------------------------------------------------
    # 1b. Parse plan with structured failure classification
    # (BUG-FTRA-SCHEMA-001, BUG-FTRA-JSON-001)
    # ----------------------------------------------------------------
    parse_result = _parse_plan_with_result(raw_plan)

    # ----------------------------------------------------------------
    # 2. Extract evaluator confidence using configured extractor
    # ----------------------------------------------------------------
    confidence: float = confidence_extractor(state)

    # ----------------------------------------------------------------
    # 3. Handle parse failures based on failure class
    # CRITICAL: Never BLOCK on parse failures alone (BUG-FTRA-SCHEMA-001)
    # ----------------------------------------------------------------

    # Start OTel span early to capture parse telemetry
    with tracer.start_as_current_span("cage.ftra_analysis") as span:
        span.set_attribute("cage.ftra.ctrl_id", _CTRL_FTRA_001)
        span.set_attribute("cage.ftra.config_source", config_source)
        span.set_attribute("cage.ftra.parse_failure_class", parse_result.failure_class.value)
        span.set_attribute("cage.ftra.sanitization_applied", parse_result.sanitization_applied)
        span.set_attribute("cage.ftra.confidence_at_analysis", confidence)

        # Add extra span attributes from config
        if extra_span_attrs:
            for key, value in extra_span_attrs.items():
                span.set_attribute(key, value)

        # Handle blocking parse errors → DEFER (not BLOCKED)
        # Per BUG-FTRA-SCHEMA-001: schema errors should DEFER for review, not auto-BLOCK
        if parse_result.failure_class == ParseFailureClass.JSON_DECODE_ERROR:
            logger.error(
                "FTRA: JSON decode error after sanitization — DEFER for review. "
                "Error: %s",
                parse_result.error_message,
            )
            # JSON_DECODE_ERROR after sanitization → log ERROR, use safe default (DEFER)
            return {
                "ftra_status": "HITL_REQUIRED",  # DEFER, not BLOCKED
                "ftra_result": {
                    "error": parse_result.error_message,
                    "verdict": "HITL_REQUIRED",
                    "ctrl_id": _CTRL_FTRA_001,
                    "parse_failure_class": parse_result.failure_class.value,
                    "sanitization_applied": parse_result.sanitization_applied,
                },
                "ftra_defer_id": None,
            }

        if parse_result.failure_class == ParseFailureClass.SCHEMA_VALIDATION_ERROR:
            logger.warning(
                "FTRA: schema validation error — DEFER for review. Error: %s",
                parse_result.error_message,
            )
            # SCHEMA_VALIDATION_ERROR → DEFER (needs review)
            return {
                "ftra_status": "HITL_REQUIRED",  # DEFER, not BLOCKED
                "ftra_result": {
                    "error": parse_result.error_message,
                    "verdict": "HITL_REQUIRED",
                    "ctrl_id": _CTRL_FTRA_001,
                    "parse_failure_class": parse_result.failure_class.value,
                    "sanitization_applied": parse_result.sanitization_applied,
                },
                "ftra_defer_id": None,
            }

        # Handle EMPTY_STEPS with high confidence → ALLOW
        # Per spec: empty plan is a valid choice
        if parse_result.failure_class == ParseFailureClass.EMPTY_STEPS:
            if confidence >= 0.70:
                logger.info(
                    "FTRA: empty plan with high confidence (%.2f) — ALLOW (empty plan is valid choice).",
                    confidence,
                )
                span.set_attribute("cage.ftra.verdict", "CLEAR")
                span.set_attribute("cage.ftra.empty_plan_allowed", True)
                return {
                    "ftra_status": "CLEAR",
                    "ftra_result": {
                        "verdict": "CLEAR",
                        "ctrl_id": _CTRL_FTRA_001,
                        "parse_failure_class": parse_result.failure_class.value,
                        "empty_plan_allowed": True,
                        "confidence_at_analysis": confidence,
                        "total_steps": 0,
                        "reachable_terminals": [],
                    },
                    "ftra_defer_id": None,
                }
            else:
                logger.warning(
                    "FTRA: empty plan with low confidence (%.2f) — DEFER for review.",
                    confidence,
                )
                return {
                    "ftra_status": "HITL_REQUIRED",
                    "ftra_result": {
                        "verdict": "HITL_REQUIRED",
                        "ctrl_id": _CTRL_FTRA_001,
                        "parse_failure_class": parse_result.failure_class.value,
                        "confidence_at_analysis": confidence,
                        "total_steps": 0,
                    },
                    "ftra_defer_id": None,
                }

        # Handle TRUNCATED_PLAN → DEFER (not BLOCKED)
        if parse_result.failure_class == ParseFailureClass.TRUNCATED_PLAN:
            logger.warning(
                "FTRA: plan appears truncated — DEFER for review. Details: %s",
                parse_result.error_message,
            )
            return {
                "ftra_status": "HITL_REQUIRED",  # DEFER, not BLOCKED
                "ftra_result": {
                    "error": parse_result.error_message,
                    "verdict": "HITL_REQUIRED",
                    "ctrl_id": _CTRL_FTRA_001,
                    "parse_failure_class": parse_result.failure_class.value,
                    "sanitization_applied": parse_result.sanitization_applied,
                },
                "ftra_defer_id": None,
            }

        # SUCCESS or TOKENIZER_ARTIFACT (sanitization succeeded) — proceed with analysis
        if parse_result.failure_class == ParseFailureClass.TOKENIZER_ARTIFACT:
            logger.info(
                "FTRA: tokenizer artifacts sanitized successfully — proceeding with analysis."
            )

        # Convert parsed dict back to ExecutionPlan for analysis
        plan = ExecutionPlan.model_validate(parse_result.plan)

        span.set_attribute("cage.ftra.plan_id", plan.plan_id)

        # ----------------------------------------------------------------
        # 4. Run reachability analysis
        # ----------------------------------------------------------------
        result = analyzer.analyze(plan, confidence)

        span.set_attribute("cage.ftra.verdict", result.verdict.value)
        span.set_attribute(
            "cage.ftra.worst_case_classification",
            result.worst_case_classification.value,
        )
        span.set_attribute(
            "cage.ftra.reachable_terminal_count", len(result.reachable_terminals)
        )
        span.set_attribute("cage.ftra.total_steps", result.total_steps)
        span.set_attribute(
            "cage.ftra.reachable_step_count", result.reachable_step_count
        )

    # ----------------------------------------------------------------
    # 5. Build state patch
    # ----------------------------------------------------------------
    result_dict = result.model_dump()
    result_dict["ctrl_id"] = _CTRL_FTRA_001
    result_dict["parse_failure_class"] = parse_result.failure_class.value
    result_dict["sanitization_applied"] = parse_result.sanitization_applied

    if result.verdict == FTRAVerdict.CLEAR:
        logger.info("FTRA: plan '%s' CLEAR — proceeding to safety_check.", plan.plan_id)
        return {
            "ftra_status": "CLEAR",
            "ftra_result": result_dict,
            "ftra_defer_id": None,
        }

    if result.verdict == FTRAVerdict.HITL_REQUIRED:
        defer_id = _park_in_defer_queue(state, result_dict, confidence)
        logger.warning(
            "FTRA: plan '%s' HITL_REQUIRED — parked as defer_id='%s'.",
            plan.plan_id,
            defer_id,
        )
        # Raise NodeInterrupt so LangGraph suspends the thread.
        # The graph will resume when the human clears the defer token.
        _raise_node_interrupt(defer_id, result_dict)
        # Fallback (NodeInterrupt not available in this LangGraph version):
        return {
            "ftra_status": "HITL_REQUIRED",
            "ftra_result": result_dict,
            "ftra_defer_id": defer_id,
        }

    # BLOCKED
    logger.warning(
        "FTRA: plan '%s' BLOCKED (confidence=%.3f < %.2f, irreversible terminals=%s).",
        plan.plan_id,
        confidence,
        0.70,
        result.reachable_terminals,
    )
    return {
        "ftra_status": "BLOCKED",
        "ftra_result": result_dict,
        "ftra_defer_id": None,
    }


def _is_sanitization_enabled() -> bool:
    """Check if tokenizer artifact sanitization is enabled.

    Controlled by FTRA_SANITIZE_TOKENIZER_ARTIFACTS env var (default: "true").
    """
    env_value = os.environ.get(_ENV_SANITIZE_TOKENIZER_ARTIFACTS, "true").lower()
    return env_value in ("true", "1", "yes", "on")


def sanitize_llm_output(raw: str) -> tuple[str, bool]:
    """Remove common tokenizer artifacts before JSON parsing.

    Args:
        raw: Raw LLM output string.

    Returns:
        Tuple of (sanitized_string, was_modified).

    Handles:
        - Markdown code fences (```json ... ```, ``` ... ```)
        - Leading/trailing whitespace
        - Trailing incomplete tokens (common with streaming)
        - Unicode escape issues
        - BOM (Byte Order Mark) characters
    """
    original = raw
    sanitized = raw

    # Remove BOM if present
    sanitized = sanitized.lstrip("\ufeff")

    # Remove markdown code fences (```json, ```JSON, ``` etc.)
    # Match opening fence with optional language tag
    sanitized = re.sub(r"^```[a-zA-Z]*\s*\n?", "", sanitized, flags=re.MULTILINE)
    # Match closing fence
    sanitized = re.sub(r"\n?```\s*$", "", sanitized, flags=re.MULTILINE)

    # Strip leading/trailing whitespace
    sanitized = sanitized.strip()

    # Handle trailing incomplete tokens — common patterns:
    # - Trailing comma before missing element: [{"a": 1},
    # - Unclosed string: {"key": "incomplete
    # - Unclosed object/array: {"key": [1, 2
    # We try to detect truncation by checking for unbalanced brackets

    # Remove trailing comma if present (common LLM artifact)
    sanitized = re.sub(r",\s*$", "", sanitized)

    # Fix common unicode escape issues
    # Some models emit \u followed by non-hex characters
    # Replace invalid \u escapes with placeholder
    sanitized = re.sub(r"\\u(?![0-9a-fA-F]{4})", r"\\\\u", sanitized)

    was_modified = sanitized != original
    return sanitized, was_modified


def _detect_truncation(raw: str) -> bool:
    """Detect if JSON appears truncated (unbalanced brackets/braces).

    Returns True if the JSON structure appears incomplete.
    """
    # Count brackets and braces
    open_braces = raw.count("{")
    close_braces = raw.count("}")
    open_brackets = raw.count("[")
    close_brackets = raw.count("]")

    # Check for imbalance
    if open_braces != close_braces or open_brackets != close_brackets:
        return True

    # Check for trailing incomplete patterns
    truncation_patterns = [
        r',\s*$',           # Trailing comma
        r'"\s*:\s*$',       # Key without value
        r':\s*"[^"]*$',     # Unclosed string value
        r'\[\s*$',          # Empty array start
        r'{\s*$',           # Empty object start
    ]
    for pattern in truncation_patterns:
        if re.search(pattern, raw):
            return True

    return False


def _parse_plan_with_result(raw: Any) -> "ParseResult":
    """Parse raw execution_plan_output into an ExecutionPlan with structured result.

    Returns a ParseResult with failure classification for defensive parsing.
    This addresses BUG-FTRA-SCHEMA-001 and BUG-FTRA-JSON-001.

    Accepts:
        - An already-parsed ExecutionPlan object
        - A dict (from JSON-decoded state)
        - A JSON string (with optional markdown fences)
    """
    from src.gateway.governance.ftra.models import ParseFailureClass, ParseResult
    from src.governed_financial_advisor.agents.execution_analyst.agent import (
        ExecutionPlan,
    )

    raw_str = str(raw) if not isinstance(raw, str) else raw

    # Already an ExecutionPlan — success
    if isinstance(raw, ExecutionPlan):
        # Check for empty steps (warning, not error)
        if not raw.steps:
            return ParseResult(
                plan=raw.model_dump(),
                failure_class=ParseFailureClass.EMPTY_STEPS,
                raw_input=raw_str,
                sanitized_input=None,
                error_message="Plan has zero steps",
                sanitization_applied=False,
            )
        return ParseResult(
            plan=raw.model_dump(),
            failure_class=ParseFailureClass.SUCCESS,
            raw_input=raw_str,
            sanitized_input=None,
            sanitization_applied=False,
        )

    # Dict input — validate as ExecutionPlan
    if isinstance(raw, dict):
        try:
            plan = ExecutionPlan.model_validate(raw)
            # Check for empty steps
            if not plan.steps:
                return ParseResult(
                    plan=raw,
                    failure_class=ParseFailureClass.EMPTY_STEPS,
                    raw_input=raw_str,
                    sanitized_input=None,
                    error_message="Plan has zero steps",
                    sanitization_applied=False,
                )
            return ParseResult(
                plan=raw,
                failure_class=ParseFailureClass.SUCCESS,
                raw_input=raw_str,
                sanitized_input=None,
                sanitization_applied=False,
            )
        except Exception as exc:
            _increment_parse_failure_counter(ParseFailureClass.SCHEMA_VALIDATION_ERROR.value)
            return ParseResult(
                plan=None,
                failure_class=ParseFailureClass.SCHEMA_VALIDATION_ERROR,
                raw_input=raw_str,
                sanitized_input=None,
                error_message=f"dict→ExecutionPlan validation failed: {exc}",
                sanitization_applied=False,
            )

    # String input — needs JSON parsing (possibly with sanitization)
    if isinstance(raw, str):
        sanitization_enabled = _is_sanitization_enabled()
        sanitized_input = raw
        sanitization_applied = False

        # Apply sanitization if enabled
        if sanitization_enabled:
            sanitized_input, sanitization_applied = sanitize_llm_output(raw)

        # Detect truncation before parsing
        is_truncated = _detect_truncation(sanitized_input)

        # Try parsing the (possibly sanitized) JSON
        try:
            plan = ExecutionPlan.model_validate_json(sanitized_input)

            # Check for empty steps
            if not plan.steps:
                failure_class = ParseFailureClass.EMPTY_STEPS
                if is_truncated:
                    failure_class = ParseFailureClass.TRUNCATED_PLAN
                return ParseResult(
                    plan=plan.model_dump(),
                    failure_class=failure_class,
                    raw_input=raw,
                    sanitized_input=sanitized_input if sanitization_applied else None,
                    error_message="Plan has zero steps" + (" (possibly truncated)" if is_truncated else ""),
                    sanitization_applied=sanitization_applied,
                )

            # Success — but note if sanitization was applied
            failure_class = ParseFailureClass.SUCCESS
            if sanitization_applied:
                failure_class = ParseFailureClass.TOKENIZER_ARTIFACT
            return ParseResult(
                plan=plan.model_dump(),
                failure_class=failure_class,
                raw_input=raw,
                sanitized_input=sanitized_input if sanitization_applied else None,
                sanitization_applied=sanitization_applied,
            )

        except json.JSONDecodeError as exc:
            # JSON syntax error
            _increment_parse_failure_counter(ParseFailureClass.JSON_DECODE_ERROR.value)

            # Distinguish truncated from malformed
            failure_class = ParseFailureClass.TRUNCATED_PLAN if is_truncated else ParseFailureClass.JSON_DECODE_ERROR

            return ParseResult(
                plan=None,
                failure_class=failure_class,
                raw_input=raw,
                sanitized_input=sanitized_input if sanitization_applied else None,
                error_message=f"JSON decode error: {exc}",
                sanitization_applied=sanitization_applied,
            )

        except Exception as exc:
            # Pydantic validation error (valid JSON, invalid schema)
            _increment_parse_failure_counter(ParseFailureClass.SCHEMA_VALIDATION_ERROR.value)
            return ParseResult(
                plan=None,
                failure_class=ParseFailureClass.SCHEMA_VALIDATION_ERROR,
                raw_input=raw,
                sanitized_input=sanitized_input if sanitization_applied else None,
                error_message=f"Schema validation failed: {exc}",
                sanitization_applied=sanitization_applied,
            )

    # Unexpected type
    _increment_parse_failure_counter(ParseFailureClass.SCHEMA_VALIDATION_ERROR.value)
    return ParseResult(
        plan=None,
        failure_class=ParseFailureClass.SCHEMA_VALIDATION_ERROR,
        raw_input=raw_str,
        sanitized_input=None,
        error_message=f"Unexpected execution_plan_output type: {type(raw)}",
        sanitization_applied=False,
    )


def _parse_plan(raw: Any) -> Any | None:
    """Parse raw execution_plan_output into an ExecutionPlan.

    Legacy wrapper for backward compatibility. Returns ExecutionPlan or None.
    For structured failure classification, use _parse_plan_with_result().

    Accepts:
        - An already-parsed ExecutionPlan object
        - A dict (from JSON-decoded state)
        - A JSON string
    """
    from src.gateway.governance.ftra.models import ParseFailureClass
    from src.governed_financial_advisor.agents.execution_analyst.agent import (
        ExecutionPlan,
    )

    result = _parse_plan_with_result(raw)

    # Log based on failure class
    if result.failure_class == ParseFailureClass.SUCCESS:
        return ExecutionPlan.model_validate(result.plan)
    elif result.failure_class == ParseFailureClass.TOKENIZER_ARTIFACT:
        # Sanitization succeeded — still valid
        logger.info("FTRA: tokenizer artifacts sanitized from plan input")
        return ExecutionPlan.model_validate(result.plan)
    elif result.failure_class == ParseFailureClass.EMPTY_STEPS:
        # Empty plan — valid but notable
        logger.info("FTRA: parsed plan has zero steps")
        return ExecutionPlan.model_validate(result.plan)
    elif result.failure_class == ParseFailureClass.TRUNCATED_PLAN:
        # Truncated — may still be valid partial plan
        if result.plan is not None:
            logger.warning("FTRA: plan appears truncated but partially parsed")
            return ExecutionPlan.model_validate(result.plan)
        logger.warning("FTRA: plan is truncated and could not be parsed: %s", result.error_message)
        return None
    else:
        # Hard failure
        logger.warning("FTRA: %s — %s", result.failure_class.value, result.error_message)
        return None


def _park_in_defer_queue(
    state: dict[str, Any],
    result_dict: dict[str, Any],
    confidence: float,
) -> str:
    """Park the suspended plan in DeferQueue db=1 and return the defer_id.

    Connects to Redis db=1 via REDIS_URL (matching the deployment contract
    documented in defer_queue.py — the DEFER token store is isolated from the
    LangGraph checkpointer at db=0) and parks the token through the existing
    DeferQueue infrastructure. Falls back to a local, unpersisted UUID token
    if Redis is unavailable — the HITL_REQUIRED verdict is still enforced by
    the graph interrupt/state routing, but external HITL API resolution
    (POST /v1/defer/{id}/escalate or /inject) will not find this token in
    that fallback case, since it was never written to Redis.

    NOTE (fixed): a prior version instantiated DeferQueue() with zero
    arguments, but DeferQueue.__init__ requires a redis_client. That always
    raised TypeError, which was silently caught by the except-Exception
    fallback below — meaning every HITL_REQUIRED verdict previously fell
    through to the unpersisted-token path unconditionally. See
    src/compliance_bridge/main.py's list_defer_pending()/resolve endpoints
    for the correct DeferQueue(client) instantiation pattern this mirrors.
    """
    import asyncio
    import os

    from src.gateway.governance.defer_queue import DeferQueue, DeferReason, DeferToken

    thread_id: str = state.get("thread_id", str(uuid.uuid4()))
    token = DeferToken(
        thread_id=thread_id,
        defer_reason=DeferReason.FTRA_IRREVERSIBLE_TERMINAL,
        opa_input_snapshot={
            "ftra_result": result_dict,
            "plan_id": result_dict.get("plan_id", ""),
        },
        confidence_score=confidence,
        aarm_vector="AARM-V9",  # Forward-looking reachability block
    )

    async def _park() -> str:
        import redis.asyncio as aioredis

        redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379")
        client = aioredis.from_url(redis_url, db=1, decode_responses=True)
        try:
            queue = DeferQueue(client)
            return await queue.park(token)
        finally:
            await client.aclose()

    try:
        # Run in a new event loop if we're not already in one
        try:
            asyncio.get_running_loop()
            # We're inside an async context — schedule as a task
            import concurrent.futures

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(asyncio.run, _park())
                return future.result(timeout=5.0)
        except RuntimeError:
            # No running loop — safe to use asyncio.run
            return asyncio.run(_park())
    except Exception as exc:
        logger.error(
            "FTRA: DeferQueue park failed (%s) — using local defer_id only "
            "(token NOT persisted to Redis; HITL API will not find it).",
            exc,
        )
        return token.defer_id


def _raise_node_interrupt(defer_id: str, result_dict: dict[str, Any]) -> None:
    """Raise a LangGraph NodeInterrupt to suspend the thread for HITL review.

    Gracefully degrades if NodeInterrupt is not available in the installed
    LangGraph version — the HITL_REQUIRED state patch still routes correctly
    via ``route_after_ftra``.
    """
    try:
        from langgraph.errors import NodeInterrupt

        raise NodeInterrupt(
            {
                "reason": "FTRA_IRREVERSIBLE_TERMINAL",
                "defer_id": defer_id,
                "ctrl_id": _CTRL_FTRA_001,
                "ftra_result": result_dict,
            }
        )
    except ImportError:
        logger.warning(
            "FTRA: NodeInterrupt not available in this LangGraph version — "
            "HITL_REQUIRED will be enforced via route_after_ftra state routing only."
        )
