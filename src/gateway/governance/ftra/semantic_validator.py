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
FTRA Semantic Validator — v2.1 input-dependent classification layer.

Upgrades _ftra_boundary_check from structural isinstance(tool_input, dict)
validation to semantic schema validation against FTRA boundary rules.

Fail-closed contract
--------------------
- Unknown actions with no schema defined: pass-through (rely on name-based classification)
- Known actions with missing required parameters: BOUNDARY_BREACH
- Numerical parameters outside defined bounds: BOUNDARY_BREACH
- Forbidden payload patterns detected: BOUNDARY_BREACH

Schema definitions
------------------
Schemas are defined as dataclasses with validation rules for each known action.
New actions should be added to ACTION_SCHEMAS registry.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger("Gateway.Governance.FTRA.SemanticValidator")


class ValidationFailureCode(str, Enum):
    """Diagnostic codes for semantic validation failures."""

    SUCCESS = "SUCCESS"
    """Validation passed without errors."""

    MISSING_REQUIRED_PARAMETER = "MISSING_REQUIRED_PARAMETER"
    """Required parameter is absent from tool_input."""

    TYPE_MISMATCH = "TYPE_MISMATCH"
    """Parameter value has incorrect type."""

    NUMERICAL_BOUND_VIOLATION = "NUMERICAL_BOUND_VIOLATION"
    """Numerical parameter exceeds defined bounds (negative, max limit, etc.)."""

    FORBIDDEN_PAYLOAD_INJECTION = "FORBIDDEN_PAYLOAD_INJECTION"
    """Detected null bytes, path traversal, or control override patterns."""

    INVALID_ENUM_VALUE = "INVALID_ENUM_VALUE"
    """Parameter value not in allowed set."""


@dataclass(frozen=True)
class ParameterConstraint:
    """Constraint definition for a single parameter."""

    name: str
    """Parameter name."""

    required: bool = True
    """Whether this parameter is required."""

    param_type: type | tuple[type, ...] = str
    """Expected type(s) for this parameter."""

    min_value: float | None = None
    """Minimum allowed value for numerical parameters."""

    max_value: float | None = None
    """Maximum allowed value for numerical parameters."""

    allowed_values: frozenset[Any] | None = None
    """Allowed enum values (if constrained set)."""

    pattern: str | None = None
    """Regex pattern the value must match (for strings)."""

    forbidden_patterns: frozenset[str] = field(default_factory=frozenset)
    """Regex patterns that must NOT match (security checks)."""


@dataclass(frozen=True)
class ActionSchema:
    """Schema definition for a specific action."""

    action_name: str
    """Action name (e.g., 'execute_trade')."""

    parameters: tuple[ParameterConstraint, ...]
    """Tuple of parameter constraints."""

    allow_extra_parameters: bool = False
    """Whether to allow parameters not in schema (backward compat)."""


@dataclass
class SemanticValidationResult:
    """Result of semantic validation against FTRA boundary rules."""

    is_valid: bool
    """True if validation passed."""

    failure_code: ValidationFailureCode
    """Diagnostic code for the validation outcome."""

    violations: list[str] = field(default_factory=list)
    """List of violation messages."""

    failed_parameter: str | None = None
    """Name of the parameter that failed validation (if applicable)."""

    diagnostic_message: str | None = None
    """Detailed diagnostic message for debugging."""


# ---------------------------------------------------------------------------
# Forbidden payload patterns (security invariants)
# ---------------------------------------------------------------------------

_FORBIDDEN_PATTERNS = frozenset(
    [
        r"\x00",  # Null byte injection
        r"\.\./",  # Path traversal (Unix)
        r"\.\.\\",  # Path traversal (Windows)
        r"__import__",  # Python import injection
        r"eval\s*\(",  # eval() injection
        r"exec\s*\(",  # exec() injection
        r"override_governance",  # Control override attempt
        r"bypass_ftra",  # FTRA bypass attempt
        r"DROP\s+TABLE",  # SQL injection (case-insensitive handled by validator)
        r";\s*--",  # SQL comment injection
    ]
)


# ---------------------------------------------------------------------------
# Action Schema Registry (Domain-Agnostic)
# ---------------------------------------------------------------------------
# NOTE: Schemas are registered dynamically by domain plugins via
# register_action_schema(). The kernel provides only the validation mechanism,
# not domain-specific action definitions.
#
# For backward compatibility and testing, a minimal schema registry is
# initialized here, but production deployments should register schemas
# from domain plugins (src/cage_finance/, src/cage_healthcare/, etc.).

ACTION_SCHEMAS: dict[str, ActionSchema] = {}
"""Global registry of action schemas. Populated by domain plugins at initialization."""


def register_action_schema(action_name: str, schema: ActionSchema) -> None:
    """Register a semantic schema for a specific action.

    This function is called by domain plugins during initialization to register
    their action-specific validation schemas. The kernel remains domain-agnostic.

    Args:
        action_name: The action name (e.g., from domain plugin).
        schema: The ActionSchema defining validation rules for this action.
    """
    ACTION_SCHEMAS[action_name] = schema
    logger.debug(
        "Registered semantic schema for action '%s' (%d parameters)",
        action_name,
        len(schema.parameters),
    )


# ---------------------------------------------------------------------------
# Semantic Validator
# ---------------------------------------------------------------------------


def _check_forbidden_patterns(value: Any, patterns: frozenset[str]) -> str | None:
    """Check if value matches any forbidden pattern.

    Args:
        value: Parameter value to check.
        patterns: Set of forbidden regex patterns.

    Returns:
        First matched pattern, or None if no match.
    """
    if not patterns:
        return None

    # Convert value to string for pattern matching
    str_value = str(value)

    for pattern in patterns:
        if re.search(pattern, str_value, re.IGNORECASE):
            return pattern

    return None


def _validate_parameter(
    constraint: ParameterConstraint,
    tool_input: dict[str, Any],
) -> SemanticValidationResult:
    """Validate a single parameter against its constraint.

    Args:
        constraint: Parameter constraint definition.
        tool_input: Dictionary of tool parameters.

    Returns:
        SemanticValidationResult indicating success or failure.
    """
    param_name = constraint.name
    value = tool_input.get(param_name)

    # Check required parameters
    if value is None:
        if constraint.required:
            return SemanticValidationResult(
                is_valid=False,
                failure_code=ValidationFailureCode.MISSING_REQUIRED_PARAMETER,
                violations=[
                    f"Required parameter '{param_name}' is missing from tool_input."
                ],
                failed_parameter=param_name,
            )
        else:
            # Optional parameter not provided — valid
            return SemanticValidationResult(
                is_valid=True,
                failure_code=ValidationFailureCode.SUCCESS,
            )

    # Type checking
    if constraint.param_type:
        expected_types = (
            constraint.param_type
            if isinstance(constraint.param_type, tuple)
            else (constraint.param_type,)
        )
        if not isinstance(value, expected_types):
            type_names = ", ".join(t.__name__ for t in expected_types)
            return SemanticValidationResult(
                is_valid=False,
                failure_code=ValidationFailureCode.TYPE_MISMATCH,
                violations=[
                    f"Parameter '{param_name}' has incorrect type. "
                    f"Expected {type_names}, got {type(value).__name__}."
                ],
                failed_parameter=param_name,
                diagnostic_message=f"Value: {value!r}",
            )

    # Numerical bounds checking
    if isinstance(value, (int, float)):
        if constraint.min_value is not None and value < constraint.min_value:
            return SemanticValidationResult(
                is_valid=False,
                failure_code=ValidationFailureCode.NUMERICAL_BOUND_VIOLATION,
                violations=[
                    f"Parameter '{param_name}' value {value} is below minimum "
                    f"allowed value {constraint.min_value}."
                ],
                failed_parameter=param_name,
            )
        if constraint.max_value is not None and value > constraint.max_value:
            return SemanticValidationResult(
                is_valid=False,
                failure_code=ValidationFailureCode.NUMERICAL_BOUND_VIOLATION,
                violations=[
                    f"Parameter '{param_name}' value {value} exceeds maximum "
                    f"allowed value {constraint.max_value}."
                ],
                failed_parameter=param_name,
            )

    # Enum value validation
    if constraint.allowed_values is not None:
        if value not in constraint.allowed_values:
            return SemanticValidationResult(
                is_valid=False,
                failure_code=ValidationFailureCode.INVALID_ENUM_VALUE,
                violations=[
                    f"Parameter '{param_name}' value '{value}' is not in allowed set: "
                    f"{sorted(constraint.allowed_values)}."
                ],
                failed_parameter=param_name,
            )

    # Pattern matching (for strings)
    if constraint.pattern and isinstance(value, str):
        if not re.match(constraint.pattern, value):
            return SemanticValidationResult(
                is_valid=False,
                failure_code=ValidationFailureCode.FORBIDDEN_PAYLOAD_INJECTION,
                violations=[
                    f"Parameter '{param_name}' value '{value}' does not match "
                    f"required pattern {constraint.pattern!r}."
                ],
                failed_parameter=param_name,
            )

    # Forbidden pattern detection (security)
    if constraint.forbidden_patterns:
        matched_pattern = _check_forbidden_patterns(
            value, constraint.forbidden_patterns
        )
        if matched_pattern:
            return SemanticValidationResult(
                is_valid=False,
                failure_code=ValidationFailureCode.FORBIDDEN_PAYLOAD_INJECTION,
                violations=[
                    f"Parameter '{param_name}' contains forbidden pattern: {matched_pattern!r}. "
                    "Potential injection or control override attempt detected."
                ],
                failed_parameter=param_name,
                diagnostic_message=f"Value: {value!r} (masked for security)",
            )

    # Validation passed
    return SemanticValidationResult(
        is_valid=True,
        failure_code=ValidationFailureCode.SUCCESS,
    )


def validate_tool_input(
    tool_name: str,
    tool_input: dict[str, Any],
) -> SemanticValidationResult:
    """Validate tool_input against semantic schema for tool_name.

    This is the v2.1 semantic classification layer. It validates:
    - Required parameters are present
    - Parameter types are correct
    - Numerical values are within defined bounds
    - No forbidden payload patterns are present

    Fail-closed behavior:
    - Actions without schemas: pass-through (rely on name-based classification)
    - Actions with schemas: enforce all constraints
    - Extra parameters: allowed structurally BUT must not contain forbidden patterns

    Args:
        tool_name: The action name (e.g., "execute_trade").
        tool_input: The action parameters dict.

    Returns:
        SemanticValidationResult indicating success or specific failure.
    """
    # Lookup schema for this action
    schema = ACTION_SCHEMAS.get(tool_name)

    # No schema defined → pass-through (backward compatibility)
    if schema is None:
        logger.debug(
            "No semantic schema defined for action '%s' — passing through to "
            "name-based classification.",
            tool_name,
        )
        return SemanticValidationResult(
            is_valid=True,
            failure_code=ValidationFailureCode.SUCCESS,
            diagnostic_message=f"No schema defined for '{tool_name}' (backward compatibility).",
        )

    # Validate each parameter constraint
    for constraint in schema.parameters:
        result = _validate_parameter(constraint, tool_input)
        if not result.is_valid:
            return result

    # Check for unexpected extra parameters
    expected_params = {c.name for c in schema.parameters}
    extra_params = set(tool_input.keys()) - expected_params

    if extra_params:
        # If extra parameters are not structurally allowed, fail immediately
        if not schema.allow_extra_parameters:
            return SemanticValidationResult(
                is_valid=False,
                failure_code=ValidationFailureCode.FORBIDDEN_PAYLOAD_INJECTION,
                violations=[
                    f"Unexpected parameters in tool_input: {sorted(extra_params)}. "
                    f"Schema does not allow extra parameters."
                ],
                diagnostic_message=f"Expected parameters: {sorted(expected_params)}",
            )

        # Extra parameters are structurally allowed, but check for forbidden patterns
        # This catches injection attempts in unexpected fields (fail-closed security)
        for param_name in extra_params:
            # Check parameter NAME for forbidden patterns (e.g., "override_governance")
            matched_pattern_name = _check_forbidden_patterns(
                param_name, _FORBIDDEN_PATTERNS
            )
            if matched_pattern_name:
                return SemanticValidationResult(
                    is_valid=False,
                    failure_code=ValidationFailureCode.FORBIDDEN_PAYLOAD_INJECTION,
                    violations=[
                        f"Extra parameter name '{param_name}' contains forbidden pattern: {matched_pattern_name!r}. "
                        "Potential control override attempt detected."
                    ],
                    failed_parameter=param_name,
                    diagnostic_message="Forbidden parameter name detected",
                )

            # Check parameter VALUE for forbidden patterns
            param_value = tool_input[param_name]
            matched_pattern_value = _check_forbidden_patterns(
                param_value, _FORBIDDEN_PATTERNS
            )
            if matched_pattern_value:
                return SemanticValidationResult(
                    is_valid=False,
                    failure_code=ValidationFailureCode.FORBIDDEN_PAYLOAD_INJECTION,
                    violations=[
                        f"Extra parameter '{param_name}' value contains forbidden pattern: {matched_pattern_value!r}. "
                        "Potential injection or control override attempt detected."
                    ],
                    failed_parameter=param_name,
                    diagnostic_message=f"Value: {param_value!r} (masked for security)",
                )

    # All validations passed
    logger.info(
        "✅ Semantic validation passed for action '%s' with %d parameters.",
        tool_name,
        len(tool_input),
    )
    return SemanticValidationResult(
        is_valid=True,
        failure_code=ValidationFailureCode.SUCCESS,
    )
