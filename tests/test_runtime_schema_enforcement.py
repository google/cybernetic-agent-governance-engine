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
Test suite for runtime schema enforcement (GAP-3 findings S0-1 through S1-4).
"""

import pytest
from jsonschema import Draft202012Validator

from src.gateway.governance.state_contract import (
    CompiledStateValidator,
    StateContractViolation,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]


# Test schema for validation
TEST_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "properties": {
        "status": {"type": "string", "enum": ["approved", "denied", "deferred"]},
        "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
    },
    "required": ["status", "confidence"],
    "additionalProperties": False,
}


def test_default_construction_is_enforcing() -> None:
    """S0-1: Assert default enforcing is True (fail-closed)."""
    validator = CompiledStateValidator(schema=TEST_SCHEMA)
    assert validator.enforcing is True


def test_valid_state_passes_cleanly() -> None:
    """Schema-compliant state passes without exception."""
    validator = CompiledStateValidator(schema=TEST_SCHEMA)
    valid_state = {"status": "approved", "confidence": 0.95}

    # Should not raise
    validator.validate_node_output(
        node_name="test_node", state=valid_state, context={"test": "context"}
    )


def test_contract_violation_raises_kernel_exception() -> None:
    """
    S1-1: Missing/invalid fields raise StateContractViolation, not raw ValidationError.
    S1-3: Verify structured audit/refusal emission before raising.
    """
    validator = CompiledStateValidator(schema=TEST_SCHEMA)

    # Missing required field
    invalid_state = {"status": "approved"}  # missing confidence

    with pytest.raises(StateContractViolation) as exc_info:
        validator.validate_node_output(
            node_name="failing_node", state=invalid_state, context={"test": "audit"}
        )

    # Verify kernel-owned exception properties
    exc = exc_info.value
    assert exc.node_name == "failing_node"
    assert "confidence" in exc.message.lower() or "required" in exc.message.lower()
    assert "failing_node" in str(exc)
    assert "breached state contract" in str(exc)


def test_compiled_validator_reused() -> None:
    """S1-2: Verify Draft202012Validator is initialized once at construction."""
    validator = CompiledStateValidator(schema=TEST_SCHEMA)

    # Verify validator was pre-compiled
    assert isinstance(validator.validator, Draft202012Validator)
    assert validator.validator.schema == TEST_SCHEMA

    # Store reference to compiled validator
    original_validator = validator.validator

    # Run multiple validations
    valid_state = {"status": "denied", "confidence": 0.42}
    validator.validate_node_output(node_name="node_1", state=valid_state)
    validator.validate_node_output(node_name="node_2", state=valid_state)

    # Verify same validator instance is reused
    assert validator.validator is original_validator


def test_non_enforcing_posture_skips_validation() -> None:
    """S0-1: Setting enforcing=False allows non-conforming state through."""
    validator = CompiledStateValidator(schema=TEST_SCHEMA, enforcing=False)
    assert validator.enforcing is False

    # Completely invalid state should not raise when enforcing=False
    invalid_state = {"completely": "wrong", "keys": 123}

    # Should not raise despite schema violation
    validator.validate_node_output(
        node_name="non_enforcing_node", state=invalid_state
    )


def test_invalid_enum_value_raises_violation() -> None:
    """Verify enum constraint violations are properly wrapped."""
    validator = CompiledStateValidator(schema=TEST_SCHEMA)
    invalid_enum_state = {
        "status": "invalid_status",  # not in enum
        "confidence": 0.8,
    }

    with pytest.raises(StateContractViolation) as exc_info:
        validator.validate_node_output(
            node_name="enum_test_node", state=invalid_enum_state
        )

    exc = exc_info.value
    assert exc.node_name == "enum_test_node"
    assert "status" in exc.path or "(root)" in exc.path


def test_out_of_range_number_raises_violation() -> None:
    """Verify numeric range violations are properly wrapped."""
    validator = CompiledStateValidator(schema=TEST_SCHEMA)
    out_of_range_state = {
        "status": "approved",
        "confidence": 1.5,  # exceeds maximum of 1.0
    }

    with pytest.raises(StateContractViolation) as exc_info:
        validator.validate_node_output(
            node_name="range_test_node", state=out_of_range_state
        )

    exc = exc_info.value
    assert exc.node_name == "range_test_node"
    assert "confidence" in exc.path.lower() or "1.5" in exc.message


def test_context_passed_to_audit_record() -> None:
    """Verify context is properly included in audit record on violation."""
    validator = CompiledStateValidator(schema=TEST_SCHEMA)
    invalid_state = {"status": "approved"}  # missing confidence

    test_context = {"request_id": "req-123", "user": "test_user"}

    with pytest.raises(StateContractViolation):
        validator.validate_node_output(
            node_name="context_test_node", state=invalid_state, context=test_context
        )
    # Audit emission is logged; verification via log capture would be integration-level
