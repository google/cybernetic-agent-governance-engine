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
Unit tests for FTRA v2.1 semantic boundary validation.

Tests the semantic schema validation layer for _ftra_boundary_check, including:
- Nominal payloads pass validation
- Out-of-bound numerical inputs trigger rejection
- Forbidden payload injections fail closed
- Missing required parameters fail closed
- Type mismatches fail closed
"""

import pytest

from src.gateway.governance.ftra.semantic_validator import (
    ACTION_SCHEMAS,
    ActionSchema,
    ParameterConstraint,
    ValidationFailureCode,
    register_action_schema,
    validate_tool_input,
)

# Mark all tests in this module as unit + local
pytestmark = [pytest.mark.unit, pytest.mark.local]


# ---------------------------------------------------------------------------
# Test Fixtures (Domain Plugin Simulation)
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
        r"DROP\s+TABLE",  # SQL injection
        r";\s*--",  # SQL comment injection
    ]
)


@pytest.fixture(autouse=True)
def register_test_schemas():
    """Register test action schemas (simulates domain plugin initialization)."""
    # Clear any existing schemas
    ACTION_SCHEMAS.clear()
    
    # Register schemas for test actions (using test-specific names to avoid domain literals)
    register_action_schema(
        "execute_trade",  # Test action
        ActionSchema(
            action_name="execute_trade",
            parameters=(
                ParameterConstraint(
                    name="symbol",
                    required=True,
                    param_type=str,
                    pattern=r"^[A-Z]{1,5}$",
                    forbidden_patterns=_FORBIDDEN_PATTERNS,
                ),
                ParameterConstraint(
                    name="amount",
                    required=True,
                    param_type=(int, float),
                    min_value=0.01,
                    max_value=1_000_000.0,
                    forbidden_patterns=_FORBIDDEN_PATTERNS,
                ),
                ParameterConstraint(
                    name="currency",
                    required=True,
                    param_type=str,
                    allowed_values=frozenset(["USD", "EUR", "GBP", "JPY"]),
                    forbidden_patterns=_FORBIDDEN_PATTERNS,
                ),
                ParameterConstraint(
                    name="order_type",
                    required=False,
                    param_type=str,
                    allowed_values=frozenset(["market", "limit"]),
                    forbidden_patterns=_FORBIDDEN_PATTERNS,
                ),
            ),
            allow_extra_parameters=True,
        ),
    )
    
    register_action_schema(
        "execute_trade_bounded",
        ActionSchema(
            action_name="execute_trade_bounded",
            parameters=(
                ParameterConstraint(
                    name="symbol",
                    required=True,
                    param_type=str,
                    pattern=r"^[A-Z]{1,5}$",
                    forbidden_patterns=_FORBIDDEN_PATTERNS,
                ),
                ParameterConstraint(
                    name="amount",
                    required=True,
                    param_type=(int, float),
                    min_value=0.01,
                    max_value=100_000.0,
                    forbidden_patterns=_FORBIDDEN_PATTERNS,
                ),
                ParameterConstraint(
                    name="currency",
                    required=True,
                    param_type=str,
                    allowed_values=frozenset(["USD", "EUR", "GBP", "JPY"]),
                    forbidden_patterns=_FORBIDDEN_PATTERNS,
                ),
                ParameterConstraint(
                    name="max_slippage",
                    required=False,
                    param_type=(int, float),
                    min_value=0.0,
                    max_value=10.0,
                    forbidden_patterns=_FORBIDDEN_PATTERNS,
                ),
            ),
            allow_extra_parameters=True,
        ),
    )
    
    register_action_schema(
        "release_wire",
        ActionSchema(
            action_name="release_wire",
            parameters=(
                ParameterConstraint(
                    name="wire_id",
                    required=True,
                    param_type=str,
                    pattern=r"^WR-[0-9]{8}-[A-Z0-9]{8}$",
                    forbidden_patterns=_FORBIDDEN_PATTERNS,
                ),
                ParameterConstraint(
                    name="amount",
                    required=True,
                    param_type=(int, float),
                    min_value=0.01,
                    max_value=10_000_000.0,
                    forbidden_patterns=_FORBIDDEN_PATTERNS,
                ),
                ParameterConstraint(
                    name="currency",
                    required=True,
                    param_type=str,
                    allowed_values=frozenset(["USD", "EUR", "GBP", "JPY"]),
                    forbidden_patterns=_FORBIDDEN_PATTERNS,
                ),
            ),
            allow_extra_parameters=True,
        ),
    )
    
    register_action_schema(
        "write_db",
        ActionSchema(
            action_name="write_db",
            parameters=(
                ParameterConstraint(
                    name="table",
                    required=True,
                    param_type=str,
                    pattern=r"^[a-z_][a-z0-9_]{0,63}$",
                    forbidden_patterns=_FORBIDDEN_PATTERNS,
                ),
                ParameterConstraint(
                    name="operation",
                    required=True,
                    param_type=str,
                    allowed_values=frozenset(["insert", "update", "delete"]),
                    forbidden_patterns=_FORBIDDEN_PATTERNS,
                ),
            ),
            allow_extra_parameters=True,
        ),
    )
    
    yield
    
    # Cleanup after tests
    ACTION_SCHEMAS.clear()


# ---------------------------------------------------------------------------
# Nominal Cases (Should Pass)
# ---------------------------------------------------------------------------


def test_execute_trade_nominal_payload_passes():
    """Nominal execute_trade payload passes semantic validation."""
    tool_input = {
        "symbol": "AAPL",
        "amount": 1000.0,
        "currency": "USD",
    }
    result = validate_tool_input("execute_trade", tool_input)
    assert result.is_valid
    assert result.failure_code == ValidationFailureCode.SUCCESS
    assert result.violations == []


def test_execute_trade_with_optional_order_type_passes():
    """execute_trade with optional order_type parameter passes."""
    tool_input = {
        "symbol": "TSLA",
        "amount": 5000.0,
        "currency": "USD",
        "order_type": "limit",
    }
    result = validate_tool_input("execute_trade", tool_input)
    assert result.is_valid
    assert result.failure_code == ValidationFailureCode.SUCCESS


def test_execute_trade_bounded_nominal_passes():
    """execute_trade_bounded with valid slippage passes."""
    tool_input = {
        "symbol": "NVDA",
        "amount": 50000.0,
        "currency": "USD",
        "max_slippage": 2.5,
    }
    result = validate_tool_input("execute_trade_bounded", tool_input)
    assert result.is_valid
    assert result.failure_code == ValidationFailureCode.SUCCESS


def test_release_wire_nominal_passes():
    """Nominal release_wire payload passes validation."""
    tool_input = {
        "wire_id": "WR-20260913-ABC12345",
        "amount": 100000.0,
        "currency": "USD",
    }
    result = validate_tool_input("release_wire", tool_input)
    assert result.is_valid
    assert result.failure_code == ValidationFailureCode.SUCCESS


def test_write_db_nominal_passes():
    """Nominal write_db payload passes validation."""
    tool_input = {
        "table": "trades",
        "operation": "insert",
    }
    result = validate_tool_input("write_db", tool_input)
    assert result.is_valid
    assert result.failure_code == ValidationFailureCode.SUCCESS


def test_unknown_action_passes_through():
    """Actions without schemas pass through (backward compatibility)."""
    tool_input = {"arbitrary": "parameters"}
    result = validate_tool_input("unknown_action", tool_input)
    assert result.is_valid
    assert result.failure_code == ValidationFailureCode.SUCCESS
    assert "No schema defined" in (result.diagnostic_message or "")


def test_read_only_action_passes_through():
    """READ_ONLY actions without schemas pass through."""
    tool_input = {"account_id": "12345"}
    result = validate_tool_input("check_balance", tool_input)
    assert result.is_valid
    assert result.failure_code == ValidationFailureCode.SUCCESS


# ---------------------------------------------------------------------------
# Missing Required Parameters
# ---------------------------------------------------------------------------


def test_execute_trade_missing_symbol_fails():
    """execute_trade with missing 'symbol' fails validation."""
    tool_input = {
        "amount": 1000.0,
        "currency": "USD",
    }
    result = validate_tool_input("execute_trade", tool_input)
    assert not result.is_valid
    assert result.failure_code == ValidationFailureCode.MISSING_REQUIRED_PARAMETER
    assert result.failed_parameter == "symbol"
    assert "Required parameter 'symbol' is missing" in result.violations[0]


def test_execute_trade_missing_amount_fails():
    """execute_trade with missing 'amount' fails validation."""
    tool_input = {
        "symbol": "AAPL",
        "currency": "USD",
    }
    result = validate_tool_input("execute_trade", tool_input)
    assert not result.is_valid
    assert result.failure_code == ValidationFailureCode.MISSING_REQUIRED_PARAMETER
    assert result.failed_parameter == "amount"


def test_execute_trade_missing_currency_fails():
    """execute_trade with missing 'currency' fails validation."""
    tool_input = {
        "symbol": "AAPL",
        "amount": 1000.0,
    }
    result = validate_tool_input("execute_trade", tool_input)
    assert not result.is_valid
    assert result.failure_code == ValidationFailureCode.MISSING_REQUIRED_PARAMETER
    assert result.failed_parameter == "currency"


# ---------------------------------------------------------------------------
# Type Mismatches
# ---------------------------------------------------------------------------


def test_execute_trade_symbol_wrong_type_fails():
    """execute_trade with non-string symbol fails."""
    tool_input = {
        "symbol": 12345,  # Should be string
        "amount": 1000.0,
        "currency": "USD",
    }
    result = validate_tool_input("execute_trade", tool_input)
    assert not result.is_valid
    assert result.failure_code == ValidationFailureCode.TYPE_MISMATCH
    assert result.failed_parameter == "symbol"
    assert "Expected str, got int" in result.violations[0]


def test_execute_trade_amount_wrong_type_fails():
    """execute_trade with string amount (not number) fails."""
    tool_input = {
        "symbol": "AAPL",
        "amount": "one thousand",  # Should be numeric
        "currency": "USD",
    }
    result = validate_tool_input("execute_trade", tool_input)
    assert not result.is_valid
    assert result.failure_code == ValidationFailureCode.TYPE_MISMATCH
    assert result.failed_parameter == "amount"


# ---------------------------------------------------------------------------
# Numerical Boundary Violations
# ---------------------------------------------------------------------------


def test_execute_trade_negative_amount_fails():
    """execute_trade with negative amount fails validation."""
    tool_input = {
        "symbol": "AAPL",
        "amount": -500.0,  # Negative amount
        "currency": "USD",
    }
    result = validate_tool_input("execute_trade", tool_input)
    assert not result.is_valid
    assert result.failure_code == ValidationFailureCode.NUMERICAL_BOUND_VIOLATION
    assert result.failed_parameter == "amount"
    assert "below minimum" in result.violations[0]


def test_execute_trade_zero_amount_fails():
    """execute_trade with zero amount fails validation."""
    tool_input = {
        "symbol": "AAPL",
        "amount": 0.0,  # Below minimum 0.01
        "currency": "USD",
    }
    result = validate_tool_input("execute_trade", tool_input)
    assert not result.is_valid
    assert result.failure_code == ValidationFailureCode.NUMERICAL_BOUND_VIOLATION
    assert result.failed_parameter == "amount"


def test_execute_trade_exceeds_max_amount_fails():
    """execute_trade with amount exceeding max limit fails."""
    tool_input = {
        "symbol": "AAPL",
        "amount": 2_000_000.0,  # Exceeds max 1,000,000
        "currency": "USD",
    }
    result = validate_tool_input("execute_trade", tool_input)
    assert not result.is_valid
    assert result.failure_code == ValidationFailureCode.NUMERICAL_BOUND_VIOLATION
    assert result.failed_parameter == "amount"
    assert "exceeds maximum" in result.violations[0]


def test_execute_trade_bounded_exceeds_lower_max_fails():
    """execute_trade_bounded has lower max limit (100k vs 1M)."""
    tool_input = {
        "symbol": "AAPL",
        "amount": 150_000.0,  # Exceeds bounded max 100,000
        "currency": "USD",
    }
    result = validate_tool_input("execute_trade_bounded", tool_input)
    assert not result.is_valid
    assert result.failure_code == ValidationFailureCode.NUMERICAL_BOUND_VIOLATION
    assert result.failed_parameter == "amount"


def test_execute_trade_bounded_negative_slippage_fails():
    """execute_trade_bounded with negative slippage fails."""
    tool_input = {
        "symbol": "AAPL",
        "amount": 1000.0,
        "currency": "USD",
        "max_slippage": -1.0,  # Negative slippage
    }
    result = validate_tool_input("execute_trade_bounded", tool_input)
    assert not result.is_valid
    assert result.failure_code == ValidationFailureCode.NUMERICAL_BOUND_VIOLATION
    assert result.failed_parameter == "max_slippage"


def test_execute_trade_bounded_excessive_slippage_fails():
    """execute_trade_bounded with slippage > 10% fails."""
    tool_input = {
        "symbol": "AAPL",
        "amount": 1000.0,
        "currency": "USD",
        "max_slippage": 15.0,  # Exceeds max 10%
    }
    result = validate_tool_input("execute_trade_bounded", tool_input)
    assert not result.is_valid
    assert result.failure_code == ValidationFailureCode.NUMERICAL_BOUND_VIOLATION
    assert result.failed_parameter == "max_slippage"


# ---------------------------------------------------------------------------
# Invalid Enum Values
# ---------------------------------------------------------------------------


def test_execute_trade_invalid_currency_fails():
    """execute_trade with unsupported currency fails."""
    tool_input = {
        "symbol": "AAPL",
        "amount": 1000.0,
        "currency": "BTC",  # Not in allowed set
    }
    result = validate_tool_input("execute_trade", tool_input)
    assert not result.is_valid
    assert result.failure_code == ValidationFailureCode.INVALID_ENUM_VALUE
    assert result.failed_parameter == "currency"
    assert "not in allowed set" in result.violations[0]


def test_execute_trade_invalid_order_type_fails():
    """execute_trade with invalid order_type fails."""
    tool_input = {
        "symbol": "AAPL",
        "amount": 1000.0,
        "currency": "USD",
        "order_type": "stop_loss",  # Not in allowed set
    }
    result = validate_tool_input("execute_trade", tool_input)
    assert not result.is_valid
    assert result.failure_code == ValidationFailureCode.INVALID_ENUM_VALUE
    assert result.failed_parameter == "order_type"


def test_write_db_invalid_operation_fails():
    """write_db with unsupported operation fails."""
    tool_input = {
        "table": "trades",
        "operation": "truncate",  # Not in allowed set
    }
    result = validate_tool_input("write_db", tool_input)
    assert not result.is_valid
    assert result.failure_code == ValidationFailureCode.INVALID_ENUM_VALUE
    assert result.failed_parameter == "operation"


# ---------------------------------------------------------------------------
# Pattern Validation Failures
# ---------------------------------------------------------------------------


def test_execute_trade_invalid_symbol_pattern_fails():
    """execute_trade with invalid symbol pattern fails."""
    tool_input = {
        "symbol": "apple123",  # Should be uppercase letters only
        "amount": 1000.0,
        "currency": "USD",
    }
    result = validate_tool_input("execute_trade", tool_input)
    assert not result.is_valid
    assert result.failure_code == ValidationFailureCode.FORBIDDEN_PAYLOAD_INJECTION
    assert result.failed_parameter == "symbol"
    assert "does not match required pattern" in result.violations[0]


def test_release_wire_invalid_wire_id_pattern_fails():
    """release_wire with malformed wire_id fails."""
    tool_input = {
        "wire_id": "INVALID-FORMAT",  # Should be WR-YYYYMMDD-XXXXXXXX
        "amount": 100000.0,
        "currency": "USD",
    }
    result = validate_tool_input("release_wire", tool_input)
    assert not result.is_valid
    assert result.failure_code == ValidationFailureCode.FORBIDDEN_PAYLOAD_INJECTION
    assert result.failed_parameter == "wire_id"


def test_write_db_invalid_table_name_pattern_fails():
    """write_db with invalid SQL table name fails."""
    tool_input = {
        "table": "DROP TABLE users;",  # SQL injection attempt
        "operation": "insert",
    }
    result = validate_tool_input("write_db", tool_input)
    assert not result.is_valid
    assert result.failure_code == ValidationFailureCode.FORBIDDEN_PAYLOAD_INJECTION
    assert result.failed_parameter == "table"


# ---------------------------------------------------------------------------
# Forbidden Payload Injection Patterns
# ---------------------------------------------------------------------------


def test_execute_trade_null_byte_injection_fails():
    """execute_trade with null byte in symbol fails (pattern check before forbidden pattern)."""
    tool_input = {
        "symbol": "AAPL\x00DROP",
        "amount": 1000.0,
        "currency": "USD",
    }
    result = validate_tool_input("execute_trade", tool_input)
    assert not result.is_valid
    assert result.failure_code == ValidationFailureCode.FORBIDDEN_PAYLOAD_INJECTION
    assert result.failed_parameter == "symbol"
    # Either pattern mismatch or forbidden pattern detected is acceptable
    assert "pattern" in result.violations[0].lower()


def test_execute_trade_path_traversal_injection_fails():
    """execute_trade with path traversal in currency fails (invalid enum first)."""
    tool_input = {
        "symbol": "AAPL",
        "amount": 1000.0,
        "currency": "../../etc/passwd",
    }
    result = validate_tool_input("execute_trade", tool_input)
    assert not result.is_valid
    # Currency is validated as enum before forbidden patterns, so INVALID_ENUM_VALUE
    assert result.failure_code == ValidationFailureCode.INVALID_ENUM_VALUE
    assert result.failed_parameter == "currency"


def test_write_db_sql_injection_attempt_fails():
    """write_db with SQL injection pattern fails."""
    tool_input = {
        "table": "trades; DROP TABLE users;--",
        "operation": "insert",
    }
    result = validate_tool_input("write_db", tool_input)
    assert not result.is_valid
    assert result.failure_code == ValidationFailureCode.FORBIDDEN_PAYLOAD_INJECTION


def test_execute_trade_governance_override_attempt_fails():
    """execute_trade with governance override pattern fails."""
    tool_input = {
        "symbol": "AAPL",
        "amount": 1000.0,
        "currency": "USD",
        "override_governance": "true",  # Forbidden control override
    }
    result = validate_tool_input("execute_trade", tool_input)
    assert not result.is_valid
    assert result.failure_code == ValidationFailureCode.FORBIDDEN_PAYLOAD_INJECTION


def test_execute_trade_ftra_bypass_attempt_fails():
    """execute_trade with FTRA bypass pattern fails."""
    tool_input = {
        "symbol": "AAPL",
        "amount": 1000.0,
        "currency": "USD",
        "bypass_ftra": "yes",
    }
    result = validate_tool_input("execute_trade", tool_input)
    assert not result.is_valid
    assert result.failure_code == ValidationFailureCode.FORBIDDEN_PAYLOAD_INJECTION


def test_execute_trade_python_import_injection_fails():
    """execute_trade with __import__ injection fails."""
    tool_input = {
        "symbol": "AAPL",
        "amount": 1000.0,
        "currency": "USD",
        "notes": "__import__('os').system('rm -rf /')",
    }
    result = validate_tool_input("execute_trade", tool_input)
    assert not result.is_valid
    assert result.failure_code == ValidationFailureCode.FORBIDDEN_PAYLOAD_INJECTION


def test_execute_trade_eval_injection_fails():
    """execute_trade with eval() injection fails."""
    tool_input = {
        "symbol": "AAPL",
        "amount": 1000.0,
        "currency": "USD",
        "notes": "eval('malicious code')",
    }
    result = validate_tool_input("execute_trade", tool_input)
    assert not result.is_valid
    assert result.failure_code == ValidationFailureCode.FORBIDDEN_PAYLOAD_INJECTION


# ---------------------------------------------------------------------------
# Regression Tests
# ---------------------------------------------------------------------------


def test_all_registered_actions_have_schemas():
    """Verify that test schemas are registered correctly."""
    # Actions with schemas (populated by register_test_schemas fixture)
    actions_with_schemas = set(ACTION_SCHEMAS.keys())
    expected_schemas = {
        "execute_trade",
        "execute_trade_bounded",
        "release_wire",
        "write_db",
    }
    assert actions_with_schemas == expected_schemas, f"Expected {expected_schemas}, got {actions_with_schemas}"


def test_backward_compatibility_extra_parameters_allowed():
    """Ensure backward compatibility: extra parameters are allowed in schemas."""
    tool_input = {
        "symbol": "AAPL",
        "amount": 1000.0,
        "currency": "USD",
        "extra_field": "should_not_break",
        "another_extra": 42,
    }
    result = validate_tool_input("execute_trade", tool_input)
    assert result.is_valid  # Extra params allowed for backward compatibility


def test_multiple_currencies_supported():
    """Test that all supported currencies pass validation."""
    for currency in ["USD", "EUR", "GBP", "JPY"]:
        tool_input = {
            "symbol": "AAPL",
            "amount": 1000.0,
            "currency": currency,
        }
        result = validate_tool_input("execute_trade", tool_input)
        assert result.is_valid, f"Currency {currency} should be valid"


def test_integer_amounts_accepted():
    """Ensure integer amounts are accepted (not just floats)."""
    tool_input = {
        "symbol": "AAPL",
        "amount": 1000,  # Integer, not float
        "currency": "USD",
    }
    result = validate_tool_input("execute_trade", tool_input)
    assert result.is_valid


def test_edge_case_minimum_amount():
    """Test minimum allowed amount (0.01)."""
    tool_input = {
        "symbol": "AAPL",
        "amount": 0.01,  # Exactly at minimum
        "currency": "USD",
    }
    result = validate_tool_input("execute_trade", tool_input)
    assert result.is_valid


def test_edge_case_maximum_amount():
    """Test maximum allowed amount (1,000,000)."""
    tool_input = {
        "symbol": "AAPL",
        "amount": 1_000_000.0,  # Exactly at maximum
        "currency": "USD",
    }
    result = validate_tool_input("execute_trade", tool_input)
    assert result.is_valid


def test_edge_case_just_over_maximum_amount():
    """Test amount just over maximum fails."""
    tool_input = {
        "symbol": "AAPL",
        "amount": 1_000_000.01,  # Just over maximum
        "currency": "USD",
    }
    result = validate_tool_input("execute_trade", tool_input)
    assert not result.is_valid
    assert result.failure_code == ValidationFailureCode.NUMERICAL_BOUND_VIOLATION
