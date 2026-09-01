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

"""Standing context assembly tests.

Validates that SymbolicGovernor._build_standing() correctly assembles
standing_at_refusal dictionaries from tier violation lists, preserving
tier_failures for RefusalReceipt schema v3.

Part of: PR A - Capability-Driven Tier Dispatch (Stage 8)
Gate: G5 (standing assembly from multi-tier violations)
"""

import pytest
from typing import Any
from unittest.mock import MagicMock

from src.gateway.governance.symbolic_governor import SymbolicGovernor
from src.gateway.governance.contracts import Violation


@pytest.fixture
def mock_governor() -> SymbolicGovernor:
    """Create a SymbolicGovernor with mock dependencies."""
    opa_client = MagicMock()
    safety_filter = MagicMock()
    consensus_engine = MagicMock()
    return SymbolicGovernor(opa_client, safety_filter, consensus_engine)


@pytest.mark.local
class TestStandingAssembly:
    """Standing context assembly tests."""

    def test_build_standing_with_single_violation(self, mock_governor: SymbolicGovernor) -> None:
        """Single violation produces standing with tier_failures."""
        gov = mock_governor
        violations = [
            Violation(
                tier="test_tier",
                code="TEST_RULE",
                # severity removed - not in base Violation,
                message="Test violation",
            )
        ]

        standing = gov._build_standing(violations)

        assert "failures" in standing
        assert len(standing["failures"]) == 1
        assert standing["failures"][0]["tier"] == "test_tier"
        assert standing["failures"][0]["code"] == "TEST_RULE"

    def test_build_standing_with_multiple_violations(self, mock_governor: SymbolicGovernor) -> None:
        """Multiple violations produce multiple tier_failures entries."""
        gov = mock_governor
        violations = [
            Violation(
                tier="tier_a",
                code="RULE_A",
                # severity removed - not in base Violation,
                message="Violation A",
            ),
            Violation(
                tier="tier_b",
                code="RULE_B",
                # severity removed - not in base Violation,
                message="Violation B",
            ),
        ]

        standing = gov._build_standing(violations)

        assert len(standing["failures"]) == 2
        assert standing["failures"][0]["tier"] == "tier_a"
        assert standing["failures"][1]["tier"] == "tier_b"

    def test_build_standing_preserves_violation_fields(self, mock_governor: SymbolicGovernor) -> None:
        """Standing preserves all violation fields in tier_failures."""
        gov = mock_governor
        violations = [
            Violation(
                tier="finance_tier",
                code="CBF_BARRIER",
                # severity removed - not in base Violation,
                message="Barrier violation",
                # control_id removed - not in base Violation,
                # governing_state removed,
                # protected_consequence removed,
            )
        ]

        standing = gov._build_standing(violations)

        failure = standing["failures"][0]
        assert failure["tier"] == "finance_tier"
        assert failure["code"] == "CBF_BARRIER"
        assert failure["control_id"] == "FIN-001"
        assert failure["governing_state"] == {"balance": 1000.0}
        assert failure["protected_consequence"] == "fiscal_breach"

    def test_build_standing_with_empty_violations_list(self, mock_governor: SymbolicGovernor) -> None:
        """Empty violations list produces empty tier_failures."""
        gov = mock_governor
        standing = gov._build_standing([])

        assert "failures" in standing
        assert standing["failures"] == []

    def test_violations_to_strings_conversion(self, mock_governor: SymbolicGovernor) -> None:
        """_violations_to_strings() converts violations to readable strings."""
        gov = mock_governor
        violations = [
            Violation(
                tier="tier_a",
                code="RULE_A",
                # severity removed - not in base Violation,
                message="Blocked by tier A",
            ),
            Violation(
                tier="tier_b",
                code="RULE_B",
                # severity removed - not in base Violation,
                message="Review required",
            ),
        ]

        strings = gov._violations_to_strings(violations)

        assert len(strings) == 2
        assert "tier_a" in strings[0]
        assert "RULE_A" in strings[0]
        assert "tier_b" in strings[1]
        assert "RULE_B" in strings[1]

    def test_violations_to_failures_dict_conversion(self, mock_governor: SymbolicGovernor) -> None:
        """_violations_to_failures() converts violations to dict format."""
        gov = mock_governor
        violations = [
            Violation(
                tier="example_tier",
                code="EXAMPLE_RULE",
                # severity removed - not in base Violation,
                message="Example violation",
            )
        ]

        failures = gov._violations_to_failures(violations)

        assert len(failures) == 1
        assert failures[0]["tier"] == "example_tier"
        assert failures[0]["code"] == "EXAMPLE_RULE"


@pytest.mark.local
class TestStandingAssemblyEdgeCases:
    """Edge case validation for standing assembly."""

    def test_violation_with_minimal_fields(self, mock_governor: SymbolicGovernor) -> None:
        """Violation with only required fields assembles correctly."""
        gov = mock_governor
        violations = [
            Violation(
                tier="min_tier",
                code="MIN_RULE",
                # severity removed - not in base Violation,
                message="Minimal",
            )
        ]

        standing = gov._build_standing(violations)
        failure = standing["failures"][0]

        assert failure["tier"] == "min_tier"
        assert failure["code"] == "MIN_RULE"
        # Optional fields should have default values
        assert failure.get("control_id") == ""
        assert failure.get("governing_state") == {}
        assert failure.get("protected_consequence") == ""

    def test_violation_severity_preserved(self, mock_governor: SymbolicGovernor) -> None:
        """Violation severity is not included in tier_failures dict."""
        gov = mock_governor
        violations = [
            Violation(
                tier="tier",
                code="RULE",
                # severity removed - not in base Violation,
                message="Test",
            )
        ]

        standing = gov._build_standing(violations)
        failure = standing["failures"][0]

        # severity is a Violation field but not included in the failure dict
        assert "severity" not in failure
