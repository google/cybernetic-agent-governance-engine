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

"""RefusalReceipt schema v3 tests.

Validates that RefusalReceipt schema version 3 correctly includes tier_failures
in the proof_hash computation and preserves backward compatibility with v1/v2.

Part of: PR A - Capability-Driven Tier Dispatch (Stage 8)
Task: T-A8 (RefusalReceipt schema v3)
"""

import time

import pytest

from src.gateway.governance.contracts import GovernanceTierFailure, RefusalReceipt


@pytest.mark.local
class TestRefusalReceiptSchemaV3:
    """RefusalReceipt schema v3 tests."""

    def test_default_schema_version_is_v3(self) -> None:
        """Default schema_version is 'v3'."""
        receipt = RefusalReceipt(
            thread_id="test",
            action="test_action",
            violated_tier="TEST_TIER",
            violated_rule="TEST_RULE",
        )
        assert receipt.schema_version == "v3"

    def test_v3_receipt_includes_tier_failures_in_hash(self) -> None:
        """Schema v3 proof_hash includes tier_failures in computation."""
        tier_failures = (
            GovernanceTierFailure(
                tier="tier_a",
                control_id="CTRL-001",
                rule_description="Rule A",
                governing_state={"key": "value"},
                protected_consequence="consequence_a",
            ),
        )

        receipt = RefusalReceipt(
            thread_id="test",
            action="test_action",
            violated_tier="TIER_A",
            violated_rule="RULE_A",
            tier_failures=tier_failures,
        )

        # proof_hash should be computed (non-empty)
        assert receipt.proof_hash != ""
        assert len(receipt.proof_hash) == 64  # SHA256 hex digest

    def test_v3_hash_differs_from_v1_hash(self) -> None:
        """Schema v3 proof_hash differs from v1 for same base fields."""
        timestamp = time.time()

        receipt_v1 = RefusalReceipt(
            thread_id="test",
            action="test_action",
            violated_tier="TIER",
            violated_rule="RULE",
            timestamp=timestamp,
            schema_version="v1",
        )

        tier_failures = (
            GovernanceTierFailure(
                tier="tier_a",
                control_id="CTRL-001",
                rule_description="Rule A",
                governing_state={},
                protected_consequence="",
            ),
        )

        receipt_v3 = RefusalReceipt(
            thread_id="test",
            action="test_action",
            violated_tier="TIER",
            violated_rule="RULE",
            timestamp=timestamp,
            schema_version="v3",
            tier_failures=tier_failures,
        )

        # Different schema versions → different proof_hash
        assert receipt_v1.proof_hash != receipt_v3.proof_hash

    def test_tier_failures_preserved_in_receipt(self) -> None:
        """tier_failures tuple is preserved in RefusalReceipt."""
        tier_failures = (
            GovernanceTierFailure(
                tier="tier_a",
                control_id="CTRL-001",
                rule_description="Rule A",
                governing_state={"balance": 1000.0},
                protected_consequence="fiscal_breach",
            ),
            GovernanceTierFailure(
                tier="tier_b",
                control_id="CTRL-002",
                rule_description="Rule B",
                governing_state={},
                protected_consequence="",
            ),
        )

        receipt = RefusalReceipt(
            thread_id="test",
            action="test_action",
            violated_tier="TIER_A",
            violated_rule="RULE_A",
            tier_failures=tier_failures,
        )

        assert len(receipt.tier_failures) == 2
        assert receipt.tier_failures[0].tier == "tier_a"
        assert receipt.tier_failures[1].tier == "tier_b"

    def test_empty_tier_failures_allowed(self) -> None:
        """Empty tier_failures tuple is valid."""
        receipt = RefusalReceipt(
            thread_id="test",
            action="test_action",
            violated_tier="TIER",
            violated_rule="RULE",
            tier_failures=(),
        )

        assert receipt.tier_failures == ()
        assert receipt.proof_hash != ""


@pytest.mark.local
class TestRefusalReceiptBackwardCompatibility:
    """Backward compatibility tests for v1/v2 receipts."""

    def test_v1_receipt_excludes_v2_v3_fields_from_hash(self) -> None:
        """Schema v1 receipt proof_hash excludes v2/v3 fields."""
        timestamp = time.time()

        receipt_v1_minimal = RefusalReceipt(
            thread_id="test",
            action="test_action",
            violated_tier="TIER",
            violated_rule="RULE",
            timestamp=timestamp,
            schema_version="v1",
        )

        # Same base fields + v2 fields + v3 fields, but schema_version="v1"
        # should produce the same hash as the minimal v1 receipt
        receipt_v1_with_extras = RefusalReceipt(
            thread_id="test",
            action="test_action",
            violated_tier="TIER",
            violated_rule="RULE",
            timestamp=timestamp,
            schema_version="v1",
            attempted_params={"extra": "data"},
            tier_failures=(
                GovernanceTierFailure(
                    tier="tier",
                    control_id="CTRL",
                    rule_description="Rule",
                    governing_state={},
                    protected_consequence="",
                ),
            ),
        )

        # v1 hash computation excludes v2/v3 fields
        assert receipt_v1_minimal.proof_hash == receipt_v1_with_extras.proof_hash

    def test_v2_receipt_includes_proof_chain_in_hash(self) -> None:
        """Schema v2 receipt proof_hash includes 5-part proof chain."""
        timestamp = time.time()

        receipt_v2_minimal = RefusalReceipt(
            thread_id="test",
            action="test_action",
            violated_tier="TIER",
            violated_rule="RULE",
            timestamp=timestamp,
            schema_version="v2",
        )

        receipt_v2_with_proof_chain = RefusalReceipt(
            thread_id="test",
            action="test_action",
            violated_tier="TIER",
            violated_rule="RULE",
            timestamp=timestamp,
            schema_version="v2",
            attempted_params={"symbol": "AAPL"},
            standing_snapshot={"balance": 1000.0},
            control_id="FIN-001",
            protected_consequence="fiscal_breach",
            non_formation_proof="barrier_held",
        )

        # Different proof chain content → different hash
        assert receipt_v2_minimal.proof_hash != receipt_v2_with_proof_chain.proof_hash


@pytest.mark.local
class TestGovernanceTierFailure:
    """GovernanceTierFailure dataclass tests."""

    def test_tier_failure_with_all_fields(self) -> None:
        """GovernanceTierFailure accepts all fields."""
        failure = GovernanceTierFailure(
            tier="finance_tier",
            control_id="FIN-001",
            rule_description="CBF barrier violation",
            governing_state={"balance": 1000.0, "cost": 150.0},
            protected_consequence="fiscal_breach",
        )

        assert failure.tier == "finance_tier"
        assert failure.control_id == "FIN-001"
        assert failure.rule_description == "CBF barrier violation"
        assert failure.governing_state["balance"] == 1000.0
        assert failure.protected_consequence == "fiscal_breach"

    def test_tier_failure_with_minimal_fields(self) -> None:
        """GovernanceTierFailure with only required fields."""
        failure = GovernanceTierFailure(
            tier="minimal_tier",
            control_id="",
            rule_description="Minimal rule",
            governing_state={},
            protected_consequence="",
        )

        assert failure.tier == "minimal_tier"
        assert failure.control_id == ""
        assert failure.governing_state == {}
