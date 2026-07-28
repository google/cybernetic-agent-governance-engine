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

"""Tests for provenance chain — AI 600-1 §2.7 (Information Integrity).

POAM: AI600-005
Phase: 2 (core hardening)
"""

import pytest

from src.gateway.governance.provenance_chain import (
    VALID_DECISIONS,
    build_provenance_record,
    compute_hash,
    verify_chain_integrity,
)


class TestComputeHash:
    """compute_hash must be deterministic and produce valid SHA-256 digests."""

    def test_deterministic_for_identical_inputs(self):
        """compute_hash returns the same hash for identical inputs."""
        data = {"action": "execute_trade", "amount": 5000, "symbol": "AAPL"}
        hash1 = compute_hash(data)
        hash2 = compute_hash(data)
        assert hash1 == hash2

    def test_different_inputs_produce_different_hashes(self):
        """compute_hash returns different hashes for different inputs."""
        data1 = {"action": "execute_trade", "amount": 5000}
        data2 = {"action": "execute_trade", "amount": 6000}
        assert compute_hash(data1) != compute_hash(data2)

    def test_hash_is_64_char_hex(self):
        """compute_hash returns a 64-character lowercase hex string (SHA-256)."""
        data = {"key": "value"}
        h = compute_hash(data)
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_key_order_does_not_affect_hash(self):
        """compute_hash is order-independent (keys are sorted)."""
        data1 = {"b": 2, "a": 1}
        data2 = {"a": 1, "b": 2}
        assert compute_hash(data1) == compute_hash(data2)

    def test_empty_dict_produces_valid_hash(self):
        """compute_hash handles empty dict without error."""
        h = compute_hash({})
        assert len(h) == 64


class TestBuildProvenanceRecord:
    """build_provenance_record must create correct ProvenanceRecord instances."""

    def test_builds_record_with_correct_fields(self):
        """build_provenance_record returns a ProvenanceRecord with all fields."""
        record = build_provenance_record(
            trace_id="trace-001",
            node_id="opa_node",
            input_data={"action": "execute_trade", "amount": 5000},
            output_data={"decision": "ALLOW"},
            decision="ALLOW",
            parent_hash=None,
        )
        assert record.trace_id == "trace-001"
        assert record.node_id == "opa_node"
        assert record.decision == "ALLOW"
        assert record.parent_hash is None

    def test_input_hash_is_sha256(self):
        """build_provenance_record computes SHA-256 input hash."""
        record = build_provenance_record(
            trace_id="trace-002",
            node_id="causal_gatekeeper",
            input_data={"amount": 5000},
            output_data={"safe": True},
            decision="ALLOW",
        )
        assert len(record.input_hash) == 64

    def test_output_hash_is_sha256(self):
        """build_provenance_record computes SHA-256 output hash."""
        record = build_provenance_record(
            trace_id="trace-003",
            node_id="consensus_engine",
            input_data={"amount": 15000},
            output_data={"status": "ESCALATE"},
            decision="ESCALATE",
        )
        assert len(record.output_hash) == 64

    def test_parent_hash_linked_correctly(self):
        """build_provenance_record links parent_hash to the previous record."""
        record1 = build_provenance_record(
            trace_id="trace-004",
            node_id="opa_node",
            input_data={"action": "execute_trade"},
            output_data={"decision": "ALLOW"},
            decision="ALLOW",
            parent_hash=None,
        )
        record2 = build_provenance_record(
            trace_id="trace-004",
            node_id="causal_gatekeeper",
            input_data={"amount": 5000},
            output_data={"safe": True},
            decision="ALLOW",
            parent_hash=record1.chain_hash(),
        )
        assert record2.parent_hash == record1.chain_hash()

    def test_invalid_decision_raises_value_error(self):
        """build_provenance_record raises ValueError for invalid decision."""
        with pytest.raises(ValueError, match="Invalid decision"):
            build_provenance_record(
                trace_id="trace-005",
                node_id="opa_node",
                input_data={},
                output_data={},
                decision="APPROVE",  # not a valid decision
            )

    def test_valid_decisions_are_allow_block_escalate_require_approval_defer(self):
        """VALID_DECISIONS contains exactly ALLOW, BLOCK, ESCALATE, REQUIRE_APPROVAL, DEFER."""
        assert VALID_DECISIONS == frozenset(
            {"ALLOW", "BLOCK", "ESCALATE", "REQUIRE_APPROVAL", "DEFER"}
        )

    def test_all_valid_decisions_accepted(self):
        """build_provenance_record accepts all valid decision values."""
        for decision in ["ALLOW", "BLOCK", "ESCALATE", "REQUIRE_APPROVAL", "DEFER"]:
            record = build_provenance_record(
                trace_id="trace-006",
                node_id="test_node",
                input_data={},
                output_data={},
                decision=decision,
            )
            assert record.decision == decision


class TestVerifyChainIntegrity:
    """verify_chain_integrity must detect broken chain links."""

    def test_empty_chain_is_valid(self):
        """verify_chain_integrity returns True for an empty chain."""
        assert verify_chain_integrity([]) is True

    def test_single_record_chain_is_valid(self):
        """verify_chain_integrity returns True for a single-record chain."""
        record = build_provenance_record(
            trace_id="trace-007",
            node_id="opa_node",
            input_data={},
            output_data={},
            decision="ALLOW",
            parent_hash=None,
        )
        assert verify_chain_integrity([record]) is True

    def test_valid_two_record_chain(self):
        """verify_chain_integrity returns True for a valid 2-record chain."""
        record1 = build_provenance_record(
            trace_id="trace-008",
            node_id="opa_node",
            input_data={"action": "execute_trade"},
            output_data={"decision": "ALLOW"},
            decision="ALLOW",
            parent_hash=None,
        )
        record2 = build_provenance_record(
            trace_id="trace-008",
            node_id="causal_gatekeeper",
            input_data={"amount": 5000},
            output_data={"safe": True},
            decision="ALLOW",
            parent_hash=record1.chain_hash(),
        )
        assert verify_chain_integrity([record1, record2]) is True

    def test_broken_chain_detected(self):
        """verify_chain_integrity returns False when parent_hash is wrong."""
        record1 = build_provenance_record(
            trace_id="trace-009",
            node_id="opa_node",
            input_data={},
            output_data={},
            decision="ALLOW",
            parent_hash=None,
        )
        record2 = build_provenance_record(
            trace_id="trace-009",
            node_id="causal_gatekeeper",
            input_data={},
            output_data={},
            decision="ALLOW",
            parent_hash="a" * 64,  # wrong parent hash
        )
        assert verify_chain_integrity([record1, record2]) is False

    def test_first_record_must_have_no_parent(self):
        """verify_chain_integrity returns False if first record has a parent_hash."""
        record = build_provenance_record(
            trace_id="trace-010",
            node_id="opa_node",
            input_data={},
            output_data={},
            decision="ALLOW",
            parent_hash="a" * 64,  # first record must have None parent
        )
        assert verify_chain_integrity([record]) is False

    def test_ten_record_chain_integrity(self):
        """verify_chain_integrity validates a 10-record chain (full pipeline run)."""
        node_names = [
            "opa_node",
            "causal_gatekeeper",
            "consensus_engine",
            "nemo_guardrails",
            "pii_sanitizer",
            "routing_seal",
            "confabulation_scorer",
            "hitl_escalator",
            "provenance_chain",
            "audit_logger",
        ]
        records = []
        parent_hash = None
        for i, node_id in enumerate(node_names):
            record = build_provenance_record(
                trace_id="trace-011",
                node_id=node_id,
                input_data={"step": i},
                output_data={"result": "ok"},
                decision="ALLOW",
                parent_hash=parent_hash,
            )
            records.append(record)
            parent_hash = record.chain_hash()

        assert len(records) == 10
        assert verify_chain_integrity(records) is True
