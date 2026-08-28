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
tests/test_context_accumulator.py — Unit tests for the cryptographic hash-chained
Context Accumulator (CAGE v0.1.0).

Verification invariants (approved in CAGE v0.1.0 architectural review):
  1. Single-node chain round-trips correctly (append → verify_integrity passes).
  2. Multi-node chain (N findings) links correctly.
  3. CHAIN_SEALED sentinel increases length by 1 and embeds chain_root.
  4. Tamper detection: mutating payload at node_index=0 causes verify_integrity
     to return (False, 0) — the structural failure is caught at the mutated node.
  5. Subsequent-node tamper propagation: verify_integrity fails at node_index=1
     when node_index=0 is mutated (forward hash propagation breaks chain).
  6. Export NDJSON is valid JSON, one object per line, with correct schema field.
  7. Genesis seed is deterministically derived from audit_id (two accumulators
     with the same audit_id start with the same prev_hash).
  8. Empty accumulator: verify_integrity returns (True, 0).
  9. chain_root() on empty accumulator returns sha256(audit_id).
"""

from __future__ import annotations

import json

import pytest

from src.compliance_bridge.context_accumulator import (
    ContextAccumulator,
    _sha256,
)
from src.compliance_bridge.types import OscalFinding

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _finding(control_id: str = "A.5.3", result: str = "PASS") -> OscalFinding:
    return OscalFinding(
        control_id=control_id,
        result=result,  # type: ignore[arg-type]
        finding_id=f"finding-{control_id}-001",
        safety_rate=1.0 if result == "PASS" else 0.0,
        evidence_age_s=300.0,
    )


# ---------------------------------------------------------------------------
# Test 1: Empty chain
# ---------------------------------------------------------------------------


def test_empty_chain_verify_integrity_passes():
    """Empty accumulator reports chain valid with zero nodes."""
    acc = ContextAccumulator(audit_id="empty-audit-001")
    valid, count = acc.verify_integrity()
    assert valid is True
    assert count == 0


def test_empty_chain_root_is_audit_id_hash():
    """chain_root() on an empty accumulator equals sha256(audit_id)."""
    audit_id = "empty-audit-002"
    acc = ContextAccumulator(audit_id=audit_id)
    expected = _sha256(audit_id)
    assert acc.chain_root() == expected


# ---------------------------------------------------------------------------
# Test 2: Single-node chain
# ---------------------------------------------------------------------------


def test_single_node_chain_round_trips():
    """Appending one finding creates a valid single-node chain."""
    acc = ContextAccumulator(audit_id="single-audit-001")
    acc.append_finding(_finding())

    assert acc.length == 1
    valid, count = acc.verify_integrity()
    assert valid is True
    assert count == 1


def test_single_node_record_hash_is_deterministic():
    """The same finding appended twice (different accumulators) produces the same hash."""
    f = _finding("A.5.3", "PASS")

    acc1 = ContextAccumulator(audit_id="det-audit-001")
    acc2 = ContextAccumulator(audit_id="det-audit-001")  # same audit_id

    e1 = acc1.append_finding(f)
    e2 = acc2.append_finding(f)

    assert e1.record_hash == e2.record_hash


# ---------------------------------------------------------------------------
# Test 3: Multi-node chain
# ---------------------------------------------------------------------------


def test_multi_node_chain_verify_integrity_passes():
    """Multi-finding chain (5 nodes) verifies as intact."""
    acc = ContextAccumulator(audit_id="multi-audit-001")
    controls = ["A.5.2", "A.5.3", "SC-4", "A.8.4", "A.9.2"]
    for ctrl in controls:
        acc.append_finding(_finding(ctrl))

    assert acc.length == 5
    valid, count = acc.verify_integrity()
    assert valid is True
    assert count == 5


def test_multi_node_prev_hash_links_correctly():
    """Each node's prev_hash equals the preceding node's record_hash."""
    acc = ContextAccumulator(audit_id="link-audit-001")
    acc.append_finding(_finding("A.5.3"))
    acc.append_finding(_finding("SC-4"))

    entries = acc.entries
    assert entries[1].prev_hash == entries[0].record_hash


# ---------------------------------------------------------------------------
# Test 4: CHAIN_SEALED sentinel
# ---------------------------------------------------------------------------


def test_seal_appends_sentinel_node():
    """seal() appends a CHAIN_SEALED node, increasing length by 1."""
    acc = ContextAccumulator(audit_id="seal-audit-001")
    acc.append_finding(_finding())
    pre_length = acc.length

    acc.seal()
    assert acc.length == pre_length + 1
    assert acc.entries[-1].event_type == "CHAIN_SEALED"


def test_sealed_chain_verify_integrity_passes():
    """A sealed chain (findings + sentinel) passes full integrity verification."""
    acc = ContextAccumulator(audit_id="seal-integrity-001")
    for ctrl in ["A.5.3", "SC-4", "A.8.4"]:
        acc.append_finding(_finding(ctrl))
    acc.seal()

    valid, count = acc.verify_integrity()
    assert valid is True
    assert count == 4  # 3 findings + 1 sentinel


def test_seal_payload_contains_chain_root():
    """The CHAIN_SEALED sentinel payload includes the chain_root hash."""
    acc = ContextAccumulator(audit_id="seal-root-001")
    acc.append_finding(_finding())
    root_before_seal = acc.chain_root()
    acc.seal()

    sentinel_payload = acc.entries[-1].payload
    assert sentinel_payload["chain_root"] == root_before_seal


# ---------------------------------------------------------------------------
# Test 5 (CRITICAL): Tamper detection at node_index=0
# ---------------------------------------------------------------------------


def test_tamper_node0_detected_at_node0():
    """Mutating node 0's payload causes verify_integrity to fail at node 0.

    This is the critical invariant required by the CAGE v0.1.0 architectural
    review: the structural failure must be caught at the mutated node.
    """
    acc = ContextAccumulator(audit_id="tamper-audit-001")
    acc.append_finding(_finding("A.5.3", "PASS"))
    acc.append_finding(_finding("SC-4", "PASS"))
    acc.append_finding(_finding("A.8.4", "PASS"))

    # Mutate node 0 payload DIRECTLY (simulates a post-hoc edit)
    acc._entries[0].payload["result"] = "TAMPERED"

    valid, fail_at = acc.verify_integrity()

    assert valid is False, "Chain should be invalid after tampering node 0"
    assert fail_at == 0, (
        f"Structural failure must be caught at node 0, not node {fail_at}"
    )


def test_tamper_node0_propagates_failure_to_node1():
    """Mutating node 0 also invalidates node 1 (forward hash propagation).

    verify_integrity() returns failure at node 0 (the root cause). This test
    confirms the failure detection occurs BEFORE node 1 is examined (i.e., the
    function returns early at node 0, so fail_at=0, not 1).
    """
    acc = ContextAccumulator(audit_id="tamper-propagate-001")
    acc.append_finding(_finding("A.5.3"))
    acc.append_finding(_finding("SC-4"))

    # Mutate node 0's record_hash to simulate a sophisticated tampering attempt
    # where the attacker also updates the hash but not the actual content.
    acc._entries[0].record_hash = _sha256("FAKE_HASH_INJECTED")

    valid, fail_at = acc.verify_integrity()

    assert valid is False
    # The mismatch is detected at node 0 because its record_hash doesn't match
    # the recomputed value from the unmodified payload.
    assert fail_at == 0


def test_tamper_middle_node_detected_at_correct_index():
    """Mutating node 2 (in a 4-node chain) is detected at node 2."""
    acc = ContextAccumulator(audit_id="tamper-middle-001")
    for ctrl in ["A.5.2", "A.5.3", "SC-4", "A.8.4"]:
        acc.append_finding(_finding(ctrl))

    # Tamper node 2
    acc._entries[2].payload["safety_rate"] = 999.0

    valid, fail_at = acc.verify_integrity()
    assert valid is False
    assert fail_at == 2


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("control_id", "A.9.9"),
        ("event_type", "CHAIN_SEALED"),
        ("node_index", 99),
        ("audit_id", "some-other-audit"),
        ("content_hash", "0" * 64),
    ],
)
def test_tamper_node_metadata_detected(field, value):
    """Mutating a committed metadata field is detected, not just the payload.

    Every field here is serialised by to_dict() into the persisted NDJSON, so
    each one must be bound into record_hash for the chain to be tamper-evident.
    """
    acc = ContextAccumulator(audit_id="tamper-meta-001")
    acc.append_finding(_finding("A.5.3", "PASS"))
    acc.append_finding(_finding("SC-4", "PASS"))

    setattr(acc._entries[0], field, value)

    valid, fail_at = acc.verify_integrity()
    assert valid is False, f"Mutating {field} must invalidate the chain"
    assert fail_at == 0


# ---------------------------------------------------------------------------
# Test 6: NDJSON export
# ---------------------------------------------------------------------------


def test_export_ndjson_is_valid_json():
    """NDJSON export produces one parseable JSON object per line."""
    acc = ContextAccumulator(audit_id="ndjson-audit-001")
    acc.append_finding(_finding("A.5.3"))
    acc.append_finding(_finding("SC-4"))
    acc.seal()

    ndjson = acc.export_ndjson()
    lines = [l for l in ndjson.strip().splitlines() if l.strip()]
    assert len(lines) == 3  # 2 findings + 1 seal

    for line in lines:
        obj = json.loads(line)
        assert obj["schema"] == "cage-context-accumulator/2.0"
        assert "record_hash" in obj
        assert "prev_hash" in obj
        assert "node_index" in obj


def test_export_ndjson_node_index_sequential():
    """Node indices in NDJSON export are strictly sequential from 0."""
    acc = ContextAccumulator(audit_id="ndjson-seq-001")
    for i in range(5):
        acc.append_finding(_finding(f"ctrl-{i}"))

    ndjson = acc.export_ndjson()
    indices = [json.loads(l)["node_index"] for l in ndjson.strip().splitlines()]
    assert indices == list(range(5))


# ---------------------------------------------------------------------------
# Test 7: Genesis determinism
# ---------------------------------------------------------------------------


def test_same_audit_id_produces_same_genesis():
    """Two accumulators with the same audit_id start with identical genesis."""
    audit_id = "genesis-det-001"
    acc1 = ContextAccumulator(audit_id=audit_id)
    acc2 = ContextAccumulator(audit_id=audit_id)

    # Before any appends, chain_root should equal sha256(audit_id) for both
    assert acc1.chain_root() == acc2.chain_root() == _sha256(audit_id)


def test_different_audit_id_produces_different_genesis():
    """Two accumulators with different audit_ids start with different genesis hashes."""
    acc1 = ContextAccumulator(audit_id="genesis-diff-001")
    acc2 = ContextAccumulator(audit_id="genesis-diff-002")
    assert acc1.chain_root() != acc2.chain_root()


pytestmark = [pytest.mark.unit, pytest.mark.local]
