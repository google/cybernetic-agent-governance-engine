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
tests/test_kms_evidence_signing.py — Tests for per-record KMS attestation
on evidence chain records (Feature 3 of NexArt integration).

Verification invariants:
  1. kms_sign=False (default) produces no kms_signature field — backward compat.
  2. kms_sign=True enqueues records to the AsyncBatchSigner ring buffer.
  3. After batch signer drain, kms_signature is populated on all entries.
  4. kms_signature appears in NDJSON export only when non-empty.
  5. verify_integrity still passes regardless of kms_signature state.
  6. AsyncBatchSigner lifecycle: start, enqueue, drain, stop.
  7. AsyncBatchSigner handles signing failures gracefully (failed_count increments).
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from src.compliance_bridge.context_accumulator import (
    ContextAccumulator,
    _sha256,
)
from src.compliance_bridge.kms_batch_signer import (
    AsyncBatchSigner,
    PendingSignatureRecord,
)
from src.compliance_bridge.types import OscalFinding

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _finding(control_id: str = "A.5.3", result: str = "PASS") -> OscalFinding:
    return OscalFinding(
        control_id=control_id,
        result=result,  # type: ignore[arg-type]
        finding_id=f"finding-{control_id}-kms",
        safety_rate=1.0 if result == "PASS" else 0.0,
        evidence_age_s=300.0,
    )


def _mock_signer():
    """Create a mock KMSGovernanceSigner that returns deterministic signatures."""
    signer = MagicMock()
    signer.sign.side_effect = lambda payload: (
        "mock_kms_sig_" + _sha256(json.dumps(payload, sort_keys=True))[:16]
    )
    signer.is_kms_active = True
    return signer


# ---------------------------------------------------------------------------
# Test 1: Default behavior (kms_sign=False) — backward compatibility
# ---------------------------------------------------------------------------


def test_default_no_kms_signature():
    """With kms_sign=False (default), entries have empty kms_signature."""
    acc = ContextAccumulator(audit_id="kms-default-001")
    entry = acc.append_finding(_finding())

    assert entry.kms_signature == ""


def test_default_ndjson_omits_kms_field():
    """NDJSON export omits kms_signature when it is empty."""
    acc = ContextAccumulator(audit_id="kms-ndjson-omit-001")
    acc.append_finding(_finding())
    acc.seal()

    ndjson = acc.export_ndjson()
    for line in ndjson.strip().splitlines():
        obj = json.loads(line)
        assert "kms_signature" not in obj


# ---------------------------------------------------------------------------
# Test 2: kms_sign=True enqueues to batch signer
# ---------------------------------------------------------------------------


def test_kms_sign_enqueues_record():
    """With kms_sign=True, _append_node calls _enqueue_for_signing."""
    with patch("src.compliance_bridge.kms_batch_signer.get_batch_signer") as mock_get:
        mock_signer_instance = MagicMock()
        mock_get.return_value = mock_signer_instance

        acc = ContextAccumulator(audit_id="kms-enqueue-001", kms_sign=True)
        acc.append_finding(_finding())

        mock_signer_instance.enqueue.assert_called_once()
        call_args = mock_signer_instance.enqueue.call_args
        assert "record_hash" in call_args.kwargs or len(call_args.args) >= 1


# ---------------------------------------------------------------------------
# Test 3: AsyncBatchSigner lifecycle
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_batch_signer_start_stop():
    """AsyncBatchSigner can start and stop cleanly."""
    signer = AsyncBatchSigner(flush_interval_ms=50, max_batch_size=10)
    await signer.start()
    assert signer.is_running is True

    await signer.stop()
    assert signer.is_running is False


@pytest.mark.asyncio
async def test_batch_signer_enqueue_and_drain():
    """Records enqueued to the batch signer are signed after drain."""
    signer = AsyncBatchSigner(flush_interval_ms=50, max_batch_size=10)
    mock_kms = _mock_signer()

    # Inject mock signer
    signer._signer = mock_kms

    results: dict[str, str] = {}

    def on_signed(record_hash: str, signature: str) -> None:
        results[record_hash] = signature

    # Enqueue 3 records
    for i in range(3):
        signer.enqueue(
            record_hash=f"hash_{i}",
            payload={"index": i},
            callback=on_signed,
        )

    assert signer.pending_count == 3

    # Drain synchronously
    count = await signer.drain()

    assert count == 3
    assert signer.pending_count == 0
    assert signer.signed_count == 3
    assert len(results) == 3
    assert all(sig.startswith("mock_kms_sig_") for sig in results.values())


@pytest.mark.asyncio
async def test_batch_signer_handles_signing_failure():
    """When KMS signing fails, failed_count increments and the signer continues."""
    signer = AsyncBatchSigner(flush_interval_ms=50, max_batch_size=10)
    mock_kms = MagicMock()
    mock_kms.sign.side_effect = RuntimeError("KMS unavailable")
    signer._signer = mock_kms

    signer.enqueue(
        record_hash="fail_hash_001",
        payload={"test": "failure"},
    )

    await signer.drain()

    assert signer.failed_count == 1
    assert signer.signed_count == 0


# ---------------------------------------------------------------------------
# Test 4: NDJSON export includes kms_signature when present
# ---------------------------------------------------------------------------


def test_ndjson_includes_kms_signature_when_populated():
    """NDJSON export includes kms_signature field when it is non-empty."""
    acc = ContextAccumulator(audit_id="kms-ndjson-include-001")
    entry = acc.append_finding(_finding())

    # Simulate async signing completion
    entry.kms_signature = "deadbeef1234567890"

    ndjson = acc.export_ndjson()
    obj = json.loads(ndjson.strip())
    assert obj["kms_signature"] == "deadbeef1234567890"


# ---------------------------------------------------------------------------
# Test 5: verify_integrity passes regardless of kms_signature
# ---------------------------------------------------------------------------


def test_verify_integrity_with_kms_signature():
    """Chain integrity verification passes even with kms_signature populated."""
    acc = ContextAccumulator(audit_id="kms-integrity-001")
    acc.append_finding(_finding("A.5.3"))
    acc.append_finding(_finding("SC-4"))
    acc.seal()

    # Simulate async signing on all entries
    for e in acc.entries:
        e.kms_signature = "mock_sig_" + e.record_hash[:8]

    valid, count = acc.verify_integrity()
    assert valid is True
    assert count == 3  # 2 findings + seal


def test_verify_integrity_without_kms_signature():
    """Chain integrity verification still works without kms_signature (default)."""
    acc = ContextAccumulator(audit_id="kms-integrity-no-sig-001")
    acc.append_finding(_finding("A.5.3"))
    acc.append_finding(_finding("SC-4"))

    valid, count = acc.verify_integrity()
    assert valid is True
    assert count == 2


# ---------------------------------------------------------------------------
# Test 6: End-to-end — accumulator with kms_sign + batch signer drain
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_e2e_accumulator_with_batch_signer():
    """End-to-end: kms_sign=True accumulator + batch signer produces signed records."""
    mock_kms = _mock_signer()

    with patch(
        "src.gateway.governance.kms_signer.get_governance_signer",
        return_value=mock_kms,
    ):
        # Reset the module-level singleton for test isolation
        import src.compliance_bridge.kms_batch_signer as bsm

        bsm._batch_signer = None

        signer = bsm.get_batch_signer()
        signer._signer = mock_kms

        acc = ContextAccumulator(audit_id="e2e-kms-001", kms_sign=True)
        acc.append_finding(_finding("A.5.3"))
        acc.append_finding(_finding("SC-4"))
        acc.append_finding(_finding("A.9.2"))

        assert signer.pending_count == 3

        # Drain — this calls sign() on each record
        count = await signer.drain()
        assert count == 3

        # All entries should now have kms_signature populated
        for entry in acc.entries:
            assert entry.kms_signature != "", (
                f"Entry {entry.node_index} missing kms_signature after drain"
            )
            assert entry.kms_signature.startswith("mock_kms_sig_")

        # Chain integrity should still pass
        valid, node_count = acc.verify_integrity()
        assert valid is True
        assert node_count == 3

        # NDJSON should include the signatures
        ndjson = acc.export_ndjson()
        for line in ndjson.strip().splitlines():
            obj = json.loads(line)
            assert "kms_signature" in obj

        # Clean up singleton
        bsm._batch_signer = None


# ---------------------------------------------------------------------------
# Test 7: PendingSignatureRecord defaults
# ---------------------------------------------------------------------------


def test_pending_record_defaults():
    """PendingSignatureRecord has correct defaults."""
    record = PendingSignatureRecord(
        record_hash="test_hash",
        payload={"test": True},
    )
    assert record.callback is None
    assert record.enqueued_at > 0


pytestmark = [pytest.mark.unit, pytest.mark.local]
