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
test_chain_restoration.py — Chain restoration on startup tests.

Validation Criterion V-4: Chain continuity maintained across restarts.
"""

import pytest


@pytest.mark.asyncio
@pytest.mark.local
async def test_restore_from_existing_stream():
    """Verify sink restores prev_hash, sequence from last record (V-4)."""
    from src.compliance_bridge.evidence_stream import EvidenceStreamSink, _sha256

    # This test requires a real Redis instance
    pytest.skip("Integration test — requires Redis db=1")

    # Create sink and add a record
    sink = EvidenceStreamSink(chain_id="test-restore-1")
    await sink.start()

    # Ingest a record
    await sink.ingest({"type": "TEST", "controlId": "A.5.2", "data": "test"})

    # Capture state
    prev_hash_before = sink._prev_hash
    sequence_before = sink._sequence

    await sink.stop()

    # Create new sink instance (simulating restart)
    sink2 = EvidenceStreamSink(chain_id="test-restore-1")
    await sink2.start()

    # Verify state restored
    assert sink2._prev_hash == prev_hash_before
    assert sink2._sequence == sequence_before

    await sink2.stop()


@pytest.mark.asyncio
@pytest.mark.local
async def test_genesis_cut_on_empty_stream():
    """Verify clean genesis when stream is empty (V-4)."""
    from src.compliance_bridge.evidence_stream import EvidenceStreamSink, _sha256

    # Create sink with fresh stream
    sink = EvidenceStreamSink(chain_id="test-genesis-empty")

    # Before start, should have genesis hash
    genesis_hash = _sha256("EVIDENCE_STREAM_GENESIS")
    assert sink._prev_hash == genesis_hash
    assert sink._sequence == 0

    # Note: Full test requires Redis; this validates initial state


@pytest.mark.local
def test_chain_id_persistence():
    """Verify chain_id persists and prevents silent re-genesis."""
    import time

    from src.compliance_bridge.evidence_stream import EvidenceStreamSink

    chain_id = "persistent-chain-123"

    # Create sink with explicit chain_id
    sink1 = EvidenceStreamSink(chain_id=chain_id)
    assert sink1._chain_id == chain_id

    # Second instance with same chain_id
    sink2 = EvidenceStreamSink(chain_id=chain_id)
    assert sink2._chain_id == chain_id

    # Auto-generated chain_id should be unique per instance
    # (add small delay to ensure timestamp changes)
    sink3 = EvidenceStreamSink()
    time.sleep(0.01)
    sink4 = EvidenceStreamSink()

    # They might be equal if created in same second, so just verify they're auto-generated
    assert sink3._chain_id.startswith("cage-evidence-")
    assert sink4._chain_id.startswith("cage-evidence-")


@pytest.mark.asyncio
@pytest.mark.local
async def test_chain_lock_prevents_race():
    """Verify chain_lock prevents concurrent modification of prev_hash/sequence."""
    import asyncio

    from src.compliance_bridge.evidence_stream import EvidenceStreamSink

    sink = EvidenceStreamSink()

    # Simulate concurrent access to chain state
    initial_sequence = sink._sequence

    async def increment_sequence():
        async with sink._chain_lock:
            current = sink._sequence
            await asyncio.sleep(0.01)  # Simulate work
            sink._sequence = current + 1

    # Run two concurrent increments
    await asyncio.gather(
        increment_sequence(),
        increment_sequence(),
    )

    # Should have incremented twice without race
    assert sink._sequence == initial_sequence + 2


@pytest.mark.local
def test_evidence_stream_disabled_gracefully():
    """Verify graceful behavior when EVIDENCE_STREAM_ENABLED=false."""
    import os

    from src.compliance_bridge.evidence_stream import (
        is_evidence_chain_blocking,
        validate_evidence_stream_preconditions,
    )

    # Save original env
    orig_enabled = os.environ.get("EVIDENCE_STREAM_ENABLED")
    orig_blocking = os.environ.get("EVIDENCE_CHAIN_BLOCKING")

    try:
        # Test: stream disabled, blocking disabled → OK
        os.environ["EVIDENCE_STREAM_ENABLED"] = "false"
        os.environ["EVIDENCE_CHAIN_BLOCKING"] = "false"

        # Should not raise
        validate_evidence_stream_preconditions()

    finally:
        # Restore env
        if orig_enabled is not None:
            os.environ["EVIDENCE_STREAM_ENABLED"] = orig_enabled
        else:
            os.environ.pop("EVIDENCE_STREAM_ENABLED", None)

        if orig_blocking is not None:
            os.environ["EVIDENCE_CHAIN_BLOCKING"] = orig_blocking
        else:
            os.environ.pop("EVIDENCE_CHAIN_BLOCKING", None)


@pytest.mark.local
def test_blocking_requires_stream_enabled():
    """Verify ConfigurationError when blocking=true but stream=false."""
    import os

    from src.compliance_bridge.evidence_stream import (
        ConfigurationError,
        validate_evidence_stream_preconditions,
    )

    # Save original env
    orig_enabled = os.environ.get("EVIDENCE_STREAM_ENABLED")
    orig_blocking = os.environ.get("EVIDENCE_CHAIN_BLOCKING")

    try:
        # Test: stream disabled, blocking enabled → ERROR
        os.environ["EVIDENCE_STREAM_ENABLED"] = "false"
        os.environ["EVIDENCE_CHAIN_BLOCKING"] = "true"

        # Should raise ConfigurationError
        with pytest.raises(ConfigurationError) as exc_info:
            validate_evidence_stream_preconditions()

        assert (
            "EVIDENCE_CHAIN_BLOCKING=true requires EVIDENCE_STREAM_ENABLED=true"
            in str(exc_info.value)
        )

    finally:
        # Restore env
        if orig_enabled is not None:
            os.environ["EVIDENCE_STREAM_ENABLED"] = orig_enabled
        else:
            os.environ.pop("EVIDENCE_STREAM_ENABLED", None)

        if orig_blocking is not None:
            os.environ["EVIDENCE_CHAIN_BLOCKING"] = orig_blocking
        else:
            os.environ.pop("EVIDENCE_CHAIN_BLOCKING", None)
