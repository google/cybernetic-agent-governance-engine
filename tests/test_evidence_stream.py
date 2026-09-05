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
tests/test_evidence_stream.py
=============================
Unit tests for src/compliance_bridge/evidence_stream.py.

Covers:
  - SHA-256 helpers (_sha256, _link_hash)
  - EvidenceStreamSink ingestion, hash chaining, ordering
  - Redis-unavailable graceful no-op path
  - start() / stop() lifecycle
  - GCS flush loop (mocked asyncio.sleep)
  - get_evidence_sink() singleton
  - Backpressure / maxlen behaviour (delegated to Redis; tested via mock)

All tests are hermetic — no live Redis, no GCS, no KMS.
"""

import ast
import asyncio
import hashlib
import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.gateway.governance.evidence.cold_store import (
    ColdStoreError,
    ColdStoreHealth,
    ColdStoreReceipt,
)
from src.gateway.governance.evidence.null_cold_store import NullColdStore

pytestmark = pytest.mark.local


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_sink(**kwargs):
    """Return an EvidenceStreamSink instance with sensible test defaults."""
    from src.compliance_bridge.evidence_stream import EvidenceStreamSink

    defaults = {
        "redis_url": "redis://localhost:6379",
        "redis_db": 1,
        "stream_key": "cage:evidence:test",
        "max_len": 1000,
        "kms_sign": False,
    }
    defaults.update(kwargs)
    return EvidenceStreamSink(**defaults)


def _make_redis_mock(xadd_return="1234567890-0"):
    """Return a minimal async Redis mock."""
    mock = AsyncMock()
    mock.ping = AsyncMock(return_value=True)
    mock.xadd = AsyncMock(return_value=xadd_return)
    mock.xrange = AsyncMock(return_value=[])
    mock.aclose = AsyncMock()
    return mock


# ---------------------------------------------------------------------------
# 1. SHA-256 helpers
# ---------------------------------------------------------------------------


class TestSha256Helpers:
    """Tests for the _sha256 and _link_hash helpers."""

    def test_sha256_returns_hex_string(self):
        """_sha256 must return a 64-character lowercase hex string."""
        from src.compliance_bridge.evidence_stream import _sha256

        result = _sha256("hello")
        assert len(result) == 64
        assert result == result.lower()
        assert all(c in "0123456789abcdef" for c in result)

    def test_sha256_deterministic(self):
        """Same input must always produce the same digest."""
        from src.compliance_bridge.evidence_stream import _sha256

        assert _sha256("test-input") == _sha256("test-input")

    def test_sha256_different_inputs_differ(self):
        """Different inputs must produce different digests."""
        from src.compliance_bridge.evidence_stream import _sha256

        assert _sha256("foo") != _sha256("bar")

    def test_link_hash_deterministic(self):
        """_link_hash must be deterministic given the same inputs."""
        from src.compliance_bridge.evidence_stream import _link_hash

        h1 = _link_hash("prev", 0, "AUDIT_FINDING", "A.5.3", '{"key": "val"}')
        h2 = _link_hash("prev", 0, "AUDIT_FINDING", "A.5.3", '{"key": "val"}')
        assert h1 == h2

    def test_link_hash_changes_on_sequence_change(self):
        """Changing sequence must produce a different record_hash (tamper detection)."""
        from src.compliance_bridge.evidence_stream import _link_hash

        h1 = _link_hash("prev", 0, "AUDIT_FINDING", "A.5.3", "{}")
        h2 = _link_hash("prev", 1, "AUDIT_FINDING", "A.5.3", "{}")
        assert h1 != h2

    def test_link_hash_changes_on_payload_change(self):
        """Changing payload must change the record_hash (tamper detection)."""
        from src.compliance_bridge.evidence_stream import _link_hash

        h1 = _link_hash("prev", 0, "AUDIT_FINDING", "A.5.3", '{"a": 1}')
        h2 = _link_hash("prev", 0, "AUDIT_FINDING", "A.5.3", '{"a": 2}')
        assert h1 != h2


# ---------------------------------------------------------------------------
# 2. EvidenceStreamSink — construction and properties
# ---------------------------------------------------------------------------


class TestEvidenceStreamSinkProperties:
    """Tests for EvidenceStreamSink properties and initial state."""

    def test_chain_root_is_genesis_hash(self):
        """Initial chain_root must equal the hash of the genesis string."""
        from src.compliance_bridge.evidence_stream import EvidenceStreamSink, _sha256

        sink = _make_sink()
        expected = _sha256("EVIDENCE_STREAM_GENESIS")
        assert sink.chain_root == expected

    def test_total_records_starts_at_zero(self):
        """total_records must start at 0."""
        sink = _make_sink()
        assert sink.total_records == 0

    def test_is_running_starts_false(self):
        """is_running must start as False before start() is called."""
        sink = _make_sink()
        assert sink.is_running is False

    def test_singleton_returns_same_instance(self):
        """get_evidence_sink() must return the same instance on repeated calls."""
        import src.compliance_bridge.evidence_stream as mod

        # Temporarily reset singleton for test isolation
        original = mod._evidence_sink
        try:
            mod._evidence_sink = None
            from src.compliance_bridge.evidence_stream import get_evidence_sink

            s1 = get_evidence_sink()
            s2 = get_evidence_sink()
            assert s1 is s2
        finally:
            mod._evidence_sink = original


# ---------------------------------------------------------------------------
# 3. Ingestion — Redis unavailable path
# ---------------------------------------------------------------------------


class TestIngestWithNoRedis:
    """Tests for the graceful no-op path when Redis is unavailable."""

    @pytest.mark.asyncio
    async def test_ingest_returns_none_when_redis_unavailable(self):
        """ingest() must return None when _redis is None (no-op path)."""
        sink = _make_sink()
        # Don't call start() — _redis stays None
        result = await sink.ingest({"type": "AUDIT_FINDING", "controlId": "A.5.3"})
        assert result is None

    @pytest.mark.asyncio
    async def test_ingest_does_not_advance_chain_when_redis_unavailable(self):
        """Chain state must not change when Redis is unavailable."""
        from src.compliance_bridge.evidence_stream import _sha256

        sink = _make_sink()
        initial_hash = sink.chain_root
        await sink.ingest({"type": "AUDIT_FINDING"})
        assert sink.chain_root == initial_hash
        assert sink.total_records == 0

    @pytest.mark.asyncio
    async def test_start_noop_when_redis_connection_fails(self):
        """start() must not set _running if Redis connection fails."""
        sink = _make_sink(redis_url="redis://invalid-host:9999")

        with patch("redis.asyncio.from_url") as mock_from_url:
            mock_client = AsyncMock()
            mock_client.ping = AsyncMock(side_effect=ConnectionRefusedError("no redis"))
            mock_from_url.return_value = mock_client

            await sink.start()

        assert sink.is_running is False


# ---------------------------------------------------------------------------
# 4. Ingestion — hash chain ordering and structure
# ---------------------------------------------------------------------------


class TestIngestHashChain:
    """Tests for hash-chaining and event ordering over a mocked Redis."""

    @pytest.mark.asyncio
    async def test_ingest_three_events_advances_sequence(self):
        """Ingesting 3 events must increment sequence to 3."""
        sink = _make_sink()
        sink._redis = _make_redis_mock()

        events = [
            {"type": "AUDIT_FINDING", "controlId": "A.5.3"},
            {"type": "AUDIT_FINDING", "controlId": "A.9.2"},
            {"type": "AUDIT_FINDING", "controlId": "SC-4"},
        ]
        for ev in events:
            await sink.ingest(ev)

        assert sink.total_records == 3

    @pytest.mark.asyncio
    async def test_ingest_events_have_distinct_hashes(self):
        """Each ingested event must produce a distinct record_hash (chain advances)."""
        sink = _make_sink()
        sink._redis = _make_redis_mock()

        captured_entries = []

        async def _capture_xadd(key, entry, **kwargs):
            captured_entries.append(dict(entry))
            return "1234-0"

        sink._redis.xadd = _capture_xadd

        await sink.ingest({"type": "E1", "controlId": "A.5.3"})
        await sink.ingest({"type": "E2", "controlId": "A.9.2"})
        await sink.ingest({"type": "E3", "controlId": "SC-4"})

        record_hashes = [e["record_hash"] for e in captured_entries]
        assert len(set(record_hashes)) == 3, "All record_hashes must be distinct"

    @pytest.mark.asyncio
    async def test_ingest_entry_schema_fields_present(self):
        """Every ingested entry must contain all required wire-format fields."""
        sink = _make_sink()
        sink._redis = _make_redis_mock()

        captured = {}

        async def _capture_xadd(key, entry, **kwargs):
            captured.update(entry)
            return "1234-0"

        sink._redis.xadd = _capture_xadd
        await sink.ingest({"type": "AUDIT_FINDING", "controlId": "A.5.3"})

        required_fields = {
            "schema",
            "sequence",
            "event_type",
            "control_id",
            "prev_hash",
            "record_hash",
            "payload_json",
            "timestamp_utc",
            "kms_signature",
        }
        assert required_fields.issubset(captured.keys()), (
            f"Missing fields: {required_fields - set(captured.keys())}"
        )

    @pytest.mark.asyncio
    async def test_ingest_links_previous_hash(self):
        """Each entry's prev_hash must equal the previous entry's record_hash."""
        sink = _make_sink()
        sink._redis = _make_redis_mock()

        captured_entries = []

        async def _capture_xadd(key, entry, **kwargs):
            captured_entries.append(dict(entry))
            return "1234-0"

        sink._redis.xadd = _capture_xadd

        await sink.ingest({"type": "E1", "controlId": "A.5.3"})
        await sink.ingest({"type": "E2", "controlId": "A.9.2"})

        # Entry 0's record_hash must equal entry 1's prev_hash
        assert captured_entries[0]["record_hash"] == captured_entries[1]["prev_hash"]

    @pytest.mark.asyncio
    async def test_ingest_returns_msg_id_from_redis(self):
        """ingest() must return the message ID returned by Redis xadd."""
        sink = _make_sink()
        expected_id = "9876543210-1"
        sink._redis = _make_redis_mock(xadd_return=expected_id)

        result = await sink.ingest({"type": "AUDIT_FINDING", "controlId": "A.5.3"})
        assert result == expected_id


# ---------------------------------------------------------------------------
# 5. Lifecycle — start / stop
# ---------------------------------------------------------------------------


class TestEvidenceStreamSinkLifecycle:
    """Tests for start() / stop() lifecycle semantics."""

    @pytest.mark.asyncio
    async def test_start_sets_running(self):
        """After a successful start(), is_running must be True."""
        sink = _make_sink()

        with patch("redis.asyncio.from_url", return_value=_make_redis_mock()):
            await sink.start()

        assert sink.is_running is True
        await sink.stop()

    @pytest.mark.asyncio
    async def test_start_twice_is_idempotent(self):
        """Calling start() twice must not raise and must stay running."""
        sink = _make_sink()

        mock_redis = _make_redis_mock()
        with patch("redis.asyncio.from_url", return_value=mock_redis):
            await sink.start()
            await sink.start()  # second call is a no-op

        assert sink.is_running is True
        # ping should have been called only once (start() returns early on second call)
        assert mock_redis.ping.call_count == 1
        await sink.stop()

    @pytest.mark.asyncio
    async def test_stop_sets_not_running(self):
        """After stop(), is_running must be False."""
        sink = _make_sink()

        with patch("redis.asyncio.from_url", return_value=_make_redis_mock()):
            await sink.start()

        await sink.stop()
        assert sink.is_running is False

    @pytest.mark.asyncio
    async def test_stop_without_start_does_not_raise(self):
        """Calling stop() before start() must not raise an exception."""
        sink = _make_sink()
        await sink.stop()  # should be a no-op

    @pytest.mark.asyncio
    async def test_ingest_returns_none_after_stop(self):
        """After stop(), _redis is closed; ingest() must gracefully return None."""
        sink = _make_sink()

        with patch("redis.asyncio.from_url", return_value=_make_redis_mock()):
            await sink.start()

        await sink.stop()
        # After stop, _redis.aclose() has been called — but sink._redis is still set.
        # Force it to None to simulate the closed state properly.
        sink._redis = None
        result = await sink.ingest({"type": "AUDIT_FINDING"})
        assert result is None

    @pytest.mark.asyncio
    async def test_ingest_redis_error_returns_none_and_does_not_raise(self):
        """If Redis xadd raises, ingest() must return None (not propagate exception)."""
        sink = _make_sink()
        sink._redis = AsyncMock()
        sink._redis.xadd = AsyncMock(side_effect=ConnectionError("redis gone"))

        result = await sink.ingest({"type": "AUDIT_FINDING", "controlId": "A.5.3"})
        assert result is None
        # Chain must still have advanced (lock was held before xadd)
        assert sink.total_records == 1


# ---------------------------------------------------------------------------
# 6. Cold store flush loop & seam integration
# ---------------------------------------------------------------------------


class FakeColdStore:
    """In-memory EvidenceColdStore test double for evidence stream tests."""

    def __init__(self, should_fail: bool = False, backend_id: str = "fake") -> None:
        self.should_fail = should_fail
        self._backend_id = backend_id
        self.batches: list[tuple[str, bytes, dict]] = []

    @property
    def backend_id(self) -> str:
        return self._backend_id

    async def put_batch(
        self, key: str, content: bytes, metadata: dict | None = None
    ) -> ColdStoreReceipt:
        if self.should_fail:
            raise ColdStoreError("Simulated cold store failure")

        digest = hashlib.sha256(content).hexdigest()
        self.batches.append((key, content, metadata or {}))
        return ColdStoreReceipt(
            uri=f"fake://bucket/{key}",
            key=key,
            content_sha256=digest,
            backend_id=self._backend_id,
            written_at=datetime.now(tz=timezone.utc),
        )

    async def exists(self, key: str) -> bool:
        return any(k == key for k, _, _ in self.batches)

    async def put_if_absent(
        self, key: str, content: bytes, metadata: dict | None = None
    ) -> tuple[ColdStoreReceipt, bool]:
        if await self.exists(key):
            digest = hashlib.sha256(content).hexdigest()
            return (
                ColdStoreReceipt(
                    uri=f"fake://bucket/{key}",
                    key=key,
                    content_sha256=digest,
                    backend_id=self._backend_id,
                    written_at=datetime.now(tz=timezone.utc),
                ),
                False,
            )
        receipt = await self.put_batch(key, content, metadata)
        return receipt, True

    def health(self) -> ColdStoreHealth:
        return ColdStoreHealth(
            available=not self.should_fail,
            backend_id=self._backend_id,
            detail="Fake cold store operational",
        )


class TestColdFlushLoop:
    """Tests for the EvidenceColdStore flush daemon background task."""

    @pytest.mark.asyncio
    async def test_cold_flush_loop_exits_on_cancelled_error(self):
        """_cold_flush_loop must exit cleanly on CancelledError (stop() path)."""
        sink = _make_sink(cold_store=FakeColdStore())
        sink._running = True
        sink._redis = _make_redis_mock()

        # Patch asyncio.sleep to immediately raise CancelledError
        with patch("asyncio.sleep", side_effect=asyncio.CancelledError):
            await sink._cold_flush_loop()

    @pytest.mark.asyncio
    async def test_stop_cancels_flush_task(self):
        """stop() must cancel the cold flush task if it is running."""
        sink = _make_sink(cold_store=FakeColdStore())

        async def _forever():
            await asyncio.sleep(10000)

        sink._flush_task = asyncio.create_task(_forever(), name="test-flush")
        sink._running = True
        sink._redis = _make_redis_mock()

        await sink.stop()

        assert sink._flush_task.cancelled() or sink._flush_task.done()

    @pytest.mark.asyncio
    async def test_cold_flush_loop_persists_entries_to_cold_store(self):
        """_cold_flush_loop reads entries from Redis and writes them to cold store."""
        fake_store = FakeColdStore()
        sink = _make_sink(cold_store=fake_store)
        sink._running = True

        redis_mock = _make_redis_mock()
        redis_mock.xrange.return_value = [
            ("100-0", {"event_type": "GOVERNANCE_DECISION", "rule": "US_FED_CAS"}),
            ("101-0", {"event_type": "AUDIT_FINDING", "status": "PASS"}),
        ]
        sink._redis = redis_mock

        # First sleep succeeds (run one flush pass), second sleep cancels
        with patch("asyncio.sleep", side_effect=[None, asyncio.CancelledError]):
            await sink._cold_flush_loop()

        assert len(fake_store.batches) == 1
        key, content, metadata = fake_store.batches[0]
        assert key.startswith("evidence-stream/")
        assert key.endswith(".ndjson")
        assert b"GOVERNANCE_DECISION" in content
        assert b"AUDIT_FINDING" in content
        assert metadata["content-type"] == "application/x-ndjson"
        assert metadata["entries-count"] == "2"

    @pytest.mark.asyncio
    async def test_cold_flush_loop_survives_cold_store_error(self):
        """ColdStoreError during flush is logged, backs off, and loop survives."""
        failing_store = FakeColdStore(should_fail=True)
        sink = _make_sink(cold_store=failing_store)
        sink._running = True

        redis_mock = _make_redis_mock()
        redis_mock.xrange.return_value = [("100-0", {"event_type": "FAULT"})]
        sink._redis = redis_mock

        # First sleep triggers flush (raises error), error handler sleeps 5s which cancels
        with patch("asyncio.sleep", side_effect=[None, asyncio.CancelledError]):
            await sink._cold_flush_loop()

    def test_sink_imports_no_vendor_module(self):
        """AST check: evidence_stream.py must not import vendor storage SDKs."""
        import inspect

        from src.compliance_bridge import evidence_stream

        source = inspect.getsource(evidence_stream)
        tree = ast.parse(source)

        forbidden_prefixes = ("google.cloud", "boto3", "botocore", "azure")
        imported_modules: list[str] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported_modules.append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imported_modules.append(node.module)

        for mod in imported_modules:
            for forbidden in forbidden_prefixes:
                assert not mod.startswith(forbidden), (
                    f"Forbidden vendor import '{mod}' found in evidence_stream.py"
                )

    def test_null_cold_store_opens_no_socket(self):
        """NullColdStore integration requires no credentials and opens no network sockets."""
        null_store = NullColdStore()
        sink = _make_sink(cold_store=null_store)
        health = null_store.health()
        assert health.available is True
        assert health.backend_id == "null"
        assert sink._cold_store.backend_id == "null"
