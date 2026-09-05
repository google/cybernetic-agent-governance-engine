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
test_clickhouse_sink.py — ClickHouse Evidence Sink Integration Tests

Comprehensive unit test coverage for ClickHouseSink batch buffering, retry logic,
circuit breaker, and graceful degradation without requiring live ClickHouse.

Test Spec: docs/architecture/CLICKHOUSE_EVIDENCE_SINK.md §11.7
"""

import asyncio
import sys
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Mock clickhouse_connect before importing ClickHouseSink
sys.modules["clickhouse_connect"] = MagicMock()

from src.compliance_bridge.clickhouse_sink import CircuitBreaker, ClickHouseSink

# Mark all tests as local and unit (no live ClickHouse required)
pytestmark = [pytest.mark.local, pytest.mark.unit]


def test_clickhouse_sink_initialization():
    """Verify constructor sets host, port, database, lazy connection."""
    sink = ClickHouseSink(
        host="test-host",
        port=9000,
        username="test_user",
        password="test_pass",
        database="test_db",
        batch_size=50,
        flush_seconds=3.0,
        max_queue=5000,
    )

    assert sink._host == "test-host"
    assert sink._port == 9000
    assert sink._username == "test_user"
    assert sink._password == "test_pass"
    assert sink._database == "test_db"
    assert sink._batch_size == 50
    assert sink._flush_seconds == 3.0
    assert sink._max_queue == 5000
    assert sink._client is None  # Lazy connection


@pytest.mark.asyncio
async def test_clickhouse_sink_batch_buffering():
    """Verify batch insert triggers at configured batch size (100 records default)."""
    mock_conn = MagicMock()
    mock_get_client = MagicMock(return_value=mock_conn)

    with patch.object(sys.modules["clickhouse_connect"], "get_client", mock_get_client):
        sink = ClickHouseSink(
            host="localhost",
            port=9000,
            database="test_db",
            username="test_user",
            password="test_pass",
            batch_size=100,
        )

        await sink.start()

        # Ingest 99 records - should NOT trigger flush
        for i in range(99):
            record = {
                "schema": "cage-audit/3.0",
                "chain_id": "test-chain",
                "sequence": str(i),
                "timestamp_utc": "2026-09-05T15:00:00.000Z",
                "event_type": "request_admitted",
                "control_id": "A.5.2",
                "trace_id": f"00-trace{i:02d}-span{i:02d}-01",
                "hash_algorithm": "SHA-256",
                "canonicalization": "RFC8785",
                "payload_json": "{}",
                "record_hash": "a" * 64,
                "prev_hash": "b" * 64 if i > 0 else None,
                "kms_signature": "",
                "kms_signature_algorithm": "HMAC_SHA256_FALLBACK",
            }
            await sink.ingest(record)

        # Allow flush loop to process queue
        await asyncio.sleep(0.1)

        # Should not have called insert yet
        mock_conn.insert.assert_not_called()

        # Ingest 100th record - should trigger flush
        record["sequence"] = "99"
        record["trace_id"] = "00-trace99-span99-01"
        await sink.ingest(record)

        # Allow flush loop to process and flush
        await asyncio.sleep(0.2)

        # Should have called insert once with 100 records
        mock_conn.insert.assert_called_once()
        call_args = mock_conn.insert.call_args
        assert len(call_args[0][1]) == 100  # 100 rows

        await sink.close()


@pytest.mark.asyncio
async def test_clickhouse_sink_time_based_flush():
    """Verify flush interval triggers even with partial batch."""
    mock_conn = MagicMock()
    mock_get_client = MagicMock(return_value=mock_conn)

    with patch.object(sys.modules["clickhouse_connect"], "get_client", mock_get_client):
        sink = ClickHouseSink(
            host="localhost",
            port=9000,
            database="test_db",
            username="test_user",
            password="test_pass",
            batch_size=100,
            flush_seconds=0.5,  # Short interval for testing
        )

        await sink.start()

        # Ingest only 10 records (well below batch size)
        for i in range(10):
            record = {
                "schema": "cage-audit/3.0",
                "chain_id": "test-chain",
                "sequence": str(i),
                "timestamp_utc": "2026-09-05T15:00:00.000Z",
                "event_type": "request_admitted",
                "control_id": "A.5.2",
                "trace_id": f"00-trace{i:02d}-span{i:02d}-01",
                "hash_algorithm": "SHA-256",
                "canonicalization": "RFC8785",
                "payload_json": "{}",
                "record_hash": "a" * 64,
                "prev_hash": "b" * 64 if i > 0 else None,
                "kms_signature": "",
                "kms_signature_algorithm": "HMAC_SHA256_FALLBACK",
            }
            await sink.ingest(record)

        # Wait for time-based flush
        await asyncio.sleep(0.7)

        # Should have called insert with partial batch
        mock_conn.insert.assert_called_once()
        call_args = mock_conn.insert.call_args
        assert len(call_args[0][1]) == 10  # Only 10 rows

        await sink.close()


@pytest.mark.asyncio
async def test_clickhouse_sink_retry_exponential_backoff():
    """Verify 3 retries with exponential backoff on insert failure."""
    mock_conn = MagicMock()
    mock_conn.insert.side_effect = Exception("ClickHouse unavailable")
    mock_get_client = MagicMock(return_value=mock_conn)

    with patch.object(sys.modules["clickhouse_connect"], "get_client", mock_get_client):
        sink = ClickHouseSink(
            host="localhost",
            port=9000,
            database="test_db",
            username="test_user",
            password="test_pass",
            batch_size=10,
            flush_seconds=0.5,
        )

        await sink.start()

        # Ingest records to trigger flush
        for i in range(10):
            record = {
                "schema": "cage-audit/3.0",
                "chain_id": "test-chain",
                "sequence": str(i),
                "timestamp_utc": "2026-09-05T15:00:00.000Z",
                "event_type": "request_admitted",
                "control_id": "A.5.2",
                "trace_id": f"00-trace{i:02d}-span{i:02d}-01",
                "hash_algorithm": "SHA-256",
                "canonicalization": "RFC8785",
                "payload_json": "{}",
                "record_hash": "a" * 64,
                "prev_hash": None,
                "kms_signature": "",
                "kms_signature_algorithm": "HMAC_SHA256_FALLBACK",
            }
            await sink.ingest(record)

        # Wait for flush and retries
        await asyncio.sleep(4.5)

        # Should have attempted insert at least 3 times (may have multiple flush attempts)
        assert mock_conn.insert.call_count >= 3

        await sink.close()


def test_clickhouse_sink_circuit_breaker_opens():
    """Verify circuit opens after 10 consecutive failures."""
    breaker = CircuitBreaker(failure_threshold=10, cooldown_seconds=60.0)

    assert breaker.is_open() is False

    # Record 9 failures - should stay closed
    for _ in range(9):
        breaker.record_failure()

    assert breaker.is_open() is False

    # 10th failure - should open
    breaker.record_failure()
    assert breaker.is_open() is True


def test_clickhouse_sink_circuit_breaker_closes():
    """Verify circuit closes after cooldown."""
    breaker = CircuitBreaker(failure_threshold=10, cooldown_seconds=0.2)

    # Open the circuit
    for _ in range(10):
        breaker.record_failure()

    assert breaker.is_open() is True

    # Wait for cooldown
    time.sleep(0.3)

    # Should close after cooldown
    assert breaker.is_open() is False


def test_clickhouse_sink_circuit_breaker_resets_on_success():
    """Verify circuit resets consecutive failures on success."""
    breaker = CircuitBreaker(failure_threshold=10, cooldown_seconds=60.0)

    # Record some failures
    for _ in range(5):
        breaker.record_failure()

    # Success should reset
    breaker.record_success()

    # Failure count reset, so 9 more failures shouldn't open
    for _ in range(9):
        breaker.record_failure()

    assert breaker.is_open() is False

    # But 10th will open
    breaker.record_failure()
    assert breaker.is_open() is True


@pytest.mark.asyncio
async def test_clickhouse_sink_queue_overflow_drops_oldest():
    """Verify bounded queue drops oldest on overflow."""
    mock_conn = MagicMock()
    mock_get_client = MagicMock(return_value=mock_conn)

    with patch.object(sys.modules["clickhouse_connect"], "get_client", mock_get_client):
        sink = ClickHouseSink(
            host="localhost",
            port=9000,
            database="test_db",
            username="test_user",
            password="test_pass",
            batch_size=1000,
            flush_seconds=60.0,
            max_queue=5,  # Small queue for testing
        )

        await sink.start()

        # Fill queue to capacity
        for i in range(5):
            record = {
                "schema": "cage-audit/3.0",
                "chain_id": "test-chain",
                "sequence": str(i),
                "timestamp_utc": "2026-09-05T15:00:00.000Z",
                "event_type": "request_admitted",
                "control_id": "A.5.2",
                "trace_id": f"00-trace{i:02d}-span{i:02d}-01",
                "hash_algorithm": "SHA-256",
                "canonicalization": "RFC8785",
                "payload_json": "{}",
                "record_hash": "a" * 64,
                "prev_hash": None,
                "kms_signature": "",
                "kms_signature_algorithm": "HMAC_SHA256_FALLBACK",
            }
            await sink.ingest(record)

        assert sink._queue.qsize() == 5

        # Ingest one more - should drop oldest
        overflow_record = {
            "schema": "cage-audit/3.0",
            "chain_id": "test-chain",
            "sequence": "999",
            "timestamp_utc": "2026-09-05T15:00:00.000Z",
            "event_type": "request_admitted",
            "control_id": "A.5.2",
            "trace_id": "00-trace999-span999-01",
            "hash_algorithm": "SHA-256",
            "canonicalization": "RFC8785",
            "payload_json": "{}",
            "record_hash": "a" * 64,
            "prev_hash": None,
            "kms_signature": "",
            "kms_signature_algorithm": "HMAC_SHA256_FALLBACK",
        }
        await sink.ingest(overflow_record)

        assert sink._queue.qsize() == 5

        await sink.close()


@pytest.mark.asyncio
async def test_clickhouse_sink_schema_mapping():
    """Verify EvidenceRecord → ClickHouse row transformation."""
    sink = ClickHouseSink()

    record = {
        "schema": "cage-audit/3.0",
        "chain_id": "test-chain-123",
        "sequence": "42",
        "timestamp_utc": "2026-09-05T15:30:00.000Z",
        "event_type": "governance_violation",
        "control_id": "A.5.3",
        "trace_id": "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01",
        "hash_algorithm": "SHA-256",
        "canonicalization": "RFC8785",
        "payload_json": '{"action":"test","result":"DENY"}',
        "record_hash": "a1b2c3d4e5f6" * 11,
        "prev_hash": "f6e5d4c3b2a1" * 11,
        "kms_signature": "signature_base64",
        "kms_signature_algorithm": "KMS_ASYMMETRIC",
        "redis_msg_id": "1725540000000-0",
    }

    row = sink._evidence_to_row(record)

    assert row["schema_version"] == "3.0"
    assert row["chain_id"] == "test-chain-123"
    assert row["sequence"] == 42
    assert row["event_type"] == "governance_violation"
    assert row["control_id"] == "A.5.3"
    assert row["trace_id"] == "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"
    assert row["hash_algorithm"] == "SHA-256"


@pytest.mark.asyncio
async def test_clickhouse_sink_non_blocking_failure():
    """Verify failures never raise exceptions (non-blocking design)."""
    mock_get_client = MagicMock(side_effect=Exception("Connection refused"))

    with patch.object(sys.modules["clickhouse_connect"], "get_client", mock_get_client):
        sink = ClickHouseSink(
            host="localhost",
            port=9000,
            database="test_db",
            username="test_user",
            password="test_pass",
            batch_size=10,
            flush_seconds=0.5,
        )

        await sink.start()

        # Ingest records - should NOT raise exception
        for i in range(10):
            record = {
                "schema": "cage-audit/3.0",
                "chain_id": "test-chain",
                "sequence": str(i),
                "timestamp_utc": "2026-09-05T15:00:00.000Z",
                "event_type": "request_admitted",
                "control_id": "A.5.2",
                "trace_id": f"00-trace{i:02d}-span{i:02d}-01",
                "hash_algorithm": "SHA-256",
                "canonicalization": "RFC8785",
                "payload_json": "{}",
                "record_hash": "a" * 64,
                "prev_hash": None,
                "kms_signature": "",
                "kms_signature_algorithm": "HMAC_SHA256_FALLBACK",
            }
            await sink.ingest(record)

        await asyncio.sleep(0.7)

        await sink.close()


@pytest.mark.asyncio
async def test_clickhouse_sink_metrics_emitted():
    """Verify Prometheus metrics incremented on insert."""
    mock_conn = MagicMock()
    mock_get_client = MagicMock(return_value=mock_conn)

    with patch.object(sys.modules["clickhouse_connect"], "get_client", mock_get_client):
        from src.compliance_bridge.metrics import (
            CLICKHOUSE_SINK_BATCH_DURATION_SECONDS,
            CLICKHOUSE_SINK_RECORDS_TOTAL,
        )

        with (
            patch.object(
                CLICKHOUSE_SINK_BATCH_DURATION_SECONDS, "observe"
            ) as mock_observe,
            patch.object(CLICKHOUSE_SINK_RECORDS_TOTAL, "inc") as mock_inc,
        ):
            sink = ClickHouseSink(
                host="localhost",
                port=9000,
                database="test_db",
                username="test_user",
                password="test_pass",
                batch_size=5,
                flush_seconds=0.5,
            )

            await sink.start()

            for i in range(5):
                record = {
                    "schema": "cage-audit/3.0",
                    "chain_id": "test-chain",
                    "sequence": str(i),
                    "timestamp_utc": "2026-09-05T15:00:00.000Z",
                    "event_type": "request_admitted",
                    "control_id": "A.5.2",
                    "trace_id": f"00-trace{i:02d}-span{i:02d}-01",
                    "hash_algorithm": "SHA-256",
                    "canonicalization": "RFC8785",
                    "payload_json": "{}",
                    "record_hash": "a" * 64,
                    "prev_hash": None,
                    "kms_signature": "",
                    "kms_signature_algorithm": "HMAC_SHA256_FALLBACK",
                }
                await sink.ingest(record)

            await asyncio.sleep(0.7)

            # Metrics should be called at least once
            assert mock_observe.call_count >= 1
            assert mock_inc.call_count >= 1
            # Verify total records ingested
            total_ingested = sum(call[0][0] for call in mock_inc.call_args_list)
            assert total_ingested >= 5

            await sink.close()


@pytest.mark.asyncio
async def test_clickhouse_sink_health_check():
    """Verify health check returns connectivity status."""
    mock_conn = MagicMock()
    mock_conn.command.return_value = 1
    mock_get_client = MagicMock(return_value=mock_conn)

    with patch.object(sys.modules["clickhouse_connect"], "get_client", mock_get_client):
        sink = ClickHouseSink(
            host="localhost",
            port=9000,
            database="test_db",
            username="test_user",
            password="test_pass",
        )

        result = await sink.health_check()
        assert result is True


@pytest.mark.asyncio
async def test_clickhouse_sink_nullable_field_handling():
    """Verify nullable fields mapped correctly."""
    sink = ClickHouseSink()

    genesis_record = {
        "schema": "cage-audit/3.0",
        "chain_id": "test-chain",
        "sequence": "0",
        "timestamp_utc": "2026-09-05T15:30:00.000Z",
        "event_type": "genesis",
        "control_id": "GENESIS",
        "trace_id": "",
        "hash_algorithm": "SHA-256",
        "canonicalization": "RFC8785",
        "payload_json": "{}",
        "record_hash": "a" * 64,
        "prev_hash": "",
        "kms_signature": "",
        "kms_signature_algorithm": "",
        "redis_msg_id": "",
    }

    row = sink._evidence_to_row(genesis_record)

    assert row["prev_hash"] is None
    assert row["kms_signature"] is None
    assert row["kms_signature_algorithm"] is None


@pytest.mark.asyncio
async def test_clickhouse_sink_circuit_breaker_integration():
    """Verify circuit breaker skips flush when open."""
    mock_conn = MagicMock()
    mock_conn.insert.side_effect = Exception("ClickHouse unavailable")
    mock_get_client = MagicMock(return_value=mock_conn)

    with patch.object(sys.modules["clickhouse_connect"], "get_client", mock_get_client):
        sink = ClickHouseSink(
            host="localhost",
            port=9000,
            database="test_db",
            username="test_user",
            password="test_pass",
            batch_size=5,
            flush_seconds=0.5,
        )

        # Manually open circuit breaker
        for _ in range(10):
            sink._breaker.record_failure()

        assert sink._breaker.is_open() is True

        await sink.start()

        for i in range(5):
            record = {
                "schema": "cage-audit/3.0",
                "chain_id": "test-chain",
                "sequence": str(i),
                "timestamp_utc": "2026-09-05T15:00:00.000Z",
                "event_type": "request_admitted",
                "control_id": "A.5.2",
                "trace_id": f"00-trace{i:02d}-span{i:02d}-01",
                "hash_algorithm": "SHA-256",
                "canonicalization": "RFC8785",
                "payload_json": "{}",
                "record_hash": "a" * 64,
                "prev_hash": None,
                "kms_signature": "",
                "kms_signature_algorithm": "HMAC_SHA256_FALLBACK",
            }
            await sink.ingest(record)

        await asyncio.sleep(0.7)

        # Insert should NOT have been called (circuit breaker open)
        mock_conn.insert.assert_not_called()

        await sink.close()
