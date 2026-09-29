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
Unit tests for src/gateway/governance/evidence/stream.py (the producer).

Covers:
  - SHA-256 helpers (_sha256, _link_hash)
  - EvidenceStreamSink ingestion, hash chaining, ordering
  - Compare-and-append: replicas sharing a stream never fork the chain, and a
    failed write never consumes a sequence number
  - Redis-unavailable graceful no-op path
  - start() / stop() lifecycle and start_evidence_sink() posture handling
  - Fail-closed chain state restoration
  - get_evidence_sink() singleton

Signing and cold-store custody are the compliance bridge's job and are tested
in tests/test_evidence_custodian.py. All tests here are hermetic: Redis is
fakeredis (with Lua), no GCS, no KMS.
"""

import ast
from unittest.mock import AsyncMock, patch

import fakeredis
import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]

STREAM_KEY = "cage:evidence:test"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_sink(**kwargs):
    """Return an EvidenceStreamSink instance with sensible test defaults."""
    from src.gateway.governance.evidence.stream import EvidenceStreamSink

    defaults = {
        "redis_url": "redis://localhost:6379",
        "redis_db": 1,
        "stream_key": STREAM_KEY,
        "max_len": 1000,
    }
    defaults.update(kwargs)
    return EvidenceStreamSink(**defaults)


def _fake_redis(server=None):
    """A fakeredis asyncio client (Lua-capable) on ``server``."""
    return fakeredis.FakeAsyncRedis(
        server=server or fakeredis.FakeServer(), decode_responses=True
    )


async def _entries(redis):
    return await redis.xrange(STREAM_KEY)


# ---------------------------------------------------------------------------
# 1. SHA-256 helpers
# ---------------------------------------------------------------------------


class TestSha256Helpers:
    """Tests for the _sha256 and _link_hash helpers."""

    def test_sha256_returns_hex_string(self):
        """_sha256 must return a 64-character lowercase hex string."""
        from src.gateway.governance.evidence.stream import _sha256

        result = _sha256("hello")
        assert len(result) == 64
        assert result == result.lower()
        assert all(c in "0123456789abcdef" for c in result)

    def test_sha256_deterministic(self):
        """Same input must always produce the same digest."""
        from src.gateway.governance.evidence.stream import _sha256

        assert _sha256("test-input") == _sha256("test-input")

    def test_sha256_different_inputs_differ(self):
        """Different inputs must produce different digests."""
        from src.gateway.governance.evidence.stream import _sha256

        assert _sha256("foo") != _sha256("bar")

    def test_link_hash_deterministic(self):
        """_link_hash must be deterministic given the same inputs."""
        from src.gateway.governance.evidence.stream import _link_hash

        h1 = _link_hash(
            "prev", 0, "AUDIT_FINDING", "A.5.3", '{"key": "val"}', "chain-1", "trace-1"
        )
        h2 = _link_hash(
            "prev", 0, "AUDIT_FINDING", "A.5.3", '{"key": "val"}', "chain-1", "trace-1"
        )
        assert h1 == h2

    def test_link_hash_changes_on_sequence_change(self):
        """Changing sequence must produce a different record_hash (tamper detection)."""
        from src.gateway.governance.evidence.stream import _link_hash

        h1 = _link_hash("prev", 0, "AUDIT_FINDING", "A.5.3", "{}", "chain-1", "trace-1")
        h2 = _link_hash("prev", 1, "AUDIT_FINDING", "A.5.3", "{}", "chain-1", "trace-1")
        assert h1 != h2

    def test_link_hash_changes_on_payload_change(self):
        """Changing payload must change the record_hash (tamper detection)."""
        from src.gateway.governance.evidence.stream import _link_hash

        h1 = _link_hash(
            "prev", 0, "AUDIT_FINDING", "A.5.3", '{"a": 1}', "chain-1", "trace-1"
        )
        h2 = _link_hash(
            "prev", 0, "AUDIT_FINDING", "A.5.3", '{"a": 2}', "chain-1", "trace-1"
        )
        assert h1 != h2


# ---------------------------------------------------------------------------
# 2. EvidenceStreamSink — construction and properties
# ---------------------------------------------------------------------------


class TestEvidenceStreamSinkProperties:
    """Tests for EvidenceStreamSink properties and initial state."""

    def test_chain_root_is_empty_before_restore(self):
        """Initial chain_root must be empty string before state restoration."""
        assert _make_sink().chain_root == ""

    def test_total_records_starts_at_zero(self):
        assert _make_sink().total_records == 0

    def test_is_running_starts_false(self):
        assert _make_sink().is_running is False

    def test_sink_has_no_signing_or_cold_store_parameters(self):
        """The producer takes no signer or cold store: custody is the bridge's."""
        from src.gateway.governance.evidence.stream import EvidenceStreamSink

        with pytest.raises(TypeError):
            EvidenceStreamSink(kms_sign=True)  # type: ignore[call-arg]
        with pytest.raises(TypeError):
            EvidenceStreamSink(cold_store=object())  # type: ignore[call-arg]

    def test_singleton_returns_same_instance(self):
        """get_evidence_sink() must return the same instance on repeated calls."""
        import src.gateway.governance.evidence.stream as mod

        original = mod._evidence_sink
        try:
            mod._evidence_sink = None
            assert mod.get_evidence_sink() is mod.get_evidence_sink()
        finally:
            mod._evidence_sink = original


# ---------------------------------------------------------------------------
# 3. Ingestion — Redis unavailable path
# ---------------------------------------------------------------------------


class TestIngestWithNoRedis:
    """Tests for the graceful no-op path when Redis is unavailable."""

    @pytest.mark.asyncio
    async def test_ingest_returns_none_when_redis_unavailable(self):
        sink = _make_sink()
        result = await sink.ingest({"type": "AUDIT_FINDING", "controlId": "A.5.3"})
        assert result is None

    @pytest.mark.asyncio
    async def test_ingest_does_not_advance_chain_when_redis_unavailable(self):
        sink = _make_sink()
        await sink.ingest({"type": "AUDIT_FINDING"})
        assert sink.chain_root == ""
        assert sink.total_records == 0

    @pytest.mark.asyncio
    async def test_start_noop_when_redis_connection_fails(self):
        """start() must not set _running if Redis connection fails."""
        sink = _make_sink(redis_url="redis://invalid-host:9999")

        with patch(
            "src.gateway.infrastructure.redis_client.build_async_redis"
        ) as mock_from_url:
            mock_client = AsyncMock()
            mock_client.ping = AsyncMock(side_effect=ConnectionRefusedError("no redis"))
            mock_from_url.return_value = mock_client
            await sink.start()

        assert sink.is_running is False


# ---------------------------------------------------------------------------
# 4. Ingestion — hash chain ordering and structure
# ---------------------------------------------------------------------------


class TestIngestHashChain:
    """Hash-chaining and event ordering over fakeredis."""

    @pytest.mark.asyncio
    async def test_ingest_three_events_advances_sequence(self):
        sink = _make_sink()
        sink._redis = _fake_redis()
        for control in ("A.5.3", "A.9.2", "SC-4"):
            await sink.ingest({"type": "AUDIT_FINDING", "controlId": control})
        assert sink.total_records == 3

    @pytest.mark.asyncio
    async def test_ingest_events_have_distinct_hashes_and_link(self):
        from src.gateway.governance.evidence.stream import verify_record

        sink = _make_sink()
        sink._redis = _fake_redis()
        for i in range(3):
            await sink.ingest({"type": f"E{i}", "controlId": "A.5.3"})

        entries = await _entries(sink._redis)
        assert len({f["record_hash"] for _, f in entries}) == 3
        prev = ""
        for i, (_id, fields) in enumerate(entries):
            assert fields["sequence"] == str(i)
            assert fields["prev_hash"] == prev
            assert verify_record(fields, prev_hash=prev).valid
            prev = fields["record_hash"]

    @pytest.mark.asyncio
    async def test_ingest_entry_schema_fields_present(self):
        """Every entry carries the wire fields and no signature placeholder."""
        sink = _make_sink()
        sink._redis = _fake_redis()
        await sink.ingest({"type": "AUDIT_FINDING", "controlId": "A.5.3"})

        (_id, fields) = (await _entries(sink._redis))[0]
        required = {
            "schema",
            "chain_id",
            "sequence",
            "event_type",
            "control_id",
            "trace_id",
            "prev_hash",
            "record_hash",
            "payload_json",
            "timestamp_utc",
        }
        assert required.issubset(fields.keys())
        assert "kms_signature" not in fields
        assert "kms_signature_algorithm" not in fields

    @pytest.mark.asyncio
    async def test_ingest_returns_stream_message_id(self):
        sink = _make_sink()
        sink._redis = _fake_redis()
        msg_id = await sink.ingest({"type": "AUDIT_FINDING", "controlId": "A.5.3"})
        (stored_id, _fields) = (await _entries(sink._redis))[0]
        assert msg_id == stored_id

    @pytest.mark.asyncio
    async def test_max_len_trims_stream(self):
        sink = _make_sink(max_len=2)
        sink._redis = _fake_redis()
        for i in range(4):
            await sink.ingest({"type": f"E{i}"})
        entries = await _entries(sink._redis)
        assert [f["sequence"] for _, f in entries] == ["2", "3"]


# ---------------------------------------------------------------------------
# 5. Compare-and-append
# ---------------------------------------------------------------------------


class TestCompareAndAppend:
    """The head check and XADD are atomic, so writers cannot fork the chain."""

    @pytest.mark.asyncio
    async def test_two_replicas_share_one_linear_chain(self):
        """Interleaved writes from two sinks on one stream form one chain."""
        from src.gateway.governance.evidence.stream import verify_record

        server = fakeredis.FakeServer()
        a, b = _make_sink(), _make_sink()
        a._redis, b._redis = _fake_redis(server), _fake_redis(server)

        await a.ingest({"type": "X", "n": 1})
        await b.ingest({"type": "X", "n": 2})
        await a.ingest({"type": "X", "n": 3})  # a's in-memory head is stale
        await b.ingest({"type": "X", "n": 4})

        entries = await _entries(a._redis)
        assert len({f["chain_id"] for _, f in entries}) == 1
        prev = ""
        for i, (_id, fields) in enumerate(entries):
            assert int(fields["sequence"]) == i
            assert fields["prev_hash"] == prev
            assert verify_record(fields, prev_hash=prev).valid
            prev = fields["record_hash"]

    @pytest.mark.asyncio
    async def test_stale_head_is_rejected_by_script(self):
        """The script refuses an append whose expected head is not the head."""
        from src.gateway.governance.evidence.stream import _APPEND_SCRIPT

        redis = _fake_redis()
        sink = _make_sink()
        sink._redis = redis
        await sink.ingest({"type": "X"})

        result = await redis.eval(
            _APPEND_SCRIPT,
            1,
            STREAM_KEY,
            sink.chain_id,
            "1",
            "f" * 64,
            "1000",
            "k",
            "v",
        )
        assert result == ["CONFLICT"]
        assert len(await _entries(redis)) == 1

    @pytest.mark.asyncio
    async def test_non_genesis_append_to_empty_stream_is_rejected(self):
        from src.gateway.governance.evidence.stream import _APPEND_SCRIPT

        redis = _fake_redis()
        result = await redis.eval(
            _APPEND_SCRIPT, 1, STREAM_KEY, "c", "5", "a" * 64, "1000", "k", "v"
        )
        assert result == ["CONFLICT"]
        assert await _entries(redis) == []

    @pytest.mark.asyncio
    async def test_failed_write_does_not_advance_chain(self):
        """A Redis error returns None and leaves chain state untouched."""
        sink = _make_sink()
        sink._redis = _fake_redis()
        await sink.ingest({"type": "X"})
        head = (sink.chain_root, sink.total_records)

        with patch.object(
            sink._redis, "eval", AsyncMock(side_effect=ConnectionError("redis gone"))
        ):
            result = await sink.ingest({"type": "Y"})

        assert result is None
        assert (sink.chain_root, sink.total_records) == head
        # The next successful write continues the chain without a gap.
        await sink.ingest({"type": "Z"})
        entries = await _entries(sink._redis)
        assert [f["sequence"] for _, f in entries] == ["0", "1"]
        assert entries[1][1]["prev_hash"] == entries[0][1]["record_hash"]

    @pytest.mark.asyncio
    async def test_persistent_contention_fails_closed(self):
        """If every attempt loses the head, ingest raises instead of forking."""
        from src.gateway.governance.evidence.stream import (
            _MAX_APPEND_ATTEMPTS,
            EvidenceChainUnavailableError,
        )

        sink = _make_sink()
        sink._redis = _fake_redis()
        await sink.ingest({"type": "X"})

        conflict = AsyncMock(return_value=["CONFLICT"])
        with patch.object(sink._redis, "eval", conflict):
            with pytest.raises(EvidenceChainUnavailableError, match="head race"):
                await sink.ingest({"type": "Y"})
        assert conflict.await_count == _MAX_APPEND_ATTEMPTS
        assert sink.total_records == 1


# ---------------------------------------------------------------------------
# 6. Lifecycle — start / stop / start_evidence_sink
# ---------------------------------------------------------------------------


class TestEvidenceStreamSinkLifecycle:
    """Tests for start() / stop() lifecycle semantics."""

    @pytest.mark.asyncio
    async def test_start_sets_running(self):
        sink = _make_sink()
        with patch(
            "src.gateway.infrastructure.redis_client.build_async_redis",
            return_value=_fake_redis(),
        ):
            await sink.start()
        assert sink.is_running is True
        await sink.stop()

    @pytest.mark.asyncio
    async def test_start_twice_is_idempotent(self):
        sink = _make_sink()
        redis = _fake_redis()
        with patch(
            "src.gateway.infrastructure.redis_client.build_async_redis",
            return_value=redis,
        ) as from_url:
            await sink.start()
            await sink.start()
        assert sink.is_running is True
        assert from_url.call_count == 1
        await sink.stop()

    @pytest.mark.asyncio
    async def test_stop_sets_not_running_and_drops_client(self):
        sink = _make_sink()
        with patch(
            "src.gateway.infrastructure.redis_client.build_async_redis",
            return_value=_fake_redis(),
        ):
            await sink.start()
        await sink.stop()
        assert sink.is_running is False
        assert await sink.ingest({"type": "AUDIT_FINDING"}) is None

    @pytest.mark.asyncio
    async def test_stop_without_start_does_not_raise(self):
        await _make_sink().stop()


class TestStartEvidenceSink:
    """start_evidence_sink() is what the gateway lifespan calls."""

    @pytest.fixture(autouse=True)
    def _fresh_singleton(self, monkeypatch):
        import src.gateway.governance.evidence.stream as mod

        monkeypatch.setattr(mod, "_evidence_sink", None)

    @pytest.mark.asyncio
    async def test_disabled_stream_returns_none(self, monkeypatch):
        from src.gateway.governance.evidence.stream import start_evidence_sink

        monkeypatch.setenv("EVIDENCE_STREAM_ENABLED", "false")
        assert await start_evidence_sink() is None

    @pytest.mark.asyncio
    async def test_starts_the_singleton(self, monkeypatch):
        from src.gateway.governance.evidence.stream import (
            get_evidence_sink,
            start_evidence_sink,
        )

        monkeypatch.setenv("EVIDENCE_STREAM_ENABLED", "true")
        with patch(
            "src.gateway.infrastructure.redis_client.build_async_redis",
            return_value=_fake_redis(),
        ):
            sink = await start_evidence_sink()
        assert sink is get_evidence_sink()
        assert sink.is_running
        await sink.stop()

    @pytest.mark.asyncio
    async def test_unreachable_redis_fails_startup_when_enforcing(self, monkeypatch):
        from src.gateway.governance.evidence.stream import (
            EvidenceChainUnavailableError,
            start_evidence_sink,
        )

        monkeypatch.setenv("EVIDENCE_STREAM_ENABLED", "true")
        monkeypatch.setenv("CAGE_ENV", "production")
        broken = AsyncMock()
        broken.ping = AsyncMock(side_effect=ConnectionRefusedError("no redis"))
        with patch(
            "src.gateway.infrastructure.redis_client.build_async_redis",
            return_value=broken,
        ):
            with pytest.raises(EvidenceChainUnavailableError, match="enforcing"):
                await start_evidence_sink()

    @pytest.mark.asyncio
    async def test_unreachable_redis_is_tolerated_when_permissive(self, monkeypatch):
        from src.gateway.governance.evidence.stream import start_evidence_sink

        monkeypatch.setenv("EVIDENCE_STREAM_ENABLED", "true")
        monkeypatch.setenv("CAGE_ENV", "test")
        broken = AsyncMock()
        broken.ping = AsyncMock(side_effect=ConnectionRefusedError("no redis"))
        with patch(
            "src.gateway.infrastructure.redis_client.build_async_redis",
            return_value=broken,
        ):
            sink = await start_evidence_sink()
        assert sink is not None and not sink.is_running


# ---------------------------------------------------------------------------
# 7. Layer purity
# ---------------------------------------------------------------------------


class TestLayerPurity:
    def test_sink_imports_no_vendor_module(self):
        """AST check: stream.py must not import vendor storage SDKs."""
        import inspect

        from src.gateway.governance.evidence import stream as evidence_stream

        tree = ast.parse(inspect.getsource(evidence_stream))
        forbidden_prefixes = ("google.cloud", "boto3", "botocore", "azure")
        imported: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.append(node.module)

        for mod in imported:
            assert not mod.startswith(forbidden_prefixes), mod
            assert "compliance_bridge" not in mod, mod
            assert "kms_signer" not in mod, mod


# ---------------------------------------------------------------------------
# 8. Fail-closed chain state restoration
# ---------------------------------------------------------------------------


class TestEvidenceChainRestoration:
    """Tests for fail-closed chain state restoration."""

    @pytest.mark.asyncio
    async def test_restore_from_non_empty_stream_resumes_chain(self):
        """Restart with a non-empty stream -> chain_id preserved, resumes at seq+1."""
        redis = _fake_redis()
        await redis.xadd(
            STREAM_KEY,
            {"chain_id": "test-chain-123", "record_hash": "a" * 64, "sequence": "42"},
        )
        sink = _make_sink()
        with patch(
            "src.gateway.infrastructure.redis_client.build_async_redis",
            return_value=redis,
        ):
            await sink.start()

        assert sink.chain_id == "test-chain-123"
        assert sink.chain_root == "a" * 64
        assert sink.total_records == 43

    @pytest.mark.asyncio
    async def test_restart_continues_chain_across_processes(self):
        server = fakeredis.FakeServer()
        first = _make_sink()
        first._redis = _fake_redis(server)
        await first.ingest({"type": "X"})

        second = _make_sink()
        with patch(
            "src.gateway.infrastructure.redis_client.build_async_redis",
            return_value=_fake_redis(server),
        ):
            await second.start()
        await second.ingest({"type": "Y"})

        entries = await _entries(second._redis)
        assert entries[1][1]["chain_id"] == entries[0][1]["chain_id"]
        assert entries[1][1]["prev_hash"] == entries[0][1]["record_hash"]

    @pytest.mark.asyncio
    async def test_corrupted_last_entry_raises_does_not_regenesis(self):
        from src.gateway.governance.evidence.stream import EvidenceChainCorruptError

        redis = _fake_redis()
        await redis.xadd(
            STREAM_KEY,
            {
                "chain_id": "test-chain-123",
                "record_hash": "short-hash",
                "sequence": "42",
            },
        )
        sink = _make_sink()
        with patch(
            "src.gateway.infrastructure.redis_client.build_async_redis",
            return_value=redis,
        ):
            with pytest.raises(
                EvidenceChainCorruptError,
                match="record_hash is not 64 lowercase hex chars",
            ):
                await sink.start()

    @pytest.mark.asyncio
    async def test_genesis_record_has_empty_prev_hash(self):
        sink = _make_sink()
        with patch(
            "src.gateway.infrastructure.redis_client.build_async_redis",
            return_value=_fake_redis(),
        ):
            await sink.start()
        await sink.ingest({"type": "TEST", "controlId": "A.5.3"})
        (_id, fields) = (await _entries(sink._redis))[0]
        assert fields["prev_hash"] == ""
        assert fields["sequence"] == "0"

    @pytest.mark.asyncio
    async def test_kernel_emitted_record_satisfies_constraints(self):
        """A kernel-emitted record satisfies chk_schema_version and chk_trace_id_present."""
        sink = _make_sink()
        with patch(
            "src.gateway.infrastructure.redis_client.build_async_redis",
            return_value=_fake_redis(),
        ):
            await sink.start()
        await sink.ingest({"type": "TEST", "controlId": "A.5.3"})
        (_id, entry) = (await _entries(sink._redis))[0]
        assert entry["schema"].startswith("cage-audit/")
        assert len(entry["trace_id"]) == 32


class TestEvidenceStreamCanonicalization:
    def test_link_hash_matches_ddl_view(self):
        """Python _link_hash output matches a hand-built canonical header replicating the DDL view exactly."""
        from src.gateway.governance.evidence.stream import (
            _link_hash,
            _sha256,
            jcs_canonicalize_plan,
        )

        actual_hash = _link_hash(
            prev_hash="a" * 64,
            sequence=1,
            event_type="TEST",
            control_id="C.1",
            payload_json='{"test": 1}',
            chain_id="chain-123",
            trace_id="trace-123" + "0" * 23,
            classification_reason="reason",
            narrowing_applied={"k": "v"},
            pause_token="pause-1",
        )

        canonical_header = {
            "canonicalization": "RFC8785",
            "chain_id": "chain-123",
            "classification_reason": "reason",
            "control_id": "C.1",
            "event_type": "TEST",
            "hash_algorithm": "SHA-256",
            "narrowing_applied": {"k": "v"},
            "pause_token": "pause-1",
            "schema": "cage-audit/3.0",
            "sequence": 1,
            "trace_id": "trace-123" + "0" * 23,
        }

        header_bytes = jcs_canonicalize_plan(canonical_header)
        expected_hash = _sha256(b"a" * 64 + header_bytes + b'{"test": 1}')

        assert actual_hash == expected_hash


class TestLifespanWiring:
    """E1 regression: the gateway must start the sink; the bridge must custody."""

    def test_gateway_lifespan_starts_and_stops_the_sink(self):
        import inspect

        from src.gateway.server import hybrid_server

        source = inspect.getsource(hybrid_server._gateway_lifespan)
        assert "await start_evidence_sink()" in source
        assert "await evidence_sink.stop()" in source

    def test_bridge_lifespan_runs_the_custodian(self):
        import inspect

        from src.compliance_bridge import main as bridge_main

        source = inspect.getsource(bridge_main.lifespan)
        assert "EvidenceCustodian.from_env()" in source
        assert "run_forever()" in source
        assert "validate_evidence_stream_preconditions" not in source
