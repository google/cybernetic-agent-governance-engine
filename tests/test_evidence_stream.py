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
  - Retry-safe appends (#511): a lost reply, a re-sent script or a surfaced
    timeout never writes an event twice, and an unsettled append fails closed
  - Redis-unavailable graceful no-op path
  - start() / stop() lifecycle and start_evidence_sink() posture handling
  - Fail-closed chain state restoration: an unverifiable head, and (for a sink
    that holds a chain) an emptied, rotated or regressed stream, are corrupt
  - get_evidence_sink() singleton

Signing and cold-store custody are the compliance bridge's job and are tested
in tests/test_evidence_custodian.py. All tests here are hermetic: Redis is
fakeredis (with Lua), no GCS, no KMS.
"""

import ast
import asyncio
import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import fakeredis
import pytest
from redis.exceptions import TimeoutError as RedisTimeoutError

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


def _assert_linear(entries) -> None:
    """One chain, sequences 0..n-1, every record verifying and linking."""
    from src.gateway.governance.evidence.stream import verify_record

    assert len({f["chain_id"] for _, f in entries}) == 1
    prev = ""
    for i, (_id, fields) in enumerate(entries):
        assert int(fields["sequence"]) == i
        assert fields["prev_hash"] == prev
        assert verify_record(fields, prev_hash=prev).valid
        prev = fields["record_hash"]


def _sealed_entry(
    chain_id: str = "test-chain-123", sequence: int = 42, prev_hash: str = "b" * 64
) -> dict[str, str]:
    """A wire entry whose record_hash really is the hash of its own fields."""
    sealer = _make_sink()
    sealer._chain_id = chain_id
    entry, _record_hash = sealer._seal_record(
        {"type": "AUDIT_FINDING"},
        '{"n":42}',
        "AUDIT_FINDING",
        "A.5.3",
        datetime.now(tz=timezone.utc),
        prev_hash=prev_hash,
        sequence=sequence,
    )
    return entry


class _LostReply:
    """A fakeredis client whose first append script(s) lose their reply.

    The script still runs inside Redis; only the answer is lost. ``mode``:

    * ``"resend"`` - redis-py's ``Retry`` re-sends the identical script and
      the sink gets the second answer (the path reported in #511).
    * ``"timeout"`` - the client's retries are exhausted, so redis
      ``TimeoutError`` reaches the sink after the script ran.
    * ``"drop"`` - the request never reached Redis; ``TimeoutError`` reaches
      the sink and the script did not run.

    ``between`` runs after the first execution and before the re-send, to
    model another writer appending in that window. ``sent_argv`` records the
    ARGV of every script call the sink made.
    """

    def __init__(self, inner, mode="resend", between=None, lossy_calls=1):
        self._inner = inner
        self._mode = mode
        self._between = between
        self._lossy_calls = lossy_calls
        self.sent_argv: list[tuple] = []

    def __getattr__(self, name):
        return getattr(self._inner, name)

    async def evalsha(self, *args, **kwargs):
        return await self._send(self._inner.evalsha, *args, **kwargs)

    async def eval(self, *args, **kwargs):
        return await self._send(self._inner.eval, *args, **kwargs)

    async def _send(self, call, *args, **kwargs):
        self.sent_argv.append(tuple(args[3:]))
        if len(self.sent_argv) > self._lossy_calls:
            return await call(*args, **kwargs)
        if self._mode == "drop":
            raise RedisTimeoutError("request lost before it reached Redis")
        await call(*args, **kwargs)  # runs in Redis; the reply is lost
        if self._between is not None:
            await self._between()
        if self._mode == "timeout":
            raise RedisTimeoutError("reply lost after Redis ran the script")
        return await call(*args, **kwargs)  # the client re-sends it


async def _lossy(server, **kwargs) -> _LostReply:
    from src.gateway.governance.evidence.stream import _APPEND_BATCH_SCRIPT

    inner = _fake_redis(server)
    await inner.script_load(_APPEND_BATCH_SCRIPT)  # so the first EVALSHA runs
    return _LostReply(inner, **kwargs)


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
        from src.gateway.governance.evidence.stream import _APPEND_BATCH_SCRIPT

        redis = _fake_redis()
        sink = _make_sink()
        sink._redis = redis
        await sink.ingest({"type": "X"})

        result = await redis.eval(
            _APPEND_BATCH_SCRIPT,
            1,
            STREAM_KEY,
            sink.chain_id,
            "1",
            "f" * 64,
            "1000",
            "1",
            "e" * 64,
            "2026-01-01T00:00:00+00:00",
            "2",
            "k",
            "v",
        )
        assert result == ["CONFLICT"]
        assert len(await _entries(redis)) == 1

    @pytest.mark.asyncio
    async def test_non_genesis_append_to_empty_stream_is_rejected(self):
        from src.gateway.governance.evidence.stream import _APPEND_BATCH_SCRIPT

        redis = _fake_redis()
        result = await redis.eval(
            _APPEND_BATCH_SCRIPT,
            1,
            STREAM_KEY,
            "c",
            "5",
            "a" * 64,
            "1000",
            "1",
            "e" * 64,
            "2026-01-01T00:00:00+00:00",
            "2",
            "k",
            "v",
        )
        assert result == ["CONFLICT"]
        assert await _entries(redis) == []

    @pytest.mark.asyncio
    async def test_resent_script_answers_already_without_appending(self):
        """#511: the same sealing sent twice lands once and reports the same IDs."""
        from src.gateway.governance.evidence.stream import _APPEND_BATCH_SCRIPT

        redis = _fake_redis()
        sink = _make_sink()
        sink._redis = redis
        await sink.ingest({"type": "GENESIS"})
        async with sink._chain_lock:
            sealed = sink._seal_batch(
                [
                    sink._prepare_item({"type": "E", "i": i}, future=None)
                    for i in range(3)
                ]
            )

        first = await redis.eval(_APPEND_BATCH_SCRIPT, 1, STREAM_KEY, *sealed.args)
        again = await redis.eval(_APPEND_BATCH_SCRIPT, 1, STREAM_KEY, *sealed.args)

        assert first[0] == "OK"
        assert again == ["ALREADY", *first[1:]]
        entries = await _entries(redis)
        assert [entry_id for entry_id, _ in entries[1:]] == first[1:]
        _assert_linear(entries)

        # The same records under another sealing's timestamp are not "this
        # batch": the head check also pins the last record's timestamp.
        other_sealing = list(sealed.args)
        other_sealing[6] = "2000-01-01T00:00:00+00:00"
        assert await redis.eval(
            _APPEND_BATCH_SCRIPT, 1, STREAM_KEY, *other_sealing
        ) == ["CONFLICT"]
        assert len(await _entries(redis)) == 4

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
        head = _sealed_entry(chain_id="test-chain-123", sequence=42)
        await redis.xadd(STREAM_KEY, head)
        sink = _make_sink()
        with patch(
            "src.gateway.infrastructure.redis_client.build_async_redis",
            return_value=redis,
        ):
            await sink.start()

        assert sink.chain_id == "test-chain-123"
        assert sink.chain_root == head["record_hash"]
        assert sink.total_records == 43
        await sink.stop()

    @pytest.mark.asyncio
    async def test_well_formed_head_with_arbitrary_hash_is_rejected(self):
        """#511: the old ``"a" * 64`` fixture is shaped right but proves nothing."""
        from src.gateway.governance.evidence.stream import EvidenceChainCorruptError

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
            with pytest.raises(EvidenceChainCorruptError, match="prev_hash is missing"):
                await sink.start()
        assert sink.is_running is False
        assert len(await _entries(redis)) == 1

    @pytest.mark.asyncio
    async def test_head_that_does_not_hash_to_its_record_hash_is_rejected(self):
        """#511: a head whose payload no longer matches its hash is corrupt."""
        from src.gateway.governance.evidence.stream import EvidenceChainCorruptError

        redis = _fake_redis()
        await redis.xadd(STREAM_KEY, {**_sealed_entry(), "payload_json": '{"n":999}'})
        sink = _make_sink()
        with patch(
            "src.gateway.infrastructure.redis_client.build_async_redis",
            return_value=redis,
        ):
            with pytest.raises(
                EvidenceChainCorruptError, match="does not hash to its record_hash"
            ):
                await sink.start()
        assert len(await _entries(redis)) == 1

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


# ---------------------------------------------------------------------------
# 9. Group-commit batching, conflict re-chaining, trace shedding, and drain
# ---------------------------------------------------------------------------


class TestEvidenceGroupCommit:
    """Tests for Wave C2 group-commit batching in EvidenceStreamSink."""

    @pytest.mark.asyncio
    async def test_batch_ordering_coalesces_concurrent_ingests(self):
        """Concurrent ingests coalesce into a single _APPEND_BATCH_SCRIPT call and preserve order."""
        import asyncio

        from src.gateway.governance.evidence.stream import verify_record

        sink = _make_sink(max_batch_size=16, max_wait_ms=10.0)
        redis = _fake_redis()
        sink._redis = redis

        eval_calls = 0
        orig_eval = redis.eval

        async def counting_eval(*args, **kwargs):
            nonlocal eval_calls
            eval_calls += 1
            return await orig_eval(*args, **kwargs)

        with patch.object(redis, "eval", side_effect=counting_eval):
            msg_ids = await asyncio.gather(
                *(
                    sink.ingest({"type": "GOVERNANCE_DECISION", "seq_hint": i})
                    for i in range(10)
                )
            )

        assert all(m is not None for m in msg_ids)
        assert len(set(msg_ids)) == 10
        # All 10 concurrent items coalesced into far fewer than 10 script calls (typically 1)
        assert eval_calls <= 2

        entries = await _entries(redis)
        assert len(entries) == 10
        prev = ""
        for i, (entry_id, fields) in enumerate(entries):
            assert entry_id == msg_ids[i]
            assert int(fields["sequence"]) == i
            assert fields["prev_hash"] == prev
            assert verify_record(fields, prev_hash=prev).valid
            prev = fields["record_hash"]

        await sink.stop()

    @pytest.mark.asyncio
    async def test_conflict_rechaining_reseals_entire_batch_against_new_head(self):
        """When another writer advances the head before a batch lands, the whole batch re-chains cleanly."""
        import asyncio

        from src.gateway.governance.evidence.stream import verify_record

        server = fakeredis.FakeServer()
        sink = _make_sink(max_batch_size=8, max_wait_ms=10.0)
        other = _make_sink(max_batch_size=1, max_wait_ms=0.0)
        sink._redis = _fake_redis(server)
        other._redis = _fake_redis(server)

        # Seed genesis so both sinks share the same chain_id
        await sink.ingest({"type": "GENESIS"})

        orig_eval_batch = sink._eval_batch_script
        injected_conflict = False

        async def conflict_once(args):
            nonlocal injected_conflict
            if not injected_conflict:
                injected_conflict = True
                # External writer appends seq=1 while sink's batch was sealed at seq=1..3
                await other.ingest({"type": "INTERLEAVED_WRITER"})
            return await orig_eval_batch(args)

        with patch.object(sink, "_eval_batch_script", side_effect=conflict_once):
            ids = await asyncio.gather(
                sink.ingest({"type": "BATCH_A", "i": 1}),
                sink.ingest({"type": "BATCH_A", "i": 2}),
                sink.ingest({"type": "BATCH_A", "i": 3}),
            )

        assert injected_conflict is True
        assert all(m is not None for m in ids)

        entries = await _entries(sink._redis)
        assert len(entries) == 5  # genesis (0), interleaved (1), batch of 3 (2, 3, 4)
        prev = ""
        for i, (_id, fields) in enumerate(entries):
            assert int(fields["sequence"]) == i
            assert fields["prev_hash"] == prev
            assert verify_record(fields, prev_hash=prev).valid
            prev = fields["record_hash"]

        await sink.stop()
        await other.stop()

    @pytest.mark.asyncio
    async def test_two_sinks_concurrent_batches_produce_no_fork(self):
        """Two sinks concurrently writing batches to one Redis never fork and verify end-to-end."""
        import asyncio

        from src.gateway.governance.evidence.stream import verify_record

        server = fakeredis.FakeServer()
        sink_a = _make_sink(max_batch_size=8, max_wait_ms=2.0)
        sink_b = _make_sink(max_batch_size=8, max_wait_ms=2.0)
        sink_a._redis = _fake_redis(server)
        sink_b._redis = _fake_redis(server)

        # Establish genesis so both replicas share chain_id
        await sink_a.ingest({"type": "GENESIS"})

        tasks = []
        for i in range(12):
            tasks.append(sink_a.ingest({"type": "REPLICA_A", "i": i}))
            tasks.append(sink_b.ingest({"type": "REPLICA_B", "i": i}))

        results = await asyncio.gather(*tasks)
        assert all(r is not None for r in results)

        entries = await _entries(sink_a._redis)
        assert len(entries) == 25
        assert len({f["chain_id"] for _, f in entries}) == 1

        prev = ""
        for i, (_id, fields) in enumerate(entries):
            assert int(fields["sequence"]) == i
            assert fields["prev_hash"] == prev
            assert verify_record(fields, prev_hash=prev).valid
            prev = fields["record_hash"]

        await sink_a.stop()
        await sink_b.stop()

    @pytest.mark.asyncio
    async def test_refusal_receipts_never_dropped_when_queue_full(self):
        """Refusal receipts use awaited enqueue (ingest) and wait for capacity rather than dropping."""
        import asyncio

        from src.gateway.governance.evidence.stream import verify_record

        sink = _make_sink(queue_size=2, max_batch_size=4, max_wait_ms=5.0)
        sink._redis = _fake_redis()

        # Submit 6 refusal receipts concurrently across a queue of size 2
        results = await asyncio.gather(
            *(
                sink.ingest(
                    {
                        "type": "GOVERNANCE_REFUSAL",
                        "controlId": "A.5.3",
                        "idx": i,
                    }
                )
                for i in range(6)
            )
        )
        assert all(r is not None for r in results)
        entries = await _entries(sink._redis)
        assert len(entries) == 6
        prev = ""
        for i, (_id, fields) in enumerate(entries):
            assert int(fields["sequence"]) == i
            assert verify_record(fields, prev_hash=prev).valid
            prev = fields["record_hash"]

        await sink.stop()

    @pytest.mark.asyncio
    async def test_trace_shedding_when_queue_full_increments_metric(self):
        """Only GOVERNANCE_TRACE events use submit() and are shed with a metric when the queue is full."""
        import asyncio

        from src.gateway.governance.evidence.stream import EVIDENCE_TRACE_SHED_TOTAL

        sink = _make_sink(queue_size=2, max_batch_size=4, max_wait_ms=50.0)
        sink._redis = _fake_redis()

        # Block the appender loop from draining the queue while we fill it
        gate = asyncio.Event()
        orig_commit = sink._commit_batch

        async def gated_commit(batch):
            await gate.wait()
            await orig_commit(batch)

        with patch.object(sink, "_commit_batch", side_effect=gated_commit):
            before = (
                EVIDENCE_TRACE_SHED_TOTAL._value.get()
                if EVIDENCE_TRACE_SHED_TOTAL is not None
                else 0.0
            )
            # First event starts the appender and may be pulled immediately;
            # fill until queue is full and subsequent submit() sheds.
            accepted = [
                sink.submit({"type": "GOVERNANCE_TRACE", "i": i}) for i in range(6)
            ]
            assert any(not ok for ok in accepted)
            if EVIDENCE_TRACE_SHED_TOTAL is not None:
                after = EVIDENCE_TRACE_SHED_TOTAL._value.get()
                assert after > before

            # Refusal receipts are forbidden on submit()
            with pytest.raises(ValueError, match="GOVERNANCE_TRACE"):
                sink.submit({"type": "GOVERNANCE_REFUSAL"})

            gate.set()

        await sink.stop()

    @pytest.mark.asyncio
    async def test_stop_drains_queued_records_before_closing_redis(self):
        """stop() drains pending items already in the queue before closing Redis."""
        redis = _fake_redis()
        sink = _make_sink(queue_size=16, max_batch_size=8, max_wait_ms=200.0)
        sink._redis = redis

        # Enqueue 4 trace events via non-blocking submit() and immediately call stop()
        for i in range(4):
            assert sink.submit({"type": "GOVERNANCE_TRACE", "i": i}) is True

        await sink.stop()

        entries = await _entries(redis)
        assert len(entries) == 4
        assert [int(f["sequence"]) for _, f in entries] == [0, 1, 2, 3]


# ---------------------------------------------------------------------------
# 10. Retry-safe appends (#511)
# ---------------------------------------------------------------------------


class TestRetrySafeAppend:
    """A lost Redis reply never puts an event in the chain twice."""

    @pytest.mark.asyncio
    async def test_lost_reply_resend_writes_each_event_once(self):
        """The re-sent script finds its own batch at the head (ALREADY)."""
        server = fakeredis.FakeServer()
        redis = await _lossy(server, mode="resend")
        sink = _make_sink(max_batch_size=8, max_wait_ms=20.0)
        sink._redis = redis

        results = await asyncio.gather(
            *(sink.ingest_sync({"type": "G1_EVENT", "n": i}) for i in range(3))
        )

        entries = await _entries(_fake_redis(server))
        assert len(entries) == 3
        _assert_linear(entries)
        by_n = {json.loads(f["payload_json"])["n"]: (eid, f) for eid, f in entries}
        assert sorted(by_n) == [0, 1, 2]
        for n, result in enumerate(results):
            entry_id, fields = by_n[n]
            assert result.evidence_id == entry_id
            assert result.hash == fields["record_hash"]
            assert result.sequence == int(fields["sequence"])

        # The chain continues from the batch, not from a second copy of it.
        await sink.ingest({"type": "NEXT"})
        entries = await _entries(_fake_redis(server))
        assert len(entries) == 4
        _assert_linear(entries)
        await sink.stop()

    @pytest.mark.asyncio
    async def test_lost_reply_then_other_writer_resolves_without_reseal(self):
        """The re-send meets CONFLICT, but the batch already sits after its predecessor."""
        server = fakeredis.FakeServer()
        other = _make_sink()
        other._redis = _fake_redis(server)
        await other.ingest({"type": "GENESIS"})

        async def other_writer_appends():
            await other.ingest({"type": "INTERLEAVED"})

        redis = await _lossy(server, mode="resend", between=other_writer_appends)
        sink = _make_sink()
        sink._redis = redis
        result = await sink.ingest_sync({"type": "MINE"})

        entries = await _entries(_fake_redis(server))
        assert [f["event_type"] for _, f in entries] == [
            "GENESIS",
            "MINE",
            "INTERLEAVED",
        ]
        _assert_linear(entries)
        assert (result.evidence_id, result.sequence) == (entries[1][0], 1)
        assert len(redis.sent_argv) == 1  # resolved from the stream, not re-sealed

        await sink.ingest({"type": "AFTER"})
        entries = await _entries(_fake_redis(server))
        assert entries[-1][1]["event_type"] == "AFTER"
        _assert_linear(entries)
        await sink.stop()
        await other.stop()

    @pytest.mark.asyncio
    async def test_genuine_contention_still_reseals_in_order(self):
        """A real lost race is not mistaken for a landed batch."""
        from src.gateway.governance.evidence.stream import (
            EVIDENCE_APPEND_CONFLICTS_TOTAL,
        )

        server = fakeredis.FakeServer()
        sink = _make_sink(max_batch_size=8, max_wait_ms=20.0)
        other = _make_sink()
        sink._redis, other._redis = _fake_redis(server), _fake_redis(server)
        await sink.ingest({"type": "GENESIS"})

        sent: list[list[str]] = []
        original = sink._eval_batch_script

        async def other_writer_first(args):
            if not sent:
                await other.ingest({"type": "OTHER"})  # takes sequence 1 first
            sent.append(list(args))
            return await original(args)

        conflicts_before = EVIDENCE_APPEND_CONFLICTS_TOTAL._value.get()
        with patch.object(sink, "_eval_batch_script", side_effect=other_writer_first):
            results = await asyncio.gather(
                *(sink.ingest_sync({"type": "MINE", "i": i}) for i in range(3))
            )

        entries = await _entries(sink._redis)
        assert [f["event_type"] for _, f in entries] == [
            "GENESIS",
            "OTHER",
            "MINE",
            "MINE",
            "MINE",
        ]
        _assert_linear(entries)
        assert [json.loads(f["payload_json"])["i"] for _, f in entries[2:]] == [0, 1, 2]
        assert sorted(r.sequence for r in results) == [2, 3, 4]
        # Sealed at sequence 1, lost the race, re-sealed at sequence 2.
        assert (sent[0][1], sent[1][1]) == ("1", "2")
        assert EVIDENCE_APPEND_CONFLICTS_TOTAL._value.get() == conflicts_before + 1
        await sink.stop()
        await other.stop()

    @pytest.mark.asyncio
    async def test_surfaced_timeout_after_landing_settles_as_success(self):
        server = fakeredis.FakeServer()
        redis = await _lossy(server, mode="timeout")
        sink = _make_sink()
        sink._redis = redis

        result = await sink.ingest_sync({"type": "LANDED"})

        entries = await _entries(_fake_redis(server))
        assert len(entries) == 1
        assert (result.evidence_id, result.sequence, result.hash) == (
            entries[0][0],
            0,
            entries[0][1]["record_hash"],
        )
        # Settled by re-sending the identical ARGV, never by re-sealing.
        assert len(redis.sent_argv) == 2
        assert redis.sent_argv[0] == redis.sent_argv[1]
        await sink.stop()

    @pytest.mark.asyncio
    async def test_surfaced_timeout_before_landing_appends_exactly_once(self):
        server = fakeredis.FakeServer()
        redis = await _lossy(server, mode="drop")
        sink = _make_sink()
        sink._redis = redis

        result = await sink.ingest_sync({"type": "DROPPED"})

        entries = await _entries(_fake_redis(server))
        assert len(entries) == 1
        assert (result.evidence_id, result.sequence) == (entries[0][0], 0)
        assert len(redis.sent_argv) == 2
        assert redis.sent_argv[0] == redis.sent_argv[1]
        await sink.stop()

    @pytest.mark.asyncio
    async def test_unsettled_append_fails_closed_without_resealing(self):
        from src.gateway.governance.evidence.stream import (
            _MAX_SETTLE_ATTEMPTS,
            EvidenceAppendUnsettledError,
        )

        server = fakeredis.FakeServer()
        redis = await _lossy(server, mode="drop", lossy_calls=99)
        sink = _make_sink()
        sink._redis = redis

        with pytest.raises(
            EvidenceAppendUnsettledError, match="whether it landed is unknown"
        ):
            await sink.ingest_sync({"type": "UNSETTLED"})

        assert len(redis.sent_argv) == _MAX_SETTLE_ATTEMPTS + 1
        assert len(set(redis.sent_argv)) == 1  # one sealing, re-sent verbatim
        assert await _entries(_fake_redis(server)) == []
        # Best-effort ingest() reports an unsettled append as a failed write.
        assert await sink.ingest({"type": "UNSETTLED_BEST_EFFORT"}) is None
        await sink.stop()


# ---------------------------------------------------------------------------
# 11. Restore under a live chain (#511)
# ---------------------------------------------------------------------------


class TestLiveChainRestore:
    """A sink that holds a chain never re-genesises or resumes over a broken stream."""

    @pytest.mark.asyncio
    async def test_emptied_stream_under_live_sink_is_corrupt_not_genesis(self):
        from src.gateway.governance.evidence.stream import EvidenceChainCorruptError

        redis = _fake_redis()
        sink = _make_sink()
        sink._redis = redis
        await sink.ingest({"type": "X"})
        await redis.delete(STREAM_KEY)

        with pytest.raises(EvidenceChainCorruptError, match="stream is empty"):
            await sink.ingest_sync({"type": "Y"})
        assert await _entries(redis) == []
        # Still refused on the next write: no silent re-genesis.
        with pytest.raises(EvidenceChainCorruptError):
            await sink.ingest({"type": "Z"})
        assert await _entries(redis) == []
        await sink.stop()

    @pytest.mark.asyncio
    async def test_regressed_head_is_corrupt(self):
        from src.gateway.governance.evidence.stream import EvidenceChainCorruptError

        redis = _fake_redis()
        sink = _make_sink()
        sink._redis = redis
        for i in range(3):
            await sink.ingest({"type": "X", "n": i})
        entries = await _entries(redis)
        await redis.xdel(STREAM_KEY, entries[-1][0])  # the acknowledged head is gone

        with pytest.raises(
            EvidenceChainCorruptError, match="behind the last acknowledged sequence"
        ):
            await sink.ingest({"type": "NEXT"})
        assert len(await _entries(redis)) == 2
        await sink.stop()

    @pytest.mark.asyncio
    async def test_rewritten_head_at_the_same_sequence_is_corrupt(self):
        from src.gateway.governance.evidence.stream import EvidenceChainCorruptError

        server = fakeredis.FakeServer()
        sink = _make_sink()
        sink._redis = _fake_redis(server)
        for i in range(2):
            await sink.ingest({"type": "X", "n": i})
        redis = _fake_redis(server)
        await redis.xdel(STREAM_KEY, (await _entries(redis))[-1][0])
        rewriter = _make_sink()
        rewriter._redis = _fake_redis(server)
        await rewriter.ingest({"type": "REWRITTEN"})  # a valid, different seq 1

        with pytest.raises(EvidenceChainCorruptError, match="no longer holds"):
            await sink.ingest({"type": "NEXT"})
        await sink.stop()
        await rewriter.stop()

    @pytest.mark.asyncio
    async def test_head_on_another_chain_is_corrupt(self):
        from src.gateway.governance.evidence.stream import EvidenceChainCorruptError

        server = fakeredis.FakeServer()
        sink = _make_sink()
        sink._redis = _fake_redis(server)
        await sink.ingest({"type": "X"})
        await _fake_redis(server).delete(STREAM_KEY)
        fresh = _make_sink()  # a genuinely fresh sink may cold-start
        fresh._redis = _fake_redis(server)
        await fresh.ingest({"type": "NEW_CHAIN"})
        assert fresh.chain_id != sink.chain_id

        with pytest.raises(
            EvidenceChainCorruptError, match="but this sink holds chain"
        ):
            await sink.ingest({"type": "NEXT"})
        entries = await _entries(_fake_redis(server))
        assert [f["event_type"] for _, f in entries] == ["NEW_CHAIN"]
        await sink.stop()
        await fresh.stop()

    @pytest.mark.asyncio
    async def test_cold_start_race_adopts_the_winning_chain(self):
        """Minting a genesis chain is not holding one: the loser adopts the winner."""
        server = fakeredis.FakeServer()
        a, b = _make_sink(), _make_sink()
        a._redis, b._redis = _fake_redis(server), _fake_redis(server)
        for sink in (a, b):
            async with sink._chain_lock:
                await sink._ensure_chain_restored()  # both see an empty stream
        assert a.chain_id != b.chain_id

        await a.ingest({"type": "A"})
        await b.ingest({"type": "B"})

        entries = await _entries(a._redis)
        assert [f["event_type"] for _, f in entries] == ["A", "B"]
        assert b.chain_id == a.chain_id
        _assert_linear(entries)
        await a.stop()
        await b.stop()
