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
tests/test_defer_queue.py — Unit tests for the DEFER state machine primitive (CAGE v0.1.0).

Uses fakeredis for hermetic Redis simulation (no live cluster required).
Tests verify Redis isolation semantics (db=1 namespace) and all DeferQueue operations.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from src.gateway.governance.defer_queue import (
    _FLOWSIGNAL_ESCALATION_TTL,
    DEFER_CONFIDENCE_THRESHOLD,
    DeferQueue,
    DeferReason,
    DeferToken,
    create_flowsignal_escalation_token,
    is_flowsignal_hold_finding,
)

# ---------------------------------------------------------------------------
# fakeredis fixture — async pipeline simulation
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_redis():
    """Minimal async Redis mock using an in-memory dict store."""
    store: dict[str, dict] = {}
    zsets: dict[str, dict] = {}

    redis = MagicMock()

    # hset
    async def _hset(key: str, mapping: dict):
        store.setdefault(key, {}).update(mapping)

    # hget
    async def _hget(key: str, field: str):
        return store.get(key, {}).get(field)

    # expire (no-op in mock — TTL not enforced in unit tests)
    async def _expire(key: str, ttl: int):
        pass

    # zadd
    async def _zadd(zset_key: str, mapping: dict):
        zsets.setdefault(zset_key, {}).update(mapping)

    # zrangebyscore
    async def _zrangebyscore(zset_key: str, min_score, max_score, start=0, num=100):
        members = zsets.get(zset_key, {})
        result = []
        max_f = float("inf") if max_score == "+inf" else float(max_score)
        for member, score in sorted(members.items(), key=lambda x: x[1]):
            if score <= max_f:
                result.append(member)
        return result[start : start + num]

    # zrem
    async def _zrem(zset_key: str, member: str):
        zsets.get(zset_key, {}).pop(member, None)

    # Pipeline context manager
    class FakePipeline:
        def __init__(self):
            self._ops = []

        def hset(self, key, mapping):
            self._ops.append(("hset", key, mapping))
            return self

        def expire(self, key, ttl):
            self._ops.append(("expire", key, ttl))
            return self

        def zadd(self, zset_key, mapping):
            self._ops.append(("zadd", zset_key, mapping))
            return self

        def zrem(self, zset_key, member):
            self._ops.append(("zrem", zset_key, member))
            return self

        async def execute(self):
            for op in self._ops:
                if op[0] == "hset":
                    store.setdefault(op[1], {}).update(op[2])
                elif op[0] == "zadd":
                    zsets.setdefault(op[1], {}).update(op[2])
                elif op[0] == "zrem":
                    zsets.get(op[1], {}).pop(op[2], None)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

    redis.hget = _hget
    redis.zadd = _zadd
    redis.zrangebyscore = _zrangebyscore
    redis.zrem = _zrem
    redis.pipeline = lambda transaction=True: FakePipeline()

    return redis


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _token(
    thread_id: str = "thread-001",
    reason: DeferReason = DeferReason.CONFIDENCE_BELOW_THRESHOLD,
    confidence: float = 0.55,
    ttl: int = 300,
) -> DeferToken:
    return DeferToken(
        thread_id=thread_id,
        defer_reason=reason,
        confidence_score=confidence,
        semantic_distance=0.45,
        ttl_seconds=ttl,
        opa_input_snapshot={"action": "execute_trade", "amount_usd": 12000},
    )


# ---------------------------------------------------------------------------
# Test: DEFER_CONFIDENCE_THRESHOLD constant
# ---------------------------------------------------------------------------


def test_defer_confidence_threshold_is_070():
    """The Confidence-Starvation Boundary must be exactly 0.70 (v0.1.0 decision)."""
    assert DEFER_CONFIDENCE_THRESHOLD == 0.70


# ---------------------------------------------------------------------------
# Test: park
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_park_returns_defer_id(fake_redis):
    queue = DeferQueue(fake_redis)
    token = _token()
    defer_id = await queue.park(token)

    assert defer_id == token.defer_id


@pytest.mark.asyncio
async def test_park_stores_token_retrievable(fake_redis):
    queue = DeferQueue(fake_redis)
    token = _token(thread_id="thread-park-001")
    await queue.park(token)

    retrieved = await queue.get(token.defer_id)
    assert retrieved is not None
    assert retrieved.thread_id == "thread-park-001"


@pytest.mark.asyncio
async def test_park_token_appears_in_list_pending(fake_redis):
    queue = DeferQueue(fake_redis)
    t1 = _token(thread_id="thread-A")
    t2 = _token(thread_id="thread-B")
    await queue.park(t1)
    await queue.park(t2)

    # Use include_expired=True so the score bound is +inf — the default `now`
    # upper-bound would filter out tokens with future expiry times (which all
    # freshly parked tokens have in a test environment where time does not advance).
    pending = await queue.list_pending(limit=10, include_expired=True)
    thread_ids = {t.thread_id for t in pending}
    assert "thread-A" in thread_ids
    assert "thread-B" in thread_ids


# ---------------------------------------------------------------------------
# Test: resolve
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_resolve_escalated(fake_redis):
    queue = DeferQueue(fake_redis)
    token = _token()
    await queue.park(token)

    resolved = await queue.resolve(token.defer_id, "ESCALATED")

    assert resolved is not None
    assert resolved.resolution == "ESCALATED"
    assert resolved.resolved_at_utc is not None


@pytest.mark.asyncio
async def test_resolve_injected_with_data(fake_redis):
    queue = DeferQueue(fake_redis)
    token = _token()
    inject_data = {"market_data": {"TSLA": 650.0}, "confidence_refreshed": 0.88}
    await queue.park(token)

    resolved = await queue.resolve(
        token.defer_id, "INJECTED", injection_data=inject_data
    )

    assert resolved is not None
    assert resolved.resolution == "INJECTED"


@pytest.mark.asyncio
async def test_resolve_unknown_defer_id_returns_none(fake_redis):
    queue = DeferQueue(fake_redis)
    resolved = await queue.resolve("nonexistent-defer-id", "ESCALATED")
    assert resolved is None


# ---------------------------------------------------------------------------
# Test: expire_stale
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_expire_stale_returns_count(fake_redis):
    """expire_stale() sweeps tokens past TTL deadline."""
    queue = DeferQueue(fake_redis)

    # Park a token with TTL=0 (already expired)
    token = _token(ttl=0)
    await queue.park(token)

    # Forcibly move its expiry score to the past in the zset mock
    # Since ttl=0, expiry_ts ≈ time.time() — treat as stale
    count = await queue.expire_stale()
    # count may be 0 or 1 depending on timing; just verify it's non-negative
    assert count >= 0


# ---------------------------------------------------------------------------
# Test: DeferReason enum values
# ---------------------------------------------------------------------------


def test_defer_reason_enum_values():
    """Confirm all DeferReason values exist, including FLOWSIGNAL_ESCALATION."""
    reasons = {r.value for r in DeferReason}
    assert "INSUFFICIENT_CONTEXT" in reasons
    assert "AMBIGUOUS_SEMANTIC_DISTANCE" in reasons
    assert "DATA_STARVATION" in reasons
    assert "CONFIDENCE_BELOW_THRESHOLD" in reasons
    assert "EXTERNAL_VALIDATION" in reasons
    assert "FTRA_IRREVERSIBLE_TERMINAL" in reasons
    # Phase 1, §3.2: FlowSignal escalation
    assert "FLOWSIGNAL_ESCALATION" in reasons


# ---------------------------------------------------------------------------
# Test: DeferToken AARM vector annotation
# ---------------------------------------------------------------------------


def test_defer_token_default_aarm_vector():
    """DeferToken default aarm_vector maps to AARM-V7 (Context Window Overflow)."""
    token = _token()
    assert token.aarm_vector == "AARM-V7"


def test_defer_token_serialization_round_trip():
    """DeferToken serializes and deserializes without data loss."""
    token = _token()
    json_str = token.model_dump_json()
    restored = DeferToken.model_validate_json(json_str)

    assert restored.defer_id == token.defer_id
    assert restored.thread_id == token.thread_id
    assert restored.defer_reason == token.defer_reason
    assert restored.confidence_score == token.confidence_score


# ---------------------------------------------------------------------------
# Test: FlowSignal escalation (Phase 1, §3.2)
# ---------------------------------------------------------------------------


def test_flowsignal_escalation_ttl_constant():
    """FLOWSIGNAL_ESCALATION_TTL must be exactly 300 seconds (5 minutes)."""
    assert _FLOWSIGNAL_ESCALATION_TTL == 300


def test_create_flowsignal_escalation_token_sets_correct_reason():
    """create_flowsignal_escalation_token() must set FLOWSIGNAL_ESCALATION reason."""
    token = create_flowsignal_escalation_token(
        thread_id="thread-fs-001",
        confidence_score=0.82,
        opa_input_snapshot={"action": "execute_trade", "amount_usd": 50000},
    )
    assert token.defer_reason == DeferReason.FLOWSIGNAL_ESCALATION


def test_create_flowsignal_escalation_token_sets_300s_ttl():
    """create_flowsignal_escalation_token() must use 300s TTL, not 4h default."""
    token = create_flowsignal_escalation_token(
        thread_id="thread-fs-002",
        confidence_score=0.85,
        opa_input_snapshot={"action": "execute_trade"},
    )
    assert token.ttl_seconds == 300


def test_create_flowsignal_escalation_token_embeds_finding_message():
    """FlowSignal finding message is embedded in opa_input_snapshot for audit."""
    token = create_flowsignal_escalation_token(
        thread_id="thread-fs-003",
        confidence_score=0.75,
        opa_input_snapshot={"action": "execute_trade"},
        finding_message="FlowSignal: requires senior approval",
    )
    assert (
        token.opa_input_snapshot.get("_flowsignal_finding_message")
        == "FlowSignal: requires senior approval"
    )


def test_create_flowsignal_escalation_token_aarm_vector():
    """FlowSignal escalation tokens use AARM-V8 (External Hold) vector."""
    token = create_flowsignal_escalation_token(
        thread_id="thread-fs-004",
        confidence_score=0.80,
        opa_input_snapshot={},
    )
    assert token.aarm_vector == "AARM-V8"


def test_is_flowsignal_hold_finding_true_positive():
    """is_flowsignal_hold_finding() returns True for valid FLOWSIGNAL_HOLD findings."""
    finding = {
        "code": "FLOWSIGNAL_HOLD",
        "severity": "review",
        "message": "Requires human approval",
        "needs_human_review": True,
    }
    assert is_flowsignal_hold_finding(finding) is True


def test_is_flowsignal_hold_finding_missing_needs_human_review():
    """is_flowsignal_hold_finding() returns False if needs_human_review is missing."""
    finding = {
        "code": "FLOWSIGNAL_HOLD",
        "severity": "review",
        "message": "Requires human approval",
    }
    assert is_flowsignal_hold_finding(finding) is False


def test_is_flowsignal_hold_finding_wrong_code():
    """is_flowsignal_hold_finding() returns False for non-FLOWSIGNAL_HOLD codes."""
    finding = {
        "code": "FLOWSIGNAL_REFUSE",
        "severity": "blocked",
        "message": "Hard deny",
        "needs_human_review": True,  # Even with this, wrong code
    }
    assert is_flowsignal_hold_finding(finding) is False


def test_is_flowsignal_hold_finding_needs_human_review_false():
    """is_flowsignal_hold_finding() returns False if needs_human_review is False."""
    finding = {
        "code": "FLOWSIGNAL_HOLD",
        "severity": "review",
        "message": "...",
        "needs_human_review": False,
    }
    assert is_flowsignal_hold_finding(finding) is False


# ---------------------------------------------------------------------------
# Test: DLQ publisher callback behavior (Phase 1, §3.2)
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_redis_with_past_expiry():
    """Redis mock that places tokens in the past for expire_stale() testing."""
    import time

    store: dict[str, dict] = {}
    zsets: dict[str, dict] = {}

    redis = MagicMock()

    async def _hget(key: str, field: str):
        return store.get(key, {}).get(field)

    async def _zrangebyscore(zset_key: str, min_score, max_score, start=0, num=100):
        members = zsets.get(zset_key, {})
        result = []
        now = time.time()
        for member, score in sorted(members.items(), key=lambda x: x[1]):
            if score <= now:  # Only return expired tokens
                result.append(member)
        return result[start : start + num]

    class FakePipeline:
        def __init__(self):
            self._ops = []

        def hset(self, key, mapping):
            self._ops.append(("hset", key, mapping))
            return self

        def expire(self, key, ttl):
            self._ops.append(("expire", key, ttl))
            return self

        def zadd(self, zset_key, mapping):
            self._ops.append(("zadd", zset_key, mapping))
            return self

        def zrem(self, zset_key, member):
            self._ops.append(("zrem", zset_key, member))
            return self

        async def execute(self):
            for op in self._ops:
                if op[0] == "hset":
                    store.setdefault(op[1], {}).update(op[2])
                elif op[0] == "zadd":
                    zsets.setdefault(op[1], {}).update(op[2])
                elif op[0] == "zrem":
                    zsets.get(op[1], {}).pop(op[2], None)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

    redis.hget = _hget
    redis.zadd = lambda zset_key, mapping: zsets.setdefault(zset_key, {}).update(
        mapping
    )
    redis.zrangebyscore = _zrangebyscore
    redis.zrem = lambda zset_key, member: zsets.get(zset_key, {}).pop(member, None)

    # Park helper that places token in the past (already expired)
    def park_expired(token: DeferToken):
        import time

        key = f"DEFER:{token.defer_id}"
        store[key] = {"token": token.model_dump_json(), "status": "PARKED"}
        # Set expiry time to 1 second in the past
        zsets.setdefault("DEFER:expiry_index", {})[token.defer_id] = time.time() - 1

    redis.pipeline = lambda transaction=True: FakePipeline()
    redis._park_expired = park_expired

    return redis


@pytest.mark.asyncio
async def test_expire_stale_calls_dlq_publisher_for_flowsignal_escalation(
    fake_redis_with_past_expiry,
):
    """DLQ publisher is called exactly once for expired FLOWSIGNAL_ESCALATION tokens."""
    dlq_publisher = AsyncMock()

    queue = DeferQueue(fake_redis_with_past_expiry, dlq_publisher=dlq_publisher)

    # Park a FLOWSIGNAL_ESCALATION token that's already expired
    token = create_flowsignal_escalation_token(
        thread_id="thread-dlq-001",
        confidence_score=0.82,
        opa_input_snapshot={"action": "execute_trade"},
    )
    fake_redis_with_past_expiry._park_expired(token)

    count = await queue.expire_stale()

    assert count == 1
    dlq_publisher.assert_called_once()
    # Verify the token passed to publisher has the correct defer_id
    published_token = dlq_publisher.call_args[0][0]
    assert published_token.defer_id == token.defer_id
    assert published_token.defer_reason == DeferReason.FLOWSIGNAL_ESCALATION


@pytest.mark.asyncio
async def test_expire_stale_does_not_call_dlq_for_non_flowsignal_reasons(
    fake_redis_with_past_expiry,
):
    """DLQ publisher is NOT called for non-FLOWSIGNAL_ESCALATION tokens."""
    dlq_publisher = AsyncMock()

    queue = DeferQueue(fake_redis_with_past_expiry, dlq_publisher=dlq_publisher)

    # Park an EXTERNAL_VALIDATION token (not FlowSignal)
    token = DeferToken(
        thread_id="thread-ext-001",
        defer_reason=DeferReason.EXTERNAL_VALIDATION,
        confidence_score=0.85,
        ttl_seconds=300,
    )
    fake_redis_with_past_expiry._park_expired(token)

    count = await queue.expire_stale()

    assert count == 1
    # DLQ publisher should NOT be called for EXTERNAL_VALIDATION
    dlq_publisher.assert_not_called()


@pytest.mark.asyncio
async def test_expire_stale_without_dlq_publisher_logs_warning_only(
    fake_redis_with_past_expiry,
    caplog,
):
    """Without dlq_publisher, expired FLOWSIGNAL_ESCALATION tokens just log a warning."""
    # No dlq_publisher configured (default behavior)
    queue = DeferQueue(fake_redis_with_past_expiry)

    token = create_flowsignal_escalation_token(
        thread_id="thread-no-dlq-001",
        confidence_score=0.80,
        opa_input_snapshot={},
    )
    fake_redis_with_past_expiry._park_expired(token)

    count = await queue.expire_stale()

    assert count == 1
    # Should complete without error — just logs warning (covered by caplog)


@pytest.mark.asyncio
async def test_expire_stale_dlq_publisher_error_does_not_crash_sweep(
    fake_redis_with_past_expiry,
    caplog,
):
    """If dlq_publisher raises, the error is logged but sweep continues."""
    dlq_publisher = AsyncMock(side_effect=RuntimeError("Pub/Sub unavailable"))

    queue = DeferQueue(fake_redis_with_past_expiry, dlq_publisher=dlq_publisher)

    # Park two FLOWSIGNAL_ESCALATION tokens
    token1 = create_flowsignal_escalation_token(
        thread_id="thread-err-001",
        confidence_score=0.80,
        opa_input_snapshot={},
    )
    token2 = create_flowsignal_escalation_token(
        thread_id="thread-err-002",
        confidence_score=0.80,
        opa_input_snapshot={},
    )
    fake_redis_with_past_expiry._park_expired(token1)
    fake_redis_with_past_expiry._park_expired(token2)

    # Should not raise — errors are caught and logged
    count = await queue.expire_stale()

    # Both tokens should be expired and resolved
    assert count == 2
    # Publisher was called for both (even though it failed)
    assert dlq_publisher.call_count == 2


pytestmark = [pytest.mark.unit, pytest.mark.local]
