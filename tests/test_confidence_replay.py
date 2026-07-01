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
Confidence Score Replay Test Suite
===================================
Canonical proof fixture for the July 2026 proof surface review (v0.1.0-rc.2).

Demonstrates the three-phase changed-condition replay flow:
  Phase 1 — PARK:     Token with confidence < 0.70 is parked in Redis db=1
  Phase 2 — HYDRATE:  Out-of-band context enrichment raises effective confidence
  Phase 3 — REPLAY:   Token is re-evaluated; admitted if confidence >= 0.70

Run with: pytest -k confidence_replay -v
"""

from __future__ import annotations

from typing import Any, Callable
from unittest.mock import MagicMock

import pytest

from src.gateway.governance.defer_queue import (
    DEFER_CONFIDENCE_THRESHOLD,
    DeferQueue,
    DeferReason,
    DeferToken,
    ReplayResult,
    replay_evaluate,
)

# ---------------------------------------------------------------------------
# In-memory fake Redis — mirrors the pattern from test_defer_queue.py
# ---------------------------------------------------------------------------

def _make_fake_redis() -> MagicMock:
    """Build a minimal async Redis mock backed by in-memory dicts.

    Replicates the FakePipeline pattern established in test_defer_queue.py so
    that DeferQueue.park(), DeferQueue.get(), DeferQueue.resolve(), and
    replay_evaluate() all operate against a hermetic in-memory store with no
    live Redis dependency.
    """
    store: dict[str, dict] = {}
    zsets: dict[str, dict] = {}

    redis = MagicMock()

    async def _hset(key: str, mapping: dict) -> None:
        store.setdefault(key, {}).update(mapping)

    async def _hget(key: str, field: str) -> str | None:
        return store.get(key, {}).get(field)

    async def _hdel(key: str, *fields: str) -> None:
        for f in fields:
            store.get(key, {}).pop(f, None)

    async def _delete(key: str) -> None:
        store.pop(key, None)

    async def _exists(key: str) -> int:
        return 1 if key in store else 0

    async def _expire(key: str, ttl: int) -> None:
        pass  # TTL not enforced in unit tests

    async def _zadd(zset_key: str, mapping: dict) -> None:
        zsets.setdefault(zset_key, {}).update(mapping)

    async def _zrangebyscore(
        zset_key: str, min_score: Any, max_score: Any, start: int = 0, num: int = 100
    ) -> list[str]:
        members = zsets.get(zset_key, {})
        max_f = float("inf") if max_score == "+inf" else float(max_score)
        result = [
            member
            for member, score in sorted(members.items(), key=lambda x: x[1])
            if score <= max_f
        ]
        return result[start : start + num]

    async def _zrem(zset_key: str, member: str) -> None:
        zsets.get(zset_key, {}).pop(member, None)

    class FakePipeline:
        """Async pipeline that buffers operations and executes them atomically."""

        def __init__(self) -> None:
            self._ops: list[tuple] = []

        def hset(self, key: str, mapping: dict) -> "FakePipeline":
            self._ops.append(("hset", key, mapping))
            return self

        def expire(self, key: str, ttl: int) -> "FakePipeline":
            self._ops.append(("expire", key, ttl))
            return self

        def zadd(self, zset_key: str, mapping: dict) -> "FakePipeline":
            self._ops.append(("zadd", zset_key, mapping))
            return self

        def zrem(self, zset_key: str, member: str) -> "FakePipeline":
            self._ops.append(("zrem", zset_key, member))
            return self

        async def execute(self) -> list:
            results = []
            for op in self._ops:
                if op[0] == "hset":
                    store.setdefault(op[1], {}).update(op[2])
                    results.append(True)
                elif op[0] == "expire":
                    results.append(True)
                elif op[0] == "zadd":
                    zsets.setdefault(op[1], {}).update(op[2])
                    results.append(1)
                elif op[0] == "zrem":
                    zsets.get(op[1], {}).pop(op[2], None)
                    results.append(1)
            return results

        async def __aenter__(self) -> "FakePipeline":
            return self

        async def __aexit__(self, *args: Any) -> None:
            pass

    redis.hset = _hset
    redis.hget = _hget
    redis.hdel = _hdel
    redis.delete = _delete
    redis.exists = _exists
    redis.zadd = _zadd
    redis.zrangebyscore = _zrangebyscore
    redis.zrem = _zrem
    redis.pipeline = lambda transaction=True: FakePipeline()

    # Expose the raw store dict so tests can inspect Redis state directly.
    redis._store = store
    redis._zsets = zsets

    return redis


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def redis_db1_client() -> MagicMock:
    """Return a fake Redis client simulating db=1 (the DEFER queue database).

    Uses the same in-memory mock pattern as test_defer_queue.py — no live
    Redis instance is required.  The client is scoped to the test function
    and discarded after each test, preventing cross-test state leakage.

    Yields:
        A MagicMock that behaves like an async Redis client connected to db=1.
    """
    client = _make_fake_redis()
    yield client
    # Cleanup: clear the in-memory store after the test.
    client._store.clear()
    client._zsets.clear()


@pytest.fixture
async def deferred_token_below_threshold(redis_db1_client: MagicMock) -> dict:
    """Park a DeferToken with confidence_score=0.65 (below the 0.70 threshold).

    Phase 1 of the three-phase confidence-score replay flow.

    Creates a DeferToken with:
      - confidence_score = 0.65  (below DEFER_CONFIDENCE_THRESHOLD = 0.70)
      - defer_reason = DeferReason.CONFIDENCE_BELOW_THRESHOLD
      - thread_id = "replay-proof-thread-001"

    Parks the token in the fake Redis db=1 store via DeferQueue.park() and
    yields a dict containing the defer_id and the DeferQueue instance so that
    downstream fixtures and tests can interact with the same queue state.

    Yields:
        dict with keys:
          "defer_id" (str)  — the UUID assigned by DeferQueue.park()
          "queue"    (DeferQueue) — the queue instance backed by redis_db1_client
          "token"    (DeferToken) — the original DeferToken that was parked

    Cleanup:
        Removes the DEFER:{defer_id} hash key from the fake Redis store after
        the test completes, leaving the store in a clean state.
    """
    queue = DeferQueue(redis_db1_client)
    token = DeferToken(
        thread_id="replay-proof-thread-001",
        defer_reason=DeferReason.CONFIDENCE_BELOW_THRESHOLD,
        confidence_score=0.65,
        semantic_distance=0.48,
        ttl_seconds=3600,
        opa_input_snapshot={
            "action": "execute_trade",
            "amount_usd": 25000,
            "symbol": "NVDA",
            "trader_role": "senior",
        },
    )

    defer_id = await queue.park(token)

    yield {
        "defer_id": defer_id,
        "queue": queue,
        "token": token,
    }

    # Teardown: remove the key from the fake store.
    key = f"DEFER:{defer_id}"
    redis_db1_client._store.pop(key, None)
    redis_db1_client._zsets.get("DEFER:expiry_index", {}).pop(defer_id, None)


@pytest.fixture
def mock_context_hydrator() -> Callable[[str], dict]:
    """Return a callable that simulates out-of-band context enrichment.

    Phase 2 of the three-phase confidence-score replay flow.

    The hydrator is a pure mock — no external calls are made.  It accepts a
    defer_id string and returns an enriched context dict whose
    ``confidence_score`` is 0.85, which is above the 0.70 threshold and
    therefore sufficient to admit the token in Phase 3.

    Returns:
        A callable ``(defer_id: str) -> dict`` that returns an enriched
        context dict with the following fields:
          - confidence_score (float): 0.85 — above DEFER_CONFIDENCE_THRESHOLD
          - enrichment_source (str):  "mock_market_data_hydrator_v1"
          - market_data (dict):       synthetic market snapshot
          - hydration_timestamp (str): ISO-8601 UTC timestamp placeholder
    """
    def _hydrate(defer_id: str) -> dict:
        return {
            "confidence_score": 0.85,
            "enrichment_source": "mock_market_data_hydrator_v1",
            "market_data": {
                "NVDA": {"price": 875.42, "volume_24h": 42_000_000, "volatility": 0.18},
                "SPY":  {"price": 512.10, "volume_24h": 95_000_000, "volatility": 0.12},
            },
            "hydration_timestamp": "2026-07-01T00:00:00+00:00",
            "defer_id_hydrated": defer_id,
        }

    return _hydrate


# ---------------------------------------------------------------------------
# Test 1 — Phase 1: low-confidence token is parked in Redis db=1
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_low_confidence_token_is_parked(
    deferred_token_below_threshold: dict,
    redis_db1_client: MagicMock,
) -> None:
    """Verify that a token with confidence=0.65 is written to Redis db=1 and NOT admitted.

    Asserts:
      - The DEFER:{defer_id} hash key exists in the fake Redis store.
      - The stored status field is "PARKED" (not "RESOLVED" or "ADMITTED").
      - The token's confidence_score is below DEFER_CONFIDENCE_THRESHOLD (0.70).
      - The token is retrievable via DeferQueue.get() and has the expected fields.
    """
    defer_id = deferred_token_below_threshold["defer_id"]
    queue    = deferred_token_below_threshold["queue"]

    # Assert: key exists in Redis db=1 store.
    key = f"DEFER:{defer_id}"
    assert key in redis_db1_client._store, (
        f"Expected DEFER hash key '{key}' to exist in Redis db=1 after park()."
    )

    # Assert: status is PARKED (not admitted).
    status = redis_db1_client._store[key].get("status")
    assert status == "PARKED", (
        f"Expected status='PARKED', got status='{status}'."
    )

    # Assert: token is retrievable and has correct confidence.
    retrieved = await queue.get(defer_id)
    assert retrieved is not None, "DeferQueue.get() returned None for a parked token."
    assert retrieved.confidence_score == 0.65
    assert retrieved.confidence_score < DEFER_CONFIDENCE_THRESHOLD, (
        f"confidence_score={retrieved.confidence_score} must be below "
        f"DEFER_CONFIDENCE_THRESHOLD={DEFER_CONFIDENCE_THRESHOLD}."
    )
    assert retrieved.defer_reason == DeferReason.CONFIDENCE_BELOW_THRESHOLD
    assert retrieved.resolution is None, (
        "A freshly parked token must not have a resolution set."
    )


# ---------------------------------------------------------------------------
# Test 2 — Phase 2: hydration raises effective confidence above threshold
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_hydration_raises_confidence_above_threshold(
    deferred_token_below_threshold: dict,
    mock_context_hydrator: Callable[[str], dict],
) -> None:
    """Verify that after hydration the effective confidence is above 0.70.

    Asserts:
      - mock_context_hydrator(defer_id)["confidence_score"] >= 0.70
      - The hydrated context contains the expected enrichment fields:
          enrichment_source, market_data, hydration_timestamp, defer_id_hydrated
      - The hydrated confidence is strictly above the original 0.65.
    """
    defer_id       = deferred_token_below_threshold["defer_id"]
    original_token = deferred_token_below_threshold["token"]

    enriched = mock_context_hydrator(defer_id)

    # Assert: effective confidence is above the threshold.
    assert enriched["confidence_score"] >= DEFER_CONFIDENCE_THRESHOLD, (
        f"Hydrated confidence_score={enriched['confidence_score']} must be >= "
        f"DEFER_CONFIDENCE_THRESHOLD={DEFER_CONFIDENCE_THRESHOLD}."
    )

    # Assert: hydrated confidence is strictly above the original parked value.
    assert enriched["confidence_score"] > original_token.confidence_score, (
        "Hydrated confidence must exceed the original parked confidence."
    )

    # Assert: enrichment fields are present.
    assert "enrichment_source" in enriched, "Missing 'enrichment_source' in hydrated context."
    assert "market_data" in enriched, "Missing 'market_data' in hydrated context."
    assert "hydration_timestamp" in enriched, "Missing 'hydration_timestamp' in hydrated context."
    assert enriched.get("defer_id_hydrated") == defer_id, (
        "Hydrated context must echo back the defer_id it was called with."
    )


# ---------------------------------------------------------------------------
# Test 3 — Full end-to-end replay flow (canonical proof artifact)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_confidence_replay_full_flow(
    deferred_token_below_threshold: dict,
    mock_context_hydrator: Callable[[str], dict],
    redis_db1_client: MagicMock,
) -> None:
    """Canonical end-to-end proof fixture for the July 2026 proof surface review.

    Demonstrates the complete three-phase confidence-score replay flow:

      Phase 1 — PARK:    deferred_token_below_threshold fixture parks a token
                         with confidence=0.65 in Redis db=1.
      Phase 2 — HYDRATE: mock_context_hydrator raises effective confidence to 0.85.
      Phase 3 — REPLAY:  replay_evaluate() re-evaluates the token; since 0.85 >= 0.70
                         the token is admitted and removed from the DEFER queue.

    Asserts:
      - replay_evaluate() returns ReplayResult.ADMITTED.
      - The token's Redis hash status field is updated to "RESOLVED".
      - The token is no longer in the DEFER:expiry_index sorted set.
      - DeferQueue.get() still returns the token (hash preserved for audit trail)
        with resolution="INJECTED".

    Run with: pytest -k confidence_replay -v
    """
    defer_id = deferred_token_below_threshold["defer_id"]
    queue    = deferred_token_below_threshold["queue"]

    # Phase 2 — HYDRATE: obtain enriched context from the mock hydrator.
    enriched_context = mock_context_hydrator(defer_id)
    assert enriched_context["confidence_score"] >= DEFER_CONFIDENCE_THRESHOLD

    # Phase 3 — REPLAY: call the real replay_evaluate() from defer_queue.py.
    result = await replay_evaluate(queue, defer_id, enriched_context)

    # Assert: token is admitted.
    assert result == ReplayResult.ADMITTED, (
        f"Expected ReplayResult.ADMITTED, got {result!r}. "
        f"Effective confidence={enriched_context['confidence_score']:.2f} "
        f"should be >= threshold={DEFER_CONFIDENCE_THRESHOLD}."
    )

    # Assert: Redis hash status is now "RESOLVED".
    key = f"DEFER:{defer_id}"
    status = redis_db1_client._store.get(key, {}).get("status")
    assert status == "RESOLVED", (
        f"Expected Redis status='RESOLVED' after admission, got '{status}'."
    )

    # Assert: token is removed from the expiry sorted set (no longer pending).
    expiry_members = redis_db1_client._zsets.get("DEFER:expiry_index", {})
    assert defer_id not in expiry_members, (
        f"defer_id={defer_id} must be removed from DEFER:expiry_index after admission."
    )

    # Assert: resolved token has resolution="INJECTED" (audit trail preserved).
    resolved_token = await queue.get(defer_id)
    assert resolved_token is not None, (
        "Resolved token hash must remain in Redis for audit trail purposes."
    )
    assert resolved_token.resolution == "INJECTED", (
        f"Expected resolution='INJECTED', got '{resolved_token.resolution}'."
    )
    assert resolved_token.resolved_at_utc is not None, (
        "resolved_at_utc must be set after admission."
    )


# ---------------------------------------------------------------------------
# Test 4 — Token remains parked when hydration is insufficient
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_token_remains_parked_if_hydration_insufficient(
    deferred_token_below_threshold: dict,
    redis_db1_client: MagicMock,
) -> None:
    """Verify that a token stays parked when hydration only raises confidence to 0.68.

    If the enriched context's confidence_score is still below
    DEFER_CONFIDENCE_THRESHOLD (0.70), replay_evaluate() must return
    ReplayResult.PARKED and leave the token in Redis db=1 unchanged.

    Asserts:
      - replay_evaluate() returns ReplayResult.PARKED.
      - The DEFER:{defer_id} hash key still exists in Redis db=1.
      - The token status remains "PARKED" (not "RESOLVED").
      - The token is still present in the DEFER:expiry_index sorted set.
      - DeferQueue.get() still returns the token with resolution=None.
    """
    defer_id = deferred_token_below_threshold["defer_id"]
    queue    = deferred_token_below_threshold["queue"]

    # Insufficient hydration: confidence raised to 0.68, still below 0.70.
    insufficient_context = {
        "confidence_score": 0.68,
        "enrichment_source": "partial_market_data_hydrator_v1",
        "market_data": {
            "NVDA": {"price": 870.00, "volume_24h": 10_000_000, "volatility": 0.22},
        },
        "hydration_timestamp": "2026-07-01T00:00:00+00:00",
        "note": "Partial enrichment — confidence still below threshold.",
    }

    assert insufficient_context["confidence_score"] < DEFER_CONFIDENCE_THRESHOLD, (
        "Test pre-condition: insufficient_context confidence must be below threshold."
    )

    # Phase 3 — REPLAY with insufficient context.
    result = await replay_evaluate(queue, defer_id, insufficient_context)

    # Assert: token remains parked.
    assert result == ReplayResult.PARKED, (
        f"Expected ReplayResult.PARKED when confidence={insufficient_context['confidence_score']:.2f} "
        f"< threshold={DEFER_CONFIDENCE_THRESHOLD}, got {result!r}."
    )

    # Assert: Redis hash key still exists.
    key = f"DEFER:{defer_id}"
    assert key in redis_db1_client._store, (
        f"DEFER hash key '{key}' must still exist in Redis db=1 after a PARKED result."
    )

    # Assert: status is still "PARKED" (not "RESOLVED").
    status = redis_db1_client._store[key].get("status")
    assert status == "PARKED", (
        f"Expected status='PARKED' after insufficient hydration, got '{status}'."
    )

    # Assert: token is still in the expiry sorted set.
    expiry_members = redis_db1_client._zsets.get("DEFER:expiry_index", {})
    assert defer_id in expiry_members, (
        f"defer_id={defer_id} must remain in DEFER:expiry_index when token stays PARKED."
    )

    # Assert: token is retrievable and still has no resolution.
    still_parked = await queue.get(defer_id)
    assert still_parked is not None, "DeferQueue.get() must return the token (still parked)."
    assert still_parked.resolution is None, (
        "resolution must remain None when the token is not admitted."
    )
    assert still_parked.confidence_score == 0.65, (
        "Original confidence_score on the stored token must be unchanged."
    )
