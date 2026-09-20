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
test_defer_queue_concurrency.py — WU-4 concurrent approver interleaving

Covers R-13 (concurrent approval safety) against a live Redis instance.

Why this exists alongside test_defer_queue_quorum.py's
``test_concurrent_approvals_no_lost_update``: that test cannot fail for the
defect it is named after. Its final assertion is
``assert len(final_token.approvals) >= 1``, and a lost update leaves exactly
one approval, so ``1 >= 1`` passes. It also drives both approvals through a
single shared client, whereas two real operators arrive on separate
connections (``compliance_bridge/main.py`` constructs a fresh
``aioredis.from_url(...)`` per request), and it runs on fakeredis, whose
per-connection WATCH semantics differ from real Redis.

This test reproduces the real topology: one client per approver, and an
``asyncio.Barrier`` forcing both to interleave after their read and before
their write. Redis WATCH state is per-connection, so whether the guard holds
depends on WATCH and EXEC riding the same connection.

Marked ``chaos``: skipped by default, runs only under ``--run-chaos``.

``chaos`` rather than ``integration`` is deliberate. The session-scoped
``requires_port_forward`` guard in conftest.py gates every ``integration``
test on the Backend and Langfuse being reachable; this test needs neither —
only a live Redis — so under ``integration`` it would skip for unrelated
reasons and the failure it exists to demonstrate would never be seen. The
guard early-returns unless ``--run-integration`` is passed, so ``chaos``
runs it without requiring port-forwards. The scenario is also chaos-shaped:
a concurrency race surfaced by forced interleaving.

Run with::

    uv run pytest tests/test_defer_queue_concurrency.py --run-chaos
"""

import asyncio
import hashlib
import os
import uuid

import pytest

pytest.importorskip("redis", reason="redis required for concurrency tests")
import redis.asyncio as aioredis

from src.gateway.governance.defer_queue import (
    _EXPIRY_ZSET,
    _KEY_PREFIX,
    ApprovalRecord,
    ApprovalStatus,
    DeferQueue,
    DeferReason,
    DeferToken,
)

pytestmark = [pytest.mark.chaos, pytest.mark.red_team]

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")
#: Isolated from db=1 (production DEFER queue) so a stray run cannot touch it.
TEST_DB = int(os.environ.get("CAGE_TEST_REDIS_DB", "15"))


def create_approval_record(operator_urn: str) -> ApprovalRecord:
    """Create a test approval record."""
    session_id = str(uuid.uuid4())
    return ApprovalRecord(
        approver_urn=operator_urn,
        approved_at_utc="2026-09-20T12:00:00Z",
        auth_method="OIDC",
        auth_principal_hash=hashlib.sha256(session_id.encode()).hexdigest(),
    )


class _InterleavingClient:
    """Delegating Redis client that pauses once, between read and write.

    ``approve()`` reads the token with ``hget`` and writes it back later in the
    same call. Under real concurrency the damaging interleaving is: both
    operators complete their read before either performs its write. Scheduling
    alone does not reliably produce that window in a test, so this wrapper
    makes it deterministic — it blocks on a barrier immediately after the
    token read, releasing both approvers only once both hold stale state.

    Every other attribute delegates to the real client, so ``approve()`` runs
    entirely unmodified against live Redis.
    """

    def __init__(self, client: aioredis.Redis, barrier: asyncio.Barrier):
        self._client = client
        self._barrier = barrier
        self._paused = False

    async def hget(self, key: str, field: str):
        value = await self._client.hget(key, field)
        if field == "token" and not self._paused:
            self._paused = True
            await self._barrier.wait()
        return value

    def __getattr__(self, name):
        return getattr(self._client, name)


async def _approve_interleaved(
    client: aioredis.Redis,
    defer_id: str,
    operator_urn: str,
    barrier: asyncio.Barrier,
):
    """Approve via a dedicated client whose read/write window is interleaved."""
    queue = DeferQueue(_InterleavingClient(client, barrier))
    try:
        return await queue.approve(defer_id, create_approval_record(operator_urn))
    except Exception as exc:  # noqa: BLE001 — the abort type is what we assert on
        return exc


@pytest.fixture
async def redis_clients():
    """Two independent clients, mirroring two operators on separate requests."""
    clients = [
        aioredis.from_url(REDIS_URL, db=TEST_DB, decode_responses=True)
        for _ in range(2)
    ]
    try:
        await clients[0].ping()
    except Exception as exc:  # noqa: BLE001
        for c in clients:
            await c.aclose()
        pytest.skip(f"live Redis unavailable at {REDIS_URL}: {exc}")
    yield clients
    for c in clients:
        await c.aclose()


@pytest.mark.asyncio
async def test_concurrent_approvals_do_not_lose_an_approval(redis_clients):
    """Two operators approving at once must not silently discard an approval.

    R-13. Either both approvals are recorded (quorum reached), or one is
    rejected with a detectable abort so the caller can retry. What must not
    happen is both callers being told they succeeded while only one approval
    is persisted — that under-represents who authorised the escalation in the
    audit record, which is the property dual control exists to guarantee.
    """
    client_a, client_b = redis_clients

    token = DeferToken(
        thread_id=f"wu4-concurrency-{uuid.uuid4().hex[:8]}",
        defer_reason=DeferReason.CONFIDENCE_BELOW_THRESHOLD,
        required_quorum=2,
    )
    defer_id = await DeferQueue(client_a).park(token)

    try:
        barrier = asyncio.Barrier(2)
        result_a, result_b = await asyncio.gather(
            _approve_interleaved(client_a, defer_id, "urn:cage:operator:alice", barrier),
            _approve_interleaved(client_b, defer_id, "urn:cage:operator:bob", barrier),
        )

        final_token = await DeferQueue(client_a).get(defer_id)
        assert final_token is not None
        stored_urns = {a.approver_urn for a in final_token.approvals}

        committed = [
            r
            for r in (result_a, result_b)
            if not isinstance(r, Exception)
            and r[0] in (ApprovalStatus.PARTIAL_QUORUM, ApprovalStatus.QUORUM_REACHED)
        ]

        # The invariant: every approval reported as committed must be durable.
        # Asserting on the committed count (rather than ">= 1") is what makes
        # this test capable of failing when an update is lost.
        assert len(stored_urns) == len(committed), (
            f"lost update: {len(committed)} approval(s) reported success but "
            f"{len(stored_urns)} persisted (stored={sorted(stored_urns)}, "
            f"results={result_a!r}, {result_b!r})"
        )

        # And no approval may vanish: if both committed, quorum must be reached.
        if len(committed) == 2:
            assert stored_urns == {
                "urn:cage:operator:alice",
                "urn:cage:operator:bob",
            }
            assert len(final_token.approvals) == 2
    finally:
        # Import the real constants rather than hardcoding the prefix, so this
        # cleanup cannot drift from the implementation.
        await client_a.delete(f"{_KEY_PREFIX}{defer_id}")
        await client_a.zrem(_EXPIRY_ZSET, defer_id)
