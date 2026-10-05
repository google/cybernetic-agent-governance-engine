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

"""A deferral ticket is resolved at most once (POAM-2026-093).

``SingleUseDeferralTicket`` in ``proof/LangGraphHarness.tla``. Before the fix,
``replay_evaluate()`` (and so ``POST /v1/defer/{id}/inject``) re-resolved a
token in any status, and ``expire_stale()`` could overwrite a quorum approval
that ``approve()`` had resolved but not yet removed from the expiry index.
"""

from __future__ import annotations

import time
from unittest.mock import patch

import fakeredis.aioredis
import pytest
from fastapi import HTTPException

from src.gateway.governance.defer_queue import (
    _EXPIRY_ZSET,
    _KEY_PREFIX,
    ApprovalRecord,
    DeferQueue,
    DeferReason,
    DeferToken,
    ReplayResult,
    replay_evaluate,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

HIGH = {"confidence_score": 0.85}


@pytest.fixture
def fake_redis():
    return fakeredis.aioredis.FakeRedis(decode_responses=True)


def _token(reason: DeferReason = DeferReason.CONFIDENCE_BELOW_THRESHOLD) -> DeferToken:
    return DeferToken(
        thread_id="thread-single-use",
        defer_reason=reason,
        confidence_score=0.55,
        ttl_seconds=300,
        opa_input_snapshot={"action": "execute_trade", "params": {"amount": 10.0}},
    )


def _approval(who: str) -> ApprovalRecord:
    return ApprovalRecord(
        approver_urn=f"urn:operator:{who}",
        approved_at_utc="2026-10-03T12:00:00Z",
        auth_method="OIDC",
        auth_principal_hash=f"hash-{who}",
    )


async def _status(redis, defer_id: str) -> tuple[str, str | None]:
    raw, status = await redis.hmget(f"{_KEY_PREFIX}{defer_id}", "token", "status")
    return status, DeferToken.model_validate_json(raw).resolution


async def _approved_hitl_token(queue: DeferQueue) -> str:
    token = _token(DeferReason.HITL_REQUIRED)
    await queue.park(token)
    await queue.approve(token.defer_id, _approval("alice"))
    await queue.approve(token.defer_id, _approval("bob"))
    return token.defer_id


@pytest.mark.asyncio
async def test_reinject_after_injected_is_refused(fake_redis):
    queue = DeferQueue(fake_redis)
    token = _token()
    await queue.park(token)

    assert (
        await replay_evaluate(queue, token.defer_id, dict(HIGH))
        == ReplayResult.ADMITTED
    )
    first = await queue.get(token.defer_id)

    assert (
        await replay_evaluate(queue, token.defer_id, dict(HIGH))
        == ReplayResult.ALREADY_RESOLVED
    )
    again = await queue.get(token.defer_id)
    assert again.resolved_at_utc == first.resolved_at_utc
    assert await _status(fake_redis, token.defer_id) == ("RESOLVED", "INJECTED")


@pytest.mark.asyncio
async def test_inject_after_quorum_approval_is_refused(fake_redis):
    queue = DeferQueue(fake_redis)
    defer_id = await _approved_hitl_token(queue)
    assert await _status(fake_redis, defer_id) == ("RESOLVED", "ESCALATED")

    assert (
        await replay_evaluate(queue, defer_id, dict(HIGH))
        == ReplayResult.ALREADY_RESOLVED
    )
    assert await _status(fake_redis, defer_id) == ("RESOLVED", "ESCALATED")


@pytest.mark.asyncio
async def test_inject_after_consumed_is_refused_and_approval_stays_spent(fake_redis):
    queue = DeferQueue(fake_redis)
    defer_id = await _approved_hitl_token(queue)
    consumed = await queue.consume_approval(
        defer_id, action="execute_trade", covers=lambda _p: True
    )
    assert consumed is not None

    assert (
        await replay_evaluate(queue, defer_id, dict(HIGH))
        == ReplayResult.ALREADY_RESOLVED
    )
    status, _ = await _status(fake_redis, defer_id)
    assert status == "CONSUMED"
    assert (
        await queue.consume_approval(
            defer_id, action="execute_trade", covers=lambda _p: True
        )
        is None
    )


@pytest.mark.asyncio
async def test_inject_with_partial_approval_is_refused(fake_redis):
    queue = DeferQueue(fake_redis)
    token = _token(DeferReason.HITL_REQUIRED)
    await queue.park(token)
    await queue.approve(token.defer_id, _approval("alice"))

    assert (
        await replay_evaluate(queue, token.defer_id, dict(HIGH))
        == ReplayResult.ALREADY_RESOLVED
    )
    status, _ = await _status(fake_redis, token.defer_id)
    assert status == "PARTIALLY_APPROVED"


@pytest.mark.asyncio
async def test_expire_sweep_does_not_overwrite_quorum_approval(fake_redis):
    """The approve() CAS -> zrem window: the sweep must refuse, not re-resolve."""
    queue = DeferQueue(fake_redis)
    defer_id = await _approved_hitl_token(queue)
    # Recreate the race: approve() has resolved the token but its zrem has
    # not landed, and the expiry score is already in the past.
    await fake_redis.zadd(_EXPIRY_ZSET, {defer_id: time.time() - 1})

    assert await queue.expire_stale() == 0
    assert await _status(fake_redis, defer_id) == ("RESOLVED", "ESCALATED")
    assert await fake_redis.zscore(_EXPIRY_ZSET, defer_id) is None
    assert (
        await queue.consume_approval(
            defer_id, action="execute_trade", covers=lambda _p: True
        )
        is not None
    )


@pytest.mark.asyncio
async def test_expire_sweep_still_expires_parked_and_partial(fake_redis):
    queue = DeferQueue(fake_redis)
    parked, partial = _token(), _token(DeferReason.HITL_REQUIRED)
    await queue.park(parked)
    await queue.park(partial)
    await queue.approve(partial.defer_id, _approval("alice"))
    past = time.time() - 1
    await fake_redis.zadd(_EXPIRY_ZSET, {parked.defer_id: past, partial.defer_id: past})

    assert await queue.expire_stale() == 2
    assert await _status(fake_redis, parked.defer_id) == ("RESOLVED", "EXPIRED")
    assert await _status(fake_redis, partial.defer_id) == ("RESOLVED", "EXPIRED")


@pytest.mark.asyncio
async def test_resolve_rejects_unknown_resolution(fake_redis):
    queue = DeferQueue(fake_redis)
    token = _token()
    await queue.park(token)
    with pytest.raises(ValueError, match="unknown DEFER resolution"):
        await queue._resolve(token.defer_id, "APPROVED")


@pytest.mark.asyncio
async def test_inject_endpoint_maps_reinjection_to_409(fake_redis):
    from src.compliance_bridge.main import DeferResolveRequest, defer_inject

    queue = DeferQueue(fake_redis)
    token = _token()
    await queue.park(token)
    assert (
        await replay_evaluate(queue, token.defer_id, dict(HIGH))
        == ReplayResult.ADMITTED
    )

    with patch("redis.asyncio.from_url", return_value=fake_redis):
        with pytest.raises(HTTPException) as exc_info:
            await defer_inject(
                token.defer_id,
                DeferResolveRequest(confidence_score=0.9),
                _token="internal",
            )
    assert exc_info.value.status_code == 409
    assert exc_info.value.detail["error"] == "DEFER_TOKEN_ALREADY_RESOLVED"


@pytest.mark.asyncio
async def test_inject_endpoint_maps_approved_hitl_token_to_409(fake_redis):
    """Quorum reached (2/2) passes the partial-approval gate; the status guard refuses."""
    from src.compliance_bridge.main import DeferResolveRequest, defer_inject

    queue = DeferQueue(fake_redis)
    defer_id = await _approved_hitl_token(queue)

    with patch("redis.asyncio.from_url", return_value=fake_redis):
        with pytest.raises(HTTPException) as exc_info:
            await defer_inject(
                defer_id, DeferResolveRequest(confidence_score=0.9), _token="internal"
            )
    assert exc_info.value.status_code == 409
    assert await _status(fake_redis, defer_id) == ("RESOLVED", "ESCALATED")
