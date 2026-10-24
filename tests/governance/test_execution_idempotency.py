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

"""ExecutionLedger: one claim per idempotency key, fail closed without Redis (#514)."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import fakeredis.aioredis
import pytest

from src.gateway.governance.execution_idempotency import (
    SHARED_CALLER,
    Claim,
    Duplicate,
    ExecutionLedger,
    ExecutionLedgerUnavailable,
    ExecutionStatus,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

_ACTION = "do_thing"
_KEY = "5f0c6f7e-9d43-4b8e-a1e2-3c4d5e6f7a8b"


@pytest.fixture
def redis() -> fakeredis.aioredis.FakeRedis:
    return fakeredis.aioredis.FakeRedis()


@pytest.fixture
def enforcing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CAGE_ENV", "production")


@pytest.fixture
def permissive(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CAGE_ENV", "test")


class _ReplyLost:
    """Redis whose first ``command`` lands but loses its reply, as a reset would."""

    def __init__(
        self, inner: fakeredis.aioredis.FakeRedis, command: str = "set"
    ) -> None:
        self._inner = inner
        self._command = command
        self.calls = 0

    def __getattr__(self, name: str) -> Any:
        attr = getattr(self._inner, name)
        if name != self._command:
            return attr

        async def lossy(*args: Any, **kwargs: Any) -> Any:
            self.calls += 1
            result = await attr(*args, **kwargs)
            if self.calls == 1:
                raise ConnectionError(f"connection reset after {name.upper()}")
            return result

        return lossy


class _Down:
    """A configured Redis that cannot be reached."""

    async def set(self, *args: Any, **kwargs: Any) -> Any:
        raise ConnectionError("redis unreachable")

    async def get(self, *args: Any, **kwargs: Any) -> Any:
        raise ConnectionError("redis unreachable")

    async def eval(self, *args: Any, **kwargs: Any) -> Any:
        raise ConnectionError("redis unreachable")


class _SharedWrapper:
    """Mimics the gateway's shared client: the raw client sits behind it."""

    def __init__(self, raw: fakeredis.aioredis.FakeRedis) -> None:
        self._raw = raw

    async def get_raw_client(self) -> fakeredis.aioredis.FakeRedis:
        return self._raw


@pytest.mark.asyncio
async def test_second_claim_is_a_duplicate_until_the_outcome_is_recorded(
    redis: fakeredis.aioredis.FakeRedis,
) -> None:
    ledger = ExecutionLedger(redis)

    first = await ledger.claim(_ACTION, SHARED_CALLER, _KEY)
    in_flight = await ledger.claim(_ACTION, SHARED_CALLER, _KEY)

    assert isinstance(first, Claim)
    assert first.key == f"cage:exec:{_ACTION}:{SHARED_CALLER}:{_KEY}"
    assert in_flight == Duplicate(first.key, ExecutionStatus.IN_FLIGHT, None)
    assert 0 < await redis.ttl(first.key) <= ledger._ttl_seconds

    assert await ledger.record_outcome(first, ExecutionStatus.EXECUTED, "EXECUTED: ok")
    replay = await ledger.claim(_ACTION, SHARED_CALLER, _KEY)
    assert replay == Duplicate(first.key, ExecutionStatus.EXECUTED, "EXECUTED: ok")
    assert await redis.ttl(first.key) > 0  # recording keeps the expiry


@pytest.mark.asyncio
async def test_keys_are_namespaced_by_action_and_caller(
    redis: fakeredis.aioredis.FakeRedis,
) -> None:
    ledger = ExecutionLedger(redis)

    claims = [
        await ledger.claim(_ACTION, SHARED_CALLER, _KEY),
        await ledger.claim("other_action", SHARED_CALLER, _KEY),
        await ledger.claim(
            _ACTION,
            "advisor.governance-stack.serviceaccount.identity.linkerd.local",
            _KEY,
        ),
    ]

    assert all(isinstance(c, Claim) for c in claims)


@pytest.mark.asyncio
async def test_concurrent_claims_produce_exactly_one_owner(
    redis: fakeredis.aioredis.FakeRedis,
) -> None:
    ledger = ExecutionLedger(redis)

    results = await asyncio.gather(
        *(ledger.claim(_ACTION, SHARED_CALLER, _KEY) for _ in range(20))
    )

    assert sum(isinstance(r, Claim) for r in results) == 1
    assert all(
        r.status is ExecutionStatus.IN_FLIGHT
        for r in results
        if isinstance(r, Duplicate)
    )


@pytest.mark.asyncio
async def test_unknown_outcome_keeps_the_claim(
    redis: fakeredis.aioredis.FakeRedis,
) -> None:
    ledger = ExecutionLedger(redis)
    claim = await ledger.claim(_ACTION, SHARED_CALLER, _KEY)
    assert isinstance(claim, Claim)

    await ledger.record_outcome(claim, ExecutionStatus.UNKNOWN, "UNKNOWN: timed out")

    again = await ledger.claim(_ACTION, SHARED_CALLER, _KEY)
    assert again == Duplicate(claim.key, ExecutionStatus.UNKNOWN, "UNKNOWN: timed out")


@pytest.mark.asyncio
async def test_lost_set_reply_is_recognised_as_this_attempts_claim(
    redis: fakeredis.aioredis.FakeRedis,
) -> None:
    flaky = _ReplyLost(redis)
    ledger = ExecutionLedger(flaky)

    claim = await ledger.claim(_ACTION, SHARED_CALLER, _KEY)

    assert isinstance(claim, Claim)
    assert flaky.calls == 2
    stored = json.loads(await redis.get(claim.key))
    assert stored["token"] == claim.token


async def _first_attempt(ledger: ExecutionLedger, status: ExecutionStatus) -> Claim:
    """Claim the key; record ``status`` unless the attempt is still in flight."""
    claim = await ledger.claim(_ACTION, SHARED_CALLER, _KEY)
    assert isinstance(claim, Claim)
    if status is not ExecutionStatus.IN_FLIGHT:
        assert await ledger.record_outcome(claim, status, f"{status.value}: first")
    return claim


@pytest.mark.asyncio
@pytest.mark.parametrize("backend", ["redis", "local"])
async def test_reclaim_blocked_takes_over_a_blocked_key_exactly_once(
    backend: str, redis: fakeredis.aioredis.FakeRedis, permissive: None
) -> None:
    ledger = ExecutionLedger(redis if backend == "redis" else None)
    first = await _first_attempt(ledger, ExecutionStatus.BLOCKED)

    plain = await ledger.claim(_ACTION, SHARED_CALLER, _KEY)
    assert plain == Duplicate(first.key, ExecutionStatus.BLOCKED, "BLOCKED: first")

    results = await asyncio.gather(
        *(
            ledger.claim(_ACTION, SHARED_CALLER, _KEY, reclaim_blocked=True)
            for _ in range(10)
        )
    )
    (owner,) = [r for r in results if isinstance(r, Claim)]
    assert owner.token != first.token
    assert all(
        r.status is ExecutionStatus.IN_FLIGHT
        for r in results
        if isinstance(r, Duplicate)
    )
    # The superseded attempt can no longer record; the new owner can.
    assert not await ledger.record_outcome(first, ExecutionStatus.EXECUTED, "stale")
    assert await ledger.record_outcome(owner, ExecutionStatus.EXECUTED, "EXECUTED: ok")


@pytest.mark.asyncio
@pytest.mark.parametrize("backend", ["redis", "local"])
@pytest.mark.parametrize(
    "status",
    [ExecutionStatus.IN_FLIGHT, ExecutionStatus.EXECUTED, ExecutionStatus.UNKNOWN],
)
async def test_reclaim_blocked_never_takes_over_a_key_that_may_have_run(
    backend: str,
    status: ExecutionStatus,
    redis: fakeredis.aioredis.FakeRedis,
    permissive: None,
) -> None:
    ledger = ExecutionLedger(redis if backend == "redis" else None)
    await _first_attempt(ledger, status)

    again = await ledger.claim(_ACTION, SHARED_CALLER, _KEY, reclaim_blocked=True)

    assert isinstance(again, Duplicate)
    assert again.status is status


@pytest.mark.asyncio
async def test_lost_reclaim_reply_is_recognised_as_this_attempts_claim(
    redis: fakeredis.aioredis.FakeRedis,
) -> None:
    await _first_attempt(ExecutionLedger(redis), ExecutionStatus.BLOCKED)
    flaky = _ReplyLost(redis, command="eval")

    claim = await ExecutionLedger(flaky).claim(
        _ACTION, SHARED_CALLER, _KEY, reclaim_blocked=True
    )

    assert isinstance(claim, Claim)
    assert flaky.calls == 1  # the second pass reads its own token back
    stored = json.loads(await redis.get(claim.key))
    assert stored == {"token": claim.token, "status": "IN_FLIGHT", "outcome": None}


@pytest.mark.asyncio
async def test_only_the_claim_holder_records_the_outcome(
    redis: fakeredis.aioredis.FakeRedis,
) -> None:
    ledger = ExecutionLedger(redis)
    claim = await ledger.claim(_ACTION, SHARED_CALLER, _KEY)
    assert isinstance(claim, Claim)
    impostor = Claim(claim.key, "not-the-token")

    assert not await ledger.record_outcome(impostor, ExecutionStatus.BLOCKED, "x")
    assert await ledger.claim(_ACTION, SHARED_CALLER, _KEY) == Duplicate(
        claim.key, ExecutionStatus.IN_FLIGHT, None
    )

    await redis.delete(claim.key)  # expired
    assert not await ledger.record_outcome(claim, ExecutionStatus.EXECUTED, "x")


@pytest.mark.asyncio
async def test_unreadable_record_reads_as_unknown(
    redis: fakeredis.aioredis.FakeRedis,
) -> None:
    ledger = ExecutionLedger(redis)
    await redis.set(ExecutionLedger.key_for(_ACTION, SHARED_CALLER, _KEY), "garbage")

    result = await ledger.claim(_ACTION, SHARED_CALLER, _KEY)

    assert isinstance(result, Duplicate)
    assert result.status is ExecutionStatus.UNKNOWN


@pytest.mark.asyncio
async def test_shared_wrapper_resolves_its_raw_client(
    redis: fakeredis.aioredis.FakeRedis,
) -> None:
    ledger = ExecutionLedger(_SharedWrapper(redis))

    claim = await ledger.claim(_ACTION, SHARED_CALLER, _KEY)

    assert isinstance(claim, Claim)
    assert await redis.exists(claim.key) == 1


@pytest.mark.asyncio
async def test_enforcing_posture_without_redis_refuses(enforcing: None) -> None:
    ledger = ExecutionLedger(None)

    with pytest.raises(ExecutionLedgerUnavailable):
        await ledger.claim(_ACTION, SHARED_CALLER, _KEY)


@pytest.mark.asyncio
@pytest.mark.parametrize("posture", ["enforcing", "permissive"])
async def test_unreachable_redis_refuses_in_every_posture(
    posture: str, request: pytest.FixtureRequest
) -> None:
    request.getfixturevalue(posture)
    ledger = ExecutionLedger(_Down())

    with pytest.raises(ExecutionLedgerUnavailable):
        await ledger.claim(_ACTION, SHARED_CALLER, _KEY)


@pytest.mark.asyncio
async def test_permissive_posture_without_redis_uses_a_local_registry(
    permissive: None,
) -> None:
    ledger = ExecutionLedger(None)

    claim = await ledger.claim(_ACTION, SHARED_CALLER, _KEY)
    assert isinstance(claim, Claim)
    assert isinstance(await ledger.claim(_ACTION, SHARED_CALLER, _KEY), Duplicate)

    assert await ledger.record_outcome(claim, ExecutionStatus.BLOCKED, "BLOCKED: no")
    assert await ledger.claim(_ACTION, SHARED_CALLER, _KEY) == Duplicate(
        claim.key, ExecutionStatus.BLOCKED, "BLOCKED: no"
    )
    assert not await ledger.record_outcome(
        Claim(claim.key, "not-the-token"), ExecutionStatus.EXECUTED, "x"
    )


@pytest.mark.asyncio
async def test_unrecordable_outcome_is_logged_not_raised(
    caplog: pytest.LogCaptureFixture,
) -> None:
    ledger = ExecutionLedger(_Down())

    recorded = await ledger.record_outcome(
        Claim("cage:exec:a:b:c", "t"), ExecutionStatus.EXECUTED, "EXECUTED: ok"
    )

    assert recorded is False
    assert "not recorded" in caplog.text


@pytest.mark.parametrize(
    ("action", "caller", "key"),
    [
        ("do:thing", SHARED_CALLER, _KEY),
        (_ACTION, "a b", _KEY),
        (_ACTION, SHARED_CALLER, "k*"),
        (_ACTION, SHARED_CALLER, ""),
        (_ACTION, SHARED_CALLER, f"{_KEY}\n"),
    ],
)
def test_key_parts_cannot_escape_their_segment(
    action: str, caller: str, key: str
) -> None:
    with pytest.raises(ValueError):
        ExecutionLedger.key_for(action, caller, key)


@pytest.mark.asyncio
async def test_record_outcome_requires_a_final_status(
    redis: fakeredis.aioredis.FakeRedis,
) -> None:
    ledger = ExecutionLedger(redis)
    claim = await ledger.claim(_ACTION, SHARED_CALLER, _KEY)
    assert isinstance(claim, Claim)

    with pytest.raises(ValueError):
        await ledger.record_outcome(claim, ExecutionStatus.IN_FLIGHT, "x")
