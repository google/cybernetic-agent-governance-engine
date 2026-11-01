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

"""Single use at the consequence boundary survives a failover (POAM-2026-156 item 1).

A consumption marker counts only once a replica has acknowledged it: the store
sends ``WAIT`` on the socket that wrote the marker, and under strict
replication refuses (``CONSUMPTION_NOT_REPLICATED``) when the acknowledgement
falls short or fails, leaving the marker in place.

The tests drive the store through the real redis-py client
(``build_async_redis()``, with its pool and retry policy) against
:class:`~tests.fixtures.replicated_valkey.ReplicatedValkey`, an in-process
primary with an asynchronous replica. Replication runs only on ``WAIT``, so a
failover can land inside the replication window whenever a test needs it to.
"""

from __future__ import annotations

import hashlib
from collections.abc import AsyncIterator
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import fakeredis.aioredis
import pytest
from prometheus_client import REGISTRY

import src.gateway.governance.consequence_authority_store as store_module
from src.gateway.governance.consequence_authority_store import (
    ConsequenceAuthorityStore,
    ConsumptionNotReplicatedError,
)
from src.gateway.governance.consequence_gateway import (
    ConsequenceDecision,
    ConsequenceGateway,
)
from src.gateway.governance.consequence_magnitude import ConsequenceMagnitudes
from src.gateway.governance.consequence_token import ConsequenceToken
from src.gateway.governance.contracts import ConsequenceMagnitude, MagnitudePath
from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
from src.gateway.governance.kms_signer import (
    KMSGovernanceSigner,
    SoftwareEd25519Provider,
)
from src.gateway.infrastructure.redis_replication import (
    ReplicaAckError,
    ReplicationPolicy,
    acknowledged_replicas,
    pinned_connection,
    write_socket,
)
from tests.fixtures.replicated_valkey import ReplicatedValkey, build_client

pytestmark = [pytest.mark.unit, pytest.mark.local]

STRICT = ReplicationPolicy(replicas=1, timeout_ms=100, strict=True)
LENIENT = ReplicationPolicy(replicas=1, timeout_ms=100, strict=False)
BINDING = ConsequenceAuthorityStore.binding_hash("thread-1", "agent-a", "digest", "v1")
PAYLOAD = {"action": "payment.release", "params": {"amount": 250000.0}}
MAGNITUDES = ConsequenceMagnitudes(
    (ConsequenceMagnitude("payment.release", (MagnitudePath(("amount",), 2),)),)
)


def _key(rec: str) -> str:
    return f"flowsignal:token:{rec}"


@pytest.fixture
async def valkey(monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[ReplicatedValkey]:
    for name in ("REDIS_PASSWORD", "REDIS_TLS", "REDIS_AUTH_MODE", "REDIS_IAM_AUTH"):
        monkeypatch.delenv(name, raising=False)
    server = await ReplicatedValkey(replicas=1).start()
    yield server
    await server.stop()


@pytest.fixture
async def client(valkey: ReplicatedValkey) -> AsyncIterator[Any]:
    redis = build_client(valkey)
    yield redis
    await redis.aclose()


@pytest.fixture
def signer() -> KMSGovernanceSigner:
    return KMSGovernanceSigner(provider=SoftwareEd25519Provider(key_id="c3-durability"))


@pytest.fixture
def evidence(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Events the gateway emits to the evidence stream."""
    events: list[dict[str, Any]] = []

    async def ingest(event: dict[str, Any]) -> str:
        events.append(event)
        return f"ev-{len(events)}"

    sink = MagicMock()
    sink.ingest = AsyncMock(side_effect=ingest)
    monkeypatch.setattr(
        "src.gateway.governance.evidence.stream.get_evidence_sink", lambda: sink
    )
    return events


async def _token(signer: KMSGovernanceSigner, rec: str) -> str:
    return await ConsequenceToken.mint(
        sub="agent-a",
        tid="thread-1",
        rec=rec,
        act=hashlib.sha256(jcs_canonicalize_plan(PAYLOAD)).hexdigest(),
        ver="v1",
        ttl_seconds=60,
        signer=signer,
    )


def _count(outcome: str) -> float:
    value = REGISTRY.get_sample_value(
        "cage_consequence_consumption_unacknowledged_total", {"outcome": outcome}
    )
    return value or 0.0


# ---------------------------------------------------------------------------
# Store: replica acknowledgement on the writing socket
# ---------------------------------------------------------------------------


async def test_acknowledged_marker_is_consumed(valkey, client) -> None:
    store = ConsequenceAuthorityStore(client, replication=STRICT)
    assert await store.consume_once("rcpt-1", BINDING) is True
    assert valkey.replica_value(_key("rcpt-1")) == valkey.value(_key("rcpt-1"))


async def test_short_ack_under_strict_refuses_and_keeps_the_marker(
    valkey, client
) -> None:
    valkey.replication_paused = True
    store = ConsequenceAuthorityStore(client, replication=STRICT)
    with pytest.raises(ConsumptionNotReplicatedError, match="0 of 1 replicas"):
        await store.consume_once("rcpt-2", BINDING)
    # The record stays consumed: the marker is never deleted to allow a retry.
    assert await store.get_binding("rcpt-2") == BINDING
    assert await store.consume_once("rcpt-2", BINDING) is False


async def test_wait_error_under_strict_refuses_and_keeps_the_marker(
    valkey, client
) -> None:
    valkey.fail_next("WAIT", "ERR WAIT cannot be used here")
    store = ConsequenceAuthorityStore(client, replication=STRICT)
    with pytest.raises(ConsumptionNotReplicatedError, match="WAIT failed"):
        await store.consume_once("rcpt-3", BINDING)
    assert await store.get_binding("rcpt-3") == BINDING


async def test_wait_runs_on_the_connection_that_wrote_the_marker(
    valkey, client
) -> None:
    store = ConsequenceAuthorityStore(client, replication=STRICT)
    assert await store.consume_once("rcpt-4", BINDING) is True
    assert valkey.connections_running("WAIT") == valkey.connections_running("SET")
    assert len(valkey.connections_running("WAIT")) == 1


async def test_lenient_shortfall_proceeds_and_is_counted(valkey, client) -> None:
    valkey.replication_paused = True
    before = _count("proceeded")
    store = ConsequenceAuthorityStore(client, replication=LENIENT)
    assert await store.consume_once("rcpt-5", BINDING) is True
    assert _count("proceeded") == before + 1


async def test_strict_refusal_is_counted(valkey, client) -> None:
    valkey.replication_paused = True
    before = _count("refused")
    store = ConsequenceAuthorityStore(client, replication=STRICT)
    with pytest.raises(ConsumptionNotReplicatedError):
        await store.consume_once("rcpt-6", BINDING)
    assert _count("refused") == before + 1


async def test_no_wait_without_replicas_to_acknowledge(valkey, client) -> None:
    store = ConsequenceAuthorityStore(
        client, replication=ReplicationPolicy(replicas=0, timeout_ms=100, strict=True)
    )
    assert await store.consume_once("rcpt-7", BINDING) is True
    assert valkey.connections_running("WAIT") == []


async def test_a_waiting_policy_needs_a_positive_timeout(client) -> None:
    with pytest.raises(ValueError, match="WAIT timeout must be positive"):
        ConsequenceAuthorityStore(
            client, replication=ReplicationPolicy(replicas=1, timeout_ms=0, strict=True)
        )


async def test_unpinnable_client_refuses_under_strict() -> None:
    """A client the store cannot pin can't prove the WAIT counted the marker."""
    store = ConsequenceAuthorityStore(
        fakeredis.aioredis.FakeRedis(decode_responses=True), replication=STRICT
    )
    with pytest.raises(ConsumptionNotReplicatedError, match="socket"):
        await store.consume_once("rcpt-8", BINDING)


# ---------------------------------------------------------------------------
# Store: the WAIT is never vacuous
# ---------------------------------------------------------------------------


async def test_lost_reply_marker_is_reasserted_before_wait(valkey, client) -> None:
    """A SET re-sent after a lost reply recovers the marker on a new socket.

    The marker was written on the old socket, so a WAIT on the new one would
    count nothing; the compare-and-set re-write gives it something to count.
    """
    valkey.lose_next_reply("SET")
    valkey.replication_paused = True
    store = ConsequenceAuthorityStore(client, replication=STRICT)
    with pytest.raises(ConsumptionNotReplicatedError, match="0 of 1 replicas"):
        await store.consume_once("rcpt-9", BINDING)
    first_set, resent_set = valkey.connections_running("SET")
    assert first_set != resent_set
    assert valkey.connections_running("EVAL") == [resent_set]
    assert valkey.connections_running("WAIT") == [resent_set]


async def test_lost_reply_marker_is_consumed_once_acknowledged(valkey, client) -> None:
    valkey.lose_next_reply("SET")
    store = ConsequenceAuthorityStore(client, replication=STRICT)
    assert await store.consume_once("rcpt-10", BINDING) is True
    assert await store.get_binding("rcpt-10") == BINDING
    assert valkey.replica_value(_key("rcpt-10")) == valkey.value(_key("rcpt-10"))


async def test_wait_is_not_resent_after_a_connection_error(valkey, client) -> None:
    """The socket drops after the write; redis-py must not re-send WAIT elsewhere."""
    valkey.close_after_next("SET")
    store = ConsequenceAuthorityStore(client, replication=STRICT)
    with pytest.raises(ConsumptionNotReplicatedError, match="WAIT failed"):
        await store.consume_once("rcpt-11", BINDING)
    assert valkey.connections_running("WAIT") == []


async def test_reconnect_between_write_and_wait_refuses(
    valkey, client, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A WAIT after a reconnect would count a socket that wrote nothing."""
    real_acknowledged_replicas = store_module.acknowledged_replicas

    async def disconnect_then_acknowledge(
        pinned: Any, socket: object | None, replicas: int, timeout_ms: int
    ) -> int:
        await pinned.connection.disconnect()  # the write's socket is gone
        return await real_acknowledged_replicas(pinned, socket, replicas, timeout_ms)

    monkeypatch.setattr(
        store_module, "acknowledged_replicas", disconnect_then_acknowledge
    )
    store = ConsequenceAuthorityStore(client, replication=STRICT)
    with pytest.raises(ConsumptionNotReplicatedError, match="socket"):
        await store.consume_once("rcpt-12", BINDING)
    assert valkey.connections_running("WAIT") == []


async def test_acknowledged_replicas_refuses_a_replaced_socket(valkey, client) -> None:
    pinned, _ = await pinned_connection(client)
    try:
        assert await pinned.set("k", "v", nx=True, ex=90)
        socket = write_socket(pinned)
        await pinned.connection.disconnect()
        with pytest.raises(ReplicaAckError, match="socket"):
            await acknowledged_replicas(pinned, socket, 1, 100)
        assert valkey.connections_running("WAIT") == []
    finally:
        await pinned.aclose()


async def test_reassert_never_overwrites_another_consumers_marker(
    valkey, client
) -> None:
    store = ConsequenceAuthorityStore(client, replication=STRICT)
    await client.set(_key("rcpt-13"), "theirs:op", ex=90)
    pinned, _ = await pinned_connection(client)
    try:
        assert await store._reassert(pinned, _key("rcpt-13"), "ours:op") is False
    finally:
        await pinned.aclose()
    assert valkey.value(_key("rcpt-13")) == "theirs:op"


def test_write_socket_reads_redis_py_connection_internals() -> None:
    """Pin the redis-py internals the single-shot WAIT relies on."""
    from redis.asyncio import Redis
    from redis.asyncio.connection import Connection

    connection = Connection(host="127.0.0.1", port=6379)
    assert connection.is_connected is False
    assert connection._writer is None
    assert callable(connection.send_command)
    assert callable(connection.read_response)
    pinned = Redis(host="127.0.0.1", port=6379).client()
    assert pinned.single_connection_client is True
    assert pinned.connection is None


# ---------------------------------------------------------------------------
# Failover
# ---------------------------------------------------------------------------


async def test_replay_refused_after_failover_when_marker_was_acknowledged(
    valkey, client, signer
) -> None:
    gateway = ConsequenceGateway(
        store=ConsequenceAuthorityStore(client, replication=STRICT),
        signer=signer,
        magnitudes=MAGNITUDES,
    )
    token = await _token(signer, "rcpt-failover")
    first = await gateway.evaluate(token, PAYLOAD)
    assert first.decision == ConsequenceDecision.EXECUTE

    await valkey.fail_over()

    replay = await gateway.evaluate(token, PAYLOAD)
    assert replay.decision == ConsequenceDecision.BLOCK
    assert replay.reason_code == "ALREADY_CONSUMED"


async def test_without_wait_a_failover_inside_the_replication_window_replays(
    valkey, client, signer
) -> None:
    """Control: with no WAIT the marker can die with the primary.

    This is the gap the replica acknowledgement closes: the first consumption
    executes before any replica holds its marker, and after the failover the
    same token executes again.
    """
    gateway = ConsequenceGateway(
        store=ConsequenceAuthorityStore(
            client, replication=ReplicationPolicy.standalone()
        ),
        signer=signer,
        magnitudes=MAGNITUDES,
    )
    token = await _token(signer, "rcpt-no-wait")
    assert (await gateway.evaluate(token, PAYLOAD)).decision == (
        ConsequenceDecision.EXECUTE
    )

    await valkey.fail_over()

    assert (await gateway.evaluate(token, PAYLOAD)).decision == (
        ConsequenceDecision.EXECUTE
    )


# ---------------------------------------------------------------------------
# Gateway
# ---------------------------------------------------------------------------


async def test_gateway_executes_an_acknowledged_consumption(
    client, signer, evidence
) -> None:
    gateway = ConsequenceGateway(
        store=ConsequenceAuthorityStore(client, replication=STRICT),
        signer=signer,
        magnitudes=MAGNITUDES,
    )
    result = await gateway.evaluate(await _token(signer, "rcpt-g1"), PAYLOAD)
    assert result.decision == ConsequenceDecision.EXECUTE
    assert [e["reason_code"] for e in evidence] == ["OK"]


async def test_gateway_blocks_an_unreplicated_consumption_and_records_it(
    valkey, client, signer, evidence
) -> None:
    valkey.replication_paused = True
    gateway = ConsequenceGateway(
        store=ConsequenceAuthorityStore(client, replication=STRICT),
        signer=signer,
        magnitudes=MAGNITUDES,
    )
    token = await _token(signer, "rcpt-g2")

    result = await gateway.evaluate(token, PAYLOAD)
    assert result.decision == ConsequenceDecision.BLOCK
    assert result.reason_code == "CONSUMPTION_NOT_REPLICATED"
    (refusal,) = evidence
    assert refusal["type"] == "CONSEQUENCE_GATEWAY_REFUSAL"
    assert refusal["reason_code"] == "CONSUMPTION_NOT_REPLICATED"
    assert refusal["rec"] == "rcpt-g2"

    # The marker stayed, so the record stays consumed: no retry can execute it.
    retry = await gateway.evaluate(token, PAYLOAD)
    assert retry.decision == ConsequenceDecision.BLOCK
    assert retry.reason_code == "ALREADY_CONSUMED"


async def test_gateway_blocks_when_wait_fails(valkey, client, signer) -> None:
    valkey.fail_next("WAIT", "ERR simulated WAIT failure")
    gateway = ConsequenceGateway(
        store=ConsequenceAuthorityStore(client, replication=STRICT),
        signer=signer,
        magnitudes=MAGNITUDES,
    )
    result = await gateway.evaluate(await _token(signer, "rcpt-g3"), PAYLOAD)
    assert result.decision == ConsequenceDecision.BLOCK
    assert result.reason_code == "CONSUMPTION_NOT_REPLICATED"


# ---------------------------------------------------------------------------
# Policy (shared with the CBF engine)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("env", "strict"),
    [
        ({}, True),
        ({"CAGE_ENV": "production"}, True),
        ({"CAGE_ENV": "staging"}, True),
        ({"CAGE_ENV": "testing"}, True),
        ({"CAGE_ENV": "test"}, False),
        ({"CAGE_ENV": "dev"}, False),
        ({"ENVIRONMENT": "development"}, False),
        ({"CAGE_ENV": "ci"}, False),
        ({"CAGE_ENV": "test", "CAGE_STRICT_REPLICATION": "yes"}, True),
        ({"CAGE_ENV": "production", "CAGE_STRICT_REPLICATION": "false"}, False),
    ],
)
def test_policy_defaults_match_the_cbf_engine(
    monkeypatch: pytest.MonkeyPatch, env: dict[str, str], strict: bool
) -> None:
    for name in (
        "CAGE_ENV",
        "ENVIRONMENT",
        "CAGE_STRICT_REPLICATION",
        "CAGE_REDIS_WAIT_REPLICAS",
        "CAGE_REDIS_WAIT_TIMEOUT_MS",
    ):
        monkeypatch.delenv(name, raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    assert ReplicationPolicy.from_env() == ReplicationPolicy(
        replicas=1, timeout_ms=1000, strict=strict
    )


def test_policy_reads_replicas_and_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CAGE_REDIS_WAIT_REPLICAS", "2")
    monkeypatch.setenv("CAGE_REDIS_WAIT_TIMEOUT_MS", "250")
    policy = ReplicationPolicy.from_env()
    assert (policy.replicas, policy.timeout_ms, policy.waits) == (2, 250, True)
    assert ReplicationPolicy.standalone().waits is False


# ---------------------------------------------------------------------------
# CBF engine: rollback_state pins one connection; commit WAIT never reconnects
# ---------------------------------------------------------------------------


async def test_cbf_rollback_state_runs_lua_and_wait_on_one_pinned_connection(
    valkey, client, monkeypatch: pytest.MonkeyPatch
) -> None:
    """rollback_state must pin a single-connection client around [LUA_ROLLBACK_CBF, WAIT]."""
    import src.gateway.governance.safety.cbf_engine as cbf_module
    from src.cage_finance.invariants import CashBarrier, finance_cost_resolver
    from src.gateway.governance.safety.cbf_engine import (
        _REDIS_KEY_FENCE_EPOCH,
        ControlBarrierFunction,
    )

    cbf = ControlBarrierFunction(
        invariant=CashBarrier(gamma=0.5),
        cost_resolver=finance_cost_resolver,
        skip_epoch_seed=True,
    )
    cbf.tracer = None
    await client.set(cbf.redis_key, "99000.0")
    await client.set(_REDIS_KEY_FENCE_EPOCH, "2")

    monkeypatch.setattr(cbf_module, "_WAIT_REPLICAS", 1)
    monkeypatch.setattr(cbf_module, "_WAIT_TIMEOUT_MS", 100)

    await cbf.rollback_state(1000.0, debit_id="d-rb", client=client)

    assert valkey.connections_running("WAIT") == valkey.connections_running("EVAL")
    assert len(valkey.connections_running("WAIT")) == 1
    assert float(valkey.replica_value(cbf.redis_key)) == pytest.approx(100000.0)


async def test_cbf_commit_does_not_resend_wait_after_connection_drop(
    valkey, client, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When the write socket drops after EVALSHA, _sync_to_replicas must fail closed
    instead of letting redis-py Retry reconnect and issue a vacuous WAIT on a fresh socket.
    """
    import src.gateway.governance.safety.cbf_engine as cbf_module
    from src.cage_finance.invariants import CashBarrier, finance_cost_resolver
    from src.gateway.governance.safety.cbf_engine import (
        _REDIS_KEY_FENCE_EPOCH,
        _REDIS_KEY_FENCE_EPOCH_HWM,
        ControlBarrierFunction,
    )

    cbf = ControlBarrierFunction(
        invariant=CashBarrier(gamma=0.5),
        cost_resolver=finance_cost_resolver,
        skip_epoch_seed=True,
    )
    cbf.tracer = None
    await client.set(cbf.redis_key, "100000.0")
    await client.set(_REDIS_KEY_FENCE_EPOCH, "1")
    await client.set(_REDIS_KEY_FENCE_EPOCH_HWM, "1")

    monkeypatch.setattr(cbf_module, "redis_client", client)
    monkeypatch.setattr(cbf_module, "_get_raw_redis", AsyncMock(return_value=client))
    monkeypatch.setattr(cbf_module, "_WAIT_REPLICAS", 1)
    monkeypatch.setattr(cbf_module, "_WAIT_TIMEOUT_MS", 100)
    monkeypatch.setattr(cbf_module, "_STRICT_REPLICATION", True)
    monkeypatch.setattr(cbf_module, "_FENCE_EPOCH_ENABLED", True)
    monkeypatch.setattr(
        cbf,
        "_resolve_ground_truth_balance",
        AsyncMock(
            return_value=(
                100000.0,
                {"source": "self_reported", "mode": "self_reported", "fence_epoch": 1},
            )
        ),
    )

    valkey.close_after_next("EVALSHA")
    committed, reason, cost = await cbf.atomic_verify_and_commit(
        "execute_trade",
        {"symbol": "AAPL", "shares": 10, "price": 100.0, "amount": 1000.0},
        debit_id="d-drop",
    )

    assert committed is False
    assert "REPLICATION_UNCONFIRMED" in reason
    assert cost == 0.0
    # The commit's WAIT never reached valkey on a reconnected socket; only the
    # strict-mode rollback's [EVAL, WAIT] ran on its own pinned connection.
    assert valkey.connections_running("WAIT") == valkey.connections_running("EVAL")
