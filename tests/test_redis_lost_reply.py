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

"""Single-use Redis operations survive a redis-py re-send after a lost reply.

Pooled async clients retry ``ConnectionError`` and ``TimeoutError``
(``build_async_redis()``). If the server executed a command but the reply was
lost, the client sends the identical command again. :class:`LostReply` models
that: the first call of each named method runs twice and the caller sees the
second reply. For every single-use operation:

* the re-send must not turn the first success into a refusal;
* a genuine second consumer (another attempt) must still be refused;
* a Redis error on the new read-back path must still fail closed.

The GCRA rate limiter is deliberately not idempotent (a re-send charges the
request twice, which only throttles more); the last test pins that.
"""

from __future__ import annotations

import base64
import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import AsyncMock

import fakeredis.aioredis as fakeredis
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

import src.gateway.governance.routing_seal as rs
from src.gateway.governance.consequence_authority_store import (
    ConsequenceAuthorityStore,
)
from src.gateway.governance.defer_queue import (
    _PARK_LUA,
    ApprovalRecord,
    ApprovalStatus,
    DeferQueue,
    DeferReason,
    DeferToken,
)
from src.gateway.infrastructure.redis_single_use import new_op_id, set_nx_retry_safe
from src.gateway.server.dpop_validator import DPoPValidator, TokenBindingError
from src.gateway.server.rate_limit import LUA_GCRA_DUAL_BUCKET, SharedRateLimiter

pytestmark = [pytest.mark.unit, pytest.mark.local]

ACTION = "execute_trade"
PARAMS = {"symbol": "AAPL", "amount": 100.0}
RH = "c" * 64
DPOP_URI = "https://api.example.com/resource"


class LostReply:
    """Client wrapper: the first call of each named method executes twice.

    The first execution reaches the server and its reply is lost; the second
    is redis-py's re-send of the identical command, whose reply the caller
    sees.
    """

    def __init__(self, inner: Any, *methods: str) -> None:
        self._inner = inner
        self._pending = set(methods)

    def __getattr__(self, name: str) -> Any:
        attr = getattr(self._inner, name)
        if name not in self._pending:
            return attr

        async def send_twice(*args: Any, **kwargs: Any) -> Any:
            self._pending.discard(name)
            await attr(*args, **kwargs)
            return await attr(*args, **kwargs)

        return send_twice


class ConflictReadFails:
    """Client whose ``SET NX`` always loses and whose read-back raises."""

    async def exists(self, key: str) -> int:
        return 0

    async def set(self, *args: Any, **kwargs: Any) -> None:
        return None

    async def get(self, key: str) -> Any:
        raise ConnectionError("redis down during read-back")


# ---------------------------------------------------------------------------
# set_nx_retry_safe
# ---------------------------------------------------------------------------


class TestSetNxRetrySafe:
    async def test_recognises_its_own_write(self):
        redis = fakeredis.FakeRedis()  # bytes replies
        value = f"claim:{new_op_id()}"
        assert await set_nx_retry_safe(LostReply(redis, "set"), "k", value, ex=60)
        assert await redis.get("k") == value.encode()

    async def test_another_writer_is_a_conflict(self):
        redis = fakeredis.FakeRedis()
        await redis.set("k", f"claim:{new_op_id()}")
        assert not await set_nx_retry_safe(redis, "k", f"claim:{new_op_id()}", ex=60)

    async def test_read_back_error_propagates(self):
        with pytest.raises(ConnectionError):
            await set_nx_retry_safe(ConflictReadFails(), "k", "v", ex=60)


# ---------------------------------------------------------------------------
# Routing seal: nonce consume and revocation
# ---------------------------------------------------------------------------


@pytest.fixture
def hmac_seal_posture(monkeypatch):
    """HMAC seals in a non-production posture, evidence binding on."""
    monkeypatch.setenv("CAGE_SEAL_STRICT_MODE", "false")
    monkeypatch.setenv("CAGE_ENV", "test")
    monkeypatch.delenv("ENVIRONMENT", raising=False)
    monkeypatch.delenv("CAGE_REQUIRE_EVIDENCE_BINDING", raising=False)
    monkeypatch.setattr(rs, "_ATOMIC_BURN_NONCE_SHA", None)


async def _indexed_seal(redis: Any) -> str:
    seal = await rs.generate_seal(ACTION, PARAMS, record_hash=RH)
    await redis.set(f"cage:seal:evidence:{rs.seal_nonce(seal)}", RH)
    return seal


@pytest.mark.usefixtures("hmac_seal_posture")
class TestRoutingSeal:
    async def test_consume_survives_lost_reply(self):
        redis = fakeredis.FakeRedis()
        seal = await _indexed_seal(redis)
        lossy = LostReply(redis, "eval", "evalsha")
        assert await rs.verify_and_consume_seal(
            seal, ACTION, PARAMS, redis_client=lossy
        )
        assert await rs.seal_state(seal, redis_client=redis) is rs.SealState.CONSUMED

    async def test_second_consumer_still_refused(self):
        redis = fakeredis.FakeRedis()
        seal = await _indexed_seal(redis)
        lossy = LostReply(redis, "eval", "evalsha")
        assert await rs.verify_and_consume_seal(
            seal, ACTION, PARAMS, redis_client=lossy
        )
        with pytest.raises(rs.SymbolicGovernorViolation, match="replay attack"):
            await rs.verify_and_consume_seal(seal, ACTION, PARAMS, redis_client=redis)

    async def test_revoke_survives_lost_reply(self):
        redis = fakeredis.FakeRedis()
        seal = await _indexed_seal(redis)
        lossy = LostReply(redis, "set")
        assert await rs.revoke_seal(seal, "operator kill", redis_client=lossy) is True
        assert await rs.revoke_seal(seal, "second", redis_client=redis) is False
        with pytest.raises(rs.SymbolicGovernorViolation, match="seal revoked"):
            await rs.verify_and_consume_seal(seal, ACTION, PARAMS, redis_client=redis)

    async def test_revoke_fails_closed_when_read_back_fails(self):
        seal = await rs.generate_seal(ACTION, PARAMS, record_hash=RH)
        with pytest.raises(rs.SymbolicGovernorViolation, match="revocation failed"):
            await rs.revoke_seal(seal, "x", redis_client=ConflictReadFails())


# ---------------------------------------------------------------------------
# DeferQueue: park, revision CAS, status CAS
# ---------------------------------------------------------------------------


def _approval(urn: str) -> ApprovalRecord:
    return ApprovalRecord(
        approver_urn=urn,
        approved_at_utc="2026-01-01T00:00:00Z",
        auth_method="MTLS",
        auth_principal_hash="h",
    )


def _hitl_token() -> DeferToken:
    return DeferToken(
        thread_id="t-lost-reply",
        defer_reason=DeferReason.HITL_REQUIRED,
        opa_input_snapshot={"action": ACTION, "params": PARAMS},
    )


def _covers(params: dict[str, Any]) -> bool:
    return params == PARAMS


async def _approved(redis: Any) -> DeferToken:
    """A parked HITL token approved to quorum (2 approvers)."""
    token = _hitl_token()
    queue = DeferQueue(redis)
    await queue.park(token)
    for urn in ("urn:op:alice", "urn:op:bob"):
        await queue.approve(token.defer_id, _approval(urn))
    return token


class TestDeferQueue:
    async def test_park_survives_lost_reply(self):
        redis = fakeredis.FakeRedis(decode_responses=True)
        token = _hitl_token()
        await DeferQueue(LostReply(redis, "eval")).park(token)
        key = f"DEFER:{token.defer_id}"
        assert await redis.hmget(key, "status", "rev") == ["PARKED", "0"]
        assert await redis.ttl(key) > 0
        assert await redis.zscore("DEFER:expiry_index", token.defer_id) is not None
        status, _ = await DeferQueue(redis).approve(
            token.defer_id, _approval("urn:op:alice")
        )
        assert status is ApprovalStatus.PARTIAL_QUORUM

    async def test_park_script_refuses_another_attempt(self):
        redis = fakeredis.FakeRedis(decode_responses=True)
        token_json = _hitl_token().model_dump_json()
        op_id = new_op_id()
        assert await redis.eval(_PARK_LUA, 1, "DEFER:x", token_json, 60, op_id) == 1
        assert await redis.eval(_PARK_LUA, 1, "DEFER:x", token_json, 60, op_id) == 1
        assert (
            await redis.eval(_PARK_LUA, 1, "DEFER:x", token_json, 60, new_op_id()) == 0
        )

    async def test_park_fails_closed_on_redis_error(self):
        redis = AsyncMock()
        redis.eval.side_effect = ConnectionError("redis down")
        with pytest.raises(ConnectionError):
            await DeferQueue(redis).park(_hitl_token())
        redis.zadd.assert_not_awaited()

    async def test_quorum_approval_survives_lost_reply(self):
        redis = fakeredis.FakeRedis(decode_responses=True)
        token = _hitl_token()
        await DeferQueue(redis).park(token)
        await DeferQueue(redis).approve(token.defer_id, _approval("urn:op:alice"))
        status, approved = await DeferQueue(LostReply(redis, "evalsha")).approve(
            token.defer_id, _approval("urn:op:bob")
        )
        assert status is ApprovalStatus.QUORUM_REACHED
        assert approved is not None
        assert approved.resolution == "ESCALATED"

    async def test_cas_from_another_attempt_still_conflicts(self):
        redis = fakeredis.FakeRedis(decode_responses=True)
        token = _hitl_token()
        queue = DeferQueue(redis)
        await queue.park(token)
        await queue.approve(token.defer_id, _approval("urn:op:alice"))  # rev 0 -> 1
        assert await queue._cas_update(token.defer_id, 0, token, "RESOLVED") == (
            False,
            1,
        )

    async def test_resolve_survives_lost_reply_and_keeps_injection_data(self):
        redis = fakeredis.FakeRedis(decode_responses=True)
        token = DeferToken(
            thread_id="t-inject", defer_reason=DeferReason.DATA_STARVATION
        )
        await DeferQueue(redis).park(token)
        resolved = await DeferQueue(LostReply(redis, "evalsha"))._resolve(
            token.defer_id, "INJECTED", injection_data={"k": "v"}
        )
        assert resolved is not None
        assert await redis.hmget(
            f"DEFER:{token.defer_id}", "status", "injection_data"
        ) == ["RESOLVED", '{"k": "v"}']
        # A replayed inject is still refused: a ticket resolves at most once.
        assert await DeferQueue(redis)._resolve(token.defer_id, "INJECTED") is None

    async def test_consume_approval_survives_lost_reply(self):
        redis = fakeredis.FakeRedis(decode_responses=True)
        token = await _approved(redis)
        consumed = await DeferQueue(LostReply(redis, "eval")).consume_approval(
            token.defer_id, action=ACTION, covers=_covers
        )
        assert consumed is not None
        assert await redis.hget(f"DEFER:{token.defer_id}", "status") == "CONSUMED"

    async def test_second_spend_still_refused(self):
        redis = fakeredis.FakeRedis(decode_responses=True)
        token = await _approved(redis)
        queue = DeferQueue(redis)
        lossy = DeferQueue(LostReply(redis, "eval"))
        assert await lossy.consume_approval(
            token.defer_id, action=ACTION, covers=_covers
        )
        assert not await queue.atomic_resolve(
            token.defer_id, expected_status="RESOLVED", new_status="CONSUMED"
        )
        assert (
            await queue.consume_approval(token.defer_id, action=ACTION, covers=_covers)
            is None
        )

    async def test_status_cas_fails_closed_on_redis_error(self):
        redis = AsyncMock()
        redis.eval.side_effect = ConnectionError("redis down")
        assert not await DeferQueue(redis).atomic_resolve(
            "t", expected_status="RESOLVED", new_status="CONSUMED"
        )


# ---------------------------------------------------------------------------
# Consequence authority store
# ---------------------------------------------------------------------------

BINDING = ConsequenceAuthorityStore.binding_hash("thread-1", "agent-a", "digest", "v1")


class TestConsequenceAuthorityStore:
    async def test_consume_survives_lost_reply(self):
        redis = fakeredis.FakeRedis(decode_responses=True)
        store = ConsequenceAuthorityStore(LostReply(redis, "set"))
        assert await store.consume_once("rec-1", BINDING) is True
        assert await store.get_binding("rec-1") == BINDING

    async def test_replay_and_substitution_still_refused(self):
        redis = fakeredis.FakeRedis(decode_responses=True)
        lossy = ConsequenceAuthorityStore(LostReply(redis, "set"))
        assert await lossy.consume_once("rec-2", BINDING) is True
        store = ConsequenceAuthorityStore(redis)
        assert await store.consume_once("rec-2", BINDING) is False
        other = ConsequenceAuthorityStore.binding_hash(
            "thread-1", "agent-b", "digest", "v1"
        )
        assert await store.consume_once("rec-2", other) is False
        assert await store.get_binding("rec-2") == BINDING

    async def test_read_back_failure_fails_closed(self):
        store = ConsequenceAuthorityStore(ConflictReadFails())
        with pytest.raises(ConnectionError):
            await store.consume_once("rec-3", BINDING)


# ---------------------------------------------------------------------------
# DPoP jti replay store
# ---------------------------------------------------------------------------


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


@pytest.fixture(scope="module")
def dpop_client() -> tuple[rsa.RSAPrivateKey, str]:
    """An RSA key and a self-signed client certificate for it."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "client.example.com")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return key, cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _proof(key: rsa.RSAPrivateKey, jti: str) -> str:
    numbers = key.public_key().public_numbers()
    jwk = {
        "kty": "RSA",
        "n": _b64url(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
        "e": _b64url(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
    }
    header = {"typ": "dpop+jwt", "alg": "RS256", "jwk": jwk}
    claims = {"htm": "POST", "htu": DPOP_URI, "iat": int(time.time()), "jti": jti}
    signing_input = (
        f"{_b64url(json.dumps(header).encode())}.{_b64url(json.dumps(claims).encode())}"
    )
    signature = key.sign(signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{signing_input}.{_b64url(signature)}"


async def _validate(validator: DPoPValidator, cert_pem: str, proof: str) -> bool:
    return await validator.validate_token_binding(
        dpop_proof=proof,
        client_cert_pem=cert_pem,
        expected_uri=DPOP_URI,
        http_method="POST",
    )


class TestDPoPJti:
    async def test_claim_survives_lost_reply(self, dpop_client):
        key, cert_pem = dpop_client
        redis = fakeredis.FakeRedis(decode_responses=True)
        validator = DPoPValidator(redis_client=LostReply(redis, "set"))
        assert await _validate(validator, cert_pem, _proof(key, "jti-lost-reply"))

    async def test_replay_on_another_replica_still_refused(self, dpop_client):
        key, cert_pem = dpop_client
        redis = fakeredis.FakeRedis(decode_responses=True)
        proof = _proof(key, "jti-replayed")
        lossy = DPoPValidator(redis_client=LostReply(redis, "set"))
        assert await _validate(lossy, cert_pem, proof)
        with pytest.raises(TokenBindingError, match="JTI replay detected"):
            await _validate(DPoPValidator(redis_client=redis), cert_pem, proof)

    async def test_claim_lost_to_a_racing_replica_still_refused(self, dpop_client):
        key, cert_pem = dpop_client
        redis = fakeredis.FakeRedis(decode_responses=True)

        class RacingReplica(LostReply):
            """Another replica claims the jti between our EXISTS and our SET."""

            async def exists(self, name: str) -> int:
                await redis.set(name, new_op_id(), ex=60)
                return 0

        validator = DPoPValidator(redis_client=RacingReplica(redis, "set"))
        with pytest.raises(TokenBindingError, match="JTI replay detected"):
            await _validate(validator, cert_pem, _proof(key, "jti-raced"))

    async def test_read_back_failure_fails_closed(self, dpop_client):
        key, cert_pem = dpop_client
        validator = DPoPValidator(redis_client=ConflictReadFails())
        with pytest.raises(TokenBindingError, match="fail-closed"):
            await _validate(validator, cert_pem, _proof(key, "jti-read-back"))


# ---------------------------------------------------------------------------
# GCRA rate limiter: conservative by design
# ---------------------------------------------------------------------------


async def test_gcra_resend_double_counts_conservatively():
    """A re-sent GCRA script charges one request twice; it never admits more."""
    redis = fakeredis.FakeRedis(decode_responses=True)
    await redis.script_load(LUA_GCRA_DUAL_BUCKET)  # the re-send hits EVALSHA
    limiter = SharedRateLimiter(
        LostReply(redis, "evalsha"), principal_per_min=60, identity_per_min=600
    )
    verdict = await limiter.check("/r", identity="id", principal="p", now_ms=1_000_000)
    assert verdict.allowed
    # Two emission intervals (60/min -> T = 1000 ms) charged for one request.
    assert float(await redis.get("rl:/r:p:p")) == 1_000_000 + 2 * 1000
