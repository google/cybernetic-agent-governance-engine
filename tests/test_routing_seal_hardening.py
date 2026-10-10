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

"""Routing-seal hardening: exact hashing, default evidence binding, revocation.

1. Canonicalization (``cage-action/1``): params are hashed as exact I-JSON
   values. Nothing is ``str()``-coerced, so structurally different params
   can never share a seal.
2. Evidence binding is required by default in every posture. Consumption
   reads the expected ``record_hash`` from the issuance-time evidence index,
   independently of the seal.
3. Revocation: an unconsumed seal can be revoked before it expires; the
   revoke and the consume race on one ``SET NX`` key.
"""

from __future__ import annotations

import datetime
import hashlib
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import fakeredis.aioredis as fakeredis
import pytest

import src.gateway.governance.routing_seal as rs
from src.gateway.governance.evidence.stream import EvidenceChainUnavailableError
from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan

pytestmark = [pytest.mark.unit, pytest.mark.local]

ACTION = "execute_trade"
PARAMS = {"symbol": "AAPL", "amount": 100.0}
RH = "c" * 64


@pytest.fixture(autouse=True)
def _hmac_test_posture(monkeypatch):
    """HMAC seals in a non-production posture, binding at its default (on)."""
    monkeypatch.setenv("CAGE_SEAL_STRICT_MODE", "false")
    monkeypatch.setenv("CAGE_ENV", "test")
    monkeypatch.delenv("ENVIRONMENT", raising=False)
    monkeypatch.delenv("CAGE_REQUIRE_EVIDENCE_BINDING", raising=False)


@pytest.fixture
def redis():
    return fakeredis.FakeRedis()


async def _index(redis, seal: str, record_hash: str = RH) -> None:
    await redis.set(f"cage:seal:evidence:{rs.seal_nonce(seal)}", record_hash)


# ---------------------------------------------------------------------------
# 1. Canonicalization
# ---------------------------------------------------------------------------


class TestCanonicalization:
    def test_recipe_is_jcs_of_nested_action_and_params(self):
        expected = hashlib.sha256(
            jcs_canonicalize_plan({"action": ACTION, "params": PARAMS})
        ).hexdigest()
        assert rs.compute_action_hash(ACTION, PARAMS) == expected
        assert rs.SEAL_CANON == "cage-action/1"

    @pytest.mark.parametrize(
        ("structured", "stringly"),
        [
            ({"x": [1, 2]}, {"x": "[1, 2]"}),
            ({"x": {"k": "v"}}, {"x": "{'k': 'v'}"}),
            ({"x": None}, {"x": "None"}),
            ({"x": True}, {"x": "True"}),
        ],
    )
    def test_structured_and_stringified_params_never_collide(
        self, structured, stringly
    ):
        assert rs.compute_action_hash(ACTION, structured) != rs.compute_action_hash(
            ACTION, stringly
        )
        seal = rs.generate_seal(ACTION, structured, record_hash=RH)
        assert rs.verify_seal(seal, ACTION, structured) is True
        with pytest.raises(rs.SymbolicGovernorViolation):
            rs.verify_seal(seal, ACTION, stringly)

    def test_param_named_action_cannot_shadow_the_action(self):
        # Under the old flat merge {"action": a, **params}, the param won.
        assert rs.compute_action_hash(
            "cancel_trade", {"action": "execute_trade"}
        ) != rs.compute_action_hash("execute_trade", {"action": "execute_trade"})
        seal = rs.generate_seal("cancel_trade", {"action": ACTION}, record_hash=RH)
        with pytest.raises(rs.SymbolicGovernorViolation):
            rs.verify_seal(seal, ACTION, {"action": ACTION})

    def test_key_order_does_not_matter(self):
        assert rs.compute_action_hash(
            ACTION, {"a": 1, "b": [1, {"y": 2, "x": 1}]}
        ) == rs.compute_action_hash(ACTION, {"b": [1, {"x": 1, "y": 2}], "a": 1})

    def test_tuple_and_list_are_the_same_json_array(self):
        assert rs.compute_action_hash(ACTION, {"x": (1, 2)}) == rs.compute_action_hash(
            ACTION, {"x": [1, 2]}
        )

    @pytest.mark.parametrize(
        "bad_params",
        [
            {"x": float("nan")},
            {"x": float("inf")},
            {"x": 2**53},
            {"x": -(2**53)},
            {"x": datetime.datetime(2026, 1, 1)},
            {"x": b"bytes"},
            {"x": {1, 2}},
            {"x": {1: "int-key"}},
            {"x": object()},
        ],
    )
    def test_non_json_params_refused_at_issuance(self, bad_params):
        with pytest.raises(rs.SealCanonicalizationError):
            rs.generate_seal(ACTION, bad_params, record_hash=RH)

    @pytest.mark.parametrize(
        "bad_params",
        [{"x": float("nan")}, {"x": datetime.date(2026, 1, 1)}, {"x": 2**60}],
    )
    def test_non_json_params_refused_at_verification(self, bad_params):
        seal = rs.generate_seal(ACTION, {"x": 1}, record_hash=RH)
        with pytest.raises(rs.SymbolicGovernorViolation):
            rs.verify_seal(seal, ACTION, bad_params)

    def test_max_safe_integer_is_accepted(self):
        params = {"x": 2**53 - 1, "y": -(2**53 - 1)}
        seal = rs.generate_seal(ACTION, params, record_hash=RH)
        assert rs.verify_seal(seal, ACTION, params) is True

    @pytest.mark.parametrize("bad_action", ["", None, 7])
    def test_action_must_be_non_empty_string(self, bad_action):
        with pytest.raises(rs.SealCanonicalizationError):
            rs.canonical_action_bytes(bad_action, {})

    def test_params_must_be_object(self):
        with pytest.raises(rs.SealCanonicalizationError):
            rs.canonical_action_bytes(ACTION, [1, 2])  # type: ignore[arg-type]


class TestJwtCanonClaim:
    """JWT seals must declare the recipe they were hashed with."""

    @pytest.fixture
    def trusted_key(self, monkeypatch):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        import src.gateway.governance.jwks as jwks_mod

        key = ec.generate_private_key(ec.SECP256R1())
        pub = key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        monkeypatch.setattr(jwks_mod, "get_verification_key_for_jwt", lambda _t: pub)
        return key

    def _seal(self, key, **overrides) -> str:
        import time

        import jwt as pyjwt

        claims = {
            "action_hash": rs.compute_action_hash(ACTION, PARAMS),
            "canon": rs.SEAL_CANON,
            "record_hash": RH,
            "nonce": "jwt-nonce-0001",
            "exp": int(time.time()) + 60,
        }
        claims.update(overrides)
        claims = {k: v for k, v in claims.items() if v is not None}
        return pyjwt.encode(claims, key, algorithm="ES256", headers={"kid": "k1"})

    def test_current_recipe_verifies(self, trusted_key):
        assert rs.verify_seal(self._seal(trusted_key), ACTION, PARAMS) is True

    @pytest.mark.parametrize("canon", [None, "cage-action/0", "legacy"])
    def test_missing_or_unknown_canon_refused(self, trusted_key, canon):
        with pytest.raises(rs.SymbolicGovernorViolation):
            rs.verify_seal(self._seal(trusted_key, canon=canon), ACTION, PARAMS)

    def test_legacy_flat_merge_hash_refused(self, trusted_key):
        legacy = hashlib.sha256(
            jcs_canonicalize_plan({"action": ACTION, **PARAMS})
        ).hexdigest()
        with pytest.raises(rs.SymbolicGovernorViolation):
            rs.verify_seal(self._seal(trusted_key, action_hash=legacy), ACTION, PARAMS)


# ---------------------------------------------------------------------------
# 2. Evidence binding on by default
# ---------------------------------------------------------------------------


class TestEvidenceBindingDefault:
    def test_binding_required_by_default(self):
        assert rs._require_evidence_binding() is True
        seal = rs.generate_seal(ACTION, PARAMS, record_hash=None)
        with pytest.raises(rs.SymbolicGovernorViolation, match="Evidence sufficiency"):
            rs.verify_seal(seal, ACTION, PARAMS)

    def test_opt_out_honoured_outside_production(self, monkeypatch):
        monkeypatch.setenv("CAGE_REQUIRE_EVIDENCE_BINDING", "false")
        assert rs._require_evidence_binding() is False
        seal = rs.generate_seal(ACTION, PARAMS, record_hash=None)
        assert rs.verify_seal(seal, ACTION, PARAMS) is True

    def test_opt_out_ignored_in_production(self, monkeypatch):
        monkeypatch.setenv("CAGE_REQUIRE_EVIDENCE_BINDING", "false")
        monkeypatch.setenv("CAGE_ENV", "production")
        assert rs._require_evidence_binding() is True

    def test_flag_read_at_call_time(self, monkeypatch):
        assert rs._require_evidence_binding() is True
        monkeypatch.setenv("CAGE_REQUIRE_EVIDENCE_BINDING", "false")
        assert rs._require_evidence_binding() is False

    @pytest.mark.asyncio
    async def test_consume_refused_without_evidence_index(self, redis):
        seal = rs.generate_seal(ACTION, PARAMS, record_hash=RH)
        with pytest.raises(rs.SymbolicGovernorViolation, match="not bound"):
            await rs.verify_and_consume_seal(seal, ACTION, PARAMS, redis_client=redis)
        assert await rs.seal_state(seal, redis_client=redis) is rs.SealState.UNUSED

    @pytest.mark.asyncio
    async def test_consume_refused_when_index_names_other_record(self, redis):
        seal = rs.generate_seal(ACTION, PARAMS, record_hash=RH)
        await _index(redis, seal, "d" * 64)
        with pytest.raises(rs.SymbolicGovernorViolation, match="record_hash mismatch"):
            await rs.verify_and_consume_seal(seal, ACTION, PARAMS, redis_client=redis)
        assert await rs.seal_state(seal, redis_client=redis) is rs.SealState.UNUSED

    @pytest.mark.asyncio
    async def test_consume_succeeds_with_matching_index(self, redis):
        seal = rs.generate_seal(ACTION, PARAMS, record_hash=RH)
        await _index(redis, seal)
        assert await rs.verify_and_consume_seal(
            seal, ACTION, PARAMS, redis_client=redis
        )
        assert await rs.seal_state(seal, redis_client=redis) is rs.SealState.CONSUMED

    @pytest.mark.asyncio
    async def test_index_read_failure_fails_closed(self):
        broken = AsyncMock()
        broken.get.side_effect = ConnectionError("redis down")
        seal = rs.generate_seal(ACTION, PARAMS, record_hash=RH)
        with pytest.raises(rs.SymbolicGovernorViolation, match="evidence index"):
            await rs.verify_and_consume_seal(seal, ACTION, PARAMS, redis_client=broken)


class TestGenerateSealWithEvidence:
    @staticmethod
    def _sink(record_hash: str = RH):
        sink = SimpleNamespace(
            ingest_sync=AsyncMock(
                return_value=SimpleNamespace(
                    hash=record_hash, evidence_id="ev-1", sequence=1
                )
            ),
            ingest=AsyncMock(),
            is_running=True,
        )
        return sink

    @pytest.mark.asyncio
    async def test_blocking_issue_writes_index_and_consumes(self, redis):
        sink = self._sink()
        with (
            patch.object(rs.es, "is_evidence_chain_blocking", return_value=True),
            patch.object(rs.es, "get_evidence_sink", return_value=sink),
        ):
            seal = await rs.generate_seal_with_evidence(
                ACTION, PARAMS, redis_client=redis
            )
        stored = await redis.get(f"cage:seal:evidence:{rs.seal_nonce(seal)}")
        assert stored.decode() == RH
        assert await redis.ttl(f"cage:seal:evidence:{rs.seal_nonce(seal)}") > 0
        assert await rs.verify_and_consume_seal(
            seal, ACTION, PARAMS, redis_client=redis
        )

    @pytest.mark.asyncio
    async def test_nonblocking_refuses_to_mint_unbound_seal(self, redis):
        with (
            patch.object(rs.es, "is_evidence_chain_blocking", return_value=False),
            patch.object(rs.es, "get_evidence_sink", return_value=self._sink()),
        ):
            with pytest.raises(EvidenceChainUnavailableError, match="binding"):
                await rs.generate_seal_with_evidence(ACTION, PARAMS, redis_client=redis)
        assert await redis.dbsize() == 0

    @pytest.mark.asyncio
    async def test_index_write_failure_withholds_seal(self):
        broken = AsyncMock()
        broken.set.side_effect = ConnectionError("redis down")
        with (
            patch.object(rs.es, "is_evidence_chain_blocking", return_value=True),
            patch.object(rs.es, "get_evidence_sink", return_value=self._sink()),
        ):
            with pytest.raises(EvidenceChainUnavailableError, match="evidence index"):
                await rs.generate_seal_with_evidence(
                    ACTION, PARAMS, redis_client=broken
                )

    @pytest.mark.asyncio
    async def test_non_json_params_refused_before_evidence_commit(self, redis):
        sink = self._sink()
        with (
            patch.object(rs.es, "is_evidence_chain_blocking", return_value=True),
            patch.object(rs.es, "get_evidence_sink", return_value=sink),
        ):
            with pytest.raises(rs.SealCanonicalizationError):
                await rs.generate_seal_with_evidence(
                    ACTION, {"x": float("nan")}, redis_client=redis
                )
        sink.ingest_sync.assert_not_awaited()


# ---------------------------------------------------------------------------
# 3. Revocation
# ---------------------------------------------------------------------------


class TestRevocation:
    @pytest.mark.asyncio
    async def test_revoked_seal_cannot_be_consumed(self, redis):
        seal = rs.generate_seal(ACTION, PARAMS, record_hash=RH)
        await _index(redis, seal)
        assert await rs.revoke_seal(seal, "operator kill", redis_client=redis) is True
        assert await rs.seal_state(seal, redis_client=redis) is rs.SealState.REVOKED
        with pytest.raises(
            rs.SymbolicGovernorViolation, match="seal revoked: operator kill"
        ):
            await rs.verify_and_consume_seal(seal, ACTION, PARAMS, redis_client=redis)
        assert await rs.seal_state(seal, redis_client=redis) is rs.SealState.REVOKED

    @pytest.mark.asyncio
    async def test_consumed_seal_cannot_be_revoked(self, redis):
        seal = rs.generate_seal(ACTION, PARAMS, record_hash=RH)
        await _index(redis, seal)
        assert await rs.verify_and_consume_seal(
            seal, ACTION, PARAMS, redis_client=redis
        )
        assert await rs.revoke_seal(seal, "too late", redis_client=redis) is False
        assert await rs.seal_state(seal, redis_client=redis) is rs.SealState.CONSUMED

    @pytest.mark.asyncio
    async def test_double_revoke_is_idempotent_false(self, redis):
        seal = rs.generate_seal(ACTION, PARAMS, record_hash=RH)
        assert await rs.revoke_seal(seal, "first", redis_client=redis) is True
        assert await rs.revoke_seal(seal, "second", redis_client=redis) is False
        raw = json.loads(await redis.get(f"cage:seal:nonce:{rs.seal_nonce(seal)}"))
        assert raw["reason"] == "first"

    @pytest.mark.asyncio
    async def test_revocation_key_outlives_seal(self, redis):
        seal = rs.generate_seal(ACTION, PARAMS, ttl_s=30, record_hash=RH)
        await rs.revoke_seal(seal, "ttl", redis_client=redis)
        ttl = await redis.ttl(f"cage:seal:nonce:{rs.seal_nonce(seal)}")
        assert ttl >= 60

    @pytest.mark.asyncio
    async def test_revoke_does_not_require_a_valid_seal(self, redis):
        forged = "ffffffff.execute-trade." + RH + "." + "0" * 64
        assert await rs.revoke_seal(forged, "forged", redis_client=redis) is True

    @pytest.mark.asyncio
    @pytest.mark.parametrize("bad", ["", None, 42])
    async def test_malformed_seal_rejected(self, redis, bad):
        with pytest.raises(rs.SymbolicGovernorViolation):
            await rs.revoke_seal(bad, "x", redis_client=redis)

    @pytest.mark.asyncio
    async def test_redis_failure_fails_closed(self):
        broken = AsyncMock()
        broken.set.side_effect = ConnectionError("redis down")
        broken.get.side_effect = ConnectionError("redis down")
        seal = rs.generate_seal(ACTION, PARAMS, record_hash=RH)
        with pytest.raises(rs.SymbolicGovernorViolation, match="revocation failed"):
            await rs.revoke_seal(seal, "x", redis_client=broken)
        with pytest.raises(rs.SymbolicGovernorViolation, match="state unavailable"):
            await rs.seal_state(seal, redis_client=broken)

    @pytest.mark.asyncio
    async def test_revoke_and_consume_race_has_one_winner(self, redis):
        import asyncio

        seal = rs.generate_seal(ACTION, PARAMS, record_hash=RH)
        await _index(redis, seal)
        consume, revoke = await asyncio.gather(
            rs.verify_and_consume_seal(seal, ACTION, PARAMS, redis_client=redis),
            rs.revoke_seal(seal, "race", redis_client=redis),
            return_exceptions=True,
        )
        consumed = consume is True
        revoked = revoke is True
        assert consumed != revoked, (consume, revoke)
        state = await rs.seal_state(seal, redis_client=redis)
        assert state is (rs.SealState.CONSUMED if consumed else rs.SealState.REVOKED)


@pytest.mark.asyncio
async def test_default_store_uses_raw_client_behind_shared_wrapper(monkeypatch):
    """The shared wrapper lacks SET NX EX and EVAL; the raw client is used instead."""
    import src.gateway.infrastructure.redis_client as rc

    raw = fakeredis.FakeRedis()

    class _Wrapper:
        async def get_raw_client(self):
            return raw

    monkeypatch.setattr(rc, "redis_client", _Wrapper())
    seal = rs.generate_seal(ACTION, PARAMS, record_hash=RH)
    await _index(raw, seal)
    assert await rs.verify_and_consume_seal(seal, ACTION, PARAMS)
    assert await rs.seal_state(seal) is rs.SealState.CONSUMED
    assert await rs.revoke_seal(seal, "late") is False


@pytest.mark.asyncio
async def test_revoke_jwt_rejects_unverified_token_claiming_victim_nonce(
    redis, monkeypatch
):
    """Issue #405: An unsigned/forged JWT cannot poison a legitimate seal's nonce or pin a 68-year TTL."""
    import time

    import jwt as pyjwt
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    legit_key = ec.generate_private_key(ec.SECP256R1())
    attacker_key = ec.generate_private_key(ec.SECP256R1())
    legit_pem = legit_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    monkeypatch.setattr(
        "src.gateway.governance.jwks.get_verification_key_for_jwt",
        lambda token: legit_pem,
    )

    now = int(time.time())
    victim_nonce = "11" * 16
    forged_jwt = pyjwt.encode(
        {
            "action_hash": rs.compute_action_hash(ACTION, PARAMS),
            "canon": rs.SEAL_CANON,
            "record_hash": RH,
            "nonce": victim_nonce,
            "iat": now,
            "exp": 2**31 - 1,
            "iss": "cage-gateway",
            "aud": f"cage-actuator:{ACTION}",
        },
        attacker_key,
        algorithm="ES256",
        headers={"kid": "gw-key-1"},
    )

    with pytest.raises(
        rs.SymbolicGovernorViolation, match="malformed seal or invalid signature"
    ):
        await rs.revoke_seal(forged_jwt, "attacker poison", redis_client=redis)

    assert await redis.get(f"cage:seal:nonce:{victim_nonce}") is None

    # A legitimately signed JWT with the trusted kid CAN be revoked and has a bounded TTL.
    legit_jwt = pyjwt.encode(
        {
            "action_hash": rs.compute_action_hash(ACTION, PARAMS),
            "canon": rs.SEAL_CANON,
            "record_hash": RH,
            "nonce": victim_nonce,
            "iat": now,
            "exp": now + 30,
            "iss": "cage-gateway",
            "aud": f"cage-actuator:{ACTION}",
        },
        legit_key,
        algorithm="ES256",
        headers={"kid": "gw-key-1"},
    )
    assert await rs.revoke_seal(legit_jwt, "legit revoke", redis_client=redis) is True
    assert await rs.seal_state(legit_jwt, redis_client=redis) is rs.SealState.REVOKED

