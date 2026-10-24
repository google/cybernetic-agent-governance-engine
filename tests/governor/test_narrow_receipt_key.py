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

"""Regression tests for the NARROW receipt key: one key per seal.

The receipt key used to be the first 32 characters of the seal. Those
characters encode only the start of a JWT seal's header (``alg`` and
``typ``), so every seal with the same algorithm mapped to one Redis key.
Concurrent narrowed trades overwrote each other's receipt and the first
consumer deleted it; an ALLOW trade could even consume a narrowed trade's
receipt and be blocked as a signature mismatch.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import re
import uuid
from unittest.mock import AsyncMock, patch

import fakeredis.aioredis
import pytest

from src.gateway.governance.narrow_receipt import (
    NARROW_RECEIPT_TTL_SECONDS,
    issue_narrow_receipt,
    narrow_receipt_key,
)
from tests.fixtures.trade_inputs import trade_governor

pytestmark = [pytest.mark.unit, pytest.mark.local]

_KEY_PATTERN = re.compile(r"^narrow:receipt:[0-9a-f]{64}$")


def _b64url(obj: dict) -> str:
    raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _jwt_seal(nonce: str) -> str:
    """A JWT-shaped seal: shared header, per-seal payload and signature."""
    header = _b64url({"alg": "ES256", "typ": "JWT", "kid": "kid-1"})
    payload = _b64url({"nonce": nonce, "action_hash": "a" * 64})
    signature = (
        base64.urlsafe_b64encode(nonce.encode("utf-8") * 4).rstrip(b"=").decode()
    )
    return f"{header}.{payload}.{signature}"


@pytest.fixture
def receipt_store(monkeypatch: pytest.MonkeyPatch) -> fakeredis.aioredis.FakeRedis:
    """A stateful Redis for receipts, so overwrites and burns are observable."""
    store = fakeredis.aioredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr("src.gateway.infrastructure.redis_client.redis_client", store)
    return store


async def _issue(seal: str, amount: float) -> None:
    await issue_narrow_receipt(
        seal,
        {"symbol": "AAPL", "amount": amount},
        constraints_applied=["amount clamped"],
        narrowing_reason="fiscal headroom",
    )


def test_seals_sharing_a_header_get_distinct_keys() -> None:
    first, second = _jwt_seal("nonce-1"), _jwt_seal("nonce-2")
    assert first[:32] == second[:32]  # the prefix the old key used collides
    assert narrow_receipt_key(first) != narrow_receipt_key(second)


def test_key_is_deterministic_per_seal() -> None:
    seal = _jwt_seal("nonce-1")
    assert narrow_receipt_key(seal) == narrow_receipt_key(seal)


def test_key_is_the_sha256_digest_of_the_whole_seal() -> None:
    seal = _jwt_seal("nonce-1")
    key = narrow_receipt_key(seal)
    assert _KEY_PATTERN.match(key)
    assert key == "narrow:receipt:" + hashlib.sha256(seal.encode("utf-8")).hexdigest()


def test_key_carries_no_seal_material() -> None:
    seal = _jwt_seal("nonce-1")
    key = narrow_receipt_key(seal)
    for part in seal.split("."):
        assert part[:16] not in key


@pytest.mark.asyncio
async def test_issue_stores_receipt_under_the_digest_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = AsyncMock()
    monkeypatch.setattr("src.gateway.infrastructure.redis_client.redis_client", store)
    seal = _jwt_seal("nonce-1")

    await issue_narrow_receipt(
        seal,
        {"symbol": "AAPL", "amount": 50.0},
        constraints_applied=["amount<=50"],
        narrowing_reason="fiscal headroom",
    )

    store.setex.assert_awaited_once()
    key, ttl, payload = store.setex.await_args.args
    assert key == narrow_receipt_key(seal)
    assert ttl == NARROW_RECEIPT_TTL_SECONDS
    assert json.loads(payload)["original_signature"] == seal


@pytest.mark.asyncio
async def test_concurrent_receipts_survive_each_other(
    receipt_store: fakeredis.aioredis.FakeRedis,
) -> None:
    first, second, never_narrowed = (_jwt_seal(f"nonce-{i}") for i in range(3))
    assert first[:32] == second[:32] == never_narrowed[:32]  # one old-style key

    await asyncio.gather(_issue(first, 10.0), _issue(second, 20.0))

    for seal, amount in ((first, 10.0), (second, 20.0)):
        receipt = json.loads(await receipt_store.get(narrow_receipt_key(seal)))
        assert receipt["original_signature"] == seal
        assert receipt["narrowed_params"]["amount"] == amount
    # A seal that was never narrowed (an ALLOW trade's) finds no receipt.
    assert await receipt_store.get(narrow_receipt_key(never_narrowed)) is None


@pytest.mark.asyncio
async def test_each_trade_redeems_only_its_own_receipt(
    receipt_store: fakeredis.aioredis.FakeRedis,
) -> None:
    """Two narrowed trades and one ALLOW trade, all sharing a seal header."""
    from src.cage_finance.tools.tool_provider import execute_trade_action

    allowed, narrowed_a, narrowed_b = (
        _jwt_seal(nonce) for nonce in ("allow", "narrow-a", "narrow-b")
    )
    await asyncio.gather(_issue(narrowed_a, 10.0), _issue(narrowed_b, 20.0))
    verify = AsyncMock()

    with (
        patch(
            "src.cage_finance.tools.tool_provider.enforce_governance",
            AsyncMock(side_effect=[allowed, narrowed_a, narrowed_b]),
        ),
        patch("src.gateway.governance.routing_seal.verify_and_consume_seal", verify),
    ):
        results = [
            await execute_trade_action(
                governor=trade_governor(),
                transaction_id=str(uuid.uuid4()),
                symbol="AAPL",
                amount=100.0,
                currency="USD",
                confidence=0.95,
                dry_run=True,
            )
            for _ in range(3)
        ]

    assert all(result.startswith("DRY_RUN: APPROVED") for result in results), results
    # Each seal is verified against its own params: the ALLOW trade's
    # original amount, and each narrowed trade's clamped amount.
    verified = {call.args[0]: call.args[2]["amount"] for call in verify.await_args_list}
    assert verified == {allowed: 100.0, narrowed_a: 10.0, narrowed_b: 20.0}
    assert await receipt_store.keys("narrow:receipt:*") == []
