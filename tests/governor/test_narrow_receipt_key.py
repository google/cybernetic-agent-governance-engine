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

The receipt key used to be the first 32 characters of the seal. Every JWT
seal minted under one signing key starts with the same base64url header, so
concurrent narrowed trades collided on a single key: one receipt overwrote
the other, the first consumer deleted it, and both trades failed closed.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import re
from unittest.mock import AsyncMock

import pytest

from src.gateway.governance.narrow_receipt import (
    NARROW_RECEIPT_TTL_SECONDS,
    issue_narrow_receipt,
    narrow_receipt_key,
)

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
async def test_concurrent_narrowed_seals_never_share_a_receipt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = AsyncMock()
    monkeypatch.setattr("src.gateway.infrastructure.redis_client.redis_client", store)
    seals = [_jwt_seal(f"nonce-{i}") for i in range(8)]

    await asyncio.gather(
        *(
            issue_narrow_receipt(
                seal,
                {"amount": float(i)},
                constraints_applied=[],
                narrowing_reason="clamp",
            )
            for i, seal in enumerate(seals)
        )
    )

    written = [call.args[0] for call in store.setex.await_args_list]
    assert len(written) == len(seals)
    assert len(set(written)) == len(seals)
    assert set(written) == {narrow_receipt_key(seal) for seal in seals}
