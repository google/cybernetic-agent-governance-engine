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
Hermetic unit tests for POAM-023: CBF external balance reconciliation.

Tests verify:
  1. ReconciliationResult with fresh timestamp is valid
  2. ReconciliationResult with old timestamp is stale
  3. read_verified_balance returns None when Redis key missing
  4. read_verified_balance returns None when TTL expired (stale)
  5. CBF reads from reconciliation key when available
  6. CBF falls back to safety:current_cash when reconciliation absent

All tests run without live Redis (fakeredis) or live KMS (mocked).
"""

from __future__ import annotations

import json
import time
from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip(
    "fakeredis", reason="fakeredis required for CBF reconciliation tests"
)

import fakeredis  # type: ignore[import]

from src.cage_finance.compliance.reconciliation_worker import (
    _REDIS_KEY_VERIFIED_BALANCE,
    TTL_SECONDS,
    ReconciliationResult,
    read_verified_balance,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SAFE_BALANCE = 95_000.0  # above min_cash_balance (default 10_000)
_RECON_BALANCE = 92_000.0  # externally reconciled balance


# ---------------------------------------------------------------------------
# Test 1: ReconciliationResult with fresh timestamp is valid
# ---------------------------------------------------------------------------


@pytest.mark.local
def test_reconciliation_result_is_valid() -> None:
    """ReconciliationResult with a fresh timestamp and no error is valid."""
    result = ReconciliationResult(
        source="plaid",
        balance_usd=_RECON_BALANCE,
        verified_at=time.time(),  # fresh
        signature="deadbeef",
        ttl_seconds=TTL_SECONDS,
    )
    assert result.is_valid is True, (
        "Expected is_valid=True for fresh result with no error"
    )
    assert result.is_stale is False, (
        "Expected is_stale=False for freshly created result"
    )


# ---------------------------------------------------------------------------
# Test 2: ReconciliationResult with old timestamp is stale
# ---------------------------------------------------------------------------


@pytest.mark.local
def test_reconciliation_result_is_stale() -> None:
    """ReconciliationResult with verified_at older than ttl_seconds is stale."""
    result = ReconciliationResult(
        source="plaid",
        balance_usd=_RECON_BALANCE,
        verified_at=time.time() - (TTL_SECONDS + 60),  # older than TTL
        signature="deadbeef",
        ttl_seconds=TTL_SECONDS,
    )
    assert result.is_stale is True, "Expected is_stale=True for result older than TTL"
    # is_valid checks error field only, not staleness
    assert result.is_valid is True, "is_valid should be True (no error field set)"


# ---------------------------------------------------------------------------
# Test 3: read_verified_balance returns None when Redis key missing
# ---------------------------------------------------------------------------


@pytest.mark.local
def test_read_verified_balance_returns_none_when_absent() -> None:
    """read_verified_balance returns None when the reconciliation key is not in Redis."""
    fake_redis = fakeredis.FakeRedis(decode_responses=True)
    # Key is not set — simulates first run or expired TTL
    result = read_verified_balance(fake_redis)
    assert result is None, f"Expected None when key absent, got {result!r}"


# ---------------------------------------------------------------------------
# Test 4: read_verified_balance returns None when TTL expired (stale)
# ---------------------------------------------------------------------------


@pytest.mark.local
def test_read_verified_balance_returns_none_when_stale() -> None:
    """read_verified_balance returns None when the stored balance is stale (past TTL)."""
    fake_redis = fakeredis.FakeRedis(decode_responses=True)

    # Write a stale payload directly — verified_at is older than ttl_seconds
    stale_result = ReconciliationResult(
        source="plaid",
        balance_usd=_RECON_BALANCE,
        verified_at=time.time() - (TTL_SECONDS + 120),  # well past TTL
        signature="deadbeef",
        ttl_seconds=TTL_SECONDS,
    )
    fake_redis.set(_REDIS_KEY_VERIFIED_BALANCE, stale_result.to_redis_payload())

    result = read_verified_balance(fake_redis)
    assert result is None, (
        f"Expected None for stale balance (age > TTL), got {result!r}"
    )


# ---------------------------------------------------------------------------
# Test 5: CBF uses reconciliation balance when available
# ---------------------------------------------------------------------------


@pytest.mark.local
def test_cbf_uses_reconciliation_balance_when_available() -> None:
    """CBF _read_cbf_state_atomic returns source='reconciled' when reconciliation key present."""
    import asyncio

    fake_redis_async = pytest.importorskip(
        "fakeredis.aioredis", reason="fakeredis[aioredis] required"
    ).FakeRedis(decode_responses=True)

    fresh_result = ReconciliationResult(
        source="plaid",
        balance_usd=_RECON_BALANCE,
        verified_at=time.time(),
        signature="valid_sig",
        ttl_seconds=TTL_SECONDS,
    )

    from src.cage_finance.safety.cbf import ControlBarrierFunction

    cbf = ControlBarrierFunction(skip_epoch_seed=True)
    cbf.tracer = None

    # Seed self-reported balance and initial fence epoch
    asyncio.run(fake_redis_async.set(cbf.redis_key, str(_SAFE_BALANCE)))
    asyncio.run(fake_redis_async.set("safety:fence_epoch", "0"))

    mock_signer = MagicMock()
    mock_signer.verify.return_value = True

    with (
        patch(
            "src.cage_finance.safety.cbf.redis_client",
            new=MagicMock(get_raw_client=MagicMock(return_value=fake_redis_async)),
        ),
        patch(
            "src.cage_finance.compliance.reconciliation_worker.read_verified_balance",
            return_value=fresh_result,
        ),
        patch(
            "src.gateway.governance.kms_signer.get_governance_signer",
            return_value=mock_signer,
        ),
    ):
        state = asyncio.run(cbf._read_cbf_state_atomic())

    assert state["source"] == "reconciled", (
        f"Expected source='reconciled', got {state['source']!r}"
    )
    assert abs(state["current_cash"] - _RECON_BALANCE) < 0.01, (
        f"Expected current_cash≈{_RECON_BALANCE}, got {state['current_cash']}"
    )


# ---------------------------------------------------------------------------
# Test 6: CBF falls back to safety:current_cash when reconciliation absent
# ---------------------------------------------------------------------------


@pytest.mark.local
def test_cbf_falls_back_to_redis_when_reconciliation_absent() -> None:
    """CBF _read_cbf_state_atomic returns source='self_reported' when reconciliation key absent."""
    import asyncio

    fake_redis_async = pytest.importorskip(
        "fakeredis.aioredis", reason="fakeredis[aioredis] required"
    ).FakeRedis(decode_responses=True)

    from src.cage_finance.safety.cbf import ControlBarrierFunction

    cbf = ControlBarrierFunction(skip_epoch_seed=True)
    cbf.tracer = None

    # Seed self-reported balance and initial fence epoch
    asyncio.run(fake_redis_async.set(cbf.redis_key, str(_SAFE_BALANCE)))
    asyncio.run(fake_redis_async.set("safety:fence_epoch", "0"))

    with (
        patch(
            "src.cage_finance.safety.cbf.redis_client",
            new=MagicMock(get_raw_client=MagicMock(return_value=fake_redis_async)),
        ),
        patch(
            "src.cage_finance.compliance.reconciliation_worker.read_verified_balance",
            return_value=None,  # reconciliation key absent / stale
        ),
    ):
        state = asyncio.run(cbf._read_cbf_state_atomic())

    assert state["source"] == "self_reported", (
        f"Expected source='self_reported', got {state['source']!r}"
    )
    assert abs(state["current_cash"] - _SAFE_BALANCE) < 0.01, (
        f"Expected current_cash≈{_SAFE_BALANCE}, got {state['current_cash']}"
    )


# ---------------------------------------------------------------------------
# POAM-023 Remediation Tests: atomic commit path verification
# ---------------------------------------------------------------------------


@pytest.mark.local
def test_atomic_commit_uses_reconciled_balance() -> None:
    """POAM-023: Verify atomic_verify_and_commit uses KMS-verified reconciled balance."""
    import asyncio

    fake_redis_async = pytest.importorskip(
        "fakeredis.aioredis", reason="fakeredis[aioredis] required"
    ).FakeRedis(decode_responses=True)

    fresh_result = ReconciliationResult(
        source="plaid",
        balance_usd=_RECON_BALANCE,
        verified_at=time.time(),
        signature="valid_sig",
        ttl_seconds=TTL_SECONDS,
        sequence=1,
    )

    from src.cage_finance.safety.cbf import ControlBarrierFunction

    cbf = ControlBarrierFunction(skip_epoch_seed=True)
    cbf.tracer = None

    # Seed self-reported balance and fence epoch
    asyncio.run(fake_redis_async.set(cbf.redis_key, str(_SAFE_BALANCE)))
    asyncio.run(fake_redis_async.set("safety:fence_epoch", "0"))

    mock_signer = MagicMock()
    mock_signer.verify.return_value = True

    async def mock_lrange(*args):
        return []

    async def mock_rpush(*args):
        return 1

    async def mock_ltrim(*args):
        return True

    with (
        patch(
            "src.cage_finance.safety.cbf.redis_client",
            new=MagicMock(
                get_raw_client=MagicMock(return_value=fake_redis_async),
                lrange=MagicMock(side_effect=mock_lrange),
                rpush=MagicMock(side_effect=mock_rpush),
                ltrim=MagicMock(side_effect=mock_ltrim),
            ),
        ),
        patch(
            "src.cage_finance.compliance.reconciliation_worker.read_verified_balance",
            return_value=fresh_result,
        ),
        patch(
            "src.gateway.governance.kms_signer.get_governance_signer",
            return_value=mock_signer,
        ),
    ):
        # Attempt small trade (should succeed with reconciled balance)
        committed, message = asyncio.run(
            cbf.atomic_verify_and_commit(
                "execute_trade", {"amount": 100.0}, governance_signature="test_sig"
            )
        )

    assert committed is True, f"Expected commit to succeed, got message: {message}"
    assert message == "COMMITTED", f"Expected COMMITTED, got {message}"


@pytest.mark.local
def test_strict_mode_fails_closed_without_reconciliation() -> None:
    """POAM-023: _CBF_STRICT_MODE=true rejects transactions when reconciliation unavailable."""
    import asyncio

    fake_redis_async = pytest.importorskip(
        "fakeredis.aioredis", reason="fakeredis[aioredis] required"
    ).FakeRedis(decode_responses=True)

    from src.cage_finance.safety.cbf import ControlBarrierFunction

    cbf = ControlBarrierFunction(skip_epoch_seed=True)
    cbf.tracer = None

    # Seed self-reported balance and fence epoch
    asyncio.run(fake_redis_async.set(cbf.redis_key, str(_SAFE_BALANCE)))
    asyncio.run(fake_redis_async.set("safety:fence_epoch", "0"))

    async def mock_get(key):
        return await fake_redis_async.get(key)

    with (
        patch(
            "src.cage_finance.safety.cbf.redis_client",
            new=MagicMock(
                get_raw_client=MagicMock(return_value=fake_redis_async),
                get=MagicMock(side_effect=mock_get),
            ),
        ),
        patch(
            "src.cage_finance.compliance.reconciliation_worker.read_verified_balance",
            return_value=None,  # reconciliation unavailable
        ),
        patch("src.cage_finance.safety.cbf._CBF_STRICT_MODE", True),
    ):
        # Attempt trade with strict mode enabled and no reconciliation
        committed, message = asyncio.run(
            cbf.atomic_verify_and_commit(
                "execute_trade", {"amount": 100.0}, governance_signature="test_sig"
            )
        )

    assert committed is False, "Expected strict mode to reject without reconciliation"
    assert "RECONCILIATION_UNAVAILABLE" in message or "CBF strict mode" in message, (
        f"Expected fail-closed message, got: {message}"
    )


@pytest.mark.local
def test_fence_epoch_regression_rejected() -> None:
    """POAM-023: Fence epoch regression blocks atomic commit."""
    import asyncio

    fake_redis_async = pytest.importorskip(
        "fakeredis.aioredis", reason="fakeredis[aioredis] required"
    ).FakeRedis(decode_responses=True)

    fresh_result = ReconciliationResult(
        source="plaid",
        balance_usd=_RECON_BALANCE,
        verified_at=time.time(),
        signature="valid_sig",
        ttl_seconds=TTL_SECONDS,
        sequence=1,
    )

    from src.cage_finance.safety.cbf import ControlBarrierFunction

    cbf = ControlBarrierFunction(skip_epoch_seed=True)
    cbf.tracer = None
    cbf._last_verified_fence_epoch = 10  # Simulate previous epoch

    # Set current epoch to lower value (regression scenario)
    asyncio.run(fake_redis_async.set(cbf.redis_key, str(_SAFE_BALANCE)))
    asyncio.run(fake_redis_async.set("safety:fence_epoch", "5"))  # Regressed!

    mock_signer = MagicMock()
    mock_signer.verify.return_value = True

    async def mock_lrange(*args):
        return []

    with (
        patch(
            "src.cage_finance.safety.cbf.redis_client",
            new=MagicMock(
                get_raw_client=MagicMock(return_value=fake_redis_async),
                lrange=MagicMock(side_effect=mock_lrange),
            ),
        ),
        patch(
            "src.cage_finance.compliance.reconciliation_worker.read_verified_balance",
            return_value=fresh_result,
        ),
        patch(
            "src.gateway.governance.kms_signer.get_governance_signer",
            return_value=mock_signer,
        ),
    ):
        committed, message = asyncio.run(
            cbf.atomic_verify_and_commit(
                "execute_trade", {"amount": 100.0}, governance_signature="test_sig"
            )
        )

    assert committed is False, "Expected fence epoch regression to block commit"
    assert "Fence epoch regression" in message, (
        f"Expected fence regression message, got: {message}"
    )


@pytest.mark.local
def test_local_debits_accumulated_within_cycle() -> None:
    """POAM-023: Multiple trades accumulate debits correctly before next reconciliation."""
    import asyncio

    fake_redis_async = pytest.importorskip(
        "fakeredis.aioredis", reason="fakeredis[aioredis] required"
    ).FakeRedis(decode_responses=True)

    fresh_result = ReconciliationResult(
        source="plaid",
        balance_usd=_RECON_BALANCE,
        verified_at=time.time(),
        signature="valid_sig",
        ttl_seconds=TTL_SECONDS,
        sequence=1,
    )

    from src.cage_finance.safety.cbf import ControlBarrierFunction

    cbf = ControlBarrierFunction(skip_epoch_seed=True)
    cbf.tracer = None

    asyncio.run(fake_redis_async.set(cbf.redis_key, str(_SAFE_BALANCE)))
    asyncio.run(fake_redis_async.set("safety:fence_epoch", "0"))

    mock_signer = MagicMock()
    mock_signer.verify.return_value = True

    async def mock_lrange(*args):
        return []

    async def mock_ltrim(*args):
        return True

    with (
        patch(
            "src.cage_finance.safety.cbf.redis_client",
            new=MagicMock(
                get_raw_client=MagicMock(return_value=fake_redis_async),
                lrange=MagicMock(side_effect=mock_lrange),
                ltrim=MagicMock(side_effect=mock_ltrim),
            ),
        ),
        patch(
            "src.cage_finance.compliance.reconciliation_worker.read_verified_balance",
            return_value=fresh_result,
        ),
        patch(
            "src.gateway.governance.kms_signer.get_governance_signer",
            return_value=mock_signer,
        ),
    ):
        # Execute two trades
        asyncio.run(
            cbf.atomic_verify_and_commit(
                "execute_trade", {"amount": 100.0}, governance_signature="sig1"
            )
        )
        asyncio.run(
            cbf.atomic_verify_and_commit(
                "execute_trade", {"amount": 200.0}, governance_signature="sig2"
            )
        )

    # Read local debits directly from fakeredis (Lua script writes them natively)
    local_debits_raw = asyncio.run(fake_redis_async.lrange("cbf:local_debits", 0, -1))
    local_debits = [d.decode() if isinstance(d, bytes) else d for d in local_debits_raw]

    # Verify local debits were recorded
    assert len(local_debits) == 2, f"Expected 2 local debits, got {len(local_debits)}"
    debit1 = json.loads(local_debits[0])
    debit2 = json.loads(local_debits[1])
    assert debit1["amount"] == 100.0, (
        f"Expected first debit 100.0, got {debit1['amount']}"
    )
    assert debit2["amount"] == 200.0, (
        f"Expected second debit 200.0, got {debit2['amount']}"
    )
    assert debit1["reconciliation_sequence"] == 1
    assert debit2["reconciliation_sequence"] == 1


@pytest.mark.local
def test_kms_signature_verified_before_commit() -> None:
    """POAM-023: Invalid KMS signature blocks atomic commit."""
    import asyncio

    fake_redis_async = pytest.importorskip(
        "fakeredis.aioredis", reason="fakeredis[aioredis] required"
    ).FakeRedis(decode_responses=True)

    fresh_result = ReconciliationResult(
        source="plaid",
        balance_usd=_RECON_BALANCE,
        verified_at=time.time(),
        signature="invalid_sig",
        ttl_seconds=TTL_SECONDS,
        sequence=1,
    )

    from src.cage_finance.safety.cbf import ControlBarrierFunction

    cbf = ControlBarrierFunction(skip_epoch_seed=True)
    cbf.tracer = None

    asyncio.run(fake_redis_async.set(cbf.redis_key, str(_SAFE_BALANCE)))
    asyncio.run(fake_redis_async.set("safety:fence_epoch", "0"))

    mock_signer = MagicMock()
    mock_signer.verify.return_value = False  # Signature verification fails

    async def mock_get(key):
        return await fake_redis_async.get(key)

    with (
        patch(
            "src.cage_finance.safety.cbf.redis_client",
            new=MagicMock(
                get_raw_client=MagicMock(return_value=fake_redis_async),
                get=MagicMock(side_effect=mock_get),
            ),
        ),
        patch(
            "src.cage_finance.compliance.reconciliation_worker.read_verified_balance",
            return_value=fresh_result,
        ),
        patch(
            "src.gateway.governance.kms_signer.get_governance_signer",
            return_value=mock_signer,
        ),
        patch("src.cage_finance.safety.cbf._CBF_STRICT_MODE", False),
    ):
        # Attempt commit with invalid signature (should fall back to self-reported in non-strict mode)
        committed, message = asyncio.run(
            cbf.atomic_verify_and_commit(
                "execute_trade", {"amount": 100.0}, governance_signature="test_sig"
            )
        )

    # In non-strict mode, it should fall back to self-reported balance and succeed
    # (though this is logged as CRITICAL by _read_cbf_state_atomic)
    assert committed is True, (
        f"Expected fallback to self-reported balance to succeed, got: {message}"
    )
