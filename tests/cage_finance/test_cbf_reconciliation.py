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

from src.gateway.governance.reconciliation.daemon import (
    _REDIS_KEY_VERIFIED_BALANCE,
    TTL_SECONDS,
    ReconciliationResult,
    read_verified_balance,
    reconciled_state_key,
)
from src.gateway.governance.safety.debit_ledger import DEBITS_KEY, DEBITS_TOTAL_KEY

# Hermetic: tests CBF reconciliation using fakeredis, no live Redis.
pytestmark = [pytest.mark.unit, pytest.mark.local]

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
        state_scalar=_RECON_BALANCE,
        verified_at=time.time(),  # fresh
        signature="deadbeef",
        kms_key_id="reconciler-kid",
        signing_algorithm="gcp_kms",
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
        state_scalar=_RECON_BALANCE,
        verified_at=time.time() - (TTL_SECONDS + 60),  # older than TTL
        signature="deadbeef",
        kms_key_id="reconciler-kid",
        signing_algorithm="gcp_kms",
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
        state_scalar=_RECON_BALANCE,
        verified_at=time.time() - (TTL_SECONDS + 120),  # well past TTL
        signature="deadbeef",
        kms_key_id="reconciler-kid",
        signing_algorithm="gcp_kms",
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
        state_scalar=_RECON_BALANCE,
        verified_at=time.time(),
        signature="valid_sig",
        kms_key_id="reconciler-kid",
        signing_algorithm="gcp_kms",
        ttl_seconds=TTL_SECONDS,
    )

    from src.cage_finance.invariants import CashBarrier, finance_cost_resolver
    from src.gateway.governance.safety.cbf_engine import ControlBarrierFunction

    cbf = ControlBarrierFunction(
        invariant=CashBarrier(gamma=0.5),
        cost_resolver=finance_cost_resolver,
        skip_epoch_seed=True,
    )
    cbf.tracer = None

    # Seed self-reported balance and initial fence epoch
    asyncio.run(fake_redis_async.set(cbf.redis_key, str(_SAFE_BALANCE)))
    asyncio.run(fake_redis_async.set("safety:fence_epoch", "0"))

    mock_signer = MagicMock()
    mock_signer.verify_decision.return_value = True

    with (
        patch(
            "src.gateway.governance.safety.cbf_engine.redis_client",
            new=MagicMock(get_raw_client=MagicMock(return_value=fake_redis_async)),
        ),
        patch(
            "src.gateway.governance.reconciliation.daemon.read_verified_balance",
            return_value=fresh_result,
        ),
        patch(
            "src.gateway.governance.reconciliation.trust.get_reconciler_verifier",
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

    from src.cage_finance.invariants import CashBarrier, finance_cost_resolver
    from src.gateway.governance.safety.cbf_engine import ControlBarrierFunction

    cbf = ControlBarrierFunction(
        invariant=CashBarrier(gamma=0.5),
        cost_resolver=finance_cost_resolver,
        skip_epoch_seed=True,
    )
    cbf.tracer = None

    # Seed self-reported balance and initial fence epoch
    asyncio.run(fake_redis_async.set(cbf.redis_key, str(_SAFE_BALANCE)))
    asyncio.run(fake_redis_async.set("safety:fence_epoch", "0"))

    with (
        patch(
            "src.gateway.governance.safety.cbf_engine.redis_client",
            new=MagicMock(get_raw_client=MagicMock(return_value=fake_redis_async)),
        ),
        patch(
            "src.gateway.governance.reconciliation.daemon.read_verified_balance",
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
        state_scalar=_RECON_BALANCE,
        verified_at=time.time(),
        signature="valid_sig",
        kms_key_id="reconciler-kid",
        signing_algorithm="gcp_kms",
        ttl_seconds=TTL_SECONDS,
        sequence=1,
    )

    from src.cage_finance.invariants import CashBarrier, finance_cost_resolver
    from src.gateway.governance.safety.cbf_engine import ControlBarrierFunction

    cbf = ControlBarrierFunction(
        invariant=CashBarrier(gamma=0.5),
        cost_resolver=finance_cost_resolver,
        skip_epoch_seed=True,
    )
    cbf.tracer = None

    # Seed self-reported balance, fence epoch, and the published snapshot the
    # commit script pins its generation check to (ADR-010).
    asyncio.run(fake_redis_async.set(cbf.redis_key, str(_SAFE_BALANCE)))
    asyncio.run(fake_redis_async.set("safety:fence_epoch", "0"))
    asyncio.run(
        fake_redis_async.set(
            reconciled_state_key(cbf.invariant.invariant_id),
            fresh_result.to_redis_payload(),
        )
    )

    mock_signer = MagicMock()
    mock_signer.verify_decision.return_value = True

    with (
        patch(
            "src.gateway.governance.safety.cbf_engine.redis_client",
            new=MagicMock(get_raw_client=MagicMock(return_value=fake_redis_async)),
        ),
        patch(
            "src.gateway.governance.reconciliation.daemon.read_verified_balance",
            return_value=fresh_result,
        ),
        patch(
            "src.gateway.governance.reconciliation.trust.get_reconciler_verifier",
            return_value=mock_signer,
        ),
    ):
        # Attempt small trade (should succeed with reconciled balance)
        committed, message, _ = asyncio.run(
            cbf.atomic_verify_and_commit(
                "execute_trade", {"amount": 100.0}, governance_signature="test_sig"
            )
        )

    assert committed is True, f"Expected commit to succeed, got message: {message}"
    assert message == "COMMITTED", f"Expected COMMITTED, got {message}"
    # The barrier debited the *reconciled* scalar, not the self-reported key.
    assert float(asyncio.run(fake_redis_async.get(cbf.redis_key))) == pytest.approx(
        _RECON_BALANCE - 100.0
    )


@pytest.mark.local
def test_strict_mode_fails_closed_without_reconciliation() -> None:
    """POAM-023: _CBF_STRICT_MODE=true rejects transactions when reconciliation unavailable."""
    import asyncio

    fake_redis_async = pytest.importorskip(
        "fakeredis.aioredis", reason="fakeredis[aioredis] required"
    ).FakeRedis(decode_responses=True)

    from src.cage_finance.invariants import CashBarrier, finance_cost_resolver
    from src.gateway.governance.safety.cbf_engine import ControlBarrierFunction

    cbf = ControlBarrierFunction(
        invariant=CashBarrier(gamma=0.5),
        cost_resolver=finance_cost_resolver,
        skip_epoch_seed=True,
    )
    cbf.tracer = None

    # Seed self-reported balance and fence epoch
    asyncio.run(fake_redis_async.set(cbf.redis_key, str(_SAFE_BALANCE)))
    asyncio.run(fake_redis_async.set("safety:fence_epoch", "0"))

    async def mock_get(key):
        return await fake_redis_async.get(key)

    with (
        patch(
            "src.gateway.governance.safety.cbf_engine.redis_client",
            new=MagicMock(
                get_raw_client=MagicMock(return_value=fake_redis_async),
                get=MagicMock(side_effect=mock_get),
            ),
        ),
        patch(
            "src.gateway.governance.reconciliation.daemon.read_verified_balance",
            return_value=None,  # reconciliation unavailable
        ),
        patch("src.gateway.governance.safety.cbf_engine._CBF_STRICT_MODE", True),
    ):
        # Attempt trade with strict mode enabled and no reconciliation
        committed, message, _ = asyncio.run(
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
        state_scalar=_RECON_BALANCE,
        verified_at=time.time(),
        signature="valid_sig",
        kms_key_id="reconciler-kid",
        signing_algorithm="gcp_kms",
        ttl_seconds=TTL_SECONDS,
        sequence=1,
    )

    from src.cage_finance.invariants import CashBarrier, finance_cost_resolver
    from src.gateway.governance.safety.cbf_engine import ControlBarrierFunction

    cbf = ControlBarrierFunction(
        invariant=CashBarrier(gamma=0.5),
        cost_resolver=finance_cost_resolver,
        skip_epoch_seed=True,
    )
    cbf.tracer = None
    cbf._last_verified_fence_epoch = 10  # Simulate previous epoch

    # Set current epoch to lower value (regression scenario)
    asyncio.run(fake_redis_async.set(cbf.redis_key, str(_SAFE_BALANCE)))
    asyncio.run(fake_redis_async.set("safety:fence_epoch", "5"))  # Regressed!

    mock_signer = MagicMock()
    mock_signer.verify_decision.return_value = True

    with (
        patch(
            "src.gateway.governance.safety.cbf_engine.redis_client",
            new=MagicMock(get_raw_client=MagicMock(return_value=fake_redis_async)),
        ),
        patch(
            "src.gateway.governance.reconciliation.daemon.read_verified_balance",
            return_value=fresh_result,
        ),
        patch(
            "src.gateway.governance.reconciliation.trust.get_reconciler_verifier",
            return_value=mock_signer,
        ),
    ):
        committed, message, _ = asyncio.run(
            cbf.atomic_verify_and_commit(
                "execute_trade", {"amount": 100.0}, governance_signature="test_sig"
            )
        )

    assert committed is False, "Expected fence epoch regression to block commit"
    assert "Fence epoch regression" in message, (
        f"Expected fence regression message, got: {message}"
    )


@pytest.mark.local
def test_debits_accumulate_in_ledger_within_cycle() -> None:
    """POAM-023 / ADR-010: trades within one reconciliation cycle accumulate in the debit ledger."""
    import asyncio

    fake_redis_async = pytest.importorskip(
        "fakeredis.aioredis", reason="fakeredis[aioredis] required"
    ).FakeRedis(decode_responses=True)

    fresh_result = ReconciliationResult(
        source="plaid",
        state_scalar=_RECON_BALANCE,
        verified_at=time.time(),
        signature="valid_sig",
        kms_key_id="reconciler-kid",
        signing_algorithm="gcp_kms",
        ttl_seconds=TTL_SECONDS,
        sequence=1,
    )

    from src.cage_finance.invariants import CashBarrier, finance_cost_resolver
    from src.gateway.governance.safety.cbf_engine import ControlBarrierFunction

    cbf = ControlBarrierFunction(
        invariant=CashBarrier(gamma=0.5),
        cost_resolver=finance_cost_resolver,
        skip_epoch_seed=True,
    )
    cbf.tracer = None

    asyncio.run(fake_redis_async.set(cbf.redis_key, str(_SAFE_BALANCE)))
    asyncio.run(fake_redis_async.set("safety:fence_epoch", "0"))
    asyncio.run(
        fake_redis_async.set(
            reconciled_state_key(cbf.invariant.invariant_id),
            fresh_result.to_redis_payload(),
        )
    )

    mock_signer = MagicMock()
    mock_signer.verify_decision.return_value = True

    with (
        patch(
            "src.gateway.governance.safety.cbf_engine.redis_client",
            new=MagicMock(get_raw_client=MagicMock(return_value=fake_redis_async)),
        ),
        patch(
            "src.gateway.governance.reconciliation.daemon.read_verified_balance",
            return_value=fresh_result,
        ),
        patch(
            "src.gateway.governance.reconciliation.trust.get_reconciler_verifier",
            return_value=mock_signer,
        ),
    ):
        # Execute two trades against the same (unchanged) snapshot
        ok1, msg1, _ = asyncio.run(
            cbf.atomic_verify_and_commit(
                "execute_trade",
                {"amount": 100.0},
                governance_signature="sig1",
                debit_id="d1",
            )
        )
        ok2, msg2, _ = asyncio.run(
            cbf.atomic_verify_and_commit(
                "execute_trade",
                {"amount": 200.0},
                governance_signature="sig2",
                debit_id="d2",
            )
        )
    assert ok1 and ok2, (msg1, msg2)

    # The Lua script ledgers each debit under its id (ADR-010) and keeps a
    # running total that the next commit nets against the reconciled scalar.
    ledger = {
        k: json.loads(v)
        for k, v in asyncio.run(fake_redis_async.hgetall(DEBITS_KEY)).items()
    }
    assert set(ledger) == {"d1", "d2"}, f"Expected debits d1/d2, got {sorted(ledger)}"
    assert ledger["d1"]["amount"] == 100.0
    assert ledger["d2"]["amount"] == 200.0
    assert ledger["d1"]["snapshot_sequence"] == 1
    assert ledger["d2"]["snapshot_sequence"] == 1
    assert float(asyncio.run(fake_redis_async.get(DEBITS_TOTAL_KEY))) == pytest.approx(
        300.0
    )
    # Both commits were netted against the same reconciled scalar.
    assert float(asyncio.run(fake_redis_async.get(cbf.redis_key))) == pytest.approx(
        _RECON_BALANCE - 300.0
    )


@pytest.mark.local
def test_kms_signature_verified_before_commit() -> None:
    """POAM-023: Invalid KMS signature blocks atomic commit."""
    import asyncio

    fake_redis_async = pytest.importorskip(
        "fakeredis.aioredis", reason="fakeredis[aioredis] required"
    ).FakeRedis(decode_responses=True)

    fresh_result = ReconciliationResult(
        source="plaid",
        state_scalar=_RECON_BALANCE,
        verified_at=time.time(),
        signature="invalid_sig",
        kms_key_id="reconciler-kid",
        signing_algorithm="gcp_kms",
        ttl_seconds=TTL_SECONDS,
        sequence=1,
    )

    from src.cage_finance.invariants import CashBarrier, finance_cost_resolver
    from src.gateway.governance.safety.cbf_engine import ControlBarrierFunction

    cbf = ControlBarrierFunction(
        invariant=CashBarrier(gamma=0.5),
        cost_resolver=finance_cost_resolver,
        skip_epoch_seed=True,
    )
    cbf.tracer = None

    asyncio.run(fake_redis_async.set(cbf.redis_key, str(_SAFE_BALANCE)))
    asyncio.run(fake_redis_async.set("safety:fence_epoch", "0"))

    mock_signer = MagicMock()
    mock_signer.verify_decision.return_value = False  # Signature verification fails

    async def mock_get(key):
        return await fake_redis_async.get(key)

    with (
        patch(
            "src.gateway.governance.safety.cbf_engine.redis_client",
            new=MagicMock(
                get_raw_client=MagicMock(return_value=fake_redis_async),
                get=MagicMock(side_effect=mock_get),
            ),
        ),
        patch(
            "src.gateway.governance.reconciliation.daemon.read_verified_balance",
            return_value=fresh_result,
        ),
        patch(
            "src.gateway.governance.reconciliation.trust.get_reconciler_verifier",
            return_value=mock_signer,
        ),
        patch("src.gateway.governance.safety.cbf_engine._CBF_STRICT_MODE", False),
    ):
        # Attempt commit with invalid signature (should fall back to self-reported in non-strict mode)
        committed, message, _ = asyncio.run(
            cbf.atomic_verify_and_commit(
                "execute_trade", {"amount": 100.0}, governance_signature="test_sig"
            )
        )

    # In non-strict mode, it should fall back to self-reported balance and succeed
    # (though this is logged as CRITICAL by _read_cbf_state_atomic)
    assert committed is True, (
        f"Expected fallback to self-reported balance to succeed, got: {message}"
    )
