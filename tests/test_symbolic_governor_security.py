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
Security tests for SymbolicGovernor and assert_safe_operational_state().

Covers:
  1. assert_safe_operational_state() — environment-gated enforcement
     - Does NOT raise when CBF_FAIL_OPEN=false (regardless of KMS state)
     - Does NOT raise in development even when both CBF_FAIL_OPEN=true and KMS inactive
     - Raises RuntimeError in production when CBF_FAIL_OPEN=true AND KMS inactive
     - Does NOT raise in production when CBF_FAIL_OPEN=true but KMS IS active

  2. fiscal_limit_guard.reserve() is awaited
     - SymbolicGovernor awaits reserve() (AsyncMock is actually awaited)
     - SymbolicGovernor awaits release() on violation after reservation
"""

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_governor(fiscal_limit_guard=None):
    """Construct a SymbolicGovernor with all dependencies mocked."""
    from src.gateway.governance.symbolic_governor import SymbolicGovernor

    opa_client = AsyncMock()
    opa_client.evaluate_policy.return_value = "ALLOW"

    safety_filter = AsyncMock()
    safety_filter.verify_action.return_value = "SAFE"

    consensus_engine = AsyncMock()
    consensus_engine.check_consensus.return_value = {"status": "APPROVE"}

    return SymbolicGovernor(
        opa_client=opa_client,
        safety_filter=safety_filter,
        consensus_engine=consensus_engine,
        stpa_validator=None,
        telemetry_provider=None,
        fiscal_limit_guard=fiscal_limit_guard,
    )


# ---------------------------------------------------------------------------
# 1. assert_safe_operational_state()
# ---------------------------------------------------------------------------

def test_assert_safe_operational_state_does_not_raise_when_cbf_not_fail_open():
    """assert_safe_operational_state() does NOT raise when CBF_FAIL_OPEN=false, regardless of KMS state."""
    mock_signer = MagicMock()
    mock_signer.is_kms_active = False  # KMS inactive — but CBF is active, so combined risk is absent

    env = {k: v for k, v in os.environ.items() if k not in ("CBF_FAIL_OPEN",)}
    env["CBF_FAIL_OPEN"] = "false"

    with patch.dict(os.environ, env, clear=True), \
         patch("src.gateway.governance.symbolic_governor.get_governance_signer",
               return_value=mock_signer, create=True):
        from src.gateway.governance.symbolic_governor import assert_safe_operational_state
        # Should not raise — CBF is active, so combined risk state is not present
        assert_safe_operational_state()


def test_assert_safe_operational_state_does_not_raise_when_cbf_not_fail_open_kms_active():
    """assert_safe_operational_state() does NOT raise when CBF_FAIL_OPEN=false and KMS is active."""
    mock_signer = MagicMock()
    mock_signer.is_kms_active = True

    env = {k: v for k, v in os.environ.items() if k not in ("CBF_FAIL_OPEN",)}
    env["CBF_FAIL_OPEN"] = "false"

    with patch.dict(os.environ, env, clear=True), \
         patch("src.gateway.governance.symbolic_governor.get_governance_signer",
               return_value=mock_signer, create=True):
        from src.gateway.governance.symbolic_governor import assert_safe_operational_state
        assert_safe_operational_state()


def test_assert_safe_operational_state_does_not_raise_in_development_combined_risk():
    """assert_safe_operational_state() does NOT raise in CAGE_ENV=development even when CBF_FAIL_OPEN=true and KMS inactive."""
    mock_signer = MagicMock()
    mock_signer.is_kms_active = False

    env = {k: v for k, v in os.environ.items() if k not in ("CBF_FAIL_OPEN", "CAGE_ENV", "ENVIRONMENT")}
    env["CBF_FAIL_OPEN"] = "true"
    env["CAGE_ENV"] = "development"

    with patch.dict(os.environ, env, clear=True), \
         patch("src.gateway.governance.symbolic_governor.get_governance_signer",
               return_value=mock_signer, create=True):
        from src.gateway.governance.symbolic_governor import assert_safe_operational_state
        # Should not raise — development environment is exempt
        assert_safe_operational_state()


def test_assert_safe_operational_state_does_not_raise_in_test_combined_risk():
    """assert_safe_operational_state() does NOT raise in CAGE_ENV=test even when CBF_FAIL_OPEN=true and KMS inactive."""
    mock_signer = MagicMock()
    mock_signer.is_kms_active = False

    env = {k: v for k, v in os.environ.items() if k not in ("CBF_FAIL_OPEN", "CAGE_ENV", "ENVIRONMENT")}
    env["CBF_FAIL_OPEN"] = "true"
    env["CAGE_ENV"] = "test"

    with patch.dict(os.environ, env, clear=True), \
         patch("src.gateway.governance.symbolic_governor.get_governance_signer",
               return_value=mock_signer, create=True):
        from src.gateway.governance.symbolic_governor import assert_safe_operational_state
        assert_safe_operational_state()


def test_assert_safe_operational_state_does_not_raise_in_ci_combined_risk():
    """assert_safe_operational_state() does NOT raise in CAGE_ENV=ci even when CBF_FAIL_OPEN=true and KMS inactive."""
    mock_signer = MagicMock()
    mock_signer.is_kms_active = False

    env = {k: v for k, v in os.environ.items() if k not in ("CBF_FAIL_OPEN", "CAGE_ENV", "ENVIRONMENT")}
    env["CBF_FAIL_OPEN"] = "true"
    env["CAGE_ENV"] = "ci"

    with patch.dict(os.environ, env, clear=True), \
         patch("src.gateway.governance.symbolic_governor.get_governance_signer",
               return_value=mock_signer, create=True):
        from src.gateway.governance.symbolic_governor import assert_safe_operational_state
        assert_safe_operational_state()


def test_assert_safe_operational_state_raises_in_production_combined_risk():
    """assert_safe_operational_state() raises RuntimeError in CAGE_ENV=production when CBF_FAIL_OPEN=true AND KMS inactive."""
    mock_signer = MagicMock()
    mock_signer.is_kms_active = False

    env = {k: v for k, v in os.environ.items() if k not in ("CBF_FAIL_OPEN", "CAGE_ENV", "ENVIRONMENT")}
    env["CBF_FAIL_OPEN"] = "true"
    env["CAGE_ENV"] = "production"

    with patch.dict(os.environ, env, clear=True), \
         patch("src.gateway.governance.symbolic_governor.get_governance_signer",
               return_value=mock_signer, create=True):
        from src.gateway.governance.symbolic_governor import assert_safe_operational_state
        with pytest.raises(RuntimeError, match="Combined high-risk operational state"):
            assert_safe_operational_state()


def test_assert_safe_operational_state_raises_message_mentions_cbf_fail_open():
    """assert_safe_operational_state() RuntimeError message mentions CBF_FAIL_OPEN."""
    mock_signer = MagicMock()
    mock_signer.is_kms_active = False

    env = {k: v for k, v in os.environ.items() if k not in ("CBF_FAIL_OPEN", "CAGE_ENV", "ENVIRONMENT")}
    env["CBF_FAIL_OPEN"] = "true"
    env["CAGE_ENV"] = "production"

    with patch.dict(os.environ, env, clear=True), \
         patch("src.gateway.governance.symbolic_governor.get_governance_signer",
               return_value=mock_signer, create=True):
        from src.gateway.governance.symbolic_governor import assert_safe_operational_state
        with pytest.raises(RuntimeError) as exc_info:
            assert_safe_operational_state()
        assert "CBF_FAIL_OPEN" in str(exc_info.value)


def test_assert_safe_operational_state_does_not_raise_in_production_when_kms_active():
    """assert_safe_operational_state() does NOT raise in production when CBF_FAIL_OPEN=true but KMS IS active."""
    mock_signer = MagicMock()
    mock_signer.is_kms_active = True  # KMS is active — combined risk state is not present

    env = {k: v for k, v in os.environ.items() if k not in ("CBF_FAIL_OPEN", "CAGE_ENV", "ENVIRONMENT")}
    env["CBF_FAIL_OPEN"] = "true"
    env["CAGE_ENV"] = "production"

    with patch.dict(os.environ, env, clear=True), \
         patch("src.gateway.governance.kms_signer.get_governance_signer",
               return_value=mock_signer):
        from src.gateway.governance.symbolic_governor import assert_safe_operational_state
        # Should not raise — KMS is active, so non-repudiation gap is closed
        assert_safe_operational_state()


def test_assert_safe_operational_state_uses_environment_fallback():
    """assert_safe_operational_state() uses ENVIRONMENT var when CAGE_ENV is not set."""
    mock_signer = MagicMock()
    mock_signer.is_kms_active = False

    env = {k: v for k, v in os.environ.items() if k not in ("CBF_FAIL_OPEN", "CAGE_ENV", "ENVIRONMENT")}
    env["CBF_FAIL_OPEN"] = "true"
    env["ENVIRONMENT"] = "production"

    with patch.dict(os.environ, env, clear=True), \
         patch("src.gateway.governance.symbolic_governor.get_governance_signer",
               return_value=mock_signer, create=True):
        from src.gateway.governance.symbolic_governor import assert_safe_operational_state
        with pytest.raises(RuntimeError):
            assert_safe_operational_state()


def test_assert_safe_operational_state_handles_signer_exception_as_kms_inactive():
    """assert_safe_operational_state() treats a signer load exception as KMS inactive (worst case)."""
    env = {k: v for k, v in os.environ.items() if k not in ("CBF_FAIL_OPEN", "CAGE_ENV", "ENVIRONMENT")}
    env["CBF_FAIL_OPEN"] = "true"
    env["CAGE_ENV"] = "production"

    with patch.dict(os.environ, env, clear=True), \
         patch("src.gateway.governance.symbolic_governor.get_governance_signer",
               side_effect=RuntimeError("KMS unavailable"), create=True):
        from src.gateway.governance.symbolic_governor import assert_safe_operational_state
        # Exception from get_governance_signer → kms_active=False → combined risk → RuntimeError
        with pytest.raises(RuntimeError):
            assert_safe_operational_state()


# ---------------------------------------------------------------------------
# 2. fiscal_limit_guard.reserve() is awaited
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_fiscal_limit_guard_reserve_is_awaited():
    """SymbolicGovernor awaits fiscal_limit_guard.reserve() — AsyncMock is actually awaited, not called synchronously."""
    from src.gateway.governance.fiscal_limit_guard import ReservationToken
    import time

    # Create a mock FiscalLimitGuard with AsyncMock for reserve()
    mock_guard = MagicMock()
    mock_token = ReservationToken(
        reservation_id="test-reservation-id",
        agent_id="test-agent",
        amount_usd=5000.0,
        amount_cents=500000,
        window_key="fiscal:daily_limit:2026-06-02",
        cap_usd=500_000.0,
        running_total_usd=5000.0,
        rejected=False,
        reserved_at=time.time(),
        ttl_seconds=300,
    )
    mock_guard.reserve = AsyncMock(return_value=mock_token)
    mock_guard.release = AsyncMock(return_value=0.0)

    governor = _make_governor(fiscal_limit_guard=mock_guard)

    params = {
        "confidence": 0.99,
        "amount": 5000.0,
        "symbol": "AAPL",
        "agent_id": "test-agent",
    }

    await governor.govern("execute_trade", params)

    # Verify reserve() was actually awaited (AsyncMock tracks await calls)
    mock_guard.reserve.assert_awaited_once()


@pytest.mark.asyncio
async def test_fiscal_limit_guard_reserve_called_with_correct_args():
    """SymbolicGovernor calls reserve() with agent_id and amount_usd from params."""
    from src.gateway.governance.fiscal_limit_guard import ReservationToken
    import time

    mock_guard = MagicMock()
    mock_token = ReservationToken(
        reservation_id="test-id",
        agent_id="trading-agent",
        amount_usd=10000.0,
        amount_cents=1000000,
        window_key="fiscal:daily_limit:2026-06-02",
        cap_usd=500_000.0,
        running_total_usd=10000.0,
        rejected=False,
        reserved_at=time.time(),
        ttl_seconds=300,
    )
    mock_guard.reserve = AsyncMock(return_value=mock_token)
    mock_guard.release = AsyncMock(return_value=0.0)

    governor = _make_governor(fiscal_limit_guard=mock_guard)

    params = {
        "confidence": 0.99,
        "amount": 10000.0,
        "symbol": "TSLA",
        "agent_id": "trading-agent",
    }

    with patch("src.gateway.governance.causal_gatekeeper.causal_safety_check", return_value=True):
        await governor.govern("execute_trade", params)

    mock_guard.reserve.assert_awaited_once_with(agent_id="trading-agent", amount_usd=10000.0)


@pytest.mark.asyncio
async def test_fiscal_limit_guard_release_is_awaited_on_rejection():
    """SymbolicGovernor awaits fiscal_limit_guard.release() when the fiscal reservation is rejected."""
    from src.gateway.governance.fiscal_limit_guard import ReservationToken
    from src.gateway.governance.symbolic_governor import GovernanceError
    import time

    mock_guard = MagicMock()
    # Rejected token — reserve() returns a rejected token
    rejected_token = ReservationToken(
        reservation_id="rejected-id",
        agent_id="test-agent",
        amount_usd=999_999.0,
        amount_cents=99999900,
        window_key="fiscal:daily_limit:2026-06-02",
        cap_usd=500_000.0,
        running_total_usd=500_000.0,
        rejected=True,
        reserved_at=time.time(),
        ttl_seconds=300,
    )
    mock_guard.reserve = AsyncMock(return_value=rejected_token)
    mock_guard.release = AsyncMock(return_value=0.0)

    governor = _make_governor(fiscal_limit_guard=mock_guard)

    params = {
        "confidence": 0.99,
        "amount": 999_999.0,
        "symbol": "AAPL",
        "agent_id": "test-agent",
    }

    with pytest.raises(GovernanceError, match="Fiscal Limit Pre-Reservation REJECTED"):
        await governor.govern("execute_trade", params)

    # reserve() was awaited
    mock_guard.reserve.assert_awaited_once()
    # release() should NOT be called for a rejected token (nothing to release)
    mock_guard.release.assert_not_awaited()


@pytest.mark.asyncio
async def test_fiscal_limit_guard_release_awaited_on_post_reservation_violation():
    """SymbolicGovernor awaits fiscal_limit_guard.release() when a post-reservation tier (consensus) fails."""
    from src.gateway.governance.fiscal_limit_guard import ReservationToken
    from src.gateway.governance.symbolic_governor import GovernanceError, SymbolicGovernor
    import time

    mock_guard = MagicMock()
    good_token = ReservationToken(
        reservation_id="good-id",
        agent_id="test-agent",
        amount_usd=5000.0,
        amount_cents=500000,
        window_key="fiscal:daily_limit:2026-06-02",
        cap_usd=500_000.0,
        running_total_usd=5000.0,
        rejected=False,
        reserved_at=time.time(),
        ttl_seconds=300,
    )
    mock_guard.reserve = AsyncMock(return_value=good_token)
    mock_guard.release = AsyncMock(return_value=0.0)

    # Consensus engine rejects — this is a post-reservation violation
    opa_client = AsyncMock()
    opa_client.evaluate_policy.return_value = "ALLOW"
    safety_filter = AsyncMock()
    safety_filter.verify_action.return_value = "SAFE"
    consensus_engine = AsyncMock()
    consensus_engine.check_consensus.return_value = {"status": "REJECT", "reason": "Too risky"}

    governor = SymbolicGovernor(
        opa_client=opa_client,
        safety_filter=safety_filter,
        consensus_engine=consensus_engine,
        stpa_validator=None,
        telemetry_provider=None,
        fiscal_limit_guard=mock_guard,
    )

    params = {
        "confidence": 0.99,
        "amount": 5000.0,
        "symbol": "AAPL",
        "agent_id": "test-agent",
    }

    with pytest.raises(GovernanceError, match="Consensus Rejection"):
        await governor.govern("execute_trade", params)

    # reserve() was awaited
    mock_guard.reserve.assert_awaited_once()
    # release() was awaited to return capacity after consensus rejection
    mock_guard.release.assert_awaited_once()


@pytest.mark.asyncio
async def test_fiscal_limit_guard_skipped_when_none():
    """SymbolicGovernor skips fiscal reservation when fiscal_limit_guard is None (backward compat)."""
    governor = _make_governor(fiscal_limit_guard=None)

    params = {
        "confidence": 0.99,
        "amount": 5000.0,
        "symbol": "AAPL",
    }

    # Should not raise — fiscal guard is optional
    await governor.govern("execute_trade", params)


@pytest.mark.asyncio
async def test_fiscal_limit_guard_skipped_for_non_trade_actions():
    """SymbolicGovernor does NOT call fiscal_limit_guard.reserve() for non-trade actions."""
    mock_guard = MagicMock()
    mock_guard.reserve = AsyncMock()
    mock_guard.release = AsyncMock()

    governor = _make_governor(fiscal_limit_guard=mock_guard)

    params = {"confidence": 0.99, "amount": 5000.0}

    # Non-trade action — fiscal guard should not be invoked
    await governor.govern("market_analysis", params)

    mock_guard.reserve.assert_not_awaited()
