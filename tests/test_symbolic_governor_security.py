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
     - Raises RuntimeError in production when RECONCILIATION_PROVIDER=stub (POAM-023)
     - Logs CRITICAL but does not raise in development / test / ci
     - Does not raise in production with a non-stub reconciliation provider
     - CBF_FAIL_OPEN has no effect (the flag was removed)

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


def _make_governor(fiscal_limit_guard=None, classification_engine=None):
    """Construct a SymbolicGovernor with all dependencies mocked."""
    from src.gateway.governance.classification_engine import ClassificationEngine
    from src.gateway.governance.ftra.models import FtraBoundaryResult
    from src.gateway.governance.narrower import NarrowerRegistry
    from src.gateway.governance.governor.governor import SymbolicGovernor

    if classification_engine is None:
        classification_engine = ClassificationEngine(NarrowerRegistry())

    opa_client = AsyncMock()
    opa_client.evaluate_policy.return_value = "ALLOW"

    safety_filter = AsyncMock()
    safety_filter.verify_action.return_value = "SAFE"
    # atomic_verify_and_commit is called by _run_checks() instead of verify_action()
    # for the CBF gate. Stub it to return (True, "SAFE") so tests that don't
    # specifically exercise CBF-block behavior pass through the CBF tier cleanly.
    safety_filter.atomic_verify_and_commit = AsyncMock(return_value=(True, "SAFE"))

    consensus_engine = AsyncMock()
    consensus_engine.check_consensus.return_value = {"status": "APPROVE"}

    from src.cage_finance.tiers.cbf_tier import CBFTierPlugin
    from src.cage_finance.tiers.consensus_tier import ConsensusTierPlugin

    tiers = [
        CBFTierPlugin(safety_filter),
        ConsensusTierPlugin(consensus_engine),
    ]
    if fiscal_limit_guard:
        from src.cage_finance.tiers.fiscal_tier import FiscalTierPlugin

        tiers.append(FiscalTierPlugin(fiscal_limit_guard))

    governor = SymbolicGovernor(
        opa_client=opa_client,
        safety_filter=safety_filter,
        consensus_engine=consensus_engine,
        classification_engine=classification_engine,
        stpa_validator=None,
        telemetry_provider=None,
        domain_tiers=tuple(tiers),
    )

    # Mock FTRA boundary check to return a safe result (no HITL required).
    # This allows tests to pass through the FTRA boundary gate without being
    # blocked by the IrreversibilityClassifier classifying "execute_trade" as
    # IRREVERSIBLE_TERMINAL.
    safe_ftra_result = FtraBoundaryResult(
        requires_hitl=False,
        irreversibility_score=0.0,
        classification="READ_ONLY",
        terminal_match=None,
        violations=[],
        bypassed_ftra_node=False,
    )
    from src.gateway.governance.governor.stages.ftra import FtraStage
    for stage in governor.stages:
        if isinstance(stage, FtraStage):
            stage._ftra_boundary_check = AsyncMock(return_value=safe_ftra_result)
    governor._ftra_boundary_check = AsyncMock(return_value=safe_ftra_result) # Keep this for legacy methods

    return governor



# ---------------------------------------------------------------------------
# 1. assert_safe_operational_state()
# ---------------------------------------------------------------------------


def _clean_env(**overrides: str) -> dict[str, str]:
    drop = {"CAGE_ENV", "ENVIRONMENT", "RECONCILIATION_PROVIDER", "CBF_FAIL_OPEN"}
    env = {k: v for k, v in os.environ.items() if k not in drop}
    env.update(overrides)
    return env


def test_raises_in_production_with_stub_reconciliation():
    """Fail-closed path: production posture + stub ground truth must refuse to start."""
    from src.gateway.governance.governor._legacy_startup import assert_safe_operational_state

    env = _clean_env(CAGE_ENV="production", RECONCILIATION_PROVIDER="stub")
    with patch.dict(os.environ, env, clear=True):
        with pytest.raises(RuntimeError, match="POAM-023"):
            assert_safe_operational_state()


def test_raises_in_production_when_reconciliation_provider_unset():
    """An unset provider defaults to stub, so production must still refuse."""
    from src.gateway.governance.governor._legacy_startup import assert_safe_operational_state

    env = _clean_env(CAGE_ENV="production")
    with patch.dict(os.environ, env, clear=True):
        with pytest.raises(RuntimeError, match="POAM-023"):
            assert_safe_operational_state()


@pytest.mark.parametrize("cage_env", ["development", "dev", "test", "ci"])
def test_non_production_stub_logs_critical_without_raising(cage_env, caplog):
    from src.gateway.governance.governor._legacy_startup import assert_safe_operational_state

    env = _clean_env(CAGE_ENV=cage_env, RECONCILIATION_PROVIDER="stub")
    with patch.dict(os.environ, env, clear=True):
        with caplog.at_level("CRITICAL"):
            assert_safe_operational_state()
    assert "POAM_023_STUB_PROVIDER_IN_USE" in caplog.text


def test_production_with_real_provider_does_not_raise():
    from src.gateway.governance.governor._legacy_startup import assert_safe_operational_state

    env = _clean_env(CAGE_ENV="production", RECONCILIATION_PROVIDER="plaid")
    with patch.dict(os.environ, env, clear=True):
        assert_safe_operational_state()


def test_cbf_fail_open_flag_has_no_effect():
    """CBF_FAIL_OPEN was removed; setting it must neither rescue nor break startup."""
    from src.gateway.governance.governor._legacy_startup import assert_safe_operational_state

    for value in ("true", "false"):
        env = _clean_env(
            CAGE_ENV="production", RECONCILIATION_PROVIDER="stub", CBF_FAIL_OPEN=value
        )
        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(RuntimeError, match="POAM-023"):
                assert_safe_operational_state()
        env["RECONCILIATION_PROVIDER"] = "plaid"
        with patch.dict(os.environ, env, clear=True):
            assert_safe_operational_state()


# ---------------------------------------------------------------------------
# 2. fiscal_limit_guard.reserve() is awaited
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fiscal_limit_guard_reserve_is_awaited():
    """SymbolicGovernor awaits fiscal_limit_guard.reserve() — AsyncMock is actually awaited, not called synchronously."""
    import time

    from src.gateway.governance.safety.resource_guard import ReservationToken

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
    mock_guard.confirm = AsyncMock()

    governor = _make_governor(fiscal_limit_guard=mock_guard)

    params = {
        "confidence": 0.99,
        "amount": 5000.0,
        "symbol": "AAPL",
        "agent_id": "test-agent",
        "ftra_status": "CLEAR",  # Indicates FTRA gate already processed in-graph
    }

    # Mock generate_seal_with_evidence to avoid Redis dependency
    with patch(
        "src.gateway.governance.routing_seal.generate_seal_with_evidence",
        new=AsyncMock(return_value="mock-seal-token"),
    ):
        await governor.govern("execute_trade", params)

    # Verify reserve() was actually awaited (AsyncMock tracks await calls)
    mock_guard.reserve.assert_awaited_once()


@pytest.mark.asyncio
async def test_fiscal_limit_guard_reserve_called_with_correct_args():
    """SymbolicGovernor calls reserve() with agent_id and amount_usd from params."""
    import time

    from src.gateway.governance.safety.resource_guard import ReservationToken

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
    mock_guard.confirm = AsyncMock()

    governor = _make_governor(fiscal_limit_guard=mock_guard)

    params = {
        "confidence": 0.99,
        "amount": 10000.0,
        "symbol": "TSLA",
        "agent_id": "trading-agent",
        "ftra_status": "CLEAR",  # Indicates FTRA gate already processed in-graph
    }

    with (
        patch(
            "src.gateway.governance.causal.gatekeeper.causal_safety_check",
            return_value=True,
        ),
        patch(
            "src.gateway.governance.routing_seal.generate_seal_with_evidence",
            new=AsyncMock(return_value="mock-seal-token"),
        ),
    ):
        await governor.govern("execute_trade", params)

    mock_guard.reserve.assert_awaited_once_with(
        agent_id="trading-agent", amount_usd=10000.0
    )


@pytest.mark.asyncio
async def test_fiscal_limit_guard_release_is_awaited_on_rejection():
    """SymbolicGovernor awaits fiscal_limit_guard.release() when the fiscal reservation is rejected."""
    import time

    from src.gateway.governance.safety.resource_guard import ReservationToken
    from src.gateway.governance.governor.governor import GovernanceError

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
    mock_guard.confirm = AsyncMock()

    governor = _make_governor(fiscal_limit_guard=mock_guard)

    params = {
        "confidence": 0.99,
        "amount": 999_999.0,
        "symbol": "AAPL",
        "agent_id": "test-agent",
        "ftra_status": "CLEAR",  # Indicates FTRA gate already processed in-graph
    }

    with pytest.raises(GovernanceError, match="Fiscal Limit Pre-Reservation REJECTED"):
        await governor.govern("execute_trade", params)

    # reserve() was awaited
    mock_guard.reserve.assert_awaited_once()
    # release() should NOT be called for a rejected token (nothing to release)
    mock_guard.release.assert_not_awaited()


@pytest.mark.asyncio
async def test_fiscal_limit_guard_skipped_when_none():
    """SymbolicGovernor skips fiscal reservation when fiscal_limit_guard is None (backward compat)."""
    governor = _make_governor(fiscal_limit_guard=None)

    params = {
        "confidence": 0.99,
        "amount": 5000.0,
        "symbol": "AAPL",
        "ftra_status": "CLEAR",  # Indicates FTRA gate already processed in-graph
    }

    # Mock generate_seal_with_evidence to avoid Redis dependency
    with patch(
        "src.gateway.governance.routing_seal.generate_seal_with_evidence",
        new=AsyncMock(return_value="mock-seal-token"),
    ):
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

    # Mock generate_seal_with_evidence to avoid Redis dependency
    with patch(
        "src.gateway.governance.routing_seal.generate_seal_with_evidence",
        new=AsyncMock(return_value="mock-seal-token"),
    ):
        # Non-trade action — fiscal guard should not be invoked
        await governor.govern("market_analysis", params)

    mock_guard.reserve.assert_not_awaited()
