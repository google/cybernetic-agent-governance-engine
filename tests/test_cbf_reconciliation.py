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

Tests verify the CBF read-path priority logic introduced in Phase 1b/1c/1d:
  1. CBF uses reconciled balance when available and KMS signature is valid
  2. CBF falls back to self-reported when reconciled balance is absent (TTL expired)
  3. CBF falls back to self-reported when KMS signature is invalid (CRITICAL log emitted)
  4. CBF falls back to self-reported when reconciled balance is unsigned in production
  5. OTel span has safety.balance.source="reconciled" when reconciled path taken
  6. OTel span has safety.balance.source="self_reported" when fallback path taken

All tests run without live Redis (fakeredis) or live KMS (mocked).
"""

from __future__ import annotations

import json
import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

pytest.importorskip("fakeredis", reason="fakeredis required for CBF reconciliation tests")

import fakeredis.aioredis  # type: ignore[import]

from src.compliance_bridge.reconciliation_worker import ReconciliationResult

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SAFE_BALANCE = 95_000.0   # above min_cash_balance (default 10_000)
_RECON_BALANCE = 92_000.0  # externally reconciled balance


def _make_result(
    balance: float = _RECON_BALANCE,
    signature: str = "deadbeef",
    source: str = "plaid",
    age_seconds: float = 0.0,
) -> ReconciliationResult:
    """Build a ReconciliationResult with controllable freshness."""
    return ReconciliationResult(
        source=source,
        balance_usd=balance,
        verified_at=time.time() - age_seconds,
        signature=signature,
        ttl_seconds=300,
    )


class _FakeSpan:
    """Minimal OTel span stub that records set_attribute calls."""

    def __init__(self) -> None:
        self.attrs: dict[str, Any] = {}

    def set_attribute(self, key: str, value: Any) -> None:
        self.attrs[key] = value

    def record_exception(self, exc: Exception) -> None:  # noqa: ARG002
        pass


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
async def fake_redis() -> fakeredis.aioredis.FakeRedis:
    """Fresh in-memory async fakeredis instance per test."""
    return fakeredis.aioredis.FakeRedis(decode_responses=True)


@pytest.fixture
def cbf(fake_redis: fakeredis.aioredis.FakeRedis):
    """ControlBarrierFunction with fakeredis injected via module-level singleton patch."""
    from src.gateway.governance.cbf import ControlBarrierFunction

    cbf_instance = ControlBarrierFunction()
    cbf_instance.tracer = None  # disable tracing by default; tests inject spans manually

    # Seed the self-reported balance key so fallback path has a value
    import asyncio
    asyncio.get_event_loop().run_until_complete(
        fake_redis.set(cbf_instance.redis_key, str(_SAFE_BALANCE))
    )

    return cbf_instance


# ---------------------------------------------------------------------------
# Test 1: CBF uses reconciled balance when available and signature is valid
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cbf_uses_reconciled_balance_when_signature_valid(
    cbf, fake_redis: fakeredis.aioredis.FakeRedis
) -> None:
    """CBF returns source='reconciled' when read_verified_balance returns a signed result."""
    result = _make_result(balance=_RECON_BALANCE, signature="valid_sig")

    mock_signer = MagicMock()
    mock_signer.verify.return_value = True

    with (
        patch(
            "src.gateway.governance.cbf.redis_client",
            new=MagicMock(_get=MagicMock(return_value=fake_redis)),
        ),
        patch(
            "src.compliance_bridge.reconciliation_worker.read_verified_balance",
            return_value=result,
        ),
        patch(
            "src.gateway.governance.cbf.redis_client",
            new=MagicMock(_get=MagicMock(return_value=fake_redis)),
        ),
        patch(
            "src.gateway.governance.kms_signer.get_governance_signer",
            return_value=mock_signer,
        ),
    ):
        state = await cbf._read_cbf_state_atomic()

    assert state["source"] == "reconciled", f"Expected 'reconciled', got {state['source']!r}"
    assert state["current_cash"] == pytest.approx(_RECON_BALANCE)


# ---------------------------------------------------------------------------
# Test 2: CBF falls back to self-reported when reconciled balance is absent
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cbf_falls_back_when_reconciled_balance_absent(
    cbf, fake_redis: fakeredis.aioredis.FakeRedis
) -> None:
    """CBF returns source='self_reported' when read_verified_balance returns None (TTL expired)."""
    with (
        patch(
            "src.gateway.governance.cbf.redis_client",
            new=MagicMock(_get=MagicMock(return_value=fake_redis)),
        ),
        patch(
            "src.compliance_bridge.reconciliation_worker.read_verified_balance",
            return_value=None,
        ),
    ):
        state = await cbf._read_cbf_state_atomic()

    assert state["source"] == "self_reported", f"Expected 'self_reported', got {state['source']!r}"
    assert state["current_cash"] == pytest.approx(_SAFE_BALANCE)


# ---------------------------------------------------------------------------
# Test 3: CBF falls back when KMS signature is invalid (CRITICAL log emitted)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cbf_falls_back_when_kms_signature_invalid(
    cbf, fake_redis: fakeredis.aioredis.FakeRedis, caplog: pytest.LogCaptureFixture
) -> None:
    """CBF falls back to self-reported and emits CRITICAL log when KMS verify returns False."""
    result = _make_result(balance=_RECON_BALANCE, signature="bad_sig")

    mock_signer = MagicMock()
    mock_signer.verify.return_value = False  # signature invalid

    import logging

    with (
        patch(
            "src.gateway.governance.cbf.redis_client",
            new=MagicMock(_get=MagicMock(return_value=fake_redis)),
        ),
        patch(
            "src.compliance_bridge.reconciliation_worker.read_verified_balance",
            return_value=result,
        ),
        patch(
            "src.gateway.governance.kms_signer.get_governance_signer",
            return_value=mock_signer,
        ),
        caplog.at_level(logging.CRITICAL, logger="src.gateway.governance.cbf"),
    ):
        state = await cbf._read_cbf_state_atomic()

    assert state["source"] == "self_reported", f"Expected 'self_reported', got {state['source']!r}"
    # Verify CRITICAL audit log was emitted
    critical_events = [
        r for r in caplog.records
        if r.levelno >= logging.CRITICAL and "SIGNATURE_INVALID" in r.getMessage()
    ]
    assert critical_events, "Expected CRITICAL log for invalid KMS signature, none found"


# ---------------------------------------------------------------------------
# Test 4: CBF falls back when reconciled balance is unsigned in production
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cbf_falls_back_when_unsigned_in_production(
    cbf, fake_redis: fakeredis.aioredis.FakeRedis, caplog: pytest.LogCaptureFixture
) -> None:
    """CBF falls back to self-reported and emits CRITICAL log when balance has no signature in prod."""
    result = _make_result(balance=_RECON_BALANCE, signature="")  # no signature

    import logging

    with (
        patch(
            "src.gateway.governance.cbf.redis_client",
            new=MagicMock(_get=MagicMock(return_value=fake_redis)),
        ),
        patch(
            "src.compliance_bridge.reconciliation_worker.read_verified_balance",
            return_value=result,
        ),
        patch("src.gateway.governance.cbf._IS_PRODUCTION", True),
        caplog.at_level(logging.CRITICAL, logger="src.gateway.governance.cbf"),
    ):
        state = await cbf._read_cbf_state_atomic()

    assert state["source"] == "self_reported", f"Expected 'self_reported', got {state['source']!r}"
    critical_events = [
        r for r in caplog.records
        if r.levelno >= logging.CRITICAL and "UNSIGNED_IN_PRODUCTION" in r.getMessage()
    ]
    assert critical_events, "Expected CRITICAL log for unsigned balance in production, none found"


# ---------------------------------------------------------------------------
# Test 5: OTel span has safety.balance.source="reconciled" on reconciled path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_otel_span_stamped_reconciled(
    cbf, fake_redis: fakeredis.aioredis.FakeRedis
) -> None:
    """_do_verify_action stamps safety.balance.source='reconciled' and safety.balance.reconciled=True."""
    span = _FakeSpan()

    await cbf._do_verify_action(
        action_name="execute_trade",
        payload={"amount": 1000.0},
        current_cash=_RECON_BALANCE,
        balance_source="reconciled",
        span=span,
    )

    assert span.attrs.get("safety.balance.source") == "reconciled", (
        f"Expected 'reconciled', got {span.attrs.get('safety.balance.source')!r}"
    )
    assert span.attrs.get("safety.balance.reconciled") is True, (
        f"Expected True, got {span.attrs.get('safety.balance.reconciled')!r}"
    )


# ---------------------------------------------------------------------------
# Test 6: OTel span has safety.balance.source="self_reported" on fallback path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_otel_span_stamped_self_reported(
    cbf, fake_redis: fakeredis.aioredis.FakeRedis
) -> None:
    """_do_verify_action stamps safety.balance.source='self_reported' and safety.balance.reconciled=False."""
    span = _FakeSpan()

    await cbf._do_verify_action(
        action_name="execute_trade",
        payload={"amount": 500.0},
        current_cash=_SAFE_BALANCE,
        balance_source="self_reported",
        span=span,
    )

    assert span.attrs.get("safety.balance.source") == "self_reported", (
        f"Expected 'self_reported', got {span.attrs.get('safety.balance.source')!r}"
    )
    assert span.attrs.get("safety.balance.reconciled") is False, (
        f"Expected False, got {span.attrs.get('safety.balance.reconciled')!r}"
    )
