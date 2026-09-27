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
Unit tests for src.gateway.governance.reconciliation.daemon

Covers the ExternalLedgerReconciler polling daemon, ReconciliationResult
data contract, StubLedgerProvider, and read_verified_balance() reader.

All tests use fakeredis so no live Redis is required.
"""

from __future__ import annotations

import json
import time
from unittest.mock import MagicMock, patch

import fakeredis
import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]

# ---------------------------------------------------------------------------
# The reconciliation_worker module-level guard blocks import when
# CAGE_ENV is "production" AND RECONCILIATION_PROVIDER is "stub".
# Force dev environment so the stub is allowed during tests.
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _force_dev_env(monkeypatch):
    """Force CAGE_ENV=ci so the module-level production guard allows stub."""
    monkeypatch.setenv("CAGE_ENV", "ci")
    monkeypatch.setenv("RECONCILIATION_PROVIDER", "stub")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_module():
    """Import the module after env is patched (autouse fixture ensures this)."""
    import importlib
    import sys

    # Force re-evaluation of module-level guards by evicting any cached import.
    sys.modules.pop("src.gateway.governance.reconciliation.daemon", None)
    return importlib.import_module("src.gateway.governance.reconciliation.daemon")


def _make_fakeredis():
    """Return a synchronous fakeredis client with decode_responses=True."""
    return fakeredis.FakeRedis(decode_responses=True)


# ---------------------------------------------------------------------------
# ReconciliationResult data contract
# ---------------------------------------------------------------------------


class TestReconciliationResult:
    """Tests for the ReconciliationResult dataclass and its helpers."""

    def test_is_valid_true_when_no_error_and_nonnegative_balance(self):
        """is_valid is True when error is None and balance >= 0."""
        mod = _get_module()
        r = mod.ReconciliationResult(source="stub", state_scalar=100_000.0)
        assert r.is_valid is True

    def test_is_valid_false_when_error_set(self):
        """is_valid is False when error is set."""
        mod = _get_module()
        r = mod.ReconciliationResult(source="stub", state_scalar=0.0, error="oops")
        assert r.is_valid is False

    def test_is_valid_false_when_balance_negative(self):
        """is_valid is False when balance is negative."""
        mod = _get_module()
        r = mod.ReconciliationResult(source="stub", state_scalar=-1.0)
        assert r.is_valid is False

    def test_is_stale_false_for_fresh_result(self):
        """is_stale is False immediately after construction."""
        mod = _get_module()
        r = mod.ReconciliationResult(
            source="stub", state_scalar=100.0, verified_at=time.time(), ttl_seconds=300
        )
        assert r.is_stale is False

    def test_is_stale_true_when_older_than_ttl(self):
        """is_stale is True when verified_at is older than ttl_seconds."""
        mod = _get_module()
        # Use a verified_at 1000 seconds ago with a 300s TTL
        r = mod.ReconciliationResult(
            source="stub",
            state_scalar=100.0,
            verified_at=time.time() - 1000,
            ttl_seconds=300,
        )
        assert r.is_stale is True

    def test_to_redis_payload_is_valid_json(self):
        """to_redis_payload() produces valid JSON with required fields."""
        mod = _get_module()
        r = mod.ReconciliationResult(
            source="stub",
            state_scalar=55_000.0,
            verified_at=1700000000.0,
            signature="abc123",
        )
        payload = r.to_redis_payload()
        data = json.loads(payload)
        assert data["source"] == "stub"
        assert data["state_scalar"] == 55_000.0
        assert data["verified_at"] == 1700000000.0
        assert data["signature"] == "abc123"

    def test_from_redis_payload_round_trips(self):
        """from_redis_payload() reconstructs a result that matches the original."""
        mod = _get_module()
        original = mod.ReconciliationResult(
            source="plaid",
            state_scalar=95_000.0,
            verified_at=1700000000.0,
            signature="deadbeef",
        )
        payload = original.to_redis_payload()
        reconstructed = mod.ReconciliationResult.from_redis_payload(payload)
        assert reconstructed.source == original.source
        assert reconstructed.state_scalar == original.state_scalar
        assert abs(reconstructed.verified_at - original.verified_at) < 0.01
        assert reconstructed.signature == original.signature


# ---------------------------------------------------------------------------
# SimulatedCashLedgerProvider
# ---------------------------------------------------------------------------


class TestSimulatedCashLedgerProvider:
    """Tests for the SimulatedCashLedgerProvider (posture-completing finance provider)."""

    def test_fetch_snapshot_returns_valid_result(self):
        """SimulatedCashLedgerProvider.fetch_snapshot_sync returns a valid GroundTruthSnapshot."""
        from src.cage_finance.ground_truth import SimulatedCashLedgerProvider

        provider = SimulatedCashLedgerProvider()
        snap = provider.fetch_snapshot_sync()
        assert snap.invariant_id == "finance.cash_balance"
        assert snap.source == "simulated:finance_cash_ledger"
        assert snap.scalar >= 0.0

    def test_fetch_snapshot_uses_env_var(self, monkeypatch):
        """RECONCILIATION_STUB_BALANCE_USD overrides the default balance."""
        from src.cage_finance.ground_truth import SimulatedCashLedgerProvider

        monkeypatch.setenv("RECONCILIATION_STUB_BALANCE_USD", "42000.0")
        provider = SimulatedCashLedgerProvider()
        snap = provider.fetch_snapshot_sync()
        assert snap.scalar == pytest.approx(42_000.0)

    def test_fetch_snapshot_includes_metadata(self):
        """SimulatedCashLedgerProvider includes deterministic seed metadata."""
        from src.cage_finance.ground_truth import SimulatedCashLedgerProvider

        provider = SimulatedCashLedgerProvider(seed=99)
        snap = provider.fetch_snapshot_sync()
        assert snap.metadata is not None
        assert snap.metadata.get("seed") == 99


# ---------------------------------------------------------------------------
# ExternalLedgerReconciler / GroundTruthReconciler — happy path
# ---------------------------------------------------------------------------


class TestExternalLedgerReconcilerHappyPath:
    """Tests for GroundTruthReconciler's reconcile() happy paths."""

    def _make_reconciler(self, redis_client, state_scalar=100_000.0, ttl=300):
        """Create a reconciler with a simulated finance provider and given fakeredis client."""
        from src.cage_finance.ground_truth import SimulatedCashLedgerProvider

        mod = _get_module()
        provider = SimulatedCashLedgerProvider(initial_scalar=state_scalar)
        return mod.ExternalLedgerReconciler(
            provider=provider,
            redis_client=redis_client,
            account_id="test-account",
            ttl=ttl,
        )

    def test_reconcile_writes_verified_balance_to_redis(self):
        """After reconcile(), the verified balance key exists in Redis."""
        _get_module()
        r = _make_fakeredis()
        reconciler = self._make_reconciler(r)

        with patch(
            "src.gateway.governance.reconciliation.trust.get_reconciler_signer",
            side_effect=Exception("KMS unavailable in test"),
        ):
            result = reconciler.reconcile()

        assert result.is_valid
        raw = r.get("reconciliation:verified_balance")
        assert raw is not None
        data = json.loads(raw)
        assert data["source"] == "simulated:finance_cash_ledger"
        assert data["state_scalar"] == pytest.approx(100_000.0)

    def test_reconcile_sets_redis_ttl_on_write(self):
        """After reconcile(), the Redis key has a TTL set."""
        _get_module()
        r = _make_fakeredis()
        reconciler = self._make_reconciler(r, ttl=120)

        with patch(
            "src.gateway.governance.reconciliation.trust.get_reconciler_signer",
            side_effect=Exception("KMS unavailable in test"),
        ):
            reconciler.reconcile()

        ttl = r.ttl("reconciliation:verified_balance")
        assert 0 < ttl <= 120

    def test_reconcile_writes_verified_at_and_provider_keys(self):
        """reconcile() writes the verified_at and provider metadata keys."""
        _get_module()
        r = _make_fakeredis()
        reconciler = self._make_reconciler(r)

        with patch(
            "src.gateway.governance.reconciliation.trust.get_reconciler_signer",
            side_effect=Exception("KMS unavailable in test"),
        ):
            reconciler.reconcile()

        assert r.get("reconciliation:verified_at") is not None
        assert r.get("reconciliation:provider") == "simulated:finance_cash_ledger"

    def test_reconcile_kms_signs_balance_when_signer_available(self):
        """When KMS signer is available, it is called with the balance payload."""
        _get_module()
        r = _make_fakeredis()
        reconciler = self._make_reconciler(r)

        mock_signer = MagicMock()
        mock_signer.sign_decision.return_value = MagicMock(signature="hex-signature-0xdeadbeef", kid="reconciler-kid", algorithm="gcp_kms")
        mock_signer.is_kms_active = True

        with patch(
            "src.gateway.governance.reconciliation.trust.get_reconciler_signer",
            return_value=mock_signer,
        ):
            result = reconciler.reconcile()

        mock_signer.sign_decision.assert_called_once()
        assert result.signature == "hex-signature-0xdeadbeef"
        assert r.get("reconciliation:signature") == "hex-signature-0xdeadbeef"


# ---------------------------------------------------------------------------
# ExternalLedgerReconciler — failure paths
# ---------------------------------------------------------------------------


class TestExternalLedgerReconcilerFailurePaths:
    """Tests for GroundTruthReconciler's error-handling paths."""

    def test_provider_exception_returns_error_result_without_crashing(self):
        """When the provider raises, reconcile() returns an error result (daemon resilience)."""
        mod = _get_module()
        r = _make_fakeredis()

        failing_provider = MagicMock()
        failing_provider.fetch_balance.side_effect = RuntimeError("Network error")

        reconciler = mod.ExternalLedgerReconciler(
            provider=failing_provider,
            redis_client=r,
            account_id="acc",
        )

        result = reconciler.reconcile()

        assert result.error is not None
        assert "Network error" in result.error
        assert r.get("reconciliation:verified_balance") is None

    def test_kms_sign_failure_still_writes_unsigned_balance(self):
        """When KMS signing is unconfigured in dev/test posture, balance is written unsigned."""
        from src.cage_finance.ground_truth import SimulatedCashLedgerProvider

        mod = _get_module()
        r = _make_fakeredis()
        provider = SimulatedCashLedgerProvider()
        reconciler = mod.ExternalLedgerReconciler(
            provider=provider, redis_client=r, account_id="acc"
        )

        with patch(
            "src.gateway.governance.reconciliation.trust.get_reconciler_signer",
            side_effect=Exception("KMS unavailable"),
        ):
            result = reconciler.reconcile()

        assert result.is_valid
        raw = r.get("reconciliation:verified_balance")
        assert raw is not None

    def test_redis_write_failure_sets_error_on_result(self):
        """When Redis write fails, result.error is set with the Redis error message."""
        from src.cage_finance.ground_truth import SimulatedCashLedgerProvider

        mod = _get_module()

        mock_redis = MagicMock()
        mock_pipe = MagicMock()
        mock_pipe.execute.side_effect = ConnectionError("Redis down")
        mock_redis.pipeline.return_value = mock_pipe

        provider = SimulatedCashLedgerProvider()
        reconciler = mod.ExternalLedgerReconciler(
            provider=provider, redis_client=mock_redis, account_id="acc"
        )

        with patch(
            "src.gateway.governance.reconciliation.trust.get_reconciler_signer",
            side_effect=Exception("KMS unavailable"),
        ):
            result = reconciler.reconcile()

        assert result.error is not None
        assert "Redis write failed" in result.error


# ---------------------------------------------------------------------------
# read_verified_balance() & read_verified_state() readers
# ---------------------------------------------------------------------------


class TestReadVerifiedBalance:
    """Tests for the read_verified_balance() and read_verified_state() CBF readers."""

    def test_returns_none_when_key_absent(self):
        """Returns None when reconciled key is not in Redis."""
        mod = _get_module()
        r = _make_fakeredis()
        result = mod.read_verified_balance(r)
        assert result is None

    def test_returns_result_when_fresh_balance_present(self):
        """Returns ReconciliationResult when a fresh balance is stored."""
        mod = _get_module()
        r = _make_fakeredis()

        fresh_result = mod.ReconciliationResult(
            source="simulated:finance_cash_ledger",
            state_scalar=75_000.0,
            verified_at=time.time(),
            ttl_seconds=300,
        )
        r.setex("reconciliation:verified_balance", 300, fresh_result.to_redis_payload())

        read = mod.read_verified_balance(r)
        assert read is not None
        assert read.state_scalar == pytest.approx(75_000.0)
        assert read.source == "simulated:finance_cash_ledger"
        assert mod.read_verified_state(r, "finance.cash_balance") == pytest.approx(
            75_000.0
        )

    def test_returns_none_when_balance_is_stale(self):
        """Returns None when the stored balance is older than ttl_seconds."""
        mod = _get_module()
        r = _make_fakeredis()

        stale_result = mod.ReconciliationResult(
            source="simulated:finance_cash_ledger",
            state_scalar=10_000.0,
            verified_at=time.time() - 1000,  # 1000s ago
            ttl_seconds=300,  # 300s TTL → stale
        )
        r.setex(
            "reconciliation:verified_balance", 9999, stale_result.to_redis_payload()
        )

        read = mod.read_verified_balance(r)
        assert read is None

    def test_returns_none_on_corrupted_payload(self):
        """Returns None when the Redis payload is not valid JSON."""
        mod = _get_module()
        r = _make_fakeredis()
        r.setex("reconciliation:verified_balance", 300, "not-valid-json{{{")

        result = mod.read_verified_balance(r)
        assert result is None

    def test_returns_none_on_redis_error(self):
        """Returns None when Redis raises an exception (fail-closed)."""
        mod = _get_module()
        mock_redis = MagicMock()
        mock_redis.get.side_effect = ConnectionError("Redis down")

        result = mod.read_verified_balance(mock_redis)
        assert result is None
