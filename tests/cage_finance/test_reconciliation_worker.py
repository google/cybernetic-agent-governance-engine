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
Unit tests for src.cage_finance.reconciliation_worker.py

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

pytestmark = pytest.mark.local

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
        r = mod.ReconciliationResult(source="stub", balance_usd=100_000.0)
        assert r.is_valid is True

    def test_is_valid_false_when_error_set(self):
        """is_valid is False when error is set."""
        mod = _get_module()
        r = mod.ReconciliationResult(source="stub", balance_usd=0.0, error="oops")
        assert r.is_valid is False

    def test_is_valid_false_when_balance_negative(self):
        """is_valid is False when balance is negative."""
        mod = _get_module()
        r = mod.ReconciliationResult(source="stub", balance_usd=-1.0)
        assert r.is_valid is False

    def test_is_stale_false_for_fresh_result(self):
        """is_stale is False immediately after construction."""
        mod = _get_module()
        r = mod.ReconciliationResult(
            source="stub", balance_usd=100.0, verified_at=time.time(), ttl_seconds=300
        )
        assert r.is_stale is False

    def test_is_stale_true_when_older_than_ttl(self):
        """is_stale is True when verified_at is older than ttl_seconds."""
        mod = _get_module()
        # Use a verified_at 1000 seconds ago with a 300s TTL
        r = mod.ReconciliationResult(
            source="stub",
            balance_usd=100.0,
            verified_at=time.time() - 1000,
            ttl_seconds=300,
        )
        assert r.is_stale is True

    def test_to_redis_payload_is_valid_json(self):
        """to_redis_payload() produces valid JSON with required fields."""
        mod = _get_module()
        r = mod.ReconciliationResult(
            source="stub",
            balance_usd=55_000.0,
            verified_at=1700000000.0,
            signature="abc123",
        )
        payload = r.to_redis_payload()
        data = json.loads(payload)
        assert data["source"] == "stub"
        assert data["balance_usd"] == 55_000.0
        assert data["verified_at"] == 1700000000.0
        assert data["signature"] == "abc123"

    def test_from_redis_payload_round_trips(self):
        """from_redis_payload() reconstructs a result that matches the original."""
        mod = _get_module()
        original = mod.ReconciliationResult(
            source="plaid",
            balance_usd=95_000.0,
            verified_at=1700000000.0,
            signature="deadbeef",
        )
        payload = original.to_redis_payload()
        reconstructed = mod.ReconciliationResult.from_redis_payload(payload)
        assert reconstructed.source == original.source
        assert reconstructed.balance_usd == original.balance_usd
        assert abs(reconstructed.verified_at - original.verified_at) < 0.01
        assert reconstructed.signature == original.signature


# ---------------------------------------------------------------------------
# StubLedgerProvider
# ---------------------------------------------------------------------------


class TestStubLedgerProvider:
    """Tests for the StubLedgerProvider (dev/CI provider)."""

    def test_fetch_balance_returns_valid_result(self):
        """StubLedgerProvider.fetch_balance returns a valid ReconciliationResult."""
        mod = _get_module()
        provider = mod.StubLedgerProvider()
        result = provider.fetch_balance("test-account")
        assert result.is_valid
        assert result.source == "stub"
        assert result.balance_usd >= 0.0

    def test_fetch_balance_uses_env_var(self, monkeypatch):
        """RECONCILIATION_STUB_BALANCE_USD overrides the default balance."""
        monkeypatch.setenv("RECONCILIATION_STUB_BALANCE_USD", "42000.0")
        mod = _get_module()
        provider = mod.StubLedgerProvider()
        result = provider.fetch_balance("acc")
        assert result.balance_usd == pytest.approx(42_000.0)

    def test_fetch_balance_includes_raw_response(self):
        """StubLedgerProvider includes raw_response with account_id."""
        mod = _get_module()
        provider = mod.StubLedgerProvider()
        result = provider.fetch_balance("my-account-id")
        assert result.raw_response is not None
        assert result.raw_response.get("account_id") == "my-account-id"
        assert result.raw_response.get("stub") is True


# ---------------------------------------------------------------------------
# ExternalLedgerReconciler — happy path
# ---------------------------------------------------------------------------


class TestExternalLedgerReconcilerHappyPath:
    """Tests for the ExternalLedgerReconciler's reconcile() happy paths."""

    def _make_reconciler(self, redis_client, balance_usd=100_000.0, ttl=300):
        """Create a reconciler with a stub provider and given fakeredis client."""
        mod = _get_module()
        provider = mod.StubLedgerProvider()
        provider._balance = balance_usd
        return mod.ExternalLedgerReconciler(
            provider=provider,
            redis_client=redis_client,
            account_id="test-account",
            ttl=ttl,
        )

    def test_reconcile_writes_verified_balance_to_redis(self):
        """After reconcile(), the verified balance key exists in Redis."""
        # Arrange
        _get_module()
        r = _make_fakeredis()
        reconciler = self._make_reconciler(r)

        # Patch KMS to avoid real cloud call
        with patch(
            "src.gateway.governance.kms_signer.get_governance_signer",
            side_effect=Exception("KMS unavailable in test"),
        ):
            # Act
            result = reconciler.reconcile()

        # Assert
        assert result.is_valid
        raw = r.get("reconciliation:verified_balance")
        assert raw is not None
        data = json.loads(raw)
        assert data["source"] == "stub"
        assert data["balance_usd"] == pytest.approx(100_000.0)

    def test_reconcile_sets_redis_ttl_on_write(self):
        """After reconcile(), the Redis key has a TTL set."""
        _get_module()
        r = _make_fakeredis()
        reconciler = self._make_reconciler(r, ttl=120)

        with patch(
            "src.gateway.governance.kms_signer.get_governance_signer",
            side_effect=Exception("KMS unavailable in test"),
        ):
            reconciler.reconcile()

        ttl = r.ttl("reconciliation:verified_balance")
        # TTL should be between 1 and 120 seconds
        assert 0 < ttl <= 120

    def test_reconcile_writes_verified_at_and_provider_keys(self):
        """reconcile() writes the verified_at and provider metadata keys."""
        _get_module()
        r = _make_fakeredis()
        reconciler = self._make_reconciler(r)

        with patch(
            "src.gateway.governance.kms_signer.get_governance_signer",
            side_effect=Exception("KMS unavailable in test"),
        ):
            reconciler.reconcile()

        assert r.get("reconciliation:verified_at") is not None
        assert r.get("reconciliation:provider") == "stub"

    def test_reconcile_kms_signs_balance_when_signer_available(self):
        """When KMS signer is available, it is called with the balance payload."""
        _get_module()
        r = _make_fakeredis()
        reconciler = self._make_reconciler(r)

        mock_signer = MagicMock()
        mock_signer.sign.return_value = "hex-signature-0xdeadbeef"
        mock_signer.is_kms_active = True

        with patch(
            "src.gateway.governance.kms_signer.get_governance_signer",
            return_value=mock_signer,
        ):
            result = reconciler.reconcile()

        mock_signer.sign.assert_called_once()
        assert result.signature == "hex-signature-0xdeadbeef"
        # Signature key should also be written to Redis
        assert r.get("reconciliation:signature") == "hex-signature-0xdeadbeef"


# ---------------------------------------------------------------------------
# ExternalLedgerReconciler — failure paths
# ---------------------------------------------------------------------------


class TestExternalLedgerReconcilerFailurePaths:
    """Tests for the ExternalLedgerReconciler's error-handling paths."""

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

        # Act — should not raise
        result = reconciler.reconcile()

        # Assert
        assert result.error is not None
        assert "Network error" in result.error
        # Balance key should NOT be written
        assert r.get("reconciliation:verified_balance") is None

    def test_kms_sign_failure_still_writes_unsigned_balance(self):
        """When KMS signing fails, the balance is still written unsigned."""
        mod = _get_module()
        r = _make_fakeredis()
        provider = mod.StubLedgerProvider()
        reconciler = mod.ExternalLedgerReconciler(
            provider=provider, redis_client=r, account_id="acc"
        )

        with patch(
            "src.gateway.governance.kms_signer.get_governance_signer",
            side_effect=Exception("KMS unavailable"),
        ):
            result = reconciler.reconcile()

        # Balance still written even without signature
        assert result.is_valid
        raw = r.get("reconciliation:verified_balance")
        assert raw is not None

    def test_redis_write_failure_sets_error_on_result(self):
        """When Redis write fails, result.error is set with the Redis error message."""
        mod = _get_module()

        # Create a mock Redis client that raises on pipeline execution
        mock_redis = MagicMock()
        mock_pipe = MagicMock()
        mock_pipe.execute.side_effect = ConnectionError("Redis down")
        mock_redis.pipeline.return_value = mock_pipe

        provider = mod.StubLedgerProvider()
        reconciler = mod.ExternalLedgerReconciler(
            provider=provider, redis_client=mock_redis, account_id="acc"
        )

        with patch(
            "src.gateway.governance.kms_signer.get_governance_signer",
            side_effect=Exception("KMS unavailable"),
        ):
            result = reconciler.reconcile()

        assert result.error is not None
        assert "Redis write failed" in result.error


# ---------------------------------------------------------------------------
# read_verified_balance() reader
# ---------------------------------------------------------------------------


class TestReadVerifiedBalance:
    """Tests for the read_verified_balance() CBF reader function."""

    def test_returns_none_when_key_absent(self):
        """Returns None when reconciliation:verified_balance is not in Redis."""
        mod = _get_module()
        r = _make_fakeredis()
        result = mod.read_verified_balance(r)
        assert result is None

    def test_returns_result_when_fresh_balance_present(self):
        """Returns ReconciliationResult when a fresh balance is stored."""
        mod = _get_module()
        r = _make_fakeredis()

        fresh_result = mod.ReconciliationResult(
            source="stub",
            balance_usd=75_000.0,
            verified_at=time.time(),
            ttl_seconds=300,
        )
        r.setex("reconciliation:verified_balance", 300, fresh_result.to_redis_payload())

        read = mod.read_verified_balance(r)
        assert read is not None
        assert read.balance_usd == pytest.approx(75_000.0)
        assert read.source == "stub"

    def test_returns_none_when_balance_is_stale(self):
        """Returns None when the stored balance is older than ttl_seconds."""
        mod = _get_module()
        r = _make_fakeredis()

        stale_result = mod.ReconciliationResult(
            source="stub",
            balance_usd=10_000.0,
            verified_at=time.time() - 1000,  # 1000s ago
            ttl_seconds=300,  # 300s TTL → stale
        )
        # Still write to Redis (key hasn't expired yet)
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


# ---------------------------------------------------------------------------
# GcsLedgerProvider / ObjectStoreLedgerProvider — zero-balance mapping
#
# A drained (0.0) account in a multi-account snapshot must be reported as 0.0,
# not silently replaced by the top-level "balance" fallback. The barrier the
# reconciler feeds, h(x) = cash - min_cash, relies on the real balance; a
# masked zero inflates it and lets trades clear against an empty account.
# ---------------------------------------------------------------------------


class TestLedgerProviderZeroBalanceMapping:
    """Ledger providers must not treat a present 0.0 balance as absent."""

    def _gcs_client_for(self, snapshot: dict) -> MagicMock:
        blob = MagicMock()
        blob.download_as_text.return_value = json.dumps(snapshot)
        bucket = MagicMock()
        bucket.blob.return_value = blob
        client = MagicMock()
        client.bucket.return_value = bucket
        return client

    def _s3_provider_with_snapshot(self, mod, monkeypatch, snapshot: dict):
        monkeypatch.setenv("S3_RECONCILIATION_BUCKET", "cage-ledger")
        body = MagicMock()
        body.read.return_value = json.dumps(snapshot).encode("utf-8")
        client = MagicMock()
        client.get_object.return_value = {"Body": body}
        provider = mod.ObjectStoreLedgerProvider()
        monkeypatch.setattr(provider, "_make_client", lambda: client)
        return provider

    def test_gcs_present_zero_balance_not_masked(self, monkeypatch):
        """A 0.0 target balance must survive even when a top-level fallback exists."""
        mod = _get_module()
        monkeypatch.setenv("GCS_RECONCILIATION_BUCKET", "cage-ledger")
        snapshot = {"balances": {"acct1": 0.0}, "balance": 100_000.0}
        client = self._gcs_client_for(snapshot)
        provider = mod.GcsLedgerProvider()
        with patch("google.cloud.storage.Client", return_value=client):
            result = provider.fetch_balance("acct1")
        assert result.balance_usd == 0.0

    def test_s3_present_zero_balance_not_masked(self, monkeypatch):
        """Same containment for the S3-compatible provider."""
        mod = _get_module()
        snapshot = {"balances": {"acct1": 0.0}, "balance": 100_000.0}
        provider = self._s3_provider_with_snapshot(mod, monkeypatch, snapshot)

        result = provider.fetch_balance("acct1")
        assert result.balance_usd == 0.0

    def test_gcs_nonzero_balance_preferred_over_fallback(self, monkeypatch):
        """A real per-account balance still wins over the top-level fallback."""
        mod = _get_module()
        monkeypatch.setenv("GCS_RECONCILIATION_BUCKET", "cage-ledger")
        snapshot = {"balances": {"acct1": 4_200.0}, "balance": 100_000.0}
        client = self._gcs_client_for(snapshot)
        provider = mod.GcsLedgerProvider()
        with patch("google.cloud.storage.Client", return_value=client):
            result = provider.fetch_balance("acct1")
        assert result.balance_usd == 4_200.0

    def test_gcs_absent_account_falls_back_to_top_level_balance(self, monkeypatch):
        """When the account is absent, the top-level balance is still used."""
        mod = _get_module()
        monkeypatch.setenv("GCS_RECONCILIATION_BUCKET", "cage-ledger")
        snapshot = {"balances": {}, "balance": 100_000.0}
        client = self._gcs_client_for(snapshot)
        provider = mod.GcsLedgerProvider()
        with patch("google.cloud.storage.Client", return_value=client):
            result = provider.fetch_balance("acct1")
        assert result.balance_usd == 100_000.0
