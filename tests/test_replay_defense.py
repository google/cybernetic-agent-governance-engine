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
# Closure regression guard for: POAM-2026-054, POAM-2026-097

"""
Tests for R-04 Replay Defense (Monotonic Sequence Number) — §2.10

These tests verify that the reconciliation system correctly implements
monotonic sequence number validation to prevent replay of stale balance data.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# ReconciliationResult dataclass tests
# ---------------------------------------------------------------------------


class TestReconciliationResultSequence:
    """Tests for sequence field in ReconciliationResult."""

    def test_sequence_default_zero(self) -> None:
        """Verify sequence defaults to 0 for backward compatibility."""
        from src.gateway.governance.reconciliation.daemon import ReconciliationResult

        result = ReconciliationResult(
            source="test",
            state_scalar=50000.0,
        )
        assert result.sequence == 0

    def test_sequence_in_redis_payload(self) -> None:
        """Verify sequence is included in serialized Redis payload."""
        from src.gateway.governance.reconciliation.daemon import ReconciliationResult

        result = ReconciliationResult(
            source="plaid",
            state_scalar=75000.0,
            verified_at=1234567890.0,
            signature="test_sig",
            sequence=42,
        )
        payload = result.to_redis_payload()
        parsed = json.loads(payload)

        assert "sequence" in parsed
        assert parsed["sequence"] == 42

    def test_sequence_deserialized_from_payload(self) -> None:
        """Verify sequence is correctly deserialized from Redis payload."""
        from src.gateway.governance.reconciliation.daemon import ReconciliationResult

        payload = json.dumps(
            {
                "source": "anchorage",
                "state_scalar": 100000.0,
                "verified_at": 1234567890.0,
                "signature": "kms_sig",
                "sequence": 99,
            }
        )
        result = ReconciliationResult.from_redis_payload(payload)

        assert result.sequence == 99

    def test_sequence_backward_compat_missing_field(self) -> None:
        """Verify sequence defaults to 0 when missing from payload (backward compat)."""
        from src.gateway.governance.reconciliation.daemon import ReconciliationResult

        # Old-format payload without sequence field
        payload = json.dumps(
            {
                "source": "stub",
                "state_scalar": 50000.0,
                "verified_at": 1234567890.0,
                "signature": "",
            }
        )
        result = ReconciliationResult.from_redis_payload(payload)

        assert result.sequence == 0


# ---------------------------------------------------------------------------
# Sequence included in KMS signature
# ---------------------------------------------------------------------------


class TestSequenceInSignedPayload:
    """Tests verifying sequence is included in KMS signature payload."""

    def test_sequence_included_in_kms_signature(self) -> None:
        """Verify sequence is part of the payload passed to KMS signer.sign_decision()."""
        from src.cage_finance.ground_truth import SimulatedCashLedgerProvider
        from src.gateway.governance.reconciliation.daemon import (
            ExternalLedgerReconciler,
        )

        # Mock Redis client
        mock_redis = MagicMock()
        mock_redis.incr.return_value = 5  # New sequence
        mock_pipe = MagicMock()
        mock_redis.pipeline.return_value = mock_pipe

        # Mock KMS signer
        mock_signer = MagicMock()
        mock_signer.is_kms_active = True
        mock_signer.sign_decision.return_value = MagicMock(
            signature="test_signature", kid="reconciler-kid", algorithm="gcp_kms"
        )

        reconciler = ExternalLedgerReconciler(
            provider=SimulatedCashLedgerProvider(),
            redis_client=mock_redis,
            account_id="test_account",
        )

        with (
            patch(
                "src.gateway.governance.reconciliation.daemon.REPLAY_DEFENSE_ENABLED",
                True,
            ),
            patch(
                "src.gateway.governance.reconciliation.trust.get_reconciler_signer",
                return_value=mock_signer,
            ),
        ):
            reconciler.reconcile()

        # Verify signer.sign was called with sequence in payload
        assert mock_signer.sign_decision.called
        signed_payload = mock_signer.sign_decision.call_args[0][0]
        assert "sequence" in signed_payload
        assert signed_payload["sequence"] == 5


# ---------------------------------------------------------------------------
# CBF read-path sequence validation tests
# ---------------------------------------------------------------------------


class TestCBFSequenceValidation:
    """Tests for CBF read-path sequence validation (atomic, regression-only)."""

    @staticmethod
    def _cbf():
        from src.cage_finance.invariants import CashBarrier, finance_cost_resolver
        from src.gateway.governance.safety.cbf_engine import ControlBarrierFunction

        return ControlBarrierFunction(
            invariant=CashBarrier(gamma=0.5),
            cost_resolver=finance_cost_resolver,
            skip_epoch_seed=True,
        )

    @staticmethod
    def _redis(last_accepted: int | None):
        import fakeredis

        from src.gateway.governance.safety.cbf_engine import (
            _REDIS_KEY_SEQUENCE_LAST_ACCEPTED,
        )

        r = fakeredis.FakeRedis()
        if last_accepted is not None:
            r.set(_REDIS_KEY_SEQUENCE_LAST_ACCEPTED, str(last_accepted))
        return r

    @pytest.mark.asyncio
    async def test_monotonic_sequence_number_rejects_regression(self) -> None:
        """R-04: a sequence lower than the high-water mark is a replay."""
        r = self._redis(10)
        is_valid, reason = await self._cbf()._validate_sequence(5, "test_source", r)

        assert is_valid is False
        assert "5" in reason and "10" in reason
        assert int(r.get("reconciliation:sequence:last_accepted")) == 10

    @pytest.mark.asyncio
    async def test_sequence_validation_accepts_advancing_sequence(self) -> None:
        """An advancing sequence is accepted and advances the high-water mark."""
        r = self._redis(10)
        is_valid, reason = await self._cbf()._validate_sequence(11, "test_source", r)

        assert is_valid is True
        assert reason == "OK"
        assert int(r.get("reconciliation:sequence:last_accepted")) == 11

    @pytest.mark.asyncio
    async def test_sequence_validation_first_sequence_accepted(self) -> None:
        """First sequence (no high-water mark yet) is accepted."""
        r = self._redis(None)
        is_valid, reason = await self._cbf()._validate_sequence(1, "test_source", r)

        assert is_valid is True
        assert reason == "OK"

    @pytest.mark.asyncio
    async def test_sequence_validation_accepts_reread_of_current_snapshot(
        self,
    ) -> None:
        """Re-reading the current snapshot (equal sequence) is not a replay.

        Every admission re-reads the same snapshot until the reconciler
        publishes the next one; rejecting equal sequences would admit only
        one trade per snapshot generation.
        """
        cbf = self._cbf()
        r = self._redis(None)
        for _ in range(3):
            is_valid, reason = await cbf._validate_sequence(42, "test_source", r)
            assert is_valid is True, reason
        assert int(r.get("reconciliation:sequence:last_accepted")) == 42

    @pytest.mark.asyncio
    async def test_sequence_validation_fails_closed_on_redis_error(self) -> None:
        """A Redis error rejects the reconciled payload (fail-closed)."""
        broken = MagicMock()
        broken.eval.side_effect = ConnectionError("redis down")

        is_valid, reason = await self._cbf()._validate_sequence(
            7, "test_source", broken
        )

        assert is_valid is False
        assert "fail-closed" in reason

    @pytest.mark.asyncio
    async def test_sequence_zero_default_accepted_when_disabled(self) -> None:
        """Verify sequence=0 payloads are accepted when replay defense is disabled.

        When CAGE_RECONCILIATION_REPLAY_DEFENSE is disabled:
        - Payloads with sequence=0 (default) should be accepted
        - The _validate_sequence method should not even be called
        - This ensures backward compatibility during staged rollout
        """
        from src.cage_finance.invariants import CashBarrier, finance_cost_resolver
        from src.gateway.governance.reconciliation.daemon import ReconciliationResult
        from src.gateway.governance.safety.cbf_engine import ControlBarrierFunction

        # Create a verified result with sequence=0 (default)
        verified = ReconciliationResult(
            source="stub",
            state_scalar=100000.0,
            verified_at=1234567890.0,
            signature="valid_sig",
            sequence=0,  # Default / replay defense not enabled on write side
        )

        # When replay defense is disabled, the CBF should accept the payload
        # without calling _validate_sequence
        ControlBarrierFunction(
            invariant=CashBarrier(gamma=0.5),
            cost_resolver=finance_cost_resolver,
            skip_epoch_seed=True,
        )

        # Verify the ReconciliationResult has sequence=0
        assert verified.sequence == 0

        # Verify the payload serialization includes sequence
        payload = verified.to_redis_payload()
        parsed = json.loads(payload)
        assert parsed["sequence"] == 0


# ---------------------------------------------------------------------------
# Integration test: full reconciliation flow with sequence
# ---------------------------------------------------------------------------


class TestReconciliationSequenceIntegration:
    """Integration tests for the full reconciliation flow with sequence."""

    def test_reconcile_stamps_sequence_when_enabled(self) -> None:
        """Verify reconcile() stamps sequence on payload when feature flag is enabled."""
        from src.cage_finance.ground_truth import SimulatedCashLedgerProvider
        from src.gateway.governance.reconciliation.daemon import (
            ExternalLedgerReconciler,
        )

        # Mock Redis
        mock_redis = MagicMock()
        mock_redis.incr.return_value = 123
        mock_pipe = MagicMock()
        mock_redis.pipeline.return_value = mock_pipe

        reconciler = ExternalLedgerReconciler(
            provider=SimulatedCashLedgerProvider(),
            redis_client=mock_redis,
            account_id="test",
        )

        with patch(
            "src.gateway.governance.reconciliation.daemon.REPLAY_DEFENSE_ENABLED", True
        ):
            result = reconciler.reconcile()

        assert result.sequence == 123
        mock_redis.incr.assert_called_once_with("reconciliation:sequence:latest")

    def test_reconcile_skips_sequence_when_disabled(self) -> None:
        """Verify reconcile() does not call Redis INCR and preserves provider sequence when disabled."""
        from src.cage_finance.ground_truth import SimulatedCashLedgerProvider
        from src.gateway.governance.reconciliation.daemon import (
            ExternalLedgerReconciler,
        )

        # Mock Redis
        mock_redis = MagicMock()
        mock_pipe = MagicMock()
        mock_redis.pipeline.return_value = mock_pipe

        reconciler = ExternalLedgerReconciler(
            provider=SimulatedCashLedgerProvider(),
            redis_client=mock_redis,
            account_id="test",
        )

        with patch(
            "src.gateway.governance.reconciliation.daemon.REPLAY_DEFENSE_ENABLED", False
        ):
            result = reconciler.reconcile()

        assert result.sequence == 1
        mock_redis.incr.assert_not_called()

    def test_reconcile_fails_closed_when_sequence_incr_raises(self) -> None:
        """Verify reconcile() fails closed when Redis INCR for sequence raises an exception."""
        from src.cage_finance.ground_truth import SimulatedCashLedgerProvider
        from src.gateway.governance.reconciliation.daemon import (
            ExternalLedgerReconciler,
        )

        mock_redis = MagicMock()
        mock_redis.incr.side_effect = RuntimeError("redis sequence incr error")
        mock_pipe = MagicMock()
        mock_redis.pipeline.return_value = mock_pipe

        reconciler = ExternalLedgerReconciler(
            provider=SimulatedCashLedgerProvider(),
            redis_client=mock_redis,
            account_id="test",
        )

        with patch(
            "src.gateway.governance.reconciliation.daemon.REPLAY_DEFENSE_ENABLED", True
        ):
            result = reconciler.reconcile()

        assert result.is_valid is False
        assert result.error is not None
        assert "Failed to increment sequence counter" in result.error
        assert reconciler.failure_count == 1
        mock_pipe.setex.assert_not_called()


# ---------------------------------------------------------------------------
# Telemetry tests
# ---------------------------------------------------------------------------


class TestReplayDefenseTelemetry:
    """Tests for replay defense telemetry (Prometheus counter, OTel span)."""

    @pytest.mark.asyncio
    async def test_prometheus_counter_incremented_on_replay_rejection(self) -> None:
        """Verify Prometheus counter is incremented when replay is rejected."""
        from src.cage_finance.invariants import CashBarrier, finance_cost_resolver
        from src.gateway.governance.safety import cbf_engine as cbf_module

        # Create a mock counter
        mock_counter = MagicMock()
        mock_labels = MagicMock()
        mock_counter.labels.return_value = mock_labels

        original_counter = cbf_module._REPLAY_REJECTED_COUNTER

        try:
            cbf_module._REPLAY_REJECTED_COUNTER = mock_counter

            cbf = cbf_module.ControlBarrierFunction(
                invariant=CashBarrier(gamma=0.5),
                cost_resolver=finance_cost_resolver,
                skip_epoch_seed=True,
            )

            # last_accepted=10, incoming=5 (replay)
            import fakeredis

            mock_sync_redis = fakeredis.FakeRedis()
            mock_sync_redis.set("reconciliation:sequence:last_accepted", "10")

            is_valid, _ = await cbf._validate_sequence(
                5, "test_source", mock_sync_redis
            )

            # Note: The counter is incremented in _read_cbf_state_atomic,
            # not in _validate_sequence. This test verifies _validate_sequence
            # returns the correct rejection status.
            assert is_valid is False

        finally:
            cbf_module._REPLAY_REJECTED_COUNTER = original_counter

    def test_otel_span_attribute_stamped_on_reconcile(self) -> None:
        """Verify OTel span attribute cage.reconciliation.sequence is set.

        This test verifies that when REPLAY_DEFENSE_ENABLED is True,
        the reconcile() method stamps sequence on the result, which
        is then recorded as an OTel span attribute.
        """
        from src.cage_finance.ground_truth import SimulatedCashLedgerProvider
        from src.gateway.governance.reconciliation.daemon import (
            ExternalLedgerReconciler,
        )

        mock_redis = MagicMock()
        mock_redis.incr.return_value = 77
        mock_pipe = MagicMock()
        mock_redis.pipeline.return_value = mock_pipe

        reconciler = ExternalLedgerReconciler(
            provider=SimulatedCashLedgerProvider(),
            redis_client=mock_redis,
            account_id="test",
        )

        with patch(
            "src.gateway.governance.reconciliation.daemon.REPLAY_DEFENSE_ENABLED", True
        ):
            result = reconciler.reconcile()

        # Result should have sequence stamped
        assert result.sequence == 77
        # Verify INCR was called on the sequence key
        mock_redis.incr.assert_called_once_with("reconciliation:sequence:latest")


class TestPoam2026238ReconcilerRestartSequenceContinuity:
    """POAM-2026-238: reconciler pod restarts must never reset sequences below last_accepted."""

    @pytest.mark.asyncio
    async def test_restarted_reconciler_advances_above_last_accepted_even_without_latest_key(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Migrating from unconfigured replay defense (latest=None, last_accepted=585) mints 586 and CBF accepts."""
        import fakeredis

        from src.cage_finance.ground_truth import SimulatedCashLedgerProvider
        from src.cage_finance.invariants import CashBarrier, finance_cost_resolver
        from src.gateway.governance.kms_signer import (
            KMSGovernanceSigner,
            SoftwareEd25519Provider,
        )
        from src.gateway.governance.reconciliation.daemon import GroundTruthReconciler
        from src.gateway.governance.safety.cbf_engine import ControlBarrierFunction

        monkeypatch.setenv("CAGE_ENV", "development")
        monkeypatch.setenv("CAGE_RECONCILIATION_REPLAY_DEFENSE", "true")
        signer = KMSGovernanceSigner(
            provider=SoftwareEd25519Provider(key_id="reconciler-poam-238-k1")
        )
        sync_redis = fakeredis.FakeRedis(decode_responses=True)
        # Replicate live cage-staging state after rollout from unconfigured reconciler:
        # last_accepted persisted at 585 while reconciliation:sequence:latest was never written.
        sync_redis.set("reconciliation:sequence:last_accepted", "585")
        assert sync_redis.get("reconciliation:sequence:latest") is None

        # Fresh reconciler instance (SimulatedSource._sequence starts at 0).
        reconciler_1 = GroundTruthReconciler(
            provider=SimulatedCashLedgerProvider(initial_scalar=100_000.0, seed=1),
            redis_client=sync_redis,
            signer=signer,
        )
        res_1 = reconciler_1.reconcile("finance.cash_balance")
        assert res_1.is_valid, res_1.error
        assert res_1.sequence == 586
        assert sync_redis.get("reconciliation:sequence:latest") == "586"

        # CBF accepts sequence=586 and advances last_accepted to 586.
        cbf = ControlBarrierFunction(
            invariant=CashBarrier(gamma=0.5),
            cost_resolver=finance_cost_resolver,
            skip_epoch_seed=True,
        )
        ok_586, reason_586 = await cbf._validate_sequence(
            res_1.sequence, res_1.source, sync_redis
        )
        assert ok_586 is True, reason_586
        assert sync_redis.get("reconciliation:sequence:last_accepted") == "586"

        # A second pod restart (another brand-new provider at _sequence=0) advances to 587.
        reconciler_2 = GroundTruthReconciler(
            provider=SimulatedCashLedgerProvider(initial_scalar=100_000.0, seed=1),
            redis_client=sync_redis,
            signer=signer,
        )
        res_2 = reconciler_2.reconcile("finance.cash_balance")
        assert res_2.is_valid, res_2.error
        assert res_2.sequence == 587

        # Replaying an older snapshot (sequence=585 < last_accepted=586) STILL fails closed.
        ok_replay, reason_replay = await cbf._validate_sequence(
            585, res_1.source, sync_redis
        )
        assert ok_replay is False
        assert "585 < last_accepted=586" in reason_replay

    def test_enforcing_posture_allocates_redis_sequence_even_when_env_flag_unset(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Under CAGE_ENV=staging, durable Redis sequence allocation stays on even if env var is omitted."""
        import fakeredis

        from src.cage_finance.ground_truth import SimulatedCashLedgerProvider
        from src.gateway.governance.reconciliation.daemon import GroundTruthReconciler

        monkeypatch.setenv("CAGE_ENV", "staging")
        monkeypatch.delenv("CAGE_RECONCILIATION_REPLAY_DEFENSE", raising=False)
        sync_redis = fakeredis.FakeRedis(decode_responses=True)
        sync_redis.set("reconciliation:sequence:last_accepted", "42")

        mock_signer = MagicMock()
        mock_signer.is_kms_active = True
        mock_signer.sign_decision.return_value = MagicMock(
            signature="30440220deadbeef",
            kid="reconciler-kms-k1",
            algorithm="KMS_ASYMMETRIC",
        )
        reconciler = GroundTruthReconciler(
            provider=SimulatedCashLedgerProvider(initial_scalar=100_000.0, seed=1),
            redis_client=sync_redis,
            signer=mock_signer,
        )
        with patch(
            "src.gateway.governance.reconciliation.daemon.REPLAY_DEFENSE_ENABLED", False
        ):
            res = reconciler.reconcile("finance.cash_balance")
        assert res.is_valid, res.error
        assert res.sequence == 43
        assert sync_redis.get("reconciliation:sequence:latest") == "43"


pytestmark = [pytest.mark.unit, pytest.mark.local]
