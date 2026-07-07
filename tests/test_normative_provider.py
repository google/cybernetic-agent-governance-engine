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
test_normative_provider.py — Tests for §2.5 External Normative Provider Interface
==================================================================================

Tests the adaptive gating primitive, provider implementations, and daemon lifecycle.

Test Structure:
  - Stub Provider Tests: validate StubNormativeProvider returns local baselines
  - Adaptive Gating Tests: core enforce_fria_boundary() boundary conditions
  - Daemon Tests: boot_fetch + polling lifecycle
  - Integration Tests: default 'static' provider preserves existing behavior
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from src.gateway.governance.defer_queue import DeferReason
from src.gateway.governance.normative_provider import (
    EvidenceSeal,
    ExecutionStatus,
    FRIAEnforcementResult,
    NormativeBaseline,
    NormativeProviderDaemon,
    StubNormativeProvider,
    ValidationResult,
    enforce_fria_boundary,
    get_normative_provider,
)
from src.integrations.trustlayers import TrustLayersProvider

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def stub_provider() -> StubNormativeProvider:
    """Create a StubNormativeProvider."""
    return StubNormativeProvider()


@pytest.fixture
def mock_provider() -> AsyncMock:
    """Create a mock NormativeProvider for testing enforce_fria_boundary."""
    provider = AsyncMock()
    provider.validate_fria = AsyncMock(return_value=ValidationResult(admitted=True))
    provider.submit_evidence = AsyncMock(
        return_value=EvidenceSeal(thread_id="test-thread")
    )
    return provider


@pytest.fixture
def rejecting_provider() -> AsyncMock:
    """Provider that rejects FRIA validation."""
    provider = AsyncMock()
    provider.validate_fria = AsyncMock(
        return_value=ValidationResult(
            admitted=False,
            findings=[{"code": "FRIA-001", "message": "Missing fairness assessment"}],
        )
    )
    return provider


@pytest.fixture
def timeout_provider() -> AsyncMock:
    """Provider that times out on FRIA validation."""
    provider = AsyncMock()

    async def slow_validate(*args: Any, **kwargs: Any) -> ValidationResult:
        await asyncio.sleep(60)  # Will be cancelled by timeout
        return ValidationResult(admitted=True)

    provider.validate_fria = slow_validate
    return provider


@pytest.fixture
def action_context() -> dict[str, Any]:
    """Sample governance action context."""
    return {
        "action": "execute_trade",
        "symbol": "AAPL",
        "amount": 15000.0,
        "confidence": 0.92,
        "thread_id": "test-thread-001",
    }


@pytest.fixture
def mock_defer_queue() -> AsyncMock:
    """Mock DeferQueue for testing DEFER zone behavior."""
    queue = AsyncMock()
    queue.park = AsyncMock(return_value="mock-defer-id")
    queue.resolve = AsyncMock()
    return queue


# ---------------------------------------------------------------------------
# §1 — Stub Provider Tests
# ---------------------------------------------------------------------------


class TestStubNormativeProvider:
    """Tests for StubNormativeProvider (dev/CI mode)."""

    @pytest.mark.asyncio
    async def test_stub_returns_local_baseline(
        self, stub_provider: StubNormativeProvider
    ) -> None:
        """StubNormativeProvider reads from config/compliance/ and returns valid baseline."""
        baseline = await stub_provider.fetch_baseline("US_FED")
        # US_FED_BASELINE.json should exist in the repo
        assert baseline.is_valid, (
            f"Baseline should be valid but got error: {baseline.error}"
        )
        assert baseline.region == "US_FED"
        assert "CTRL_AGT_001" in baseline.profile

    @pytest.mark.asyncio
    async def test_stub_validate_fria_always_admits(
        self, stub_provider: StubNormativeProvider
    ) -> None:
        """Stub always returns admitted=True."""
        result = await stub_provider.validate_fria({"action": "test"})
        assert result.admitted is True
        assert result.error is None

    @pytest.mark.asyncio
    async def test_stub_evidence_seal_no_op(
        self, stub_provider: StubNormativeProvider
    ) -> None:
        """Stub returns seal with empty hash."""
        seal = await stub_provider.submit_evidence("thread-1", "abc123")
        assert seal.thread_id == "thread-1"
        assert seal.seal_hash == ""
        assert seal.error is None

    @pytest.mark.asyncio
    async def test_stub_missing_region_returns_error(
        self, stub_provider: StubNormativeProvider
    ) -> None:
        """Non-existent region returns NormativeBaseline with error."""
        baseline = await stub_provider.fetch_baseline("NONEXISTENT_REGION")
        assert not baseline.is_valid
        assert baseline.error is not None
        assert "not found" in baseline.error.lower()


# ---------------------------------------------------------------------------
# §2 — Adaptive Gating Tests (core)
# ---------------------------------------------------------------------------


class TestEnforceFRIABoundary:
    """Tests for enforce_fria_boundary() — the adaptive gating primitive."""

    @pytest.mark.asyncio
    async def test_high_confidence_async_attestation(
        self, mock_provider: AsyncMock, action_context: dict[str, Any]
    ) -> None:
        """Score ≥ 0.95 → ALLOW + ASYNC_ATTESTATION path (non-blocking)."""
        result = await enforce_fria_boundary(
            provider=mock_provider,
            action_context=action_context,
            consensus_score=0.98,
            thread_id="test-001",
        )

        assert result.status == ExecutionStatus.ALLOW
        assert result.path == "ASYNC_ATTESTATION"
        assert result.consensus_score == 0.98
        # The async task was dispatched but we don't block on it
        # Give it a moment to fire
        await asyncio.sleep(0.1)

    @pytest.mark.asyncio
    async def test_ambiguous_zone_sync_gate_admitted(
        self,
        mock_provider: AsyncMock,
        action_context: dict[str, Any],
        mock_defer_queue: AsyncMock,
    ) -> None:
        """Score in [0.70, 0.95) → DEFER → provider admits → ALLOW + SYNC_GATE_ADMITTED."""
        result = await enforce_fria_boundary(
            provider=mock_provider,
            action_context=action_context,
            consensus_score=0.85,
            defer_queue=mock_defer_queue,
            thread_id="test-002",
        )

        assert result.status == ExecutionStatus.ALLOW
        assert result.path == "SYNC_GATE_ADMITTED"
        assert result.consensus_score == 0.85
        assert result.validation is not None
        assert result.validation.admitted is True

        # Verify DEFER queue was used
        mock_defer_queue.park.assert_called_once()
        mock_defer_queue.resolve.assert_called_once()
        # Verify resolution was INJECTED (admitted)
        resolve_args = mock_defer_queue.resolve.call_args
        assert resolve_args[0][1] == "INJECTED"

    @pytest.mark.asyncio
    async def test_ambiguous_zone_sync_gate_rejected(
        self,
        rejecting_provider: AsyncMock,
        action_context: dict[str, Any],
        mock_defer_queue: AsyncMock,
    ) -> None:
        """Score in [0.70, 0.95) → DEFER → provider rejects → DENY + SYNC_GATE_REJECTED."""
        result = await enforce_fria_boundary(
            provider=rejecting_provider,
            action_context=action_context,
            consensus_score=0.85,
            defer_queue=mock_defer_queue,
            thread_id="test-003",
        )

        assert result.status == ExecutionStatus.DENY
        assert result.path == "SYNC_GATE_REJECTED"
        assert result.validation is not None
        assert result.validation.admitted is False
        assert len(result.validation.findings) == 1

        # Verify resolution was ESCALATED (rejected)
        resolve_args = mock_defer_queue.resolve.call_args
        assert resolve_args[0][1] == "ESCALATED"

    @pytest.mark.asyncio
    async def test_ambiguous_zone_timeout_fails_closed(
        self,
        timeout_provider: AsyncMock,
        action_context: dict[str, Any],
        mock_defer_queue: AsyncMock,
    ) -> None:
        """Score in [0.70, 0.95) → provider times out → DENY + SYNC_GATE_TIMEOUT."""
        with patch.dict(os.environ, {"CAGE_NORMATIVE_GATE_TIMEOUT_SECONDS": "0.1"}):
            result = await enforce_fria_boundary(
                provider=timeout_provider,
                action_context=action_context,
                consensus_score=0.85,
                defer_queue=mock_defer_queue,
                thread_id="test-004",
            )

        assert result.status == ExecutionStatus.DENY
        assert result.path == "SYNC_GATE_TIMEOUT"

        # Verify resolution was EXPIRED (timeout)
        resolve_args = mock_defer_queue.resolve.call_args
        assert resolve_args[0][1] == "EXPIRED"

    @pytest.mark.asyncio
    async def test_low_confidence_hard_deny(
        self, mock_provider: AsyncMock, action_context: dict[str, Any]
    ) -> None:
        """Score < 0.70 → DENY + LOCAL_HARD_DENY, no HTTP call made."""
        result = await enforce_fria_boundary(
            provider=mock_provider,
            action_context=action_context,
            consensus_score=0.55,
            thread_id="test-005",
        )

        assert result.status == ExecutionStatus.DENY
        assert result.path == "LOCAL_HARD_DENY"
        assert result.consensus_score == 0.55
        # Provider should NOT have been called
        mock_provider.validate_fria.assert_not_called()

    @pytest.mark.asyncio
    async def test_boundary_095_exact(
        self, mock_provider: AsyncMock, action_context: dict[str, Any]
    ) -> None:
        """Score = 0.95 exactly → ALLOW (async path)."""
        result = await enforce_fria_boundary(
            provider=mock_provider,
            action_context=action_context,
            consensus_score=0.95,
            thread_id="test-006",
        )

        assert result.status == ExecutionStatus.ALLOW
        assert result.path == "ASYNC_ATTESTATION"

    @pytest.mark.asyncio
    async def test_boundary_070_exact(
        self, mock_provider: AsyncMock, action_context: dict[str, Any]
    ) -> None:
        """Score = 0.70 exactly → DEFER (sync gate)."""
        result = await enforce_fria_boundary(
            provider=mock_provider,
            action_context=action_context,
            consensus_score=0.70,
            thread_id="test-007",
        )

        assert result.status == ExecutionStatus.ALLOW
        assert result.path == "SYNC_GATE_ADMITTED"

    @pytest.mark.asyncio
    async def test_boundary_069_deny(
        self, mock_provider: AsyncMock, action_context: dict[str, Any]
    ) -> None:
        """Score = 0.69 → DENY (hard deny)."""
        result = await enforce_fria_boundary(
            provider=mock_provider,
            action_context=action_context,
            consensus_score=0.69,
            thread_id="test-008",
        )

        assert result.status == ExecutionStatus.DENY
        assert result.path == "LOCAL_HARD_DENY"
        mock_provider.validate_fria.assert_not_called()


# ---------------------------------------------------------------------------
# §3 — Daemon Tests
# ---------------------------------------------------------------------------


class TestNormativeProviderDaemon:
    """Tests for NormativeProviderDaemon lifecycle."""

    @pytest.mark.asyncio
    async def test_boot_fetch_writes_and_reconfigures(self, tmp_path: Path) -> None:
        """Daemon.boot_fetch() writes profile to disk and calls ControlRegistry.reconfigure()."""
        provider = AsyncMock()
        provider.fetch_baseline = AsyncMock(
            return_value=NormativeBaseline(
                region="US_FED",
                profile={"CTRL_AGT_001": {"internal_id": "THR-CONF-001"}},
            )
        )

        daemon = NormativeProviderDaemon(
            provider=provider,
            region="US_FED",
            boot_timeout=5.0,
        )

        with (
            patch(
                "src.gateway.governance.normative_provider._COMPLIANCE_DIR", tmp_path
            ),
            patch(
                "src.gateway.governance.normative_provider.NormativeProviderDaemon._reconfigure_registry"
            ) as mock_reconfig,
        ):
            await daemon.boot_fetch()

            # Profile should be written to disk
            profile_path = tmp_path / "US_FED_BASELINE.json"
            assert profile_path.exists()
            with open(profile_path) as fh:
                written = json.load(fh)
            assert "CTRL_AGT_001" in written

            # Registry should be reconfigured
            mock_reconfig.assert_called_once()

    @pytest.mark.asyncio
    async def test_boot_fetch_fallback_on_failure(self, tmp_path: Path) -> None:
        """Provider unreachable → falls back to cached local copy."""
        # Create a cached profile
        profile_path = tmp_path / "US_FED_BASELINE.json"
        profile_path.write_text(json.dumps({"CTRL_AGT_001": {"cached": True}}))

        provider = AsyncMock()
        provider.fetch_baseline = AsyncMock(
            return_value=NormativeBaseline(
                region="US_FED", profile={}, error="Connection refused"
            )
        )

        daemon = NormativeProviderDaemon(
            provider=provider,
            region="US_FED",
            boot_timeout=5.0,
        )

        with patch(
            "src.gateway.governance.normative_provider._COMPLIANCE_DIR", tmp_path
        ):
            # Should NOT raise — falls back to cached copy
            await daemon.boot_fetch()

    @pytest.mark.asyncio
    async def test_boot_fetch_no_fallback_raises(self, tmp_path: Path) -> None:
        """No profile anywhere → RuntimeError."""
        provider = AsyncMock()
        provider.fetch_baseline = AsyncMock(
            return_value=NormativeBaseline(
                region="US_FED", profile={}, error="Connection refused"
            )
        )

        daemon = NormativeProviderDaemon(
            provider=provider,
            region="US_FED",
            boot_timeout=5.0,
        )

        with patch(
            "src.gateway.governance.normative_provider._COMPLIANCE_DIR", tmp_path
        ):
            with pytest.raises(RuntimeError, match="No normative baseline available"):
                await daemon.boot_fetch()

    @pytest.mark.asyncio
    async def test_polling_detects_etag_change(self, tmp_path: Path) -> None:
        """Changed baseline triggers reconfigure; unchanged is no-op."""
        call_count = 0

        async def changing_baseline(region: str) -> NormativeBaseline:
            nonlocal call_count
            call_count += 1
            return NormativeBaseline(
                region=region,
                profile={"CTRL_AGT_001": {"version": call_count}},
            )

        provider = AsyncMock()
        provider.fetch_baseline = changing_baseline

        daemon = NormativeProviderDaemon(
            provider=provider,
            region="US_FED",
            poll_interval=0.1,  # 100ms for test speed
        )
        daemon._last_hash = "initial-hash"

        with (
            patch(
                "src.gateway.governance.normative_provider._COMPLIANCE_DIR", tmp_path
            ),
            patch(
                "src.gateway.governance.normative_provider.NormativeProviderDaemon._reconfigure_registry"
            ) as mock_reconfig,
        ):
            # Run polling for a brief moment
            task = asyncio.create_task(daemon.start_polling())
            await asyncio.sleep(0.35)  # Should get ~2 poll cycles
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

            # Should have reconfigured at least once (hash changed from initial)
            assert mock_reconfig.call_count >= 1


# ---------------------------------------------------------------------------
# §4 — Integration / Regression Tests
# ---------------------------------------------------------------------------


class TestProviderFactory:
    """Tests for get_normative_provider() factory."""

    def test_provider_factory_maps_static(self) -> None:
        """get_normative_provider('static') returns StubNormativeProvider."""
        provider = get_normative_provider("static")
        assert isinstance(provider, StubNormativeProvider)

    def test_provider_factory_maps_trustlayers(self) -> None:
        """get_normative_provider('trustlayers') returns TrustLayersProvider."""
        provider = get_normative_provider("trustlayers")
        assert isinstance(provider, TrustLayersProvider)

    def test_provider_factory_unknown_raises(self) -> None:
        """Unknown provider name raises ValueError."""
        with pytest.raises(ValueError, match="Unknown normative provider"):
            get_normative_provider("nonexistent")

    def test_provider_factory_reads_env_var(self) -> None:
        """Factory reads from CAGE_NORMATIVE_PROVIDER env var."""
        with patch.dict(os.environ, {"CAGE_NORMATIVE_PROVIDER": "static"}):
            provider = get_normative_provider()
            assert isinstance(provider, StubNormativeProvider)


class TestTrustLayersProvider:
    """Tests for TrustLayersProvider URL construction."""

    def test_constructs_correct_baseline_url(self) -> None:
        """TrustLayersProvider builds correct endpoint URL for baseline fetch."""
        provider = TrustLayersProvider(endpoint="https://api.trustlayers.example.com")
        # Verify endpoint is stored correctly (URL construction tested via fetch)
        assert provider._endpoint == "https://api.trustlayers.example.com"

    def test_strips_trailing_slash(self) -> None:
        """Endpoint trailing slash is stripped."""
        provider = TrustLayersProvider(endpoint="https://api.trustlayers.example.com/")
        assert provider._endpoint == "https://api.trustlayers.example.com"


class TestDeferReasonExternalValidation:
    """Test that EXTERNAL_VALIDATION DeferReason is properly registered."""

    def test_external_validation_enum_exists(self) -> None:
        """DeferReason.EXTERNAL_VALIDATION is a valid enum member."""
        assert DeferReason.EXTERNAL_VALIDATION.value == "EXTERNAL_VALIDATION"

    def test_external_validation_in_enum_members(self) -> None:
        """EXTERNAL_VALIDATION appears in DeferReason members list."""
        assert "EXTERNAL_VALIDATION" in [r.value for r in DeferReason]


class TestDataContracts:
    """Tests for data contract validity and behavior."""

    def test_normative_baseline_validity(self) -> None:
        """Valid baseline has no error and non-empty profile."""
        baseline = NormativeBaseline(region="US_FED", profile={"key": "val"})
        assert baseline.is_valid

    def test_normative_baseline_invalid_on_error(self) -> None:
        """Baseline with error is not valid."""
        baseline = NormativeBaseline(region="US_FED", profile={}, error="fail")
        assert not baseline.is_valid

    def test_normative_baseline_invalid_on_empty_profile(self) -> None:
        """Baseline with empty profile is not valid."""
        baseline = NormativeBaseline(region="US_FED", profile={})
        assert not baseline.is_valid

    def test_normative_baseline_profile_hash_deterministic(self) -> None:
        """Same profile produces same hash."""
        b1 = NormativeBaseline(region="US_FED", profile={"a": 1, "b": 2})
        b2 = NormativeBaseline(region="US_FED", profile={"b": 2, "a": 1})
        assert b1.profile_hash == b2.profile_hash

    def test_fria_enforcement_result_fields(self) -> None:
        """FRIAEnforcementResult stores all fields."""
        result = FRIAEnforcementResult(
            status=ExecutionStatus.ALLOW,
            path="ASYNC_ATTESTATION",
            consensus_score=0.98,
        )
        assert result.status == ExecutionStatus.ALLOW
        assert result.path == "ASYNC_ATTESTATION"
        assert result.consensus_score == 0.98
        assert result.validation is None
