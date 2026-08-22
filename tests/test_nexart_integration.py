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
tests/test_nexart_integration.py
=================================
Hermetic unit tests for src/integrations/nexart/adapter.py and
src/integrations/nexart/provider.py.

Gap 6: Both nexart adapter and provider are functionally untested.
These tests exercise public APIs, data contracts, and logic branches
without making live HTTP calls (all network I/O is mocked).

Marks
-----
- ``local`` : safe to run with no live services (CI default)
"""

from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]

# ---------------------------------------------------------------------------
# Tests: adapter.py — data contracts and helper functions
# ---------------------------------------------------------------------------


@pytest.mark.local
class TestProjectBundleStepEntry:
    """Tests for the ProjectBundleStepEntry dataclass."""

    def test_step_entry_auto_generates_step_id(self) -> None:
        """ProjectBundleStepEntry must auto-generate a UUID step_id."""
        from src.integrations.nexart.adapter import ProjectBundleStepEntry

        entry = ProjectBundleStepEntry(node_name="evaluator")
        assert entry.step_id, "step_id must be non-empty"
        # Must be a valid UUID
        parsed = uuid.UUID(entry.step_id)
        assert str(parsed) == entry.step_id, "step_id must be a valid UUID string"

    def test_step_entry_to_dict_contains_all_keys(self) -> None:
        """ProjectBundleStepEntry.to_dict() must contain all NexArt API keys."""
        from src.integrations.nexart.adapter import ProjectBundleStepEntry

        entry = ProjectBundleStepEntry(
            node_name="safety_check",
            parent_step_ids=["parent-id-1"],
            timestamp_utc="2026-01-01T00:00:00+00:00",
            duration_ms=42.5,
            signals={"safetyStatus": "APPROVED"},
            state_hash="a" * 64,
        )
        d = entry.to_dict()

        assert "stepId" in d, "to_dict() must contain 'stepId'"
        assert "nodeName" in d, "to_dict() must contain 'nodeName'"
        assert "parentStepIds" in d, "to_dict() must contain 'parentStepIds'"
        assert "timestampUtc" in d, "to_dict() must contain 'timestampUtc'"
        assert "durationMs" in d, "to_dict() must contain 'durationMs'"
        assert "signals" in d, "to_dict() must contain 'signals'"
        assert "stateHash" in d, "to_dict() must contain 'stateHash'"

    def test_step_entry_to_dict_values_match(self) -> None:
        """ProjectBundleStepEntry.to_dict() values must match field values."""
        from src.integrations.nexart.adapter import ProjectBundleStepEntry

        entry = ProjectBundleStepEntry(
            node_name="governed_trader",
            parent_step_ids=["pid-a", "pid-b"],
            duration_ms=99.9,
        )
        d = entry.to_dict()

        assert d["nodeName"] == "governed_trader"
        assert d["parentStepIds"] == ["pid-a", "pid-b"]
        assert d["durationMs"] == 99.9

    def test_step_entry_default_parent_step_ids_is_empty_list(self) -> None:
        """ProjectBundleStepEntry.parent_step_ids defaults to empty list."""
        from src.integrations.nexart.adapter import ProjectBundleStepEntry

        entry = ProjectBundleStepEntry(node_name="nemo_guardrail")
        assert entry.parent_step_ids == [], "parent_step_ids must default to empty list"


@pytest.mark.local
class TestAttestationBundle:
    """Tests for the AttestationBundle dataclass."""

    def test_bundle_auto_generates_bundle_id(self) -> None:
        """AttestationBundle must auto-generate a UUID bundle_id."""
        from src.integrations.nexart.adapter import AttestationBundle

        bundle = AttestationBundle(thread_id="thread-001")
        assert bundle.bundle_id, "bundle_id must be non-empty"
        parsed = uuid.UUID(bundle.bundle_id)
        assert str(parsed) == bundle.bundle_id, "bundle_id must be a valid UUID"

    def test_bundle_to_dict_structure(self) -> None:
        """AttestationBundle.to_dict() must contain all required NexArt API keys."""
        from src.integrations.nexart.adapter import (
            AttestationBundle,
            ProjectBundleStepEntry,
        )

        step = ProjectBundleStepEntry(node_name="evaluator")
        bundle = AttestationBundle(
            thread_id="thread-123",
            steps=[step],
            started_at="2026-01-01T00:00:00+00:00",
            completed_at="2026-01-01T00:01:00+00:00",
            terminal_path="happy_path",
        )
        d = bundle.to_dict()

        assert "bundleId" in d
        assert "threadId" in d
        assert "steps" in d
        assert "startedAt" in d
        assert "completedAt" in d
        assert "terminalPath" in d

    def test_bundle_to_dict_serializes_steps(self) -> None:
        """AttestationBundle.to_dict() must serialize nested steps."""
        from src.integrations.nexart.adapter import (
            AttestationBundle,
            ProjectBundleStepEntry,
        )

        step1 = ProjectBundleStepEntry(node_name="nemo_guardrail")
        step2 = ProjectBundleStepEntry(node_name="evaluator")
        bundle = AttestationBundle(thread_id="t", steps=[step1, step2])
        d = bundle.to_dict()

        assert isinstance(d["steps"], list), "steps must be a list"
        assert len(d["steps"]) == 2, "steps list must contain 2 entries"
        assert d["steps"][0]["nodeName"] == "nemo_guardrail"
        assert d["steps"][1]["nodeName"] == "evaluator"


@pytest.mark.local
class TestHelperFunctions:
    """Tests for adapter module helper functions."""

    def test_serialize_state_snapshot_deep_copies_state(self) -> None:
        """_serialize_state_snapshot must return an independent deep copy."""
        from src.integrations.nexart.adapter import _serialize_state_snapshot

        original = {"risk_status": "APPROVED", "loop_count": 1}
        snapshot = _serialize_state_snapshot(original)

        # Modifying the copy must not affect the original
        snapshot["risk_status"] = "MODIFIED"
        assert original["risk_status"] == "APPROVED", (
            "_serialize_state_snapshot must deep-copy; original was mutated"
        )

    def test_serialize_state_snapshot_drops_completed_transactions(self) -> None:
        """_serialize_state_snapshot must drop completed_transactions."""
        from src.integrations.nexart.adapter import _serialize_state_snapshot

        state = {
            "risk_status": "APPROVED",
            "completed_transactions": [{"seq": 0, "status": "COMPLETED"}],
        }
        snapshot = _serialize_state_snapshot(state)
        assert "completed_transactions" not in snapshot, (
            "completed_transactions must be removed from the snapshot"
        )

    def test_hash_state_is_deterministic(self) -> None:
        """_hash_state must produce the same hash for identical state."""
        from src.integrations.nexart.adapter import _hash_state

        state = {"risk_status": "APPROVED", "loop_count": 1}
        hash1 = _hash_state(state)
        hash2 = _hash_state(state)
        assert hash1 == hash2, "_hash_state must be deterministic"
        assert len(hash1) == 64, "SHA-256 hex digest must be 64 chars"

    def test_hash_state_differs_for_different_states(self) -> None:
        """_hash_state must produce different hashes for different states."""
        from src.integrations.nexart.adapter import _hash_state

        state_a = {"risk_status": "APPROVED"}
        state_b = {"risk_status": "REJECTED"}
        assert _hash_state(state_a) != _hash_state(state_b), (
            "Different states must produce different hashes"
        )

    def test_extract_signals_guardrail_blocked(self) -> None:
        """_extract_signals must capture guardrail_blocked and guardrail_reason."""
        from src.integrations.nexart.adapter import _extract_signals

        state = {
            "guardrail_blocked": True,
            "guardrail_reason": "Prompt injection detected",
        }
        signals = _extract_signals("nemo_guardrail", state)
        assert signals.get("guardrailBlocked") is True
        assert signals.get("guardrailReason") == "Prompt injection detected"

    def test_extract_signals_evaluation_result(self) -> None:
        """_extract_signals must extract evaluation verdict and policy check."""
        from src.integrations.nexart.adapter import _extract_signals

        state = {
            "evaluation_result": {
                "verdict": "APPROVED",
                "reasoning": "All checks passed",
                "policy_check": "PASSED",
            }
        }
        signals = _extract_signals("evaluator", state)
        assert signals.get("evaluationVerdict") == "APPROVED"
        assert signals.get("policyCheck") == "PASSED"

    def test_classify_terminal_path_happy_path(self) -> None:
        """_classify_terminal_path must return 'happy_path' when governed_trader present."""
        from src.integrations.nexart.adapter import (
            ProjectBundleStepEntry,
            _classify_terminal_path,
        )

        steps = [
            ProjectBundleStepEntry(node_name="nemo_guardrail"),
            ProjectBundleStepEntry(node_name="evaluator"),
            ProjectBundleStepEntry(node_name="governed_trader"),
            ProjectBundleStepEntry(node_name="explainer"),
        ]
        result = _classify_terminal_path(steps)
        assert result == "happy_path", (
            f"Expected 'happy_path' when governed_trader present, got {result!r}"
        )

    def test_classify_terminal_path_cbf_block(self) -> None:
        """_classify_terminal_path must return 'cbf_block' on BLOCKED safety_check."""
        from src.integrations.nexart.adapter import (
            ProjectBundleStepEntry,
            _classify_terminal_path,
        )

        steps = [
            ProjectBundleStepEntry(node_name="evaluator"),
            ProjectBundleStepEntry(
                node_name="safety_check",
                signals={"safetyStatus": "BLOCKED"},
            ),
            ProjectBundleStepEntry(node_name="explainer"),
        ]
        result = _classify_terminal_path(steps)
        assert result == "cbf_block", (
            f"Expected 'cbf_block' for BLOCKED safety_check, got {result!r}"
        )

    def test_classify_terminal_path_loop_breaker(self) -> None:
        """_classify_terminal_path returns 'loop_breaker' when loopCount >= 3."""
        from src.integrations.nexart.adapter import (
            ProjectBundleStepEntry,
            _classify_terminal_path,
        )

        steps = [
            ProjectBundleStepEntry(
                node_name="evaluator",
                signals={"loopCount": 3},
            ),
            ProjectBundleStepEntry(node_name="explainer"),
        ]
        result = _classify_terminal_path(steps)
        assert result == "loop_breaker", (
            f"Expected 'loop_breaker' for loopCount >= 3, got {result!r}"
        )


@pytest.mark.local
class TestNexArtAttestationCallback:
    """Tests for NexArtAttestationCallback lifecycle and step recording."""

    def test_callback_initialises_with_thread_id(self) -> None:
        """NexArtAttestationCallback must store the provided thread_id."""
        from src.integrations.nexart.adapter import NexArtAttestationCallback

        cb = NexArtAttestationCallback(thread_id="thread-abc")
        assert cb._thread_id == "thread-abc"

    def test_callback_auto_generates_thread_id_when_not_provided(self) -> None:
        """NexArtAttestationCallback must auto-generate a thread_id when not given."""
        from src.integrations.nexart.adapter import NexArtAttestationCallback

        cb = NexArtAttestationCallback()
        assert cb._thread_id, "thread_id must be auto-generated"
        parsed = uuid.UUID(cb._thread_id)
        assert str(parsed) == cb._thread_id

    def test_callback_step_count_starts_at_zero(self) -> None:
        """step_count property must return 0 before any node events."""
        from src.integrations.nexart.adapter import NexArtAttestationCallback

        cb = NexArtAttestationCallback(thread_id="t")
        assert cb.step_count == 0

    def test_on_chain_end_records_attestation_nodes(self) -> None:
        """on_chain_end must record a step for governance-significant nodes."""
        from src.integrations.nexart.adapter import NexArtAttestationCallback

        cb = NexArtAttestationCallback(thread_id="t")
        cb.on_chain_start("evaluator", {})
        cb.on_chain_end("evaluator", {"risk_status": "APPROVED"})

        assert cb.step_count == 1, (
            f"Expected step_count=1 after evaluator, got {cb.step_count}"
        )

    def test_on_chain_end_skips_non_attestation_nodes(self) -> None:
        """on_chain_end must not record a step for non-significant nodes."""
        from src.integrations.nexart.adapter import NexArtAttestationCallback

        cb = NexArtAttestationCallback(thread_id="t")
        cb.on_chain_end("thinker_node", {"some": "state"})

        assert cb.step_count == 0, (
            f"Expected step_count=0 for thinker_node, got {cb.step_count}"
        )

    def test_get_bundle_returns_attestation_bundle(self) -> None:
        """get_bundle() must return an AttestationBundle with collected steps."""
        from src.integrations.nexart.adapter import (
            AttestationBundle,
            NexArtAttestationCallback,
        )

        cb = NexArtAttestationCallback(thread_id="t")
        cb.on_chain_start("evaluator", {})
        cb.on_chain_end("evaluator", {"risk_status": "APPROVED"})

        bundle = cb.get_bundle()
        assert isinstance(bundle, AttestationBundle), (
            "get_bundle() must return an AttestationBundle"
        )
        assert bundle.thread_id == "t"
        assert len(bundle.steps) == 1

    def test_hitl_interrupt_records_interrupt_step(self) -> None:
        """handle_hitl_interrupt() must record a hitl_interrupt step."""
        from src.integrations.nexart.adapter import NexArtAttestationCallback

        cb = NexArtAttestationCallback(thread_id="t")
        state = {
            "approval_required": True,
            "approval_decision": {
                "approved": None,
                "reviewer": "human-reviewer",
                "rationale": "Pending review",
                "timestamp": "2026-01-01T00:00:00+00:00",
            },
        }
        cb.handle_hitl_interrupt(state)

        assert cb.step_count == 1, (
            f"Expected step_count=1 after HITL interrupt, got {cb.step_count}"
        )
        step = cb._steps[0]
        assert step.node_name == "hitl_interrupt"
        assert step.signals.get("interruptType") == "HITL_MANUAL_REVIEW"


# ---------------------------------------------------------------------------
# Tests: provider.py — CERReceipt, CERVerification, JWKCache, NexArtAttestationProvider
# ---------------------------------------------------------------------------


@pytest.mark.local
class TestProviderDataContracts:
    """Tests for provider.py data contract dataclasses."""

    def test_cer_receipt_is_valid_when_hash_present(self) -> None:
        """CERReceipt.is_valid must be True when certificate_hash is set and no error."""
        from src.integrations.nexart.provider import CERReceipt

        receipt = CERReceipt(
            certificate_hash="a" * 64,
            receipt_url="https://nexart.example.com/cer/abc",
            signer_key_id="kid-1",
            signed_at="2026-01-01T00:00:00+00:00",
        )
        assert receipt.is_valid is True, (
            "CERReceipt must be valid when hash and no error"
        )

    def test_cer_receipt_is_invalid_when_error_set(self) -> None:
        """CERReceipt.is_valid must be False when error is set."""
        from src.integrations.nexart.provider import CERReceipt

        receipt = CERReceipt(error="HTTP 503 Service Unavailable")
        assert receipt.is_valid is False, "CERReceipt must be invalid when error is set"

    def test_cer_receipt_is_invalid_when_hash_empty(self) -> None:
        """CERReceipt.is_valid must be False when certificate_hash is empty."""
        from src.integrations.nexart.provider import CERReceipt

        receipt = CERReceipt(certificate_hash="")
        assert receipt.is_valid is False, (
            "CERReceipt must be invalid when hash is empty"
        )

    def test_jwk_cache_is_stale_when_never_synced(self) -> None:
        """JWKCache.is_stale must be True when last_synced=0."""
        from src.integrations.nexart.provider import JWKCache

        cache = JWKCache()
        assert cache.is_stale is True, "Fresh JWKCache must be stale (last_synced=0)"

    def test_jwk_cache_has_keys_false_when_empty(self) -> None:
        """JWKCache.has_keys must be False when no keys loaded."""
        from src.integrations.nexart.provider import JWKCache

        cache = JWKCache()
        assert cache.has_keys is False, "JWKCache.has_keys must be False when empty"

    def test_jwk_cache_has_keys_true_when_populated(self) -> None:
        """JWKCache.has_keys must be True when keys list is non-empty."""
        from src.integrations.nexart.provider import JWKCache

        cache = JWKCache(
            jwk_set={"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": "key-1"}]},
            last_synced=time.time(),
        )
        assert cache.has_keys is True, "JWKCache.has_keys must be True with loaded keys"


@pytest.mark.local
class TestNexArtAttestationProvider:
    """Tests for NexArtAttestationProvider (hermetic — all HTTP mocked)."""

    def test_provider_initialises_without_endpoint(self) -> None:
        """NexArtAttestationProvider must initialise without crashing even if endpoint is unset."""
        from src.integrations.nexart.provider import NexArtAttestationProvider

        # No env vars set — should not raise
        provider = NexArtAttestationProvider(endpoint="", api_key="")
        assert provider is not None

    def test_provider_has_no_jwk_keys_initially(self) -> None:
        """Provider must report has_jwk_keys=False before any sync."""
        from src.integrations.nexart.provider import NexArtAttestationProvider

        provider = NexArtAttestationProvider(endpoint="https://nexart.example.com")
        assert provider.has_jwk_keys is False

    def test_provider_jwk_cache_age_is_inf_before_sync(self) -> None:
        """jwk_cache_age_seconds must be inf before any sync."""
        from src.integrations.nexart.provider import NexArtAttestationProvider

        provider = NexArtAttestationProvider()
        assert provider.jwk_cache_age_seconds == float("inf"), (
            "jwk_cache_age_seconds must be inf before sync"
        )

    def test_verify_local_fails_with_wrong_hash_length(self) -> None:
        """_verify_local must return invalid when certificate_hash length != 64."""
        from src.integrations.nexart.provider import JWKCache, NexArtAttestationProvider

        provider = NexArtAttestationProvider(endpoint="https://nexart.example.com")
        # Inject a fake JWK cache so the local path is taken
        provider._jwk_cache = JWKCache(
            jwk_set={"keys": [{"kid": "k1"}]},
            last_synced=time.time(),
        )

        result = provider._verify_local("short-hash")
        assert result.valid is False, "Verification must fail for wrong hash length"
        assert result.error is not None, "Error message must be set"

    def test_verify_local_returns_valid_for_correct_hash_length(self) -> None:
        """_verify_local must return valid when certificate_hash is 64 chars."""
        from src.integrations.nexart.provider import JWKCache, NexArtAttestationProvider

        provider = NexArtAttestationProvider(endpoint="https://nexart.example.com")
        provider._jwk_cache = JWKCache(
            jwk_set={"keys": [{"kid": "k1"}]},
            last_synced=time.time(),
        )

        result = provider._verify_local("a" * 64)
        assert result.valid is True, (
            "Verification must succeed for a 64-char hash with populated JWK cache"
        )

    @pytest.mark.asyncio
    async def test_certify_decision_returns_error_receipt_on_http_failure(self) -> None:
        """certify_decision() must return a CERReceipt with error on HTTP failure."""
        from src.integrations.nexart.provider import NexArtAttestationProvider

        provider = NexArtAttestationProvider(endpoint="https://nexart.example.com")

        # Patch httpx to raise a connection error
        import httpx

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(side_effect=httpx.ConnectError("refused"))
            mock_client_cls.return_value = mock_client

            receipt = await provider.certify_decision({"signals": {}})

        assert receipt.is_valid is False, "Receipt must be invalid on HTTP failure"
        assert receipt.error is not None, "Error field must be set on HTTP failure"

    @pytest.mark.asyncio
    async def test_register_project_bundle_returns_error_on_failure(self) -> None:
        """register_project_bundle() must return error dict on HTTP failure."""
        from src.integrations.nexart.provider import NexArtAttestationProvider

        provider = NexArtAttestationProvider(endpoint="https://nexart.example.com")

        import httpx

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(side_effect=httpx.TimeoutException("timeout"))
            mock_client_cls.return_value = mock_client

            result = await provider.register_project_bundle({"bundleId": "b1"})

        assert "error" in result, (
            "register_project_bundle must return an error dict on HTTP failure"
        )

    def test_get_nexart_provider_returns_singleton(self) -> None:
        """get_nexart_provider() must return the same instance on repeated calls."""
        from src.integrations.nexart import provider as provider_module

        # Reset singleton for clean test
        provider_module._provider = None

        p1 = provider_module.get_nexart_provider()
        p2 = provider_module.get_nexart_provider()
        assert p1 is p2, "get_nexart_provider() must return a singleton instance"

        # Cleanup
        provider_module._provider = None
