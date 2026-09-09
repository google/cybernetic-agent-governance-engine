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
Test suite for A2 + A3: Full RefusalReceipt and PauseReceipt ingestion.

Verifies that the evidence stream receives the complete v3 receipt with
tier_failures, 5-part proof chain, and computed proof_hash intact.
"""

import pytest

from src.gateway.governance.contracts import (
    GovernanceTierFailure,
    PauseReceipt,
    RefusalReceipt,
)
from src.gateway.server.governance_middleware import (
    _emit_pause_receipt,
    _emit_refusal_receipt,
    _serialize_receipt,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]


class TestSerializeReceipt:
    """Test the _serialize_receipt helper that preserves proof_hash."""

    def test_serialize_refusal_receipt_preserves_proof_hash(self):
        """A2 requirement: proof_hash is preserved exactly as computed."""
        tier_failure = GovernanceTierFailure(
            tier="CBF",
            control_id="CAGE-CTRL-001",
            rule_description="Cash balance below threshold",
            governing_state={"balance": 1000.0, "threshold": 5000.0},
            protected_consequence="trade_rejection",
        )
        receipt = RefusalReceipt(
            thread_id="test-thread-123",
            action="execute_trade",
            violated_tier="CBF",
            violated_rule="Cash balance below threshold",
            standing_at_refusal={"balance": 1000.0},
            schema_version="v3",
            attempted_params={"symbol": "AAPL", "amount": 10000.0},
            standing_snapshot={"balance": 1000.0},
            control_id="CAGE-CTRL-001",
            protected_consequence="trade_rejection",
            non_formation_proof="action_blocked_pre_commit",
            tier_failures=(tier_failure,),
        )

        # The receipt computes proof_hash in __post_init__
        original_proof_hash = receipt.proof_hash
        assert original_proof_hash != "", "Receipt should have computed proof_hash"

        # Serialize it
        serialized = _serialize_receipt(receipt)

        # Verify proof_hash is byte-identical to the computed value
        assert serialized["proof_hash"] == original_proof_hash
        assert serialized["schema_version"] == "v3"
        assert serialized["thread_id"] == "test-thread-123"
        assert serialized["action"] == "execute_trade"

    def test_serialize_preserves_tier_failures(self):
        """A2 requirement: tier_failures survive serialization."""
        tier_failure = GovernanceTierFailure(
            tier="OPA",
            control_id="CAGE-CTRL-002",
            rule_description="Fiscal limit exceeded",
            governing_state={"limit": 50000.0, "attempted": 75000.0},
            protected_consequence="budget_violation",
        )
        receipt = RefusalReceipt(
            thread_id="test-thread-456",
            action="execute_trade",
            violated_tier="OPA",
            violated_rule="Fiscal limit exceeded",
            tier_failures=(tier_failure,),
        )

        serialized = _serialize_receipt(receipt)

        assert "tier_failures" in serialized
        assert len(serialized["tier_failures"]) == 1
        tf = serialized["tier_failures"][0]
        assert tf["tier"] == "OPA"
        assert tf["control_id"] == "CAGE-CTRL-002"
        assert tf["rule_description"] == "Fiscal limit exceeded"
        assert tf["governing_state"]["limit"] == 50000.0
        assert tf["protected_consequence"] == "budget_violation"

    def test_serialize_five_part_proof_chain(self):
        """A2 requirement: 5-part proof chain fields survive serialization."""
        receipt = RefusalReceipt(
            thread_id="test-thread-789",
            action="execute_trade",
            violated_tier="CBF",
            violated_rule="Test rule",
            schema_version="v2",
            attempted_params={"symbol": "MSFT", "amount": 5000.0},
            standing_snapshot={"balance": 2000.0, "committed": 1000.0},
            control_id="CAGE-CTRL-003",
            protected_consequence="overdraft_prevention",
            non_formation_proof="cbf_barrier_active",
        )

        serialized = _serialize_receipt(receipt)

        # Verify all 5 parts are present
        assert serialized["attempted_params"] == {"symbol": "MSFT", "amount": 5000.0}
        assert serialized["standing_snapshot"] == {
            "balance": 2000.0,
            "committed": 1000.0,
        }
        assert serialized["control_id"] == "CAGE-CTRL-003"
        assert serialized["protected_consequence"] == "overdraft_prevention"
        assert serialized["non_formation_proof"] == "cbf_barrier_active"

    def test_serialize_pause_receipt_preserves_proof_hash(self):
        """A3 requirement: PauseReceipt proof_hash is preserved."""
        pause_receipt = PauseReceipt(
            thread_id="test-thread-pause",
            action="execute_trade",
            pause_reason="RATE_LIMITED",
            pause_token="pause-token-abc123",
            standing_at_pause={"symbol": "TSLA", "amount": 1000.0},
            estimated_wait_seconds=60,
        )

        original_proof_hash = pause_receipt.proof_hash
        assert original_proof_hash != "", "PauseReceipt should have computed proof_hash"

        serialized = _serialize_receipt(pause_receipt)

        assert serialized["proof_hash"] == original_proof_hash
        assert serialized["pause_reason"] == "RATE_LIMITED"
        assert serialized["pause_token"] == "pause-token-abc123"
        assert serialized["estimated_wait_seconds"] == 60


class TestEmitRefusalReceiptIntegration:
    """Integration tests for _emit_refusal_receipt with full v3 receipts."""

    @pytest.mark.asyncio
    async def test_emit_with_full_receipt_contains_proof_hash(self, monkeypatch):
        """A2 requirement: Emitted receipt contains proof_hash matching the computed value."""
        from unittest.mock import AsyncMock, MagicMock

        # Mock the evidence sink
        mock_sink = MagicMock()
        mock_sink.ingest = AsyncMock()
        monkeypatch.setattr(
            "src.gateway.server.governance_middleware.get_evidence_sink",
            lambda: mock_sink,
        )

        # Mock the KMS signer
        mock_signer = MagicMock()
        mock_signer.sign = MagicMock(return_value="mock-kms-signature")
        monkeypatch.setattr(
            "src.gateway.server.governance_middleware.get_governance_signer",
            lambda: mock_signer,
        )

        tier_failure = GovernanceTierFailure(
            tier="FISCAL",
            control_id="CAGE-CTRL-004",
            rule_description="Budget exceeded",
            governing_state={"budget": 10000.0, "requested": 15000.0},
            protected_consequence="fiscal_violation",
        )
        receipt = RefusalReceipt(
            thread_id="test-emit-thread",
            action="execute_trade",
            violated_tier="FISCAL",
            violated_rule="Budget exceeded",
            tier_failures=(tier_failure,),
            schema_version="v3",
            attempted_params={"symbol": "NVDA", "amount": 15000.0},
            standing_snapshot={"budget": 10000.0},
            control_id="CAGE-CTRL-004",
            protected_consequence="fiscal_violation",
            non_formation_proof="action_blocked_pre_commit",
        )

        original_proof_hash = receipt.proof_hash

        await _emit_refusal_receipt(
            action_id="execute_trade",
            refusal_reason="Budget exceeded",
            oscal_control_ref="SC-4",
            params={"symbol": "NVDA", "amount": 15000.0},
            receipt=receipt,
        )

        # Verify ingest was called
        assert mock_sink.ingest.called
        ingested_payload = mock_sink.ingest.call_args[0][0]

        # A2 requirement: proof_hash is byte-identical
        assert ingested_payload["proof_hash"] == original_proof_hash

        # Verify tier_failures present
        assert "tier_failures" in ingested_payload
        assert len(ingested_payload["tier_failures"]) == 1
        assert ingested_payload["tier_failures"][0]["tier"] == "FISCAL"

        # Verify 5-part proof chain
        assert ingested_payload["attempted_params"] == {
            "symbol": "NVDA",
            "amount": 15000.0,
        }
        assert ingested_payload["control_id"] == "CAGE-CTRL-004"
        assert ingested_payload["protected_consequence"] == "fiscal_violation"

        # Verify KMS signature was applied
        assert ingested_payload["kms_signature"] == "mock-kms-signature"

    @pytest.mark.asyncio
    async def test_emit_without_receipt_degrades_gracefully(self, monkeypatch, caplog):
        """A2 requirement: receipt=None degrades to summary form with warning."""
        from unittest.mock import AsyncMock, MagicMock

        mock_sink = MagicMock()
        mock_sink.ingest = AsyncMock()
        monkeypatch.setattr(
            "src.gateway.server.governance_middleware.get_evidence_sink",
            lambda: mock_sink,
        )

        mock_signer = MagicMock()
        mock_signer.sign = MagicMock(return_value="mock-sig")
        monkeypatch.setattr(
            "src.gateway.server.governance_middleware.get_governance_signer",
            lambda: mock_signer,
        )

        await _emit_refusal_receipt(
            action_id="execute_trade",
            refusal_reason="Unknown violation",
            oscal_control_ref="SC-4",
            params={},
            receipt=None,  # Explicitly None
        )

        # Verify ingest was still called
        assert mock_sink.ingest.called
        ingested_payload = mock_sink.ingest.call_args[0][0]

        # Verify degraded form (no tier_failures, no proof_hash from receipt)
        assert "tier_failures" not in ingested_payload
        assert "proof_hash" not in ingested_payload
        assert ingested_payload["refusal_reason"] == "Unknown violation"
        assert ingested_payload["type"] == "GOVERNANCE_REFUSAL_RECEIPT"

        # Verify warning was logged
        assert any(
            "[A2]" in record.message and "receipt=None" in record.message
            for record in caplog.records
        )

    @pytest.mark.asyncio
    async def test_emission_failure_does_not_raise(self, monkeypatch, caplog):
        """A2 requirement: emission errors are logged but do not propagate."""
        from unittest.mock import AsyncMock, MagicMock

        # Mock sink to raise an exception
        mock_sink = MagicMock()
        mock_sink.ingest = AsyncMock(side_effect=RuntimeError("Redis down"))
        monkeypatch.setattr(
            "src.gateway.server.governance_middleware.get_evidence_sink",
            lambda: mock_sink,
        )

        mock_signer = MagicMock()
        mock_signer.sign = MagicMock(return_value="sig")
        monkeypatch.setattr(
            "src.gateway.server.governance_middleware.get_governance_signer",
            lambda: mock_signer,
        )

        receipt = RefusalReceipt(
            thread_id="test",
            action="execute_trade",
            violated_tier="TEST",
            violated_rule="test",
        )

        # Should not raise
        await _emit_refusal_receipt(
            action_id="execute_trade",
            refusal_reason="test",
            oscal_control_ref="SC-4",
            params={},
            receipt=receipt,
        )

        # Verify error was logged
        assert any(
            "Failed to emit OSCAL refusal receipt" in record.message
            for record in caplog.records
        )


class TestEmitPauseReceiptIntegration:
    """Integration tests for A3: PauseReceipt emission."""

    @pytest.mark.asyncio
    async def test_emit_pause_receipt_contains_proof_hash(self, monkeypatch):
        """A3 requirement: Emitted pause receipt contains proof_hash."""
        from unittest.mock import AsyncMock, MagicMock

        mock_sink = MagicMock()
        mock_sink.ingest = AsyncMock()
        monkeypatch.setattr(
            "src.gateway.server.governance_middleware.get_evidence_sink",
            lambda: mock_sink,
        )

        mock_signer = MagicMock()
        mock_signer.sign = MagicMock(return_value="pause-kms-sig")
        monkeypatch.setattr(
            "src.gateway.server.governance_middleware.get_governance_signer",
            lambda: mock_signer,
        )

        pause_receipt = PauseReceipt(
            thread_id="pause-test-thread",
            action="execute_trade",
            pause_reason="CIRCUIT_OPEN",
            pause_token="pause-xyz789",
            standing_at_pause={"symbol": "AMD", "amount": 500.0},
            estimated_wait_seconds=120,
        )

        original_proof_hash = pause_receipt.proof_hash

        await _emit_pause_receipt(
            action_id="execute_trade",
            pause_receipt=pause_receipt,
        )

        assert mock_sink.ingest.called
        ingested_payload = mock_sink.ingest.call_args[0][0]

        # A3 requirement: proof_hash is byte-identical
        assert ingested_payload["proof_hash"] == original_proof_hash
        assert ingested_payload["type"] == "GOVERNANCE_PAUSE_RECEIPT"
        assert ingested_payload["pause_reason"] == "CIRCUIT_OPEN"
        assert ingested_payload["pause_token"] == "pause-xyz789"
        assert ingested_payload["estimated_wait_seconds"] == 120
        assert ingested_payload["kms_signature"] == "pause-kms-sig"
        assert ingested_payload["oscal_control_ref"] == "ISO-42001-A.8.4"

    @pytest.mark.asyncio
    async def test_emit_pause_receipt_none_returns_early(self, monkeypatch, caplog):
        """A3: _emit_pause_receipt with None logs warning and returns."""
        from unittest.mock import AsyncMock, MagicMock

        mock_sink = MagicMock()
        mock_sink.ingest = AsyncMock()
        monkeypatch.setattr(
            "src.gateway.server.governance_middleware.get_evidence_sink",
            lambda: mock_sink,
        )

        await _emit_pause_receipt(
            action_id="execute_trade",
            pause_receipt=None,
        )

        # Should not call ingest
        assert not mock_sink.ingest.called

        # Should log warning
        assert any(
            "[A3]" in record.message and "pause_receipt=None" in record.message
            for record in caplog.records
        )
