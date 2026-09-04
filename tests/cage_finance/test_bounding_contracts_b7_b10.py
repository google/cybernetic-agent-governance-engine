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

"""Tests for bounding contracts B7 (audit trail sealing) and B10 (rollback window).

B7 is a capability check for KMS signer availability.
B10 is the critical contract that justifies EXTERNALLY_REVERSIBLE classification.
When B10 fails, it must emit a classification override to IRREVERSIBLE_TERMINAL.
"""

from unittest.mock import MagicMock, patch

import pytest

from src.cage_finance.safety.bounding.contracts import (
    contract_b7_audit_trail_sealing,
    contract_b10_rollback_window,
)
from src.cage_finance.safety.bounding.models import (
    BoundedTradeRequest,
    ContractSeverity,
)

# ───────────────────────────────────────────────────────────────────────────────
# B7 — Audit Trail Cryptographic Hash Chain Sealing Tests
# ───────────────────────────────────────────────────────────────────────────────


class TestContractB7AuditTrailSealing:
    """Tests for contract_b7_audit_trail_sealing() — HARD_BLOCK severity."""

    def test_b7_kms_signer_available_admits(self):
        """B7 admits when KMS signer class is available (normal operation)."""
        request = BoundedTradeRequest(
            symbol="AAPL",
            amount=1000.0,
            side="buy",
            venue="NYSE",
            transaction_id="test-tx-b7-01",
        )

        # In normal operation, KMSGovernanceSigner class is available
        result = contract_b7_audit_trail_sealing(request)

        assert result.admitted is True
        assert result.contract_id == "B7"
        assert result.severity == ContractSeverity.HARD_BLOCK
        assert len(result.findings) == 0

    def test_b7_kms_signer_module_unavailable_rejects(self):
        """B7 rejects when KMS signer module cannot be imported."""
        request = BoundedTradeRequest(
            symbol="AAPL",
            amount=1000.0,
            side="buy",
            venue="NYSE",
            transaction_id="test-tx-b7-02",
        )

        # Mock ImportError for KMS signer module
        with patch.dict(
            "sys.modules",
            {"src.gateway.governance.kms_signer": None},
            clear=False,
        ):
            result = contract_b7_audit_trail_sealing(request)

        assert result.admitted is False
        assert result.contract_id == "B7"
        assert result.severity == ContractSeverity.HARD_BLOCK
        assert len(result.findings) == 1
        assert (
            "KMS signer module unavailable" in result.findings[0]["reason"]
            or "KMS signer capability check failed" in result.findings[0]["reason"]
        )
        assert "Cannot execute unauditable trade" in result.findings[0]["note"]


# ───────────────────────────────────────────────────────────────────────────────
# B10 — Rollback Window Validation Tests
# ───────────────────────────────────────────────────────────────────────────────


class TestContractB10RollbackWindow:
    """Tests for contract_b10_rollback_window() — HARD_BLOCK severity.

    CRITICAL: B10 is the contract that justifies EXTERNALLY_REVERSIBLE classification.
    When B10 fails, it MUST emit a classification override to IRREVERSIBLE_TERMINAL.
    """

    def test_b10_sufficient_rollback_window_admits(self):
        """B10 admits when rollback window is sufficient and no override."""
        request = BoundedTradeRequest(
            symbol="AAPL",
            amount=1000.0,
            side="buy",
            venue="NYSE",
            rollback_window_seconds=300,  # 5 minutes
            transaction_id="test-tx-b10-01",
        )

        thresholds = {
            "bounding": {
                "b10_min_rollback_window_seconds": 60,  # 1 minute minimum
            }
        }

        mock_provider = MagicMock()
        mock_provider.verify_rollback_window.return_value = {
            "supported": True,
            "max_window_seconds": 600,  # 10 minutes max
            "api_available": True,
        }

        result, classification_override = contract_b10_rollback_window(
            request, thresholds, mock_provider
        )

        assert result.admitted is True
        assert result.contract_id == "B10"
        assert result.severity == ContractSeverity.HARD_BLOCK
        assert len(result.findings) == 0
        assert classification_override is None  # Remains EXTERNALLY_REVERSIBLE

    def test_b10_venue_no_rollback_support_rejects_and_reclassifies(self):
        """B10 rejects when venue doesn't support rollback, emits IRREVERSIBLE_TERMINAL override."""
        request = BoundedTradeRequest(
            symbol="AAPL",
            amount=1000.0,
            side="buy",
            venue="LEGACY_EXCHANGE",
            rollback_window_seconds=300,
            transaction_id="test-tx-b10-02",
        )

        thresholds = {
            "bounding": {
                "b10_min_rollback_window_seconds": 60,
            }
        }

        mock_provider = MagicMock()
        mock_provider.verify_rollback_window.return_value = {
            "supported": False,  # No rollback support
            "max_window_seconds": 0,
            "api_available": False,
        }

        result, classification_override = contract_b10_rollback_window(
            request, thresholds, mock_provider
        )

        assert result.admitted is False
        assert result.contract_id == "B10"
        assert result.severity == ContractSeverity.HARD_BLOCK
        assert len(result.findings) == 1
        assert (
            result.findings[0]["reason"]
            == "Venue does not support rollback/cancellation"
        )
        assert "IRREVERSIBLE_TERMINAL" in result.findings[0]["note"]
        assert classification_override == "IRREVERSIBLE_TERMINAL"  # Critical

    def test_b10_rollback_api_unavailable_rejects_and_reclassifies(self):
        """B10 rejects when rollback API is not operational, emits IRREVERSIBLE_TERMINAL override."""
        request = BoundedTradeRequest(
            symbol="AAPL",
            amount=1000.0,
            side="buy",
            venue="NYSE",
            rollback_window_seconds=300,
            transaction_id="test-tx-b10-03",
        )

        thresholds = {
            "bounding": {
                "b10_min_rollback_window_seconds": 60,
            }
        }

        mock_provider = MagicMock()
        mock_provider.verify_rollback_window.return_value = {
            "supported": True,
            "max_window_seconds": 600,
            "api_available": False,  # API down
        }

        result, classification_override = contract_b10_rollback_window(
            request, thresholds, mock_provider
        )

        assert result.admitted is False
        assert result.contract_id == "B10"
        assert result.severity == ContractSeverity.HARD_BLOCK
        assert len(result.findings) == 1
        assert (
            result.findings[0]["reason"]
            == "Venue rollback API is not currently operational"
        )
        assert "Cannot guarantee reversibility" in result.findings[0]["note"]
        assert classification_override == "IRREVERSIBLE_TERMINAL"  # Critical

    def test_b10_requested_window_exceeds_venue_capability_rejects_and_reclassifies(
        self,
    ):
        """B10 rejects when requested window > venue max, emits IRREVERSIBLE_TERMINAL override."""
        request = BoundedTradeRequest(
            symbol="AAPL",
            amount=1000.0,
            side="buy",
            venue="FAST_EXCHANGE",
            rollback_window_seconds=600,  # 10 minutes requested
            transaction_id="test-tx-b10-04",
        )

        thresholds = {
            "bounding": {
                "b10_min_rollback_window_seconds": 60,
            }
        }

        mock_provider = MagicMock()
        mock_provider.verify_rollback_window.return_value = {
            "supported": True,
            "max_window_seconds": 300,  # Only 5 minutes max
            "api_available": True,
        }

        result, classification_override = contract_b10_rollback_window(
            request, thresholds, mock_provider
        )

        assert result.admitted is False
        assert result.contract_id == "B10"
        assert result.severity == ContractSeverity.HARD_BLOCK
        assert len(result.findings) == 1
        assert (
            result.findings[0]["reason"]
            == "Requested rollback window exceeds venue capability"
        )
        assert result.findings[0]["requested_window_seconds"] == 600
        assert result.findings[0]["max_window_seconds"] == 300
        assert "Rollback window too long" in result.findings[0]["note"]
        assert classification_override == "IRREVERSIBLE_TERMINAL"  # Critical

    def test_b10_requested_window_below_minimum_threshold_rejects_and_reclassifies(
        self,
    ):
        """B10 rejects when requested window < min threshold, emits IRREVERSIBLE_TERMINAL override."""
        request = BoundedTradeRequest(
            symbol="AAPL",
            amount=1000.0,
            side="buy",
            venue="NYSE",
            rollback_window_seconds=30,  # Only 30 seconds
            transaction_id="test-tx-b10-05",
        )

        thresholds = {
            "bounding": {
                "b10_min_rollback_window_seconds": 60,  # 1 minute minimum
            }
        }

        mock_provider = MagicMock()
        mock_provider.verify_rollback_window.return_value = {
            "supported": True,
            "max_window_seconds": 600,
            "api_available": True,
        }

        result, classification_override = contract_b10_rollback_window(
            request, thresholds, mock_provider
        )

        assert result.admitted is False
        assert result.contract_id == "B10"
        assert result.severity == ContractSeverity.HARD_BLOCK
        assert len(result.findings) == 1
        assert (
            result.findings[0]["reason"]
            == "Requested rollback window below minimum threshold"
        )
        assert result.findings[0]["requested_window_seconds"] == 30
        assert result.findings[0]["min_threshold_seconds"] == 60
        assert "Insufficient rollback window" in result.findings[0]["note"]
        assert classification_override == "IRREVERSIBLE_TERMINAL"  # Critical

    def test_b10_provider_unavailable_rejects_and_reclassifies(self):
        """B10 rejects when provider raises RuntimeError, emits IRREVERSIBLE_TERMINAL override."""
        request = BoundedTradeRequest(
            symbol="AAPL",
            amount=1000.0,
            side="buy",
            venue="NYSE",
            rollback_window_seconds=300,
            transaction_id="test-tx-b10-06",
        )

        thresholds = {
            "bounding": {
                "b10_min_rollback_window_seconds": 60,
            }
        }

        mock_provider = MagicMock()
        mock_provider.verify_rollback_window.side_effect = RuntimeError(
            "Settlement provider unavailable"
        )

        result, classification_override = contract_b10_rollback_window(
            request, thresholds, mock_provider
        )

        assert result.admitted is False
        assert result.contract_id == "B10"
        assert result.severity == ContractSeverity.HARD_BLOCK
        assert len(result.findings) == 1
        assert (
            result.findings[0]["reason"] == "Rollback capability provider unavailable"
        )
        assert "Settlement provider unavailable" in result.findings[0]["error"]
        assert "Cannot verify reversibility" in result.findings[0]["note"]
        assert classification_override == "IRREVERSIBLE_TERMINAL"  # Critical

    def test_b10_missing_threshold_rejects_and_reclassifies(self):
        """B10 rejects when threshold is missing, emits IRREVERSIBLE_TERMINAL override."""
        request = BoundedTradeRequest(
            symbol="AAPL",
            amount=1000.0,
            side="buy",
            venue="NYSE",
            rollback_window_seconds=300,
            transaction_id="test-tx-b10-07",
        )

        thresholds = {
            "bounding": {}  # Missing b10_min_rollback_window_seconds
        }

        mock_provider = MagicMock()

        result, classification_override = contract_b10_rollback_window(
            request, thresholds, mock_provider
        )

        assert result.admitted is False
        assert result.contract_id == "B10"
        assert result.severity == ContractSeverity.HARD_BLOCK
        assert len(result.findings) == 1
        assert (
            "Missing threshold: bounding.b10_min_rollback_window_seconds"
            in result.findings[0]["reason"]
        )
        assert classification_override == "IRREVERSIBLE_TERMINAL"  # Critical

    def test_b10_invalid_threshold_rejects_and_reclassifies(self):
        """B10 rejects when threshold is invalid (negative), emits IRREVERSIBLE_TERMINAL override."""
        request = BoundedTradeRequest(
            symbol="AAPL",
            amount=1000.0,
            side="buy",
            venue="NYSE",
            rollback_window_seconds=300,
            transaction_id="test-tx-b10-08",
        )

        thresholds = {
            "bounding": {
                "b10_min_rollback_window_seconds": -100,  # Invalid negative
            }
        }

        mock_provider = MagicMock()

        result, classification_override = contract_b10_rollback_window(
            request, thresholds, mock_provider
        )

        assert result.admitted is False
        assert result.contract_id == "B10"
        assert result.severity == ContractSeverity.HARD_BLOCK
        assert len(result.findings) == 1
        assert (
            "Invalid threshold: bounding.b10_min_rollback_window_seconds must be non-negative"
            in result.findings[0]["reason"]
        )
        assert result.findings[0]["threshold_value"] == -100
        assert classification_override == "IRREVERSIBLE_TERMINAL"  # Critical

    def test_b10_boundary_conditions_inclusive(self):
        """B10 validates inclusive boundary semantics (≥ for min threshold, ≤ for max capability)."""
        # Test 1: Exactly at minimum threshold — should admit
        request_at_min = BoundedTradeRequest(
            symbol="AAPL",
            amount=1000.0,
            side="buy",
            venue="NYSE",
            rollback_window_seconds=60,  # Exactly at minimum
            transaction_id="test-tx-b10-09",
        )

        thresholds = {
            "bounding": {
                "b10_min_rollback_window_seconds": 60,
            }
        }

        mock_provider = MagicMock()
        mock_provider.verify_rollback_window.return_value = {
            "supported": True,
            "max_window_seconds": 600,
            "api_available": True,
        }

        result_at_min, override_at_min = contract_b10_rollback_window(
            request_at_min, thresholds, mock_provider
        )

        assert result_at_min.admitted is True  # Inclusive boundary
        assert override_at_min is None

        # Test 2: Exactly at maximum capability — should admit
        request_at_max = BoundedTradeRequest(
            symbol="AAPL",
            amount=1000.0,
            side="buy",
            venue="NYSE",
            rollback_window_seconds=600,  # Exactly at max
            transaction_id="test-tx-b10-10",
        )

        mock_provider.verify_rollback_window.return_value = {
            "supported": True,
            "max_window_seconds": 600,
            "api_available": True,
        }

        result_at_max, override_at_max = contract_b10_rollback_window(
            request_at_max, thresholds, mock_provider
        )

        assert result_at_max.admitted is True  # Inclusive boundary
        assert override_at_max is None
