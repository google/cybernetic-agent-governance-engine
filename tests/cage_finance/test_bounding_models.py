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

"""Tests for bounding contract data models.

Phase 5 Step 2: Validates ContractSeverity, ContractResult, and
BoundedTradeRequest fail-closed semantics and invariant validation.
"""

import math

import pytest

from src.cage_finance.safety.bounding.models import (
    BoundedTradeRequest,
    ContractResult,
    ContractSeverity,
)


class TestContractSeverity:
    """Tests for ContractSeverity enum."""

    def test_three_severity_levels_exist(self):
        """ContractSeverity must have exactly three levels per Phase 5 plan."""
        assert len(ContractSeverity) == 3
        assert ContractSeverity.HARD_BLOCK == "HARD_BLOCK"
        assert ContractSeverity.HITL_ESCALATE == "HITL_ESCALATE"
        assert ContractSeverity.ADVISORY == "ADVISORY"

    def test_severity_is_string_enum(self):
        """ContractSeverity must be string-valued for JSON serialization."""
        assert isinstance(ContractSeverity.HARD_BLOCK.value, str)
        assert isinstance(ContractSeverity.HITL_ESCALATE.value, str)
        assert isinstance(ContractSeverity.ADVISORY.value, str)


class TestContractResult:
    """Tests for ContractResult dataclass."""

    def test_valid_hard_block_rejection(self):
        """HARD_BLOCK rejection with structured findings is valid."""
        result = ContractResult(
            contract_id="B1",
            admitted=False,
            severity=ContractSeverity.HARD_BLOCK,
            findings=[{"reason": "Max notional exceeded", "limit": 10000, "actual": 15000}],
        )
        assert result.contract_id == "B1"
        assert result.admitted is False
        assert result.severity == ContractSeverity.HARD_BLOCK
        assert len(result.findings) == 1

    def test_valid_hitl_escalate_rejection(self):
        """HITL_ESCALATE rejection routes to defer queue."""
        result = ContractResult(
            contract_id="B3",
            admitted=False,
            severity=ContractSeverity.HITL_ESCALATE,
            findings=[{"reason": "Liquidity depth insufficient", "depth_ratio": 0.8}],
        )
        assert result.contract_id == "B3"
        assert result.admitted is False
        assert result.severity == ContractSeverity.HITL_ESCALATE

    def test_valid_advisory_pass(self):
        """ADVISORY severity with admitted=True is valid (informational warning)."""
        result = ContractResult(
            contract_id="B5",
            admitted=True,
            severity=ContractSeverity.ADVISORY,
            findings=[{"info": "Volatility approaching threshold", "percentile": 85}],
        )
        assert result.contract_id == "B5"
        assert result.admitted is True
        assert result.severity == ContractSeverity.ADVISORY

    def test_advisory_severity_cannot_block(self):
        """ADVISORY severity with admitted=False raises ValueError (developer error).
        
        Per Phase 5 plan Section 3.3: ADVISORY contracts must never block execution.
        If a contract needs to block, it must use HITL_ESCALATE or HARD_BLOCK severity.
        """
        with pytest.raises(ValueError, match="ADVISORY severity must not block"):
            ContractResult(
                contract_id="B_INVALID",
                admitted=False,  # ❌ Developer error
                severity=ContractSeverity.ADVISORY,
                findings=[],
            )

    def test_empty_findings_list_is_valid(self):
        """Contract results with no findings are valid (e.g., simple pass/fail)."""
        result = ContractResult(
            contract_id="B2",
            admitted=True,
            severity=ContractSeverity.HARD_BLOCK,
            findings=[],  # No diagnostic info
        )
        assert result.findings == []

    def test_findings_must_be_list(self):
        """Findings field must be a list type (fail-closed validation)."""
        with pytest.raises(TypeError, match="findings must be list"):
            ContractResult(
                contract_id="B1",
                admitted=False,
                severity=ContractSeverity.HARD_BLOCK,
                findings="invalid",  # type: ignore[arg-type]
            )

    def test_severity_must_be_contract_severity_enum(self):
        """Severity field must be ContractSeverity enum (fail-closed validation)."""
        with pytest.raises(TypeError, match="severity must be ContractSeverity"):
            ContractResult(
                contract_id="B1",
                admitted=False,
                severity="HARD_BLOCK",  # type: ignore[arg-type]  # ❌ String instead of enum
                findings=[],
            )

    def test_contract_result_is_immutable(self):
        """ContractResult must be frozen (immutable) to prevent TOCTOU."""
        result = ContractResult(
            contract_id="B1",
            admitted=True,
            severity=ContractSeverity.HARD_BLOCK,
            findings=[],
        )
        with pytest.raises(Exception):  # FrozenInstanceError in Python 3.10+
            result.admitted = False  # type: ignore[misc]


class TestBoundedTradeRequest:
    """Tests for BoundedTradeRequest dataclass."""

    def test_valid_buy_trade_request(self):
        """Valid buy trade request with all required fields."""
        req = BoundedTradeRequest(
            symbol="AAPL",
            amount=1000.0,
            side="buy",
            venue="NASDAQ",
            counterparty=None,
            trader_role="autonomous",
            jurisdiction="US",
            rollback_window_seconds=300,
            transaction_id="txn-12345",
        )
        assert req.symbol == "AAPL"
        assert req.amount == 1000.0
        assert req.side == "buy"
        assert req.venue == "NASDAQ"
        assert req.jurisdiction == "US"

    def test_valid_sell_trade_request(self):
        """Valid sell trade request."""
        req = BoundedTradeRequest(
            symbol="BTC",
            amount=5000.0,
            side="sell",
            venue="COINBASE",
        )
        assert req.side == "sell"
        assert req.amount == 5000.0

    def test_zero_amount_is_valid(self):
        """Zero amount is valid (no-op trade, useful for testing)."""
        req = BoundedTradeRequest(
            symbol="TEST",
            amount=0.0,
            side="buy",
            venue="TEST_VENUE",
        )
        assert req.amount == 0.0

    def test_rejects_nan_amount(self):
        """Non-finite amount (NaN) raises ValueError (fail-closed)."""
        with pytest.raises(ValueError, match="amount must be finite"):
            BoundedTradeRequest(
                symbol="AAPL",
                amount=math.nan,
                side="buy",
                venue="NASDAQ",
            )

    def test_rejects_inf_amount(self):
        """Non-finite amount (inf) raises ValueError (fail-closed)."""
        with pytest.raises(ValueError, match="amount must be finite"):
            BoundedTradeRequest(
                symbol="AAPL",
                amount=math.inf,
                side="buy",
                venue="NASDAQ",
            )

    def test_rejects_negative_inf_amount(self):
        """Non-finite amount (-inf) raises ValueError (fail-closed)."""
        with pytest.raises(ValueError, match="amount must be finite"):
            BoundedTradeRequest(
                symbol="AAPL",
                amount=-math.inf,
                side="buy",
                venue="NASDAQ",
            )

    def test_rejects_negative_amount(self):
        """Negative amount raises ValueError (fail-closed)."""
        with pytest.raises(ValueError, match="amount must be non-negative"):
            BoundedTradeRequest(
                symbol="AAPL",
                amount=-1000.0,
                side="buy",
                venue="NASDAQ",
            )

    def test_rejects_invalid_side(self):
        """Invalid side (not 'buy' or 'sell') raises ValueError (fail-closed)."""
        with pytest.raises(ValueError, match="side must be 'buy' or 'sell'"):
            BoundedTradeRequest(
                symbol="AAPL",
                amount=1000.0,
                side="invalid",  # ❌ Must be 'buy' or 'sell'
                venue="NASDAQ",
            )

    def test_rejects_negative_rollback_window(self):
        """Negative rollback window raises ValueError (fail-closed)."""
        with pytest.raises(ValueError, match="rollback_window_seconds must be non-negative"):
            BoundedTradeRequest(
                symbol="AAPL",
                amount=1000.0,
                side="buy",
                venue="NASDAQ",
                rollback_window_seconds=-100,  # ❌ Must be >= 0
            )

    def test_default_rollback_window_is_300_seconds(self):
        """Default rollback window is 300 seconds (5 minutes) per Phase 5 plan."""
        req = BoundedTradeRequest(
            symbol="AAPL",
            amount=1000.0,
            side="buy",
            venue="NASDAQ",
        )
        assert req.rollback_window_seconds == 300

    def test_default_trader_role_is_autonomous(self):
        """Default trader_role is 'autonomous' for audit trail."""
        req = BoundedTradeRequest(
            symbol="AAPL",
            amount=1000.0,
            side="buy",
            venue="NASDAQ",
        )
        assert req.trader_role == "autonomous"

    def test_counterparty_optional_for_exchange_trades(self):
        """Counterparty is None by default (optional for exchange trades)."""
        req = BoundedTradeRequest(
            symbol="AAPL",
            amount=1000.0,
            side="buy",
            venue="NASDAQ",
        )
        assert req.counterparty is None

    def test_counterparty_required_for_otc_trades(self):
        """Counterparty can be specified for OTC trades."""
        req = BoundedTradeRequest(
            symbol="PRIVATE_EQUITY",
            amount=100000.0,
            side="buy",
            venue="OTC",
            counterparty="CITADEL",
        )
        assert req.counterparty == "CITADEL"

    def test_to_dict_serialization(self):
        """to_dict() returns all fields for audit trail serialization."""
        req = BoundedTradeRequest(
            symbol="AAPL",
            amount=1000.0,
            side="buy",
            venue="NASDAQ",
            jurisdiction="US",
            transaction_id="txn-abc123",
        )
        d = req.to_dict()
        assert d["symbol"] == "AAPL"
        assert d["amount"] == 1000.0
        assert d["side"] == "buy"
        assert d["venue"] == "NASDAQ"
        assert d["jurisdiction"] == "US"
        assert d["transaction_id"] == "txn-abc123"
        assert d["trader_role"] == "autonomous"
        assert d["rollback_window_seconds"] == 300

    def test_bounded_trade_request_is_immutable(self):
        """BoundedTradeRequest must be frozen (immutable) to prevent TOCTOU."""
        req = BoundedTradeRequest(
            symbol="AAPL",
            amount=1000.0,
            side="buy",
            venue="NASDAQ",
        )
        with pytest.raises(Exception):  # FrozenInstanceError in Python 3.10+
            req.amount = 2000.0  # type: ignore[misc]


class TestContractResultAndRequestInteraction:
    """Integration tests for how ContractResult and BoundedTradeRequest interact."""

    def test_hard_block_rejection_captures_request_details(self):
        """HARD_BLOCK rejection should capture request details in findings."""
        req = BoundedTradeRequest(
            symbol="AAPL",
            amount=15000.0,
            side="buy",
            venue="NASDAQ",
        )
        result = ContractResult(
            contract_id="B1",
            admitted=False,
            severity=ContractSeverity.HARD_BLOCK,
            findings=[
                {
                    "reason": "Max notional exceeded",
                    "limit": 10000.0,
                    "actual": req.amount,
                    "symbol": req.symbol,
                }
            ],
        )
        assert result.findings[0]["actual"] == 15000.0
        assert result.findings[0]["symbol"] == "AAPL"

    def test_hitl_escalate_includes_request_context(self):
        """HITL_ESCALATE findings should include request context for human review."""
        req = BoundedTradeRequest(
            symbol="BTC",
            amount=50000.0,
            side="buy",
            venue="COINBASE",
            jurisdiction="US",
        )
        result = ContractResult(
            contract_id="B6",
            admitted=False,
            severity=ContractSeverity.HITL_ESCALATE,
            findings=[
                {
                    "reason": "High-impact trade requires human review",
                    "threshold_usd": 25000.0,
                    "actual_usd": req.amount,
                    "jurisdiction": req.jurisdiction,
                }
            ],
        )
        assert result.findings[0]["actual_usd"] == 50000.0
        assert result.findings[0]["jurisdiction"] == "US"
