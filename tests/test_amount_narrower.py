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

"""Tests for AmountNarrower domain plugin."""

import pytest

from src.cage_finance.narrowers.amount_narrower import AmountNarrower
from src.gateway.governance.contracts import Violation, ViolationKind

pytestmark = [pytest.mark.unit, pytest.mark.local]


class TestAmountNarrower:
    """Test suite for structured AmountNarrower (no regex message parsing)."""

    def test_can_narrow_with_valid_narrowable_violation_regardless_of_message(self):
        """Narrower accepts NARROWABLE violations when amount > limit regardless of message text."""
        narrower = AmountNarrower(limit_resolver=25000.0)

        for msg in (
            "",
            "Arbitrary policy rejection text without numbers",
            "Amount $50000 exceeds soft limit of $25000",
        ):
            violation = Violation(
                tier="fiscal",
                code="SOFT_LIMIT_EXCEEDED",
                message=msg,
                kind=ViolationKind.NARROWABLE,
            )
            params = {"amount": 50000, "symbol": "AAPL", "side": "buy"}
            assert narrower.can_narrow(violation, "execute_trade", params) is True

    def test_can_narrow_rejects_hard_violation(self):
        """Narrower rejects HARD violations even when amount > limit."""
        narrower = AmountNarrower(limit_resolver=25000.0)

        violation = Violation(
            tier="fiscal",
            code="HARD_LIMIT_EXCEEDED",
            message="Hard limit exceeded",
            kind=ViolationKind.HARD,
        )
        params = {"amount": 50000, "symbol": "AAPL"}
        assert narrower.can_narrow(violation, "execute_trade", params) is False
        assert narrower.narrow(violation, "execute_trade", params) is None

    def test_can_narrow_rejects_missing_or_invalid_amount_field(self):
        """Narrower rejects violations when params lack a valid numeric 'amount' field."""
        narrower = AmountNarrower(limit_resolver=25000.0)

        violation = Violation(
            tier="fiscal",
            code="SOFT_LIMIT_EXCEEDED",
            message="Soft limit",
            kind=ViolationKind.NARROWABLE,
        )

        assert narrower.can_narrow(violation, "execute_trade", {"symbol": "AAPL"}) is False
        assert narrower.can_narrow(violation, "execute_trade", {"amount": None}) is False
        assert narrower.can_narrow(violation, "execute_trade", {"amount": "not-a-num"}) is False
        assert narrower.can_narrow(violation, "execute_trade", {"amount": True}) is False
        assert narrower.can_narrow(violation, "execute_trade", {"amount": float("nan")}) is False
        assert narrower.can_narrow(violation, "execute_trade", {"amount": float("inf")}) is False

    def test_can_narrow_rejects_when_amount_already_within_limit(self):
        """Narrower refuses to narrow when amount <= limit."""
        narrower = AmountNarrower(limit_resolver=25000.0)

        violation = Violation(
            tier="fiscal",
            code="SOFT_LIMIT_EXCEEDED",
            message="Soft limit",
            kind=ViolationKind.NARROWABLE,
        )
        assert narrower.can_narrow(violation, "execute_trade", {"amount": 25000.0}) is False
        assert narrower.can_narrow(violation, "execute_trade", {"amount": 10000.0}) is False
        assert narrower.narrow(violation, "execute_trade", {"amount": 25000.0}) is None

    def test_can_narrow_rejects_nonpositive_limit(self):
        """Narrower refuses to narrow when resolved limit <= 0."""
        narrower = AmountNarrower(limit_resolver=lambda: 0.0)

        violation = Violation(
            tier="fiscal",
            code="SOFT_LIMIT_EXCEEDED",
            message="Soft limit",
            kind=ViolationKind.NARROWABLE,
        )
        assert narrower.can_narrow(violation, "execute_trade", {"amount": 50000.0}) is False
        assert narrower.narrow(violation, "execute_trade", {"amount": 50000.0}) is None

    def test_narrow_clamps_amount_to_99_percent_of_limit(self):
        """Narrower clamps amount to round(limit * 0.99, 2)."""
        narrower = AmountNarrower(limit_resolver=lambda: 25000.0)

        violation = Violation(
            tier="fiscal",
            code="SOFT_LIMIT_EXCEEDED",
            message="",
            kind=ViolationKind.NARROWABLE,
        )
        params = {"amount": 50000, "symbol": "AAPL", "side": "buy"}

        result = narrower.narrow(violation, "execute_trade", params)

        assert result is not None
        assert result.can_narrow is True
        assert result.narrowed_params == {
            "amount": 24750.0,
            "symbol": "AAPL",
            "side": "buy",
        }
        assert result.constraints_applied == ["amount <= 24750.0"]
        assert "50000" in result.narrowing_reason
        assert "24750.0" in result.narrowing_reason

    def test_narrow_preserves_other_parameters(self):
        """Narrower preserves all non-amount parameters unchanged."""
        narrower = AmountNarrower(limit_resolver=10000.0)

        violation = Violation(
            tier="fiscal",
            code="SOFT_LIMIT_EXCEEDED",
            message="arbitrary text",
            kind=ViolationKind.NARROWABLE,
        )
        params = {
            "amount": 15000,
            "symbol": "GOOGL",
            "side": "sell",
            "order_type": "limit",
            "limit_price": 150.50,
        }

        result = narrower.narrow(violation, "execute_trade", params)

        assert result is not None
        assert result.can_narrow is True
        assert result.narrowed_params["amount"] == 9900.0
        assert result.narrowed_params["symbol"] == "GOOGL"
        assert result.narrowed_params["side"] == "sell"
        assert result.narrowed_params["order_type"] == "limit"
        assert result.narrowed_params["limit_price"] == 150.50

    def test_narrow_uses_default_thresholds_resolver(self):
        """Default AmountNarrower() resolves limit from THRESHOLDS.resolve('domains.finance.consensus.threshold_usd')."""
        from src.gateway.governance.schemas.thresholds import THRESHOLDS

        narrower = AmountNarrower()
        limit = float(THRESHOLDS.resolve("domains.finance.consensus.threshold_usd"))
        violation = Violation(
            tier="consensus",
            code="CONSENSUS_ESCALATED",
            message="Escalated",
            kind=ViolationKind.NARROWABLE,
        )
        result = narrower.narrow(violation, "execute_trade", {"amount": limit * 2})
        assert result is not None
        assert result.narrowed_params["amount"] == round(limit * 0.99, 2)
