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
    """Test suite for AmountNarrower."""
    
    def test_can_narrow_with_valid_narrowable_violation(self):
        """Narrower accepts NARROWABLE violations with amount field and 'exceeds'."""
        narrower = AmountNarrower()
        
        violation = Violation(
            tier="fiscal",
            code="SOFT_LIMIT_EXCEEDED",
            message="Amount $50000 exceeds soft limit of $25000",
            kind=ViolationKind.NARROWABLE,
        )
        
        params = {"amount": 50000, "symbol": "AAPL", "side": "buy"}
        
        assert narrower.can_narrow(violation, "execute_trade", params) is True
    
    def test_can_narrow_rejects_hard_violation(self):
        """Narrower rejects HARD violations."""
        narrower = AmountNarrower()
        
        violation = Violation(
            tier="fiscal",
            code="HARD_LIMIT_EXCEEDED",
            message="Amount $50000 exceeds hard limit of $25000",
            kind=ViolationKind.HARD,
        )
        
        params = {"amount": 50000, "symbol": "AAPL"}
        
        assert narrower.can_narrow(violation, "execute_trade", params) is False
    
    def test_can_narrow_rejects_missing_amount_field(self):
        """Narrower rejects violations when params lack 'amount' field."""
        narrower = AmountNarrower()
        
        violation = Violation(
            tier="fiscal",
            code="SOFT_LIMIT_EXCEEDED",
            message="Amount exceeds soft limit",
            kind=ViolationKind.NARROWABLE,
        )
        
        params = {"symbol": "AAPL", "side": "buy"}  # No amount field
        
        assert narrower.can_narrow(violation, "execute_trade", params) is False
    
    def test_can_narrow_rejects_non_exceeds_message(self):
        """Narrower rejects violations without 'exceeds' in message."""
        narrower = AmountNarrower()
        
        violation = Violation(
            tier="fiscal",
            code="INVALID_AMOUNT",
            message="Amount is invalid",
            kind=ViolationKind.NARROWABLE,
        )
        
        params = {"amount": 50000, "symbol": "AAPL"}
        
        assert narrower.can_narrow(violation, "execute_trade", params) is False
    
    def test_narrow_clamps_amount_to_threshold(self):
        """Narrower clamps amount to max_allowed extracted from message."""
        narrower = AmountNarrower()
        
        violation = Violation(
            tier="fiscal",
            code="SOFT_LIMIT_EXCEEDED",
            message="Amount $50000 exceeds soft limit of $25000",
            kind=ViolationKind.NARROWABLE,
        )
        
        params = {"amount": 50000, "symbol": "AAPL", "side": "buy"}
        
        result = narrower.narrow(violation, "execute_trade", params)
        
        assert result.can_narrow is True
        assert result.narrowed_params == {"amount": 25000, "symbol": "AAPL", "side": "buy"}
        assert result.constraints_applied == ["amount <= 25000.0"]
        assert "50000" in result.narrowing_reason
        assert "25000" in result.narrowing_reason
    
    def test_narrow_preserves_other_parameters(self):
        """Narrower preserves all non-amount parameters unchanged."""
        narrower = AmountNarrower()
        
        violation = Violation(
            tier="fiscal",
            code="SOFT_LIMIT_EXCEEDED",
            message="Amount exceeds soft limit of 10000",
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
        
        assert result.can_narrow is True
        assert result.narrowed_params["amount"] == 10000
        assert result.narrowed_params["symbol"] == "GOOGL"
        assert result.narrowed_params["side"] == "sell"
        assert result.narrowed_params["order_type"] == "limit"
        assert result.narrowed_params["limit_price"] == 150.50
    
    def test_narrow_handles_decimal_amounts(self):
        """Narrower handles decimal amounts in violation message."""
        narrower = AmountNarrower()
        
        violation = Violation(
            tier="fiscal",
            code="SOFT_LIMIT_EXCEEDED",
            message="Amount exceeds soft limit of $12500.50",
            kind=ViolationKind.NARROWABLE,
        )
        
        params = {"amount": 20000, "symbol": "MSFT"}
        
        result = narrower.narrow(violation, "execute_trade", params)
        
        assert result.can_narrow is True
        assert result.narrowed_params["amount"] == 12500.50
    
    def test_narrow_handles_amount_without_dollar_sign(self):
        """Narrower extracts amounts without $ prefix."""
        narrower = AmountNarrower()
        
        violation = Violation(
            tier="fiscal",
            code="SOFT_LIMIT_EXCEEDED",
            message="Amount exceeds soft limit of 30000",
            kind=ViolationKind.NARROWABLE,
        )
        
        params = {"amount": 45000, "symbol": "TSLA"}
        
        result = narrower.narrow(violation, "execute_trade", params)
        
        assert result.can_narrow is True
        assert result.narrowed_params["amount"] == 30000
    
    def test_narrow_handles_unparseable_message(self):
        """Narrower gracefully handles violation message without extractable limit."""
        narrower = AmountNarrower()
        
        violation = Violation(
            tier="fiscal",
            code="SOFT_LIMIT_EXCEEDED",
            message="Amount is too large",  # No limit value
            kind=ViolationKind.NARROWABLE,
        )
        
        params = {"amount": 50000, "symbol": "AAPL"}
        
        result = narrower.narrow(violation, "execute_trade", params)
        
        assert result.can_narrow is False
        assert "Could not extract max_allowed" in result.narrowing_reason
        assert result.narrowed_params == params  # Unchanged
    
    def test_narrow_no_op_when_amount_already_within_limit(self):
        """Narrower returns same amount when already within threshold."""
        narrower = AmountNarrower()
        
        violation = Violation(
            tier="fiscal",
            code="SOFT_LIMIT_EXCEEDED",
            message="Amount exceeds soft limit of 50000",
            kind=ViolationKind.NARROWABLE,
        )
        
        params = {"amount": 30000, "symbol": "AAPL"}  # Already below limit
        
        result = narrower.narrow(violation, "execute_trade", params)
        
        assert result.can_narrow is True
        assert result.narrowed_params["amount"] == 30000  # Unchanged
