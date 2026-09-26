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

"""Tests for NarrowerRegistry and Narrower protocol."""

import pytest

from src.cage_finance.narrowers.amount_narrower import AmountNarrower
from src.gateway.governance.contracts import Violation, ViolationKind
from src.gateway.governance.narrower import NarrowerRegistry, NarrowingResult

pytestmark = [pytest.mark.unit, pytest.mark.local]


class TestNarrowerRegistry:
    """Test suite for NarrowerRegistry."""
    
    def test_empty_registry_returns_none(self):
        """Empty registry returns None when no narrowers registered."""
        registry = NarrowerRegistry()
        
        violation = Violation(
            tier="fiscal",
            code="SOFT_LIMIT_EXCEEDED",
            message="Amount $50000 exceeds soft limit of $25000",
            kind=ViolationKind.NARROWABLE,
        )
        
        result = registry.find_narrower(
            violation=violation,
            action="execute_trade",
            params={"amount": 50000, "symbol": "AAPL"},
        )
        
        assert result is None
    
    def test_registry_initialization_with_narrowers(self):
        """Registry can be initialized with a list of narrowers."""
        amount_narrower = AmountNarrower()
        registry = NarrowerRegistry(narrowers=[amount_narrower])
        
        violation = Violation(
            tier="fiscal",
            code="SOFT_LIMIT_EXCEEDED",
            message="Amount $50000 exceeds soft limit of $25000",
            kind=ViolationKind.NARROWABLE,
        )
        
        result = registry.find_narrower(
            violation=violation,
            action="execute_trade",
            params={"amount": 50000, "symbol": "AAPL"},
        )
        
        assert result is not None
        assert isinstance(result, AmountNarrower)
    
    def test_registry_register_narrower(self):
        """Registry.register() adds a narrower dynamically."""
        registry = NarrowerRegistry()
        amount_narrower = AmountNarrower()
        
        # Verify initially empty
        violation = Violation(
            tier="fiscal",
            code="SOFT_LIMIT_EXCEEDED",
            message="Amount $50000 exceeds soft limit of $25000",
            kind=ViolationKind.NARROWABLE,
        )
        assert registry.find_narrower(violation, "execute_trade", {"amount": 50000}) is None
        
        # Register narrower
        registry.register(amount_narrower)
        
        # Verify now finds the narrower
        result = registry.find_narrower(violation, "execute_trade", {"amount": 50000, "symbol": "AAPL"})
        assert result is not None
        assert isinstance(result, AmountNarrower)
    
    def test_registry_returns_first_matching_narrower(self):
        """Registry returns the first narrower that can handle the violation."""
        class FirstNarrower:
            def can_narrow(self, violation, action, params):
                return "amount" in params
            
            def narrow(self, violation, action, params):
                return NarrowingResult(
                    can_narrow=True,
                    narrowed_params=params,
                    constraints_applied=["first"],
                    narrowing_reason="First narrower",
                )
        
        class SecondNarrower:
            def can_narrow(self, violation, action, params):
                return "amount" in params
            
            def narrow(self, violation, action, params):
                return NarrowingResult(
                    can_narrow=True,
                    narrowed_params=params,
                    constraints_applied=["second"],
                    narrowing_reason="Second narrower",
                )
        
        first = FirstNarrower()
        second = SecondNarrower()
        registry = NarrowerRegistry(narrowers=[first, second])
        
        violation = Violation(
            tier="test",
            code="TEST_VIOLATION",
            message="Test violation",
            kind=ViolationKind.NARROWABLE,
        )
        
        result = registry.find_narrower(violation, "test", {"amount": 100})
        
        # Should return first matching narrower
        assert result is first
        assert result is not second
    
    def test_registry_skips_non_matching_narrowers(self):
        """Registry skips narrowers that cannot handle the violation."""
        class NonMatchingNarrower:
            def can_narrow(self, violation, action, params):
                return False  # Never matches
            
            def narrow(self, violation, action, params):
                raise NotImplementedError("Should not be called")
        
        non_matching = NonMatchingNarrower()
        amount_narrower = AmountNarrower()
        registry = NarrowerRegistry(narrowers=[non_matching, amount_narrower])
        
        violation = Violation(
            tier="fiscal",
            code="SOFT_LIMIT_EXCEEDED",
            message="Amount $50000 exceeds soft limit of $25000",
            kind=ViolationKind.NARROWABLE,
        )
        
        result = registry.find_narrower(
            violation=violation,
            action="execute_trade",
            params={"amount": 50000, "symbol": "AAPL"},
        )
        
        # Should skip non-matching and return amount_narrower
        assert result is amount_narrower
    
    def test_registry_with_multiple_narrowers(self):
        """Registry handles multiple different narrower types."""
        class ScopeNarrower:
            def can_narrow(self, violation, action, params):
                return "scope" in params and "exceeds scope" in violation.message.lower()
            
            def narrow(self, violation, action, params):
                return NarrowingResult(
                    can_narrow=True,
                    narrowed_params={**params, "scope": ["read"]},
                    constraints_applied=["scope <= read"],
                    narrowing_reason="Restricted scope to read-only",
                )
        
        amount_narrower = AmountNarrower()
        scope_narrower = ScopeNarrower()
        registry = NarrowerRegistry(narrowers=[amount_narrower, scope_narrower])
        
        # Test amount violation routes to amount narrower
        amount_violation = Violation(
            tier="fiscal",
            code="SOFT_LIMIT_EXCEEDED",
            message="Amount $50000 exceeds soft limit of $25000",
            kind=ViolationKind.NARROWABLE,
        )
        amount_result = registry.find_narrower(
            amount_violation,
            "execute_trade",
            {"amount": 50000},
        )
        assert isinstance(amount_result, AmountNarrower)
        
        # Test scope violation routes to scope narrower
        scope_violation = Violation(
            tier="scope",
            code="SCOPE_LIMIT_EXCEEDED",
            message="Request exceeds scope limit",
            kind=ViolationKind.NARROWABLE,
        )
        scope_result = registry.find_narrower(
            scope_violation,
            "access_data",
            {"scope": ["read", "write"]},
        )
        assert isinstance(scope_result, ScopeNarrower)


class TestNarrowerProtocol:
    """Test suite for Narrower protocol conformance."""
    
    def test_amount_narrower_conforms_to_protocol(self):
        """AmountNarrower implements the Narrower protocol."""
        narrower = AmountNarrower()
        
        # Verify protocol methods exist
        assert hasattr(narrower, "can_narrow")
        assert hasattr(narrower, "narrow")
        assert callable(narrower.can_narrow)
        assert callable(narrower.narrow)
    
    def test_narrowing_result_is_frozen_dataclass(self):
        """NarrowingResult is an immutable frozen dataclass."""
        result = NarrowingResult(
            can_narrow=True,
            narrowed_params={"amount": 1000},
            constraints_applied=["amount <= 1000"],
            narrowing_reason="Test",
        )
        
        # Verify frozen (immutable)
        with pytest.raises(Exception):  # FrozenInstanceError or AttributeError
            result.can_narrow = False
        
        # Verify fields are accessible
        assert result.can_narrow is True
        assert result.narrowed_params == {"amount": 1000}
        assert result.constraints_applied == ["amount <= 1000"]
        assert result.narrowing_reason == "Test"
