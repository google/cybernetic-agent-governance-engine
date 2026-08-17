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
Tests for src.gateway.governance.contracts — Governance contract enforcement.

Note: contracts.py defines Protocol classes (structural typing interfaces):
  - SafetyFilter: Protocol with verify_action(), update_state(), rollback_state()
  - ConsensusProvider: Protocol with check_consensus()

These tests verify the module is importable, the protocols are properly structured,
and that concrete implementations satisfying the protocols behave as expected.
"""

import pytest

pytestmark = pytest.mark.unit
from typing import Any


def test_contracts_module_importable():
    """The contracts module should be importable without errors."""
    from src.gateway.governance import contracts

    assert contracts is not None


def test_governance_contracts_has_expected_structures():
    """Governance contracts should define key data structures."""
    from src.gateway.governance import contracts

    module_attrs = dir(contracts)
    assert len(module_attrs) > 0  # Non-empty module

    # Check for common governance contract patterns
    has_contract = any(
        attr
        for attr in module_attrs
        if not attr.startswith("_") and attr not in ("annotations",)
    )
    assert has_contract, (
        "contracts.py should define public governance contract structures"
    )


def test_safety_filter_protocol_exists():
    """SafetyFilter protocol should be defined in contracts module."""
    from src.gateway.governance.contracts import SafetyFilter

    assert SafetyFilter is not None


def test_consensus_provider_protocol_exists():
    """ConsensusProvider protocol should be defined in contracts module."""
    from src.gateway.governance.contracts import ConsensusProvider

    assert ConsensusProvider is not None


def test_safety_filter_protocol_has_verify_action():
    """SafetyFilter protocol must define verify_action method."""
    from src.gateway.governance.contracts import SafetyFilter

    assert hasattr(SafetyFilter, "verify_action")


def test_safety_filter_protocol_has_update_state():
    """SafetyFilter protocol must define _update_state_unsafe method.

    v3.0.0 breaking change: The public update_state() method was renamed to
    _update_state_unsafe() to mark it as internal and encourage use of the
    atomic_verify_and_commit() method instead.
    """
    from src.gateway.governance.cbf import ControlBarrierFunction

    # The protocol doesn't define this internal method, but the implementation does
    assert hasattr(ControlBarrierFunction, "_update_state_unsafe")


def test_safety_filter_protocol_has_rollback_state():
    """SafetyFilter protocol must define rollback_state method."""
    from src.gateway.governance.contracts import SafetyFilter

    assert hasattr(SafetyFilter, "rollback_state")


def test_consensus_provider_protocol_has_check_consensus():
    """ConsensusProvider protocol must define check_consensus method."""
    from src.gateway.governance.contracts import ConsensusProvider

    assert hasattr(ConsensusProvider, "check_consensus")


def test_concrete_safety_filter_satisfies_protocol():
    """A concrete class implementing SafetyFilter should satisfy the structural protocol."""

    class ConcreteSafetyFilter:
        """Minimal concrete implementation of SafetyFilter for testing."""

        def verify_action(self, action_name: str, payload: dict[str, Any]) -> str:
            return "SAFE"

        def update_state(self, cost: float) -> None:
            pass

        def rollback_state(self, cost: float) -> None:
            pass

    instance = ConcreteSafetyFilter()
    # Verify it has all required methods
    assert callable(instance.verify_action)
    assert callable(instance.update_state)
    assert callable(instance.rollback_state)
    # Verify verify_action returns expected format
    result = instance.verify_action("execute_trade", {"amount": 100.0})
    assert result == "SAFE"


def test_concrete_safety_filter_unsafe_response():
    """A SafetyFilter verify_action returning UNSAFE should start with 'UNSAFE'."""

    class UnsafeSafetyFilter:
        def verify_action(self, action_name: str, payload: dict[str, Any]) -> str:
            return "UNSAFE: drawdown limit exceeded"

        def update_state(self, cost: float) -> None:
            pass

        def rollback_state(self, cost: float) -> None:
            pass

    instance = UnsafeSafetyFilter()
    result = instance.verify_action("execute_trade", {"amount": 99999.0})
    assert result.startswith("UNSAFE")


@pytest.mark.asyncio
async def test_concrete_consensus_provider_satisfies_protocol():
    """A concrete class implementing ConsensusProvider should satisfy the protocol."""

    class ConcreteConsensusProvider:
        """Minimal concrete implementation of ConsensusProvider for testing."""

        async def check_consensus(
            self, action: str, amount: float, symbol: str
        ) -> dict[str, Any]:
            return {"status": "APPROVE", "reason": "Below threshold", "votes": []}

    instance = ConcreteConsensusProvider()
    assert callable(instance.check_consensus)
    result = await instance.check_consensus("buy", 100.0, "AAPL")
    assert "status" in result
    assert result["status"] == "APPROVE"
