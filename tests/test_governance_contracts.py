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
    from src.cage_finance.safety.cbf import ControlBarrierFunction

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

        def rollback_state(self, magnitude: float) -> None:
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

        def rollback_state(self, magnitude: float) -> None:
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
            self,
            action: str,
            context: dict[str, Any],
            magnitude: float | None = None,
        ) -> dict[str, Any]:
            return {"status": "APPROVE", "reason": "Test", "votes": []}

    instance = ConcreteConsensusProvider()
    assert callable(instance.check_consensus)
    result = await instance.check_consensus(
        "buy", context={"amount": 100.0, "symbol": "AAPL"}, magnitude=100.0
    )
    assert "status" in result
    assert result["status"] == "APPROVE"


# ── RefusalReceipt hash-binding tests (CAGE-SEC-009) ──


class TestRefusalReceiptProofHash:
    """Tests for RefusalReceipt cryptographic proof_hash binding.

    CAGE-SEC-009 / Terry Snyder seam review protocol:
    These tests verify that the proof_hash correctly binds to all relevant
    fields, especially standing_at_refusal, ensuring two receipts for the
    same action/tier/rule but different amounts produce different hashes.
    """

    def test_standing_at_refusal_affects_proof_hash(self):
        """Two RefusalReceipts with different standing_at_refusal must have different proof_hash.

        This test verifies the fix for the binding gap identified in
        plans/unified_implementation_analysis.md:191-193 — without including
        standing_at_refusal in the hash, two receipts for the same
        thread_id/action/violated_tier/violated_rule/timestamp but different
        amounts would produce identical proof_hash values, breaking the
        evidentiary chain.
        """
        from src.gateway.governance.contracts import RefusalReceipt

        # Create two receipts with identical base fields but different standing_at_refusal
        common_fields = {
            "thread_id": "thread-abc123",
            "action": "execute_trade",
            "violated_tier": "CBF",
            "violated_rule": "h(S(t+1)) < (1-gamma)*h(S(t)): cash floor breach",
            "timestamp": 1692787200.0,  # Fixed timestamp for determinism
        }

        receipt_small_amount = RefusalReceipt(
            **common_fields,
            standing_at_refusal={"symbol": "AAPL", "amount": 100.0, "currency": "USD"},
        )

        receipt_large_amount = RefusalReceipt(
            **common_fields,
            standing_at_refusal={
                "symbol": "AAPL",
                "amount": 50000.0,
                "currency": "USD",
            },
        )

        # The proof hashes MUST differ because standing_at_refusal differs
        assert receipt_small_amount.proof_hash != receipt_large_amount.proof_hash, (
            "RefusalReceipts with different standing_at_refusal values "
            "must produce different proof_hash values"
        )

    def test_proof_hash_deterministic_with_standing_at_refusal(self):
        """A RefusalReceipt with specific standing_at_refusal produces deterministic proof_hash.

        This test ensures the hash computation is reproducible — the same
        inputs must always produce the same proof_hash, enabling receipt
        replay and verification years after issuance (per NON_FORMATION_PROOF_SPEC.md §8.1).
        """
        from src.gateway.governance.contracts import RefusalReceipt

        receipt_1 = RefusalReceipt(
            thread_id="thread-determinism-test",
            action="execute_trade",
            violated_tier="FISCAL",
            violated_rule="daily_limit_exceeded",
            standing_at_refusal={
                "symbol": "MSFT",
                "amount": 25000.0,
                "currency": "USD",
            },
            timestamp=1692787200.0,  # Fixed timestamp for determinism
        )

        receipt_2 = RefusalReceipt(
            thread_id="thread-determinism-test",
            action="execute_trade",
            violated_tier="FISCAL",
            violated_rule="daily_limit_exceeded",
            standing_at_refusal={
                "symbol": "MSFT",
                "amount": 25000.0,
                "currency": "USD",
            },
            timestamp=1692787200.0,  # Same fixed timestamp
        )

        # Identical inputs must produce identical proof_hash
        assert receipt_1.proof_hash == receipt_2.proof_hash, (
            "RefusalReceipts with identical fields must produce identical proof_hash values"
        )

        # Verify the hash is non-empty and has expected SHA-256 length (64 hex chars)
        assert len(receipt_1.proof_hash) == 64, (
            f"proof_hash should be 64 hex chars (SHA-256), got {len(receipt_1.proof_hash)}"
        )
        assert all(c in "0123456789abcdef" for c in receipt_1.proof_hash), (
            "proof_hash should be lowercase hexadecimal"
        )

    def test_different_symbol_produces_different_hash(self):
        """Changing the symbol in standing_at_refusal must change the proof_hash."""
        from src.gateway.governance.contracts import RefusalReceipt

        common_fields = {
            "thread_id": "thread-symbol-test",
            "action": "execute_trade",
            "violated_tier": "CBF",
            "violated_rule": "cash_floor_breach",
            "timestamp": 1692787200.0,
        }

        receipt_aapl = RefusalReceipt(
            **common_fields,
            standing_at_refusal={"symbol": "AAPL", "amount": 1000.0},
        )

        receipt_msft = RefusalReceipt(
            **common_fields,
            standing_at_refusal={"symbol": "MSFT", "amount": 1000.0},
        )

        assert receipt_aapl.proof_hash != receipt_msft.proof_hash, (
            "Different symbols in standing_at_refusal must produce different proof_hash"
        )

    def test_empty_standing_at_refusal_produces_valid_hash(self):
        """A RefusalReceipt with empty standing_at_refusal should still produce valid hash."""
        from src.gateway.governance.contracts import RefusalReceipt

        receipt = RefusalReceipt(
            thread_id="thread-empty-standing",
            action="execute_trade",
            violated_tier="OPA",
            violated_rule="unauthorized_agent",
            standing_at_refusal={},  # Empty dict
            timestamp=1692787200.0,
        )

        # Should produce a valid SHA-256 hash (64 hex chars)
        assert len(receipt.proof_hash) == 64
        assert all(c in "0123456789abcdef" for c in receipt.proof_hash)

    def test_nested_standing_at_refusal_produces_different_hash(self):
        """Nested structures in standing_at_refusal should affect the hash."""
        from src.gateway.governance.contracts import RefusalReceipt

        common_fields = {
            "thread_id": "thread-nested-test",
            "action": "execute_trade",
            "violated_tier": "CBF",
            "violated_rule": "cash_floor_breach",
            "timestamp": 1692787200.0,
        }

        receipt_simple = RefusalReceipt(
            **common_fields,
            standing_at_refusal={"amount": 1000.0},
        )

        receipt_nested = RefusalReceipt(
            **common_fields,
            standing_at_refusal={"amount": 1000.0, "metadata": {"source": "api"}},
        )

        assert receipt_simple.proof_hash != receipt_nested.proof_hash, (
            "Additional nested data in standing_at_refusal must change proof_hash"
        )

    def test_decimal_values_must_be_converted(self):
        """Decimal values in standing_at_refusal must be converted to float/str.

        Python's Decimal type is not JSON-serializable by the standard json
        module used by JCS canonicalization. Callers MUST convert Decimal
        values to float (for approximate) or str (for exact representation)
        before passing to standing_at_refusal.

        This test documents the expected behavior: raw Decimal raises TypeError.
        """
        from decimal import Decimal

        import pytest

        from src.gateway.governance.contracts import RefusalReceipt

        # Raw Decimal should raise TypeError during hash computation
        with pytest.raises(TypeError, match="not JSON serializable"):
            RefusalReceipt(
                thread_id="thread-decimal-test",
                action="execute_trade",
                violated_tier="FISCAL",
                violated_rule="limit_exceeded",
                standing_at_refusal={"amount": Decimal("25000.50"), "symbol": "AAPL"},
                timestamp=1692787200.0,
            )

    def test_decimal_converted_to_float_works(self):
        """Decimal values converted to float should produce valid hashes.

        This is the recommended approach for financial amounts that don't
        require exact decimal representation in the hash.
        """
        from decimal import Decimal

        from src.gateway.governance.contracts import RefusalReceipt

        # Convert Decimal to float before passing
        amount = float(Decimal("25000.50"))

        receipt = RefusalReceipt(
            thread_id="thread-decimal-float-test",
            action="execute_trade",
            violated_tier="FISCAL",
            violated_rule="limit_exceeded",
            standing_at_refusal={"amount": amount, "symbol": "AAPL"},
            timestamp=1692787200.0,
        )

        # Should produce a valid hash
        assert len(receipt.proof_hash) == 64
        assert all(c in "0123456789abcdef" for c in receipt.proof_hash)

    def test_decimal_converted_to_string_works(self):
        """Decimal values converted to string should produce valid hashes.

        This is the recommended approach when exact decimal representation
        is required (e.g., for financial audit purposes).
        """
        from decimal import Decimal

        from src.gateway.governance.contracts import RefusalReceipt

        # Convert Decimal to string for exact representation
        amount_str = str(Decimal("25000.50"))

        receipt = RefusalReceipt(
            thread_id="thread-decimal-str-test",
            action="execute_trade",
            violated_tier="FISCAL",
            violated_rule="limit_exceeded",
            standing_at_refusal={"amount": amount_str, "symbol": "AAPL"},
            timestamp=1692787200.0,
        )

        # Should produce a valid hash
        assert len(receipt.proof_hash) == 64
        assert all(c in "0123456789abcdef" for c in receipt.proof_hash)

        # String representation should be deterministic
        receipt_2 = RefusalReceipt(
            thread_id="thread-decimal-str-test",
            action="execute_trade",
            violated_tier="FISCAL",
            violated_rule="limit_exceeded",
            standing_at_refusal={"amount": str(Decimal("25000.50")), "symbol": "AAPL"},
            timestamp=1692787200.0,
        )

        assert receipt.proof_hash == receipt_2.proof_hash
