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

"""Formal model parity test: registered tier order must match proof/model.py.

The proof model defines a static TIERS tuple that specifies the formal
ordering of governance tiers.  This test ensures that when a domain plugin
registers its tiers via ``register_domain_tier()``, the resulting order
matches the tier subsequence declared in the formal model.

Option B (per the plan): The ``TIERS`` tuple in ``proof/model.py`` remains
static; this parity test asserts that runtime registration matches.
"""

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

pytestmark = [pytest.mark.local, pytest.mark.unit]


class _FakeTier:
    """Minimal GovernanceTierPlugin stub for parity testing."""

    def __init__(self, tier_name: str, phase: int, order: int):
        self._tier_name = tier_name
        self._phase = phase
        self._order = order

    @property
    def tier_name(self) -> str:
        return self._tier_name

    @property
    def phase(self) -> int:
        return self._phase

    @property
    def order(self) -> int:
        return self._order

    def claims_action(self, action: str, params: dict[str, Any]) -> bool:
        return True

    async def evaluate(self, action: str, params: dict[str, Any]) -> list:
        return []

    async def commit(self, action: str, params: dict[str, Any]) -> list:
        return []

    async def rollback(self, action: str, params: dict[str, Any]) -> None:
        pass


def _make_governor(**overrides):
    """Create a SymbolicGovernor with mocked dependencies."""
    from src.gateway.governance.symbolic_governor import SymbolicGovernor

    kwargs = {
        "opa_client": MagicMock(),
        "safety_filter": MagicMock(),
        "consensus_engine": MagicMock(),
    }
    kwargs.update(overrides)
    return SymbolicGovernor(**kwargs)


class TestFormalModelParity:
    """Verify registered tier names match the formal model's TIERS tuple."""

    def test_financial_tiers_match_formal_model_subsequence(self):
        """Register tiers matching the formal model's financial-domain tiers.

        The formal model in proof/model.py defines:
            TIERS = ("stpa", "confidence", "cbf", "opa", "fiscal",
                     "consensus", "causal", "fria")

        When a domain plugin registers its tiers with the correct order
        values, the resulting registered_tier_names() must produce the
        same ordering as the formal model.
        """
        # Import the formal model's TIERS tuple
        import proof.model as formal_model

        expected_tiers = list(formal_model.TIERS)

        governor = _make_governor()

        # Register tiers with order values matching the formal model's
        # sequence position (0-indexed).
        for idx, name in enumerate(expected_tiers):
            # Phase 1 for read-only tiers, Phase 2 for mutating tiers
            phase = 2 if name in ("cbf", "fiscal") else 1
            governor.register_domain_tier(_FakeTier(name, phase=phase, order=idx))

        # Verify the registered tier names, within each phase, preserve
        # the relative order from the formal model.
        registered = governor.registered_tier_names()

        # All tier names should be present
        assert set(registered) == set(expected_tiers)

        # Within each phase, the relative ordering must match the formal model.
        phase_1_registered = [t for t in registered if t not in ("cbf", "fiscal")]
        phase_1_expected = [t for t in expected_tiers if t not in ("cbf", "fiscal")]
        assert phase_1_registered == phase_1_expected, (
            f"Phase 1 order mismatch: got {phase_1_registered}, "
            f"expected {phase_1_expected}"
        )

        phase_2_registered = [t for t in registered if t in ("cbf", "fiscal")]
        phase_2_expected = [t for t in expected_tiers if t in ("cbf", "fiscal")]
        assert phase_2_registered == phase_2_expected, (
            f"Phase 2 order mismatch: got {phase_2_registered}, "
            f"expected {phase_2_expected}"
        )

    def test_explicit_order_prevents_alphabetic_inversion(self):
        """D5 regression: alphabetic sort would put 'causal' before 'consensus'.

        The formal model requires consensus (order=5) before causal (order=6).
        Without explicit integer ordering, alphabetic sort on tier_name would
        silently invert this to causal, consensus — breaking the proof's
        invariant.
        """
        governor = _make_governor()

        # Register in reverse alphabetic order to ensure sort uses `order` not name
        governor.register_domain_tier(_FakeTier("causal", phase=1, order=6))
        governor.register_domain_tier(_FakeTier("consensus", phase=1, order=5))

        names = governor.registered_tier_names()
        assert names == ["consensus", "causal"], (
            f"D5 regression: expected consensus before causal, got {names}"
        )

    def test_formal_tiers_tuple_is_stable(self):
        """Smoke test: the TIERS tuple in proof/model.py hasn't changed unexpectedly."""
        import proof.model as formal_model

        expected = (
            "stpa",
            "confidence",
            "cbf",
            "opa",
            "fiscal",
            "consensus",
            "causal",
            "fria",
        )
        assert formal_model.TIERS == expected, (
            f"proof/model.py TIERS changed! Expected {expected}, got {formal_model.TIERS}"
        )
