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

from unittest.mock import MagicMock

import pytest

from src.gateway.governance.symbolic_governor import SymbolicGovernor


class MockTier:
    def __init__(self, name, phase, order):
        self._tier_name = name
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

    def claims_action(self, action, params) -> bool:
        return True

    async def evaluate(self, action, params) -> list:
        return []

    async def commit(self, action, params) -> list:
        return []

    async def rollback(self, action, params) -> None:
        pass


@pytest.fixture
def governor():
    return SymbolicGovernor(opa_client=MagicMock())


@pytest.mark.local
@pytest.mark.unit
def test_tier_registry_ordering(governor):
    # Tests registering tiers with explicit order values sorts them by (phase, order, tier_name)
    t1 = MockTier("C", 1, 2)
    t2 = MockTier("B", 1, 1)
    t3 = MockTier("A", 1, 2)

    governor.register_domain_tier(t1)
    governor.register_domain_tier(t2)
    governor.register_domain_tier(t3)

    assert governor.registered_tier_names() == ["B", "A", "C"]


@pytest.mark.local
@pytest.mark.unit
def test_tier_registry_phase_1_ordering(governor):
    # Consensus (phase=1, order=5) sorts before Causal (phase=1, order=6)
    t_consensus = MockTier("Consensus", 1, 5)
    t_causal = MockTier("Causal", 1, 6)

    governor.register_domain_tier(t_causal)
    governor.register_domain_tier(t_consensus)

    assert governor.registered_tier_names() == ["Consensus", "Causal"]


@pytest.mark.local
@pytest.mark.unit
def test_tier_registry_phase_2_ordering(governor):
    # CBF (phase=2, order=3) sorts before Fiscal (phase=2, order=4)
    t_cbf = MockTier("CBF", 2, 3)
    t_fiscal = MockTier("Fiscal", 2, 4)

    governor.register_domain_tier(t_fiscal)
    governor.register_domain_tier(t_cbf)

    assert governor.registered_tier_names() == ["CBF", "Fiscal"]


@pytest.mark.local
@pytest.mark.unit
def test_tier_registry_phase_precedence(governor):
    # Phase 1 tiers sort before Phase 2 tiers with equal order values
    t_p2 = MockTier("Phase2", 2, 1)
    t_p1 = MockTier("Phase1", 1, 1)

    governor.register_domain_tier(t_p2)
    governor.register_domain_tier(t_p1)

    assert governor.registered_tier_names() == ["Phase1", "Phase2"]


@pytest.mark.local
@pytest.mark.unit
def test_tier_registry_duplicate_rejection(governor):
    # Duplicate tier_name raises ValueError
    t1 = MockTier("Duplicate", 1, 1)
    t2 = MockTier("Duplicate", 1, 2)

    governor.register_domain_tier(t1)

    with pytest.raises(ValueError, match="duplicate tier registration"):
        governor.register_domain_tier(t2)
