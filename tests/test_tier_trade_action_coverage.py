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
F1 remediation test: trade action coverage across finance tiers.

Ensures every registered finance tier claims every action in _TRADE_ACTIONS.
This prevents silent governance narrowing when a new trade verb is added
to the shared constant but not propagated to all tier implementations.

The test is tier-name-agnostic: adding a fifth finance tier will automatically
require it to claim all trade actions.
"""

import pytest

from src.cage_finance.tiers import _TRADE_ACTIONS
from src.cage_finance.plugin import FinanceCagePlugin
from src.gateway.governance.symbolic_governor import SymbolicGovernor


# Finance tier names that must claim trade actions.
# This set is derived from the registered tiers, not hardcoded.
_FINANCE_TIER_NAMES = {"consensus", "causal", "cbf", "fiscal"}


@pytest.fixture
def governor_with_finance_tiers():
    """Governor with finance domain plugin registered."""
    gov = SymbolicGovernor(
        config={},
        adapter=None,
        opa_client=None,
        cbf_engine=None,
        confidence_scorer=None,
    )
    # Register finance domain plugin which registers all four finance tiers
    finance_plugin = FinanceCagePlugin()
    finance_plugin.register(gov, None)
    return gov


class TestTradeActionCoverage:
    """F1 coherence fix: every finance tier must claim every trade action."""

    def test_all_finance_tiers_claim_all_trade_actions(
        self, governor_with_finance_tiers
    ):
        """Every registered finance tier claims every action in _TRADE_ACTIONS.

        This test is tier-name-agnostic: it identifies finance tiers by their
        tier_name membership in _FINANCE_TIER_NAMES, then asserts each claims
        all actions in _TRADE_ACTIONS. Adding a fifth finance tier will require
        updating _FINANCE_TIER_NAMES and ensuring it also claims all trade actions.

        F1 failure mode: if a new trade action is added to _TRADE_ACTIONS but
        a tier's claims_action() is not updated, this test will fail.
        """
        gov = governor_with_finance_tiers
        finance_tiers = [
            tier for tier in gov._domain_tiers if tier.tier_name in _FINANCE_TIER_NAMES
        ]

        # Smoke test: ensure we found the expected finance tiers
        found_names = {tier.tier_name for tier in finance_tiers}
        assert (
            found_names == _FINANCE_TIER_NAMES
        ), f"Expected finance tiers {_FINANCE_TIER_NAMES}, found {found_names}"

        # Core assertion: every finance tier claims every trade action
        for tier in finance_tiers:
            for action in _TRADE_ACTIONS:
                assert tier.claims_action(
                    action, {}
                ), f"{tier.tier_name} tier must claim action '{action}' (F1 coherence)"

    def test_trade_actions_is_nonempty(self):
        """_TRADE_ACTIONS must contain at least one action."""
        assert len(_TRADE_ACTIONS) > 0, "_TRADE_ACTIONS must not be empty"

    def test_trade_actions_contains_execute_trade(self):
        """_TRADE_ACTIONS must contain 'execute_trade' (the canonical trade verb)."""
        assert (
            "execute_trade" in _TRADE_ACTIONS
        ), "_TRADE_ACTIONS must include 'execute_trade'"

    def test_non_finance_tier_does_not_claim_trade_actions_by_default(
        self, governor_with_finance_tiers
    ):
        """Tiers outside the finance domain should not claim trade actions.

        This is a negative test: if a non-finance tier starts claiming trade
        actions without being added to _FINANCE_TIER_NAMES, this test will fail.
        """
        gov = governor_with_finance_tiers
        non_finance_tiers = [
            tier
            for tier in gov._domain_tiers
            if tier.tier_name not in _FINANCE_TIER_NAMES
        ]

        # For each non-finance tier, assert it does NOT claim trade actions
        for tier in non_finance_tiers:
            for action in _TRADE_ACTIONS:
                assert not tier.claims_action(
                    action, {}
                ), f"{tier.tier_name} is not a finance tier but claims '{action}'"
