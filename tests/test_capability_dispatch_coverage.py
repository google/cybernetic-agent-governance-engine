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

"""Capability-driven dispatch coverage tests.

Validates that capability predicates (claims_action) replace hardcoded action
name literals throughout SymbolicGovernor, ensuring the kernel is domain-agnostic.

Part of: PR A - Capability-Driven Tier Dispatch (Stage 8)
Gate: G2 (capability predicate coverage)
"""

from typing import Any
from unittest.mock import MagicMock

import pytest

from src.gateway.governance.symbolic_governor import SymbolicGovernor


@pytest.fixture
def mock_governor() -> SymbolicGovernor:
    """Create a SymbolicGovernor with mock dependencies."""
    opa_client = MagicMock()
    safety_filter = MagicMock()
    consensus_engine = MagicMock()
    return SymbolicGovernor(opa_client, safety_filter, consensus_engine)


@pytest.mark.local
class TestCapabilityDispatchCoverage:
    """Capability predicate dispatch tests."""

    def test_is_governed_action_accepts_any_action(
        self, mock_governor: SymbolicGovernor
    ) -> None:
        """_is_governed_action() accepts any action name (no hardcoded literals)."""
        gov = mock_governor

        # The kernel is domain-agnostic and should not hardcode action names
        assert gov._is_governed_action("execute_trade", {}) is True
        assert gov._is_governed_action("prescribe_medication", {}) is True
        assert gov._is_governed_action("arbitrary_action", {}) is True

    def test_is_governed_action_returns_bool(
        self, mock_governor: SymbolicGovernor
    ) -> None:
        """_is_governed_action() returns a boolean."""
        gov = mock_governor
        result = gov._is_governed_action("test_action", {})
        assert isinstance(result, bool)

    def test_is_governed_action_with_params(
        self, mock_governor: SymbolicGovernor
    ) -> None:
        """_is_governed_action() accepts params for future predicate expansion."""
        gov = mock_governor

        # Currently accepts any action, but params could be used for
        # future capability-based filtering
        assert gov._is_governed_action("test", {"key": "value"}) is True
        assert gov._is_governed_action("test", {}) is True


@pytest.mark.local
class TestDomainAgnosticismEnforcement:
    """Domain-agnosticism enforcement tests."""

    def test_no_hardcoded_execute_trade_in_kernel(
        self, mock_governor: SymbolicGovernor
    ) -> None:
        """Kernel does not hardcode 'execute_trade' action name."""
        gov = mock_governor

        # The old implementation had literals like:
        # if tool_name == "execute_trade": ...
        # The new implementation uses capability predicates instead.

        # We can't directly test for absence of literals (that's what G6 does),
        # but we can verify the kernel treats all actions uniformly
        assert gov._is_governed_action("execute_trade", {}) is True
        assert gov._is_governed_action("other_action", {}) is True

    def test_kernel_accepts_domain_plugin_actions(
        self, mock_governor: SymbolicGovernor
    ) -> None:
        """Kernel accepts actions from any domain (finance, healthcare, etc)."""
        gov = mock_governor

        # Finance domain
        assert gov._is_governed_action("execute_trade", {}) is True
        assert gov._is_governed_action("reverse_trade", {}) is True

        # Healthcare domain (future PR D)
        assert gov._is_governed_action("prescribe_medication", {}) is True
        assert gov._is_governed_action("adjust_dosage", {}) is True


@pytest.mark.local
class TestCapabilityPredicateContract:
    """Capability predicate contract tests."""

    def test_capability_predicate_signature(
        self, mock_governor: SymbolicGovernor
    ) -> None:
        """Capability predicates accept (action: str, params: dict) -> bool."""
        gov = mock_governor

        # Signature: (action: str, params: dict[str, Any]) -> bool
        result = gov._is_governed_action("test_action", {"param": "value"})
        assert isinstance(result, bool)

    def test_empty_params_accepted(self, mock_governor: SymbolicGovernor) -> None:
        """Capability predicates accept empty params dict."""
        gov = mock_governor
        result = gov._is_governed_action("test_action", {})
        assert isinstance(result, bool)
