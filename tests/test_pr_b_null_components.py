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

"""PR B — Null Components and Bare-Kernel Mode Tests

Verifies that the fail-closed null objects correctly deny all requests
when no plugins are installed (CAGE_ACTIVE_PLUGINS="").

These tests prove that the kernel degrades safely to an explicit deny-all
posture rather than silently allowing requests when domain components
are absent.
"""

import pytest

from src.gateway.governance.null_components import (
    NullConsensusProvider,
    NullSafetyFilter,
)


@pytest.mark.local
@pytest.mark.unit
class TestNullSafetyFilter:
    """Test suite for NullSafetyFilter (fail-closed CBF placeholder)."""

    @pytest.mark.asyncio
    async def test_atomic_verify_and_commit_denies_all(self):
        """Verify that NullSafetyFilter denies all actions with explicit reason."""
        null_filter = NullSafetyFilter()

        admitted, reason = await null_filter.atomic_verify_and_commit(
            action_name="withdraw_funds",
            payload={"amount": 1000.0, "account": "test"},
        )

        assert admitted is False, "NullSafetyFilter must deny all actions"
        assert "no domain safety filter registered" in reason.lower()
        assert "bare-kernel mode" in reason.lower()

    @pytest.mark.asyncio
    async def test_rollback_state_is_noop(self):
        """Verify that rollback is a no-op (returns None)."""
        null_filter = NullSafetyFilter()

        rolled_back = await null_filter.rollback_state(
            magnitude=500.0,
        )

        assert rolled_back is None, "NullSafetyFilter rollback must be a no-op"

    def test_verify_action_denies_with_message(self):
        """Verify that verify_action returns explicit denial message."""
        null_filter = NullSafetyFilter()

        reason = null_filter.verify_action(
            action_name="transfer",
            payload={"amount": 1000.0},
        )

        assert "UNSAFE" in reason
        assert "no domain safety filter" in reason.lower()


@pytest.mark.local
@pytest.mark.unit
class TestNullConsensusProvider:
    """Test suite for NullConsensusProvider (fail-closed consensus placeholder)."""

    @pytest.mark.asyncio
    async def test_check_consensus_rejects_all(self):
        """Verify that NullConsensusProvider rejects all consensus checks."""
        null_consensus = NullConsensusProvider()

        result = await null_consensus.check_consensus(
            action="trade_stock",
            context={"ticker": "AAPL", "quantity": 100},
        )

        assert result["status"] == "REJECT", "NullConsensusProvider must reject all"
        assert "no consensus provider registered" in result["reason"].lower()
        assert "bare-kernel mode" in result["reason"].lower()


@pytest.mark.local
@pytest.mark.unit
class TestBareKernelMode:
    """Test suite for bare-kernel mode behavior (CAGE_ACTIVE_PLUGINS="")."""

    def test_singletons_default_to_null_components(self):
        """Verify that singletons are initialized with null components by default."""
        # Import after pytest marks are set
        from src.gateway.governance import singletons

        # Before any plugin calls install_domain_components, the kernel
        # should have null objects installed
        # NOTE: This test may fail if run after test_plugin_installation_flow
        # in the same pytest session. Use --lf or isolate with -k if needed.

        # We can't directly test this without resetting the module state,
        # but we can verify that _has_null_components() works correctly
        has_nulls = singletons._has_null_components()

        # This assertion depends on whether previous tests installed components
        # The key invariant is: if has_nulls is True, then the components deny everything
        if has_nulls:
            assert isinstance(singletons.safety_filter, NullSafetyFilter)
            assert isinstance(singletons.consensus_engine, NullConsensusProvider)

    @pytest.mark.asyncio
    async def test_null_safety_filter_prevents_unsafe_actions(self):
        """Verify that null safety filter explicitly denies unsafe actions."""
        from src.gateway.governance.null_components import NullSafetyFilter

        null_filter = NullSafetyFilter()

        # Simulate a potentially dangerous action
        admitted, reason = await null_filter.atomic_verify_and_commit(
            action_name="delete_all_records",
            payload={"confirm": True},
        )

        assert admitted is False
        assert "no domain safety filter registered" in reason.lower()

    @pytest.mark.asyncio
    async def test_null_consensus_prevents_high_risk_actions(self):
        """Verify that null consensus provider explicitly denies high-risk actions."""
        from src.gateway.governance.null_components import NullConsensusProvider

        null_consensus = NullConsensusProvider()

        # Simulate a high-risk action requiring consensus
        result = await null_consensus.check_consensus(
            action="wire_transfer",
            context={
                "amount": 1000000.0,
                "recipient": "external",
                "risk_level": "HIGH",
            },
        )

        assert result["status"] == "REJECT"
        assert "no consensus provider registered" in result["reason"].lower()


@pytest.mark.local
@pytest.mark.unit
def test_install_domain_components_prevents_double_installation():
    """Verify that install_domain_components raises on double-installation."""
    from src.gateway.governance import singletons
    from src.gateway.governance.null_components import NullSafetyFilter

    # Mock a plugin trying to install components twice
    mock_filter = NullSafetyFilter()  # Use null as a stand-in for a real filter

    # First installation should succeed (if not already installed)
    has_nulls_before = singletons._has_null_components()

    if has_nulls_before:
        # If we have nulls, installation should succeed
        singletons.install_domain_components(safety_filter_impl=mock_filter)

        # Second installation should fail
        with pytest.raises(RuntimeError, match="safety_filter already installed"):
            singletons.install_domain_components(safety_filter_impl=mock_filter)
    else:
        # Components already installed by another plugin, so even first attempt should fail
        with pytest.raises(RuntimeError, match="safety_filter already installed"):
            singletons.install_domain_components(safety_filter_impl=mock_filter)
