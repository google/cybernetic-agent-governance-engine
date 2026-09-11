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

"""CAGE Finance Plugin — Domain governance tiers and tool provider."""

from typing import Any

from src.cage_finance.safety.bounding.providers import (
    StubMarketDataProvider,
    StubRollbackCapabilityProvider,
)
from src.cage_finance.safety.bounding.registry import BoundingContractRegistry
from src.cage_finance.tiers.bounding_tier import BoundingContractTierPlugin
from src.cage_finance.tiers.causal_tier import CausalTierPlugin
from src.cage_finance.tiers.cbf_tier import CBFTierPlugin
from src.cage_finance.tiers.consensus_tier import ConsensusTierPlugin
from src.cage_finance.tiers.fiscal_tier import FiscalTierPlugin
from src.gateway.governance.contracts import GovernanceTierPlugin
from src.gateway.governance.ftra.bounding_contract import (
    BoundingContractConfig,
    BoundingContractEnforcer,
)
from src.gateway.governance.schemas.thresholds import THRESHOLDS

# ---------------------------------------------------------------------------
# Canonical action surface (domain plugin's single source of truth)
# ---------------------------------------------------------------------------
# Every action name the cage_finance plugin presents to the FTRA classifier
# MUST appear here. The FTRA staleness gate (scripts/check_ftra_registry_staleness.py)
# and the corresponding conformance tests compare this set against the terminal
# registry to detect entries that are stale in either direction (Issue #107 —
# Mayur Agnihotri, https://github.com/google/cybernetic-agent-governance-engine/issues/107):
#
#   REGISTERED_ACTIONS - registry → actions live in domain but unclassified
#                                   (will silently default to IRREVERSIBLE_TERMINAL)
#   registry - REGISTERED_ACTIONS → registry has entries for actions that no
#                                   longer exist in the domain plugin
#
# Keep this set in sync with:
#   - src/cage_finance/tiers/*/handles() implementations
#   - config/opa/trade_policy.rego action name bindings
#   - config/ftra/terminal_registry.json terminals block
REGISTERED_ACTIONS: frozenset[str] = frozenset(
    {
        "execute_trade",  # IRREVERSIBLE_TERMINAL — classified by all 4 tiers
        "execute_trade_bounded",  # EXTERNALLY_REVERSIBLE — bounding_tier
        "release_wire",  # EXTERNALLY_REVERSIBLE — wire transfer
        "write_db",  # IRREVERSIBLE_TERMINAL — database write
        "check_balance",  # READ_ONLY — balance query
        "prompt_injection_check",  # READ_ONLY — safety pre-screen
    }
)


def create_finance_tiers(
    cbf: Any,
    fiscal_guard: Any,
    consensus_gate: Any,
    bounding_registry: BoundingContractRegistry | None = None,
) -> tuple[GovernanceTierPlugin, ...]:
    """Create finance domain governance tiers for construction-time registration.

    Task 2.1 (ARCH-2): Tier registration is now immutable at construction time.
    This factory returns a tuple of tiers that must be passed to
    SymbolicGovernor.__init__() via the domain_tiers parameter.

    Args:
        cbf: ControlBarrierFunction instance for cash barrier validation
        fiscal_guard: FiscalLimitGuard instance for daily spending limits
        consensus_gate: ConsensusGate instance for multi-model consensus
        bounding_registry: Optional BoundingContractRegistry for Phase 5 bounding tier.
                          If None, bounding tier is created with default stub providers.

    Returns:
        Tuple of finance domain tiers in (phase, order, tier_name) order.
        The tiers are:
        - BoundingContractTierPlugin (phase=2, order=2) — Phase 5 pre-trade constraints
        - CBFTierPlugin (phase=2, order=3) — Cash barrier validation
        - FiscalTierPlugin (phase=2, order=4) — Daily limit reservation
        - ConsensusTierPlugin (phase=1, order=5) — Multi-model consensus
        - CausalTierPlugin (phase=1, order=6) — DoWhy causal gatekeeper
    """
    if bounding_registry is None:
        # Create default bounding registry with stub providers for dev/test
        bounding_config = BoundingContractConfig(
            allowed_instruments={"AAPL", "MSFT", "GOOGL", "AMZN"},
            allowed_venues={"NYSE", "NASDAQ", "CBOE"},
            allowed_counterparties={"BROKER_A", "BROKER_B", "TEST_COUNTERPARTY"},
        )
        bounding_enforcer = BoundingContractEnforcer(bounding_config)
        market_data_provider = StubMarketDataProvider()
        rollback_provider = StubRollbackCapabilityProvider()
        bounding_registry = BoundingContractRegistry(
            thresholds=THRESHOLDS.model_dump(),
            market_data_provider=market_data_provider,
            rollback_provider=rollback_provider,
            enforcer=bounding_enforcer,
        )

    return (
        BoundingContractTierPlugin(bounding_registry),
        CBFTierPlugin(cbf),
        FiscalTierPlugin(fiscal_guard),
        ConsensusTierPlugin(consensus_gate),
        CausalTierPlugin(),
    )
