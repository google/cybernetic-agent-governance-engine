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

from src.cage_finance.safety.bounding.contract import (
    BoundingContractConfig,
    BoundingContractEnforcer,
)
from src.cage_finance.safety.bounding.providers import (
    StubMarketDataProvider,
    StubRollbackCapabilityProvider,
)
from src.cage_finance.safety.bounding.registry import BoundingContractRegistry
from src.cage_finance.tiers.bounding_tier import BoundingContractTierPlugin
from src.cage_finance.tiers.causal_tier import (
    CausalTierPlugin,
    build_finance_causal_gatekeeper,
)
from src.cage_finance.tiers.cbf_tier import CBFTierPlugin
from src.cage_finance.tiers.consensus_tier import ConsensusTierPlugin
from src.cage_finance.tiers.fiscal_tier import FiscalTierPlugin
from src.cage_finance.tiers.trade_confidence_tier import (
    TradeConfidenceTier,
    trade_confidence_norm_binding,
)
from src.gateway.governance.causal.gatekeeper import CausalGatekeeper
from src.gateway.governance.causal.world_model_refresher import WorldModelRefresher
from src.gateway.governance.contracts import GovernanceTier, NormBinding
from src.gateway.governance.feature_flags import opt_in_enabled
from src.gateway.governance.schemas.thresholds import THRESHOLDS
from src.gateway.governance.telemetry_provider import (
    BaseTelemetryProvider,
    get_telemetry_provider,
)

CAGE_CAUSAL_TIER_ENABLED_ENV = "CAGE_CAUSAL_TIER_ENABLED"


def is_causal_tier_enabled() -> bool:
    """Return True only when ``CAGE_CAUSAL_TIER_ENABLED`` explicitly opts in.

    Defaults to ``False``, so the 5 core deterministic finance tiers run
    without the DoWhy causal gatekeeper or ``WorldModelRefresher``. Parsed by
    the kernel's :func:`~src.gateway.governance.feature_flags.opt_in_enabled`,
    which every opt-in switch shares. Any value other than ``true``/``false``/
    ``1``/``0`` raises ``ConfigurationError`` at assembly rather than silently
    enabling or disabling the tier.
    """
    return opt_in_enabled(CAGE_CAUSAL_TIER_ENABLED_ENV)


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
        "execute_trade",  # IRREVERSIBLE_TERMINAL — consensus, cbf, fiscal (+ optional causal)
        "execute_trade_bounded",  # EXTERNALLY_REVERSIBLE — bounding, cbf, fiscal (claim-by-cost)
        "check_balance",  # READ_ONLY — balance query
        "market_analysis",  # READ_ONLY — market-data lookups by the data analyst
        "check_market_status",  # READ_ONLY — planner's market-open check
        "prompt_injection_check",  # READ_ONLY — safety pre-screen
    }
)


def create_finance_tiers(
    cbf: Any,
    fiscal_guard: Any,
    consensus_gate: Any,
    bounding_registry: BoundingContractRegistry | None = None,
    telemetry_provider: BaseTelemetryProvider | None = None,
    trade_confidence: NormBinding | None = None,
    *,
    causal_gatekeeper: CausalGatekeeper | None = None,
    world_model_refresher: WorldModelRefresher | None = None,
    include_causal: bool | None = None,
) -> tuple[GovernanceTier, ...]:
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
        telemetry_provider: Live telemetry source for the causal tier. If None
                          and the causal tier is enabled, resolved by
                          ``get_telemetry_provider()`` from
                          ``CAGE_TELEMETRY_PROVIDER`` (``remote`` without
                          credentials raises ``ConfigurationError`` here, at
                          assembly, rather than on the first trade).
        trade_confidence: [CTRL_AGT_001] binding of the regional
                          trade-confidence floor. If None, built from the
                          active region's effective
                          ``domains.finance.confidence.min_trade_confidence``.
        causal_gatekeeper: Optional pre-built :class:`CausalGatekeeper`.
        world_model_refresher: Optional pre-built :class:`WorldModelRefresher`.
        include_causal: Whether to include the optional ``CausalTierPlugin``.
                          If None, enabled when ``is_causal_tier_enabled()`` is
                          True or when any causal dependency
                          (``telemetry_provider``, ``causal_gatekeeper``, or
                          ``world_model_refresher``) is explicitly supplied.

    Returns:
        Tuple of finance domain tiers in (phase, order, tier_name) order.
        The core tiers are:
        - TradeConfidenceTier (phase=1, order=1) — Regional trade-confidence floor
        - BoundingContractTierPlugin (phase=1, order=2) — Phase 5 pre-trade constraints
        - CBFTierPlugin (phase=2, order=3) — Cash barrier validation
        - FiscalTierPlugin (phase=2, order=4) — Daily limit reservation
        - ConsensusTierPlugin (phase=1, order=5) — Multi-model consensus
        When ``include_causal`` resolves to True, also appends:
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
            thresholds={
                **THRESHOLDS.model_dump(),
                **THRESHOLDS.domains.get("finance", {}),
            },
            market_data_provider=market_data_provider,
            rollback_provider=rollback_provider,
            enforcer=bounding_enforcer,
        )

    if trade_confidence is None:
        from src.cage_finance.thresholds import load_finance_thresholds

        trade_confidence = trade_confidence_norm_binding(
            load_finance_thresholds().confidence.min_trade_confidence
        )

    core_tiers: tuple[GovernanceTier, ...] = (
        TradeConfidenceTier(trade_confidence),
        BoundingContractTierPlugin(bounding_registry),
        CBFTierPlugin(cbf),
        FiscalTierPlugin(fiscal_guard),
        ConsensusTierPlugin(consensus_gate),
    )

    if include_causal is None:
        include_causal = is_causal_tier_enabled() or any(
            x is not None
            for x in (telemetry_provider, causal_gatekeeper, world_model_refresher)
        )

    if not include_causal:
        return core_tiers

    resolved_provider = telemetry_provider or get_telemetry_provider()
    resolved_gatekeeper = causal_gatekeeper or build_finance_causal_gatekeeper()
    resolved_refresher = world_model_refresher or WorldModelRefresher(
        resolved_gatekeeper,
        resolved_provider,
    )

    return (
        *core_tiers,
        CausalTierPlugin(
            causal_gatekeeper=resolved_gatekeeper,
            telemetry_provider=resolved_provider,
            world_model_refresher=resolved_refresher,
        ),
    )
