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

import logging
from pathlib import Path

from src.cage_finance import (
    REGISTERED_ACTIONS,
    create_finance_tiers,
    is_causal_tier_enabled,
)
from src.cage_finance.narrowers.amount_narrower import AmountNarrower
from src.cage_finance.safety.bounding.contract import (
    BoundingContractConfig,
    BoundingContractEnforcer,
)
from src.cage_finance.safety.bounding.providers import (
    StubMarketDataProvider,
    StubRollbackCapabilityProvider,
)
from src.cage_finance.safety.bounding.registry import BoundingContractRegistry
from src.cage_finance.safety.fiscal_limit_guard import FiscalLimitGuard
from src.cage_finance.tiers.bounding_tier import BoundingContractTierPlugin
from src.cage_finance.tiers.causal_tier import CausalTierPlugin
from src.cage_finance.tiers.cbf_tier import CBFTierPlugin
from src.cage_finance.tiers.consensus_tier import (
    ConsensusTierPlugin,
    build_finance_consensus_gate,
)
from src.cage_finance.tiers.fiscal_tier import FiscalTierPlugin
from src.cage_finance.tiers.trade_confidence_tier import (
    trade_confidence_norm_binding,
)
from src.cage_finance.tools.tool_provider import FinancialToolProvider
from src.gateway.governance.consensus.engine import (
    _background_audit_worker,
    extract_field_magnitude,
)
from src.gateway.governance.contracts import (
    CagePlugin,
    DomainConfig,
    PluginContribution,
)
from src.gateway.governance.governor.assembly import DisabledTier
from src.gateway.governance.safety.cbf_engine import ControlBarrierFunction

logger = logging.getLogger(__name__)

FINANCE_EXECUTION_VERBS: frozenset[str] = frozenset(
    {"buy", "sell", "trade", "transfer", "execute_trade"}
)

# The 5 core deterministic finance tiers. An enforcing posture refuses to start
# if any of them is not enabled (posture check ``required_tiers``); listed
# explicitly so that dropping a tier from ``create_finance_tiers`` fails
# assembly instead of silently shrinking this set. The optional ``causal`` tier
# is gated by ``CAGE_CAUSAL_TIER_ENABLED=true`` and recorded in
# ``disabled_tiers`` when off.
FINANCE_REQUIRED_TIERS: frozenset[str] = frozenset(
    {"trade_confidence", "bounding", "cbf", "fiscal", "consensus"}
)


class FinanceCagePlugin(CagePlugin):
    """The finance domain capability plugin."""

    name = "finance"
    api_version = "2.0"
    domain_config = DomainConfig(
        ftra_registry_path=Path(__file__).resolve().parents[2]
        / "config"
        / "ftra"
        / "terminal_registry.json",
        # src/cage_finance/opa/trade_governance.rego
        opa_package="trade.governance",
        opa_required_rules=("allow",),
        causal_graph_path=Path(__file__).resolve().parent
        / "config"
        / "causal_graph.yaml",
    )

    def contribute(self) -> PluginContribution:
        from src.cage_finance.ground_truth import SimulatedCashLedgerProvider
        from src.cage_finance.invariants import CashBarrier, finance_cost_resolver
        from src.cage_finance.simulated_feeds import (
            SimulatedMarketQuoteFeed,
            SimulatedPortfolioNavSource,
        )
        from src.cage_finance.stpa import SAGA_COMPENSATORS, UCA_RULES
        from src.cage_finance.thresholds import (
            FinanceThresholds,
            load_finance_thresholds,
        )
        from src.cage_finance.tools.trade_inputs import (
            TRADE_ACTIONS,
            ServerTradeInputs,
            TradeInputResolver,
        )
        from src.cage_finance.tools.trader_binding import TraderRoleBindings
        from src.gateway.governance.schemas import thresholds as thresholds_module

        # The region's effective domains.finance (regional overlay applied).
        # The bounding contracts read the same thresholds object, so B1/B2
        # use the region's limits too.
        effective = thresholds_module.THRESHOLDS
        finance = load_finance_thresholds()
        cash_barrier = CashBarrier(gamma=finance.cbf.gamma)
        cash_provider = SimulatedCashLedgerProvider(
            invariant_id=cash_barrier.invariant_id
        )
        cbf = ControlBarrierFunction(
            invariant=cash_barrier,
            cost_resolver=finance_cost_resolver,
            skip_epoch_seed=True,
        )
        consensus_gate = build_finance_consensus_gate()

        # Dev/test bounding providers: permissive allowlists, stub market data
        # and rollback capability (they fail closed in production).
        bounding_registry = BoundingContractRegistry(
            thresholds={
                **effective.model_dump(),
                **effective.domains.get("finance", {}),
            },
            market_data_provider=StubMarketDataProvider(),
            rollback_provider=StubRollbackCapabilityProvider(),
            enforcer=BoundingContractEnforcer(
                BoundingContractConfig(
                    allowed_instruments={"AAPL", "MSFT", "GOOGL", "AMZN"},
                    allowed_venues={"NYSE", "NASDAQ", "CBOE"},
                    allowed_counterparties={
                        "BROKER_A",
                        "BROKER_B",
                        "TEST_COUNTERPARTY",
                    },
                )
            ),
        )
        # One binding is both enforced (the tier) and declared to the kernel
        # (norm_bindings), so the gated value is the enforced value.
        trade_confidence = trade_confidence_norm_binding(
            finance.confidence.min_trade_confidence
        )
        causal_enabled = is_causal_tier_enabled()
        tiers = create_finance_tiers(
            cbf=cbf,
            fiscal_guard=FiscalLimitGuard.from_env(),
            consensus_gate=consensus_gate,
            bounding_registry=bounding_registry,
            trade_confidence=trade_confidence,
            include_causal=causal_enabled,
        )
        disabled_tiers = (
            ()
            if causal_enabled
            else (DisabledTier("causal", "CAGE_CAUSAL_TIER_ENABLED=false"),)
        )
        required_tiers = FINANCE_REQUIRED_TIERS | (
            {"causal"} if causal_enabled else set()
        )
        background_tasks = {"consensus_audit_worker": _background_audit_worker}
        for tier in tiers:
            if isinstance(tier, CausalTierPlugin) and tier.refresher is not None:
                background_tasks["causal_world_model_refresher"] = (
                    tier.refresher.run_forever
                )
        # One resolver serves every path that evaluates a trade (the
        # validate-action and MCP previews and the committing run) for both
        # trade actions, so a bounded trade's B2 drawdown is measured too. It
        # also binds trader_role / trader_id from the caller's verified
        # workload identity; an invalid CAGE_TRADER_ROLE_BINDINGS raises here,
        # so the gateway does not start (GHSA-w39v-5v7h-fxg9).
        trade_inputs = TradeInputResolver(
            ServerTradeInputs(
                market_feed=SimulatedMarketQuoteFeed(),
                nav_source=SimulatedPortfolioNavSource.from_env(),
            ),
            traders=TraderRoleBindings.from_env(),
        )
        from src.cage_finance.rails.provider import FinancialRailsProvider

        return PluginContribution(
            domain=self.name,
            tiers=tiers,
            invariants=(cash_barrier,),
            uca_rules=UCA_RULES,
            saga_compensators=SAGA_COMPENSATORS,
            ground_truth_providers={cash_barrier.invariant_id: cash_provider},
            execution_verbs=FINANCE_EXECUTION_VERBS,
            registered_actions=REGISTERED_ACTIONS,
            magnitude_extractor=extract_field_magnitude("amount"),
            safety_filter=cbf,
            consensus=consensus_gate,
            narrowers=(AmountNarrower(),),
            tool_provider=FinancialToolProvider(),
            threshold_sections={"finance": FinanceThresholds},
            compliance_overlay_dirs=(Path(__file__).parent / "config" / "compliance",),
            background_tasks=background_tasks,
            norm_bindings=(trade_confidence,),
            server_inputs=dict.fromkeys(TRADE_ACTIONS, trade_inputs),
            rail_providers=(FinancialRailsProvider(),),
            required_tiers=required_tiers,
            disabled_tiers=disabled_tiers,
        )


def get_plugin() -> CagePlugin:
    return FinanceCagePlugin()
