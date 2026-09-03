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
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

from src.cage_finance.tiers.causal_tier import CausalTierPlugin
from src.cage_finance.tiers.cbf_tier import CBFTierPlugin
from src.cage_finance.tiers.consensus_tier import ConsensusTierPlugin
from src.cage_finance.tiers.fiscal_tier import FiscalTierPlugin
from src.cage_finance.tools.tool_provider import FinancialToolProvider
from src.gateway.governance.background_tasks import register_background_task
from src.gateway.governance.consensus.engine import (
    ConsensusGate,
    _background_audit_worker,
)
from src.gateway.governance.constants import register_overlay_dir
from src.gateway.governance.contracts import CagePlugin
from src.gateway.governance.safety.cbf_engine import ControlBarrierFunction
from src.gateway.governance.safety.resource_guard import FiscalLimitGuard
from src.gateway.governance.singletons import install_domain_components
from src.gateway.governance.symbolic_governor import SymbolicGovernor

logger = logging.getLogger(__name__)


class FinanceCagePlugin(CagePlugin):
    """The finance domain capability plugin."""

    name = "finance"
    api_version = "1.0"

    def register(
        self, governor: SymbolicGovernor, tool_server: "FastMCP | None" = None
    ) -> None:
        cbf = ControlBarrierFunction()
        fiscal_guard = FiscalLimitGuard.from_env()
        consensus_gate = ConsensusGate()

        # Register compliance overlay directory (PR B, T-B4)
        overlay_dir = Path(__file__).parent / "config" / "compliance"
        register_overlay_dir(overlay_dir)

        # Install domain components into the kernel singletons (PR B, T-B2)
        install_domain_components(
            safety_filter_impl=cbf,
            consensus_engine_impl=consensus_gate,
            resource_guard=fiscal_guard,
        )

        # Register background task (PR B, T-B6)
        register_background_task("consensus_audit_worker", _background_audit_worker)

        # Register tiers
        governor.register_domain_tier(CBFTierPlugin(cbf))
        governor.register_domain_tier(FiscalTierPlugin(fiscal_guard))
        governor.register_domain_tier(ConsensusTierPlugin(consensus_gate))
        governor.register_domain_tier(CausalTierPlugin())

        # Register tools
        if tool_server:
            provider = FinancialToolProvider()
            provider.register_tools(tool_server)


def get_plugin() -> CagePlugin:
    return FinanceCagePlugin()
