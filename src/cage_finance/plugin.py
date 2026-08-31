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

from mcp.server.fastmcp import FastMCP

from src.cage_finance.consensus.consensus import ConsensusGate
from src.cage_finance.constants import HITL_CITATIONS as _FC
from src.cage_finance.constants import HITL_SLA_HOURS as _F_SLA
from src.cage_finance.constants import INJECTION_CITATION as _F_INJ
from src.cage_finance.constants import PII_RETENTION_AUTHORITY as _F_PII
from src.cage_finance.safety.cbf import ControlBarrierFunction
from src.cage_finance.safety.fiscal_limit_guard import FiscalLimitGuard
from src.cage_finance.tiers.causal_tier import CausalTierPlugin
from src.cage_finance.tiers.cbf_tier import CBFTierPlugin
from src.cage_finance.tiers.consensus_tier import ConsensusTierPlugin
from src.cage_finance.tiers.fiscal_tier import FiscalTierPlugin
from src.cage_finance.tools.tool_provider import FinancialToolProvider
from src.gateway.governance.constants import (
    HITL_CITATIONS,
    HITL_SLA_HOURS,
    INJECTION_CITATION,
    PII_RETENTION_AUTHORITY,
)
from src.gateway.governance.contracts import CagePlugin, TierRegistry

logger = logging.getLogger(__name__)


class FinanceCagePlugin(CagePlugin):
    """The finance domain capability plugin."""

    name = "finance"
    api_version = "1.0"

    def register(
        self, registry: TierRegistry, tool_server: FastMCP | None = None
    ) -> None:
        cbf = ControlBarrierFunction()
        fiscal_guard = FiscalLimitGuard.from_env()
        consensus_gate = ConsensusGate()

        # Register domain constants
        HITL_CITATIONS.update(_FC)
        HITL_SLA_HOURS.update(_F_SLA)
        PII_RETENTION_AUTHORITY.update(_F_PII)
        INJECTION_CITATION.update(_F_INJ)

        # Register tiers
        registry.register_domain_tier(CBFTierPlugin(cbf))
        registry.register_domain_tier(FiscalTierPlugin(fiscal_guard))
        registry.register_domain_tier(ConsensusTierPlugin(consensus_gate))
        registry.register_domain_tier(CausalTierPlugin())

        # Register tools
        if tool_server:
            provider = FinancialToolProvider()
            provider.register_tools(tool_server)


def get_plugin() -> CagePlugin:
    return FinanceCagePlugin()
