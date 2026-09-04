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

"""Bounding contract registry and orchestration.

Phase 5 Master Plan: Config-driven registry that maps contract IDs (B1-B10)
to implementation functions and orchestrates evaluation across all enabled contracts.

Per Section 3 (Architecture):
- Registry is populated from governance_thresholds.json bounding.enabled_contracts
- Each contract is evaluated independently (fail-fast on first HARD_BLOCK failure)
- Severity aggregation: any HARD_BLOCK failure → block execution
- B10 special handling: classification override propagates to tier result
"""

import logging
from typing import Any, Optional

from src.cage_finance.safety.bounding.contracts import (
    contract_b1_max_notional,
    contract_b2_drawdown_breaker,
    contract_b3_liquidity_depth,
    contract_b4_counterparty_concentration,
    contract_b5_volatility_sizing,
    contract_b6_hitl_high_impact,
    contract_b7_audit_trail_sealing,
    contract_b8_twap_slippage,
    contract_b9_jurisdiction_filter,
    contract_b10_rollback_window,
)
from src.cage_finance.safety.bounding.models import (
    BoundedTradeRequest,
    ContractResult,
    ContractSeverity,
)
from src.cage_finance.safety.bounding.providers import (
    MarketDataProvider,
    RollbackCapabilityProvider,
)
from src.gateway.governance.ftra.bounding_contract import BoundingContractEnforcer

logger = logging.getLogger(__name__)


class BoundingContractRegistry:
    """Registry and orchestrator for bounding contracts B1-B10.

    Per Phase 5 Master Plan Section 5:
    - Contracts are config-driven (enabled via governance_thresholds.json)
    - Evaluation order: B1, B2, B3, B4, B5, B6, B7, B8, B9, B10
    - Fail-fast: First HARD_BLOCK failure stops evaluation (optimization)
    - B10 special case: Returns classification override when it fails

    Providers (dependency injection):
    - MarketDataProvider: Required for B3, B5, B8
    - RollbackCapabilityProvider: Required for B10
    - BoundingContractEnforcer: Required for B4, B9
    """

    def __init__(
        self,
        thresholds: dict[str, Any],
        market_data_provider: Optional[MarketDataProvider] = None,
        rollback_provider: Optional[RollbackCapabilityProvider] = None,
        enforcer: Optional[BoundingContractEnforcer] = None,
    ):
        """Initialize bounding contract registry.

        Args:
            thresholds: Governance thresholds dictionary (from governance_thresholds.json)
            market_data_provider: Provider for B3, B5, B8 (optional, uses stub if None)
            rollback_provider: Provider for B10 (optional, uses stub if None)
            enforcer: BoundingContractEnforcer for B4, B9 (optional)
        """
        self.thresholds = thresholds
        self.market_data_provider = market_data_provider
        self.rollback_provider = rollback_provider
        self.enforcer = enforcer

        # Extract bounding contract configuration
        self.bounding_config = thresholds.get("bounding", {})
        self.enabled_contracts = self.bounding_config.get("enabled_contracts", [])

        logger.info(
            "BoundingContractRegistry initialized with %d enabled contracts: %s",
            len(self.enabled_contracts),
            self.enabled_contracts,
        )

    def evaluate_all(
        self, request: BoundedTradeRequest
    ) -> tuple[list[ContractResult], Optional[str]]:
        """Evaluate all enabled bounding contracts for the given request.

        Per Phase 5 Master Plan Section 3.2:
        - Contracts evaluated in order: B1, B2, ..., B10
        - Fail-fast optimization: Stop on first HARD_BLOCK failure
        - B10 special case: Classification override propagates

        Args:
            request: Bounded trade request to validate

        Returns:
            Tuple of (results, classification_override):
            - results: List of ContractResult for each evaluated contract
            - classification_override: "IRREVERSIBLE_TERMINAL" if B10 failed, else None
        """
        results: list[ContractResult] = []
        classification_override: Optional[str] = None

        for contract_id in self.enabled_contracts:
            result = self._evaluate_contract(contract_id, request)

            # B10 returns a tuple (ContractResult, Optional[str])
            if isinstance(result, tuple):
                contract_result, override = result
                results.append(contract_result)
                if override:
                    classification_override = override
                    logger.warning(
                        "Contract %s emitted classification override: %s",
                        contract_id,
                        override,
                    )
            else:
                results.append(result)

            # Fail-fast optimization: Stop on first HARD_BLOCK failure
            # Note: Extract ContractResult from tuple first (B10 returns tuple)
            contract_result = results[-1]  # Use the already-extracted ContractResult
            if (
                not contract_result.admitted
                and contract_result.severity == ContractSeverity.HARD_BLOCK
            ):
                logger.info(
                    "Contract %s HARD_BLOCK failure — stopping evaluation (fail-fast)",
                    contract_id,
                )
                break

        return results, classification_override

    def _evaluate_contract(
        self, contract_id: str, request: BoundedTradeRequest
    ) -> ContractResult | tuple[ContractResult, Optional[str]]:
        """Evaluate a single bounding contract.

        Args:
            contract_id: Contract identifier (B1-B10)
            request: Bounded trade request to validate

        Returns:
            ContractResult (for B1-B9) or tuple[ContractResult, Optional[str]] (for B10)

        Raises:
            ValueError: If contract_id is unknown or provider is missing
        """
        if contract_id == "B1":
            return contract_b1_max_notional(request, self.thresholds)

        elif contract_id == "B2":
            # B2 uses existing drawdown thresholds, no provider needed
            return contract_b2_drawdown_breaker(request, self.thresholds)

        elif contract_id == "B3":
            if self.market_data_provider is None:
                raise ValueError(
                    "Contract B3 requires MarketDataProvider but none was provided"
                )
            return contract_b3_liquidity_depth(
                request, self.thresholds, self.market_data_provider
            )

        elif contract_id == "B4":
            if self.enforcer is None:
                raise ValueError(
                    "Contract B4 requires BoundingContractEnforcer but none was provided"
                )
            return contract_b4_counterparty_concentration(request, self.enforcer)

        elif contract_id == "B5":
            if self.market_data_provider is None:
                raise ValueError(
                    "Contract B5 requires MarketDataProvider but none was provided"
                )
            return contract_b5_volatility_sizing(
                request, self.thresholds, self.market_data_provider
            )

        elif contract_id == "B6":
            return contract_b6_hitl_high_impact(request, self.thresholds)

        elif contract_id == "B7":
            return contract_b7_audit_trail_sealing(request)

        elif contract_id == "B8":
            if self.market_data_provider is None:
                raise ValueError(
                    "Contract B8 requires MarketDataProvider but none was provided"
                )
            return contract_b8_twap_slippage(
                request, self.thresholds, self.market_data_provider
            )

        elif contract_id == "B9":
            if self.enforcer is None:
                raise ValueError(
                    "Contract B9 requires BoundingContractEnforcer but none was provided"
                )
            return contract_b9_jurisdiction_filter(request, self.enforcer)

        elif contract_id == "B10":
            if self.rollback_provider is None:
                raise ValueError(
                    "Contract B10 requires RollbackCapabilityProvider but none was provided"
                )
            return contract_b10_rollback_window(
                request, self.thresholds, self.rollback_provider
            )

        else:
            raise ValueError(f"Unknown contract ID: {contract_id}")
