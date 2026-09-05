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
B9 - Jurisdictional Asset Filter

Validates: Asset allowed in current CAGE_DEPLOYMENT_REGION
Enforcement: Jurisdiction reject (US_FED/EU_ECB/APAC_MAS filters)

Enforces regional compliance by blocking trades in assets that are restricted
in the deployment region. Integrates with CAGE_DEPLOYMENT_REGION environment
variable and regional overlay configurations.
"""

import os
from typing import Any, Optional

from . import BoundingContract, BoundingContractResult, ContractViolation

# Regional asset restrictions (illustrative examples)
REGIONAL_RESTRICTIONS: dict[str, dict[str, list[str]]] = {
    "US_FED": {
        "blocked_assets": ["USDT"],  # Stablecoins may have restrictions
        "blocked_categories": ["synthetic_derivatives"],
    },
    "EU_ECB": {
        "blocked_assets": [],
        "blocked_categories": ["privacy_coins"],  # MiCA regulations
    },
    "APAC_MAS": {
        "blocked_assets": [],
        "blocked_categories": ["leveraged_tokens"],  # MAS leverage limits
    },
    "LOCAL": {
        "blocked_assets": [],
        "blocked_categories": [],
    },
}


class B9JurisdictionFilter(BoundingContract):
    """B9 - Jurisdictional Asset Filter contract."""

    @property
    def contract_id(self) -> str:
        return "B9"

    def get_enforcement_action(self) -> str:
        return "JURISDICTION_REJECT"

    def validate(
        self, trade_params: dict[str, Any]
    ) -> tuple[BoundingContractResult, ContractViolation | None]:
        """
        Validate asset against regional restrictions.

        Args:
            trade_params: Must contain:
                - symbol: str (asset ticker)
                - asset_category: str (optional - e.g., "synthetic_derivatives")
                - deployment_region: str (optional - defaults to CAGE_DEPLOYMENT_REGION env)

        Returns:
            (PASSED, None) if asset is allowed in region
            (FAILED, violation) if asset is blocked in region
        """
        symbol = str(trade_params.get("symbol", "")).upper()
        asset_category = str(trade_params.get("asset_category", ""))
        region_param = trade_params.get("deployment_region")
        region = (
            str(region_param)
            if region_param
            else os.getenv("CAGE_DEPLOYMENT_REGION", "LOCAL")
        )

        restrictions_dict = REGIONAL_RESTRICTIONS.get(
            region, REGIONAL_RESTRICTIONS["LOCAL"]
        )
        blocked_assets = restrictions_dict.get("blocked_assets", [])
        blocked_categories = restrictions_dict.get("blocked_categories", [])

        # Check if asset is explicitly blocked
        if symbol in blocked_assets:
            violation = ContractViolation(
                contract_id=self.contract_id,
                parameter="symbol",
                limit=0.0,
                actual=1.0,
                severity=self.get_enforcement_action(),
                message=f"B9: Asset {symbol} is blocked in region {region}",
            )
            return (BoundingContractResult.FAILED, violation)

        # Check if asset category is blocked
        if asset_category and asset_category in blocked_categories:
            violation = ContractViolation(
                contract_id=self.contract_id,
                parameter="asset_category",
                limit=0.0,
                actual=1.0,
                severity=self.get_enforcement_action(),
                message=f"B9: Asset category {asset_category} is blocked in region {region}",
            )
            return (BoundingContractResult.FAILED, violation)

        return (BoundingContractResult.PASSED, None)
