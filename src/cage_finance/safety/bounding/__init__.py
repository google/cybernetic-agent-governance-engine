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

"""Bounding contracts (B1-B10) for execute_trade_bounded action.

Phase 5 implementation per plans/phase_5_autonomous_trading_plan.md.
"""

__all__ = [
    "BoundedTradeRequest",
    "BoundingContractRegistry",
    "ContractResult",
    "ContractSeverity",
    "MarketDataProvider",
    "RollbackCapabilityProvider",
    "StubMarketDataProvider",
    "StubRollbackCapabilityProvider",
]

from src.cage_finance.safety.bounding.models import (
    BoundedTradeRequest,
    ContractResult,
    ContractSeverity,
)
from src.cage_finance.safety.bounding.providers import (
    MarketDataProvider,
    RollbackCapabilityProvider,
    StubMarketDataProvider,
    StubRollbackCapabilityProvider,
)
from src.cage_finance.safety.bounding.registry import BoundingContractRegistry
