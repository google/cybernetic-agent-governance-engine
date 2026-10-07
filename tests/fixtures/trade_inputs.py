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

"""Server-side trade inputs for tests that drive ``execute_trade_action``.

The trade tool binds ``latency_ms`` / ``drawdown`` / ``portfolio_total`` through
the governor's ``execute_trade`` server-input resolver. Tests that stand in a
``MagicMock`` governor give it a real resolver over simulated sources.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

from src.cage_finance.simulated_feeds import (
    SimulatedMarketQuoteFeed,
    SimulatedPortfolioNavSource,
)
from src.cage_finance.tools.trade_inputs import ServerTradeInputs, TradeInputResolver


def trade_server_inputs(
    *,
    market_feed: Any = None,
    nav_source: Any = None,
    no_market_feed: bool = False,
    no_nav_source: bool = False,
) -> dict[str, TradeInputResolver]:
    """``execute_trade`` resolver; defaults are in limit in every region.

    A 10 ms quote age and a flat day (no drawdown, NAV = opening NAV).
    """
    return {
        "execute_trade": TradeInputResolver(
            ServerTradeInputs(
                market_feed=None
                if no_market_feed
                else (
                    market_feed
                    or SimulatedMarketQuoteFeed(
                        seed=0, publication_delay_ms=(10.0, 10.0)
                    )
                ),
                nav_source=None
                if no_nav_source
                else (nav_source or SimulatedPortfolioNavSource()),
            )
        )
    }


def trade_governor(server_inputs: dict[str, Any] | None = None) -> MagicMock:
    """A governor stand-in: settles nothing, binds real server-side inputs."""
    governor = MagicMock(settle=AsyncMock(return_value=[]))
    governor.components.server_inputs = (
        trade_server_inputs() if server_inputs is None else server_inputs
    )
    return governor
