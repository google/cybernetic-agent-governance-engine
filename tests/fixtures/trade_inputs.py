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

"""Server-side trade inputs and governor stand-ins for ``execute_trade_action`` tests.

The trade tool binds nothing itself: the governor's committing run
(``SymbolicGovernor.govern`` / ``revalidate_post_hitl``) binds
``latency_ms`` / ``drawdown`` / ``portfolio_total`` and the trader
(``trader_role`` / ``trader_id``) exactly once through its ``execute_trade``
server-input resolver, and returns the evaluated params it sealed as
``SealedAction.params``, which the tool verifies and actuates.

* :func:`trade_server_inputs` is that resolver over simulated sources, as the
  finance plugin wires it.
* :func:`trade_governor` is a ``MagicMock`` governor for tests that replace
  the governance call (``enforce_governance`` / ``enforce_approved_governance``)
  and so only need its execution ledger and ``settle``.
* :func:`sealed_governance` is such a replacement: it seals the params the
  tool hands it, as a committing run whose resolvers bind nothing does.
* :func:`committing_trade_governor` is a real governor whose committing run
  binds the trade inputs, for tests that observe the kernel binding.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, MagicMock

from src.cage_finance.simulated_feeds import (
    SimulatedMarketQuoteFeed,
    SimulatedPortfolioNavSource,
)
from src.cage_finance.tools.trade_inputs import (
    TRADE_ACTIONS,
    ServerTradeInputs,
    TradeInputResolver,
)
from src.cage_finance.tools.trader_binding import TraderRoleBindings
from src.gateway.governance.execution_idempotency import ExecutionLedger
from src.gateway.governance.governor.sealing import SealedAction

if TYPE_CHECKING:
    from src.gateway.governance.governor.governor import SymbolicGovernor


def trade_server_inputs(
    *,
    market_feed: Any = None,
    nav_source: Any = None,
    no_market_feed: bool = False,
    no_nav_source: bool = False,
    traders: TraderRoleBindings | None = None,
) -> dict[str, TradeInputResolver]:
    """The trade resolver for every trade action, as the finance plugin wires it.

    Defaults are in limit in every region: a 10 ms quote age and a flat day
    (no drawdown, NAV = opening NAV). ``traders`` binds ``trader_role`` /
    ``trader_id``; by default every verified identity is ``junior``, and so is
    a call with no identity in the (permissive) test posture.
    """
    return dict.fromkeys(
        TRADE_ACTIONS,
        TradeInputResolver(
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
            ),
            traders=TraderRoleBindings() if traders is None else traders,
        ),
    )


def trade_governor(server_inputs: dict[str, Any] | None = None) -> MagicMock:
    """A governor stand-in: settles nothing, with a real execution ledger.

    ``components.server_inputs`` carries the real trade resolver so a test
    can bind with it, but nothing binds through this stand-in: tests that
    use it replace the governance call (see :func:`sealed_governance`).
    """
    governor = MagicMock(settle=AsyncMock(return_value=[]))
    governor.components.server_inputs = (
        trade_server_inputs() if server_inputs is None else server_inputs
    )
    governor.components.execution_ledger = ExecutionLedger(None)
    return governor


def sealed_governance(seal: str) -> Callable[..., SealedAction]:
    """A governance stand-in sealing the params it is handed, as ``seal``.

    Use it as the ``side_effect`` of an ``AsyncMock`` that replaces
    ``enforce_governance`` or ``enforce_approved_governance``: the returned
    ``SealedAction`` carries a copy of the params the tool passed, as a
    committing run whose resolvers bind nothing returns them.
    """

    def _seal(
        _governor: Any, action: str, params: dict[str, Any], **_kwargs: Any
    ) -> SealedAction:
        return SealedAction(action, seal, dict(params))

    return _seal


def committing_trade_governor(
    server_inputs: dict[str, Any] | None = None,
    *,
    ground_truth_providers: Mapping[str, object] | None = None,
) -> SymbolicGovernor:
    """A real governor whose committing run binds the trade's server inputs.

    ``SymbolicGovernor.govern`` binds ``server_inputs`` (default:
    :func:`trade_server_inputs`) exactly once, as in production; an
    unavailable source blocks the run on infrastructure before any stage
    runs. The stages are ``make_governor``'s permissive defaults and the
    execution ledger is the process-local one.
    """
    from src.gateway.governance.governor.governor import SymbolicGovernor
    from tests.fixtures.governor import make_governor

    governor = make_governor(
        server_inputs=trade_server_inputs() if server_inputs is None else server_inputs,
        execution_ledger=ExecutionLedger(None),
    )
    if ground_truth_providers:
        governor = SymbolicGovernor(
            dataclasses.replace(
                governor.components,
                ground_truth_providers=dict(ground_truth_providers),
            )
        )
    return governor
