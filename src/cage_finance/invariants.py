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

"""Finance domain safety barrier declarations.

Per PR C §7.4: barriers are declarative, not callable. The kernel compiles
(state_key, threshold_key, gamma) into the Lua script at invocation time.

This file contains barrier declarations and the finance-specific cost resolver
that parameterizes the kernel's ControlBarrierFunction engine.
"""

import math
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class CashBarrier:
    """Finance domain barrier: h(x) = cash_balance - min_cash_balance.

    Declarative specification for the affine barrier that prevents
    the agent from depleting its cash reserves below the regulatory floor.

    The barrier algebra (h(x) = x - threshold) is evaluated atomically
    inside Redis via the Lua script in gateway/governance/safety/cbf_engine.py.
    This class only declares the parameters.

    Implements the InvariantModel protocol from src.gateway.governance.contracts.
    """

    invariant_id: str = "finance.cash_balance"
    state_key: str = "safety:current_cash"
    threshold_key: str = "cbf.min_cash_balance"
    gamma: float = 0.5  # Must match THRESHOLDS.cbf.gamma — asserted at registration


def finance_cost_resolver(action_name: str, payload: dict[str, Any]) -> float:
    """Finance domain cost resolver for CBF engine.

    Only ``execute_trade`` and ``execute_trade_bounded`` carry a cash cost;
    every other action is 0. A non-finite (NaN/inf) or negative ``amount`` is
    rejected here so it can never reach the barrier certificate or the Redis
    cash-state write.

    This function is injected into the CBF engine at plugin registration time,
    making the kernel domain-agnostic while preserving the finance-specific
    cost resolution logic.

    Args:
        action_name: Name of the action being evaluated.
        payload: Action parameters dict.

    Returns:
        The cash cost for the action (0.0 for non-trade actions).

    Raises:
        ValueError: If execute_trade or execute_trade_bounded has a non-finite
            or negative amount.
    """
    if action_name not in ("execute_trade", "execute_trade_bounded"):
        return 0.0

    if "amount_minor" in payload and payload["amount_minor"] is not None:
        cost = float(payload["amount_minor"]) / 100.0
    else:
        cost = float(payload.get("amount", 0.0))

    if not math.isfinite(cost) or cost < 0:
        raise ValueError(
            f"invalid trade amount {cost!r} — must be a finite, non-negative number"
        )
    return cost
