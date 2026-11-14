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

    ``gamma`` has no default: the plugin passes the region's effective
    ``domains.finance.cbf.gamma`` (``load_finance_thresholds().cbf.gamma``), so
    the barrier enforces the same decay rate the thresholds declare.
    """

    gamma: float
    invariant_id: str = "finance.cash_balance"
    state_key: str = "safety:current_cash"
    threshold_key: str = "domains.finance.cbf.min_cash_balance"
    initial_state: float = 100_000.0
    requires_external_ground_truth: bool = True


def _parse_trade_number(raw: Any) -> float:
    """Parse a non-boolean, finite, non-negative trade numeric value."""
    if isinstance(raw, bool) or not isinstance(raw, (int, float, str)):
        raise ValueError(
            f"invalid trade amount {raw!r} — must be a finite, non-negative number"
        )
    try:
        value = float(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"invalid trade amount {raw!r} — must be a finite, non-negative number"
        ) from exc
    if not math.isfinite(value) or value < 0:
        raise ValueError(
            f"invalid trade amount {value!r} — must be a finite, non-negative number"
        )
    return value


def finance_cost_resolver(action_name: str, payload: dict[str, Any]) -> float:
    """Finance domain cost resolver for CBF engine.

    Only ``execute_trade`` and ``execute_trade_bounded`` carry a cash cost;
    every other action is 0. Non-finite (NaN/inf), boolean, negative,
    fractional-cent ``amount_minor``, or conflicting ``amount`` / ``amount_minor``
    values fail closed with ``ValueError`` (POAM-2026-208).
    """
    if action_name not in ("execute_trade", "execute_trade_bounded"):
        return 0.0

    has_minor = "amount_minor" in payload and payload["amount_minor"] is not None
    has_amount = "amount" in payload and payload["amount"] is not None

    if has_minor:
        raw_minor = payload["amount_minor"]
        minor_f = _parse_trade_number(raw_minor)
        if not minor_f.is_integer():
            raise ValueError(
                f"invalid trade amount_minor {raw_minor!r} — minor units must be whole integers"
            )
        if has_amount:
            raw_amount = payload["amount"]
            amount_f = _parse_trade_number(raw_amount)
            if int(round(amount_f * 100)) != int(round(minor_f)):
                raise ValueError(
                    f"Conflicting trade amounts: amount={raw_amount!r} does not match amount_minor={raw_minor!r}"
                )
        return minor_f / 100.0

    raw_amount = payload.get("amount", 0.0)
    return _parse_trade_number(raw_amount)


resolve_finance_trade_cost = finance_cost_resolver
