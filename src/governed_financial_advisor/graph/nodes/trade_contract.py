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

"""The trade the advisor submits to the gateway, in one place.

The evaluator's dry run (``evaluator_node``) and the pre-trade gate
(``safety_check_node``) must describe a trade to the gateway in the same way.
Otherwise the dry run previews a request the real gate never sends. Both
build it here.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from src.gateway.governance.decisions import GovernanceDecision

#: The finance domain's registered trade action.
TRADE_ACTION = "execute_trade"

#: Least-privilege RBAC role. The role is never read from model output: a
#: plan that claimed ``senior`` would raise its own OPA trade limit.
DEFAULT_TRADER_ROLE = "junior"

#: Verdicts after which the graph proceeds. ``REQUIRE_APPROVAL`` proceeds
#: because the human-approval path downstream (FTRA HITL parking, the
#: approval node and the gateway's approval token) is where it is resolved.
#: Anything else stops the trade.
PROCEED_VERDICTS: frozenset[GovernanceDecision] = frozenset(
    {
        GovernanceDecision.ALLOW,
        GovernanceDecision.NARROW,
        GovernanceDecision.REQUIRE_APPROVAL,
    }
)


def trade_params(source: Mapping[str, Any]) -> dict[str, Any]:
    """Return the canonical ``execute_trade`` parameters for a plan or plan step.

    ``trade_governance.rego`` needs ``trader_role``, ``amount`` and
    ``currency`` to evaluate a trade. A missing role is an explicit DENY.

    Raises:
        ValueError: ``amount`` is not a number. Callers fail closed.
    """
    return {
        "action": TRADE_ACTION,
        "symbol": str(source.get("symbol") or "UNKNOWN"),
        "amount": float(source.get("amount") or 0),
        "currency": str(source.get("currency") or "USD"),
        "trader_role": DEFAULT_TRADER_ROLE,
        "confidence": source.get("confidence", 1.0),
    }
