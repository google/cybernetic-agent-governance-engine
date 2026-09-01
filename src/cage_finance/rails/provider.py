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

"""Finance RailProvider implementation."""

from collections.abc import Callable
from typing import Any

from src.cage_finance.rails.actions import (
    check_data_latency_action,
    check_drawdown_limit_action,
    check_slippage_risk_action,
)


class FinanceRailProvider:
    """Provides finance-specific NeMo Guardrails UCA actions."""

    def provide_rail_actions(self) -> list[tuple[str, Callable[..., Any]]]:
        """Return (action_name, callable) pairs to register with NeMo."""
        return [
            ("CheckDrawdownLimitAction", check_drawdown_limit_action),
            ("CheckSlippageRiskAction", check_slippage_risk_action),
            ("CheckDataLatencyAction", check_data_latency_action),
        ]
