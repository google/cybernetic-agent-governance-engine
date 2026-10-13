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

"""Financial domain NeMo Guardrails provider."""

from collections.abc import Callable
from pathlib import Path
from typing import Any


class FinancialRailsProvider:
    """Provides NeMo Guardrails configuration for financial domain."""

    @staticmethod
    def get_config_path() -> Path | None:
        """Return path to financial rails config directory if present."""
        candidate = Path(__file__).resolve().parents[3] / "config" / "rails"
        return candidate if candidate.is_dir() else None

    @staticmethod
    def get_actions() -> dict[str, Callable[..., Any]]:
        """Return financial domain actions for NeMo."""
        from src.cage_finance.rails import actions

        return {
            "check_trade_risk_level": actions.check_trade_risk_level,
            "validate_market_hours": actions.validate_market_hours,
            "check_portfolio_exposure": actions.check_portfolio_exposure,
        }

    def provide_rail_actions(self) -> list[tuple[str, Callable[..., Any]]]:
        """Return ``(action_name, callable)`` pairs for NeMo registration."""
        return list(self.get_actions().items())
