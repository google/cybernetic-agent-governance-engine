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
STPA Validator — Symbolic component of the Neuro-Symbolic architecture.

Phase 2.3: All threshold literals replaced with references to the
``THRESHOLDS`` singleton loaded from ``config/governance_thresholds.json``.
"""

import json
import logging
from typing import Any

from opentelemetry import trace

from .ontology import Constraint, TradingKnowledgeGraph
from src.gateway.governance.schemas.thresholds import THRESHOLDS

logger = logging.getLogger("Gateway.Governance.STPAValidator")
tracer = trace.get_tracer(__name__)


class STPAValidator:
    """
    The 'Symbolic' component of the Neuro-Symbolic architecture.
    Evaluates deterministic STPA UCA constraints against a proposed action.
    """

    def __init__(self, ontology: TradingKnowledgeGraph = None):
        self.ontology = ontology or TradingKnowledgeGraph()

    def validate(self, action_name: str, params: dict[str, Any]) -> list[str]:
        """Validate *action_name* against STPA constraints.

        Returns a list of violation messages; empty list means SAFE.
        """
        with tracer.start_as_current_span("stpa_validator.validate") as span:
            span.set_attribute("langfuse.observation.type", "span")
            span.set_attribute("langfuse.observation.name", "stpa_validation")
            span.set_attribute("langfuse.trace.metadata.iso.control_id", "A.8.4")
            span.set_attribute("langfuse.trace.metadata.iso.requirement", "Controllability")
            span.set_attribute(
                "langfuse.observation.input",
                json.dumps({"action": action_name, "params": params}),
            )
            violations: list[str] = []

            constraints = self.ontology.get_constraints_for_action(action_name)
            for constraint in constraints:
                if not self._check_constraint(constraint, params):
                    violations.append(
                        f"STPA Violation {constraint.id}: {constraint.description}"
                    )

            uca5 = self._check_uca5(action_name, params)
            if uca5:
                violations.append(uca5)

            uca6 = self._check_uca6(action_name, params)
            if uca6:
                violations.append(uca6)

            if violations:
                logger.warning("⚠️ STPA Validator blocked %s: %s", action_name, violations)
            else:
                logger.info("✅ STPA Validator approved %s", action_name)

            span.set_attribute(
                "langfuse.observation.output",
                json.dumps(violations) if violations else "APPROVED",
            )
            return violations

    def _check_constraint(self, constraint: Constraint, params: dict[str, Any]) -> bool:
        try:
            if constraint.id == "SC-1":
                return params.get("approval_token") is not None

            if constraint.id == "FIN-1":
                quantity = float(params.get("quantity", 0))
                portfolio_total = float(params.get("portfolio_total", 0))
                if portfolio_total <= 0:
                    logger.warning("Constraint FIN-1: Missing or invalid portfolio_total.")
                    return False
                # Threshold from singleton
                limit = THRESHOLDS.stpa.max_sell_portfolio_fraction
                return (quantity / portfolio_total) <= limit

            if constraint.id == "FIN-2":
                if "latency_ms" in params:
                    # Threshold from singleton
                    return float(params["latency_ms"]) <= THRESHOLDS.stpa.max_latency_ms
                else:
                    logger.warning("Constraint FIN-2: Missing latency_ms metric.")
                    return False

            logger.error(
                "Constraint %s: No handler implemented. Failing closed.", constraint.id
            )
            return False

        except Exception as exc:
            logger.error("Error evaluating constraint %s: %s", constraint.id, exc)
            return False

    def _check_uca5(self, action_name: str, params: dict[str, Any]) -> str | None:
        """UCA-5: Providing a harmful control action when it should be withheld."""
        try:
            if action_name != "execute_trade":
                return None

            # Drawdown threshold from singleton (Phase 2.3)
            threshold = THRESHOLDS.stpa.uca5_drawdown_threshold_pct
            if "drawdown" in params:
                drawdown = float(params["drawdown"])
                if drawdown > threshold:
                    logger.warning(
                        "UCA-5 triggered: drawdown=%.2f%% > %.1f%% threshold",
                        drawdown, threshold,
                    )
                    return (
                        f"STPA Violation UCA-5: Agent attempted buy_order when drawdown "
                        f"({drawdown:.2f}%) exceeds {threshold}% limit "
                        "(Unsafe Action — should be withheld)."
                    )

            if params.get("opa_denied") is True:
                logger.warning(
                    "UCA-5 triggered: execute_trade reached validator with opa_denied=True"
                )
                return (
                    "STPA Violation UCA-5: High-risk trade flagged by OPA policy but "
                    "allowed through gateway — control action provided when it should be withheld."
                )

            return None

        except Exception as exc:
            logger.error("Error evaluating UCA-5 for %s: %s", action_name, exc)
            return f"STPA Violation UCA-5: Evaluation error — failing closed ({exc})."

    def _check_uca6(self, action_name: str, params: dict[str, Any]) -> str | None:
        """UCA-6: Control action provided too late or out of sequence."""
        try:
            if action_name != "execute_trade":
                return None

            # Market-impact threshold from singleton (Phase 2.3)
            vol_fraction = THRESHOLDS.stpa.uca6_max_order_volume_fraction
            order_size = float(params.get("order_size", 0))
            daily_vol = float(params.get("daily_vol", 0))
            if daily_vol > 0 and order_size > vol_fraction * daily_vol:
                logger.warning(
                    "UCA-6 triggered: order_size=%s > %.0f%% of daily_vol=%s",
                    order_size, vol_fraction * 100, daily_vol,
                )
                return (
                    f"STPA Violation UCA-6: Order size exceeds {vol_fraction*100:.0f}% of "
                    f"daily volume ({order_size} > {vol_fraction * daily_vol:.4f}) — "
                    "High slippage risk / control action out of acceptable execution window."
                )

            if params.get("risk_assessed") is False:
                logger.warning(
                    "UCA-6 triggered: execute_trade arrived before risk_assessed=True"
                )
                return (
                    "STPA Violation UCA-6: Control action (execute_trade) provided before "
                    "risk assessment has completed — out-of-sequence execution detected."
                )

            if params.get("compliance_checked") is False:
                logger.warning(
                    "UCA-6 triggered: execute_trade arrived with compliance_checked=False"
                )
                return (
                    "STPA Violation UCA-6: Control action (execute_trade) provided with "
                    "compliance check bypassed — mandatory sequencing constraint violated."
                )

            return None

        except Exception as exc:
            logger.error("Error evaluating UCA-6 for %s: %s", action_name, exc)
            return f"STPA Violation UCA-6: Evaluation error — failing closed ({exc})."
