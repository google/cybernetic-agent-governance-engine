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
DoWhy Causal Gatekeeper — the "Lock" on the CAGE.

Uses Microsoft DoWhy's causal inference + placebo refutation to validate
that the system's world-model is trustworthy before allowing high-stakes
actions (e.g. execute_trade).

Causal Graph:
    market_volatility → trade_amount
    market_volatility → risk_score
    trade_amount → risk_score

If a Placebo Refuter detects a spurious effect (p < 0.05 or large placebo
effect), the gatekeeper "locks" the cage — the trade is blocked because
the underlying causal assumptions cannot be trusted.
"""

import logging

import numpy as np
import pandas as pd
from dowhy import CausalModel
from opentelemetry import trace

from src.gateway.governance.constants import GovernanceControl, ControlRegistry

logger = logging.getLogger(__name__)
tracer = trace.get_tracer("src.gateway.governance.causal_gatekeeper")

# Sentinel string fragment: if a regional profile's ``legacy_citation`` for a
# control contains this marker, it signals that the citation has no legal force
# in the active jurisdiction.  In that case the gatekeeper emits
# ``primary_framework`` (the jurisdiction-correct citation) on the span instead
# of the legacy string.
#
# This is data-driven: adding a new region requires only a JSON profile update,
# never a Python change.  The EU_ECB_BASELINE.json already encodes
# CTRL_MRM_004's legacy_citation as:
#   "SR 26-2 §IV (US Federal Reserve — no legal force in EU jurisdiction)"
# The APAC_MAS_BASELINE.json similarly flags its legacy citations.
_NO_LEGAL_FORCE_MARKER = "no legal force"


def generate_mock_telemetry(n_samples: int = 1000) -> pd.DataFrame:
    """
    Generates synthetic historical telemetry data for the causal model.
    W: Market Volatility (Confounder)
    X: Trade Amount (Treatment)
    Y: Risk Score (Outcome)
    """
    np.random.seed(42)
    # Confounder: Market Volatility (0.0 to 1.0)
    market_volatility = np.random.uniform(0.1, 0.9, n_samples)

    # Treatment: Trade Amount (influenced by volatility)
    # Higher volatility generally leads to smaller trade amounts, plus baseline
    trade_amount = np.random.normal(5000, 1000, n_samples) - (market_volatility * 2000)
    trade_amount = np.clip(trade_amount, 100, 10000)

    # Outcome: Risk Score (influenced by both volatility and trade amount)
    # Higher volatility -> higher risk
    # Higher trade amount -> higher risk
    risk_score = (market_volatility * 0.5) + (trade_amount / 10000 * 0.5) + np.random.normal(0, 0.05, n_samples)
    risk_score = np.clip(risk_score, 0.0, 1.0)

    return pd.DataFrame({
        'market_volatility': market_volatility,
        'trade_amount': trade_amount,
        'risk_score': risk_score
    })


def causal_safety_check(params: dict, current_telemetry: pd.DataFrame = None) -> bool:
    """
    Acts as the 'Lock' on the Cage using DoWhy refutation for execute_trade.

    Returns True if the action is causally safe, False if the world-model
    is untrustworthy or the predicted risk exceeds the safety boundary.

    Dual-tag lifecycle:
      Phase 1 (CTRL_MRM_004 / SR 26-2 MRM) — causal model setup, effect
        identification, and linear regression estimation.  This is the
        statistical kernel: fixed graph structure, coefficient estimation,
        and effect calculation.  SR 26-2 MRM back-testing requirements apply
        to these coefficients and causal graph assumptions.

      Phase 2 (CTRL_TEL_003 / ISO 42001 \u00a7A.9.4) — placebo refutation using
        live telemetry.  Executes 50 simulations per trade call against
        runtime Langfuse data.  This is the agentic operational check:
        non-deterministic, live-sourced, and high-frequency.
    """
    if current_telemetry is None:
        current_telemetry = generate_mock_telemetry()

    amount = params.get("amount", 0.0)
    if amount <= 0:
        return True  # Not a meaningful trade to causally evaluate

    causal_graph = """
    digraph {
        market_volatility -> trade_amount;
        market_volatility -> risk_score;
        trade_amount -> risk_score;
    }
    """

    try:
        registry = ControlRegistry()
        mrm_meta = registry.get_mapping(GovernanceControl.TRADITIONAL_MRM_VALIDATION)
        tel_meta = registry.get_mapping(GovernanceControl.TELEMETRY_LIVE_VALIDATION)
        active_region = registry.active_region

        # Resolve region-safe legacy citations from the loaded regional profile.
        # If a profile's legacy_citation contains the "no legal force" marker,
        # it signals the string is jurisdictionally inappropriate for audit logs.
        # In that case, emit primary_framework (the correct regional citation)
        # rather than the legacy string.  This is fully data-driven: profile
        # updates propagate here automatically with no Python changes.
        mrm_legacy = (
            mrm_meta["primary_framework"]
            if _NO_LEGAL_FORCE_MARKER in mrm_meta["legacy_citation"]
            else mrm_meta["legacy_citation"]
        )
        tel_legacy = (
            tel_meta["primary_framework"]
            if _NO_LEGAL_FORCE_MARKER in tel_meta["legacy_citation"]
            else tel_meta["legacy_citation"]
        )

        # ------------------------------------------------------------------
        # Phase 1: Statistical Kernel (CTRL_MRM_004 scope)
        # Governing framework varies by region — see active_region span attr.
        # ------------------------------------------------------------------
        # Causal model setup, effect identification, and linear regression
        # coefficient estimation. The graph structure and estimated
        # coefficients are the MRM-governed artefacts under the active
        # regional framework (SR 26-2 for US_FED; EBA/GL/2023/02 for EU_ECB;
        # MAS TRM Guidelines §6.3 for APAC_MAS).
        estimate = None
        identified_estimand = None
        with tracer.start_as_current_span("causal_gatekeeper.statistical_kernel") as mrm_span:
            mrm_span.set_attribute("governance.control_id",       mrm_meta["internal_id"])
            mrm_span.set_attribute("governance.framework",        mrm_meta["primary_framework"])
            mrm_span.set_attribute("governance.legacy_citation",  mrm_legacy)
            mrm_span.set_attribute("governance.scope",            mrm_meta["scope"])
            mrm_span.set_attribute("governance.deployment_region", active_region)
            mrm_span.set_attribute("causal.graph",                causal_graph.strip())

            model = CausalModel(
                data=current_telemetry,
                treatment='trade_amount',
                outcome='risk_score',
                graph=causal_graph
            )
            identified_estimand = model.identify_effect(proceed_when_unidentifiable=True)
            estimate = model.estimate_effect(
                identified_estimand,
                method_name="backdoor.linear_regression"
            )
            mrm_span.set_attribute("causal.estimated_effect", float(estimate.value))

        # ------------------------------------------------------------------
        # Phase 2: Operational Simulation (CTRL_TEL_003 / ISO 42001 \u00a7A.9.4)
        # ------------------------------------------------------------------
        # Placebo refutation against live telemetry.  50 simulations per
        # trade call — non-deterministic and high-frequency.  This is the
        # agentic operational check; results are only as trustworthy as the
        # live telemetry sourced from Langfuse governance spans.
        with tracer.start_as_current_span("causal_gatekeeper.placebo_refutation") as tel_span:
            tel_span.set_attribute("governance.control_id",       tel_meta["internal_id"])
            tel_span.set_attribute("governance.framework",        tel_meta["primary_framework"])
            tel_span.set_attribute("governance.legacy_citation",  tel_legacy)
            tel_span.set_attribute("governance.scope",            tel_meta["scope"])
            tel_span.set_attribute("governance.deployment_region", active_region)
            tel_span.set_attribute("causal.num_simulations",      50)

            refuter = model.refute_estimate(
                identified_estimand,
                estimate,
                method_name="placebo_treatment_refuter",
                num_simulations=50  # Reduced for speed in a real-time gatekeeper
            )

            # Check if the refuter finds a 'fake' effect
            p_value = getattr(refuter, 'refutation_result', {}).get('p_value', 1.0)
            if isinstance(p_value, (list, tuple, np.ndarray)):
                p_value = p_value[0]

            new_effect = refuter.new_effect
            if isinstance(new_effect, (list, tuple, np.ndarray)):
                new_effect = new_effect[0]

            tel_span.set_attribute("causal.placebo_p_value",    float(p_value) if p_value is not None else -1.0)
            tel_span.set_attribute("causal.placebo_new_effect", float(new_effect) if new_effect is not None else 0.0)

            if p_value is not None and not np.isnan(p_value) and float(p_value) < 0.05:
                logger.warning(
                    "[%s] CAUSAL LOCK: Placebo p-value %.4f < 0.05 — world-model untrustworthy.",
                    GovernanceControl.TELEMETRY_LIVE_VALIDATION.value, p_value,
                )
                tel_span.set_attribute("causal.lock_reason", "p_value_threshold")
                return False

            if abs(new_effect) > 0.2:
                logger.warning(
                    "[%s] CAUSAL LOCK: Placebo effect %.4f > 0.2 — world-model untrustworthy.",
                    GovernanceControl.TELEMETRY_LIVE_VALIDATION.value, new_effect,
                )
                tel_span.set_attribute("causal.lock_reason", "placebo_effect_magnitude")
                return False

        # ------------------------------------------------------------------
        # Phase 1 continued: marginal risk boundary check (MRM scope)
        # ------------------------------------------------------------------
        estimated_marginal_effect = estimate.value * amount
        MAX_RISK_THRESHOLD = 0.95

        if (0.5 + estimated_marginal_effect) > MAX_RISK_THRESHOLD:
            logger.warning(
                "[%s] CAUSAL LOCK: Proposed action predicted to exceed safety boundary.",
                GovernanceControl.TRADITIONAL_MRM_VALIDATION.value,
            )
            return False

        return True

    except Exception as e:
        logger.error("Causal validation failed due to error: %s", e)
        # Fail safe - if we can't prove it's safe causally, we don't allow it.
        return False
