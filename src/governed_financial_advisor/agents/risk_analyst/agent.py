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
Risk Analyst Agent — identifies Unsafe Control Actions (UCAs) from STAMP analysis
and generates structured constraints for the Policy Transpiler.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from src.governed_financial_advisor.governance.structs import ConstraintLogic, ProposedUCA  # re-export
from src.governed_financial_advisor.governance.policy_loader import PolicyLoader

logger = logging.getLogger("agents.risk_analyst")

# ---------------------------------------------------------------------------
# System prompt builder
# ---------------------------------------------------------------------------

_FALLBACK_HAZARDS: List[Dict[str, Any]] = [
    {
        "hazard": "H-1: Excessive Slippage",
        "description": "Market order size exceeds 1% of daily volume causing significant price impact.",
        "logic": {"variable": "order_size", "operator": ">", "threshold": "0.01 * daily_volume"},
    },
    {
        "hazard": "H-2: Portfolio Drawdown",
        "description": "Portfolio drawdown exceeds maximum tolerable loss threshold.",
        "logic": {"variable": "drawdown_pct", "operator": ">", "threshold": "5.0"},
    },
    {
        "hazard": "H-3: Stale Market Data",
        "description": "Trade executed using market data older than 200 ms.",
        "logic": {"variable": "latency_ms", "operator": ">", "threshold": "200"},
    },
]


def _load_hazards() -> List[Dict[str, Any]]:
    """Load STAMP hazards from GCS via PolicyLoader, falling back to defaults on any error.

    Always instantiates PolicyLoader so that tests can patch
    ``PolicyLoader.load_stamp_hazards`` without requiring the STAMP_HAZARDS_BUCKET
    environment variable to be set.  The bucket name defaults to a sentinel value
    when the env var is absent; load_stamp_hazards will raise (or the mock will
    intercept) before any real network call is made.
    """
    import os  # noqa: PLC0415

    bucket = os.environ.get("STAMP_HAZARDS_BUCKET", "stamp-hazards-default")
    blob = os.environ.get("STAMP_HAZARDS_BLOB", "stamp_hazards.yaml")
    try:
        loader = PolicyLoader(bucket_name=bucket)
        return loader.load_stamp_hazards(blob)
    except Exception as exc:
        logger.warning("Could not load STAMP hazards from GCS (%s) — using defaults", exc)
    return _FALLBACK_HAZARDS


def get_risk_analyst_instruction() -> str:
    """Build the Risk Analyst system prompt including current STAMP hazards."""
    hazards = _load_hazards()
    hazard_lines = "\n".join(
        f"  - {h['hazard']}: {h['description']}" for h in hazards
    )
    return (
        "You are a Risk Analyst specialising in STAMP/STPA for AI-driven financial systems.\n\n"
        "Your goal is to identify Unsafe Control Actions (UCAs) by analysing system behaviour\n"
        "against the following known hazards:\n\n"
        f"{hazard_lines}\n\n"
        "For each UCA you identify, produce a structured ProposedUCA with:\n"
        "  - category: one of [Wrong Action, Wrong Timing, Not Provided, Stopped Too Soon]\n"
        "  - hazard: reference hazard ID from the list above\n"
        "  - description: concise description of the unsafe action\n"
        "  - constraint_logic: variable / operator / threshold that defines the safe boundary\n"
    )


# Re-export structs so callers can do:
#   from src.governed_financial_advisor.agents.risk_analyst.agent import ConstraintLogic, ProposedUCA
__all__ = ["ConstraintLogic", "ProposedUCA", "get_risk_analyst_instruction"]
