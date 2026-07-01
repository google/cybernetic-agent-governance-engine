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
Pydantic models for governance_thresholds.json.

Usage (startup validation):
    from src.gateway.governance.schemas.thresholds import load_and_validate_thresholds
    THRESHOLDS = load_and_validate_thresholds()   # aborts on schema failure

All governance modules import the module-level ``THRESHOLDS`` singleton
rather than reading inline literals.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from functools import lru_cache
from typing import List

from pydantic import BaseModel, Field, field_validator
from src.gateway.governance.constants import PII_AUDIT_RETENTION_AUTHORITY_FIELD_DEFAULT as _PII_RETENTION_DEFAULT

logger = logging.getLogger("Gateway.Governance.Schemas")

_DEFAULT_CONFIG_PATH = os.path.join(
    os.path.dirname(__file__), "../../../../config/governance_thresholds.json"
)
_ENV_CONFIG_PATH = os.environ.get("GOVERNANCE_THRESHOLDS_PATH", _DEFAULT_CONFIG_PATH)


# ---------------------------------------------------------------------------
# Sub-models
# ---------------------------------------------------------------------------


class CbfThresholds(BaseModel):
    min_cash_balance: float = Field(..., gt=0, description="Minimum cash balance floor (USD).")
    gamma: float = Field(..., gt=0, lt=1, description="CBF decay factor γ ∈ (0,1).")


class DrawdownThresholds(BaseModel):
    # KEY AUDIT FINDING (2026-06-03): `drawdown.limit` and
    # `stpa.uca5_drawdown_threshold_pct` are NOT aliases — they are distinct
    # thresholds with different semantics and units:
    #
    #   drawdown.limit                  — fraction in [0,1), e.g. 0.05 (5%)
    #     Used by: cbf.py ControlBarrierFunction.verify_action()
    #     Payload key: "drawdown_pct" (raw value divided by 100 before compare)
    #     Purpose: CBF Redis-backed cash-barrier drawdown ceiling
    #
    #   stpa.uca5_drawdown_threshold_pct — percentage, e.g. 4.5 (4.5%)
    #     Used by: stpa_validator.py _check_uca5() and
    #              generated_stpa_validator.py _check_uca_5()
    #     Payload key: "drawdown" (raw percentage value, compared directly)
    #     Purpose: STPA UCA-5 unsafe-control-action drawdown trigger
    #
    # No consolidation is required. The canonical key for the CBF barrier is
    # `drawdown.limit`; the canonical key for the STPA UCA-5 trigger is
    # `stpa.uca5_drawdown_threshold_pct`. Both are single-occurrence keys with
    # no duplicate aliases in governance_thresholds.json.
    limit: float = Field(
        ..., gt=0.0, lt=1.0, description="Max portfolio drawdown fraction [0,1)."
    )


class StpaThresholds(BaseModel):
    uca5_drawdown_threshold_pct: float = Field(
        ..., gt=0, description="UCA-5 drawdown % trigger (e.g. 4.5)."
    )
    uca6_max_order_volume_fraction: float = Field(
        ..., gt=0, lt=1, description="UCA-6 max order/daily-vol fraction."
    )
    max_sell_portfolio_fraction: float = Field(
        ..., gt=0, lt=1, description="FIN-1: max fraction of portfolio sold per order."
    )
    max_latency_ms: float = Field(..., gt=0, description="FIN-2: max trade round-trip ms.")


class ConfidenceThresholds(BaseModel):
    # DEPRECATED: confidence threshold is now enforced exclusively by OPA (system_authz.rego)
    min_trade_confidence: float = Field(
        ..., ge=0.0, le=1.0,
        description=(
            "[CTRL_AGT_001] Minimum agentic model confidence score for trade execution. "
            "See config/control_mappings.json for the active regulatory framework mapping."
        ),
    )


class ConsensusThresholds(BaseModel):
    threshold_usd: float = Field(
        ..., gt=0, description="USD amount above which consensus check is triggered."
    )


# ---------------------------------------------------------------------------
# Root model
# ---------------------------------------------------------------------------


class GovernanceThresholds(BaseModel):
    """Root schema for config/governance_thresholds.json."""

    cbf: CbfThresholds
    drawdown: DrawdownThresholds
    stpa: StpaThresholds
    confidence: ConfidenceThresholds
    consensus: ConsensusThresholds
    tier1_keywords: List[str] = Field(default_factory=list)

    # AI 600-1 §2.6 CBRN keyword list (US_FED only)
    tier1_keywords_cbrn: List[str] = Field(default_factory=list)
    tier1_keywords_cbrn_enabled: bool = False

    # AI 600-1 §2.2 PII audit log settings (FISMA AU-11)
    pii_audit_log_enabled: bool = True
    pii_audit_retention_days: int = 90  # FISMA AU-11

    @field_validator("tier1_keywords")
    @classmethod
    def keywords_nonempty(cls, v: List[str]) -> List[str]:
        if not v:
            raise ValueError("tier1_keywords must contain at least one entry.")
        return [kw.upper() for kw in v if kw.strip()]

    @field_validator("tier1_keywords_cbrn")
    @classmethod
    def cbrn_keywords_uppercase(cls, v: List[str]) -> List[str]:
        """Normalise CBRN keywords to uppercase for case-insensitive matching."""
        return [kw.upper() for kw in v if kw.strip()]


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------


@lru_cache(maxsize=1)
def load_and_validate_thresholds(path: str = _ENV_CONFIG_PATH) -> GovernanceThresholds:
    """Load and validate governance_thresholds.json.

    Aborts the Python process immediately (``sys.exit(1)``) if the JSON is
    missing, malformed, or fails Pydantic validation.  This guarantees
    fail-fast semantics: no threshold drift can reach production.

    Returns:
        A fully-validated ``GovernanceThresholds`` singleton.
    """
    resolved = os.path.abspath(path)
    logger.info("Loading governance thresholds from %s", resolved)

    if not os.path.exists(resolved):
        logger.critical(
            "❌ governance_thresholds.json not found at %s — aborting startup.", resolved
        )
        sys.exit(1)

    try:
        with open(resolved) as fh:
            raw = json.load(fh)
    except json.JSONDecodeError as exc:
        logger.critical("❌ governance_thresholds.json is not valid JSON: %s", exc)
        sys.exit(1)

    try:
        thresholds = GovernanceThresholds(**raw)
    except Exception as exc:  # pydantic.ValidationError
        logger.critical(
            "❌ governance_thresholds.json failed schema validation: %s — aborting startup.", exc
        )
        sys.exit(1)

    logger.info(
        "✅ Governance thresholds validated: drawdown=%.0f%%, confidence=%.2f, consensus_usd=%.0f",
        thresholds.drawdown.limit * 100,
        thresholds.confidence.min_trade_confidence,
        thresholds.consensus.threshold_usd,
    )
    return thresholds


# ---------------------------------------------------------------------------
# Module-level singleton — import this in governance modules.
# ---------------------------------------------------------------------------

THRESHOLDS: GovernanceThresholds = load_and_validate_thresholds()
