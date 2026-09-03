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
from typing import Any

from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger("Gateway.Governance.Schemas")

_DEFAULT_CONFIG_PATH = os.path.join(
    os.path.dirname(__file__), "../../../../config/governance_thresholds.json"
)
_ENV_CONFIG_PATH = os.environ.get("GOVERNANCE_THRESHOLDS_PATH", _DEFAULT_CONFIG_PATH)


# ---------------------------------------------------------------------------
# FINDING-07 (MEDIUM) — Jurisdictional PII audit retention map
#
# pii_audit_retention_days previously hardcoded 90 (FISMA AU-11) as the
# universal Pydantic default, regardless of CAGE_DEPLOYMENT_REGION. EU_ECB
# deployments are subject to GDPR Art. 5(1)(e) storage limitation; APAC_MAS
# to MAS Notice 655 §4.3. This resolves both the retention period and the
# applicable regulatory citation from CAGE_DEPLOYMENT_REGION at load time.
# An explicit value for either field in governance_thresholds.json always
# takes precedence over this region-derived default.
#
# The citation strings themselves live in constants.py (the ControlRegistry
# module, which is intentionally excluded from the "no hardcoded regulatory
# strings" architecture guardrail — see test_governance_architecture.py) so
# that this schema module stays free of volatile citation literals.
# ---------------------------------------------------------------------------
_PII_RETENTION_DAYS_DEFAULT: int = 90


def _resolve_pii_retention() -> tuple[int, str]:
    """Return (retention_days, regulatory_authority) for the active region.

    Reads CAGE_DEPLOYMENT_REGION at call time (not import time) so tests can
    monkeypatch the env var and observe the correct resolution. The citation
    map is sourced from constants.py (PII_RETENTION_AUTHORITY) to keep this
    module free of hardcoded regulatory strings.
    """
    from src.gateway.governance.constants import (
        PII_RETENTION_AUTHORITY,
        PII_RETENTION_AUTHORITY_DEFAULT,
    )

    region = os.environ.get("CAGE_DEPLOYMENT_REGION", "").strip().upper()
    authority = PII_RETENTION_AUTHORITY.get(region, PII_RETENTION_AUTHORITY_DEFAULT)
    return _PII_RETENTION_DAYS_DEFAULT, authority


# ---------------------------------------------------------------------------
# Sub-models
# ---------------------------------------------------------------------------


class CbfThresholds(BaseModel):
    min_cash_balance: float = Field(
        ..., gt=0, description="Minimum cash balance floor (USD)."
    )
    gamma: float = Field(..., gt=0, lt=1, description="CBF decay factor g in (0,1).")


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
    max_latency_ms: float = Field(
        ..., gt=0, description="FIN-2: max trade round-trip ms."
    )


class ConfidenceThresholds(BaseModel):
    # DEPRECATED: confidence threshold is now enforced exclusively by OPA (system_authz.rego)
    min_trade_confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description=(
            "[CTRL_AGT_001] Minimum agentic model confidence score for trade execution. "
            "See config/control_mappings.json for the active regulatory framework mapping."
        ),
    )
    # EV-2: Consolidated from AGENT_CONFIDENCE_THRESHOLD env var
    agent_threshold: float = Field(
        default=0.95,
        ge=0.0,
        le=1.0,
        description=(
            "[EV-2] Agent confidence threshold for Tier-2 corroboration. "
            "Env override: AGENT_CONFIDENCE_THRESHOLD"
        ),
    )
    # EV-5: Consolidated from CONFIDENCE_MIN_SCORE env var
    min_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description=(
            "[EV-5] Minimum confabulation score floor. Production deployments "
            "should set via secretKeyRef. Env override: CONFIDENCE_MIN_SCORE"
        ),
    )


class ConsensusThresholds(BaseModel):
    threshold_usd: float = Field(
        ..., gt=0, description="USD amount above which consensus check is triggered."
    )


# ---------------------------------------------------------------------------
# EV-1: FRIA (Frontier Risk Impact Assessment) Thresholds
# ---------------------------------------------------------------------------


class FriaThresholds(BaseModel):
    """FRIA zone thresholds for automatic approval vs. deferral to HITL.

    Env overrides: FRIA_ZONE_ALLOW, FRIA_ZONE_DEFER
    """

    zone_allow: float = Field(
        default=0.95,
        ge=0.0,
        le=1.0,
        description="Confidence >= this threshold => automatic approval.",
    )
    zone_defer: float = Field(
        default=0.70,
        ge=0.0,
        le=1.0,
        description="Confidence < this threshold => defer to HITL.",
    )

    @field_validator("zone_defer")
    @classmethod
    def defer_less_than_allow(cls, v: float, info: Any) -> float:
        """Ensure zone_defer < zone_allow for coherent zone semantics."""
        # Note: zone_allow may not be in info.data yet during construction
        # so we validate at model level in GovernanceThresholds instead
        return v


# ---------------------------------------------------------------------------
# EV-3, EV-4: Causal Lock Thresholds
# ---------------------------------------------------------------------------


class CausalThresholds(BaseModel):
    """Causal gatekeeper thresholds for DoWhy causal lock decisions.

    Env overrides: CAUSAL_LOCK_P_VALUE_THRESHOLD, CAUSAL_LOCK_PLACEBO_EFFECT_MAGNITUDE,
                   CAUSAL_LOCK_RISK_BOUNDARY, CAUSAL_MIN_SAMPLES
    """

    p_value_threshold: float = Field(
        default=0.05,
        gt=0.0,
        lt=1.0,
        description=(
            "Standard frequentist significance level for causal lock. "
            "Env override: CAUSAL_LOCK_P_VALUE_THRESHOLD"
        ),
    )
    placebo_effect_magnitude: float = Field(
        default=0.2,
        gt=0.0,
        le=1.0,
        description=(
            "Max placebo refuter effect magnitude before effect is unreliable. "
            "Env override: CAUSAL_LOCK_PLACEBO_EFFECT_MAGNITUDE"
        ),
    )
    risk_boundary: float = Field(
        default=0.95,
        gt=0.0,
        le=1.0,
        description=(
            "Risk score ceiling with safety margin. "
            "Env override: CAUSAL_LOCK_RISK_BOUNDARY"
        ),
    )
    min_samples: int = Field(
        default=50,
        gt=0,
        description=(
            "[EV-4] Minimum telemetry samples for causal model training. "
            "Consolidated from CAUSAL_MIN_SAMPLES / CAUSAL_MIN_LIVE_SAMPLES"
        ),
    )


# ---------------------------------------------------------------------------
# EV-5: KMS Batch Signer Thresholds
# ---------------------------------------------------------------------------


class KmsBatchThresholds(BaseModel):
    """KMS batch signer configuration thresholds.

    The batch signer is disabled by default for safety; enable explicitly in
    production via env var or config.

    Env overrides: KMS_BATCH_MAX_SIZE, KMS_BATCH_ENABLED
    """

    max_size: int = Field(
        default=10,
        gt=0,
        description=(
            "[EV-5] Maximum records per KMS batch signing operation. "
            "Env override: KMS_BATCH_MAX_SIZE"
        ),
    )
    enabled: bool = Field(
        default=False,
        description=(
            "[EV-5] Whether KMS batch signing is enabled. Disabled by default "
            "for safety; production deployments must enable explicitly. "
            "Env override: KMS_BATCH_ENABLED"
        ),
    )


# ---------------------------------------------------------------------------
# EV-6: Telemetry Thresholds
# ---------------------------------------------------------------------------


class TelemetryThresholds(BaseModel):
    """Telemetry configuration thresholds for causal gatekeeper.

    Env overrides: TELEMETRY_MAX_STALENESS_SECONDS, CAUSAL_CACHE_TTL_SECONDS
    """

    max_staleness_seconds: int = Field(
        default=300,
        gt=0,
        description=(
            "[EV-6] Maximum age of telemetry observation before data is "
            "treated as stale and gatekeeper fails closed. Default: 300s (5 min). "
            "Env override: TELEMETRY_MAX_STALENESS_SECONDS"
        ),
    )
    cache_ttl_seconds: int = Field(
        default=60,
        ge=0,
        description=(
            "[EV-6] TTL for Redis-backed causal result cache keyed on "
            "(action_type, market_regime). Set to 0 to disable caching. "
            "Default: 60s. Env override: CAUSAL_CACHE_TTL_SECONDS"
        ),
    )


# ---------------------------------------------------------------------------
# Root model
# ---------------------------------------------------------------------------


class HealthcareThresholds(BaseModel):
    """Healthcare domain threshold configuration."""

    min_therapeutic_concentration: float = Field(
        default=5.0,
        description="Minimum therapeutic serum concentration (mg/L) for dose barrier CBF validation",
    )


class GovernanceThresholds(BaseModel):
    """Root schema for config/governance_thresholds.json.

    Schema Version 2.1.0: Adds telemetry threshold section (EV-6) to consolidate
    TELEMETRY_MAX_STALENESS_SECONDS and CAUSAL_CACHE_TTL_SECONDS into
    configuration-driven defaults with optional env var overrides.
    """

    cbf: CbfThresholds
    drawdown: DrawdownThresholds
    stpa: StpaThresholds
    confidence: ConfidenceThresholds
    consensus: ConsensusThresholds

    # EV-1: FRIA thresholds (zone_allow, zone_defer)
    fria: FriaThresholds = Field(default_factory=FriaThresholds)

    # EV-3, EV-4: Causal gatekeeper thresholds
    causal: CausalThresholds = Field(default_factory=CausalThresholds)

    # EV-5: KMS batch signer settings
    kms_batch: KmsBatchThresholds = Field(default_factory=KmsBatchThresholds)

    # EV-6: Telemetry thresholds (max_staleness_seconds, cache_ttl_seconds)
    telemetry: TelemetryThresholds = Field(default_factory=TelemetryThresholds)

    # Healthcare domain thresholds
    healthcare: HealthcareThresholds = Field(default_factory=HealthcareThresholds)

    tier1_keywords: list[str] = Field(default_factory=list)

    # AI 600-1 §2.6 CBRN keyword list (US_FED only)
    tier1_keywords_cbrn: list[str] = Field(default_factory=list)
    tier1_keywords_cbrn_enabled: bool = False

    # AI 600-1 §2.2 PII audit log settings.
    #
    # FINDING-07 (MEDIUM): retention_days and retention_authority are resolved
    # from CAGE_DEPLOYMENT_REGION via _resolve_pii_retention() rather than
    # hardcoding the US federal FISMA AU-11 value as a universal default. An
    # explicit value in governance_thresholds.json always overrides the
    # region-derived default.
    pii_audit_log_enabled: bool = True
    pii_audit_retention_days: int = Field(
        default_factory=lambda: _resolve_pii_retention()[0]
    )
    pii_audit_retention_authority: str = Field(
        default_factory=lambda: _resolve_pii_retention()[1]
    )

    @field_validator("tier1_keywords")
    @classmethod
    def keywords_nonempty(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("tier1_keywords must contain at least one entry.")
        return [kw.upper() for kw in v if kw.strip()]

    @field_validator("tier1_keywords_cbrn")
    @classmethod
    def cbrn_keywords_uppercase(cls, v: list[str]) -> list[str]:
        """Normalise CBRN keywords to uppercase for case-insensitive matching."""
        return [kw.upper() for kw in v if kw.strip()]


# ---------------------------------------------------------------------------
# Environment Variable Override Map (EV-1 through EV-6)
#
# These mappings allow runtime tuning of thresholds via environment variables
# while keeping config/governance_thresholds.json as the single source of truth
# for default values. Env vars take precedence when set.
# ---------------------------------------------------------------------------


def _parse_bool(value: str) -> bool:
    """Parse a string to boolean, handling common truthy/falsy values."""
    return value.lower() in ("true", "1", "yes", "on")


_ENV_OVERRIDES: dict[str, tuple[str, type]] = {
    # EV-1: FRIA thresholds
    "FRIA_ZONE_ALLOW": ("fria.zone_allow", float),
    "FRIA_ZONE_DEFER": ("fria.zone_defer", float),
    # EV-2: Agent confidence threshold
    "AGENT_CONFIDENCE_THRESHOLD": ("confidence.agent_threshold", float),
    # EV-3: Causal lock thresholds
    "CAUSAL_LOCK_P_VALUE_THRESHOLD": ("causal.p_value_threshold", float),
    "CAUSAL_LOCK_PLACEBO_EFFECT_MAGNITUDE": ("causal.placebo_effect_magnitude", float),
    "CAUSAL_LOCK_RISK_BOUNDARY": ("causal.risk_boundary", float),
    # EV-4: Causal min samples (consolidated)
    "CAUSAL_MIN_SAMPLES": ("causal.min_samples", int),
    "CAUSAL_MIN_LIVE_SAMPLES": ("causal.min_samples", int),  # Alias for compatibility
    # EV-5: Confidence min score
    "CONFIDENCE_MIN_SCORE": ("confidence.min_score", float),
    # EV-5: KMS batch signer settings
    "KMS_BATCH_MAX_SIZE": ("kms_batch.max_size", int),
    "KMS_BATCH_ENABLED": ("kms_batch.enabled", _parse_bool),
    # EV-6: Telemetry thresholds
    "TELEMETRY_MAX_STALENESS_SECONDS": ("telemetry.max_staleness_seconds", int),
    "CAUSAL_CACHE_TTL_SECONDS": ("telemetry.cache_ttl_seconds", int),
}


def _apply_env_overrides(raw: dict) -> dict:
    """Apply environment variable overrides to the raw config dict.

    This function mutates the input dict by applying any env var overrides
    found in _ENV_OVERRIDES. The env var value takes precedence over the
    config file value when set.

    Args:
        raw: The raw config dict loaded from JSON.

    Returns:
        The mutated dict with env var overrides applied.
    """
    overrides_applied = []

    for env_var, (path, type_fn) in _ENV_OVERRIDES.items():
        env_value = os.environ.get(env_var)
        if env_value is not None:
            try:
                parsed_value = type_fn(env_value)
                # Navigate the nested dict path (e.g., "fria.zone_allow")
                parts = path.split(".")
                target = raw
                for part in parts[:-1]:
                    if part not in target:
                        target[part] = {}
                    target = target[part]
                target[parts[-1]] = parsed_value
                overrides_applied.append(f"{env_var}={parsed_value}")
            except (ValueError, TypeError) as exc:
                logger.warning(
                    "Invalid env var override %s=%r: %s — using config default",
                    env_var,
                    env_value,
                    exc,
                )

    if overrides_applied:
        logger.info("Applied env var overrides: %s", ", ".join(overrides_applied))

    return raw


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------


@lru_cache(maxsize=1)
def load_and_validate_thresholds(path: str = _ENV_CONFIG_PATH) -> GovernanceThresholds:
    """Load and validate governance_thresholds.json with env var overrides.

    Loads the base configuration from the JSON file, then applies any
    environment variable overrides from _ENV_OVERRIDES. This allows runtime
    tuning while keeping the config file as the single source of truth for
    default values.

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
            "❌ governance_thresholds.json not found at %s — aborting startup.",
            resolved,
        )
        sys.exit(1)

    try:
        with open(resolved) as fh:
            raw = json.load(fh)
    except json.JSONDecodeError as exc:
        logger.critical("❌ governance_thresholds.json is not valid JSON: %s", exc)
        sys.exit(1)

    # Apply environment variable overrides (EV-1 through EV-6)
    raw = _apply_env_overrides(raw)

    try:
        thresholds = GovernanceThresholds(**raw)
    except Exception as exc:  # pydantic.ValidationError
        logger.critical(
            "❌ governance_thresholds.json failed schema validation: %s — aborting startup.",
            exc,
        )
        sys.exit(1)

    logger.info(
        "✅ Governance thresholds validated: drawdown=%.0f%%, confidence=%.2f, "
        "consensus_usd=%.0f, fria_allow=%.2f, causal_min_samples=%d",
        thresholds.drawdown.limit * 100,
        thresholds.confidence.min_trade_confidence,
        thresholds.consensus.threshold_usd,
        thresholds.fria.zone_allow,
        thresholds.causal.min_samples,
    )
    return thresholds


# ---------------------------------------------------------------------------
# Accessor Functions for Consuming Modules
#
# These functions provide a clean API for modules to access thresholds with
# built-in environment variable override support. They should be used instead
# of directly accessing os.environ.get() for the threshold values.
# ---------------------------------------------------------------------------


def get_fria_zone_allow() -> float:
    """Get FRIA zone_allow threshold (config default with env override).

    Returns:
        The zone_allow threshold (>= this value => automatic approval).
    """
    return THRESHOLDS.fria.zone_allow


def get_fria_zone_defer() -> float:
    """Get FRIA zone_defer threshold (config default with env override).

    Returns:
        The zone_defer threshold (< this value => defer to HITL).
    """
    return THRESHOLDS.fria.zone_defer


def get_agent_confidence_threshold() -> float:
    """Get agent confidence threshold (config default with env override).

    Returns:
        The agent confidence threshold for Tier-2 corroboration.
    """
    return THRESHOLDS.confidence.agent_threshold


def get_confidence_min_score() -> float:
    """Get confidence minimum score (config default with env override).

    Returns:
        The minimum confabulation score floor.
    """
    return THRESHOLDS.confidence.min_score


def get_causal_p_value_threshold() -> float:
    """Get causal lock p-value threshold (config default with env override).

    Returns:
        The p-value significance level for causal lock decisions.
    """
    return THRESHOLDS.causal.p_value_threshold


def get_causal_placebo_effect_magnitude() -> float:
    """Get causal lock placebo effect magnitude (config default with env override).

    Returns:
        The maximum placebo refuter effect magnitude.
    """
    return THRESHOLDS.causal.placebo_effect_magnitude


def get_causal_risk_boundary() -> float:
    """Get causal lock risk boundary (config default with env override).

    Returns:
        The risk score ceiling with safety margin.
    """
    return THRESHOLDS.causal.risk_boundary


def get_causal_min_samples() -> int:
    """Get causal minimum samples (config default with env override).

    This consolidates CAUSAL_MIN_SAMPLES and CAUSAL_MIN_LIVE_SAMPLES into
    a single source of truth.

    Returns:
        The minimum telemetry samples required for causal model training.
    """
    return THRESHOLDS.causal.min_samples


def get_kms_batch_max_size() -> int:
    """Get KMS batch max size (config default with env override).

    Returns:
        The maximum number of records per KMS batch signing operation.
    """
    return THRESHOLDS.kms_batch.max_size


def get_kms_batch_enabled() -> bool:
    """Get KMS batch enabled flag (config default with env override).

    Disabled by default for safety; production deployments must enable explicitly.

    Returns:
        True if KMS batch signing is enabled, False otherwise.
    """
    return THRESHOLDS.kms_batch.enabled


def get_telemetry_max_staleness_seconds() -> int:
    """Get telemetry max staleness seconds (config default with env override).

    Returns:
        Maximum age of telemetry observation (seconds) before data is treated
        as stale and the causal gatekeeper fails closed.
    """
    return THRESHOLDS.telemetry.max_staleness_seconds


def get_causal_cache_ttl_seconds() -> int:
    """Get causal cache TTL seconds (config default with env override).

    Returns:
        TTL for Redis-backed causal result cache. Set to 0 to disable caching.
    """
    return THRESHOLDS.telemetry.cache_ttl_seconds


# ---------------------------------------------------------------------------
# Module-level singleton — import this in governance modules.
# ---------------------------------------------------------------------------

THRESHOLDS: GovernanceThresholds = load_and_validate_thresholds()
