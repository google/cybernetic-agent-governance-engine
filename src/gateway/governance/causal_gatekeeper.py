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

Telemetry & Bounded Risk Formulation:
    - Sourced from Langfuse OTel settlement spans via TelemetryProvider.
    - If causal slope beta <= 0, the gate triggers a fail-closed lock.
    - If beta > 0, marginal risk is computed as min(1.0, max(0.0, 0.5 + beta * amount / SCALE)).
    - If risk exceeds CAUSAL_LOCK_RISK_BOUNDARY (0.95), the trade is blocked.

If a Placebo Refuter detects a spurious effect (p < 0.05 or large placebo
effect), the gatekeeper "locks" the cage — the trade is blocked because
the underlying causal assumptions cannot be trusted.
"""

import json
import logging
import os
from datetime import datetime, timezone

import networkx as nx
import numpy as np
import pandas as pd
from opentelemetry import trace

# networkx ≥3.x renamed d_separated → d_separation.is_d_separator.
# Patch the missing attribute so dowhy 0.12 can find it at runtime.
if not hasattr(nx.algorithms, "d_separated"):
    from networkx.algorithms.d_separation import is_d_separator as _is_d_separator

    nx.algorithms.d_separated = _is_d_separator

try:
    from dowhy import CausalModel as _CausalModel

    _DOWHY_AVAILABLE = True
except ImportError:
    _CausalModel = None  # type: ignore[assignment,misc]
    _DOWHY_AVAILABLE = False

from src.gateway.governance.constants import ControlRegistry, GovernanceControl

logger = logging.getLogger(__name__)
tracer = trace.get_tracer("src.gateway.governance.causal_gatekeeper")

# ---------------------------------------------------------------------------
# Configurable thresholds — EV-6 Migration
# Telemetry thresholds are now sourced from config/governance_thresholds.json
# with environment variable overrides supported. See schemas/thresholds.py.
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Causal lock thresholds — Phase 2 (CTRL_TEL_003) and Phase 1 risk boundary
# EV-3, EV-4, EV-6 Migration: Thresholds are now sourced from config/governance_thresholds.json
# with environment variable overrides supported. See schemas/thresholds.py.
# ---------------------------------------------------------------------------
from src.gateway.governance.schemas.thresholds import (
    get_causal_cache_ttl_seconds,
    get_causal_min_samples,
    get_causal_p_value_threshold,
    get_causal_placebo_effect_magnitude,
    get_causal_risk_boundary,
    get_telemetry_max_staleness_seconds,
)

# These three constants define the three conditions that trigger a CAUSAL LOCK
# (i.e. causal_safety_check() returns False, blocking the trade).
#
# CAUSAL_LOCK_P_VALUE_THRESHOLD (Phase 2 — placebo refutation):
#   If the placebo treatment refuter's p-value is below this threshold, the
#   null hypothesis (no spurious effect) is rejected at the 5% significance
#   level.  The world-model's causal assumptions cannot be trusted.
#   Rationale: standard frequentist significance level; consistent with
#   SR 26-2 MRM back-testing requirements (CTRL_TEL_003).
CAUSAL_LOCK_P_VALUE_THRESHOLD: float = get_causal_p_value_threshold()

# CAUSAL_LOCK_PLACEBO_EFFECT_MAGNITUDE (Phase 2 — placebo refutation):
#   If the absolute value of the placebo refuter's new_effect exceeds this
#   threshold, the estimated causal effect is considered unreliable regardless
#   of the p-value.  Catches cases where the refuter finds a large spurious
#   effect that is not statistically significant due to high variance.
#   Rationale: 0.2 corresponds to a "medium" effect size (Cohen's d ≈ 0.2)
#   in the normalised risk_score space [0, 1].
CAUSAL_LOCK_PLACEBO_EFFECT_MAGNITUDE: float = get_causal_placebo_effect_magnitude()

# CAUSAL_LOCK_RISK_BOUNDARY (Phase 1 — marginal risk boundary):
#   If (0.5 + estimated_marginal_effect) exceeds this threshold, the proposed
#   trade is predicted to push the system's risk score above the safety
#   boundary.  The baseline risk is modelled as 0.5 (neutral market state);
#   the estimated_marginal_effect is the linear regression coefficient
#   multiplied by the trade amount.
#   Rationale: 0.95 leaves a 5% safety margin below the maximum risk score
#   of 1.0, consistent with the CBF g=0.5 decay factor.
CAUSAL_LOCK_RISK_BOUNDARY: float = get_causal_risk_boundary()

# CAUSAL_NORMALIZATION_SCALE (Peer Review Fix — bounded risk calculation):
#   Normalization factor for converting raw trade amounts to the [0, 1] risk
#   scale. The estimated_risk is computed as:
#     estimated_risk = clamp(0.5 + β * amount / NORMALIZATION_SCALE, 0.0, 1.0)
#   This ensures risk scores are strictly bounded within [0.0, 1.0] regardless
#   of adversarial input amounts. The default value of 10000 matches the
#   maximum trade_amount in the synthetic telemetry generator and aligns with
#   typical trade size thresholds in production.
CAUSAL_NORMALIZATION_SCALE: float = float(
    os.environ.get("CAUSAL_NORMALIZATION_SCALE", "10000.0")
)

# NOTE: Timestamp-based ordering is a best-effort approximation. For production,
# use span parentId relationships via OpenTelemetry context propagation.
#
# When CAUSAL_GATEKEEPER_STRICT_MODE=true, any causal check where trace_id
# fields are missing or mismatched is rejected outright.  In non-strict mode,
# a warning is logged and the check falls back to timestamp-only ordering.
CAUSAL_GATEKEEPER_STRICT_MODE: bool = (
    os.environ.get("CAUSAL_GATEKEEPER_STRICT_MODE", "false").lower() == "true"
)

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

# Candidate column names for the telemetry timestamp field (checked in order).
_TIMESTAMP_CANDIDATES = ("timestamp", "ts", "event_time", "time", "created_at")


def generate_mock_telemetry(n_samples: int = 1000) -> pd.DataFrame:
    """
    Generates synthetic historical telemetry data for the causal model.
    W: Market Volatility (Confounder)
    X: Trade Amount (Treatment)
    Y: Risk Score (Outcome)

    A ``timestamp`` column is included so that the telemetry freshness check
    treats this data as fresh.  Timestamps are generated as recent UTC values
    (within the last hour) so they always pass the staleness threshold.
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
    risk_score = (
        (market_volatility * 0.5)
        + (trade_amount / 10000 * 0.5)
        + np.random.normal(0, 0.05, n_samples)
    )
    risk_score = np.clip(risk_score, 0.0, 1.0)

    # Timestamps: spread over the last 60 minutes so freshness check passes.
    now_epoch = datetime.now(tz=timezone.utc).timestamp()
    timestamps = now_epoch - np.random.uniform(0, 3600, n_samples)

    return pd.DataFrame(
        {
            "market_volatility": market_volatility,
            "trade_amount": trade_amount,
            "risk_score": risk_score,
            "timestamp": timestamps,
        }
    )


# ---------------------------------------------------------------------------
# Internal helpers — telemetry freshness
# ---------------------------------------------------------------------------


def _check_telemetry_freshness(  # type: ignore[no-untyped-def]
    telemetry: pd.DataFrame,
    span,
) -> bool:
    """Check that the most-recent observation in *telemetry* is not stale.

    Returns True if the telemetry is fresh (or if no timestamp column exists
    and the caller should fail-closed).  Sets OTel span attributes regardless
    of outcome.

    Fail-closed contract:
      - No timestamp column found → log WARNING, return False.
      - Timestamp cannot be parsed → log WARNING, return False.
      - Any unexpected exception → log WARNING, return False.
      - Telemetry older than TELEMETRY_MAX_STALENESS_SECONDS → log WARNING,
        set causal.telemetry_stale=True, return False.
      - Fresh telemetry → set causal.telemetry_stale=False, return True.
    """
    try:
        # Locate the timestamp column.
        ts_col: str | None = None
        for candidate in _TIMESTAMP_CANDIDATES:
            if candidate in telemetry.columns:
                ts_col = candidate
                break

        if ts_col is None:
            # No timestamp column present — fail closed.
            # generate_mock_telemetry() now includes a 'timestamp' column, so
            # any telemetry reaching this branch is genuinely missing a required
            # field and cannot be trusted for causal inference.
            logger.warning(
                "Telemetry freshness check: no timestamp column found "
                "(checked: %s) — failing closed.",
                ", ".join(_TIMESTAMP_CANDIDATES),
            )
            span.set_attribute("causal.telemetry_stale", True)
            span.set_attribute("causal.telemetry_age_seconds", -1)
            return False

        # Parse the most-recent timestamp.
        try:
            raw_ts = telemetry[ts_col].max()
            if isinstance(raw_ts, (int, float)):
                # Unix epoch seconds or milliseconds
                if raw_ts > 1e12:
                    raw_ts = raw_ts / 1000.0  # milliseconds → seconds
                most_recent = datetime.fromtimestamp(raw_ts, tz=timezone.utc)
            else:
                most_recent = pd.to_datetime(raw_ts, utc=True).to_pydatetime()
        except Exception as parse_exc:
            logger.warning(
                "Telemetry freshness check: cannot parse timestamp column '%s': %s "
                "— failing closed.",
                ts_col,
                parse_exc,
            )
            span.set_attribute("causal.telemetry_stale", True)
            span.set_attribute("causal.telemetry_age_seconds", -1)
            return False

        now_utc = datetime.now(tz=timezone.utc)
        age_seconds = int((now_utc - most_recent).total_seconds())
        max_staleness = get_telemetry_max_staleness_seconds()

        if age_seconds > max_staleness:
            logger.warning(
                "Telemetry freshness check: most-recent observation is %ds old "
                "(threshold=%ds) — failing closed (stale telemetry cannot be "
                "trusted for causal inference).",
                age_seconds,
                max_staleness,
            )
            span.set_attribute("causal.telemetry_stale", True)
            span.set_attribute("causal.telemetry_age_seconds", age_seconds)
            return False

        span.set_attribute("causal.telemetry_stale", False)
        span.set_attribute("causal.telemetry_age_seconds", age_seconds)
        return True

    except Exception as exc:
        logger.warning(
            "Telemetry freshness check: unexpected exception — failing closed: %s",
            exc,
        )
        span.set_attribute("causal.telemetry_stale", True)
        span.set_attribute("causal.telemetry_age_seconds", -1)
        return False


# ---------------------------------------------------------------------------
# Internal helpers — Redis cache
# ---------------------------------------------------------------------------


async def _causal_cache_get(cache_key: str) -> dict | None:
    """Return a cached causal result dict, or None if absent/unavailable."""
    try:
        from src.gateway.infrastructure.redis_client import (
            redis_client,
        )

        if redis_client is None:
            return None
        raw = await redis_client.get(cache_key)
        if raw is None:
            return None
        return json.loads(raw)
    except Exception as exc:
        logger.warning(
            "Causal cache GET failed (key=%s): %s — proceeding without cache.",
            cache_key,
            exc,
        )
        return None


async def _causal_cache_set(cache_key: str, result: bool, reason: str) -> None:
    """Write a causal result to Redis with telemetry.cache_ttl_seconds TTL."""
    cache_ttl = get_causal_cache_ttl_seconds()
    if cache_ttl <= 0:
        return
    try:
        from src.gateway.infrastructure.redis_client import (
            redis_client,
        )

        if redis_client is None:
            return
        payload = json.dumps({"result": result, "reason": reason})
        await redis_client.setex(cache_key, cache_ttl, payload)
    except Exception as exc:
        logger.warning(
            "Causal cache SET failed (key=%s): %s — proceeding without cache.",
            cache_key,
            exc,
        )


# ---------------------------------------------------------------------------
# Synchronous cache helpers — safe to call from thread-pool workers
# (i.e. functions dispatched via asyncio.to_thread).  These use the
# module-level sync_redis_client (redis.Redis) so they never touch the
# event loop and never raise RuntimeError in Python 3.10+.
# The async _causal_cache_get / _causal_cache_set above are preserved for
# any callers that already run inside an async context.
# ---------------------------------------------------------------------------


def _causal_cache_get_sync(cache_key: str) -> dict | None:
    """Return a cached causal result dict, or None if absent/unavailable.

    Thread-safe: uses the synchronous ``sync_redis_client`` (blocking I/O).

    # Reviewer note H55: connection errors fail-closed; absent keys treated as zero-deflection (first-boot safe).
    Distinguishes between two failure modes:
      - Key absent (successful GET returns None): treat as a cache miss and
        return None so the causal check runs from scratch.  This is safe on
        first boot before any results have been cached.
      - Connection error (exception from redis client): raise RuntimeError so
        the caller cannot silently skip the causal gate due to Redis being down.
    """
    from src.gateway.infrastructure.redis_client import (
        sync_redis_client,
    )

    if sync_redis_client is None:
        # Reviewer note H55: connection errors fail-closed; absent keys treated as zero-deflection (first-boot safe).
        raise RuntimeError(
            "Redis unavailable: cannot compute deflection rate; failing closed"
        )

    try:
        raw = sync_redis_client.get(cache_key)
    except Exception as exc:
        # Connection error — fail-closed: the causal gate must not be bypassed
        # because Redis is unreachable.
        # Reviewer note H55: connection errors fail-closed; absent keys treated as zero-deflection (first-boot safe).
        raise RuntimeError(
            "Redis unavailable: cannot compute deflection rate; failing closed"
        ) from exc

    # Key absent → legitimate cache miss (first-boot safe, zero-deflection sentinel).
    if raw is None:
        return None

    try:
        return json.loads(raw)
    except Exception as exc:
        logger.warning(
            "Causal cache GET (sync): JSON decode failed (key=%s): %s — treating as cache miss.",
            cache_key,
            exc,
        )
        return None


def _causal_cache_set_sync(cache_key: str, result: bool, reason: str) -> None:
    """Write a causal result to Redis with telemetry.cache_ttl_seconds TTL.

    Thread-safe: uses the synchronous ``sync_redis_client`` (blocking I/O).
    """
    cache_ttl = get_causal_cache_ttl_seconds()
    if cache_ttl <= 0:
        return
    try:
        from src.gateway.infrastructure.redis_client import (
            sync_redis_client,
        )

        if sync_redis_client is None:
            return
        payload = json.dumps({"result": result, "reason": reason})
        sync_redis_client.setex(cache_key, cache_ttl, payload)
    except Exception as exc:
        logger.warning(
            "Causal cache SET (sync) failed (key=%s): %s — proceeding without cache.",
            cache_key,
            exc,
        )


def validate_causal_ordering(
    governance_span: dict,
    execution_span: dict,
) -> bool:
    """Validate causal ordering between a governance span and an execution span.

    NOTE: Timestamp-based ordering is a best-effort approximation. For production,
    use span parentId relationships via OpenTelemetry context propagation.

    Performs two checks:
      1. Timestamp check: governance_span timestamp must precede execution_span timestamp.
      2. trace_id check: both spans must share the same trace_id (same causal chain).

    When CAUSAL_GATEKEEPER_STRICT_MODE=true, missing or mismatched trace_id fields
    cause an immediate rejection.  In non-strict mode, a warning is logged and the
    check falls back to timestamp-only ordering.

    Args:
        governance_span: Dict with optional keys 'timestamp', 'trace_id'.
        execution_span:  Dict with optional keys 'timestamp', 'trace_id'.

    Returns:
        True if causal ordering is valid, False if ordering cannot be confirmed.
    """
    gov_trace_id = governance_span.get("trace_id")
    exec_trace_id = execution_span.get("trace_id")

    # --- trace_id validation ---
    if gov_trace_id and exec_trace_id:
        if gov_trace_id != exec_trace_id:
            logger.warning(
                "causal_ordering: trace_id mismatch — governance=%s execution=%s. "
                "Spans are not in the same causal chain.",
                gov_trace_id,
                exec_trace_id,
            )
            return False
    else:
        # trace_id fields missing — strict mode rejects, non-strict warns and continues
        if CAUSAL_GATEKEEPER_STRICT_MODE:
            logger.warning(
                "causal_ordering: STRICT MODE — trace_id fields missing "
                "(governance_has=%s, execution_has=%s). Rejecting.",
                bool(gov_trace_id),
                bool(exec_trace_id),
            )
            return False
        logger.warning(
            "causal_ordering: trace_id fields missing — falling back to "
            "timestamp-only ordering (best-effort approximation). "
            "Set CAUSAL_GATEKEEPER_STRICT_MODE=true to reject missing trace_ids."
        )

    # --- Timestamp check (best-effort) ---
    gov_ts = governance_span.get("timestamp")
    exec_ts = execution_span.get("timestamp")

    if gov_ts is not None and exec_ts is not None:
        if gov_ts >= exec_ts:
            logger.warning(
                "causal_ordering: governance timestamp (%s) is not before "
                "execution timestamp (%s) — ordering violation.",
                gov_ts,
                exec_ts,
            )
            return False

    return True


def causal_safety_check(
    params: dict, current_telemetry: pd.DataFrame | None = None
) -> bool:
    """
    Acts as the 'Lock' on the Cage using DoWhy refutation for execute_trade.

    Returns True if the action is causally safe, False if the world-model
    is untrustworthy or the predicted risk exceeds the safety boundary.

    When ``dowhy`` is not installed, the function fails closed (returns False)
    for any trade with amount > 0, logging a warning.  This preserves the
    fail-closed safety contract while allowing the module to be imported in
    environments where ``dowhy`` is not available (e.g. unit-test runners).

    Dual-tag lifecycle:
      Phase 1 (CTRL_MRM_004 / SR 26-2 MRM) — causal model setup, effect
        identification, and linear regression estimation.  This is the
        statistical kernel: fixed graph structure, coefficient estimation,
        and effect calculation.  SR 26-2 MRM back-testing requirements apply
        to these coefficients and causal graph assumptions.

      Phase 2 (CTRL_TEL_003 / ISO 42001 §A.9.4) — placebo refutation using
        live telemetry.  Executes 50 simulations per trade call against
        runtime Langfuse data.  This is the agentic operational check:
        non-deterministic, live-sourced, and high-frequency.

    Redis cache:
      Results are cached in Redis keyed on (action_type, market_regime) with
      a TTL of CAUSAL_CACHE_TTL_SECONDS seconds (default 60s).  Cache misses
      and Redis errors are handled gracefully — the causal check always runs
      when the cache is unavailable.

    Telemetry freshness:
      Before Phase 2 placebo refutation, the most-recent observation timestamp
      in current_telemetry is checked against TELEMETRY_MAX_STALENESS_SECONDS
      (default 300s).  Stale or timestamp-less telemetry causes a fail-closed
      return of False.
    """
    if current_telemetry is None:
        # C-08 fix: in production, missing live telemetry is a fail-closed
        # condition — the causal gate cannot run against synthetic data because
        # the fixed np.random.seed(42) makes results predictable and gameable.
        # Reserve the mock fallback for dev/test environments only.
        import os as _os

        _cage_env = _os.getenv("CAGE_ENV", "production").lower()
        if _cage_env not in ("development", "test", "dev", "ci"):
            logger.error(
                "causal_safety_check: no live telemetry provided in production "
                "(CAGE_ENV=%s) — failing closed. Ensure LangfuseTelemetryProvider "
                "is configured and returning data before calling this function.",
                _cage_env,
            )
            return False
        logger.warning(
            "causal_safety_check: no telemetry provided — using mock data "
            "(CAGE_ENV=%s). This fallback is only acceptable in dev/test.",
            _cage_env,
        )
        current_telemetry = generate_mock_telemetry()

    amount = params.get("amount", 0.0)
    if amount <= 0:
        return True  # Not a meaningful trade to causally evaluate

    # Fail closed when dowhy is not installed — the causal tier is unavailable.
    if not _DOWHY_AVAILABLE:
        logger.warning(
            "causal_safety_check: 'dowhy' is not installed — failing closed "
            "(causal tier unavailable). Install dowhy to enable causal inference."
        )
        return False

    # ------------------------------------------------------------------
    # Cache key — keyed on (action_type, market_regime) from params
    # ------------------------------------------------------------------
    action_type = str(params.get("action_type", params.get("action", "unknown")))
    market_regime = str(params.get("market_regime", "unknown"))
    cache_key = f"causal_cache:{action_type}:{market_regime}"

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
        # Redis cache lookup — before Phase 1
        # ------------------------------------------------------------------
        # Attempt to retrieve a previously computed result for this
        # (action_type, market_regime) pair.  Cache hits skip both Phase 1
        # and Phase 2 entirely, reducing DoWhy overhead on repeated calls.
        with tracer.start_as_current_span(
            "causal_gatekeeper.cache_lookup"
        ) as cache_span:
            cache_span.set_attribute("causal.cache_key", cache_key)
            cached_payload = _causal_cache_get_sync(cache_key)

            if cached_payload is not None:
                cached_result = bool(cached_payload.get("result", False))
                cached_reason = cached_payload.get("reason", "")
                logger.debug(
                    "Causal cache HIT (key=%s) → result=%s reason=%s",
                    cache_key,
                    cached_result,
                    cached_reason,
                )
                cache_span.set_attribute("causal.cache_hit", True)
                return cached_result

            cache_span.set_attribute("causal.cache_hit", False)

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
        with tracer.start_as_current_span(
            "causal_gatekeeper.statistical_kernel"
        ) as mrm_span:
            mrm_span.set_attribute("governance.control_id", mrm_meta["internal_id"])
            mrm_span.set_attribute(
                "governance.framework", mrm_meta["primary_framework"]
            )
            mrm_span.set_attribute("governance.legacy_citation", mrm_legacy)
            mrm_span.set_attribute("governance.scope", mrm_meta["scope"])
            mrm_span.set_attribute("governance.deployment_region", active_region)
            mrm_span.set_attribute("causal.graph", causal_graph.strip())

            # Minimum sample guard — fail closed when there is insufficient
            # telemetry to fit a linear regression reliably.  This mirrors the
            # MIN_SAMPLES guard in telemetry_provider.py and prevents a
            # cold-start or sparse-data path from producing a meaningless
            # estimate that could incorrectly approve or reject a trade.
            # EV-4 Migration: Use config-based threshold (consolidated from
            # CAUSAL_MIN_SAMPLES and CAUSAL_MIN_LIVE_SAMPLES)
            _MIN_CAUSAL_SAMPLES = get_causal_min_samples()
            n_samples = len(current_telemetry)
            if n_samples < _MIN_CAUSAL_SAMPLES:
                mrm_span.set_attribute("causal.samples_available", n_samples)
                mrm_span.set_attribute(
                    "causal.min_samples_required", _MIN_CAUSAL_SAMPLES
                )
                mrm_span.set_attribute("causal.result", "insufficient_data_fail_closed")
                logger.warning(
                    "CausalGatekeeper: insufficient telemetry (%d < %d samples) — "
                    "failing closed (action BLOCKED). Adjust causal.min_samples in "
                    "config/governance_thresholds.json or set CAUSAL_MIN_SAMPLES env var.",
                    n_samples,
                    _MIN_CAUSAL_SAMPLES,
                )
                # NOTE: must return a bare bool, not a tuple — callers use
                # `if not causal_safety_check(...)` to detect failure, and a
                # non-empty tuple is truthy in Python, which would silently
                # invert this fail-closed guard into fail-open.
                return False

            model = _CausalModel(
                data=current_telemetry,
                treatment="trade_amount",
                outcome="risk_score",
                graph=causal_graph,
            )
            identified_estimand = model.identify_effect(
                proceed_when_unidentifiable=True
            )
            # NOTE: "backdoor.linear_regression" is a DoWhy library API method name
            # (Pearl's backdoor criterion for causal effect estimation). This is not
            # a security backdoor — it is standard causal inference terminology.
            # See: https://www.pywhy.org/dowhy/
            estimate = model.estimate_effect(
                identified_estimand, method_name="backdoor.linear_regression"
            )
            mrm_span.set_attribute("causal.estimated_effect", float(estimate.value))

            # ------------------------------------------------------------------
            # Peer Review Fix: β≤0 fail-closed guard (negative/zero causal slope)
            # ------------------------------------------------------------------
            # If the estimated causal effect (β) is negative or zero, the world-model
            # suggests that increasing trade_amount either decreases risk or has no
            # effect. This is counter-intuitive and likely indicates a confounded
            # or misspecified model. Fail closed to prevent adversarial bypass.
            if estimate.value <= 0:
                logger.warning(
                    "[%s] CAUSAL LOCK: Estimated causal effect β=%.4f ≤ 0 — "
                    "negative or zero slope indicates untrustworthy world-model.",
                    GovernanceControl.TRADITIONAL_MRM_VALIDATION.value,
                    estimate.value,
                )
                mrm_span.set_attribute(
                    "causal.lock_reason", "negative_or_zero_causal_slope"
                )
                mrm_span.set_attribute(
                    "causal.estimated_effect_blocked", float(estimate.value)
                )
                _causal_cache_set_sync(
                    cache_key, False, "negative_or_zero_causal_slope"
                )
                return False

        # ------------------------------------------------------------------
        # Phase 2: Operational Simulation (CTRL_TEL_003 / ISO 42001 §A.9.4)
        # ------------------------------------------------------------------
        # Placebo refutation against live telemetry.  50 simulations per
        # trade call — non-deterministic and high-frequency.  This is the
        # agentic operational check; results are only as trustworthy as the
        # live telemetry sourced from Langfuse governance spans.
        with tracer.start_as_current_span(
            "causal_gatekeeper.placebo_refutation"
        ) as tel_span:
            tel_span.set_attribute("governance.control_id", tel_meta["internal_id"])
            tel_span.set_attribute(
                "governance.framework", tel_meta["primary_framework"]
            )
            tel_span.set_attribute("governance.legacy_citation", tel_legacy)
            tel_span.set_attribute("governance.scope", tel_meta["scope"])
            tel_span.set_attribute("governance.deployment_region", active_region)
            tel_span.set_attribute("causal.num_simulations", 50)

            # ----------------------------------------------------------
            # Telemetry freshness check — before running 50 simulations
            # ----------------------------------------------------------
            # If the most-recent observation in current_telemetry is older
            # than TELEMETRY_MAX_STALENESS_SECONDS, stale data cannot be
            # trusted for causal inference — fail closed immediately.
            # Any exception in the freshness check also fails closed.
            freshness_ok = _check_telemetry_freshness(current_telemetry, tel_span)
            if not freshness_ok:
                tel_span.set_attribute("causal.lock_reason", "stale_telemetry")
                # Cache the fail-closed result so repeated calls don't re-check
                # stale data unnecessarily (short TTL still applies).
                _causal_cache_set_sync(cache_key, False, "stale_telemetry")
                return False

            refuter = model.refute_estimate(
                identified_estimand,
                estimate,
                method_name="placebo_treatment_refuter",
                num_simulations=50,  # Reduced for speed in a real-time gatekeeper
            )

            # Check if the refuter finds a 'fake' effect
            p_value = getattr(refuter, "refutation_result", {}).get("p_value", 1.0)
            if isinstance(p_value, (list, tuple, np.ndarray)):
                p_value = p_value[0]

            new_effect = refuter.new_effect
            if isinstance(new_effect, (list, tuple, np.ndarray)):
                new_effect = new_effect[0]

            tel_span.set_attribute(
                "causal.placebo_p_value",
                float(p_value) if p_value is not None else -1.0,
            )
            tel_span.set_attribute(
                "causal.placebo_new_effect",
                float(new_effect) if new_effect is not None else 0.0,
            )

            if (
                p_value is not None
                and not np.isnan(p_value)
                and float(p_value) < CAUSAL_LOCK_P_VALUE_THRESHOLD
            ):
                logger.warning(
                    "[%s] CAUSAL LOCK: Placebo p-value %.4f < %.2f — world-model untrustworthy.",
                    GovernanceControl.TELEMETRY_LIVE_VALIDATION.value,
                    p_value,
                    CAUSAL_LOCK_P_VALUE_THRESHOLD,
                )
                tel_span.set_attribute("causal.lock_reason", "p_value_threshold")
                tel_span.set_attribute(
                    "causal.lock_p_value_threshold", CAUSAL_LOCK_P_VALUE_THRESHOLD
                )
                _causal_cache_set_sync(cache_key, False, "p_value_threshold")
                return False

            if abs(new_effect) > CAUSAL_LOCK_PLACEBO_EFFECT_MAGNITUDE:
                logger.warning(
                    "[%s] CAUSAL LOCK: Placebo effect %.4f > %.2f — world-model untrustworthy.",
                    GovernanceControl.TELEMETRY_LIVE_VALIDATION.value,
                    new_effect,
                    CAUSAL_LOCK_PLACEBO_EFFECT_MAGNITUDE,
                )
                tel_span.set_attribute("causal.lock_reason", "placebo_effect_magnitude")
                tel_span.set_attribute(
                    "causal.lock_effect_magnitude_threshold",
                    CAUSAL_LOCK_PLACEBO_EFFECT_MAGNITUDE,
                )
                _causal_cache_set_sync(cache_key, False, "placebo_effect_magnitude")
                return False

        # ------------------------------------------------------------------
        # Phase 1 continued: marginal risk boundary check (MRM scope)
        # ------------------------------------------------------------------
        # Peer Review Fix: Bounded risk score calculation
        # The estimated_risk is strictly bounded within [0.0, 1.0] regardless
        # of adversarial input amounts. This uses CAUSAL_NORMALIZATION_SCALE
        # to normalize trade amounts before computing risk.
        #
        # Formula: estimated_risk = clamp(0.5 + β * amount / SCALE, 0.0, 1.0)
        #
        # Note: The β≤0 guard above ensures estimate.value > 0 at this point,
        # so this bounded calculation only restricts extreme positive values.
        estimated_risk = min(
            1.0,
            max(0.0, 0.5 + estimate.value * amount / CAUSAL_NORMALIZATION_SCALE),
        )

        if estimated_risk > CAUSAL_LOCK_RISK_BOUNDARY:
            logger.warning(
                "[%s] CAUSAL LOCK: Proposed action predicted to exceed safety boundary "
                "(estimated_risk=%.4f > boundary=%.4f).",
                GovernanceControl.TRADITIONAL_MRM_VALIDATION.value,
                estimated_risk,
                CAUSAL_LOCK_RISK_BOUNDARY,
            )
            _causal_cache_set_sync(cache_key, False, "risk_boundary_exceeded")
            return False

        # ------------------------------------------------------------------
        # All checks passed — cache the positive result and return True
        # ------------------------------------------------------------------
        _causal_cache_set_sync(cache_key, True, "all_checks_passed")
        return True

    except Exception as e:
        logger.error("Causal validation failed due to error: %s", e)
        # Fail safe - if we can't prove it's safe causally, we don't allow it.
        return False
