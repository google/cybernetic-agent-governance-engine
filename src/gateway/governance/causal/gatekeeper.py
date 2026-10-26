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
DoWhy Causal Gatekeeper — the domain-agnostic "Lock" on the CAGE.

Uses Microsoft DoWhy's causal inference + placebo refutation to validate
that the system's world-model is trustworthy before allowing high-stakes
domain actions.

Causal Graph (supplied via CausalSpec):
    confounder -> treatment_col
    confounder -> outcome_col
    treatment_col -> outcome_col

Telemetry & Bounded Risk Formulation:
    - Sourced from Langfuse OTel settlement spans via TelemetryProvider.
    - The treatment column is divided by ``CausalSpec.normalization_scale``
      before DoWhy fits the model, so beta is the outcome change per
      normalised unit of treatment.
    - If causal slope beta <= 0, the gate triggers a fail-closed lock.
    - If beta > 0, marginal risk is computed as
      min(1.0, max(0.0, 0.5 + beta * treatment_value / normalization_scale)),
      i.e. 0.5 plus the predicted change in the outcome metric. The scale
      cancels, so it cannot move the treatment value at which the boundary
      trips.
    - If risk exceeds CAUSAL_LOCK_RISK_BOUNDARY (0.95), the action is blocked.

The placebo refuter permutes the treatment column. The gatekeeper "locks" the
cage (the action is blocked because the underlying causal assumptions cannot
be trusted) when the refutation result is missing or non-finite, when the
simulated placebo effects have zero spread, or when it detects a spurious
effect (p < 0.05 or a large placebo effect).

Caching:
    Only the params-independent :class:`WorldModelVerdict` (trusted, beta,
    reason) is cached in Redis, and only for synthetic-factory telemetry. The
    marginal risk boundary depends on the request's treatment value and is
    evaluated on every call; it is never cached.
"""

import copy
import functools
import hashlib
import json
import logging
import math
import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any, TypeGuard

import networkx as nx
import numpy as np
import pandas as pd
import yaml
from opentelemetry import trace

# networkx >=3.x renamed d_separated -> d_separation.is_d_separator.
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
from src.gateway.governance.contracts import CausalSpec
from src.gateway.governance.env_posture import is_enforcing, resolve_posture

logger = logging.getLogger(__name__)
tracer = trace.get_tracer("src.gateway.governance.causal_gatekeeper")


@functools.cache
def _causal_config() -> dict:
    """Return the active domain's causal graph config, or ``{}`` if it has none.

    An empty result makes :func:`causal_safety_check` fail closed.
    """
    from src.gateway.governance.plugin_loader import active_domain_config

    path = active_domain_config().causal_graph_path
    if path is None:
        logger.warning(
            "active domain declares no causal_graph_path — causal tier fails closed"
        )
        return {}
    with open(path) as f:
        config = yaml.safe_load(f) or {}
    logger.info("Loaded causal graph configuration from %s", path)
    return config


from src.gateway.governance.schemas.thresholds import (
    get_causal_cache_ttl_seconds,
    get_causal_min_samples,
    get_causal_p_value_threshold,
    get_causal_placebo_effect_magnitude,
    get_causal_risk_boundary,
    get_telemetry_max_staleness_seconds,
)

# CAUSAL_LOCK_P_VALUE_THRESHOLD (Phase 2 — placebo refutation):
#   If the placebo treatment refuter's p-value is below this threshold, the
#   null hypothesis (no spurious effect) is rejected at the 5% significance
#   level. The world-model's causal assumptions cannot be trusted.
CAUSAL_LOCK_P_VALUE_THRESHOLD: float = get_causal_p_value_threshold()

# CAUSAL_LOCK_PLACEBO_EFFECT_MAGNITUDE (Phase 2 — placebo refutation):
#   If the absolute value of the placebo refuter's new_effect exceeds this
#   threshold, the estimated causal effect is considered unreliable regardless
#   of the p-value. Like beta, the placebo effect is measured per normalised
#   unit of treatment (``CausalSpec.normalization_scale``).
CAUSAL_LOCK_PLACEBO_EFFECT_MAGNITUDE: float = get_causal_placebo_effect_magnitude()

# CAUSAL_LOCK_RISK_BOUNDARY (Phase 1 — marginal risk boundary):
#   If (0.5 + estimated_marginal_effect) exceeds this threshold, the proposed
#   action is predicted to push the system's outcome metric above the safety
#   boundary. estimated_marginal_effect = beta * treatment_value /
#   normalization_scale, the predicted change in the outcome metric.
CAUSAL_LOCK_RISK_BOUNDARY: float = get_causal_risk_boundary()

# CAUSAL_NORMALIZATION_SCALE:
#   Default treatment unit for a CausalSpec that does not set one. The
#   treatment column is divided by the spec's scale before DoWhy fits the
#   model, so beta and the placebo effect are expressed per this many units of
#   treatment. The scale cancels out of the marginal risk boundary, so it
#   cannot move the trip point. It is fixed per domain, not a tuning knob, and
#   is deliberately not read from the environment: an override would silently
#   change the units of CAUSAL_LOCK_PLACEBO_EFFECT_MAGNITUDE.
CAUSAL_NORMALIZATION_SCALE: float = 10_000.0

# Phase 2 placebo refutation. The placebo is a row permutation of the
# treatment column. dowhy's default placebo for a float treatment ("Random
# Data") is drawn from N(0, 0): a constant zero column, under which every
# simulated effect is exactly 0.0 and the refutation cannot fail.
PLACEBO_TYPE: str = "permute"
PLACEBO_NUM_SIMULATIONS: int = 50
# Numerical tolerance, not a policy threshold: simulated placebo effects whose
# spread is at most this fraction of the effect scale (the larger of beta and
# the largest |effect|) have zero spread up to floating-point noise.
_PLACEBO_DEGENERATE_RTOL: float = 1e-9
# Phase 1 numerical trust. A numerical tolerance, not a policy threshold, and
# domain-agnostic by construction: phase 1 refuses, before fitting, a
# regression whose relative rounding-error bound (_least_squares_error_bound)
# exceeds it. At 1e-6 the coefficients agree to about six significant figures
# on every correct IEEE-754 platform, a floor for any decision derived from a
# fit, whatever the domain's units. The bound is normwise: a coefficient much
# smaller than the coefficient vector's norm is good to 1e-6 of that norm, not
# to six figures of itself. Above the bound, platforms may return materially
# different coefficients: an exactly rank-deficient design (a constant
# treatment) fitted a slope of +0.10 on macOS arm64 and -6.5e11 on Linux
# x86_64. Sanity check in one domain: on the finance synthetic telemetry the
# tolerance would cap the trip point's rounding error at about one cent of
# $9,144 (its actual bound is about 1e-14). The value comes from this
# reasoning, not from an empirical boundary: no frame has been measured with a
# bound between 1e-8 and 5e-5.
_LSQ_ERROR_BOUND_MAX: float = 1e-6

CAUSAL_GATEKEEPER_STRICT_MODE: bool = (
    os.environ.get("CAUSAL_GATEKEEPER_STRICT_MODE", "false").lower() == "true"
)

_NO_LEGAL_FORCE_MARKER = "no legal force"

_TIMESTAMP_CANDIDATES = ("timestamp", "ts", "event_time", "time", "created_at")


# ---------------------------------------------------------------------------
# Internal helpers — telemetry freshness
# ---------------------------------------------------------------------------


def _extract_telemetry_watermark(telemetry: pd.DataFrame) -> float | None:
    """Return the most-recent observation timestamp in *telemetry* as UTC epoch seconds, or ``None``."""
    try:
        ts_col: str | None = None
        for candidate in _TIMESTAMP_CANDIDATES:
            if candidate in telemetry.columns:
                ts_col = candidate
                break

        if ts_col is None or len(telemetry) == 0:
            return None

        raw_ts = telemetry[ts_col].max()
        if raw_ts is None or pd.isna(raw_ts):
            return None
        if isinstance(raw_ts, (int, float, np.number)):
            val = float(raw_ts)
            if not math.isfinite(val):
                return None
            if val > 1e12:
                val = val / 1000.0
            return val
        most_recent = pd.to_datetime(raw_ts, utc=True).to_pydatetime()
        ts_val = float(most_recent.timestamp())
        return ts_val if math.isfinite(ts_val) else None
    except Exception:
        return None


def _check_telemetry_freshness(  # type: ignore[no-untyped-def]
    telemetry: pd.DataFrame,
    span,
) -> bool:
    """Check that the most-recent observation in *telemetry* is not stale."""
    try:
        ts_col: str | None = None
        for candidate in _TIMESTAMP_CANDIDATES:
            if candidate in telemetry.columns:
                ts_col = candidate
                break

        if ts_col is None:
            logger.warning(
                "Telemetry freshness check: no timestamp column found "
                "(checked: %s) — failing closed.",
                ", ".join(_TIMESTAMP_CANDIDATES),
            )
            span.set_attribute("causal.telemetry_stale", True)
            span.set_attribute("causal.telemetry_age_seconds", -1)
            return False

        watermark = _extract_telemetry_watermark(telemetry)
        if watermark is None:
            logger.warning(
                "Telemetry freshness check: cannot parse timestamp column '%s' "
                "— failing closed.",
                ts_col,
            )
            span.set_attribute("causal.telemetry_stale", True)
            span.set_attribute("causal.telemetry_age_seconds", -1)
            return False

        most_recent = datetime.fromtimestamp(watermark, tz=timezone.utc)
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
# World-model verdict — the only thing the Redis cache ever stores
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class WorldModelVerdict:
    """Params-independent outcome of validating the causal world-model.

    Computed from the telemetry and the :class:`CausalSpec` graph only (sample
    count, causal slope ``beta``, telemetry freshness, placebo refutation). It
    deliberately carries no per-request information: the marginal risk
    boundary depends on the request's treatment value and is evaluated on
    every call from ``beta`` (see :meth:`CausalGatekeeper.causal_safety_check`).

    ``beta`` is the outcome change per normalised unit of treatment, i.e. per
    ``CausalSpec.normalization_scale`` units (see :func:`validate_world_model`).

    Invariant: ``trusted`` implies ``beta`` is a finite float ``> 0``.
    """

    trusted: bool
    beta: float | None
    reason: str

    def __post_init__(self) -> None:
        if self.trusted and not _is_positive_finite(self.beta):
            raise ValueError("a trusted WorldModelVerdict requires a finite beta > 0")

    def to_json(self) -> str:
        return json.dumps(
            {"trusted": self.trusted, "beta": self.beta, "reason": self.reason}
        )

    @classmethod
    def from_payload(cls, payload: Any) -> "WorldModelVerdict | None":
        """Parse a cached payload; return ``None`` (cache miss) if malformed."""
        if not isinstance(payload, dict):
            return None
        trusted = payload.get("trusted")
        beta = payload.get("beta")
        reason = payload.get("reason")
        if not isinstance(trusted, bool) or not isinstance(reason, str):
            return None
        if beta is not None and (
            isinstance(beta, bool) or not isinstance(beta, (int, float))
        ):
            return None
        try:
            return cls(
                trusted=trusted,
                beta=None if beta is None else float(beta),
                reason=reason,
            )
        except ValueError:
            return None


# Reasons a causal check can produce besides the WorldModelVerdict reasons
# (``insufficient_samples``, ``stale_telemetry``, ``p_value_threshold``, ...),
# which are passed through unchanged.
REASON_TRUSTED = "world_model_trusted"
REASON_INVALID_TREATMENT = "invalid_treatment"
REASON_NO_LIVE_TELEMETRY = "no_live_telemetry"
REASON_DOWHY_UNAVAILABLE = "dowhy_unavailable"
REASON_INCOMPLETE_SPEC = "incomplete_spec"
REASON_RISK_BOUNDARY = "risk_boundary"
REASON_CHECK_ERROR = "check_error"
REASON_INSUFFICIENT_SAMPLES = "insufficient_samples"

# Phase-1 (statistical kernel) reason for an untrusted WorldModelVerdict,
# besides the slope guard's ``negative_or_zero_causal_slope`` and
# ``non_finite_causal_slope``: the regression is too ill-conditioned for its
# coefficients to be reproducible (see _least_squares_error_bound).
REASON_DESIGN_ILL_CONDITIONED = "design_ill_conditioned"

# Phase-2 (placebo refutation) reasons for an untrusted WorldModelVerdict.
REASON_PLACEBO_RESULT_INVALID = "placebo_result_invalid"
REASON_PLACEBO_DEGENERATE = "placebo_degenerate"
REASON_PLACEBO_P_VALUE = "p_value_threshold"
REASON_PLACEBO_EFFECT_MAGNITUDE = "placebo_effect_magnitude"


@dataclass(frozen=True)
class CausalDecision:
    """Outcome of one causal check: whether the action is safe, and why.

    ``reason`` is :data:`REASON_TRUSTED` when ``safe`` is True; otherwise it
    names the first fail-closed condition hit, so callers can emit a distinct
    violation code (e.g. bootstrap ``insufficient_samples`` versus a missing
    telemetry feed) instead of one generic failure.
    """

    safe: bool
    reason: str


def _is_positive_finite(value: float | None) -> bool:
    return (
        value is not None
        and not isinstance(value, bool)
        and math.isfinite(value)
        and value > 0
    )


# ---------------------------------------------------------------------------
# Internal helpers — Redis cache (world-model verdicts only)
# ---------------------------------------------------------------------------

_CACHE_KEY_PREFIX = "causal_wm"


def _causal_cache_get_sync(cache_key: str) -> WorldModelVerdict | None:
    """Return the cached :class:`WorldModelVerdict`, or ``None`` on a miss.

    Raises ``RuntimeError`` when Redis is unavailable so the caller fails
    closed. A malformed payload is treated as a miss (the verdict is recomputed).
    """
    from src.gateway.infrastructure.redis_client import sync_redis_client

    if sync_redis_client is None:
        raise RuntimeError(
            "Redis unavailable: cannot read causal world-model cache; failing closed"
        )

    try:
        raw = sync_redis_client.get(cache_key)
    except Exception as exc:
        raise RuntimeError(
            "Redis unavailable: cannot read causal world-model cache; failing closed"
        ) from exc

    if raw is None:
        return None

    try:
        payload = json.loads(raw)
    except Exception as exc:
        logger.warning(
            "Causal cache GET (sync): JSON decode failed (key=%s): %s — treating as cache miss.",
            cache_key,
            exc,
        )
        return None

    verdict = WorldModelVerdict.from_payload(payload)
    if verdict is None:
        logger.warning(
            "Causal cache GET (sync): malformed world-model verdict (key=%s) — "
            "treating as cache miss.",
            cache_key,
        )
    return verdict


def _causal_cache_set_sync(cache_key: str, verdict: WorldModelVerdict) -> None:
    """Write a world-model verdict to Redis with telemetry.cache_ttl_seconds TTL."""
    cache_ttl = get_causal_cache_ttl_seconds()
    if cache_ttl <= 0:
        return
    try:
        from src.gateway.infrastructure.redis_client import sync_redis_client

        if sync_redis_client is None:
            return
        sync_redis_client.setex(cache_key, cache_ttl, verdict.to_json())
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
    """Validate causal ordering between a governance span and an execution span."""
    gov_trace_id = governance_span.get("trace_id")
    exec_trace_id = execution_span.get("trace_id")

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


def _extract_numeric_param(params: Mapping[str, Any], key: str) -> float | None:
    """Extract a finite float value from ``params[key]`` or return ``None``."""
    if not key or key not in params:
        return None
    raw = params.get(key)
    if raw is None or isinstance(raw, bool):
        return None
    try:
        val = float(raw)
    except (TypeError, ValueError):
        return None
    if math.isnan(val) or math.isinf(val):
        return None
    return val


def _spec_from_config(causal_config: dict[str, Any]) -> CausalSpec | None:
    """Build a :class:`CausalSpec` from a loaded domain causal graph YAML mapping."""
    if not isinstance(causal_config, dict):
        return None
    graph_dot = str(causal_config.get("graph", "")).strip()
    treatment_col = str(causal_config.get("treatment", "")).strip()
    outcome_col = str(causal_config.get("outcome", "")).strip()
    if not graph_dot or not treatment_col or not outcome_col:
        return None
    treatment_param = str(causal_config.get("treatment_param", treatment_col)).strip()
    context_key = str(causal_config.get("context_key", "")).strip()
    scale = float(causal_config.get("normalization_scale", CAUSAL_NORMALIZATION_SCALE))
    return CausalSpec(
        graph_dot=graph_dot,
        treatment_col=treatment_col,
        outcome_col=outcome_col,
        treatment_extractor=lambda p: (
            _extract_numeric_param(p, treatment_param)
            if treatment_param in p
            else _extract_numeric_param(p, treatment_col)
        ),
        context_extractor=(
            (lambda p: str(p.get(context_key, "unknown")))
            if context_key
            else (lambda _p: "default")
        ),
        normalization_scale=scale,
        synthetic_telemetry_factory=None,
    )


def _spec_fingerprint(spec: CausalSpec) -> str:
    """Return a short stable digest identifying the world-model a spec describes.

    Covers the graph, treatment/outcome columns, the treatment unit
    (``normalization_scale``, which sets the unit of the cached ``beta``) and
    the synthetic telemetry factory (the only telemetry source whose verdicts
    are cached), so two domains or specs never share a cache entry, and a
    verdict whose ``beta`` is in other units is never read back. The
    extractors are deliberately excluded: they only affect the per-request
    risk boundary, which is never cached.
    """
    factory = spec.synthetic_telemetry_factory
    factory_id = (
        ""
        if factory is None
        else f"{getattr(factory, '__module__', '')}."
        f"{getattr(factory, '__qualname__', type(factory).__qualname__)}"
    )
    material = json.dumps(
        [
            spec.graph_dot,
            spec.treatment_col,
            spec.outcome_col,
            repr(float(spec.normalization_scale)),
            factory_id,
        ]
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


class CausalGatekeeper:
    """Domain-agnostic DoWhy causal inference and placebo refutation gatekeeper.

    A check has two parts with different lifetimes:

    1. **World-model validation** (:meth:`_validate_world_model`) depends only
       on the telemetry and the spec's graph — sample count, causal slope
       ``beta``, telemetry freshness, placebo refutation — and yields a
       :class:`WorldModelVerdict`. This is the expensive DoWhy step and the
       only result that is ever cached.
    2. **Marginal risk boundary** (:meth:`_within_risk_boundary`) depends on
       the request's treatment value and is evaluated on every call from the
       verdict's ``beta``. It is never cached.

    Caching policy: a verdict is cached only when the caller passed no
    telemetry and the spec's ``synthetic_telemetry_factory`` produced it — the
    telemetry identity is then fully determined by the spec and covered by the
    spec fingerprint in the cache key. Telemetry passed explicitly by a caller
    never reads or writes the cache, because the key carries no telemetry
    identity and a verdict for one telemetry window must not be served for
    another.
    """

    def __init__(self, spec: CausalSpec) -> None:
        self.spec = spec
        self._spec_fingerprint = _spec_fingerprint(spec)

    def causal_safety_check(
        self,
        params: dict[str, Any],
        current_telemetry: pd.DataFrame | None = None,
        *,
        action: str | None = None,
        verdict: WorldModelVerdict | None = None,
    ) -> bool:
        """Boolean form of :meth:`evaluate` (``evaluate(...).safe``)."""
        return self.evaluate(
            params, current_telemetry, action=action, verdict=verdict
        ).safe

    def evaluate(
        self,
        params: dict[str, Any],
        current_telemetry: pd.DataFrame | None = None,
        *,
        action: str | None = None,
        verdict: WorldModelVerdict | None = None,
    ) -> CausalDecision:
        """Validate causal world-model integrity and the marginal risk boundary.

        Args:
            params: Action parameters; the treatment value and context are
                read via the spec's extractors.
            current_telemetry: Live telemetry to validate the world-model
                against when ``verdict`` is not precomputed. ``None`` **or an
                empty frame** means "no live telemetry": in enforcing postures
                that fails closed with :data:`REASON_NO_LIVE_TELEMETRY`; in
                non-enforcing postures the spec's synthetic telemetry factory
                stands in and the verdict may be cached. A non-empty frame is
                always validated as given (never replaced by synthetic data),
                so a frame with fewer than ``min_samples`` rows yields
                ``insufficient_samples``.
            action: Action name used to namespace the world-model cache entry.
                Falls back to ``params["action_type"]`` / ``params["action"]``.
            verdict: Precomputed :class:`WorldModelVerdict` from the background
                :class:`WorldModelRefresher`. When supplied, the request path
                skips DoWhy refutation and evaluates only treatment extraction
                and the marginal risk boundary against ``verdict.beta``.

        Fails closed (``safe=False``) on:
        - Missing, non-numeric, NaN/infinite, or non-positive (<= 0) treatment
          value (Defect A5) -> ``invalid_treatment``.
        - No live telemetry in enforcing postures, or when no synthetic
          telemetry factory is configured -> ``no_live_telemetry``.
        - ``dowhy`` unavailable -> ``dowhy_unavailable``.
        - Incomplete spec -> ``incomplete_spec``.
        - Untrusted world-model -> the verdict's reason (``insufficient_samples``,
          ``stale_telemetry``, slope or placebo reasons).
        - Predicted marginal risk exceeding ``CAUSAL_LOCK_RISK_BOUNDARY`` ->
          ``risk_boundary``.
        - Any exception, including Redis unavailable while the world-model
          cache is enabled -> ``check_error`` (never cached).
        """
        treatment_value = self._treatment_value(params)
        if treatment_value is None:
            return CausalDecision(False, REASON_INVALID_TREATMENT)

        if verdict is not None:
            if (
                not self.spec.graph_dot
                or not self.spec.treatment_col
                or not self.spec.outcome_col
            ):
                logger.warning(
                    "causal_safety_check: incomplete CausalSpec — failing closed"
                )
                return CausalDecision(False, REASON_INCOMPLETE_SPEC)
            try:
                if not verdict.trusted:
                    return CausalDecision(False, verdict.reason)
                if not self._within_risk_boundary(verdict.beta, treatment_value):
                    return CausalDecision(False, REASON_RISK_BOUNDARY)
                return CausalDecision(True, REASON_TRUSTED)
            except Exception as e:
                logger.error("Causal validation failed due to error: %s", e)
                return CausalDecision(False, REASON_CHECK_ERROR)

        no_live = current_telemetry is None or len(current_telemetry) == 0
        if no_live:
            if not self._synthetic_telemetry_permitted():
                return CausalDecision(False, REASON_NO_LIVE_TELEMETRY)
            current_telemetry = None

        if not _DOWHY_AVAILABLE:
            logger.warning(
                "causal_safety_check: 'dowhy' is not installed — failing closed "
                "(causal tier unavailable). Install dowhy to enable causal inference."
            )
            return CausalDecision(False, REASON_DOWHY_UNAVAILABLE)

        if (
            not self.spec.graph_dot
            or not self.spec.treatment_col
            or not self.spec.outcome_col
        ):
            logger.warning(
                "causal_safety_check: incomplete CausalSpec — failing closed"
            )
            return CausalDecision(False, REASON_INCOMPLETE_SPEC)

        try:
            resolved_verdict = self._resolve_world_model(
                params, current_telemetry, action
            )
            if not resolved_verdict.trusted:
                return CausalDecision(False, resolved_verdict.reason)
            if not self._within_risk_boundary(resolved_verdict.beta, treatment_value):
                return CausalDecision(False, REASON_RISK_BOUNDARY)
            return CausalDecision(True, REASON_TRUSTED)
        except Exception as e:
            logger.error("Causal validation failed due to error: %s", e)
            return CausalDecision(False, REASON_CHECK_ERROR)

    def telemetry_readiness(
        self, current_telemetry: pd.DataFrame | None = None
    ) -> dict[str, Any]:
        """Report whether the causal telemetry window has reached warmup threshold.

        Allows health checks and evaluation harnesses to distinguish cold-start
        telemetry starvation (``n_samples < min_samples``) from steady-state
        DoWhy placebo refutation failures.
        """
        min_samples = get_causal_min_samples()
        posture = resolve_posture()
        synthetic_permitted = not is_enforcing(posture) and (
            self.spec.synthetic_telemetry_factory is not None
        )
        if current_telemetry is not None and len(current_telemetry) > 0:
            n_samples = len(current_telemetry)
        elif synthetic_permitted and self.spec.synthetic_telemetry_factory is not None:
            try:
                n_samples = len(self.spec.synthetic_telemetry_factory())
            except Exception:
                n_samples = 0
        else:
            n_samples = 0
        return {
            "warmed_up": n_samples >= min_samples,
            "samples_available": n_samples,
            "min_samples_required": min_samples,
            "posture": posture.value,
            "synthetic_fallback_permitted": synthetic_permitted,
        }

    # ------------------------------------------------------------------
    # Per-request inputs
    # ------------------------------------------------------------------

    def _treatment_value(self, params: dict[str, Any]) -> float | None:
        """Extract a finite, positive treatment value or ``None`` (Defect A5)."""
        try:
            raw_treatment = self.spec.treatment_extractor(params)
        except Exception as exc:
            logger.warning(
                "causal_safety_check: treatment_extractor failed (%s) — "
                "invalid_or_nonpositive_treatment_value (failing closed).",
                exc,
            )
            return None

        if raw_treatment is None or isinstance(raw_treatment, bool):
            logger.warning(
                "causal_safety_check: invalid_or_nonpositive_treatment_value "
                "(treatment=None) — failing closed."
            )
            return None

        try:
            treatment_value = float(raw_treatment)
        except (TypeError, ValueError):
            logger.warning(
                "causal_safety_check: invalid_or_nonpositive_treatment_value "
                "(non-numeric treatment=%r) — failing closed.",
                raw_treatment,
            )
            return None

        if not _is_positive_finite(treatment_value):
            logger.warning(
                "causal_safety_check: invalid_or_nonpositive_treatment_value "
                "(treatment=%s <= 0) — failing closed.",
                treatment_value,
            )
            return None
        return treatment_value

    def _synthetic_telemetry_permitted(self) -> bool:
        """Return whether the spec's synthetic telemetry may stand in for live data."""
        posture = resolve_posture()
        if is_enforcing(posture):
            logger.error(
                "causal_safety_check: no live telemetry provided in enforcing "
                "posture (%s) — failing closed.",
                posture.value,
            )
            return False
        if self.spec.synthetic_telemetry_factory is None:
            logger.warning(
                "causal_safety_check: no live telemetry provided and no "
                "synthetic_telemetry_factory configured — failing closed."
            )
            return False
        logger.warning(
            "causal_safety_check: no telemetry provided — using domain "
            "synthetic_telemetry_factory (posture=%s).",
            posture.value,
        )
        return True

    def _cache_key(self, params: dict[str, Any], action: str | None) -> str:
        action_name = (
            action
            if action is not None
            else str(params.get("action_type", params.get("action", "unknown")))
        )
        try:
            extractor = self.spec.context_extractor
            context_val = str(extractor(params)) if extractor is not None else "unknown"
        except Exception:
            context_val = "unknown"
        return (
            f"{_CACHE_KEY_PREFIX}:{self._spec_fingerprint}:{action_name}:{context_val}"
        )

    # ------------------------------------------------------------------
    # World-model validation (params-independent, cacheable)
    # ------------------------------------------------------------------

    def _resolve_world_model(
        self,
        params: dict[str, Any],
        current_telemetry: pd.DataFrame | None,
        action: str | None,
    ) -> WorldModelVerdict:
        """Return the world-model verdict, from cache when the policy allows it.

        Exceptions propagate to the caller (fail closed) and are never cached.
        """
        if current_telemetry is not None:
            return self._validate_world_model(current_telemetry)

        cache_key: str | None = None
        if get_causal_cache_ttl_seconds() > 0:
            cache_key = self._cache_key(params, action)
            with tracer.start_as_current_span(
                "causal_gatekeeper.cache_lookup"
            ) as cache_span:
                cache_span.set_attribute("causal.cache_key", cache_key)
                cached = _causal_cache_get_sync(cache_key)
                cache_span.set_attribute("causal.cache_hit", cached is not None)
            if cached is not None:
                logger.debug(
                    "Causal world-model cache HIT (key=%s) -> trusted=%s reason=%s",
                    cache_key,
                    cached.trusted,
                    cached.reason,
                )
                return cached

        factory = self.spec.synthetic_telemetry_factory
        if factory is None:  # guarded by _synthetic_telemetry_permitted
            raise RuntimeError("no synthetic_telemetry_factory configured")
        verdict = self._validate_world_model(factory())
        if cache_key is not None:
            _causal_cache_set_sync(cache_key, verdict)
        return verdict

    def _validate_world_model(self, telemetry: pd.DataFrame) -> WorldModelVerdict:
        """Run DoWhy estimation and placebo refutation over *telemetry*."""
        return validate_world_model(
            self.spec.graph_dot,
            self.spec.treatment_col,
            self.spec.outcome_col,
            telemetry,
            normalization_scale=self.spec.normalization_scale,
        )

    # ------------------------------------------------------------------
    # Marginal risk boundary (per request, never cached)
    # ------------------------------------------------------------------

    def _within_risk_boundary(self, beta: float | None, treatment_value: float) -> bool:
        """Return whether this request's predicted risk stays within the boundary."""
        if beta is None or not _is_positive_finite(beta):
            return False
        estimated_risk = _marginal_risk(
            beta, treatment_value, self.spec.normalization_scale
        )
        with tracer.start_as_current_span(
            "causal_gatekeeper.risk_boundary"
        ) as risk_span:
            risk_span.set_attribute("causal.estimated_risk", estimated_risk)
            risk_span.set_attribute("causal.risk_boundary", CAUSAL_LOCK_RISK_BOUNDARY)
            if estimated_risk > CAUSAL_LOCK_RISK_BOUNDARY:
                logger.warning(
                    "[%s] CAUSAL LOCK: Proposed action predicted to exceed safety boundary "
                    "(estimated_risk=%.4f > boundary=%.4f).",
                    GovernanceControl.TRADITIONAL_MRM_VALIDATION.value,
                    estimated_risk,
                    CAUSAL_LOCK_RISK_BOUNDARY,
                )
                risk_span.set_attribute("causal.lock_reason", "risk_boundary_exceeded")
                return False
        return True


def _marginal_risk(
    beta: float, treatment_value: float, normalization_scale: float
) -> float:
    """Predicted outcome metric for one request, clamped to ``[0, 1]``.

    ``0.5 + beta * treatment_value / normalization_scale``. ``beta`` is the
    outcome change per normalised unit of treatment (:func:`validate_world_model`
    fits on ``treatment / normalization_scale``), so the second term is the
    predicted change in the outcome metric and the scale cancels: the treatment
    value at which the boundary trips does not depend on it.

    Raises ``ValueError`` for a non-finite or non-positive scale (callers fail
    closed).
    """
    if not _is_positive_finite(normalization_scale):
        raise ValueError("normalization_scale must be a finite number > 0")
    return min(1.0, max(0.0, 0.5 + beta * treatment_value / normalization_scale))


@dataclass(frozen=True)
class PlaceboRefutation:
    """Result of the phase-2 placebo refutation, including every simulated effect.

    ``p_value`` is dowhy's significance test of a null effect of 0 against the
    simulated placebo effects; ``new_effect`` is their mean. dowhy's own
    ``refute_estimate`` reports only those two numbers, which cannot reveal a
    placebo distribution with zero spread (see :func:`_placebo_lock_reason`),
    so the simulated ``effects`` are kept too.
    """

    p_value: float | None
    new_effect: float | None
    effects: tuple[float, ...]


def _as_float(value: Any) -> float | None:
    """Return a real scalar (or one-element array) as ``float``, else ``None``.

    NaN and infinities are returned as floats: deciding about them is
    :func:`_placebo_lock_reason`'s job.
    """
    if value is None or isinstance(value, (bool, np.bool_)):
        return None
    try:
        arr = np.asarray(value, dtype=float)
    except (TypeError, ValueError):
        return None
    return float(arr.reshape(-1)[0]) if arr.size == 1 else None


def _placebo_refutation(
    data: pd.DataFrame, identified_estimand: Any, estimate: Any
) -> PlaceboRefutation:
    """Run dowhy's placebo-treatment refutation, keeping every simulated effect.

    Uses the same per-simulation step and significance test as dowhy 0.14's
    ``refute_placebo_treatment`` (a null effect of 0 tested against the
    simulated placebo effects), with the placebo fixed to :data:`PLACEBO_TYPE`
    and :data:`PLACEBO_NUM_SIMULATIONS` simulations. Exceptions propagate, so
    callers fail closed.
    """
    from dowhy.causal_refuter import test_significance
    from dowhy.causal_refuters.placebo_treatment_refuter import (
        PlaceboType,
        _refute_once,
    )

    placebo_type = PlaceboType(PLACEBO_TYPE)
    placebo_estimand = copy.deepcopy(identified_estimand)
    placebo_estimand.treatment_variable = ["placebo"]
    treatment_names = list(identified_estimand.treatment_variable)
    type_dict = dict(data.dtypes)
    effects: list[float] = []
    for _ in range(PLACEBO_NUM_SIMULATIONS):
        effect = _as_float(
            _refute_once(
                data,
                placebo_estimand,
                estimate,
                treatment_names,
                type_dict,
                placebo_type=placebo_type,
            )
        )
        effects.append(math.nan if effect is None else effect)
    # dowhy's significance tests read only ``.value`` of the estimate under
    # test; the placebo null hypothesis is an effect of 0. A degenerate
    # distribution divides by zero in the normal test; the guard handles that.
    with np.errstate(divide="ignore", invalid="ignore"):
        significance = test_significance(
            SimpleNamespace(value=0.0), np.asarray(effects, dtype=float)
        )
    return PlaceboRefutation(
        p_value=_as_float(significance.get("p_value")),
        new_effect=float(np.mean(effects)) if effects else None,
        effects=tuple(effects),
    )


def _placebo_lock_reason(placebo: PlaceboRefutation, beta: float) -> str | None:
    """Return why the placebo refutation refuses the world-model, or ``None``.

    Checked in order; every failure is fail-closed:

    1. Fewer than two simulated effects, or any non-finite one
       -> :data:`REASON_PLACEBO_RESULT_INVALID`.
    2. Zero spread across the simulated effects (up to floating-point noise)
       -> :data:`REASON_PLACEBO_DEGENERATE`. A placebo distribution without
       spread carries no evidence, and dowhy's significance test cannot show
       it: with fewer than 100 simulations the normal test returns NaN or 0,
       and from 100 on the bootstrap test returns a finite p-value of 1.0
       when every effect is 0.0, which reads as a clean pass.
    3. A missing or non-finite p-value or mean effect
       -> :data:`REASON_PLACEBO_RESULT_INVALID`.
    4. p-value below :data:`CAUSAL_LOCK_P_VALUE_THRESHOLD`
       -> :data:`REASON_PLACEBO_P_VALUE`. dowhy tests a null effect of 0
       against the placebo distribution, so a low p-value means the placebo
       effects are not centred on 0: the refutation failed.
    5. ``|mean placebo effect|`` above
       :data:`CAUSAL_LOCK_PLACEBO_EFFECT_MAGNITUDE`
       -> :data:`REASON_PLACEBO_EFFECT_MAGNITUDE`.
    """

    effects = placebo.effects
    if len(effects) < 2 or not all(_is_finite_real(e) for e in effects):
        return REASON_PLACEBO_RESULT_INVALID
    effect_scale = max(abs(beta), max(abs(e) for e in effects))
    if max(effects) - min(effects) <= _PLACEBO_DEGENERATE_RTOL * effect_scale:
        return REASON_PLACEBO_DEGENERATE
    p_value, new_effect = placebo.p_value, placebo.new_effect
    if not _is_finite_real(p_value) or not _is_finite_real(new_effect):
        return REASON_PLACEBO_RESULT_INVALID
    if p_value < CAUSAL_LOCK_P_VALUE_THRESHOLD:
        return REASON_PLACEBO_P_VALUE
    if abs(new_effect) > CAUSAL_LOCK_PLACEBO_EFFECT_MAGNITUDE:
        return REASON_PLACEBO_EFFECT_MAGNITUDE
    return None


def _is_finite_real(value: object) -> TypeGuard[float]:
    """Return whether *value* is a finite real number (bools excluded)."""
    return (
        isinstance(value, (int, float, np.number))
        and not isinstance(value, (bool, np.bool_))
        and math.isfinite(value)
    )


def _least_squares_error_bound(
    frame: pd.DataFrame,
    treatment: str,
    outcome: str,
    adjustment: Sequence[str],
) -> float:
    """Rounding-error bound of the phase-1 regression, computed before it is fitted.

    The regression is the one ``backdoor.linear_regression`` fits: ``outcome``
    on an intercept, the (already normalised) ``treatment`` and the backdoor
    ``adjustment`` set, categorical covariates one-hot encoded with the first
    level dropped. Returns the bound the LAPACK Users' Guide (section 4.5)
    gives for an SVD-based least-squares solve, valid on any IEEE-754
    platform::

        ||x_hat - x|| / ||x||  <=  eps * (2 * kappa / cos(theta)
                                          + kappa**2 * tan(theta))

    ``kappa`` is the design's condition number and ``theta`` the angle between
    the outcome and the design's column space. Because of the ``kappa**2``
    term, residual noise amplifies ill-conditioning: neither a variance cutoff
    on the treatment nor a condition-number cutoff alone bounds the error. A
    rank-deficient design (a constant treatment, or one collinear with a
    covariate) has ``kappa >= 1 / eps``. Returns ``inf`` for a non-numeric or
    non-finite value, or for no more rows than coefficients, so the caller
    fails closed.
    """
    covariates = [
        c for c in adjustment if c in frame.columns and c not in (treatment, outcome)
    ]
    try:
        parts = [frame[[treatment]].astype(float)]
        if covariates:
            parts.append(
                pd.get_dummies(frame[covariates], drop_first=True, dtype=float)
            )
        regressors = pd.concat(parts, axis=1).to_numpy(dtype=float)
        response = frame[outcome].to_numpy(dtype=float)
    except (TypeError, ValueError):
        return math.inf
    design = np.column_stack([np.ones(len(regressors)), regressors])
    if design.shape[0] <= design.shape[1]:
        return math.inf
    if not (np.isfinite(design).all() and np.isfinite(response).all()):
        return math.inf

    eps = float(np.finfo(np.float64).eps)
    try:
        solution, _, _, singular = np.linalg.lstsq(design, response, rcond=None)
    except np.linalg.LinAlgError:
        return math.inf
    if not singular[0] > 0:
        return math.inf
    rcond = max(float(singular[-1] / singular[0]), eps)
    response_norm = float(np.linalg.norm(response))
    sin_t = (
        float(np.linalg.norm(response - design @ solution)) / response_norm
        if response_norm > 0
        else 0.0
    )
    cos_t = max(math.sqrt(max(0.0, (1.0 - sin_t) * (1.0 + sin_t))), eps)
    return eps * (2.0 / (rcond * cos_t) + (sin_t / cos_t) / rcond**2)


def validate_world_model(
    graph_dot: str,
    treatment_col: str,
    outcome_col: str,
    telemetry: pd.DataFrame,
    *,
    normalization_scale: float,
) -> WorldModelVerdict:
    """Pure, process-pool-safe DoWhy estimation and placebo refutation.

    Takes only primitive graph coordinates, the treatment unit and a
    :class:`pandas.DataFrame` so it can be executed in a
    :class:`concurrent.futures.ProcessPoolExecutor` without pickling
    :class:`CausalSpec` callables.

    The treatment column is divided by ``normalization_scale`` before DoWhy
    fits the model, so ``beta`` and the placebo effects are per normalised
    unit of treatment: the unit :func:`_marginal_risk` divides back out and
    :data:`CAUSAL_LOCK_PLACEBO_EFFECT_MAGNITUDE` is expressed in. Callers pass
    their spec's ``normalization_scale``.

    Raises ``ValueError`` for a non-finite or non-positive
    ``normalization_scale``.
    """
    if not _is_positive_finite(normalization_scale):
        raise ValueError("normalization_scale must be a finite number > 0")

    if not _DOWHY_AVAILABLE:
        logger.warning(
            "validate_world_model: 'dowhy' is not installed — failing closed."
        )
        return WorldModelVerdict(False, None, REASON_DOWHY_UNAVAILABLE)

    causal_graph = graph_dot
    treatment = treatment_col
    outcome = outcome_col

    registry = ControlRegistry()
    mrm_meta = registry.get_mapping(GovernanceControl.TRADITIONAL_MRM_VALIDATION)
    tel_meta = registry.get_mapping(GovernanceControl.TELEMETRY_LIVE_VALIDATION)
    active_region = registry.active_region

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

    # --------------------------------------------------------------
    # Phase 1: Statistical Kernel (CTRL_MRM_004 scope)
    # --------------------------------------------------------------
    with tracer.start_as_current_span(
        "causal_gatekeeper.statistical_kernel"
    ) as mrm_span:
        mrm_span.set_attribute("governance.control_id", mrm_meta["internal_id"])
        mrm_span.set_attribute("governance.framework", mrm_meta["primary_framework"])
        mrm_span.set_attribute("governance.legacy_citation", mrm_legacy)
        mrm_span.set_attribute("governance.scope", mrm_meta["scope"])
        mrm_span.set_attribute("governance.deployment_region", active_region)
        mrm_span.set_attribute("causal.graph", causal_graph.strip())
        mrm_span.set_attribute("causal.normalization_scale", float(normalization_scale))

        min_samples = get_causal_min_samples()
        n_samples = len(telemetry)
        if n_samples < min_samples:
            mrm_span.set_attribute("causal.samples_available", n_samples)
            mrm_span.set_attribute("causal.min_samples_required", min_samples)
            mrm_span.set_attribute("causal.result", "insufficient_data_fail_closed")
            logger.warning(
                "CausalGatekeeper: insufficient telemetry (%d < %d samples) — "
                "failing closed (action BLOCKED).",
                n_samples,
                min_samples,
            )
            return WorldModelVerdict(False, None, REASON_INSUFFICIENT_SAMPLES)

        # beta is estimated per normalised unit of treatment.
        frame = telemetry.copy()
        frame[treatment] = frame[treatment] / normalization_scale

        model = _CausalModel(
            data=frame,
            treatment=treatment,
            outcome=outcome,
            graph=causal_graph,
        )
        identified_estimand = model.identify_effect(proceed_when_unidentifiable=True)

        # Numerical trust: refuse, before fitting, a regression whose
        # coefficients rounding alone could move by more than
        # _LSQ_ERROR_BOUND_MAX. Its slope would depend on the platform.
        error_bound = _least_squares_error_bound(
            frame,
            treatment,
            outcome,
            identified_estimand.get_backdoor_variables() or [],
        )
        if not error_bound <= _LSQ_ERROR_BOUND_MAX:
            logger.warning(
                "[%s] CAUSAL LOCK: the regression's rounding-error bound %.3g "
                "exceeds %.0e (rank-deficient or ill-conditioned design) — "
                "untrustworthy world-model.",
                GovernanceControl.TRADITIONAL_MRM_VALIDATION.value,
                error_bound,
                _LSQ_ERROR_BOUND_MAX,
            )
            mrm_span.set_attribute("causal.lock_reason", REASON_DESIGN_ILL_CONDITIONED)
            if math.isfinite(error_bound):
                mrm_span.set_attribute("causal.lsq_error_bound", error_bound)
            return WorldModelVerdict(False, None, REASON_DESIGN_ILL_CONDITIONED)
        mrm_span.set_attribute("causal.lsq_error_bound", error_bound)

        estimate = model.estimate_effect(
            identified_estimand, method_name="backdoor.linear_regression"
        )
        beta = float(estimate.value)
        mrm_span.set_attribute("causal.estimated_effect", beta)

        # beta <= 0 (or non-finite) fail-closed guard
        if not _is_positive_finite(beta):
            reason = (
                "negative_or_zero_causal_slope"
                if math.isfinite(beta)
                else "non_finite_causal_slope"
            )
            logger.warning(
                "[%s] CAUSAL LOCK: Estimated causal effect beta=%.4f is not a "
                "finite positive slope — untrustworthy world-model.",
                GovernanceControl.TRADITIONAL_MRM_VALIDATION.value,
                beta,
            )
            mrm_span.set_attribute("causal.lock_reason", reason)
            mrm_span.set_attribute("causal.estimated_effect_blocked", beta)
            return WorldModelVerdict(False, beta, reason)

    # --------------------------------------------------------------
    # Phase 2: Operational Simulation (CTRL_TEL_003 / ISO 42001 §A.9.4)
    # --------------------------------------------------------------
    with tracer.start_as_current_span(
        "causal_gatekeeper.placebo_refutation"
    ) as tel_span:
        tel_span.set_attribute("governance.control_id", tel_meta["internal_id"])
        tel_span.set_attribute("governance.framework", tel_meta["primary_framework"])
        tel_span.set_attribute("governance.legacy_citation", tel_legacy)
        tel_span.set_attribute("governance.scope", tel_meta["scope"])
        tel_span.set_attribute("governance.deployment_region", active_region)
        tel_span.set_attribute("causal.num_simulations", PLACEBO_NUM_SIMULATIONS)
        tel_span.set_attribute("causal.placebo_type", PLACEBO_TYPE)

        if not _check_telemetry_freshness(telemetry, tel_span):
            tel_span.set_attribute("causal.lock_reason", "stale_telemetry")
            return WorldModelVerdict(False, beta, "stale_telemetry")

        placebo = _placebo_refutation(frame, identified_estimand, estimate)
        spread = (
            float(np.ptp(np.asarray(placebo.effects, dtype=float)))
            if placebo.effects
            else math.nan
        )
        if placebo.p_value is not None:
            tel_span.set_attribute("causal.placebo_p_value", placebo.p_value)
        if placebo.new_effect is not None:
            tel_span.set_attribute("causal.placebo_new_effect", placebo.new_effect)
        tel_span.set_attribute("causal.placebo_effect_spread", spread)

        lock_reason = _placebo_lock_reason(placebo, beta)
        if lock_reason is not None:
            logger.warning(
                "[%s] CAUSAL LOCK: placebo refutation failed (%s; p_value=%s, "
                "new_effect=%s, spread=%s) — world-model untrustworthy.",
                GovernanceControl.TELEMETRY_LIVE_VALIDATION.value,
                lock_reason,
                placebo.p_value,
                placebo.new_effect,
                spread,
            )
            tel_span.set_attribute("causal.lock_reason", lock_reason)
            if lock_reason == REASON_PLACEBO_P_VALUE:
                tel_span.set_attribute(
                    "causal.lock_p_value_threshold", CAUSAL_LOCK_P_VALUE_THRESHOLD
                )
            elif lock_reason == REASON_PLACEBO_EFFECT_MAGNITUDE:
                tel_span.set_attribute(
                    "causal.lock_effect_magnitude_threshold",
                    CAUSAL_LOCK_PLACEBO_EFFECT_MAGNITUDE,
                )
            return WorldModelVerdict(False, beta, lock_reason)

    return WorldModelVerdict(True, beta, REASON_TRUSTED)


def causal_safety_check(
    params: dict[str, Any],
    current_telemetry: pd.DataFrame | None = None,
    *,
    action: str | None = None,
) -> bool:
    """Thin compatibility wrapper delegating to a :class:`CausalGatekeeper` built from ``_causal_config()``."""
    try:
        causal_config = _causal_config()
    except Exception as exc:
        logger.warning(
            "causal_safety_check: causal config unavailable (%s) — failing closed",
            exc,
        )
        return False
    spec = _spec_from_config(causal_config)
    if spec is None:
        logger.warning(
            "causal_safety_check: active domain has no valid causal graph — failing closed"
        )
        return False
    return CausalGatekeeper(spec).causal_safety_check(
        params, current_telemetry, action=action
    )
