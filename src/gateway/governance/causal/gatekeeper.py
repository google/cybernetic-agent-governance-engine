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
    - If causal slope beta <= 0, the gate triggers a fail-closed lock.
    - If beta > 0, marginal risk is computed as
      min(1.0, max(0.0, 0.5 + beta * treatment_value / normalization_scale)).
    - If risk exceeds CAUSAL_LOCK_RISK_BOUNDARY (0.95), the action is blocked.

If a Placebo Refuter detects a spurious effect (p < 0.05 or large placebo
effect), the gatekeeper "locks" the cage — the action is blocked because
the underlying causal assumptions cannot be trusted.

Caching:
    Only the params-independent :class:`WorldModelVerdict` (trusted, beta,
    reason) is cached in Redis, and only for synthetic-factory telemetry. The
    marginal risk boundary depends on the request's treatment value and is
    evaluated on every call; it is never cached.
"""

import functools
import hashlib
import json
import logging
import math
import os
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

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
#   of the p-value.
CAUSAL_LOCK_PLACEBO_EFFECT_MAGNITUDE: float = get_causal_placebo_effect_magnitude()

# CAUSAL_LOCK_RISK_BOUNDARY (Phase 1 — marginal risk boundary):
#   If (0.5 + estimated_marginal_effect) exceeds this threshold, the proposed
#   action is predicted to push the system's outcome metric above the safety
#   boundary.
CAUSAL_LOCK_RISK_BOUNDARY: float = get_causal_risk_boundary()

# CAUSAL_NORMALIZATION_SCALE:
#   Default normalization factor for converting raw treatment magnitudes to the
#   [0, 1] scale when not overridden on CausalSpec.
CAUSAL_NORMALIZATION_SCALE: float = float(
    os.environ.get("CAUSAL_NORMALIZATION_SCALE", "10000.0")
)

CAUSAL_GATEKEEPER_STRICT_MODE: bool = (
    os.environ.get("CAUSAL_GATEKEEPER_STRICT_MODE", "false").lower() == "true"
)

_NO_LEGAL_FORCE_MARKER = "no legal force"

_TIMESTAMP_CANDIDATES = ("timestamp", "ts", "event_time", "time", "created_at")


# ---------------------------------------------------------------------------
# Internal helpers — telemetry freshness
# ---------------------------------------------------------------------------


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

        try:
            raw_ts = telemetry[ts_col].max()
            if isinstance(raw_ts, (int, float)):
                if raw_ts > 1e12:
                    raw_ts = raw_ts / 1000.0
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

    Covers the graph, treatment/outcome columns, and the synthetic telemetry
    factory (the only telemetry source whose verdicts are cached), so two
    domains or specs never share a cache entry. ``normalization_scale`` and the
    extractors are deliberately excluded: they only affect the per-request risk
    boundary, which is never cached.
    """
    factory = spec.synthetic_telemetry_factory
    factory_id = (
        ""
        if factory is None
        else f"{getattr(factory, '__module__', '')}."
        f"{getattr(factory, '__qualname__', type(factory).__qualname__)}"
    )
    material = json.dumps(
        [spec.graph_dot, spec.treatment_col, spec.outcome_col, factory_id]
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
    ) -> bool:
        """Boolean form of :meth:`evaluate` (``evaluate(...).safe``)."""
        return self.evaluate(params, current_telemetry, action=action).safe

    def evaluate(
        self,
        params: dict[str, Any],
        current_telemetry: pd.DataFrame | None = None,
        *,
        action: str | None = None,
    ) -> CausalDecision:
        """Validate causal world-model integrity and the marginal risk boundary.

        Args:
            params: Action parameters; the treatment value and context are
                read via the spec's extractors.
            current_telemetry: Live telemetry to validate the world-model
                against. ``None`` **or an empty frame** means "no live
                telemetry": in enforcing postures that fails closed with
                :data:`REASON_NO_LIVE_TELEMETRY`; in non-enforcing postures the
                spec's synthetic telemetry factory stands in and the verdict
                may be cached. A non-empty frame is always validated as given
                (never replaced by synthetic data), so a frame with fewer than
                ``min_samples`` rows yields ``insufficient_samples``.
            action: Action name used to namespace the world-model cache entry.
                Falls back to ``params["action_type"]`` / ``params["action"]``.

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
            verdict = self._resolve_world_model(params, current_telemetry, action)
            if not verdict.trusted:
                return CausalDecision(False, verdict.reason)
            if not self._within_risk_boundary(verdict.beta, treatment_value):
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
        causal_graph = self.spec.graph_dot
        treatment = self.spec.treatment_col
        outcome = self.spec.outcome_col

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
            mrm_span.set_attribute(
                "governance.framework", mrm_meta["primary_framework"]
            )
            mrm_span.set_attribute("governance.legacy_citation", mrm_legacy)
            mrm_span.set_attribute("governance.scope", mrm_meta["scope"])
            mrm_span.set_attribute("governance.deployment_region", active_region)
            mrm_span.set_attribute("causal.graph", causal_graph.strip())

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

            model = _CausalModel(
                data=telemetry,
                treatment=treatment,
                outcome=outcome,
                graph=causal_graph,
            )
            identified_estimand = model.identify_effect(
                proceed_when_unidentifiable=True
            )
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
            tel_span.set_attribute(
                "governance.framework", tel_meta["primary_framework"]
            )
            tel_span.set_attribute("governance.legacy_citation", tel_legacy)
            tel_span.set_attribute("governance.scope", tel_meta["scope"])
            tel_span.set_attribute("governance.deployment_region", active_region)
            tel_span.set_attribute("causal.num_simulations", 50)

            if not _check_telemetry_freshness(telemetry, tel_span):
                tel_span.set_attribute("causal.lock_reason", "stale_telemetry")
                return WorldModelVerdict(False, beta, "stale_telemetry")

            refuter = model.refute_estimate(
                identified_estimand,
                estimate,
                method_name="placebo_treatment_refuter",
                num_simulations=50,
            )

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
                return WorldModelVerdict(False, beta, "p_value_threshold")

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
                return WorldModelVerdict(False, beta, "placebo_effect_magnitude")

        return WorldModelVerdict(True, beta, REASON_TRUSTED)

    # ------------------------------------------------------------------
    # Marginal risk boundary (per request, never cached)
    # ------------------------------------------------------------------

    def _within_risk_boundary(self, beta: float | None, treatment_value: float) -> bool:
        """Return whether this request's predicted risk stays within the boundary."""
        if beta is None or not _is_positive_finite(beta):
            return False
        norm_scale = (
            self.spec.normalization_scale
            if self.spec.normalization_scale > 0
            else CAUSAL_NORMALIZATION_SCALE
        )
        estimated_risk = min(1.0, max(0.0, 0.5 + beta * treatment_value / norm_scale))
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
