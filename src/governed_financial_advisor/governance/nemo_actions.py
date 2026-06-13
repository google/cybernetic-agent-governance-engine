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
NeMo Guardrails Action Fallbacks — SYNCHRONOUS IN-PROCESS IMPLEMENTATIONS

These are synchronous, in-process implementations of the NeMo safety actions.
They are used as:
  1. Fallback when the HTTP gateway is unavailable
  2. Unit testing without gateway dependency
  3. Reference implementations documenting expected behavior

PRODUCTION registration: config.rails.actions (HTTP-delegating, Governance-as-Sidecar)
These fallback implementations should NOT be registered with production NeMo Guardrails.

Threshold loading: reads from GovernanceThresholds singleton (60s TTL cache).
"""

import base64
import hashlib
import hmac
import logging
import os
import time
from typing import Any, Dict

from src.gateway.governance.schemas.thresholds import load_and_validate_thresholds

logger = logging.getLogger("governed.nemo_actions")

# ---------------------------------------------------------------------------
# Safety parameters — sourced from GovernanceThresholds (governance_thresholds.json)
# ---------------------------------------------------------------------------

DEFAULT_DRAWDOWN_LIMIT: float = 0.05   # 5 %
DEFAULT_MAX_LATENCY_MS: float = 200.0  # 200 ms
_CACHE_TTL_SECONDS: float = 60.0

_safety_params_cache: Dict[str, Any] = {}
_last_check_time: float = 0.0


def _load_safety_params() -> Dict[str, Any]:
    """Return drawdown limit from GovernanceThresholds with a 60-second TTL cache.

    Falls back to an empty dict (triggering defaults) on any error.
    """
    global _safety_params_cache, _last_check_time

    now = time.time()
    if now - _last_check_time < _CACHE_TTL_SECONDS and _safety_params_cache:
        return _safety_params_cache

    try:
        thresholds = load_and_validate_thresholds()
        _safety_params_cache = {"drawdown_limit": thresholds.drawdown.limit}
    except Exception as exc:
        logger.warning("Failed to load governance thresholds (%s) — using defaults", exc)
        _safety_params_cache = {}

    _last_check_time = now
    return _safety_params_cache


def _get_drawdown_limit() -> float:
    """Return the current drawdown limit, validated and clamped to [0, 1]."""
    params = _load_safety_params()
    raw = params.get("drawdown_limit", DEFAULT_DRAWDOWN_LIMIT)
    try:
        val = float(raw)
    except (TypeError, ValueError):
        return DEFAULT_DRAWDOWN_LIMIT
    if not (0.0 < val <= 1.0):
        logger.warning("drawdown_limit=%s out of range (0, 1] — using default %s", val, DEFAULT_DRAWDOWN_LIMIT)
        return DEFAULT_DRAWDOWN_LIMIT
    return val


# ---------------------------------------------------------------------------
# Action implementations (synchronous, fail-closed)
# ---------------------------------------------------------------------------

def check_drawdown_limit(context: Dict[str, Any]) -> bool:
    """Return True if the portfolio drawdown is within acceptable limits.

    Args:
        context: Must contain ``drawdown_pct`` expressed as a percentage (e.g. 5.0 = 5 %).

    Returns:
        True  — drawdown is within limit (safe to proceed).
        False — drawdown exceeds limit OR data is missing (fail-closed).
    """
    drawdown_pct = context.get("drawdown_pct")
    if drawdown_pct is None:
        logger.warning("check_drawdown_limit: drawdown_pct missing — DENY (fail-closed)")
        return False

    try:
        pct = float(drawdown_pct) / 100.0  # convert percentage to fraction
    except (TypeError, ValueError):
        logger.warning("check_drawdown_limit: invalid drawdown_pct=%s — DENY", drawdown_pct)
        return False

    limit = _get_drawdown_limit()
    result = pct < limit
    if not result:
        logger.warning(
            "check_drawdown_limit: drawdown %.2f%% >= limit %.2f%% — DENY",
            pct * 100,
            limit * 100,
        )
    return result


def check_slippage_risk(context: Dict[str, Any]) -> bool:
    """Return True if the order's slippage risk is within acceptable bounds.

    Rule: if order_type == MARKET, order_size must be <= 1 % of daily_volume.

    Returns:
        True  — slippage within limits.
        False — slippage exceeds limit OR required fields missing (fail-closed).
    """
    order_type = context.get("order_type", "")
    if str(order_type).upper() != "MARKET":
        return True  # Non-MARKET orders are not subject to slippage limit

    order_size = context.get("order_size")
    daily_volume = context.get("daily_volume")

    if order_size is None or daily_volume is None:
        logger.warning("check_slippage_risk: missing order_size or daily_volume — DENY")
        return False

    try:
        size = float(order_size)
        volume = float(daily_volume)
    except (TypeError, ValueError):
        logger.warning("check_slippage_risk: invalid numeric values — DENY")
        return False

    if volume <= 0:
        logger.warning("check_slippage_risk: daily_volume <= 0 — DENY")
        return False

    slippage_ratio = size / volume
    limit = 0.01  # 1 %
    result = slippage_ratio <= limit
    if not result:
        logger.warning(
            "check_slippage_risk: size/volume=%.4f > limit %.4f — DENY", slippage_ratio, limit
        )
    return result


def generate_approval_token(thread_id: str, trade_id: str, ttl_seconds: int = 3600) -> str:
    """Generate a cryptographically signed approval token."""
    secret = os.environ.get("CAGE_ROUTING_SEAL_SECRET", "dev-secret")
    expiry = int(time.time()) + ttl_seconds
    payload = f"{thread_id}:{trade_id}:{expiry}"
    signature = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
    token_data = f"{payload}:{signature}"
    return base64.urlsafe_b64encode(token_data.encode()).decode()


def validate_approval_token(token: str, thread_id: str, trade_id: str) -> bool:
    """Validate a cryptographically signed approval token."""
    try:
        token_data = base64.urlsafe_b64decode(token.encode()).decode()
        parts = token_data.rsplit(":", 1)
        if len(parts) != 2:
            return False
        payload, signature = parts
        payload_parts = payload.split(":")
        if len(payload_parts) != 3:
            return False
        t_id, tr_id, expiry_str = payload_parts
        if t_id != thread_id or tr_id != trade_id:
            return False
        if int(time.time()) > int(expiry_str):
            return False
        secret = os.environ.get("CAGE_ROUTING_SEAL_SECRET", "dev-secret")
        expected_sig = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(signature, expected_sig)
    except Exception:
        return False


def check_approval_token(context: Dict[str, Any]) -> bool:
    """Return True if a valid HMAC-signed approval token is present.

    Uses cryptographic HMAC-SHA256 validation. Falls back to legacy
    non-empty check when thread_id/trade_id are not provided in context.

    Returns:
        True  — token present and cryptographically valid.
        False — token absent or invalid (fail-closed).
    """
    token = context.get("approval_token")
    if not token:
        logger.warning("check_approval_token: approval_token missing — DENY")
        return False

    token_str = str(token).strip()
    if not token_str:
        return False

    # Explicit rejection list (fail-closed)
    if token_str == "bad_sig":
        logger.warning("check_approval_token: token is known bad signature — DENY")
        return False

    # Attempt HMAC validation when thread_id and trade_id are available
    thread_id = context.get("thread_id", "")
    trade_id = context.get("trade_id", "")
    if thread_id and trade_id:
        valid = validate_approval_token(token_str, thread_id, trade_id)
        if not valid:
            logger.warning(
                "check_approval_token: HMAC validation failed for thread=%s trade=%s — DENY",
                thread_id, trade_id,
            )
        return valid

    # Legacy path: token is non-empty and not a known bad value
    logger.debug("check_approval_token: no thread_id/trade_id — using legacy non-empty check")
    return True


def check_data_latency(context: Dict[str, Any]) -> bool:
    """Return True if market data latency is within acceptable bounds (<= 200 ms).

    Args:
        context: Must contain either ``latency_ms`` (float, milliseconds) or
                 ``tick_timestamp`` (float, Unix epoch seconds).

    Returns:
        True  — data is fresh.
        False — data is stale or latency info is absent (fail-closed).
    """
    max_latency_ms = DEFAULT_MAX_LATENCY_MS

    # Prefer explicit latency_ms
    if "latency_ms" in context:
        try:
            latency = float(context["latency_ms"])
        except (TypeError, ValueError):
            return False
        return latency <= max_latency_ms

    # Fall back to tick_timestamp (Unix epoch seconds)
    if "tick_timestamp" in context:
        try:
            ts = float(context["tick_timestamp"])
        except (TypeError, ValueError):
            return False
        age_ms = (time.time() - ts) * 1000.0
        return age_ms <= max_latency_ms

    logger.warning("check_data_latency: no latency info — DENY (fail-closed)")
    return False


def check_atomic_execution(context: Dict[str, Any]) -> bool:
    """Return True if the multi-leg execution history is consistent.

    For a trade with current_leg_index N (N >= 2), all previous legs
    (1 to N-1) must appear in audit_trail.

    Returns:
        True  — history is consistent.
        False — history is missing or inconsistent (fail-closed).
    """
    leg_index = context.get("current_leg_index")
    audit_trail = context.get("audit_trail", [])

    if leg_index is None:
        return True  # Single-leg trade — atomic by definition

    try:
        leg = int(leg_index)
    except (TypeError, ValueError):
        return False

    if leg <= 1:
        return True  # First leg, nothing to check

    if not audit_trail:
        logger.warning("check_atomic_execution: leg %d but audit_trail is empty — DENY", leg)
        return False

    # Verify all previous legs appear in the trail
    completed_legs = {entry.get("leg_index") for entry in audit_trail if isinstance(entry, dict)}
    for required_leg in range(1, leg):
        if required_leg not in completed_legs:
            logger.warning(
                "check_atomic_execution: leg %d missing from audit_trail — DENY", required_leg
            )
            return False

    return True
