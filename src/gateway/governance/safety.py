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
Control Barrier Function (CBF) safety layer.

Phase 1 fix: imports now resolve against the canonical gateway-internal
infrastructure package (``src.gateway.infrastructure.*``) instead of the
cross-package ``src.governed_financial_advisor.*`` path.

Phase 4.1 fix: ``update_state()`` and ``rollback_state()`` use Redis
WATCH / MULTI / EXEC optimistic locking to prevent race conditions under
concurrent trade execution in the stateless Cloud Run environment.
"""

import logging
import time
from typing import Any, Optional

# ---------------------------------------------------------------------------
# Canonical gateway-internal imports (Phase 1.1)
# ---------------------------------------------------------------------------
from src.gateway.infrastructure.redis_client import redis_client
from src.gateway.infrastructure.telemetry import get_tracer
from src.gateway.governance.constants import GovernanceControl, ControlRegistry

# ---------------------------------------------------------------------------
# Threshold singleton (Phase 2.3)
# ---------------------------------------------------------------------------
from src.gateway.governance.schemas.thresholds import THRESHOLDS

logger = logging.getLogger("SafetyLayer")

# ---------------------------------------------------------------------------
# Aho-Corasick Tier-1 Keyword Scanner
# ---------------------------------------------------------------------------

try:
    import ahocorasick as _ahocorasick
    _AC_AVAILABLE = True
except ImportError:
    _ahocorasick = None  # type: ignore[assignment]
    _AC_AVAILABLE = False
    logger.warning(
        "⚠️ pyahocorasick not installed — Tier-1 keyword scan falling back to O(n×m) any() loop. "
        "Install with: pip install pyahocorasick"
    )

# Keyword list is sourced entirely from the validated threshold singleton.
# No inline literals — all values live in config/governance_thresholds.json.
_AC_AUTOMATON: Optional[Any] = None
_AC_BUILT: bool = False


def _load_tier1_keywords() -> list[str]:
    """Return the Tier-1 keyword list from the governance threshold singleton."""
    return list(THRESHOLDS.tier1_keywords)  # already upper-cased by Pydantic validator


def _build_automaton() -> Optional[Any]:
    """Build and return a pyahocorasick Automaton from the Tier-1 keyword list."""
    if not _AC_AVAILABLE:
        return None
    keywords = _load_tier1_keywords()
    A = _ahocorasick.Automaton()
    for idx, kw in enumerate(keywords):
        A.add_word(kw.upper(), (idx, kw))
    A.make_automaton()
    logger.info("✅ Aho-Corasick automaton built with %d Tier-1 keywords.", len(keywords))
    return A


def ac_keyword_scan(text: str) -> bool:
    """O(n) Tier-1 keyword scan using a lazy-initialised Aho-Corasick automaton.

    Falls back to O(n×m) ``any()`` loop when *pyahocorasick* is not installed.

    Args:
        text: The raw input string to scan.

    Returns:
        ``True`` if any forbidden keyword is found, ``False`` otherwise.
    """
    global _AC_AUTOMATON, _AC_BUILT

    upper_text = text.upper()

    if _AC_AVAILABLE:
        if not _AC_BUILT:
            _AC_AUTOMATON = _build_automaton()
            _AC_BUILT = True
        if _AC_AUTOMATON is not None:
            for _end_index, (_idx, _kw) in _AC_AUTOMATON.iter(upper_text):
                return True
            return False

    keywords = _load_tier1_keywords()
    return any(kw.upper() in upper_text for kw in keywords)


# ---------------------------------------------------------------------------
# ControlBarrierFunction
# ---------------------------------------------------------------------------

class ControlBarrierFunction:
    """Discrete-time Control Barrier Function (CBF).

    Uses Redis for state persistence so that stateless Cloud Run instances
    share a consistent cash-balance view.

    Phase 4.1: ``update_state()`` and ``rollback_state()`` wrap all
    read-modify-write operations in a Redis WATCH / MULTI / EXEC optimistic-
    locking pipeline.  If another process mutates the key between the WATCH
    and the EXEC, the transaction is aborted and retried up to
    ``_MAX_RETRIES`` times before raising ``RuntimeError``.
    """

    _MAX_RETRIES: int = 5

    def __init__(self):
        # Thresholds from singleton — no inline literals.
        self.min_cash_balance: float = THRESHOLDS.cbf.min_cash_balance
        self.gamma: float = THRESHOLDS.cbf.gamma
        self.redis_key: str = "safety:current_cash"
        self.tracer = get_tracer("src.gateway.governance.safety")

    async def setup(self) -> None:
        """Bootstrap Redis state if the key is absent (first run)."""
        if redis_client is None:
            logger.error("Redis client unavailable — cannot bootstrap CBF state.")
            return
        if await redis_client.get(self.redis_key) is None:
            await redis_client.set(self.redis_key, "100000.0")

    async def _get_current_cash(self) -> float:
        if redis_client is None:
            raise RuntimeError("Redis client unavailable.")
        return await redis_client.get_float(self.redis_key, 100000.0)

    def get_h(self, cash_balance: float) -> float:
        """Safety function h(x).  Safe when h(x) >= 0."""
        return cash_balance - self.min_cash_balance

    # ------------------------------------------------------------------
    # verify_action
    # ------------------------------------------------------------------

    async def verify_action(self, action_name: str, payload: dict[str, Any]) -> str:
        """Verify an action is safe relative to shared Redis cash state."""
        current_cash = await self._get_current_cash()

        if self.tracer:
            with self.tracer.start_as_current_span("safety.cbf_check") as span:
                return await self._do_verify_action(action_name, payload, current_cash, span)
        else:
            return await self._do_verify_action(action_name, payload, current_cash, None)

    async def _do_verify_action(
        self,
        action_name: str,
        payload: dict[str, Any],
        current_cash: float,
        span: Any,
    ) -> str:
        if span:
            span.set_attribute("safety.cash.current", current_cash)
            # CTRL_MRM_004: CBF is a traditional, deterministic quantitative formula
            # (h(x) = cash_balance - min_cash_balance with static decay γ).
            # It falls under SR 26-2 Model Risk Management scope, not agentic ISO 42001.
            _mrm_meta = ControlRegistry().get_mapping(GovernanceControl.TRADITIONAL_MRM_VALIDATION)
            span.set_attribute("governance.control_id",     _mrm_meta["internal_id"])
            span.set_attribute("governance.framework",      _mrm_meta["primary_framework"])
            span.set_attribute("governance.legacy_citation", _mrm_meta["legacy_citation"])
            span.set_attribute("governance.scope",          _mrm_meta["scope"])

        cost = 0.0
        if action_name == "execute_trade":
            cost = float(payload.get("amount", 0.0))

        next_cash = current_cash - cost
        h_t = self.get_h(current_cash)
        h_next = self.get_h(next_cash)
        required_h_next = (1.0 - self.gamma) * h_t

        logger.info("🛡️ CBF Check | Cash: %.2f → %.2f", current_cash, next_cash)

        result = "SAFE"
        if h_next < required_h_next or h_next < 0:
            _mrm_meta = ControlRegistry().get_mapping(GovernanceControl.TRADITIONAL_MRM_VALIDATION)
            result = (
                f"[{GovernanceControl.TRADITIONAL_MRM_VALIDATION.value}] "
                f"{_mrm_meta['primary_framework']} Violation: "
                f"Safety Violation (RBC/CBF). "
                f"h(next)={h_next:.2f} < threshold={required_h_next:.2f}"
            )
            if h_next < 0 and span:
                span.set_attribute("safety.bankruptcy", True)
                span.set_attribute("safety.bankruptcy_deficit", abs(h_next))

        # Drawdown check — read limit from threshold singleton
        if "drawdown_pct" in payload:
            limit = THRESHOLDS.drawdown.limit
            raw_drawdown = float(payload.get("drawdown_pct", 0.0))
            current_drawdown = raw_drawdown / 100.0
            if current_drawdown > limit:
                msg = (
                    f"UNSAFE: Drawdown Violation. {current_drawdown:.2%} > Limit {limit:.2%}"
                )
                logger.warning("⛔ %s", msg)
                result = msg if result == "SAFE" else f"{result}; {msg}"

        if span:
            span.set_attribute("safety.cash.next", next_cash)
            span.set_attribute("safety.barrier.h_next", h_next)
            span.set_attribute("safety.result", result)

        return result

    # ------------------------------------------------------------------
    # update_state — WATCH/MULTI/EXEC atomic transaction (Phase 4.1)
    # ------------------------------------------------------------------

    async def update_state(self, cost: float) -> None:
        """Atomically deduct *cost* from the Redis cash balance.

        Uses WATCH / MULTI / EXEC optimistic locking.  Retries up to
        ``_MAX_RETRIES`` times if a concurrent writer modified the key.

        Raises:
            RuntimeError: If all retries are exhausted or Redis is unavailable.
        """
        if redis_client is None:
            raise RuntimeError("Redis client unavailable — cannot update CBF state.")

        for attempt in range(self._MAX_RETRIES):
            try:
                async with redis_client.pipeline() as pipe:
                    await pipe.watch(self.redis_key)
                    raw = await pipe.get(self.redis_key)
                    current = float(raw) if raw is not None else 100000.0
                    new_balance = current - cost
                    pipe.multi()
                    pipe.set(self.redis_key, str(new_balance))
                    await pipe.execute()
                    logger.info(
                        "✅ CBF state updated atomically: %.2f → %.2f (attempt %d)",
                        current, new_balance, attempt + 1,
                    )
                    return
            except Exception as exc:
                # WatchError or transient failure — retry
                if "WatchError" in type(exc).__name__:
                    logger.warning(
                        "⚡ CBF WATCH conflict on attempt %d/%d — retrying.",
                        attempt + 1, self._MAX_RETRIES,
                    )
                    continue
                raise

        raise RuntimeError(
            f"CBF update_state failed after {self._MAX_RETRIES} retries due to concurrent writes."
        )

    # ------------------------------------------------------------------
    # rollback_state — WATCH/MULTI/EXEC atomic transaction (Phase 4.1)
    # ------------------------------------------------------------------

    async def rollback_state(self, cost: float) -> None:
        """Atomically restore *cost* to the Redis cash balance.

        Mirrors ``update_state`` but adds rather than deducts.  Call this
        when a trade was approved by the CBF but failed downstream (e.g.
        broker API error).

        Raises:
            RuntimeError: If all retries are exhausted or Redis is unavailable.
        """
        if redis_client is None:
            raise RuntimeError("Redis client unavailable — cannot rollback CBF state.")

        for attempt in range(self._MAX_RETRIES):
            try:
                async with redis_client.pipeline() as pipe:
                    await pipe.watch(self.redis_key)
                    raw = await pipe.get(self.redis_key)
                    current = float(raw) if raw is not None else 100000.0
                    restored = current + cost
                    pipe.multi()
                    pipe.set(self.redis_key, str(restored))
                    await pipe.execute()
                    logger.info(
                        "🔄 CBF state rolled back atomically: %.2f → %.2f (attempt %d)",
                        current, restored, attempt + 1,
                    )
                    return
            except Exception as exc:
                if "WatchError" in type(exc).__name__:
                    logger.warning(
                        "⚡ CBF WATCH conflict on rollback attempt %d/%d — retrying.",
                        attempt + 1, self._MAX_RETRIES,
                    )
                    continue
                raise

        raise RuntimeError(
            f"CBF rollback_state failed after {self._MAX_RETRIES} retries due to concurrent writes."
        )


# Global singleton
safety_filter = ControlBarrierFunction()
