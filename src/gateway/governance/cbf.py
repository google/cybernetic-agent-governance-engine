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

# ---------------------------------------------------------------------------
# Formal State-Transition Safety Model — Discrete-Time CBF
# ---------------------------------------------------------------------------
# CAGE enforces financial state transitions using a discrete-time Control
# Barrier Function (CBF), ensuring the admissibility envelope E is never
# violated at the storage layer.
#
# State-transition model:
#   S(t+1) = f(S(t), I(t), R, E)   subject to   f(S(t), I(t), R) ∈ E
#
# Where:
#   S(t)  = current system state = {cash_balance: float}
#   I(t)  = agent input = {action: str, amount: float, ...}
#   R     = compiled domain rules (OPA Rego ASTs, NeMo Colang rails, STPA UCAs)
#   E     = admissibility envelope = {s ∈ S : h(s) >= 0}
#
# Safety function (barrier certificate):
#   h(S(t)) = cash_balance(t) - min_cash_balance   [h >= 0 iff state is safe]
#
# Discrete-time CBF condition (Ames et al., IEEE TAC 2017):
#   h(S(t+1)) >= (1 - γ) · h(S(t))   for all t, where γ ∈ (0,1)
#
# Enforcement layers:
#   verify_action():            Evaluates h(S(t+1)) >= (1-γ)·h(S(t)) — read-only
#   update_state():             Commits S(t) → S(t+1) — WATCH/MULTI/EXEC
#   atomic_verify_and_commit(): Evaluates AND commits atomically via Lua,
#                               eliminating the TOCTOU window between phases.
# ---------------------------------------------------------------------------

"""
Stateful Redis-backed financial invariant enforcer.

Implements a discrete-time Control Barrier Function (CBF) that uses Redis
for state persistence so that stateless Cloud Run instances share a
consistent cash-balance view.

Phase 1 fix: imports now resolve against the canonical gateway-internal
infrastructure package (``src.gateway.infrastructure.*``) instead of the
cross-package ``src.governed_financial_advisor.*`` path.

Phase 4.1 fix: ``update_state()`` and ``rollback_state()`` use Redis
WATCH / MULTI / EXEC optimistic locking to prevent race conditions under
concurrent trade execution in the stateless Cloud Run environment.
"""

import json
import logging
import time
from typing import Any

from src.gateway.governance.constants import ControlRegistry, GovernanceControl

# ---------------------------------------------------------------------------
# Threshold singleton (Phase 2.3)
# ---------------------------------------------------------------------------
from src.gateway.governance.schemas.thresholds import THRESHOLDS

# ---------------------------------------------------------------------------
# Canonical gateway-internal imports (Phase 1.1)
# ---------------------------------------------------------------------------
from src.gateway.infrastructure.redis_client import redis_client
from src.gateway.infrastructure.telemetry import get_tracer

logger = logging.getLogger("SafetyLayer")


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

    LUA_ATOMIC_CBF: str = """
-- KEYS[1]: safety:current_cash
-- KEYS[2]: audit:state_ledger
-- ARGV[1]: cost (float string)
-- ARGV[2]: min_cash_balance (float string)
-- ARGV[3]: gamma (float string)
-- ARGV[4]: governance_signature (string, may be empty)
-- Returns: array {status_code, message, new_balance_str}
--   status_code 1 = COMMITTED, 0 = UNSAFE (envelope violation)
local raw = redis.call('GET', KEYS[1])
local current = raw and tonumber(raw) or 100000.0
local cost = tonumber(ARGV[1]) or 0.0
local min_cash = tonumber(ARGV[2])
local gamma = tonumber(ARGV[3])
local sig = ARGV[4]

local next_cash = current - cost
local h_t = current - min_cash
local h_next = next_cash - min_cash
local required_h_next = (1.0 - gamma) * h_t

if h_next < required_h_next or h_next < 0 then
    return {0, "UNSAFE: h_next=" .. tostring(h_next) .. " < required=" .. tostring(required_h_next), tostring(current)}
end

redis.call('SET', KEYS[1], tostring(next_cash))
if sig ~= "" then
    redis.call('RPUSH', KEYS[2], sig .. ":" .. tostring(next_cash))
end
return {1, "COMMITTED", tostring(next_cash)}
"""

    def __init__(self):
        # Thresholds from singleton — no inline literals.
        self.min_cash_balance: float = THRESHOLDS.cbf.min_cash_balance
        self.gamma: float = THRESHOLDS.cbf.gamma
        self.redis_key: str = "safety:current_cash"
        self.tracer = get_tracer("src.gateway.governance.safety")
        self._lua_sha: str | None = None

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

    async def _read_cbf_state_atomic(self) -> dict[str, float]:
        """Atomically read all CBF state keys in a single pipeline round-trip.

        Using a pipeline (implicit MULTI/EXEC) prevents the race condition where
        individual GET calls observe inconsistent state snapshots between reads.
        All keys are fetched in one atomic batch — no other writer can interleave.

        Returns:
            dict with key "current_cash" (float).
        """
        if redis_client is None:
            raise RuntimeError("Redis client unavailable.")
        # pipeline() without transaction=True uses implicit pipelining (batched
        # GETs sent in one round-trip). For read-only snapshots this is sufficient
        # and avoids the WATCH overhead of a full MULTI/EXEC transaction.
        client = redis_client._get()
        async with client.pipeline(transaction=False) as pipe:
            pipe.get(self.redis_key)
            results = await pipe.execute()
        raw_cash = results[0]
        current_cash = float(raw_cash) if raw_cash is not None else 100000.0
        return {"current_cash": current_cash}

    def get_h(self, cash_balance: float) -> float:
        """Safety function h(x).  Safe when h(x) >= 0."""
        return cash_balance - self.min_cash_balance

    # ------------------------------------------------------------------
    # verify_action
    # ------------------------------------------------------------------

    async def verify_action(self, action_name: str, payload: dict[str, Any]) -> str:
        """Verify an action is safe relative to shared Redis cash state.

        Uses ``_read_cbf_state_atomic()`` to snapshot all state keys in a single
        pipeline round-trip, preventing the race condition where interleaved writes
        between individual GETs cause the barrier certificate to be evaluated
        against an inconsistent state snapshot (H-07).
        """
        state = await self._read_cbf_state_atomic()
        current_cash = state["current_cash"]

        if self.tracer:
            with self.tracer.start_as_current_span("safety.cbf_check") as span:
                return await self._do_verify_action(
                    action_name, payload, current_cash, span
                )
        else:
            return await self._do_verify_action(
                action_name, payload, current_cash, None
            )

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
            _mrm_meta = ControlRegistry().get_mapping(
                GovernanceControl.TRADITIONAL_MRM_VALIDATION
            )
            span.set_attribute("governance.control_id", _mrm_meta["internal_id"])
            span.set_attribute("governance.framework", _mrm_meta["primary_framework"])
            span.set_attribute(
                "governance.legacy_citation", _mrm_meta["legacy_citation"]
            )
            span.set_attribute("governance.scope", _mrm_meta["scope"])

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
            _mrm_meta = ControlRegistry().get_mapping(
                GovernanceControl.TRADITIONAL_MRM_VALIDATION
            )
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
                msg = f"UNSAFE: Drawdown Violation. {current_drawdown:.2%} > Limit {limit:.2%}"
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

    async def update_state(
        self, cost: float, governance_signature: str | None = None
    ) -> None:
        """Atomically deduct *cost* from the Redis cash balance.

        Uses WATCH / MULTI / EXEC optimistic locking.  Retries up to
        ``_MAX_RETRIES`` times if a concurrent writer modified the key.

        Args:
            cost:                 Amount to deduct from the cash balance.
            governance_signature: Optional KMS governance signature to persist
                                  in the ``audit:state_ledger`` RPUSH log.

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
                    if governance_signature:
                        ledger_entry = json.dumps(
                            {
                                "ts": time.time(),
                                "cost": cost,
                                "new_balance": new_balance,
                                "governance_signature": governance_signature,
                            }
                        )
                        pipe.rpush("audit:state_ledger", ledger_entry)
                    await pipe.execute()
                    logger.info(
                        "✅ CBF state updated atomically: %.2f → %.2f (attempt %d)",
                        current,
                        new_balance,
                        attempt + 1,
                    )
                    return
            except Exception as exc:
                # WatchError or transient failure — retry
                if "WatchError" in type(exc).__name__:
                    logger.warning(
                        "⚡ CBF WATCH conflict on attempt %d/%d — retrying.",
                        attempt + 1,
                        self._MAX_RETRIES,
                    )
                    continue
                raise

        raise RuntimeError(
            f"CBF update_state failed after {self._MAX_RETRIES} retries due to concurrent writes."
        )

    # ------------------------------------------------------------------
    # rollback_state — WATCH/MULTI/EXEC atomic transaction (Phase 4.1)
    # ------------------------------------------------------------------

    async def rollback_state(
        self, cost: float, governance_signature: str | None = None
    ) -> None:
        """Atomically restore *cost* to the Redis cash balance.

        Mirrors ``update_state`` but adds rather than deducts.  Call this
        when a trade was approved by the CBF but failed downstream (e.g.
        broker API error).

        Args:
            cost:                 Amount to restore to the cash balance.
            governance_signature: Optional KMS governance signature to persist
                                  in the ``audit:state_ledger`` RPUSH log.

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
                    if governance_signature:
                        ledger_entry = json.dumps(
                            {
                                "ts": time.time(),
                                "cost": cost,
                                "new_balance": restored,
                                "governance_signature": governance_signature,
                                "rollback": True,
                            }
                        )
                        pipe.rpush("audit:state_ledger", ledger_entry)
                    await pipe.execute()
                    logger.info(
                        "🔄 CBF state rolled back atomically: %.2f → %.2f (attempt %d)",
                        current,
                        restored,
                        attempt + 1,
                    )
                    return
            except Exception as exc:
                if "WatchError" in type(exc).__name__:
                    logger.warning(
                        "⚡ CBF WATCH conflict on rollback attempt %d/%d — retrying.",
                        attempt + 1,
                        self._MAX_RETRIES,
                    )
                    continue
                raise

        raise RuntimeError(
            f"CBF rollback_state failed after {self._MAX_RETRIES} retries due to concurrent writes."
        )

    # ------------------------------------------------------------------
    # atomic_verify_and_commit — Lua-atomic CBF check+commit (CAGE-SEC-002)
    # ------------------------------------------------------------------

    async def atomic_verify_and_commit(
        self,
        action_name: str,
        payload: dict[str, Any],
        governance_signature: str = "",
    ) -> tuple[bool, str]:
        """Collapse CBF check and state commit into one atomic Redis Lua hop.

        Eliminates the TOCTOU window between ``verify_action()`` (read-only,
        governance check phase) and ``update_state()`` (write, MCP tool handler
        phase) by executing both as a single Lua script inside Redis.

        The Lua script replicates the exact CBF formula:
            h(S(t+1)) >= (1 - γ) · h(S(t))   AND   h(S(t+1)) >= 0

        KMS signature verification (proof of compliance) must occur in Python
        before calling this method — Redis Lua has no cryptographic FFI.

        Args:
            action_name:          Name of the action being evaluated (e.g.
                                  ``"execute_trade"``).
            payload:              Action parameters dict; ``payload["amount"]``
                                  is used as the cost for ``execute_trade``.
            governance_signature: Optional KMS governance signature string.
                                  Persisted to ``audit:state_ledger`` on commit.

        Returns:
            ``(True, "COMMITTED")`` on success.
            ``(False, reason_string)`` when the CBF envelope is violated.

        Raises:
            RuntimeError: If Redis is unavailable.
        """
        if redis_client is None:
            raise RuntimeError("Redis client unavailable — cannot run atomic CBF.")

        cost = 0.0
        if action_name == "execute_trade":
            cost = float(payload.get("amount", 0.0))

        keys = ["safety:current_cash", "audit:state_ledger"]
        argv = [
            str(cost),
            str(self.min_cash_balance),
            str(self.gamma),
            governance_signature,
        ]

        client = redis_client._get()

        async def _run_evalsha() -> list:
            return await client.evalsha(self._lua_sha, len(keys), *keys, *argv)

        async def _load_and_run() -> list:
            self._lua_sha = await client.script_load(self.LUA_ATOMIC_CBF)
            return await _run_evalsha()

        if self.tracer:
            with self.tracer.start_as_current_span(
                "safety.cbf_atomic_check_commit"
            ) as span:
                span.set_attribute("safety.cash.cost", cost)
                _mrm_meta = ControlRegistry().get_mapping(
                    GovernanceControl.TRADITIONAL_MRM_VALIDATION
                )
                span.set_attribute("governance.control_id", _mrm_meta["internal_id"])
                span.set_attribute(
                    "governance.framework", _mrm_meta["primary_framework"]
                )
                span.set_attribute(
                    "governance.legacy_citation", _mrm_meta["legacy_citation"]
                )
                span.set_attribute("governance.scope", _mrm_meta["scope"])
                result_list = await self._evalsha_with_noscript_retry(
                    client, keys, argv, _run_evalsha, _load_and_run
                )
                return self._parse_lua_result(result_list, span)
        else:
            result_list = await self._evalsha_with_noscript_retry(
                client, keys, argv, _run_evalsha, _load_and_run
            )
            return self._parse_lua_result(result_list, None)

    async def _evalsha_with_noscript_retry(
        self,
        client: Any,
        keys: list[str],
        argv: list[str],
        run_evalsha_fn: Any,
        load_and_run_fn: Any,
    ) -> list:
        """Load the Lua SHA on first call; retry once on NOSCRIPT error."""
        if self._lua_sha is None:
            self._lua_sha = await client.script_load(self.LUA_ATOMIC_CBF)

        try:
            return await run_evalsha_fn()
        except Exception as exc:
            if "NOSCRIPT" in str(exc):
                logger.warning("⚡ Lua SHA evicted from Redis — reloading script.")
                return await load_and_run_fn()
            raise

    def _parse_lua_result(
        self,
        result_list: list,
        span: Any,
    ) -> tuple[bool, str]:
        """Parse the Lua script return array into a Python (bool, str) tuple."""
        status_code = int(result_list[0])
        message = (
            result_list[1].decode()
            if isinstance(result_list[1], bytes)
            else str(result_list[1])
        )
        new_balance_str = (
            result_list[2].decode()
            if isinstance(result_list[2], bytes)
            else str(result_list[2])
        )

        committed = status_code == 1
        if span:
            span.set_attribute("safety.result", "COMMITTED" if committed else "UNSAFE")
            span.set_attribute("safety.cash.next", float(new_balance_str))

        if committed:
            logger.info(
                "✅ CBF atomic check+commit: COMMITTED — new_balance=%s",
                new_balance_str,
            )
            return (True, "COMMITTED")
        else:
            logger.info("⛔ CBF atomic check+commit: UNSAFE — %s", message)
            return (False, message)


# Global singleton
safety_filter = ControlBarrierFunction()
